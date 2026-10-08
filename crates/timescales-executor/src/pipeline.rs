//! Plaintext execution pipeline.
//!
//! ```text
//! check header -> open envelopes -> provenance -> canonical order
//!   -> validate -> match -> settle -> next state -> outcome
//! ```
//!
//! Pure apart from timing: the same inputs always yield the same outcome,
//! artifacts and trace. Opening is parallel (rayon) but results are placed
//! by index, so parallelism never affects the result.

use std::time::Instant;

use rayon::prelude::*;
use timescales_auction::collateral::BalanceSheet;
use timescales_auction::matching::match_batch;
use timescales_auction::orderbook::{
    Candidate, OrderStateTable, RejectReason, ValidatedBatch, ValidationContext, validate,
};
use timescales_auction::receipts::{
    ExecutionArtifacts, ExecutionOutcome, ExecutionTrace, commitments_root, fills_root,
};
use timescales_auction::settlement::settle;
use timescales_auction::{
    BatchHeader, batch_leaves, batch_root, batch_root_v2, canonical_order, epoch_seed,
};
use timescales_core::crypto::{EpochSecret, Zeroizing};
use timescales_core::intent::{IntentBody, PrivateIntent, SealedEnvelope};
use timescales_core::{
    ClearingPrice, CommitmentScheme, Encode, Fill, HEADER_VERSION_ENVELOPE_BOUND, Hash32,
    OrderCommitment, PROTOCOL_VERSION, PriceBand, TraderId, encoding::put_seq,
};

use crate::{ExecutionBatch, ExecutionMetrics, ExecutorError};

/// Check that the header describes exactly these inputs and return the band.
///
/// A version 1 header's root is over the commitments. A version 2 header's
/// root is over `commitment || envelope digest` leaves, so it also pins
/// the exact envelope bytes.
pub fn check_header(
    header: &BatchHeader,
    envelopes: &[SealedEnvelope],
    balances: &BalanceSheet,
    prior: &OrderStateTable,
) -> Result<PriceBand, ExecutorError> {
    match header.version {
        PROTOCOL_VERSION => {
            let commitments: Vec<OrderCommitment> =
                envelopes.iter().map(|e| e.commitment).collect();
            check_header_commitments(header, &commitments, balances, prior)
        }
        HEADER_VERSION_ENVELOPE_BOUND => {
            let band = check_terms(header, envelopes.len())?;
            if header.batch_root != batch_root_v2(&batch_leaves(envelopes)) {
                return Err(ExecutorError::BadHeader("batch root"));
            }
            check_state(header, balances, prior)?;
            Ok(band)
        }
        _ => Err(ExecutorError::BadHeader("header version")),
    }
}

/// As [`check_header`], for any input encoding that carries commitments.
/// Only version 1 headers can be checked this way: a version 2 root also
/// covers envelope digests.
pub fn check_header_commitments(
    header: &BatchHeader,
    commitments: &[OrderCommitment],
    balances: &BalanceSheet,
    prior: &OrderStateTable,
) -> Result<PriceBand, ExecutorError> {
    if header.version != PROTOCOL_VERSION {
        return Err(ExecutorError::BadHeader(
            "header version 2 binds envelope digests",
        ));
    }
    let band = check_terms(header, commitments.len())?;
    if header.batch_root != batch_root(commitments) {
        return Err(ExecutorError::BadHeader("batch root"));
    }
    check_state(header, balances, prior)?;
    Ok(band)
}

fn check_terms(header: &BatchHeader, count: usize) -> Result<PriceBand, ExecutorError> {
    header
        .params
        .validate()
        .map_err(|_| ExecutorError::BadHeader("market params"))?;
    if header.market != header.params.market {
        return Err(ExecutorError::BadHeader("market"));
    }
    let band = header
        .params
        .band(header.band.reference)
        .map_err(|_| ExecutorError::BadHeader("band"))?;
    if band != header.band {
        return Err(ExecutorError::BadHeader(
            "band does not follow from reference",
        ));
    }
    if header.envelope_count as usize != count {
        return Err(ExecutorError::BadHeader("envelope count"));
    }
    if count > header.params.max_batch_envelopes as usize {
        return Err(ExecutorError::BadHeader("batch too large"));
    }
    Ok(band)
}

fn check_state(
    header: &BatchHeader,
    balances: &BalanceSheet,
    prior: &OrderStateTable,
) -> Result<(), ExecutorError> {
    if header.balances_root != balances.root() {
        return Err(ExecutorError::BadHeader("balances root"));
    }
    if header.prior_state_root != prior.root() {
        return Err(ExecutorError::BadHeader("prior state root"));
    }
    Ok(())
}

/// Seed of the batch's canonical order.
///
/// Version 1: [`BatchHeader::seed`]. Version 2: [`BatchHeader::seed_v2`]
/// over `epoch_seed(s, market address, epoch)`, which mixes in the epoch
/// secret `s` (the scalar of a threshold-dealt key, the X25519 secret of a
/// dev key), so nobody without the secret can evaluate the order.
pub fn order_seed(header: &BatchHeader, key: &EpochSecret, market_address: &[u8; 32]) -> Hash32 {
    if header.version != HEADER_VERSION_ENVELOPE_BOUND {
        return header.seed();
    }
    let secret = Zeroizing::new(match key {
        EpochSecret::Dev(s) => s.to_bytes(),
        EpochSecret::Threshold(s) => s.scalar().to_bytes(),
    });
    header.seed_v2(&epoch_seed(&secret, market_address, header.epoch))
}

/// Decrypt and check every envelope in parallel.
pub fn open_envelopes(
    key: &EpochSecret,
    scheme: CommitmentScheme,
    envelopes: &[SealedEnvelope],
) -> Vec<Result<PrivateIntent, RejectReason>> {
    envelopes
        .par_iter()
        .map(|e| {
            e.open_with(key, scheme)
                .map_err(|err| RejectReason::from(&err))
        })
        .collect()
}

/// Everything the plaintext pipeline produces.
pub struct PlainExecution {
    pub outcome: ExecutionOutcome,
    pub artifacts: ExecutionArtifacts,
    pub trace: ExecutionTrace,
    /// Opened intents in canonical order (plaintext, never leaves the
    /// executor except into a proof witness).
    pub candidates: Vec<Candidate>,
    pub validated: ValidatedBatch,
    pub next_state: OrderStateTable,
    /// Includes the envelopes that did not authenticate.
    pub metrics: ExecutionMetrics,
}

/// Prints the public results only: the opened intents and the validated
/// books are plaintext orders.
impl core::fmt::Debug for PlainExecution {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlainExecution")
            .field("outcome", &self.outcome)
            .field("candidates", &self.candidates.len())
            .field("metrics", &self.metrics)
            .finish_non_exhaustive()
    }
}

/// Run provenance, ordering, validation and settlement on opened
/// envelopes.
///
/// `opened[i]` is the opening of `batch.envelopes[i]` and `seed` comes from
/// [`order_seed`]. With `admission`, a Place or Cancel at index `i` is
/// admitted only if `admission[i]` is its trader (provenance). Otherwise
/// it is rejected like an intent with a bad signature. Cover intents name no
/// trader and pass.
pub fn execute_opened(
    batch: &ExecutionBatch,
    band: &PriceBand,
    seed: &Hash32,
    mut opened: Vec<Result<PrivateIntent, RejectReason>>,
    admission: Option<&[Option<TraderId>]>,
    mut metrics: ExecutionMetrics,
) -> Result<PlainExecution, ExecutorError> {
    let header = &batch.header;
    let envelopes = &batch.envelopes;
    let params = &header.params;
    if opened.len() != envelopes.len() {
        return Err(ExecutorError::Execution(
            "one opening per envelope required".into(),
        ));
    }
    if admission.is_some_and(|a| a.len() != envelopes.len()) {
        return Err(ExecutorError::Execution(
            "one admission entry per envelope required".into(),
        ));
    }
    let mut trace = ExecutionTrace::new();
    trace.record("header", header.digest().as_bytes());

    metrics.unauthenticated = admit(&mut opened, admission)?;

    let t = Instant::now();
    let order = canonical_order(seed, envelopes);
    let mut opened: Vec<Option<Result<PrivateIntent, RejectReason>>> =
        opened.into_iter().map(Some).collect();
    let candidates: Vec<Candidate> = order
        .iter()
        .map(|(i, key)| Candidate {
            commitment: envelopes[*i].commitment,
            priority: *key,
            intent: opened[*i].take().unwrap_or(Err(RejectReason::Malformed)),
        })
        .collect();
    metrics.stages.push(("order".into(), t.elapsed()));
    let mut ordered = Vec::with_capacity(candidates.len() * 32);
    for c in &candidates {
        c.commitment.encode(&mut ordered);
    }
    trace.record("canonical-order", &ordered);

    let t = Instant::now();
    let ctx = ValidationContext {
        params,
        band,
        epoch: header.epoch,
        state: &batch.prior_state,
        balances: &batch.balances,
    };
    let validated = validate(&ctx, &candidates);
    metrics.stages.push(("validate".into(), t.elapsed()));
    metrics.accepted = validated.accepted();
    metrics.rejected = validated.rejected();
    let mut v = Vec::new();
    for (c, d) in &validated.dispositions {
        c.encode(&mut v);
        v.extend_from_slice(d.trace_label().as_bytes());
    }
    trace.record("validate", &v);

    let t = Instant::now();
    let matched = match_batch(band, params.rationing, &validated)
        .map_err(|e| ExecutorError::Execution(e.to_string()))?;
    metrics.stages.push(("match".into(), t.elapsed()));
    let mut m = Vec::new();
    put_seq(&mut m, &matched.clearing);
    put_seq(&mut m, &matched.fills);
    trace.record("match", &m);

    let t = Instant::now();
    let fin = finalize(
        header,
        matched.fills,
        matched.clearing,
        validated.cancelled.clone(),
        &batch.balances,
        &batch.prior_state,
    )?;
    metrics.stages.push(("settle".into(), t.elapsed()));
    trace.record("settle", fin.artifacts.settlement.root().as_bytes());
    Ok(PlainExecution {
        outcome: fin.outcome,
        artifacts: fin.artifacts,
        trace,
        candidates,
        validated,
        next_state: fin.next_state,
        metrics,
    })
}

/// Apply the admission vector and list the envelopes that did not
/// authenticate.
fn admit(
    opened: &mut [Result<PrivateIntent, RejectReason>],
    admission: Option<&[Option<TraderId>]>,
) -> Result<Vec<u32>, ExecutorError> {
    let mut unauthenticated = Vec::new();
    for (i, o) in opened.iter_mut().enumerate() {
        if let (Ok(pi), Some(admission)) = (&*o, admission) {
            let trader = match &pi.body {
                IntentBody::Place(order) => Some(order.trader),
                IntentBody::Cancel(cancel) => Some(cancel.trader),
                IntentBody::Noop => None,
            };
            if trader.is_some_and(|t| admission[i] != Some(t)) {
                *o = Err(RejectReason::BadSignature);
            }
        }
        if o.is_err() {
            unauthenticated.push(
                u32::try_from(i)
                    .map_err(|_| ExecutorError::Execution("too many envelopes".into()))?,
            );
        }
    }
    Ok(unauthenticated)
}

/// Result of turning fills into settlement, next state and an outcome.
#[derive(Debug)]
pub struct Finalized {
    pub outcome: ExecutionOutcome,
    pub artifacts: ExecutionArtifacts,
    pub next_state: OrderStateTable,
}

/// Settlement, cross-epoch state and outcome from public results. Shared by
/// every backend so that only matching differs between them.
pub fn finalize(
    header: &BatchHeader,
    fills: Vec<Fill>,
    clearing: Vec<ClearingPrice>,
    cancelled: Vec<OrderCommitment>,
    balances: &BalanceSheet,
    prior: &OrderStateTable,
) -> Result<Finalized, ExecutorError> {
    let params = &header.params;
    let settlement = settle(params, header.epoch, &fills)
        .map_err(|e| ExecutorError::Execution(e.to_string()))?;
    // Collateral admission should make this impossible. Check anyway so a
    // logic error surfaces here rather than on chain.
    settlement
        .apply(balances)
        .map_err(|e| ExecutorError::Execution(e.to_string()))?;
    let mut next_state = prior.clone();
    next_state.apply(
        header.epoch,
        params.max_order_lifetime,
        fills.iter().map(|f| (f.commitment, f.quantity)),
        cancelled.iter().copied(),
    );
    let outcome = ExecutionOutcome {
        market: header.market,
        epoch: header.epoch,
        header_digest: header.digest(),
        clearing,
        fill_count: u32::try_from(fills.len())
            .map_err(|_| ExecutorError::Execution("too many fills".into()))?,
        fills_root: fills_root(&fills),
        cancelled_root: commitments_root(&cancelled),
        next_state_root: next_state.root(),
        settlement_count: u32::try_from(settlement.deltas.len())
            .map_err(|_| ExecutorError::Execution("too many deltas".into()))?,
        settlement_root: settlement.root(),
        fees: settlement.fees,
    };
    Ok(Finalized {
        outcome,
        artifacts: ExecutionArtifacts {
            fills,
            cancelled,
            settlement,
        },
        next_state,
    })
}
