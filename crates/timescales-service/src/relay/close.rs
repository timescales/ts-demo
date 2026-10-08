//! Closing an epoch: the padded envelope set fixed at the cutoff, and
//! the header v2 batch assembled from it once the beacon is revealed.

use std::collections::BTreeSet;

use rand::SeedableRng;
use rand::distributions::{Bernoulli, Distribution};
use rand_chacha::ChaCha20Rng;
use rand_core::OsRng;
use timescales_auction::collateral::BalanceSheet;
use timescales_auction::orderbook::OrderStateTable;
use timescales_auction::{
    Auction, AuctionEpoch, AuctionError, BatchHeader, BatchLeaf, batch_leaves, batch_root_v2,
};
#[cfg(feature = "simulation")]
use timescales_core::intent::MaskedIntent;
use timescales_core::intent::SealedEnvelope;
use timescales_core::{EpochId, Hash32, MarketParams, OrderCommitment, PriceBand};
use timescales_executor::ExecutionBatch;

use crate::relay::{CoverRng, CoverSource, Open, RelayConfig, RelayError, Sealed};

/// A closed epoch: the padded envelope set fixed at the cutoff, ready to be
/// committed and, once the beacon is known, assembled into a header v2 batch.
///
/// Masked (MPC) encodings are not part of it: a header v2 batch carries
/// none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedBatch {
    pub market_address: [u8; 32],
    pub epoch: EpochId,
    pub params: MarketParams,
    pub band: PriceBand,
    pub price_commitment: Hash32,
    pub binding: Hash32,
    pub opens_at_ms: u64,
    pub cutoff_ms: u64,
    pub envelopes: Vec<SealedEnvelope>,
    /// Submitting wallet per envelope. Zero for cover.
    pub submitters: Vec<[u8; 32]>,
    /// Leaves sorted by their 64-byte encoding.
    pub leaves: Vec<BatchLeaf>,
    pub root: Hash32,
    pub real: u32,
    pub cover: u32,
}

impl ClosedBatch {
    /// Header v2 batch for execution, after the beacon is revealed.
    ///
    /// Checks the closed batch against itself first, so a corrupted or
    /// mis-decoded one cannot be executed: the params are valid, the band
    /// follows from the reference, the counts agree, the leaves hash to
    /// `root`, and replaying every envelope through a fresh header v2
    /// auction reproduces the header's root and count.
    pub fn assemble(
        &self,
        beacon: Hash32,
        balances: BalanceSheet,
        prior: OrderStateTable,
        prev_receipt: Hash32,
    ) -> Result<Sealed, RelayError> {
        // Decoding does not validate params, and deriving a band from
        // invalid ones can overflow.
        self.params
            .validate()
            .map_err(|e| RelayError::Band(e.to_string()))?;
        let band = self
            .params
            .band(self.band.reference)
            .map_err(|e| RelayError::Band(e.to_string()))?;
        if band != self.band {
            return Err(RelayError::Band(
                "closed batch band does not follow from its reference".into(),
            ));
        }
        let count = self.envelopes.len();
        if self.submitters.len() != count
            || u32::try_from(count).ok() != self.real.checked_add(self.cover)
            || count > self.params.max_batch_envelopes as usize
        {
            return Err(AuctionError::HeaderMismatch.into());
        }
        let header = BatchHeader::assemble_v2(
            self.params,
            self.epoch,
            self.band,
            self.binding,
            &self.leaves,
            beacon,
            prior.root(),
            balances.root(),
            prev_receipt,
        );
        if header.batch_root != self.root {
            return Err(AuctionError::HeaderMismatch.into());
        }
        let timing = AuctionEpoch {
            epoch: self.epoch,
            opens_at_ms: self.opens_at_ms,
            cutoff_ms: self.cutoff_ms,
        };
        let mut replay = Auction::new_v2(self.params.market, timing, header.envelope_count);
        for e in &self.envelopes {
            replay.submit(timing.opens_at_ms, e.clone())?;
        }
        replay.seal(timing.cutoff_ms, header)?;
        Ok(Sealed {
            batch: ExecutionBatch {
                header,
                envelopes: self.envelopes.clone(),
                masked: Vec::new(),
                balances,
                prior_state: prior,
            },
            promises: Vec::new(),
            real: self.real as usize,
            cover: self.cover as usize,
        })
    }
}

/// What the first close caches in the open epoch.
#[derive(Debug)]
pub(crate) struct Closing {
    pub(crate) batch: ClosedBatch,
    /// Masked encodings index-aligned with `batch.envelopes`, read only by
    /// the header v1 sealing of simulations.
    #[cfg(feature = "simulation")]
    pub(crate) masked: Vec<Option<MaskedIntent>>,
}

/// Pad `open` with cover up to the padding target, and an epoch opened for
/// header v2 to at least one envelope, and fix its envelope set: accepted
/// envelopes in arrival order, then cover.
pub(crate) fn close(
    config: &RelayConfig,
    cover: &dyn CoverSource,
    rng: &mut CoverRng,
    open: &Open,
    now_ms: u64,
) -> Result<Closing, RelayError> {
    let params = config.params;
    let timing = open.auction.timing();
    if now_ms < timing.cutoff_ms {
        return Err(AuctionError::InvalidTransition {
            from: "Open (before cutoff)",
        }
        .into());
    }
    let carry = Bernoulli::new(config.carry_p)
        .map_err(|e| RelayError::Cover(format!("carry_p {}: {e}", config.carry_p)))?;
    let mut fresh_rng;
    let rng = match rng {
        CoverRng::Os => {
            fresh_rng = ChaCha20Rng::from_rng(OsRng)
                .map_err(|e| RelayError::Cover(format!("os rng: {e}")))?;
            &mut fresh_rng
        }
        #[cfg(feature = "simulation")]
        CoverRng::Seeded(r) => r.as_mut(),
    };

    let real = open.entries.len();
    // CommitBatch refuses a batch without envelopes, so a header v2
    // batch always carries one, cover if nobody submitted.
    let least = usize::from(open.binding.is_some());
    let target = config
        .padding
        .target(real)
        .min(params.max_batch_envelopes as usize)
        .max(real)
        .max(least);
    let mut envelopes = Vec::with_capacity(target);
    let mut masked = Vec::with_capacity(target);
    let mut submitters = Vec::with_capacity(target);
    for e in &open.entries {
        envelopes.push(e.submission.envelope.clone());
        masked.push(e.submission.masked.clone());
        submitters.push(e.submitter);
    }
    let mut present: BTreeSet<OrderCommitment> = open.commitments.clone();
    while envelopes.len() < target {
        // A carried no-op whose commitment someone already submitted this
        // epoch is skipped. Fresh cover takes the slot.
        let carried = if config.carry_p > 0.0 && carry.sample(rng) {
            cover
                .carry(params.market, timing.epoch, rng)
                .map_err(RelayError::Cover)?
                .filter(|(e, _)| !present.contains(&e.commitment))
        } else {
            None
        };
        let (env, m) = match carried {
            Some(c) => c,
            None => cover
                .cover(params.market, timing.epoch, rng)
                .map_err(RelayError::Cover)?,
        };
        if env.market != params.market || env.epoch != timing.epoch {
            return Err(RelayError::Cover(
                "cover sealed for another market or epoch".into(),
            ));
        }
        present.insert(env.commitment);
        envelopes.push(env);
        masked.push(m);
        submitters.push([0; 32]);
    }
    let leaves = batch_leaves(&envelopes);
    let root = batch_root_v2(&leaves);
    let count = |n: usize| u32::try_from(n).map_err(|_| RelayError::Auction(AuctionError::Full));
    Ok(Closing {
        batch: ClosedBatch {
            market_address: config.market_address,
            epoch: timing.epoch,
            params,
            band: open.band,
            price_commitment: open.price_commitment,
            // Only header v1 sealing reads the closing of an epoch opened
            // without a binding. `close` and `take_closed` refuse it.
            binding: open.binding.unwrap_or(Hash32::ZERO),
            opens_at_ms: timing.opens_at_ms,
            cutoff_ms: timing.cutoff_ms,
            submitters,
            leaves,
            root,
            real: count(real)?,
            cover: count(envelopes.len() - real)?,
            envelopes,
        },
        #[cfg(feature = "simulation")]
        masked,
    })
}
