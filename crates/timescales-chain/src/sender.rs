//! [`TxSender`]: one transaction from instructions to a known outcome, with
//! a journal row written before the send.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::program::{Ix, compute_budget};
use parking_lot::Mutex;
use tokio::time::Instant;

use crate::wire;
use crate::{
    Address, FeeMode, FeePolicy, Landed, Level, RpcError, SolanaRpc, TxError, TxJournal, TxOp,
    TxOutcome, TxRecord, TxSigner, TxStatus,
};

/// Compute units one transaction may request.
const MAX_UNITS: u32 = 1_400_000;
/// Signatures per `getSignatureStatuses` call.
const STATUS_BATCH: usize = 256;

/// What the journal row of a transaction names, and the `minContextSlot`
/// of its send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendOptions {
    pub market: Address,
    pub epoch: Option<u64>,
    pub op: TxOp,
    /// The node's preflight bank must have reached this slot, so a
    /// transaction is never checked against older state than the sender
    /// saw.
    pub min_slot: Option<u64>,
}

/// The compute-unit cache key: the operation and, per instruction, its
/// program, account count and data length.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Shape {
    op: TxOp,
    ixs: Vec<(Address, usize, usize)>,
}

impl Shape {
    fn of(op: TxOp, ixs: &[Ix]) -> Self {
        Self {
            op,
            ixs: ixs
                .iter()
                .map(|ix| (ix.program, ix.accounts.len(), ix.data.len()))
                .collect(),
        }
    }
}

/// Sends transactions: compute-unit sizing by simulation, priority fees, a
/// journal row before every send, confirmation polling and expiry.
///
/// Every transaction is `[SetComputeUnitLimit, SetComputeUnitPrice] ++ ixs`.
/// The limit is the simulated consumption plus `cu_margin_pct`, cached per
/// operation and instruction shape (and dropped when a transaction runs out
/// of units). The price follows the [`FeePolicy`]. A send whose outcome is
/// unknown (transport failure, timeout, lost response) is polled until it is
/// confirmed, fails, or its blockhash expires. It is never re-sent.
pub struct TxSender {
    rpc: Arc<dyn SolanaRpc>,
    fees: FeePolicy,
    journal: Arc<dyn TxJournal>,
    poll: Duration,
    confirm_timeout: Duration,
    units: Mutex<HashMap<Shape, u32>>,
    last_landed: AtomicU64,
}

impl fmt::Debug for TxSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxSender")
            .field("fees", &self.fees)
            .field("poll", &self.poll)
            .field("confirm_timeout", &self.confirm_timeout)
            .field("last_landed", &self.last_landed)
            .finish_non_exhaustive()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The `percentile`-th (nearest rank) of `values`, 0 for none.
fn percentile(values: &mut [u64], percentile: u8) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let rank = (usize::from(percentile.min(100)) * values.len()).div_ceil(100);
    values[rank.saturating_sub(1)]
}

/// The outcome a status and the confirmed block height prove, if any.
fn outcome(status: Option<TxStatus>, height: u64, last_valid: u64) -> Option<TxOutcome> {
    match status {
        Some(s) if s.level >= Level::Confirmed => Some(match s.err {
            None => TxOutcome::Landed { slot: s.slot },
            Some(err) => TxOutcome::Failed { slot: s.slot, err },
        }),
        // The height was read before the status: once the confirmed chain
        // is past `last_valid`, no block that could still carry the
        // transaction can become confirmed.
        _ if height > last_valid => Some(TxOutcome::Expired),
        _ => None,
    }
}

impl TxSender {
    pub fn new(
        rpc: Arc<dyn SolanaRpc>,
        fees: FeePolicy,
        journal: Arc<dyn TxJournal>,
        poll: Duration,
        confirm_timeout: Duration,
    ) -> Self {
        Self {
            rpc,
            fees,
            journal,
            poll,
            confirm_timeout,
            units: Mutex::new(HashMap::new()),
            last_landed: AtomicU64::new(0),
        }
    }

    /// The highest slot in which a transaction of this sender landed
    /// (succeeded or failed), 0 before the first.
    pub fn last_landed_slot(&self) -> u64 {
        self.last_landed.load(Ordering::Acquire)
    }

    /// [`send_with`](Self::send_with) without an epoch or `minContextSlot`.
    /// The journal row names the market in the second account of the last
    /// instruction, where every settlement-program instruction lists it.
    pub async fn send(
        &self,
        op: TxOp,
        ixs: Vec<Ix>,
        payer: Arc<dyn TxSigner>,
        extra: Vec<Arc<dyn TxSigner>>,
    ) -> Result<Landed, TxError> {
        let market = ixs
            .last()
            .and_then(|ix| ix.accounts.get(1))
            .map_or([0; 32], |m| m.key);
        let opts = SendOptions {
            market,
            epoch: None,
            op,
            min_slot: None,
        };
        self.send_with(opts, ixs, payer, extra).await
    }

    /// Signs `ixs` (paid by `payer`, co-signed by `extra`), records the
    /// transaction in the journal, sends it with preflight and waits for a
    /// Confirmed outcome.
    ///
    /// A cached compute-unit limit can be short for this transaction's data
    /// (a PDA whose bump search takes longer, a longer Merkle path). When
    /// the node's preflight shows it running out of units, the transaction
    /// is sized again by simulation and sent once more. The refused one was
    /// never forwarded.
    pub async fn send_with(
        &self,
        opts: SendOptions,
        ixs: Vec<Ix>,
        payer: Arc<dyn TxSigner>,
        extra: Vec<Arc<dyn TxSigner>>,
    ) -> Result<Landed, TxError> {
        let shape = Shape::of(opts.op, &ixs);
        let cached = self.units.lock().contains_key(&shape);
        match self
            .send_once(&opts, &shape, &ixs, &payer, &extra, false)
            .await
        {
            Err(TxError::Preflight { err, logs }) if cached && err.out_of_units(&logs) => {
                tracing::debug!(op = opts.op.as_str(), "cached compute-unit limit too low");
                self.send_once(&opts, &shape, &ixs, &payer, &extra, true)
                    .await
            }
            other => other,
        }
    }

    async fn send_once(
        &self,
        opts: &SendOptions,
        shape: &Shape,
        ixs: &[Ix],
        payer: &Arc<dyn TxSigner>,
        extra: &[Arc<dyn TxSigner>],
        resize: bool,
    ) -> Result<Landed, TxError> {
        let payer_key = payer.address();
        let (blockhash, last_valid) = self.rpc.latest_blockhash(Level::Confirmed).await?;
        let price = self.priority_fee(ixs).await?;
        let units = self
            .units(shape, ixs, &payer_key, &blockhash, price, resize)
            .await?;
        let mut all = vec![
            compute_budget::set_limit(units),
            compute_budget::set_price(price),
        ];
        all.extend_from_slice(ixs);
        let message = wire::compile(&all, &payer_key, &blockhash);
        let mut signers = vec![payer.clone()];
        signers.extend_from_slice(extra);
        let signed = wire::sign(&message, &signers)?;
        let record = TxRecord {
            id: None,
            market: opts.market,
            epoch: opts.epoch,
            op: opts.op,
            signature: signed.signature,
            last_valid_block_height: last_valid,
            sent_at_ms: now_ms(),
        };
        let id = self.journal.before_send(record).await?;
        match self
            .rpc
            .send_transaction(signed.wire, false, opts.min_slot)
            .await
        {
            Ok(_) => {}
            // The same signature was processed before: it landed, so it is
            // polled like any other.
            Err(RpcError::Preflight { err, .. }) if err.already_processed() => {}
            Err(RpcError::Preflight { err, logs }) => {
                self.journal.resolved(id, TxOutcome::Expired).await?;
                return Err(TxError::Preflight { err, logs });
            }
            Err(e) if e.refused_send() => {
                self.journal.resolved(id, TxOutcome::Expired).await?;
                return Err(TxError::Rpc(e));
            }
            Err(e) => {
                tracing::warn!(op = opts.op.as_str(), error = %e, "send outcome unknown; polling");
            }
        }
        self.confirm(id, signed.signature, last_valid, shape).await
    }

    /// Run at startup: raises [`Self::last_landed_slot`] to the journal's,
    /// then polls every journalled transaction without an outcome until it
    /// lands, fails or expires, and records the outcome.
    pub async fn resolve_pending(&self) -> Result<Vec<(TxRecord, TxOutcome)>, TxError> {
        self.landed_at(self.journal.last_landed_slot().await?);
        let mut pending = self.journal.pending().await?;
        let mut resolved = Vec::with_capacity(pending.len());
        let mut failing_since: Option<Instant> = None;
        while !pending.is_empty() {
            let txs: Vec<([u8; 64], u64)> = pending
                .iter()
                .map(|r| (r.signature, r.last_valid_block_height))
                .collect();
            match self.check(&txs).await {
                Ok(outcomes) => {
                    failing_since = None;
                    let mut still = Vec::new();
                    for (rec, outcome) in pending.into_iter().zip(outcomes) {
                        let Some(outcome) = outcome else {
                            still.push(rec);
                            continue;
                        };
                        if let Some(id) = rec.id {
                            self.journal.resolved(id, outcome.clone()).await?;
                        }
                        if let TxOutcome::Landed { slot } | TxOutcome::Failed { slot, .. } = outcome
                        {
                            self.landed_at(slot);
                        }
                        resolved.push((rec, outcome));
                    }
                    pending = still;
                }
                Err(e) => {
                    let since = *failing_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= self.confirm_timeout {
                        return Err(TxError::Rpc(e));
                    }
                }
            }
            if !pending.is_empty() {
                tokio::time::sleep(self.poll).await;
            }
        }
        Ok(resolved)
    }

    fn landed_at(&self, slot: u64) {
        self.last_landed.fetch_max(slot, Ordering::AcqRel);
    }

    async fn priority_fee(&self, ixs: &[Ix]) -> Result<u64, TxError> {
        let price = match self.fees.mode {
            FeeMode::Fixed(price) => price,
            FeeMode::Recent => {
                let mut writable: Vec<Address> = ixs
                    .iter()
                    .flat_map(|ix| ix.accounts.iter().filter(|m| m.writable).map(|m| m.key))
                    .collect();
                writable.sort_unstable();
                writable.dedup();
                let mut fees = self.rpc.recent_prioritization_fees(writable).await?;
                percentile(&mut fees, self.fees.percentile)
            }
        };
        Ok(price.min(self.fees.max_micro_lamports))
    }

    /// The compute-unit limit for `ixs`: cached for the shape (unless
    /// `resize`), or the simulated consumption plus the margin. The cache
    /// keeps the largest limit a transaction of the shape needed, so it
    /// settles on the costliest data instead of following the last one.
    async fn units(
        &self,
        shape: &Shape,
        ixs: &[Ix],
        payer: &Address,
        blockhash: &[u8; 32],
        price: u64,
        resize: bool,
    ) -> Result<u32, TxError> {
        if let (Some(units), false) = (self.units.lock().get(shape), resize) {
            return Ok(*units);
        }
        let mut all = vec![
            compute_budget::set_limit(MAX_UNITS),
            compute_budget::set_price(price),
        ];
        all.extend(ixs.iter().cloned());
        let message = wire::compile(&all, payer, blockhash);
        let sim = self
            .rpc
            .simulate_transaction(wire::unsigned(&message)?)
            .await?;
        if let Some(err) = sim.err {
            return Err(TxError::Preflight {
                err,
                logs: sim.logs,
            });
        }
        // Without a reported consumption the transaction gets the maximum,
        // and nothing is cached.
        let Some(consumed) = sim.units else {
            return Ok(MAX_UNITS);
        };
        let margin = u128::from(self.fees.cu_margin_pct);
        let limit = (u128::from(consumed) * (100 + margin)).div_ceil(100);
        let units = u32::try_from(limit)
            .unwrap_or(MAX_UNITS)
            .clamp(1, MAX_UNITS);
        let mut cache = self.units.lock();
        let kept = cache.entry(shape.clone()).or_insert(units);
        *kept = (*kept).max(units);
        Ok(units)
    }

    async fn confirm(
        &self,
        id: i64,
        signature: [u8; 64],
        last_valid: u64,
        shape: &Shape,
    ) -> Result<Landed, TxError> {
        let deadline = Instant::now() + self.confirm_timeout;
        loop {
            tokio::time::sleep(self.poll).await;
            match self.check(&[(signature, last_valid)]).await {
                Ok(mut outcomes) => {
                    if let Some(outcome) = outcomes.pop().flatten() {
                        self.journal.resolved(id, outcome.clone()).await?;
                        return match outcome {
                            TxOutcome::Landed { slot } => {
                                self.landed_at(slot);
                                Ok(Landed { signature, slot })
                            }
                            TxOutcome::Failed { slot, err } => {
                                self.landed_at(slot);
                                if err.budget_exceeded() {
                                    self.units.lock().remove(shape);
                                }
                                Err(TxError::Failed {
                                    signature,
                                    slot,
                                    err,
                                })
                            }
                            TxOutcome::Expired => Err(TxError::Expired { signature }),
                        };
                    }
                }
                Err(e) => tracing::debug!(error = %e, "status poll failed"),
            }
            if Instant::now() >= deadline {
                return Err(TxError::Timeout { signature });
            }
        }
    }

    /// One look at `(signature, last valid block height)` pairs: the
    /// confirmed block height first, then the statuses.
    async fn check(&self, txs: &[([u8; 64], u64)]) -> Result<Vec<Option<TxOutcome>>, RpcError> {
        let height = self.rpc.block_height(Level::Confirmed).await?;
        let mut statuses = Vec::with_capacity(txs.len());
        for chunk in txs.chunks(STATUS_BATCH) {
            let sigs = chunk.iter().map(|(sig, _)| *sig).collect();
            let got = self.rpc.signature_statuses(sigs).await?;
            if got.len() != chunk.len() {
                return Err(RpcError::Decode(
                    "another number of statuses than signatures".into(),
                ));
            }
            statuses.extend(got);
        }
        Ok(txs
            .iter()
            .zip(statuses)
            .map(|((_, last_valid), s)| outcome(s, height, *last_valid))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TxErrorDetail;

    #[test]
    fn nearest_rank_percentiles() {
        assert_eq!(percentile(&mut [], 75), 0);
        let mut fees = [40, 10, 30, 20];
        assert_eq!(percentile(&mut fees, 0), 10);
        assert_eq!(percentile(&mut fees, 25), 10);
        assert_eq!(percentile(&mut fees, 26), 20);
        assert_eq!(percentile(&mut fees, 75), 30);
        assert_eq!(percentile(&mut fees, 100), 40);
        assert_eq!(percentile(&mut fees, 250), 40);
    }

    #[test]
    fn outcomes_need_confirmation_or_expiry() {
        let status = |level, err: Option<TxErrorDetail>| {
            Some(TxStatus {
                slot: 7,
                level,
                err,
            })
        };
        let err = TxErrorDetail {
            ix_index: Some(2),
            custom: Some(6014),
            message: "x".into(),
        };
        assert_eq!(outcome(status(Level::Processed, None), 10, 20), None);
        assert_eq!(
            outcome(status(Level::Confirmed, None), 10, 20),
            Some(TxOutcome::Landed { slot: 7 })
        );
        assert_eq!(
            outcome(status(Level::Finalized, Some(err.clone())), 10, 20),
            Some(TxOutcome::Failed { slot: 7, err })
        );
        assert_eq!(outcome(None, 20, 20), None);
        assert_eq!(outcome(None, 21, 20), Some(TxOutcome::Expired));
        assert_eq!(
            outcome(status(Level::Processed, None), 21, 20),
            Some(TxOutcome::Expired)
        );
    }
}
