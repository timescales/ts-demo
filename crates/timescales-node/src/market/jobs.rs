//! Jobs: each performs one transition of an epoch, or observes that
//! the chain already made it, persists the result and reports the epoch's
//! new row. Every job starts with a store barrier, so the writes the actor
//! emitted before spawning it are durable, and reads the row from the
//! store. Every chain step goes through the idempotent `MarketChain`
//! operations, so a job that is interrupted anywhere can simply run
//! again.
//!
//! What a job does for a given (phase x chain status) is the table:
//! [`super::recover::action`] is consulted by the jobs and by start-up
//! recovery alike.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use timescales_auction::collateral::BalanceSheet;
use timescales_auction::orderbook::OrderStateTable;
use timescales_chain::program::{AbortReason, BatchAccount, BatchStatus, GovernanceChange};
use timescales_chain::{
    BatchPredicate, ChainError, ChangeOutcome, CommitOutcome, Level, MarketChain, RevealOutcome,
    SolanaRpc, TxSigner,
};
use timescales_core::{Decode, Encode, Hash32};
use timescales_service::api::{B58, B58Sig, Event, Hex32, U64};
use timescales_service::relay::{ClosedBatch, Relay};
use timescales_service::store::StoreError;
use timescales_service::store::node::{EpochPatch, EpochRow, NodeRepo, Phase, Retention};
use timescales_service::wire::CommitteeDescription;
use tokio::time::Instant;

use super::recover::{Action, ChainState, action};
use super::{FenceReason, Job, JobKind, JobOutput, JobResult, MarketSettings, public_abort_reason};
use crate::archive::{Archive, Record, Terminal};
use crate::clock::Clock;
use crate::config::ExecutionConfig;
use crate::events::EventBus;
use crate::exec::{Enclaves, execute_job, fetch_and_post};
use crate::intake::Eligibility;
use crate::keys::KeyDirectory;
use crate::telemetry::NodeMetrics;
use crate::{Address, ExecClient};

/// Everything a job of one market may use.
pub struct JobCtx {
    pub market: Address,
    pub settings: Arc<MarketSettings>,
    pub chain: Arc<dyn MarketChain>,
    pub rpc: Arc<dyn SolanaRpc>,
    pub repo: Arc<NodeRepo>,
    pub exec: Arc<dyn ExecClient>,
    pub enclaves: Arc<Enclaves>,
    pub exec_cfg: ExecutionConfig,
    pub keys: Arc<KeyDirectory>,
    pub committee: CommitteeDescription,
    pub relay_signer: Arc<dyn TxSigner>,
    pub cranker: Arc<dyn TxSigner>,
    pub clock: Arc<dyn Clock>,
    pub events: Arc<EventBus>,
    pub metrics: Arc<NodeMetrics>,
    pub archive: Archive,
    pub eligibility: Arc<Eligibility>,
    /// Beacon finality before assembly (`release_commitment`).
    pub release_level: Level,
    /// Wall time of one slot, for waits measured in slots.
    pub slot_ms: u64,
    pub retention: Retention,
    pub backup_dir: PathBuf,
    /// Longest a job waits on the chain before it reports a retry.
    pub wait: Duration,
}

impl core::fmt::Debug for JobCtx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JobCtx")
            .field("market", &bs58::encode(self.market).into_string())
            .finish_non_exhaustive()
    }
}

/// Why a job stopped early.
#[derive(Debug)]
pub(crate) enum Stop {
    Retry(String, u64),
    Failed(String),
    Fence(FenceReason),
}

impl From<StoreError> for Stop {
    fn from(e: StoreError) -> Self {
        match e {
            // A closed store is fail-stop: the node exits through its
            // readiness check. Retrying cannot help.
            StoreError::Closed => Stop::Fence(FenceReason::Store("store closed".into())),
            StoreError::Full => Stop::Retry("store queue full".into(), 200),
            other => Stop::Failed(other.to_string()),
        }
    }
}

impl From<ChainError> for Stop {
    fn from(e: ChainError) -> Self {
        Stop::Retry(e.to_string(), 1_000)
    }
}

pub(crate) type Step<T> = Result<T, Stop>;

fn finish(r: Step<JobOutput>) -> JobResult {
    match r {
        Ok(o) => JobResult::Done(o),
        Err(Stop::Retry(detail, after_ms)) => JobResult::Retry { detail, after_ms },
        Err(Stop::Failed(detail)) => JobResult::Failed(detail),
        Err(Stop::Fence(reason)) => JobResult::Done(JobOutput::Fence(reason)),
    }
}

impl JobCtx {
    pub(crate) fn now(&self) -> u64 {
        self.clock.now_ms()
    }

    pub(crate) async fn row(&self, e: u64) -> Step<EpochRow> {
        self.repo
            .epoch(self.market, e)
            .await?
            .ok_or_else(|| Stop::Failed(format!("epoch {e} has no row")))
    }

    pub(crate) async fn advance(&self, e: u64, to: Phase, mut patch: EpochPatch) -> Step<EpochRow> {
        patch.updated_at_ms = Some(self.now());
        self.repo.advance(self.market, e, to, patch).await?;
        self.row(e).await
    }

    pub(crate) async fn publish(&self, events: Vec<Event>) {
        let events = events.into_iter().map(|e| (Some(self.market), e)).collect();
        if let Err(e) = self.events.publish(events, self.now()).await {
            tracing::warn!(error = %e, "event not published");
        }
    }

    pub(crate) fn b58(&self) -> B58 {
        B58(self.market)
    }

    pub(crate) async fn batch(&self, e: u64) -> Step<Option<BatchAccount>> {
        Ok(self.chain.batch(e, Level::Confirmed).await?)
    }

    /// The chain state of epoch `e`.
    pub(crate) async fn chain_state(&self, e: u64) -> Step<(ChainState, Option<BatchAccount>)> {
        let batch = self.batch(e).await?;
        let state = match &batch {
            Some(b) => ChainState::from(b.status),
            None => {
                let m = self.chain.market(Level::Confirmed).await?;
                if m.last_committed >= e {
                    ChainState::NoBatchCommitted
                } else {
                    ChainState::NoBatch
                }
            }
        };
        Ok((state, batch))
    }

    pub(crate) fn wait_ms(&self, slots: u64) -> u64 {
        slots
            .saturating_mul(self.slot_ms)
            .clamp(self.slot_ms, 30_000)
    }

    /// Marks the epoch aborted as the chain shows it: the
    /// carried order state stays that of the last settled epoch.
    pub(crate) async fn mark_aborted(
        &self,
        e: u64,
        batch: Option<&BatchAccount>,
    ) -> Step<EpochRow> {
        let row = self.row(e).await?;
        let reason = batch
            .and_then(|b| b.abort_reason)
            .or_else(|| row.abort_reason.and_then(super::abort_reason))
            .unwrap_or(AbortReason::Admin);
        let slot = self.chain.slot(Level::Confirmed).await.unwrap_or(0);
        let row = self
            .advance(
                e,
                Phase::Aborted,
                EpochPatch {
                    abort_reason: Some(reason as u8),
                    terminal_slot: Some(slot),
                    ..EpochPatch::default()
                },
            )
            .await?;
        self.metrics
            .epoch_aborts
            .get_or_create(
                &self
                    .metrics
                    .with(&self.market, &[("reason", reason_label(reason))]),
            )
            .inc();
        self.publish(vec![Event::EpochAborted {
            market: self.b58(),
            epoch: U64(e),
            reason: public_abort_reason(reason),
        }])
        .await;
        self.write_archive(&row, Terminal::Aborted).await;
        Ok(row)
    }

    /// Starts an abort the node decided on (abort triggers).
    pub(crate) async fn begin_abort(
        &self,
        e: u64,
        reason: AbortReason,
        detail: &str,
        earliest_slot: Option<u64>,
    ) -> Step<EpochRow> {
        let row = self
            .advance(
                e,
                Phase::Aborting,
                EpochPatch {
                    abort_reason: Some(reason as u8),
                    abort_detail: Some(detail.to_owned()),
                    ..EpochPatch::default()
                },
            )
            .await?;
        tracing::warn!(
            epoch = e,
            reason = reason_label(reason),
            detail,
            "aborting epoch"
        );
        self.publish(vec![Event::EpochAborting {
            market: self.b58(),
            epoch: U64(e),
            reason: public_abort_reason(reason),
            earliest_slot: earliest_slot.map(U64),
        }])
        .await;
        Ok(row)
    }

    /// Archives a terminal epoch's public data, when it has any.
    pub(crate) async fn write_archive(&self, row: &EpochRow, terminal: Terminal) {
        let Ok(Some(result)) = super::store::result(&self.repo, self.market, row.epoch).await
        else {
            return;
        };
        if !row.artifacts_public {
            return;
        }
        let record = Record {
            epoch: row.epoch,
            terminal,
            terminal_slot: row.terminal_slot.unwrap_or(0),
            header: row.header.clone(),
            receipt: result.receipt,
            artifacts: result.artifacts,
            attestation: result.attestation,
            cosigs: result.cosigs,
        };
        if let Err(e) = self.archive.write(&self.market, &record) {
            tracing::error!(epoch = row.epoch, error = %e, "archive write failed");
        }
    }

    /// The carried order state epoch `e` executes against: that of the
    /// newest settled epoch before it (an aborted epoch changes nothing).
    pub(crate) async fn prior_state(&self, e: u64) -> Step<OrderStateTable> {
        let Some(from) = super::store::carried_state_epoch(&self.repo, self.market, e).await?
        else {
            return Ok(OrderStateTable::default());
        };
        let (bytes, root, _) = self
            .repo
            .order_state(self.market, from)
            .await?
            .ok_or_else(|| Stop::Failed(format!("order state of epoch {from} is missing")))?;
        let table = OrderStateTable::decode_exact(&bytes)
            .map_err(|_| Stop::Failed(format!("order state of epoch {from} does not decode")))?;
        if table.root() != root {
            return Err(Stop::Fence(FenceReason::StateDivergence));
        }
        Ok(table)
    }

    /// `Market.prev_receipt` as it was while `e` was in flight.
    pub(crate) async fn prev_receipt(&self, e: u64) -> Step<Hash32> {
        let m = self.chain.market(Level::Confirmed).await?;
        if m.last_settled + 1 == e {
            return Ok(m.prev_receipt);
        }
        match super::store::prev_receipt_before(&self.repo, self.market, e).await? {
            Some(bytes) => timescales_auction::receipts::ExecutionReceipt::decode_exact(&bytes)
                .map(|r| r.digest())
                .map_err(|_| Stop::Failed("a stored receipt does not decode".into())),
            None => Ok(Hash32::ZERO),
        }
    }
}

pub(crate) fn reason_label(r: AbortReason) -> &'static str {
    match r {
        AbortReason::Admin => "admin",
        AbortReason::Relay => "relay",
        AbortReason::BeaconExpired => "beacon_expired",
        AbortReason::ExecTimeout => "exec_timeout",
        AbortReason::SettleTimeout => "settle_timeout",
        AbortReason::QuorumTimeout => "quorum_timeout",
    }
}

/// Runs `job` to completion.
pub async fn run(ctx: Arc<JobCtx>, job: Job) -> JobResult {
    let e = job.epoch;
    let started = std::time::Instant::now();
    if let Some(relay) = job.relay {
        return close(&ctx, e, *relay).await;
    }
    if let Err(err) = ctx.repo.store().barrier().await {
        return finish(Err(err.into()));
    }
    let r = match job.kind {
        JobKind::Close => Err(Stop::Failed("close without the relay".into())),
        JobKind::Commit => commit(&ctx, e).await,
        JobKind::Snapshot => snapshot(&ctx, e).await,
        JobKind::Reveal => reveal(&ctx, e).await,
        JobKind::Assemble => assemble(&ctx, e).await,
        JobKind::Execute => execute_job(&ctx, e).await,
        JobKind::Settle => crate::settle::settle_job(&ctx, e).await,
        JobKind::Abort => abort(&ctx, e).await,
        JobKind::ApplyChange => apply_change(&ctx).await,
        JobKind::Reclaim => reclaim(&ctx, e).await,
        JobKind::Prune => prune(&ctx, e).await,
        JobKind::Backup => backup(&ctx, e).await,
    };
    ctx.metrics
        .observe_phase(&ctx.market, job.kind.as_str(), started.elapsed());
    finish(r)
}

/// Close (phase 2 -> 3): every acknowledged submission is durable
/// (barrier), the relay pads and fixes the batch on the blocking pool, and
/// the closed batch and its sorted leaves are written in one transaction.
async fn close(ctx: &JobCtx, e: u64, relay: Relay) -> JobResult {
    if let Err(err) = ctx.repo.store().barrier().await {
        return JobResult::Done(JobOutput::CloseFailed {
            relay: Box::new(relay),
            detail: err.to_string(),
        });
    }
    let now = ctx.now();
    let mut relay = relay;
    let joined = tokio::task::spawn_blocking(move || {
        let closed = relay
            .close(now)
            .map(|_| ())
            .and_then(|()| relay.take_closed());
        (relay, closed)
    })
    .await;
    let (relay, closed) = match joined {
        Ok(r) => r,
        Err(e) => return JobResult::Failed(format!("close task: {e}")),
    };
    let closed = match closed {
        Ok(c) => c,
        Err(err) => {
            return JobResult::Done(JobOutput::CloseFailed {
                relay: Box::new(relay),
                detail: err.to_string(),
            });
        }
    };
    let bytes = closed.to_bytes();
    let leaves: Vec<u8> = closed.leaves.iter().flat_map(|l| l.to_bytes()).collect();
    let count = closed.real + closed.cover;
    // The relay already freed its slot: the closed batch must reach the
    // store, or the market stops rather than open the next epoch.
    let mut attempts = 0;
    loop {
        attempts += 1;
        match ctx
            .repo
            .close_epoch(
                ctx.market,
                e,
                bytes.clone(),
                leaves.clone(),
                closed.root,
                count,
                closed.real,
                closed.cover,
            )
            .await
        {
            Ok(()) => break,
            Err(err) if attempts < 5 && err != StoreError::Closed => {
                tracing::warn!(epoch = e, error = %err, "closed batch not written; retrying");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(err) => {
                tracing::error!(epoch = e, error = %err, "closed batch not written");
                return JobResult::Done(JobOutput::Fence(FenceReason::Store(format!(
                    "closed batch of epoch {e} not written: {err}"
                ))));
            }
        }
    }
    let labels = |kind: &str| ctx.metrics.with(&ctx.market, &[("kind", kind)]);
    ctx.metrics
        .batch_envelopes
        .get_or_create(&labels("real"))
        .observe(f64::from(closed.real));
    ctx.metrics
        .batch_envelopes
        .get_or_create(&labels("cover"))
        .observe(f64::from(closed.cover));
    match ctx.row(e).await {
        Ok(row) => JobResult::Done(JobOutput::Closed {
            relay: Box::new(relay),
            row: Box::new(row),
        }),
        Err(stop) => finish(Err(stop)),
    }
}

/// The landed CommitBatch signature from the journal, zero when unknown
/// (another process committed it).
async fn commit_signature(ctx: &JobCtx, e: u64) -> [u8; 64] {
    ctx.repo
        .txs_for(ctx.market, e)
        .await
        .ok()
        .and_then(|txs| {
            txs.into_iter()
                .rev()
                .find(|t| t.op == "commit" && t.status == "landed")
                .map(|t| t.signature)
        })
        .unwrap_or([0; 64])
}

/// Commit (phases 3 -> 4 -> 5, rows closed/committing).
async fn commit(ctx: &JobCtx, e: u64) -> Step<JobOutput> {
    let row = ctx.row(e).await?;
    let (Some(root), Some(count), Some(terms)) = (row.root, row.envelope_count, row.terms_digest)
    else {
        return Err(Stop::Failed(format!("epoch {e} has no closed batch")));
    };
    match row.phase {
        Phase::Closed => {
            let m = ctx.chain.market(Level::Confirmed).await?;
            if m.last_committed < e {
                if m.halted {
                    return Ok(JobOutput::Halted);
                }
                let slot = ctx.chain.slot(Level::Confirmed).await?;
                if let Some(p) = &m.pending
                    && p.change.between_batches()
                    && slot >= p.eta_slot
                {
                    return Ok(JobOutput::ChangeDue {
                        kind: p.change.kind(),
                    });
                }
                if m.in_flight() || m.last_committed + 1 != e {
                    return Err(Stop::Retry("the previous batch is in flight".into(), 1_000));
                }
            }
            // Durable before anything is signed for this root.
            ctx.advance(e, Phase::Committing, EpochPatch::default())
                .await?;
        }
        Phase::Committing => {}
        _ => return Ok(JobOutput::Row(Box::new(row))),
    }
    let outcome = ctx
        .chain
        .ensure_committed(e, root, count, terms, ctx.relay_signer.clone())
        .await;
    let outcome = match outcome {
        Ok(o) => o,
        Err(err) => {
            ctx.metrics.chain_op("commit", "error");
            return Err(err.into());
        }
    };
    match outcome {
        CommitOutcome::Committed { slot } => {
            ctx.metrics.chain_op("commit", "ok");
            let sig = commit_signature(ctx, e).await;
            let row = ctx
                .advance(
                    e,
                    Phase::Committed,
                    EpochPatch {
                        commit_slot: Some(slot),
                        commit_sig: Some(sig),
                        ..EpochPatch::default()
                    },
                )
                .await?;
            ctx.publish(vec![Event::EpochCommitted {
                market: ctx.b58(),
                epoch: U64(e),
                root: Hex32(root.0),
                count,
                slot: U64(slot),
                signature: B58Sig(sig),
            }])
            .await;
            Ok(JobOutput::Row(Box::new(row)))
        }
        CommitOutcome::Equivocation { onchain_root } => {
            ctx.metrics
                .equivocation_detected
                .get_or_create(&ctx.metrics.market(&ctx.market))
                .inc();
            tracing::error!(
                epoch = e,
                ours = %Hex32(root.0),
                onchain = %Hex32(onchain_root.0),
                "TimescalesEquivocation: the chain holds another root for this epoch"
            );
            Err(Stop::Fence(FenceReason::Equivocation))
        }
        CommitOutcome::OutOfOrder { .. } => Err(Stop::Fence(FenceReason::StateDivergence)),
        CommitOutcome::InFlight { .. } => {
            Err(Stop::Retry("the previous batch is in flight".into(), 1_000))
        }
        CommitOutcome::ChangeDue { kind } => Ok(JobOutput::ChangeDue { kind }),
        CommitOutcome::Halted => Ok(JobOutput::Halted),
    }
}

/// Snapshot (phase 5 -> 6): every trader's available balance for
/// batch `e` at a slot at or after the commit.
async fn snapshot(ctx: &JobCtx, e: u64) -> Step<JobOutput> {
    let row = ctx.row(e).await?;
    if row.phase != Phase::Committed {
        return Ok(JobOutput::Row(Box::new(row)));
    }
    let (state, batch) = ctx.chain_state(e).await?;
    match action(Some(row.phase), state) {
        Action::Fence => return Err(Stop::Fence(FenceReason::StateDivergence)),
        Action::MarkAborted => {
            return Ok(JobOutput::Row(Box::new(
                ctx.mark_aborted(e, batch.as_ref()).await?,
            )));
        }
        // Settled on chain: the artifacts, not a snapshot, finish it.
        Action::FetchSettled => return Ok(JobOutput::Row(Box::new(fetch_and_post(ctx, e).await?))),
        _ => {}
    }
    let commit_slot = row
        .commit_slot
        .or_else(|| batch.as_ref().map(|b| b.commit_slot))
        .unwrap_or(0);
    let late = batch
        .as_ref()
        .is_some_and(|b| b.status >= BatchStatus::BeaconRevealed);
    let snap = ctx.chain.trader_snapshot(commit_slot).await?;
    let sheet = snap.balance_sheet(e);
    ctx.repo
        .put_snapshot(ctx.market, e, sheet.to_bytes(), snap.slot)
        .await?;
    ctx.eligibility.seed(ctx.market, &snap);
    if late {
        ctx.metrics
            .snapshot_late
            .get_or_create(&ctx.metrics.market(&ctx.market))
            .inc();
        tracing::warn!(
            epoch = e,
            "balance snapshot taken after the beacon was revealed"
        );
    }
    let row = ctx
        .advance(
            e,
            Phase::Snapshotted,
            EpochPatch {
                snapshot_slot: Some(snap.slot),
                snapshot_late: Some(late),
                commit_slot: Some(commit_slot),
                ..EpochPatch::default()
            },
        )
        .await?;
    Ok(JobOutput::Row(Box::new(row)))
}

/// Reveal (phase 6 -> 7): `RevealBeacon` once `slot > commit_slot +
/// 2d`, then the reveal at `release_commitment`.
async fn reveal(ctx: &JobCtx, e: u64) -> Step<JobOutput> {
    let row = ctx.row(e).await?;
    if row.phase != Phase::Snapshotted {
        return Ok(JobOutput::Row(Box::new(row)));
    }
    let (state, batch) = ctx.chain_state(e).await?;
    match action(Some(row.phase), state) {
        Action::Fence => return Err(Stop::Fence(FenceReason::StateDivergence)),
        Action::MarkAborted => {
            return Ok(JobOutput::Row(Box::new(
                ctx.mark_aborted(e, batch.as_ref()).await?,
            )));
        }
        Action::FetchSettled => return Ok(JobOutput::Row(Box::new(fetch_and_post(ctx, e).await?))),
        _ => {}
    }
    if state == ChainState::Committed {
        match ctx.chain.ensure_revealed(e, ctx.cranker.clone()).await? {
            RevealOutcome::Revealed { .. } => ctx.metrics.chain_op("reveal", "ok"),
            RevealOutcome::NotReady { slots_left } => {
                return Err(Stop::Retry(String::new(), ctx.wait_ms(slots_left)));
            }
            RevealOutcome::Expired => {
                let m = ctx.chain.market(Level::Confirmed).await?;
                let commit = batch.as_ref().map_or(0, |b| b.commit_slot);
                let earliest =
                    commit + u64::from(m.beacon_delay_slots) + super::phase::REVEAL_WINDOW + 1;
                let row = ctx
                    .begin_abort(
                        e,
                        AbortReason::BeaconExpired,
                        "the beacon was not revealed in its window",
                        Some(earliest),
                    )
                    .await?;
                return Ok(JobOutput::Row(Box::new(row)));
            }
            RevealOutcome::Terminal(BatchStatus::Aborted) => {
                return Ok(JobOutput::Row(Box::new(ctx.mark_aborted(e, None).await?)));
            }
            RevealOutcome::Terminal(_) => {
                return Ok(JobOutput::Row(Box::new(fetch_and_post(ctx, e).await?)));
            }
        }
    }
    // No key is released before the reveal is final, and no header is
    // assembled over a beacon a fork could change.
    let deadline = Instant::now() + ctx.wait;
    let b = match ctx
        .chain
        .wait_batch(
            e,
            BatchPredicate::AtLeast(BatchStatus::BeaconRevealed),
            ctx.release_level,
            deadline,
        )
        .await
    {
        Ok(b) => b,
        Err(err) => {
            return Err(Stop::Retry(
                format!("waiting for reveal finality: {err}"),
                1_000,
            ));
        }
    };
    if b.status == BatchStatus::Aborted {
        return Ok(JobOutput::Row(Box::new(
            ctx.mark_aborted(e, Some(&b)).await?,
        )));
    }
    let row = ctx
        .advance(
            e,
            Phase::Revealed,
            EpochPatch {
                beacon: Some(b.beacon),
                reveal_slot: Some(b.reveal_slot),
                ..EpochPatch::default()
            },
        )
        .await?;
    ctx.publish(vec![Event::EpochRevealed {
        market: ctx.b58(),
        epoch: U64(e),
        beacon: Hex32(b.beacon.0),
        beacon_slots: [U64(b.beacon_slot_a), U64(b.beacon_slot_b)],
        finalized: ctx.release_level == Level::Finalized,
    }])
    .await;
    Ok(JobOutput::Row(Box::new(row)))
}

/// Assemble (phase 7 -> 8): the header v2 over the closed batch, the
/// beacon, the snapshot, the carried state and the previous receipt.
/// Deterministic, so recovery can redo it.
async fn assemble(ctx: &JobCtx, e: u64) -> Step<JobOutput> {
    let row = ctx.row(e).await?;
    if row.phase != Phase::Revealed {
        return Ok(JobOutput::Row(Box::new(row)));
    }
    if let Some((header, _)) = ctx.repo.sealed(ctx.market, e).await? {
        let row = ctx
            .advance(
                e,
                Phase::Sealed,
                EpochPatch {
                    header: Some(header.to_vec()),
                    ..EpochPatch::default()
                },
            )
            .await?;
        return Ok(JobOutput::Row(Box::new(row)));
    }
    let header = assemble_header(ctx, &row).await?;
    let row = ctx
        .advance(
            e,
            Phase::Sealed,
            EpochPatch {
                header: Some(header.to_vec()),
                ..EpochPatch::default()
            },
        )
        .await?;
    Ok(JobOutput::Row(Box::new(row)))
}

/// Builds and stores the sealed batch of `row`'s epoch. Returns its header.
pub(crate) async fn assemble_header(ctx: &JobCtx, row: &EpochRow) -> Step<[u8; 283]> {
    let e = row.epoch;
    let closed = super::store::closed_batch(&ctx.repo, ctx.market, e)
        .await?
        .ok_or_else(|| Stop::Failed(format!("closed batch of epoch {e} is missing")))?;
    let closed = ClosedBatch::decode_exact(&closed)
        .map_err(|err| Stop::Failed(format!("closed batch does not decode: {err}")))?;
    let (sheet, _) = ctx
        .repo
        .snapshot(ctx.market, e)
        .await?
        .ok_or_else(|| Stop::Failed(format!("balance snapshot of epoch {e} is missing")))?;
    let sheet = BalanceSheet::decode_exact(&sheet)
        .map_err(|err| Stop::Failed(format!("balance snapshot does not decode: {err}")))?;
    let prior = ctx.prior_state(e).await?;
    let m = ctx.chain.market(Level::Confirmed).await?;
    if m.last_settled + 1 == e && prior.root() != m.state_root {
        tracing::error!(
            epoch = e,
            "carried order state differs from Market.state_root"
        );
        return Err(Stop::Fence(FenceReason::StateDivergence));
    }
    let prev = ctx.prev_receipt(e).await?;
    let beacon = row
        .beacon
        .ok_or_else(|| Stop::Failed(format!("epoch {e} has no beacon")))?;
    let sealed = tokio::task::spawn_blocking(move || closed.assemble(beacon, sheet, prior, prev))
        .await
        .map_err(|err| Stop::Failed(format!("assembly task: {err}")))?
        .map_err(|err| {
            tracing::error!(epoch = e, error = %err, "the closed batch does not assemble");
            Stop::Fence(FenceReason::StateDivergence)
        })?;
    let header_bytes = sealed.batch.header.to_bytes();
    let header: [u8; 283] = header_bytes
        .try_into()
        .map_err(|_| Stop::Failed("header is not 283 bytes".into()))?;
    ctx.repo
        .put_sealed(ctx.market, e, header, sealed.batch.to_bytes())
        .await?;
    Ok(header)
}

/// Abort: `ensure_aborted`. A superseded abort goes back to
/// the phase the batch status implies ("abort"), except a relay abort
/// that missed its window, which becomes a beacon_expired abort.
async fn abort(ctx: &JobCtx, e: u64) -> Step<JobOutput> {
    let row = ctx.row(e).await?;
    if row.phase != Phase::Aborting {
        return Ok(JobOutput::Row(Box::new(row)));
    }
    let reason = row
        .abort_reason
        .and_then(super::abort_reason)
        .unwrap_or(AbortReason::ExecTimeout);
    let signer = if reason == AbortReason::Relay {
        ctx.relay_signer.clone()
    } else {
        ctx.cranker.clone()
    };
    if reason == AbortReason::Admin {
        // The node holds no admin key: the admin multisig sends it.
        let b = ctx.batch(e).await?;
        return match b.as_ref().map(|b| b.status) {
            Some(BatchStatus::Aborted) => Ok(JobOutput::Row(Box::new(
                ctx.mark_aborted(e, b.as_ref()).await?,
            ))),
            _ => Err(Stop::Retry("waiting for the admin's abort".into(), 5_000)),
        };
    }
    match ctx.chain.ensure_aborted(e, reason, signer).await? {
        timescales_chain::AbortOutcome::Aborted { .. }
        | timescales_chain::AbortOutcome::AlreadyTerminal(BatchStatus::Aborted) => {
            let b = ctx.batch(e).await?;
            Ok(JobOutput::Row(Box::new(
                ctx.mark_aborted(e, b.as_ref()).await?,
            )))
        }
        timescales_chain::AbortOutcome::NotAllowedYet { slots_left } => {
            Err(Stop::Retry(String::new(), ctx.wait_ms(slots_left)))
        }
        timescales_chain::AbortOutcome::Superseded(BatchStatus::Committed)
            if reason == AbortReason::Relay =>
        {
            // Decided inside the relay window, sent after it: the epoch
            // still cannot proceed, so it waits for beacon_expired
            // instead of revealing the beacon.
            let m = ctx.chain.market(Level::Confirmed).await?;
            let commit = ctx.batch(e).await?.map_or(0, |b| b.commit_slot);
            let earliest =
                commit + u64::from(m.beacon_delay_slots) + super::phase::REVEAL_WINDOW + 1;
            let row = ctx
                .begin_abort(
                    e,
                    AbortReason::BeaconExpired,
                    "the relay abort window passed before the abort landed",
                    Some(earliest),
                )
                .await?;
            Ok(JobOutput::Row(Box::new(row)))
        }
        timescales_chain::AbortOutcome::AlreadyTerminal(status)
        | timescales_chain::AbortOutcome::Superseded(status) => {
            tracing::info!(epoch = e, ?status, "abort superseded by the chain");
            let to = rederive(ctx, e, status).await?;
            super::store::clear_abort(&ctx.repo, ctx.market, e).await?;
            let row = ctx.advance(e, to, EpochPatch::default()).await?;
            Ok(JobOutput::Row(Box::new(row)))
        }
    }
}

/// The phase an epoch resumes at after the chain superseded its abort:
/// the furthest one whose artefact is stored, and the jobs of that phase
/// follow the chain from there.
async fn rederive(ctx: &JobCtx, e: u64, status: BatchStatus) -> Step<Phase> {
    if status >= BatchStatus::ReceiptPosted && ctx.repo.sealed(ctx.market, e).await?.is_some() {
        return Ok(Phase::Sealed);
    }
    if ctx.repo.snapshot(ctx.market, e).await?.is_some() {
        return Ok(Phase::Snapshotted);
    }
    Ok(Phase::Committed)
}

/// Applies a due between-batches change before the next commit.
async fn apply_change(ctx: &JobCtx) -> Step<JobOutput> {
    match ctx.chain.ensure_change_applied(ctx.cranker.clone()).await? {
        ChangeOutcome::Applied { kind } => {
            ctx.metrics.chain_op("apply_change", "ok");
            tracing::info!(kind, "governance change applied");
            if kind == GovernanceChange::SET_COMMITTEE_DIGEST {
                let m = ctx.chain.market(Level::Confirmed).await?;
                ctx.keys
                    .set_allowed(m.committee_digest, m.prev_committee_digest);
            }
            Ok(JobOutput::ChangeApplied { kind: Some(kind) })
        }
        ChangeOutcome::NothingDue => Ok(JobOutput::ChangeApplied { kind: None }),
        ChangeOutcome::NotYet { slots_left } => {
            Err(Stop::Retry(String::new(), ctx.wait_ms(slots_left)))
        }
        ChangeOutcome::InFlight => Err(Stop::Retry("a batch is in flight".into(), 1_000)),
    }
}

async fn reclaim(ctx: &JobCtx, e: u64) -> Step<JobOutput> {
    ctx.chain.ensure_reclaimed(e, ctx.cranker.clone()).await?;
    ctx.metrics.chain_op("reclaim", "ok");
    Ok(JobOutput::Nothing)
}

async fn prune(ctx: &JobCtx, last_terminal: u64) -> Step<JobOutput> {
    let report = ctx
        .repo
        .prune(ctx.market, ctx.now(), last_terminal, ctx.retention)
        .await?;
    ctx.keys.forget_before(last_terminal.saturating_add(1));
    tracing::debug!(
        rows = report.rows_deleted,
        wallets = report.wallets_nulled,
        "pruned"
    );
    Ok(JobOutput::Nothing)
}

async fn backup(ctx: &JobCtx, epoch: u64) -> Step<JobOutput> {
    std::fs::create_dir_all(&ctx.backup_dir)
        .map_err(|e| Stop::Failed(format!("backup dir: {e}")))?;
    let dest = ctx
        .backup_dir
        .join(format!("node-epoch-{epoch:020}.sqlite"));
    let report = ctx.repo.backup(dest).await?;
    if report.integrity_ok {
        let ts = i64::try_from(ctx.now() / 1000).unwrap_or(i64::MAX);
        ctx.metrics
            .backup_last_success
            .get_or_create(&vec![("kind".to_owned(), "nightly".to_owned())])
            .set(ts);
    }
    Ok(JobOutput::Nothing)
}

impl From<BatchStatus> for ChainState {
    fn from(s: BatchStatus) -> Self {
        match s {
            BatchStatus::Committed => ChainState::Committed,
            BatchStatus::BeaconRevealed => ChainState::BeaconRevealed,
            BatchStatus::ReceiptPosted => ChainState::ReceiptPosted,
            BatchStatus::Verified => ChainState::Verified,
            BatchStatus::Settled => ChainState::Settled,
            BatchStatus::Aborted => ChainState::Aborted,
        }
    }
}
