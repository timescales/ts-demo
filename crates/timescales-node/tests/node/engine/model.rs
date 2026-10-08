//! Model test of the pure transition function: random sequences of
//! submissions, ticks, chain observations, job completions, job failures
//! and crashes (crash = drop the actor and its running jobs, rebuild it
//! from the modelled database) against a modelled chain that enforces the
//! program's rules. Jobs follow the real jobs' contract: they write the
//! database before acting on the chain, and the chain step is idempotent.
//!
//! Checked: never two commits with different roots for one epoch. Never a
//! commit while another batch is in flight. Never a relay abort at or
//! after `commit_slot + d`. An attempt row before every dispatch. Artifacts
//! never public before the quorum is on chain. Every acknowledged
//! submission in the committed batch of its epoch (or provably excluded).
//! At most one open, one waiting and one in-flight epoch. And every (phase x
//! chain status) pair has exactly one action.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use timescales_auction::BatchLeaf;
use timescales_chain::program::{AbortReason, MarketAccount};
use timescales_core::crypto::{Keypair, hash};
use timescales_core::identity::TraderKey;
use timescales_core::intent::{PrivateIntent, SealedEnvelope};
use timescales_core::{
    CommitmentScheme, Decode, Encode, EpochId, FeeBps, FlowMode, Hash32, Lots, MarketId,
    MarketParams, Order, OrderKind, Rationing, Role, Side, Tick,
};
use timescales_executor::{KeyProvider, LocalKeySchedule};
use timescales_node::config::{DecimalU64, IdlePolicyConfig, QuotaConfig};
use timescales_node::market::recover::{Action, Adopted, ChainState, action};
use timescales_node::market::{
    BundleFacts, ChainObservation, Cmd, Effect, IntakeItem, Job, JobKind, JobOutput, JobResult,
    MarketActor, MarketSettings, Now, Persist, Reply, RequestId, Restored,
};
use timescales_node::reference::Fixed;
use timescales_node::{SessionRef, VerifiedSubmission};
use timescales_service::relay::{
    ClosedBatch, EpochKeyCover, InclusionPromiseV2, OpenSnapshot, Padding, Relay, RelayConfig,
    Submission, prove_exclusion_v2, verify_submission,
};
use timescales_service::store::node::{EpochPatch, EpochRow, Phase, SubmissionRow};

const MARKET: [u8; 32] = [0x4d; 32];
const D: u64 = 4;
const SLOT_MS: u64 = 400;
const INTERVAL_MS: u64 = 4_000;
const EXEC_TIMEOUT: u64 = 150;

fn params() -> MarketParams {
    MarketParams {
        market: MarketId(9),
        base_lot_size: 1,
        tick_size: 1,
        band_half_width: 16,
        max_order_lots_log2: 20,
        max_orders_per_trader: 8,
        max_batch_envelopes: 1024,
        max_order_lifetime: 8,
        maker_fee: FeeBps(0),
        taker_fee: FeeBps(10),
        flow: FlowMode::DualFlow,
        rationing: Rationing::ProRata,
        commitment_scheme: CommitmentScheme::Sha256,
    }
}

fn relay_cfg() -> RelayConfig {
    RelayConfig {
        params: params(),
        market_address: MARKET,
        padding: Padding::PowerOfTwo { min: 4 },
        allow_masked: false,
        max_real: 64,
        carry_p: 0.0,
    }
}

fn relay_key() -> Arc<Keypair> {
    Arc::new(Keypair::from_seed([0x11; 32]))
}

fn keys() -> Arc<LocalKeySchedule> {
    Arc::new(LocalKeySchedule::new([0x22; 32]))
}

fn cover() -> Box<dyn timescales_service::relay::CoverSource> {
    Box::new(EpochKeyCover {
        keys: keys(),
        params: params(),
        masked: false,
    })
}

fn settings() -> Arc<MarketSettings> {
    Arc::new(MarketSettings {
        address: MARKET,
        params: params(),
        interval_ms: INTERVAL_MS,
        padding: Padding::PowerOfTwo { min: 4 },
        carry_p: 0.0,
        max_real: 64,
        park_ahead: 2,
        idle: IdlePolicyConfig::Commit,
        max_idle_extend: 0,
        quota: QuotaConfig {
            max_envelopes_per_wallet_per_epoch: 16,
            max_parked_per_wallet: 64,
            require_trader_account: true,
            min_available_value_quote: DecimalU64(1),
            min_value_per_envelope_quote: DecimalU64(1),
            ban_epochs: 4,
        },
        relay_key: relay_key(),
        min_relay_lamports: 0,
        reclaim_batches: false,
        backup_every_epochs: 0,
        private_keep_epochs: 64,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Status {
    Committed,
    Revealed,
    Posted { quorum: bool },
    Settled,
    Aborted,
}

#[derive(Clone, Debug)]
struct Batch {
    root: Hash32,
    leaves: Vec<BatchLeaf>,
    status: Status,
    commit_slot: u64,
    reveal_slot: u64,
}

/// The program's rules over one market.
#[derive(Default)]
struct Chain {
    slot: u64,
    last_committed: u64,
    last_settled: u64,
    batches: BTreeMap<u64, Batch>,
}

impl Chain {
    fn commit(&mut self, e: u64, closed: &ClosedBatch) -> Result<u64, &'static str> {
        if let Some(b) = self.batches.get(&e) {
            assert_eq!(
                b.root, closed.root,
                "two commits with different roots for epoch {e}"
            );
            return Ok(b.commit_slot);
        }
        if self.last_committed != self.last_settled {
            return Err("in flight");
        }
        assert_eq!(self.last_committed + 1, e, "commit out of order");
        self.last_committed = e;
        self.batches.insert(
            e,
            Batch {
                root: closed.root,
                leaves: closed.leaves.clone(),
                status: Status::Committed,
                commit_slot: self.slot,
                reveal_slot: 0,
            },
        );
        Ok(self.slot)
    }

    fn terminal(&mut self, e: u64, s: Status) {
        if let Some(b) = self.batches.get_mut(&e)
            && !matches!(b.status, Status::Settled | Status::Aborted)
        {
            b.status = s;
            self.last_settled = e;
        }
    }

    fn market(&self) -> MarketAccount {
        MarketAccount {
            bump: 0,
            layout_version: 2,
            halted: false,
            market_id: 9,
            creator: [1; 32],
            admin: [2; 32],
            pending_admin: None,
            relay: relay_key().public(),
            base_mint: [3; 32],
            quote_mint: [4; 32],
            base_vault: [5; 32],
            quote_vault: [6; 32],
            params: params(),
            params_digest: Hash32::ZERO,
            committee_digest: Hash32([7; 32]),
            executor_count: 3,
            receipt_quorum: 2,
            executors: [[0; 32]; 8],
            beacon_delay_slots: u16::try_from(D).unwrap(),
            timelock_slots: 20,
            exec_timeout_slots: EXEC_TIMEOUT,
            settle_timeout_slots: 1_500,
            last_committed: self.last_committed,
            last_settled: self.last_settled,
            last_progress_slot: self.slot,
            fees_accrued: 0,
            fees_claimed: 0,
            prev_receipt: Hash32::ZERO,
            state_root: Hash32::ZERO,
            pending: None,
            salt: [0; 32],
            prev_committee_digest: Hash32::ZERO,
        }
    }
}

/// The node's database as the effects and jobs wrote it.
#[derive(Default)]
struct Db {
    epochs: BTreeMap<u64, EpochRow>,
    closed: BTreeMap<u64, ClosedBatch>,
    submissions: BTreeMap<u64, Vec<SubmissionRow>>,
    parked: BTreeMap<u64, Vec<SubmissionRow>>,
    attempts: BTreeMap<u64, u32>,
    results: BTreeSet<u64>,
}

impl Db {
    fn advance(&mut self, e: u64, to: Phase, patch: EpochPatch) -> EpochRow {
        let row = self.epochs.get_mut(&e).expect("row");
        assert!(row.phase.can_move_to(to), "{:?} -> {to:?}", row.phase);
        row.phase = to;
        if let Some(s) = patch.commit_slot {
            row.commit_slot = Some(s);
        }
        if let Some(s) = patch.reveal_slot {
            row.reveal_slot = Some(s);
        }
        if let Some(r) = patch.abort_reason {
            row.abort_reason = Some(r);
        }
        if let Some(p) = patch.artifacts_public {
            row.artifacts_public = p;
        }
        row.clone()
    }

    fn apply(&mut self, p: Persist) {
        match p {
            Persist::OpenEpoch { row, injected } => {
                let e = row.epoch;
                let parked = self.parked.remove(&e).unwrap_or_default();
                let subs = self.submissions.entry(e).or_default();
                for (c, w) in injected {
                    let r = parked
                        .iter()
                        .find(|r| r.commitment == c && r.wallet == Some(w))
                        .expect("an injected envelope was parked");
                    subs.push(r.clone());
                }
                self.epochs.insert(e, *row);
            }
            Persist::Advance {
                epoch,
                phase,
                patch,
            } => {
                let mut row = self.epochs[&epoch].clone();
                if let Some(c) = patch.cutoff_ms {
                    row.cutoff_ms = Some(c);
                }
                if let Some(r) = patch.abort_reason {
                    row.abort_reason = Some(r);
                }
                assert!(row.phase.can_move_to(phase));
                row.phase = phase;
                self.epochs.insert(epoch, row);
            }
            Persist::Submission(row) => self.submissions.entry(row.epoch).or_default().push(*row),
            Persist::Parked(rows) => {
                for r in rows {
                    self.parked.entry(r.epoch).or_default().push(r);
                }
            }
            Persist::Retract { .. } | Persist::BundleServed { .. } => {}
        }
    }
}

struct Model {
    rng: StdRng,
    chain: Chain,
    db: Db,
    actor: MarketActor,
    now_ms: u64,
    jobs: Vec<Job>,
    acknowledged: Vec<(u64, InclusionPromiseV2)>,
    traders: Vec<(TraderKey, TraderKey)>,
    request: u64,
    nonce: u64,
}

fn restored(db: &Db, chain: &Chain, next: u64) -> Restored {
    let epochs: Vec<EpochRow> = db
        .epochs
        .values()
        .filter(|r| !r.phase.is_terminal())
        .cloned()
        .collect();
    let last_terminal = db
        .epochs
        .values()
        .rev()
        .find(|r| r.phase.is_terminal())
        .cloned();
    let mut relay = Relay::new(relay_cfg(), relay_key(), cover());
    let mut open_entries = Vec::new();
    if let Some(open) = epochs.iter().find(|r| r.phase == Phase::Open) {
        let subs = db.submissions.get(&open.epoch).cloned().unwrap_or_default();
        relay = Relay::restore(
            relay_cfg(),
            relay_key(),
            cover(),
            OpenSnapshot {
                epoch: EpochId(open.epoch),
                opens_at_ms: open.opens_at_ms.unwrap(),
                cutoff_ms: open.cutoff_ms.unwrap(),
                band: open.band.unwrap(),
                price_commitment: open.price_commitment.unwrap(),
                binding: open.binding.unwrap(),
                submissions: subs
                    .iter()
                    .map(|s| (s.submission.clone(), s.wallet.unwrap()))
                    .collect(),
            },
        )
        .expect("the open epoch restores");
        open_entries = subs
            .iter()
            .map(|s| {
                (
                    s.commitment,
                    s.wallet.unwrap(),
                    s.envelope_digest,
                    s.promise.clone(),
                )
            })
            .collect();
    }
    let parked = db
        .parked
        .values()
        .flatten()
        .map(|r| {
            let sub = Submission::decode_exact(&r.submission).unwrap();
            let inner = verify_submission(&relay_cfg(), &sub).unwrap();
            (
                r.clone(),
                VerifiedSubmission {
                    raw: r.submission.clone(),
                    inner,
                },
            )
        })
        .collect();
    let db_next = db.epochs.keys().max().map_or(1, |e| e + 1);
    Restored {
        epochs,
        last_terminal,
        relay,
        open_entries,
        parked,
        bundles: (1..next + 8).map(|e| (e, bundle(e))).collect(),
        served: Vec::new(),
        next_epoch: (chain.last_committed + 1).max(db_next),
        fenced: None,
        chain: None,
    }
}

fn bundle(e: u64) -> BundleFacts {
    BundleFacts {
        key_digest: hash(b"model/key", &e.to_le_bytes()),
        committee_digest: Hash32([7; 32]),
        epoch_pk: keys().epoch_public(MarketId(9), EpochId(e)).unwrap(),
        bytes: Vec::new(),
    }
}

fn actor(r: Restored) -> MarketActor {
    let factory: timescales_node::market::RelayFactory =
        Arc::new(|| Relay::new(relay_cfg(), relay_key(), cover()));
    MarketActor::new(
        settings(),
        r,
        Box::new(Fixed {
            market: MarketId(9),
            tick: Tick(100),
        }),
        factory,
    )
}

impl Model {
    fn new(seed: u64) -> Self {
        let chain = Chain {
            slot: 1_000,
            ..Chain::default()
        };
        let db = Db::default();
        let actor = actor(restored(&db, &chain, 1));
        let mut m = Model {
            rng: StdRng::seed_from_u64(seed),
            chain,
            db,
            actor,
            now_ms: 1_000_000,
            jobs: Vec::new(),
            acknowledged: Vec::new(),
            traders: (0..4)
                .map(|i| {
                    (
                        TraderKey::from_seed([i + 1; 32]),
                        TraderKey::from_seed([i + 0x41; 32]),
                    )
                })
                .collect(),
            request: 0,
            nonce: 0,
        };
        m.observe();
        m
    }

    fn now(&self) -> Now {
        Now {
            ms: self.now_ms,
            slot: self.chain.slot,
        }
    }

    fn on(&mut self, cmd: Cmd) {
        let now = self.now();
        let effects = self.actor.on(cmd, now);
        for e in effects {
            match e {
                Effect::Persist(p) => self.db.apply(p),
                Effect::Spawn(job) => {
                    assert!(
                        !self
                            .jobs
                            .iter()
                            .any(|j| j.epoch == job.epoch && j.kind == job.kind),
                        "two {:?} jobs for epoch {}",
                        job.kind,
                        job.epoch
                    );
                    if job.kind == JobKind::Execute {
                        let p = self.db.epochs[&job.epoch].phase;
                        assert!(matches!(p, Phase::Sealed | Phase::Executing), "{p:?}");
                    }
                    self.jobs.push(job);
                }
                Effect::Reply(Reply::Submit { results, .. }) => {
                    for r in results.into_iter().flatten() {
                        let p = InclusionPromiseV2::decode_exact(&r.promise_b64.0).unwrap();
                        self.acknowledged.push((r.epoch.0, p));
                    }
                }
                _ => {}
            }
        }
        self.check();
    }

    fn observe(&mut self) {
        let obs = ChainObservation {
            slot: self.chain.slot,
            market: self.chain.market(),
            batch: None,
            relay_lamports: None,
            cranker_lamports: None,
            program: None,
        };
        self.on(Cmd::ChainObserved(Box::new(obs)));
    }

    fn check(&self) {
        let rows: Vec<&EpochRow> = self.db.epochs.values().collect();
        let open = rows.iter().filter(|r| r.phase == Phase::Open).count();
        let closed = rows.iter().filter(|r| r.phase == Phase::Closed).count();
        let inflight = rows
            .iter()
            .filter(|r| r.phase >= Phase::Committing && !r.phase.is_terminal())
            .count();
        assert!(
            open <= 1 && closed <= 1 && inflight <= 1,
            "{open} {closed} {inflight}"
        );
        for r in &rows {
            if r.artifacts_public {
                let b = &self.chain.batches[&r.epoch];
                assert!(
                    matches!(b.status, Status::Posted { quorum: true } | Status::Settled),
                    "artifacts public before the quorum is on chain"
                );
            }
        }
    }

    fn submit(&mut self) {
        let Some(e) = self.actor.view(self.now()).open.map(|o| o.epoch) else {
            return;
        };
        let e = if self.rng.gen_bool(0.2) { e + 1 } else { e };
        let i = self.rng.gen_range(0..self.traders.len());
        self.nonce += 1;
        let (wallet, session) = &self.traders[i];
        let order = Order {
            market: MarketId(9),
            trader: wallet.id(),
            nonce: self.nonce,
            side: Side::Buy,
            role: Role::Taker,
            kind: OrderKind::Limit,
            limit: Tick(100),
            quantity: Lots(1),
            valid_from: EpochId(e),
            expires_at: EpochId(e),
        };
        let (intent, c) =
            PrivateIntent::place(&mut self.rng, wallet, CommitmentScheme::Sha256, order).unwrap();
        let pk = keys().epoch_public(MarketId(9), EpochId(e)).unwrap();
        let env =
            SealedEnvelope::seal(&mut self.rng, MarketId(9), EpochId(e), &pk, c, &intent).unwrap();
        let sub = Submission::sign(session, env, None);
        let v = VerifiedSubmission {
            raw: sub.to_bytes(),
            inner: verify_submission(&relay_cfg(), &sub).unwrap(),
        };
        self.request += 1;
        let session = SessionRef {
            session_key: session.id().0,
            wallet: wallet.id().0,
            market: Some(MARKET),
        };
        self.on(Cmd::Submit {
            request: RequestId(self.request),
            items: vec![IntakeItem {
                sub: v,
                received_at_ms: self.now_ms,
            }],
            session,
            quota: 16,
        });
    }

    /// Runs a job as the real one would: database first, then chain.
    fn finish(&mut self, job: Job) -> Option<JobResult> {
        let e = job.epoch;
        let fail = self.rng.gen_bool(0.15);
        let retry = || JobResult::Retry {
            detail: "modelled failure".into(),
            after_ms: 200,
        };
        let row = self.db.epochs.get(&e).cloned();
        Some(match job.kind {
            JobKind::Close => {
                let mut relay = job.relay.expect("close carries the relay");
                if fail {
                    return Some(JobResult::Done(JobOutput::CloseFailed {
                        relay,
                        detail: "modelled".into(),
                    }));
                }
                relay.close(self.now_ms).unwrap();
                let closed = relay.take_closed().unwrap();
                let row = self.db.advance(e, Phase::Closed, EpochPatch::default());
                let mut row = row;
                row.root = Some(closed.root);
                row.envelope_count = Some(closed.real + closed.cover);
                self.db.epochs.insert(e, row.clone());
                self.db.closed.insert(e, closed);
                JobResult::Done(JobOutput::Closed {
                    relay,
                    row: Box::new(row),
                })
            }
            JobKind::Commit => {
                let row = row?;
                if row.phase == Phase::Closed {
                    if self.chain.last_committed < e
                        && (self.chain.last_committed != self.chain.last_settled
                            || self.chain.last_committed + 1 != e)
                    {
                        return Some(retry());
                    }
                    self.db.advance(e, Phase::Committing, EpochPatch::default());
                }
                if fail {
                    return Some(retry());
                }
                match self.chain.commit(e, &self.db.closed[&e]) {
                    Ok(slot) => JobResult::Done(JobOutput::Row(Box::new(self.db.advance(
                        e,
                        Phase::Committed,
                        EpochPatch {
                            commit_slot: Some(slot),
                            ..EpochPatch::default()
                        },
                    )))),
                    Err(_) => retry(),
                }
            }
            JobKind::Snapshot => JobResult::Done(JobOutput::Row(Box::new(self.db.advance(
                e,
                Phase::Snapshotted,
                EpochPatch::default(),
            )))),
            JobKind::Reveal => {
                let b = self.chain.batches.get_mut(&e)?;
                if b.status == Status::Committed {
                    if self.chain.slot <= b.commit_slot + 2 * D {
                        return Some(JobResult::Retry {
                            detail: String::new(),
                            after_ms: SLOT_MS,
                        });
                    }
                    b.status = Status::Revealed;
                    b.reveal_slot = self.chain.slot;
                }
                let slot = b.reveal_slot;
                JobResult::Done(JobOutput::Row(Box::new(self.db.advance(
                    e,
                    Phase::Revealed,
                    EpochPatch {
                        reveal_slot: Some(slot),
                        ..EpochPatch::default()
                    },
                ))))
            }
            JobKind::Assemble => JobResult::Done(JobOutput::Row(Box::new(self.db.advance(
                e,
                Phase::Sealed,
                EpochPatch::default(),
            )))),
            JobKind::Execute => {
                let row = row?;
                let b = self.chain.batches.get(&e)?.clone();
                if b.status == Status::Revealed && self.chain.slot > b.reveal_slot + EXEC_TIMEOUT {
                    return Some(JobResult::Done(JobOutput::Row(Box::new(self.db.advance(
                        e,
                        Phase::Aborting,
                        EpochPatch {
                            abort_reason: Some(AbortReason::ExecTimeout as u8),
                            ..EpochPatch::default()
                        },
                    )))));
                }
                // The attempt row is durable before the request is sent.
                *self.db.attempts.entry(e).or_default() += 1;
                if row.phase == Phase::Sealed {
                    self.db.advance(e, Phase::Executing, EpochPatch::default());
                }
                if fail {
                    return Some(retry());
                }
                let quorum = self.rng.gen_bool(0.8);
                let batch = self.chain.batches.get_mut(&e)?;
                if batch.status == Status::Revealed {
                    batch.status = Status::Posted { quorum };
                }
                self.db.results.insert(e);
                if !matches!(
                    batch.status,
                    Status::Posted { quorum: true } | Status::Settled
                ) {
                    // Quorum not on chain: the result stays private.
                    if let Status::Posted { quorum: false } = batch.status {
                        batch.status = Status::Posted {
                            quorum: self.rng.gen_bool(0.5),
                        };
                    }
                    return Some(retry());
                }
                assert!(self.db.attempts[&e] > 0, "dispatch without an attempt row");
                JobResult::Done(JobOutput::Row(Box::new(self.db.advance(
                    e,
                    Phase::Posted,
                    EpochPatch {
                        artifacts_public: Some(true),
                        ..EpochPatch::default()
                    },
                ))))
            }
            JobKind::Settle => {
                if fail {
                    return Some(retry());
                }
                self.chain.terminal(e, Status::Settled);
                JobResult::Done(JobOutput::Row(Box::new(self.db.advance(
                    e,
                    Phase::Settled,
                    EpochPatch::default(),
                ))))
            }
            JobKind::Abort => {
                let row = row?;
                let b = self.chain.batches.get(&e)?.clone();
                if row.abort_reason == Some(AbortReason::Relay as u8) {
                    assert!(
                        self.chain.slot < b.commit_slot + D,
                        "relay abort at or after commit_slot + d"
                    );
                }
                if b.status == (Status::Posted { quorum: true }) {
                    // Superseded: the receipt made it.
                    return Some(JobResult::Done(JobOutput::Row(Box::new(self.db.advance(
                        e,
                        Phase::Sealed,
                        EpochPatch::default(),
                    )))));
                }
                self.chain.terminal(e, Status::Aborted);
                JobResult::Done(JobOutput::Row(Box::new(self.db.advance(
                    e,
                    Phase::Aborted,
                    EpochPatch::default(),
                ))))
            }
            _ => JobResult::Done(JobOutput::Nothing),
        })
    }

    fn crash(&mut self) {
        self.jobs.clear();
        let next = self.db.epochs.keys().max().map_or(1, |e| e + 1);
        self.actor = actor(restored(&self.db, &self.chain, next));
        self.observe();
    }

    fn step(&mut self) {
        match self.rng.gen_range(0..100) {
            0..=24 => self.submit(),
            25..=44 => {
                self.now_ms += self.rng.gen_range(0..INTERVAL_MS);
                self.chain.slot = self.chain.slot.max(self.now_ms / SLOT_MS);
                self.on(Cmd::Tick);
            }
            45..=59 => {
                self.chain.slot += self.rng.gen_range(1..20);
                self.observe();
            }
            60..=97 => {
                if self.jobs.is_empty() {
                    return;
                }
                let i = self.rng.gen_range(0..self.jobs.len());
                let job = self.jobs.swap_remove(i);
                let id = job.id;
                if let Some(result) = self.finish(job) {
                    self.on(Cmd::JobDone(id, result));
                }
            }
            _ => self.crash(),
        }
    }

    /// Every acknowledged envelope of a committed epoch is in its batch, or
    /// its promise proves the exclusion.
    fn check_promises(&self) {
        for (e, p) in &self.acknowledged {
            let Some(b) = self.chain.batches.get(e) else {
                continue;
            };
            let included = b.leaves.contains(&p.leaf());
            let count = u32::try_from(b.leaves.len()).unwrap();
            assert!(
                included || prove_exclusion_v2(p, &b.leaves, &MARKET, EpochId(*e), &b.root, count),
                "an acknowledged envelope of epoch {e} is neither committed nor provably excluded"
            );
        }
    }
}

/// The recovery table, one row per phase on disk
/// (`None`: the database has no row for the epoch), columns in
/// [`ChainState::ALL`] order: no Batch with `last_committed < e`, no Batch
/// with `last_committed >= e`, Committed, BeaconRevealed, ReceiptPosted,
/// Verified, Settled, Aborted.
fn d3_table() -> Vec<(Option<Phase>, [Action; 8])> {
    use Action::*;
    const F: Action = Fence;
    const AH: Action = Ahead;
    let adopt = [
        F,
        Adopt(Adopted::Committed),
        Adopt(Adopted::SnapReveal),
        Adopt(Adopted::Fetch),
        Adopt(Adopted::FetchSettle),
        Adopt(Adopted::FetchSettled),
        Adopt(Adopted::Aborted),
    ];
    let snap = [
        F,
        F,
        Snap,
        SnapReveal,
        SnapFetch,
        SnapFetchSettle,
        FetchSettled,
        MarkAborted,
    ];
    let exec = [F, F, F, Exec, Fetch, FetchSettle, FetchSettled, MarkAborted];
    let with = |first: Action, rest: [Action; 7]| {
        let mut row = [first; 8];
        row[1..].copy_from_slice(&rest);
        row
    };
    vec![
        (None, [NotApplicable, AH, AH, AH, AH, AH, AH, AH]),
        (Some(Phase::Scheduled), [Keep, AH, AH, AH, AH, AH, AH, AH]),
        (Some(Phase::Open), [Restore, AH, AH, AH, AH, AH, AH, AH]),
        (Some(Phase::Closed), with(WaitInFlight, adopt)),
        (Some(Phase::Committing), with(ResendCommit, adopt)),
        (Some(Phase::Committed), snap),
        (Some(Phase::Snapshotted), snap),
        (Some(Phase::Revealed), exec),
        (Some(Phase::Sealed), exec),
        (Some(Phase::Executing), exec),
        (
            Some(Phase::Posted),
            [F, F, F, F, Settle, Settle, MarkSettled, MarkAborted],
        ),
        (
            Some(Phase::Settled),
            [F, KeepReclaimed, F, F, F, F, Keep, F],
        ),
        (
            Some(Phase::Aborting),
            [
                F,
                F,
                Abort,
                Abort,
                AbortElseFetch,
                AbortElseFetchSettle,
                SupersededFetchSettled,
                MarkAborted,
            ],
        ),
        (
            Some(Phase::Aborted),
            [F, KeepReclaimed, F, F, F, F, F, Keep],
        ),
    ]
}

#[test]
fn every_d3_cell_has_exactly_one_action() {
    let table = d3_table();
    let rows: Vec<Option<Phase>> = table.iter().map(|(p, _)| *p).collect();
    let phases: Vec<Option<Phase>> = std::iter::once(None)
        .chain(Phase::ALL.into_iter().map(Some))
        .collect();
    assert_eq!(rows.len(), phases.len(), "one row per phase");
    for p in &phases {
        assert_eq!(rows.iter().filter(|r| *r == p).count(), 1, "{p:?}");
    }
    for (p, expected) in table {
        for (c, want) in ChainState::ALL.into_iter().zip(expected) {
            assert_eq!(action(p, c), want, "{p:?} x {c:?}");
        }
    }
}

#[test]
fn random_runs_keep_the_invariants() {
    let mut settled = 0;
    let mut acknowledged = 0;
    let mut committed = 0;
    for seed in 0..48 {
        let mut m = Model::new(seed);
        for _ in 0..600 {
            m.step();
        }
        m.check_promises();
        settled +=
            m.db.epochs
                .values()
                .filter(|r| r.phase == Phase::Settled)
                .count();
        committed += m.chain.batches.len();
        acknowledged += m.acknowledged.len();
    }
    // The runs made progress, so the invariants were exercised.
    assert!(settled > 20, "settled {settled}");
    assert!(committed > settled / 2);
    assert!(acknowledged > 100, "acknowledged {acknowledged}");
}
