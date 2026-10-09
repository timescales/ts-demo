//! The pure transition function of a market.
//!
//! [`MarketActor::on`] handles one command and returns the effects it
//! needs: writes, replies, jobs, events, intake pauses. It reads the clock
//! only through [`Now`] and never touches the network or the disk. After
//! every command it reconciles: it closes the open epoch at its cutoff,
//! spawns the job for the in-flight epoch's phase, opens the next epoch as
//! soon as `can_open` holds and recomputes the intake pause reason.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use timescales_auction::{AuctionEpoch, AuctionError, epoch_binding, terms_digest};
use timescales_chain::Address;
use timescales_chain::program::{AbortReason, BatchStatus, GovernanceChange};
use timescales_core::{Encode, EpochId, Hash32, OrderCommitment, Tick};
use timescales_service::api::{
    B58, B64, Band, BatchFullDetails, ChangeKind, DuplicateCommitmentDetails, EpochClosedDetails,
    EpochKey, ErrorCode, Event, Hex32, IntakePausedDetails, MarketState, PauseReason,
    ProblemDetails, QuotaExceededDetails, SubmitResult, SubmitStatus, U64,
};
use timescales_service::relay::{InclusionPromiseV2, Relay, RelayError};
use timescales_service::store::node::{EpochPatch, EpochRow, Phase, SubmissionRow};
use timescales_service::wire::{AnnouncementFields, EpochAnnouncement, RelayRefusal};

use super::{
    BundleFacts, ChainObservation, Cmd, Effect, FenceReason, IntakeItem, Job, JobId, JobKind,
    JobOutput, JobResult, MarketSettings, MarketView, Mode, Now, OpenView, Persist, Reply,
    RequestId, Restored, SlotsLeft, public_abort_reason,
};
use crate::config::IdlePolicyConfig;
use crate::reference::PriceSource;
use crate::{AdminCmd, AdminMarketStatus, AdminReply, AdminStatus, SessionRef, SubmitError};

/// Slots after `commit_slot + d` in which the beacon can be revealed.
pub const REVEAL_WINDOW: u64 = 400;
/// Errors kept for the admin status.
const LAST_ERRORS: usize = 16;
/// Pause between retries of a job that failed without a retry hint.
const FAILED_RETRY_MS: u64 = 30_000;
/// Pause between retries of a job blocked by a halt.
const HALTED_RETRY_MS: u64 = 2_000;
/// Runbook of the admin abort refusal.
pub(crate) const ABORT_RUNBOOK: &str = "abort";

/// Builds the relay a fresh epoch opens in, for the idle policy "extend"
/// (the open epoch's window cannot move inside a relay).
pub type RelayFactory = Arc<dyn Fn() -> Relay + Send + Sync>;

#[derive(Debug, Default)]
struct Jobs {
    running: BTreeMap<(u64, JobKind), JobId>,
    by_id: BTreeMap<JobId, (u64, JobKind)>,
    not_before: BTreeMap<(u64, JobKind), u64>,
    next: u64,
}

impl Jobs {
    fn busy(&self, epoch: u64, kind: JobKind) -> bool {
        self.running.contains_key(&(epoch, kind))
    }

    fn ready(&self, epoch: u64, kind: JobKind, now_ms: u64) -> bool {
        !self.busy(epoch, kind)
            && self
                .not_before
                .get(&(epoch, kind))
                .is_none_or(|t| now_ms >= *t)
    }

    fn start(&mut self, epoch: u64, kind: JobKind) -> JobId {
        self.next += 1;
        let id = JobId(self.next);
        self.running.insert((epoch, kind), id);
        self.by_id.insert(id, (epoch, kind));
        self.not_before.remove(&(epoch, kind));
        id
    }

    fn finish(&mut self, id: JobId) -> Option<(u64, JobKind)> {
        let key = self.by_id.remove(&id)?;
        self.running.remove(&key);
        Some(key)
    }

    fn defer(&mut self, epoch: u64, kind: JobKind, until_ms: u64) {
        self.not_before.insert((epoch, kind), until_ms);
    }

    fn any_running(&self, kind: JobKind) -> bool {
        self.running.keys().any(|(_, k)| *k == kind)
    }
}

/// An accepted envelope of an epoch (open or parked).
#[derive(Clone, Debug)]
struct Accepted {
    digest: Hash32,
    promise: Vec<u8>,
}

/// The open epoch.
#[derive(Debug)]
struct OpenState {
    epoch: u64,
    row: EpochRow,
    announcement: EpochAnnouncement,
    price_commitment: Option<timescales_core::oracle::PriceCommitment>,
    /// Real envelopes accepted, parked injections included.
    real: u32,
    per_wallet: BTreeMap<Address, u32>,
    /// Envelopes each wallet added once fewer than a quarter of the slots
    /// were left (fair share).
    low_adds: BTreeMap<Address, u32>,
    index: BTreeMap<(OrderCommitment, Address), Accepted>,
    idle_extensions: u32,
}

/// A parked envelope: verified and promised, injected when its epoch opens.
#[derive(Clone, Debug)]
struct ParkedEntry {
    row: SubmissionRow,
    verified: crate::VerifiedSubmission,
}

#[derive(Debug, Default)]
struct ParkedEpoch {
    /// Arrival order.
    order: Vec<(OrderCommitment, Address)>,
    entries: BTreeMap<(OrderCommitment, Address), ParkedEntry>,
    per_wallet: BTreeMap<Address, u32>,
    low_adds: BTreeMap<Address, u32>,
}

impl ParkedEpoch {
    fn len(&self) -> u32 {
        u32::try_from(self.entries.len()).unwrap_or(u32::MAX)
    }

    fn insert(&mut self, e: ParkedEntry, wallet: Address) {
        let key = (e.row.commitment, wallet);
        self.order.push(key);
        *self.per_wallet.entry(wallet).or_default() += 1;
        self.entries.insert(key, e);
    }

    fn remove(&mut self, key: &(OrderCommitment, Address)) -> bool {
        if self.entries.remove(key).is_none() {
            return false;
        }
        self.order.retain(|k| k != key);
        if let Some(n) = self.per_wallet.get_mut(&key.1) {
            *n = n.saturating_sub(1);
        }
        true
    }
}

/// Last governance state seen on chain, to publish changes once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct GovernanceSeen {
    pending: Option<(u8, u64, bool)>,
    halted: Option<bool>,
    deploy_slot: Option<u64>,
    program: Option<timescales_chain::program::loader::ProgramData>,
}

/// Owns the relay and the epoch table of one market.
pub struct MarketActor {
    s: Arc<MarketSettings>,
    reference: Box<dyn PriceSource>,
    new_relay: RelayFactory,
    relay: Option<Relay>,
    mode: Mode,
    operator_paused: bool,
    /// The pause reason last published. `None` while intake is open.
    pause: Option<PauseReason>,
    pause_published: bool,
    epochs: BTreeMap<u64, EpochRow>,
    last_terminal: Option<EpochRow>,
    open: Option<OpenState>,
    /// The next epoch to open.
    next_epoch: u64,
    parked: BTreeMap<u64, ParkedEpoch>,
    parked_per_wallet: BTreeMap<Address, u32>,
    bundles: BTreeMap<u64, BundleFacts>,
    served: BTreeSet<u64>,
    chain: Option<ChainObservation>,
    jobs: Jobs,
    change_due: Option<u8>,
    /// `Market.relay` is no longer this node's key (an applied SetRelay):
    /// nothing more is promised, opened or committed with the old key until
    /// the node restarts with the new one.
    relay_rotated: bool,
    seen: GovernanceSeen,
    errors: VecDeque<String>,
    /// Terminal epochs already pruned, backed up and reclaimed through.
    maintained_through: u64,
    reclaim_next: u64,
    last_clearing: Vec<timescales_core::ClearingPrice>,
}

impl core::fmt::Debug for MarketActor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MarketActor")
            .field("market", &bs58::encode(self.s.address).into_string())
            .field("mode", &self.mode)
            .field("next_epoch", &self.next_epoch)
            .finish_non_exhaustive()
    }
}

fn b58(a: &Address) -> B58 {
    B58(*a)
}

fn band_json(b: &timescales_core::PriceBand) -> Band {
    Band {
        lo: U64(b.lo.0),
        hi: U64(b.hi.0),
        reference: U64(b.reference.0),
    }
}

fn change_kind(kind: u8) -> ChangeKind {
    match kind {
        GovernanceChange::SET_RELAY => ChangeKind::SetRelay,
        GovernanceChange::SET_EXECUTORS => ChangeKind::SetExecutors,
        GovernanceChange::SET_COMMITTEE_DIGEST => ChangeKind::SetCommitteeDigest,
        GovernanceChange::SET_ADMIN => ChangeKind::SetAdmin,
        GovernanceChange::SET_TIMINGS => ChangeKind::SetTimings,
        _ => ChangeKind::SetTimelock,
    }
}

impl MarketActor {
    /// The actor of a market as `restored` describes it (start, or a
    /// crash in the model test).
    pub fn new(
        s: Arc<MarketSettings>,
        restored: Restored,
        reference: Box<dyn PriceSource>,
        new_relay: RelayFactory,
    ) -> Self {
        let mut a = MarketActor {
            s,
            reference,
            new_relay,
            relay: Some(restored.relay),
            mode: match restored.fenced {
                Some(r) => Mode::Fenced(r),
                None => Mode::Running,
            },
            operator_paused: false,
            pause: None,
            pause_published: false,
            epochs: BTreeMap::new(),
            last_terminal: restored.last_terminal,
            open: None,
            next_epoch: restored.next_epoch.max(1),
            parked: BTreeMap::new(),
            parked_per_wallet: BTreeMap::new(),
            bundles: BTreeMap::new(),
            served: restored.served.into_iter().collect(),
            chain: restored.chain,
            jobs: Jobs::default(),
            change_due: None,
            relay_rotated: false,
            seen: GovernanceSeen::default(),
            errors: VecDeque::new(),
            maintained_through: 0,
            reclaim_next: 0,
            last_clearing: Vec::new(),
        };
        a.maintained_through = a.last_terminal.as_ref().map_or(0, |r| r.epoch);
        for (epoch, facts) in restored.bundles {
            a.remember_bundle(epoch, facts);
        }
        for row in restored.epochs {
            if row.phase == Phase::Open {
                if let Some(open) = a.restore_open(&row, &restored.open_entries) {
                    a.open = Some(open);
                }
                a.next_epoch = a.next_epoch.max(row.epoch + 1);
            } else if row.phase > Phase::Scheduled {
                a.next_epoch = a.next_epoch.max(row.epoch + 1);
            }
            if row.phase != Phase::Scheduled {
                a.epochs.insert(row.epoch, row);
            }
        }
        for (row, verified) in restored.parked {
            let Some(wallet) = row.wallet else { continue };
            *a.parked_per_wallet.entry(wallet).or_default() += 1;
            a.parked
                .entry(row.epoch)
                .or_default()
                .insert(ParkedEntry { row, verified }, wallet);
        }
        if let Some(last) = &a.last_terminal {
            a.next_epoch = a.next_epoch.max(last.epoch + 1);
        }
        a
    }

    fn remember_bundle(&mut self, epoch: u64, facts: BundleFacts) {
        self.bundles.insert(epoch, facts);
    }

    fn restore_open(
        &self,
        row: &EpochRow,
        entries: &[(OrderCommitment, Address, Hash32, Vec<u8>)],
    ) -> Option<OpenState> {
        let announcement = row
            .announcement
            .as_deref()
            .and_then(|b| <EpochAnnouncement as timescales_core::Decode>::decode_exact(b).ok())?;
        let price_commitment = row
            .reference
            .map(|t| self.reference.rebuild(row.epoch, Tick(t)));
        let price_commitment =
            price_commitment.filter(|pc| Some(pc.digest()) == row.price_commitment);
        let mut open = OpenState {
            epoch: row.epoch,
            row: row.clone(),
            announcement,
            price_commitment,
            real: 0,
            per_wallet: BTreeMap::new(),
            low_adds: BTreeMap::new(),
            index: BTreeMap::new(),
            idle_extensions: 0,
        };
        for (c, wallet, digest, promise) in entries {
            open.real += 1;
            *open.per_wallet.entry(*wallet).or_default() += 1;
            open.index.insert(
                (*c, *wallet),
                Accepted {
                    digest: *digest,
                    promise: promise.clone(),
                },
            );
        }
        Some(open)
    }

    pub fn address(&self) -> Address {
        self.s.address
    }

    pub fn settings(&self) -> &Arc<MarketSettings> {
        &self.s
    }

    /// Pure transition function. The model test drives it directly.
    pub fn on(&mut self, cmd: Cmd, now: Now) -> Vec<Effect> {
        let mut out = Vec::new();
        match cmd {
            Cmd::Submit {
                request,
                items,
                session,
                quota,
            } => self.submit(request, items, session, quota, now, &mut out),
            Cmd::Tick => {}
            Cmd::KeyBundle { epoch, facts } => {
                if epoch >= self.next_epoch || !self.bundles.contains_key(&epoch) {
                    self.remember_bundle(epoch, facts);
                }
            }
            Cmd::JobDone(id, result) => self.job_done(id, result, now, &mut out),
            Cmd::ChainObserved(obs) => self.observe(*obs, &mut out),
            Cmd::Admin { request, cmd } => {
                let reply = self.admin(cmd, now, &mut out);
                out.push(Effect::Reply(Reply::Admin { request, reply }));
            }
            Cmd::Retract {
                request,
                wallet,
                commitment,
            } => self.retract(request, wallet, commitment, &mut out),
            Cmd::ParkedInvalidated { epochs } => {
                for e in &epochs {
                    if let Some(p) = self.parked.remove(e) {
                        for (_, w) in p.order {
                            if let Some(n) = self.parked_per_wallet.get_mut(&w) {
                                *n = n.saturating_sub(1);
                            }
                        }
                    }
                    self.bundles.remove(e);
                }
                if !epochs.is_empty() {
                    out.push(Effect::Publish(Box::new(Event::ParkedInvalidated {
                        market: b58(&self.s.address),
                        epochs: epochs.into_iter().map(U64).collect(),
                    })));
                }
            }
            Cmd::Shutdown => {
                if !matches!(self.mode, Mode::Fenced(_)) {
                    self.mode = Mode::Draining;
                }
            }
        }
        self.reconcile(now, &mut out);
        out
    }

    // ---- intake ----

    fn refusal(&self, epoch: u64, digest: Hash32, code: u8, now: Now) -> (Vec<u8>, B64) {
        let r = RelayRefusal::sign(
            self.s.address,
            EpochId(epoch),
            digest,
            code,
            now.ms,
            &self.s.relay_key,
        );
        let bytes = r.to_bytes();
        (bytes.clone(), B64(bytes))
    }

    fn refuse(
        &self,
        code: ErrorCode,
        epoch: u64,
        digest: Hash32,
        now: Now,
        fair_share: bool,
    ) -> SubmitError {
        let refusal_code = code.refusal_code();
        let (bytes, b64) = match refusal_code {
            Some(c) => {
                let (b, b64) = self.refusal(epoch, digest, c, now);
                (Some(b), Some(b64))
            }
            None => (None, None),
        };
        let details = match (code, b64) {
            (ErrorCode::BatchFull, Some(refusal_b64)) => {
                Some(ProblemDetails::BatchFull(BatchFullDetails {
                    fair_share: fair_share.then_some(1),
                    refusal_b64,
                }))
            }
            (ErrorCode::QuotaExceeded, Some(refusal_b64)) => {
                Some(ProblemDetails::QuotaExceeded(QuotaExceededDetails {
                    refusal_b64,
                }))
            }
            (ErrorCode::EpochClosed, Some(refusal_b64)) => {
                let (next_epoch, next_opens_at_ms) = self.next_opening(now);
                Some(ProblemDetails::EpochClosed(EpochClosedDetails {
                    next_epoch: U64(next_epoch),
                    next_opens_at_ms,
                    refusal_b64,
                }))
            }
            (ErrorCode::IntakePaused, Some(refusal_b64)) => {
                Some(ProblemDetails::IntakePaused(IntakePausedDetails {
                    reason: self.pause.unwrap_or(PauseReason::PipelineBacklog),
                    refusal_b64,
                }))
            }
            _ => None,
        };
        let retry_after_ms = match code {
            ErrorCode::IntakePaused | ErrorCode::EpochKeyUnavailable => Some(1_000),
            ErrorCode::EpochClosed | ErrorCode::BatchFull => {
                Some(self.next_opening(now).1.saturating_sub(now.ms))
            }
            _ => None,
        };
        SubmitError {
            code,
            details: details.map_or(serde_json::Value::Null, |d| d.to_value()),
            retry_after_ms,
            refusal: bytes,
        }
    }

    fn plain(code: ErrorCode) -> SubmitError {
        SubmitError {
            code,
            details: serde_json::Value::Null,
            retry_after_ms: None,
            refusal: None,
        }
    }

    /// The epoch intake takes next and when it opens (an estimate while it
    /// is not open).
    fn next_opening(&self, now: Now) -> (u64, u64) {
        match &self.open {
            Some(o) if now.ms < o.row.cutoff_ms.unwrap_or(0) => {
                (o.epoch, o.row.opens_at_ms.unwrap_or(now.ms))
            }
            Some(o) => (o.epoch + 1, o.row.cutoff_ms.unwrap_or(now.ms).max(now.ms)),
            None => {
                let last_cutoff = self.last_cutoff().unwrap_or(now.ms);
                (self.next_epoch, last_cutoff.max(now.ms))
            }
        }
    }

    fn last_cutoff(&self) -> Option<u64> {
        self.epochs
            .values()
            .rev()
            .find_map(|r| r.cutoff_ms)
            .or_else(|| self.last_terminal.as_ref().and_then(|r| r.cutoff_ms))
    }

    fn submit(
        &mut self,
        request: RequestId,
        items: Vec<IntakeItem>,
        session: SessionRef,
        quota: u32,
        now: Now,
        out: &mut Vec<Effect>,
    ) {
        let mut results = Vec::with_capacity(items.len());
        let mut parked_rows = Vec::new();
        for item in items {
            let r = self.submit_one(item, &session, quota, now, out, &mut parked_rows);
            results.push(r);
        }
        if !parked_rows.is_empty() {
            out.push(Effect::Persist(Persist::Parked(parked_rows)));
        }
        out.push(Effect::Reply(Reply::Submit { request, results }));
    }

    fn submit_one(
        &mut self,
        item: IntakeItem,
        session: &SessionRef,
        quota: u32,
        now: Now,
        out: &mut Vec<Effect>,
        parked_rows: &mut Vec<SubmissionRow>,
    ) -> Result<SubmitResult, SubmitError> {
        let wallet = session.wallet;
        let v = item.sub.inner.clone();
        let env = &v.submission.envelope;
        let e = env.epoch.0;
        let c = env.commitment;
        let digest = v.envelope_digest;
        match &self.mode {
            Mode::Fenced(_) | Mode::Recovering => {
                return Err(Self::plain(ErrorCode::MarketUnavailable));
            }
            Mode::Draining => return Err(Self::plain(ErrorCode::Draining)),
            Mode::Running => {}
        }
        if self.relay_rotated {
            return Err(Self::plain(ErrorCode::Draining));
        }
        if self.chain.as_ref().is_some_and(|c| c.market.halted) {
            return Err(Self::plain(ErrorCode::MarketHalted));
        }
        let result = |status, promise: Vec<u8>, duplicate| SubmitResult {
            status,
            market: b58(&self.s.address),
            epoch: U64(e),
            commitment: Hex32(c.0),
            envelope_digest: Hex32(digest.0),
            received_at_ms: item.received_at_ms,
            promise_b64: B64(promise),
            duplicate,
        };
        let duplicate = |original: &Accepted| -> Result<SubmitResult, SubmitError> {
            if original.digest == digest {
                return Ok(result(
                    SubmitStatus::Accepted,
                    original.promise.clone(),
                    true,
                ));
            }
            Err(SubmitError {
                code: ErrorCode::DuplicateCommitment,
                details: ProblemDetails::DuplicateCommitment(DuplicateCommitmentDetails {
                    promise_b64: B64(original.promise.clone()),
                })
                .to_value(),
                retry_after_ms: None,
                refusal: None,
            })
        };

        let cap = self.s.capacity();
        let open_epoch = self.open.as_ref().map(|o| o.epoch);
        if open_epoch == Some(e) {
            let closing = self.relay.is_none()
                || self
                    .open
                    .as_ref()
                    .is_some_and(|o| now.ms >= o.row.cutoff_ms.unwrap_or(0));
            if let Some(original) = self.open.as_ref().and_then(|o| o.index.get(&(c, wallet))) {
                return duplicate(original).map(|mut r| {
                    r.status = SubmitStatus::Accepted;
                    r
                });
            }
            if closing {
                return Err(self.refuse(ErrorCode::EpochClosed, e, digest, now, false));
            }
            let Some(open) = self.open.as_ref() else {
                return Err(Self::plain(ErrorCode::Internal));
            };
            if open.per_wallet.get(&wallet).copied().unwrap_or(0) >= quota {
                return Err(self.refuse(ErrorCode::QuotaExceeded, e, digest, now, false));
            }
            if open.real >= cap {
                return Err(self.refuse(ErrorCode::BatchFull, e, digest, now, false));
            }
            let low = (cap - open.real).saturating_mul(4) < cap;
            if low && open.low_adds.get(&wallet).copied().unwrap_or(0) >= 1 {
                return Err(self.refuse(ErrorCode::BatchFull, e, digest, now, true));
            }
            let Some(relay) = self.relay.as_mut() else {
                return Err(Self::plain(ErrorCode::Internal));
            };
            let promise = match relay.submit_verified(now.ms, v, wallet) {
                Ok(p) => p,
                Err(err) => return Err(self.map_relay_error(&err, e, digest, now)),
            };
            let promise = promise.to_bytes();
            let Some(open) = self.open.as_mut() else {
                return Err(Self::plain(ErrorCode::Internal));
            };
            open.real += 1;
            *open.per_wallet.entry(wallet).or_default() += 1;
            if low {
                *open.low_adds.entry(wallet).or_default() += 1;
            }
            open.index.insert(
                (c, wallet),
                Accepted {
                    digest,
                    promise: promise.clone(),
                },
            );
            out.push(Effect::Persist(Persist::Submission(Box::new(
                SubmissionRow {
                    market: self.s.address,
                    epoch: e,
                    commitment: c,
                    envelope_digest: digest,
                    wallet: Some(wallet),
                    session_pk: Some(session.session_key),
                    submission: item.sub.raw,
                    promise: promise.clone(),
                    received_at_ms: item.received_at_ms,
                },
            ))));
            return Ok(result(SubmitStatus::Accepted, promise, false));
        }

        // Not the open epoch: closed, paused, parked or too far.
        let base = open_epoch.unwrap_or(self.next_epoch.saturating_sub(1));
        if e <= base {
            return Err(self.refuse(ErrorCode::EpochClosed, e, digest, now, false));
        }
        if open_epoch.is_none() && e == self.next_epoch {
            return Err(self.refuse(ErrorCode::IntakePaused, e, digest, now, false));
        }
        if e > base.saturating_add(u64::from(self.s.park_ahead)) {
            return Err(Self::plain(ErrorCode::EpochTooFar));
        }
        if !self.bundles.contains_key(&e) {
            return Err(Self::plain(ErrorCode::EpochKeyUnavailable));
        }
        let parked = self.parked.entry(e).or_default();
        if let Some(p) = parked.entries.get(&(c, wallet)) {
            let original = Accepted {
                digest: p.row.envelope_digest,
                promise: p.row.promise.clone(),
            };
            return duplicate(&original).map(|mut r| {
                r.status = SubmitStatus::Parked;
                r
            });
        }
        let (used, len, low_adds) = (
            parked.per_wallet.get(&wallet).copied().unwrap_or(0),
            parked.len(),
            parked.low_adds.get(&wallet).copied().unwrap_or(0),
        );
        let total_parked = self.parked_per_wallet.get(&wallet).copied().unwrap_or(0);
        if used >= quota || total_parked >= self.s.quota.max_parked_per_wallet {
            return Err(self.refuse(ErrorCode::QuotaExceeded, e, digest, now, false));
        }
        if len >= cap {
            return Err(self.refuse(ErrorCode::BatchFull, e, digest, now, false));
        }
        let low = (cap - len).saturating_mul(4) < cap;
        if low && low_adds >= 1 {
            return Err(self.refuse(ErrorCode::BatchFull, e, digest, now, true));
        }
        let promise =
            InclusionPromiseV2::sign(&self.s.relay_key, self.s.address, EpochId(e), c, digest)
                .to_bytes();
        let row = SubmissionRow {
            market: self.s.address,
            epoch: e,
            commitment: c,
            envelope_digest: digest,
            wallet: Some(wallet),
            session_pk: Some(session.session_key),
            submission: item.sub.raw.clone(),
            promise: promise.clone(),
            received_at_ms: item.received_at_ms,
        };
        let parked = self.parked.entry(e).or_default();
        parked.insert(
            ParkedEntry {
                row: row.clone(),
                verified: item.sub,
            },
            wallet,
        );
        if low {
            *parked.low_adds.entry(wallet).or_default() += 1;
        }
        *self.parked_per_wallet.entry(wallet).or_default() += 1;
        parked_rows.push(row);
        Ok(result(SubmitStatus::Parked, promise, false))
    }

    fn map_relay_error(&self, err: &RelayError, e: u64, digest: Hash32, now: Now) -> SubmitError {
        match err {
            RelayError::Auction(AuctionError::Full) => {
                self.refuse(ErrorCode::BatchFull, e, digest, now, false)
            }
            RelayError::Auction(
                AuctionError::AfterCutoff { .. } | AuctionError::InvalidTransition { .. },
            ) => self.refuse(ErrorCode::EpochClosed, e, digest, now, false),
            RelayError::Auction(AuctionError::WrongMarket { .. }) => {
                Self::plain(ErrorCode::WrongMarket)
            }
            RelayError::MaskedNotAllowed => Self::plain(ErrorCode::MaskedNotSupported),
            RelayError::UnsupportedVersion(_) => Self::plain(ErrorCode::VersionUnsupported),
            RelayError::BadSignature => Self::plain(ErrorCode::BadSignature),
            // The same envelope submitted by another wallet first: the leaf
            // is already in the batch.
            RelayError::Auction(AuctionError::Duplicate) | RelayError::DuplicateForSubmitter => {
                Self::plain(ErrorCode::BadRequest)
            }
            _ => Self::plain(ErrorCode::BadRequest),
        }
    }

    fn retract(
        &mut self,
        request: RequestId,
        wallet: Address,
        commitment: OrderCommitment,
        out: &mut Vec<Effect>,
    ) {
        let open = self.open.as_ref().map(|o| o.epoch);
        let after = open.unwrap_or(self.next_epoch.saturating_sub(1));
        let mut removed = Vec::new();
        for (e, p) in self.parked.range_mut(after.saturating_add(1)..) {
            if p.remove(&(commitment, wallet)) {
                removed.push(*e);
            }
        }
        if let Some(n) = self.parked_per_wallet.get_mut(&wallet) {
            *n = n.saturating_sub(u32::try_from(removed.len()).unwrap_or(u32::MAX));
        }
        let kept_open = self
            .open
            .as_ref()
            .filter(|o| o.index.contains_key(&(commitment, wallet)))
            .map(|o| o.epoch);
        out.push(Effect::Persist(Persist::Retract {
            wallet,
            commitment,
            after,
        }));
        out.push(Effect::Reply(Reply::Retract {
            request,
            removed,
            kept_open,
        }));
    }

    // ---- jobs ----

    fn note(&mut self, error: String) {
        if self.errors.len() == LAST_ERRORS {
            self.errors.pop_front();
        }
        self.errors.push_back(error);
    }

    fn job_done(&mut self, id: JobId, result: JobResult, now: Now, out: &mut Vec<Effect>) {
        let Some((epoch, kind)) = self.jobs.finish(id) else {
            return;
        };
        match result {
            JobResult::Done(output) => self.job_output(epoch, kind, output, now, out),
            JobResult::Retry { detail, after_ms } => {
                self.jobs
                    .defer(epoch, kind, now.ms.saturating_add(after_ms));
                if !detail.is_empty() {
                    self.note(format!("{} {epoch}: {detail}", kind.as_str()));
                }
            }
            JobResult::Failed(detail) => {
                self.jobs
                    .defer(epoch, kind, now.ms.saturating_add(FAILED_RETRY_MS));
                self.note(format!("{} {epoch} failed: {detail}", kind.as_str()));
            }
        }
    }

    fn job_output(
        &mut self,
        epoch: u64,
        kind: JobKind,
        output: JobOutput,
        now: Now,
        out: &mut Vec<Effect>,
    ) {
        match output {
            JobOutput::Row(row) => self.update_row(*row),
            JobOutput::Closed { relay, row } => {
                self.relay = Some(*relay);
                if self.open.as_ref().is_some_and(|o| o.epoch == row.epoch) {
                    self.open = None;
                }
                out.push(Effect::Publish(Box::new(Event::EpochClosed {
                    market: b58(&self.s.address),
                    epoch: U64(row.epoch),
                })));
                self.update_row(*row);
            }
            JobOutput::CloseFailed { relay, detail } => {
                self.relay = Some(*relay);
                self.jobs.defer(epoch, kind, now.ms.saturating_add(1_000));
                self.note(format!("close {epoch}: {detail}"));
            }
            JobOutput::ChangeDue { kind: change } => {
                self.change_due = Some(change);
            }
            JobOutput::Halted => {
                self.jobs
                    .defer(epoch, kind, now.ms.saturating_add(HALTED_RETRY_MS));
            }
            JobOutput::ChangeApplied { kind: applied } => {
                self.change_due = None;
                if applied == Some(GovernanceChange::SET_RELAY) {
                    // The next observation confirms it. Until then nothing
                    // may be committed with a key the chain no longer takes.
                    let ours = self.s.relay_key.public();
                    let rotated = self.chain.as_ref().is_none_or(|c| {
                        c.market.pending.as_ref().is_none_or(
                            |p| !matches!(p.change, GovernanceChange::SetRelay(k) if k == ours),
                        )
                    });
                    if rotated {
                        self.rotate_relay(out);
                    }
                }
                if let Some(k) = applied {
                    out.push(Effect::Publish(Box::new(Event::GovernanceApplied {
                        market: b58(&self.s.address),
                        change: change_kind(k),
                        slot: U64(now.slot),
                    })));
                }
            }
            JobOutput::Fence(reason) => self.fence(reason, out),
            JobOutput::Nothing => {}
        }
    }

    fn fence(&mut self, reason: FenceReason, out: &mut Vec<Effect>) {
        if matches!(self.mode, Mode::Fenced(_)) {
            return;
        }
        self.note(format!("fenced: {}", reason.as_str()));
        self.mode = Mode::Fenced(reason.clone());
        out.push(Effect::Fence(reason));
        out.push(Effect::Publish(Box::new(Event::MarketStateChanged {
            market: b58(&self.s.address),
            state: MarketState::Fenced,
            halted: self.halted(),
        })));
    }

    fn update_row(&mut self, row: EpochRow) {
        let e = row.epoch;
        if row.phase.is_terminal() {
            self.epochs.remove(&e);
            if row.phase == Phase::Settled
                && let Some(clearing) = clearing(&row)
            {
                // A book that matched nothing reports the tick its clearing
                // rule picked over an empty curve. Following it would let a
                // single resting order walk the band. Only traded prices count.
                if let Some(p) = clearing.iter().find(|p| p.volume.0 > 0) {
                    self.reference.observe_clearing(p.tick);
                }
                self.last_clearing = clearing;
            }
            if self.last_terminal.as_ref().is_none_or(|t| t.epoch < e) {
                self.last_terminal = Some(row);
            }
            self.bundles.retain(|b, _| *b > e);
            self.served.retain(|b| *b > e);
        } else {
            self.epochs.insert(e, row);
        }
    }

    // ---- chain and governance ----

    fn halted(&self) -> bool {
        self.chain.as_ref().is_some_and(|c| c.market.halted)
    }

    fn observe(&mut self, obs: ChainObservation, out: &mut Vec<Effect>) {
        let market = b58(&self.s.address);
        let halted = obs.market.halted;
        if self.seen.halted != Some(halted) {
            if self.seen.halted.is_some() {
                out.push(Effect::Publish(Box::new(Event::MarketStateChanged {
                    market,
                    state: self.market_state(),
                    halted,
                })));
            }
            self.seen.halted = Some(halted);
        }
        let pending = obs.market.pending.as_ref().map(|p| {
            (
                p.change.kind(),
                p.eta_slot,
                p.change.between_batches() && obs.slot >= p.eta_slot,
            )
        });
        if pending != self.seen.pending {
            if let Some((kind, eta, due)) = pending {
                out.push(Effect::Publish(Box::new(Event::GovernancePending {
                    market,
                    change: change_kind(kind),
                    eta_slot: U64(eta),
                    due,
                })));
            } else if let Some((kind, _, _)) = self.seen.pending {
                // Applied (by this node or anyone) or cancelled. Only an
                // apply changes the market.
                out.push(Effect::Publish(Box::new(Event::GovernanceApplied {
                    market,
                    change: change_kind(kind),
                    slot: U64(obs.slot),
                })));
            }
            self.seen.pending = pending;
        }
        self.change_due = pending.and_then(|(k, _, due)| due.then_some(k));
        if let Some(p) = obs.program {
            if self
                .seen
                .deploy_slot
                .is_some_and(|s| s != p.last_deploy_slot)
            {
                out.push(Effect::Publish(Box::new(Event::ProgramUpgraded {
                    slot: U64(p.last_deploy_slot),
                })));
            }
            self.seen.deploy_slot = Some(p.last_deploy_slot);
            self.seen.program = Some(p);
        }
        if obs.market.relay != self.s.relay_key.public() {
            self.rotate_relay(out);
        } else if self.relay_rotated {
            tracing::warn!(market = %market, "the market's relay is this node's key again");
            self.relay_rotated = false;
        }
        // Never open an epoch the chain already committed.
        self.next_epoch = self.next_epoch.max(obs.market.last_committed + 1);
        self.chain = Some(obs);
    }

    /// The chain no longer takes this node's relay key (relay
    /// rotation): drain. The open epoch closes at its cutoff, closed epochs
    /// wait for the restart with the new key, which commits them (promises
    /// stay valid against the relay recorded at submission, V-5).
    fn rotate_relay(&mut self, out: &mut Vec<Effect>) {
        if self.relay_rotated {
            return;
        }
        self.relay_rotated = true;
        tracing::error!(
            market = %b58(&self.s.address),
            "Market.relay is no longer this node's relay key; intake drained, restart with the new key (relay rotation)"
        );
        self.note("relay rotated: restart with the new relay key".into());
        if self.mode == Mode::Running {
            self.mode = Mode::Draining;
        }
        out.push(Effect::Publish(Box::new(Event::MarketStateChanged {
            market: b58(&self.s.address),
            state: self.market_state(),
            halted: self.halted(),
        })));
    }

    fn market_state(&self) -> MarketState {
        match &self.mode {
            Mode::Fenced(_) => MarketState::Fenced,
            Mode::Recovering => MarketState::Recovering,
            Mode::Draining => MarketState::Draining,
            Mode::Running if self.operator_paused => MarketState::Paused,
            Mode::Running => MarketState::Running,
        }
    }

    // ---- admin ----

    fn admin(&mut self, cmd: AdminCmd, now: Now, out: &mut Vec<Effect>) -> AdminReply {
        match cmd {
            AdminCmd::Status => AdminReply::Status(AdminStatus {
                markets: vec![self.admin_status()],
            }),
            AdminCmd::Pause(_) => {
                self.operator_paused = true;
                AdminReply::Ok
            }
            AdminCmd::Resume(_) => {
                self.operator_paused = false;
                if self.mode == Mode::Draining && !self.relay_rotated {
                    self.mode = Mode::Running;
                }
                AdminReply::Ok
            }
            AdminCmd::Drain(_) => {
                if self.mode == Mode::Running {
                    self.mode = Mode::Draining;
                }
                AdminReply::Ok
            }
            AdminCmd::SetReference(_, tick) => match self.reference.set_operator(Tick(tick)) {
                Ok(()) if self.reference.kind() == crate::config::ReferenceSource::Operator => {
                    AdminReply::Ok
                }
                Ok(()) => AdminReply::Refused {
                    reason: "the market's reference source is not \"operator\"".into(),
                    runbook: "reference-price",
                },
                Err(e) => AdminReply::Refused {
                    reason: e.to_string(),
                    runbook: "reference-price",
                },
            },
            AdminCmd::Abort(_, epoch) => self.admin_abort(epoch, now, out),
            AdminCmd::Backup => AdminReply::Refused {
                reason: "backups are node-wide".into(),
                runbook: "backup",
            },
        }
    }

    fn admin_status(&self) -> AdminMarketStatus {
        let c = self.chain.as_ref();
        AdminMarketStatus {
            market: self.s.address,
            state: format!("{:?}", self.market_state()).to_lowercase(),
            epochs: self.epochs.values().map(|r| (r.epoch, r.phase)).collect(),
            settlement_lag: self
                .open
                .as_ref()
                .map_or(self.next_epoch, |o| o.epoch)
                .saturating_sub(self.last_terminal.as_ref().map_or(0, |r| r.epoch)),
            keys_ready_ahead: self.keys_ready_ahead(),
            relay_balance_lamports: c.and_then(|c| c.relay_lamports).unwrap_or(0),
            cranker_balance_lamports: c.and_then(|c| c.cranker_lamports).unwrap_or(0),
            pending_change: c.and_then(|c| c.market.pending.as_ref().map(|p| p.change.kind())),
            last_errors: self.errors.iter().cloned().collect(),
        }
    }

    /// Which abort the admin may request now (admin route): the
    /// relay abort before any beacon input exists, or a timeout abort that
    /// is due. Everything else is refused with the runbook.
    fn admin_abort(&mut self, epoch: u64, now: Now, out: &mut Vec<Effect>) -> AdminReply {
        let refuse = |reason: String| AdminReply::Refused {
            reason,
            runbook: ABORT_RUNBOOK,
        };
        let Some(row) = self.epochs.get(&epoch).cloned() else {
            return refuse(format!("epoch {epoch} is not in flight"));
        };
        let Some(c) = self.chain.as_ref() else {
            return refuse("no chain observation yet".into());
        };
        let m = &c.market;
        let slot = c.slot.max(now.slot);
        let batch = c.batch.as_ref().filter(|b| b.epoch == epoch);
        let reason = match (row.phase, batch.map(|b| b.status)) {
            (
                Phase::Committed | Phase::Snapshotted | Phase::Committing,
                Some(BatchStatus::Committed),
            ) => {
                let commit = batch.map_or(0, |b| b.commit_slot);
                if slot < commit + u64::from(m.beacon_delay_slots) {
                    Some(AbortReason::Relay)
                } else if slot > commit + u64::from(m.beacon_delay_slots) + REVEAL_WINDOW {
                    Some(AbortReason::BeaconExpired)
                } else {
                    None
                }
            }
            (_, Some(BatchStatus::BeaconRevealed)) => {
                let reveal = batch.map_or(u64::MAX, |b| b.reveal_slot);
                (slot > reveal.saturating_add(m.exec_timeout_slots))
                    .then_some(AbortReason::ExecTimeout)
            }
            (_, Some(BatchStatus::ReceiptPosted)) => {
                let b = batch.map_or(0, |b| b.receipt_slot);
                let quorum = batch.is_some_and(|b| m.quorum_met(b.cosign_bitmap));
                if !quorum && slot > b.saturating_add(m.exec_timeout_slots) {
                    Some(AbortReason::QuorumTimeout)
                } else if slot > b.saturating_add(m.settle_timeout_slots)
                    && batch.is_some_and(|b| b.applied_count == 0)
                {
                    Some(AbortReason::SettleTimeout)
                } else {
                    None
                }
            }
            (_, Some(BatchStatus::Verified)) => {
                let b = batch.map_or(0, |b| b.receipt_slot);
                (slot > b.saturating_add(m.settle_timeout_slots)
                    && batch.is_some_and(|b| b.applied_count == 0))
                .then_some(AbortReason::SettleTimeout)
            }
            _ => None,
        };
        let Some(reason) = reason else {
            return refuse(format!(
                "no abort is legal for epoch {epoch} at slot {slot}: the relay abort ends at \
                 commit_slot + d and timeout aborts start at their deadlines"
            ));
        };
        self.begin_abort(row, reason, "admin request", None, out);
        AdminReply::Ok
    }

    fn begin_abort(
        &mut self,
        mut row: EpochRow,
        reason: AbortReason,
        detail: &str,
        earliest_slot: Option<u64>,
        out: &mut Vec<Effect>,
    ) {
        let epoch = row.epoch;
        row.phase = Phase::Aborting;
        row.abort_reason = Some(reason as u8);
        row.abort_detail = Some(detail.to_owned());
        out.push(Effect::Persist(Persist::Advance {
            epoch,
            phase: Phase::Aborting,
            patch: Box::new(EpochPatch {
                abort_reason: Some(reason as u8),
                abort_detail: Some(detail.to_owned()),
                ..EpochPatch::default()
            }),
        }));
        out.push(Effect::Publish(Box::new(Event::EpochAborting {
            market: b58(&self.s.address),
            epoch: U64(epoch),
            reason: public_abort_reason(reason),
            earliest_slot: earliest_slot.map(U64),
        })));
        self.epochs.insert(epoch, row);
    }

    // ---- reconcile ----

    fn spawn(&mut self, epoch: u64, kind: JobKind, out: &mut Vec<Effect>) {
        let id = self.jobs.start(epoch, kind);
        out.push(Effect::Spawn(Job {
            id,
            epoch,
            kind,
            relay: None,
        }));
    }

    fn keys_ready_ahead(&self) -> u32 {
        let from = self
            .open
            .as_ref()
            .map_or(self.next_epoch.saturating_sub(1), |o| o.epoch);
        let mut n = 0u32;
        let mut e = from + 1;
        while self.bundles.contains_key(&e) {
            n += 1;
            e += 1;
        }
        n
    }

    fn reconcile(&mut self, now: Now, out: &mut Vec<Effect>) {
        if !matches!(self.mode, Mode::Fenced(_)) {
            self.close_open(now, out);
            self.drive_pipeline(now, out);
            self.open_next(now, out);
            self.maintain(now, out);
        }
        self.mark_served(out);
        self.update_pause(out);
    }

    fn close_open(&mut self, now: Now, out: &mut Vec<Effect>) {
        let Some(open) = self.open.as_mut() else {
            return;
        };
        let cutoff = open.row.cutoff_ms.unwrap_or(0);
        if now.ms < cutoff || self.relay.is_none() || self.jobs.busy(open.epoch, JobKind::Close) {
            return;
        }
        if !self.jobs.ready(open.epoch, JobKind::Close, now.ms) {
            return;
        }
        // Idle policy "extend": an epoch nobody submitted to stays open.
        if self.s.idle == IdlePolicyConfig::Extend
            && open.real == 0
            && open.idle_extensions < self.s.max_idle_extend
        {
            let epoch = open.epoch;
            let opens_at = open.row.opens_at_ms.unwrap_or(now.ms);
            let new_cutoff = cutoff.max(now.ms).saturating_add(self.s.interval_ms);
            let a = open.announcement;
            let announcement = EpochAnnouncement::sign(
                AnnouncementFields {
                    market: a.market,
                    epoch: a.epoch,
                    opens_at_ms: opens_at,
                    cutoff_ms: new_cutoff,
                    band: a.band,
                    price_commitment: a.price_commitment,
                    key_digest: a.key_digest,
                    committee_digest: a.committee_digest,
                },
                &self.s.relay_key,
            );
            let mut relay = (self.new_relay)();
            let timing = AuctionEpoch {
                epoch: EpochId(epoch),
                opens_at_ms: opens_at,
                cutoff_ms: new_cutoff,
            };
            if relay
                .open_epoch_v2(timing, a.band.reference, a.price_commitment, a.binding())
                .is_err()
            {
                self.note(format!("extend {epoch}: the relay refused the new window"));
                return;
            }
            let Some(open) = self.open.as_mut() else {
                return;
            };
            open.idle_extensions += 1;
            open.announcement = announcement;
            open.row.cutoff_ms = Some(new_cutoff);
            open.row.announcement = Some(announcement.to_bytes());
            self.relay = Some(relay);
            out.push(Effect::Persist(Persist::Advance {
                epoch,
                phase: Phase::Open,
                patch: Box::new(EpochPatch {
                    cutoff_ms: Some(new_cutoff),
                    announcement: Some(announcement.to_bytes()),
                    ..EpochPatch::default()
                }),
            }));
            return;
        }
        let epoch = open.epoch;
        let Some(relay) = self.relay.take() else {
            return;
        };
        let id = self.jobs.start(epoch, JobKind::Close);
        out.push(Effect::Spawn(Job {
            id,
            epoch,
            kind: JobKind::Close,
            relay: Some(Box::new(relay)),
        }));
    }

    /// Whether the chain shows the in-flight slot free for `epoch`, or
    /// already committed it (the commit job adopts that).
    fn slot_free_for(&self, epoch: u64) -> bool {
        let Some(c) = self.chain.as_ref() else {
            return false;
        };
        let m = &c.market;
        (m.last_committed == m.last_settled && m.last_committed + 1 == epoch)
            || m.last_committed >= epoch
    }

    fn drive_pipeline(&mut self, now: Now, out: &mut Vec<Effect>) {
        // The lowest non-terminal epoch past `open` is the only one that
        // may be in flight. A closed epoch behind it waits.
        let Some((&epoch, row)) = self.epochs.iter().find(|(_, r)| r.phase > Phase::Open) else {
            return;
        };
        let phase = row.phase;
        let kind = match phase {
            Phase::Closed => {
                if !self.slot_free_for(epoch) || self.relay_rotated {
                    return;
                }
                if self.change_due.is_some() {
                    JobKind::ApplyChange
                } else if self.halted() {
                    return;
                } else {
                    JobKind::Commit
                }
            }
            Phase::Committing => JobKind::Commit,
            Phase::Committed => JobKind::Snapshot,
            Phase::Snapshotted => JobKind::Reveal,
            Phase::Revealed => JobKind::Assemble,
            Phase::Sealed | Phase::Executing => JobKind::Execute,
            Phase::Posted => JobKind::Settle,
            Phase::Aborting => JobKind::Abort,
            Phase::Scheduled | Phase::Open | Phase::Settled | Phase::Aborted => return,
        };
        if kind == JobKind::ApplyChange {
            if self.jobs.any_running(JobKind::ApplyChange) || !self.jobs.ready(epoch, kind, now.ms)
            {
                return;
            }
        } else if !self.jobs.ready(epoch, kind, now.ms) {
            return;
        }
        let id = self.jobs.start(epoch, kind);
        out.push(Effect::Spawn(Job {
            id,
            epoch,
            kind,
            relay: None,
        }));
    }

    /// `can_open(e)`, or the reason intake stays paused.
    fn blocked(&self) -> Option<PauseReason> {
        match &self.mode {
            Mode::Fenced(_) => return Some(PauseReason::Fenced),
            Mode::Recovering => return Some(PauseReason::Recovering),
            Mode::Draining => return Some(PauseReason::Draining),
            Mode::Running => {}
        }
        if self.relay_rotated {
            return Some(PauseReason::Draining);
        }
        let Some(c) = self.chain.as_ref() else {
            return Some(PauseReason::Recovering);
        };
        if c.market.halted {
            return Some(PauseReason::Halted);
        }
        if self.operator_paused {
            return Some(PauseReason::Operator);
        }
        let closed_waiting = self.epochs.values().any(|r| r.phase == Phase::Closed);
        if closed_waiting && self.change_due.is_some() {
            return Some(PauseReason::GovernanceDue);
        }
        if c.relay_lamports
            .is_some_and(|l| l < self.s.min_relay_lamports / 4)
        {
            return Some(PauseReason::LowRelayBalance);
        }
        if closed_waiting || self.relay.is_none() {
            return Some(PauseReason::PipelineBacklog);
        }
        if !self.bundles.contains_key(&self.next_epoch) {
            return Some(PauseReason::EpochKeyUnavailable);
        }
        None
    }

    fn open_next(&mut self, now: Now, out: &mut Vec<Effect>) {
        if self.open.is_some() || self.blocked().is_some() {
            return;
        }
        let epoch = self.next_epoch;
        let Some(facts) = self.bundles.get(&epoch).cloned() else {
            return;
        };
        let (tick, pc) = match self.reference.reference(epoch) {
            Ok(r) => r,
            Err(e) => {
                self.note(format!("open {epoch}: reference price: {e}"));
                return;
            }
        };
        let band = match self.s.params.band(tick) {
            Ok(b) => b,
            Err(e) => {
                self.note(format!("open {epoch}: band: {e}"));
                return;
            }
        };
        let price_commitment = pc.digest();
        let binding = epoch_binding(
            &price_commitment,
            &facts.key_digest,
            &facts.committee_digest,
        );
        let terms = terms_digest(&band, &binding);
        // Contiguous with the previous epoch when it opens on time.
        let interval = self.s.interval_ms;
        let opens_at = match self.last_cutoff() {
            Some(prev) if now.ms <= prev.saturating_add(interval / 4) && prev <= now.ms => prev,
            _ => now.ms,
        };
        let cutoff = opens_at.saturating_add(interval);
        let announcement = EpochAnnouncement::sign(
            AnnouncementFields {
                market: self.s.address,
                epoch: EpochId(epoch),
                opens_at_ms: opens_at,
                cutoff_ms: cutoff,
                band,
                price_commitment,
                key_digest: facts.key_digest,
                committee_digest: facts.committee_digest,
            },
            &self.s.relay_key,
        );
        let Some(relay) = self.relay.as_mut() else {
            return;
        };
        let timing = AuctionEpoch {
            epoch: EpochId(epoch),
            opens_at_ms: opens_at,
            cutoff_ms: cutoff,
        };
        if let Err(e) = relay.open_epoch_v2(timing, tick, price_commitment, binding) {
            self.note(format!("open {epoch}: {e}"));
            return;
        }
        let mut open = OpenState {
            epoch,
            row: EpochRow {
                market: self.s.address,
                epoch,
                phase: Phase::Open,
                opens_at_ms: Some(opens_at),
                cutoff_ms: Some(cutoff),
                reference: Some(tick.0),
                band: Some(band),
                price_commitment: Some(price_commitment),
                committee_digest: Some(facts.committee_digest),
                binding: Some(binding),
                terms_digest: Some(terms),
                announcement: Some(announcement.to_bytes()),
                root: None,
                envelope_count: None,
                real_count: None,
                cover_count: None,
                commit_sig: None,
                commit_slot: None,
                snapshot_slot: None,
                snapshot_late: false,
                beacon: None,
                reveal_slot: None,
                header: None,
                receipt: None,
                receipt_slot: None,
                artifacts_public: false,
                abort_reason: None,
                abort_detail: None,
                terminal_slot: None,
                updated_at_ms: now.ms,
            },
            announcement,
            price_commitment: Some(pc),
            real: 0,
            per_wallet: BTreeMap::new(),
            low_adds: BTreeMap::new(),
            index: BTreeMap::new(),
            idle_extensions: 0,
        };
        // Parked envelopes become submissions of the epoch, in arrival
        // order, with the promises they were given when parked.
        let mut injected = Vec::new();
        if let Some(parked) = self.parked.remove(&epoch) {
            for key in parked.order {
                let Some(p) = parked.entries.get(&key) else {
                    continue;
                };
                let wallet = key.1;
                if let Some(n) = self.parked_per_wallet.get_mut(&wallet) {
                    *n = n.saturating_sub(1);
                }
                match relay.submit_verified(opens_at, p.verified.inner.clone(), wallet) {
                    Ok(promise) if promise.to_bytes() == p.row.promise => {
                        open.real += 1;
                        *open.per_wallet.entry(wallet).or_default() += 1;
                        open.index.insert(
                            key,
                            Accepted {
                                digest: p.row.envelope_digest,
                                promise: p.row.promise.clone(),
                            },
                        );
                        injected.push(key);
                    }
                    Ok(_) => {
                        self.errors.push_back(format!(
                            "open {epoch}: a parked promise did not re-derive; envelope dropped"
                        ));
                    }
                    Err(e) => {
                        self.errors
                            .push_back(format!("open {epoch}: parked envelope refused: {e}"));
                    }
                }
            }
        }
        let row = open.row.clone();
        let key = EpochKey {
            epoch: U64(epoch),
            epoch_pk: Hex32(facts.epoch_pk),
            committee_digest: Hex32(facts.committee_digest.0),
            bundle_b64: B64(facts.bytes.clone()),
        };
        out.push(Effect::Persist(Persist::OpenEpoch {
            row: Box::new(row.clone()),
            injected,
        }));
        out.push(Effect::Publish(Box::new(Event::EpochOpened {
            market: b58(&self.s.address),
            epoch: U64(epoch),
            opens_at_ms: opens_at,
            cutoff_ms: cutoff,
            band: band_json(&band),
            terms_digest: Hex32(terms.0),
            announcement_b64: B64(announcement.to_bytes()),
            key,
        })));
        self.epochs.insert(epoch, row);
        self.open = Some(open);
        self.next_epoch = epoch + 1;
    }

    /// Bundles exposed in the park window are never replaced.
    fn mark_served(&mut self, out: &mut Vec<Effect>) {
        let Some(open) = self.open.as_ref().map(|o| o.epoch) else {
            return;
        };
        let window = open + 1..=open + u64::from(self.s.park_ahead);
        let fresh: Vec<u64> = self
            .bundles
            .keys()
            .filter(|e| window.contains(e) && !self.served.contains(e))
            .copied()
            .collect();
        for epoch in fresh {
            self.served.insert(epoch);
            out.push(Effect::Persist(Persist::BundleServed { epoch }));
        }
    }

    /// Prune, backup and reclaim after terminal epochs.
    fn maintain(&mut self, now: Now, out: &mut Vec<Effect>) {
        let Some(last) = self.last_terminal.as_ref().map(|r| r.epoch) else {
            return;
        };
        if last > self.maintained_through && self.jobs.ready(last, JobKind::Prune, now.ms) {
            self.maintained_through = last;
            self.spawn(last, JobKind::Prune, out);
            if self.s.backup_every_epochs > 0
                && last % self.s.backup_every_epochs == 0
                && !self.jobs.any_running(JobKind::Backup)
            {
                self.spawn(last, JobKind::Backup, out);
            }
        }
        if self.s.reclaim_batches {
            const BATCH_RETENTION: u64 = 1024;
            let settled = self.chain.as_ref().map_or(0, |c| c.market.last_settled);
            if self.reclaim_next == 0 {
                self.reclaim_next = settled.saturating_sub(BATCH_RETENTION).max(1);
            }
            let e = self.reclaim_next;
            if e + BATCH_RETENTION <= settled
                && !self.jobs.any_running(JobKind::Reclaim)
                && self.jobs.ready(e, JobKind::Reclaim, now.ms)
            {
                self.reclaim_next = e + 1;
                self.spawn(e, JobKind::Reclaim, out);
            }
        }
    }

    fn update_pause(&mut self, out: &mut Vec<Effect>) {
        let reason = if self.open.is_some() && self.mode == Mode::Running && !self.halted() {
            None
        } else {
            Some(self.blocked().unwrap_or(PauseReason::PipelineBacklog))
        };
        if reason == self.pause && self.pause_published {
            return;
        }
        let market = b58(&self.s.address);
        match reason {
            Some(r) => {
                out.push(Effect::PauseIntake(r));
                out.push(Effect::Publish(Box::new(Event::IntakePaused {
                    market,
                    reason: Some(r),
                })));
            }
            None => {
                out.push(Effect::ResumeIntake);
                if self.pause_published {
                    out.push(Effect::Publish(Box::new(Event::IntakeResumed { market })));
                }
            }
        }
        self.pause = reason;
        self.pause_published = true;
    }

    // ---- view ----

    /// The view the API reads (`CurrentEpoch`, `Status`, eligibility).
    pub fn view(&self, now: Now) -> MarketView {
        let c = self.chain.as_ref();
        let cap = self.s.capacity();
        let open = self.open.as_ref().map(|o| {
            let left = cap.saturating_sub(o.real);
            OpenView {
                epoch: o.epoch,
                opens_at_ms: o.row.opens_at_ms.unwrap_or(0),
                cutoff_ms: o.row.cutoff_ms.unwrap_or(0),
                band: o.announcement.band,
                binding: o.announcement.binding(),
                terms_digest: o.announcement.terms_digest(),
                announcement: o.announcement.to_bytes(),
                slots_left: if left == 0 || now.ms >= o.row.cutoff_ms.unwrap_or(0) {
                    SlotsLeft::Full
                } else if left.saturating_mul(4) < cap {
                    SlotsLeft::Low
                } else {
                    SlotsLeft::Available
                },
                price_commitment: o.price_commitment.clone(),
            }
        });
        let base = self
            .open
            .as_ref()
            .map_or(self.next_epoch.saturating_sub(1), |o| o.epoch);
        let park_window = (base + 1..=base + u64::from(self.s.park_ahead))
            .filter(|e| self.bundles.contains_key(e))
            .collect();
        let inflight = self
            .epochs
            .values()
            .find(|r| r.phase >= Phase::Committing)
            .map(|r| (r.epoch, r.phase));
        MarketView {
            market: self.s.address,
            mode: self.mode.clone(),
            operator_paused: self.operator_paused,
            pause: self.pause,
            halted: self.halted(),
            open,
            park_window,
            previous: self.last_terminal.as_ref().map(|r| (r.epoch, r.phase)),
            inflight,
            next_epoch: self.open.as_ref().map_or(self.next_epoch, |o| o.epoch),
            band: self.open.as_ref().map(|o| o.announcement.band).or_else(|| {
                // Between epochs, eligibility values base at the band the
                // next epoch would open with.
                let (tick, _) = self.reference.reference(self.next_epoch).ok()?;
                self.s.params.band(tick).ok()
            }),
            context_slot: c.map_or(0, |c| c.slot),
            last_committed: c.map_or(0, |c| c.market.last_committed),
            last_settled: c.map_or(0, |c| c.market.last_settled),
            keys_ready_ahead: self.keys_ready_ahead(),
            pending_change: c.and_then(|c| c.market.pending.as_ref().map(|p| p.change.kind())),
            epochs: self.epochs.values().map(|r| (r.epoch, r.phase)).collect(),
            last_errors: self.errors.iter().cloned().collect(),
            relay_lamports: c.and_then(|c| c.relay_lamports).unwrap_or(0),
            cranker_lamports: c.and_then(|c| c.cranker_lamports).unwrap_or(0),
            chain_market: c.map(|c| c.market.clone()),
            program: self.seen.program,
            last_clearing: self.last_clearing.clone(),
        }
    }

    /// The epoch rows the actor holds (non-terminal), for tests.
    pub fn epochs(&self) -> impl Iterator<Item = &EpochRow> {
        self.epochs.values()
    }

    /// Whether `(epoch, kind)` has a job running.
    pub fn job_running(&self, epoch: u64, kind: JobKind) -> bool {
        self.jobs.busy(epoch, kind)
    }

    pub fn mode(&self) -> &Mode {
        &self.mode
    }
}

/// The clearing prices of a settled epoch's receipt. `last_clearing`
/// follows the first book's.
fn clearing(row: &EpochRow) -> Option<Vec<timescales_core::ClearingPrice>> {
    let bytes = row.receipt.as_deref()?;
    let receipt =
        <timescales_auction::receipts::ExecutionReceipt as timescales_core::Decode>::decode_exact(
            bytes,
        )
        .ok()?;
    Some(receipt.outcome.clearing)
}
