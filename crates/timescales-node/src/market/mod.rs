//! One actor per market: it owns the `Relay`, the epoch table, quota
//! counters and carried state, and never awaits network I/O. Its transition
//! function [`MarketActor::on`] is pure, so the model test drives it
//! directly.
//!
//! Everything that waits on the network or the disk runs as a job
//! ([`jobs`]): a job performs one transition (or observes that the
//! chain already made it), persists it and reports the epoch's new row.
//! The actor decides which job runs next from the rows it holds, the latest
//! chain observation and the clock. At most one job runs per (epoch, kind).
//! [`runtime`] owns the actor's task, executes its effects in order and
//! feeds back job results and chain observations.

pub mod governance;
pub mod jobs;
mod phase;
pub mod recover;
pub mod runtime;
pub(crate) mod store;

use std::sync::Arc;

pub use phase::{MarketActor, REVEAL_WINDOW, RelayFactory};
use timescales_chain::Address;
use timescales_chain::program::loader::ProgramData;
use timescales_chain::program::{AbortReason, BatchAccount, MarketAccount};
use timescales_core::PriceBand;
use timescales_core::crypto::Keypair;
use timescales_core::{Hash32, MarketParams, OrderCommitment};
use timescales_service::api::{Event, PauseReason, SubmitResult};
use timescales_service::relay::{Padding, Relay};
use timescales_service::store::node::{EpochPatch, EpochRow, Phase, SubmissionRow};

use crate::config::{IdlePolicyConfig, QuotaConfig};
use crate::{AdminCmd, AdminReply, SessionRef, SubmitError, VerifiedSubmission};

/// The moment a command is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    pub ms: u64,
    /// Latest confirmed slot the actor has seen.
    pub slot: u64,
}

/// Correlates a reply with the request that caused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(pub u64);

/// At most one job per (epoch, kind) runs at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JobKind {
    Close,
    Commit,
    Snapshot,
    Reveal,
    Assemble,
    Execute,
    Settle,
    Abort,
    ApplyChange,
    Reclaim,
    Prune,
    Backup,
}

impl JobKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            JobKind::Close => "close",
            JobKind::Commit => "commit",
            JobKind::Snapshot => "snapshot",
            JobKind::Reveal => "reveal",
            JobKind::Assemble => "assemble",
            JobKind::Execute => "execute",
            JobKind::Settle => "settle",
            JobKind::Abort => "abort",
            JobKind::ApplyChange => "apply_change",
            JobKind::Reclaim => "reclaim",
            JobKind::Prune => "prune",
            JobKind::Backup => "backup",
        }
    }
}

/// A job to start. `relay` is set only for `Close`: the relay moves into
/// the job and comes back with its result.
#[derive(Debug)]
pub struct Job {
    pub id: JobId,
    pub epoch: u64,
    pub kind: JobKind,
    pub relay: Option<Box<Relay>>,
}

/// What a finished job reports.
#[derive(Debug)]
pub enum JobResult {
    Done(JobOutput),
    /// Not done. Try again after `after_ms` (the detail is logged).
    Retry {
        detail: String,
        after_ms: u64,
    },
    /// Not done and not retryable without operator action. Logged and
    /// retried at a slow pace.
    Failed(String),
}

#[derive(Debug)]
pub enum JobOutput {
    /// The epoch's row after the job.
    Row(Box<EpochRow>),
    /// The close job's batch is persisted. The relay comes back.
    Closed {
        relay: Box<Relay>,
        row: Box<EpochRow>,
    },
    /// The close job failed before persisting. The relay comes back
    /// unchanged and the close is retried.
    CloseFailed { relay: Box<Relay>, detail: String },
    /// The chain refused the commit because a between-batches change is due.
    ChangeDue { kind: u8 },
    /// The chain is halted. The job waits for it to resume.
    Halted,
    /// A governance change was applied (or nothing was due).
    ChangeApplied { kind: Option<u8> },
    /// The market must stop: equivocation or a state divergence.
    Fence(FenceReason),
    /// Nothing changed (prune, backup, reclaim).
    Nothing,
}

/// Chain state the actor was told about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainObservation {
    pub slot: u64,
    pub market: MarketAccount,
    /// The batch of the lowest non-terminal epoch, when it exists.
    pub batch: Option<BatchAccount>,
    pub relay_lamports: Option<u64>,
    pub cranker_lamports: Option<u64>,
    pub program: Option<ProgramData>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FenceReason {
    StateDivergence,
    ChainAhead,
    Equivocation,
    Store(String),
}

impl FenceReason {
    pub fn as_str(&self) -> &str {
        match self {
            FenceReason::StateDivergence => "state_divergence",
            FenceReason::ChainAhead => "chain_ahead",
            FenceReason::Equivocation => "equivocation",
            FenceReason::Store(s) => s,
        }
    }
}

/// One item of a submission request after intake's checks.
#[derive(Clone, Debug)]
pub struct IntakeItem {
    pub sub: VerifiedSubmission,
    pub received_at_ms: u64,
}

/// A verified key bundle the actor may open an epoch under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleFacts {
    /// `EpochKeyAnnouncement` digest.
    pub key_digest: Hash32,
    pub committee_digest: Hash32,
    pub epoch_pk: [u8; 32],
    /// Canonical `EpochKeyBundle` bytes.
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum Cmd {
    Submit {
        request: RequestId,
        items: Vec<IntakeItem>,
        session: SessionRef,
        /// Envelopes the wallet may place per epoch (collateral-scaled).
        quota: u32,
    },
    Tick,
    /// A verified `EpochKeyBundle` for `epoch`.
    KeyBundle {
        epoch: u64,
        facts: BundleFacts,
    },
    JobDone(JobId, JobResult),
    ChainObserved(Box<ChainObservation>),
    Admin {
        request: RequestId,
        cmd: AdminCmd,
    },
    /// Parked envelopes the wallet retracts (operator-trusted).
    Retract {
        request: RequestId,
        wallet: Address,
        commitment: OrderCommitment,
    },
    /// Parked envelopes of these epochs were invalidated.
    ParkedInvalidated {
        epochs: Vec<u64>,
    },
    Shutdown,
}

/// What a state change needs written before it counts. Writes are
/// applied in the order the actor emits them. A reply waits for every
/// write emitted before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Persist {
    OpenEpoch {
        row: Box<EpochRow>,
        injected: Vec<(OrderCommitment, Address)>,
    },
    Advance {
        epoch: u64,
        phase: Phase,
        patch: Box<EpochPatch>,
    },
    Submission(Box<SubmissionRow>),
    Parked(Vec<SubmissionRow>),
    Retract {
        wallet: Address,
        commitment: OrderCommitment,
        after: u64,
    },
    BundleServed {
        epoch: u64,
    },
}

#[derive(Debug)]
pub enum Reply {
    Submit {
        request: RequestId,
        results: Vec<Result<SubmitResult, SubmitError>>,
    },
    Admin {
        request: RequestId,
        reply: AdminReply,
    },
    Retract {
        request: RequestId,
        removed: Vec<u64>,
        kept_open: Option<u64>,
    },
}

#[derive(Debug)]
pub enum Effect {
    Persist(Persist),
    Reply(Reply),
    Spawn(Job),
    Publish(Box<Event>),
    Fence(FenceReason),
    PauseIntake(PauseReason),
    ResumeIntake,
}

/// Everything static about one market the actor needs.
#[derive(Debug)]
pub struct MarketSettings {
    pub address: Address,
    pub params: MarketParams,
    pub interval_ms: u64,
    pub padding: Padding,
    pub carry_p: f64,
    pub max_real: u32,
    pub park_ahead: u32,
    pub idle: IdlePolicyConfig,
    pub max_idle_extend: u32,
    pub quota: QuotaConfig,
    /// The relay key (promises, announcements, refusals).
    pub relay_key: Arc<Keypair>,
    /// Lamports below which intake pauses (`low_relay_balance`).
    pub min_relay_lamports: u64,
    pub reclaim_batches: bool,
    pub backup_every_epochs: u64,
    pub private_keep_epochs: u64,
}

impl MarketSettings {
    /// Real envelopes one epoch takes, parked reservations included.
    pub fn capacity(&self) -> u32 {
        let cap = self.max_real.min(self.params.max_batch_envelopes);
        match self.padding {
            Padding::Fixed(n) => cap.min(n),
            _ => cap,
        }
    }
}

/// Coarse capacity, as `CurrentEpoch.open.real_slots_left` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotsLeft {
    Available,
    Low,
    Full,
}

/// The open epoch as the API shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenView {
    pub epoch: u64,
    pub opens_at_ms: u64,
    pub cutoff_ms: u64,
    pub band: PriceBand,
    pub binding: Hash32,
    pub terms_digest: Hash32,
    /// Relay-signed `EpochAnnouncement`.
    pub announcement: Vec<u8>,
    pub slots_left: SlotsLeft,
    /// The commitment the announcement's `price_commitment` digests.
    pub price_commitment: Option<timescales_core::oracle::PriceCommitment>,
}

/// Market-level state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Recovering,
    Running,
    Draining,
    Fenced(FenceReason),
}

/// Published after every command. Read without an actor round trip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketView {
    pub market: Address,
    pub mode: Mode,
    pub operator_paused: bool,
    pub pause: Option<PauseReason>,
    pub halted: bool,
    pub open: Option<OpenView>,
    /// Epochs after the open one with a verified bundle, within the park
    /// window.
    pub park_window: Vec<u64>,
    pub previous: Option<(u64, Phase)>,
    pub inflight: Option<(u64, Phase)>,
    /// The epoch intake targets next (the open one, or the next to open).
    pub next_epoch: u64,
    /// Band of the open epoch, for eligibility.
    pub band: Option<PriceBand>,
    pub context_slot: u64,
    pub last_committed: u64,
    pub last_settled: u64,
    pub keys_ready_ahead: u32,
    pub pending_change: Option<u8>,
    pub epochs: Vec<(u64, Phase)>,
    pub last_errors: Vec<String>,
    pub relay_lamports: u64,
    pub cranker_lamports: u64,
    /// The Market account last observed.
    pub chain_market: Option<MarketAccount>,
    pub program: Option<ProgramData>,
    /// Clearing prices of the newest settled epoch.
    pub last_clearing: Vec<timescales_core::ClearingPrice>,
}

/// What the store and chain say about a market at start, after recovery.
/// The actor is built from this and nothing else, which is also how
/// the model test "crashes" it.
#[derive(Debug)]
pub struct Restored {
    /// Non-terminal epochs, ascending.
    pub epochs: Vec<EpochRow>,
    /// The newest terminal epoch.
    pub last_terminal: Option<EpochRow>,
    /// The relay, with the open epoch restored into it if there is one.
    pub relay: Relay,
    /// Accepted submissions of the open epoch: (commitment, wallet,
    /// envelope digest, promise bytes).
    pub open_entries: Vec<(OrderCommitment, Address, Hash32, Vec<u8>)>,
    /// Parked envelopes, verified again, with their stored rows.
    pub parked: Vec<(SubmissionRow, VerifiedSubmission)>,
    /// Epochs with a verified bundle.
    pub bundles: Vec<(u64, BundleFacts)>,
    /// Epochs whose bundles were served in the park window.
    pub served: Vec<u64>,
    /// The first epoch intake may still open (above everything the chain
    /// committed).
    pub next_epoch: u64,
    pub fenced: Option<FenceReason>,
    pub chain: Option<ChainObservation>,
}

/// The on-chain reason of a persisted abort (numbering).
pub fn abort_reason(code: u8) -> Option<AbortReason> {
    AbortReason::try_from(code).ok()
}

/// The public phase a persisted phase maps to (committing -> closed,
/// snapshotted -> committed, sealed -> revealed).
pub fn public_phase(p: Phase) -> timescales_service::api::PublicPhase {
    use timescales_service::api::PublicPhase as P;
    match p {
        Phase::Scheduled => P::Scheduled,
        Phase::Open => P::Open,
        Phase::Closed | Phase::Committing => P::Closed,
        Phase::Committed | Phase::Snapshotted => P::Committed,
        Phase::Revealed | Phase::Sealed => P::Revealed,
        Phase::Executing => P::Executing,
        Phase::Posted => P::Posted,
        Phase::Settled => P::Settled,
        Phase::Aborting => P::Aborting,
        Phase::Aborted => P::Aborted,
    }
}

/// The API's abort reason for a program abort code.
pub fn public_abort_reason(r: AbortReason) -> timescales_service::api::AbortReason {
    use timescales_service::api::AbortReason as A;
    match r {
        AbortReason::Admin => A::Admin,
        AbortReason::Relay => A::Relay,
        AbortReason::BeaconExpired => A::BeaconExpired,
        AbortReason::ExecTimeout => A::ExecTimeout,
        AbortReason::SettleTimeout => A::SettleTimeout,
        AbortReason::QuorumTimeout => A::QuorumTimeout,
    }
}
