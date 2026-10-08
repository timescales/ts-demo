//! The WebSocket stream `GET /v1/stream`: events, and the frames
//! clients and the node exchange.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::{
    AbortReason, B58, B58Sig, B64, Band, ChangeKind, Clearing, CurrentEpoch, EpochKey, ErrorCode,
    Hex, Hex32, MarketState, PauseReason, Status, U64,
};

/// One event of the node's log. `seq` is global, `topic_seq` contiguous per
/// topic.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StreamEvent {
    pub seq: U64,
    pub topic_seq: U64,
    pub topic: String,
    pub at_ms: u64,
    pub event: Event,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStage {
    Verifying,
    Applying,
}

/// Event payloads, tagged by `kind`. Events are hints: clients re-read REST
/// and chain state before changing an order's state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum Event {
    #[serde(rename = "key.published")]
    KeyPublished { market: B58, epoch: U64 },
    #[serde(rename = "epoch.opened")]
    EpochOpened {
        market: B58,
        epoch: U64,
        opens_at_ms: u64,
        cutoff_ms: u64,
        band: Band,
        terms_digest: Hex32,
        announcement_b64: B64,
        key: EpochKey,
    },
    /// No counts.
    #[serde(rename = "epoch.closed")]
    EpochClosed { market: B58, epoch: U64 },
    #[serde(rename = "epoch.committed")]
    EpochCommitted {
        market: B58,
        epoch: U64,
        root: Hex32,
        count: u32,
        slot: U64,
        signature: B58Sig,
    },
    #[serde(rename = "epoch.revealed")]
    EpochRevealed {
        market: B58,
        epoch: U64,
        beacon: Hex32,
        beacon_slots: [U64; 2],
        finalized: bool,
    },
    #[serde(rename = "epoch.executing")]
    EpochExecuting { market: B58, epoch: U64 },
    #[serde(rename = "epoch.posted")]
    EpochPosted {
        market: B58,
        epoch: U64,
        receipt_digest: Hex32,
        clearing: Vec<Clearing>,
        fill_count: u32,
        settlement_count: u32,
    },
    #[serde(rename = "epoch.cosigned")]
    EpochCosigned {
        market: B58,
        epoch: U64,
        executor: B58,
    },
    /// At most one per second.
    #[serde(rename = "epoch.settlement")]
    EpochSettlement {
        market: B58,
        epoch: U64,
        stage: SettlementStage,
        done: u32,
        total: u32,
    },
    #[serde(rename = "epoch.settled")]
    EpochSettled { market: B58, epoch: U64, slot: U64 },
    #[serde(rename = "epoch.aborting")]
    EpochAborting {
        market: B58,
        epoch: U64,
        reason: AbortReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        earliest_slot: Option<U64>,
    },
    #[serde(rename = "epoch.aborted")]
    EpochAborted {
        market: B58,
        epoch: U64,
        reason: AbortReason,
    },
    #[serde(rename = "intake.paused")]
    IntakePaused {
        market: B58,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<PauseReason>,
    },
    #[serde(rename = "intake.resumed")]
    IntakeResumed { market: B58 },
    /// The change kind is `change`: `kind` is the event tag.
    #[serde(rename = "governance.pending")]
    GovernancePending {
        market: B58,
        change: ChangeKind,
        eta_slot: U64,
        due: bool,
    },
    #[serde(rename = "governance.applied")]
    GovernanceApplied {
        market: B58,
        change: ChangeKind,
        slot: U64,
    },
    /// Artifacts become public when `have >= need`.
    #[serde(rename = "epoch.quorum")]
    EpochQuorum {
        market: B58,
        epoch: U64,
        have: u32,
        need: u32,
    },
    /// Emergency committee rotation.
    #[serde(rename = "parked.invalidated")]
    ParkedInvalidated { market: B58, epochs: Vec<U64> },
    /// ProgramData `last_deploy_slot` changed.
    #[serde(rename = "program.upgraded")]
    ProgramUpgraded { slot: U64 },
    #[serde(rename = "market.state")]
    MarketStateChanged {
        market: B58,
        state: MarketState,
        halted: bool,
    },
    /// Topic `status`.
    #[serde(rename = "status.changed")]
    StatusChanged(Box<Status>),
}

impl Event {
    /// The `kind` tag.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::KeyPublished { .. } => "key.published",
            Event::EpochOpened { .. } => "epoch.opened",
            Event::EpochClosed { .. } => "epoch.closed",
            Event::EpochCommitted { .. } => "epoch.committed",
            Event::EpochRevealed { .. } => "epoch.revealed",
            Event::EpochExecuting { .. } => "epoch.executing",
            Event::EpochPosted { .. } => "epoch.posted",
            Event::EpochCosigned { .. } => "epoch.cosigned",
            Event::EpochSettlement { .. } => "epoch.settlement",
            Event::EpochSettled { .. } => "epoch.settled",
            Event::EpochAborting { .. } => "epoch.aborting",
            Event::EpochAborted { .. } => "epoch.aborted",
            Event::IntakePaused { .. } => "intake.paused",
            Event::IntakeResumed { .. } => "intake.resumed",
            Event::GovernancePending { .. } => "governance.pending",
            Event::GovernanceApplied { .. } => "governance.applied",
            Event::EpochQuorum { .. } => "epoch.quorum",
            Event::ParkedInvalidated { .. } => "parked.invalidated",
            Event::ProgramUpgraded { .. } => "program.upgraded",
            Event::MarketStateChanged { .. } => "market.state",
            Event::StatusChanged(_) => "status.changed",
        }
    }
}

/// WebSocket subprotocol of the stream.
pub const STREAM_SUBPROTOCOL: &str = "timescales.v1";

/// Version carried in every server frame (`v`).
pub const STREAM_FRAME_VERSION: u32 = 1;

/// Topic of the node's status (`status.changed`).
pub const STATUS_TOPIC: &str = "status";

/// Topic of one market's events: `market:<b58>`.
pub fn market_topic(market: &B58) -> String {
    format!("market:{market}")
}

/// Client to node frames (inbound frames are at most 4 KiB).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    /// Resume with `since_seq` only for an unchanged `stream_id`.
    Subscribe {
        topics: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since_seq: Option<U64>,
        /// The `stream_id` the client last saw. With `since_seq`, the node
        /// answers `resync_required { stream_changed }` when it differs
        /// instead of replaying a log the client never followed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stream_id: Option<Hex>,
    },
    Unsubscribe {
        topics: Vec<String>,
    },
    Ping {
        t: u64,
    },
}

/// Node to client frame: `{ "v": 1, "type":...,... }`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ServerFrame {
    /// Always 1.
    #[schemars(extend("const" = 1))]
    pub v: u32,
    #[serde(flatten)]
    pub message: ServerMessage,
}

impl ServerFrame {
    pub fn new(message: ServerMessage) -> Self {
        Self {
            v: STREAM_FRAME_VERSION,
            message,
        }
    }
}

/// Why a client must refetch over REST and subscribe without `since_seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResyncReason {
    SeqTooOld,
    Lagged,
    /// `since_seq > head_seq`.
    UnknownSeq,
    /// The client's last `stream_id` differs: after a restore or failover
    /// `head_seq` may move backwards.
    StreamChanged,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Followed by one `snapshot` per subscribed market topic.
    Subscribed {
        topics: Vec<String>,
        head_seq: U64,
        /// 16 bytes. New on every boot and restore.
        stream_id: Hex,
        topic_seqs: BTreeMap<String, U64>,
    },
    Snapshot {
        topic: String,
        seq: U64,
        topic_seq: U64,
        current: Box<CurrentEpoch>,
    },
    Event(StreamEvent),
    /// Every `ws_heartbeat_ms`.
    Heartbeat {
        server_time_ms: u64,
        head_seq: U64,
        stream_id: Hex,
    },
    Pong {
        t: u64,
        server_time_ms: u64,
    },
    ResyncRequired {
        reason: ResyncReason,
    },
    Error {
        code: ErrorCode,
        detail: String,
    },
}
