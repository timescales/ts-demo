//! Request and response bodies. Field names are the JSON names.
//! `TimeMs` values are JSON numbers (`u64`), `Num` values are `u32`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::{B58, B58Sig, B64, Hex, Hex32, Hex64, Problem, U64};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Book {
    Single,
    MakerAskTakerBid,
    MakerBidTakerAsk,
}

/// Internal phases map as committing->closed, snapshotted->committed,
/// sealed->revealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicPhase {
    Scheduled,
    Open,
    Closed,
    Committed,
    Revealed,
    Executing,
    Posted,
    Settled,
    Aborting,
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    Admin,
    Relay,
    BeaconExpired,
    ExecTimeout,
    SettleTimeout,
    QuorumTimeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PauseReason {
    PipelineBacklog,
    EpochKeyUnavailable,
    Halted,
    Operator,
    LowRelayBalance,
    Recovering,
    Fenced,
    Draining,
    GovernanceDue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Band {
    pub lo: U64,
    pub hi: U64,
    pub reference: U64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Clearing {
    pub book: Book,
    pub tick: U64,
    pub volume: U64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowJson {
    SingleBook,
    DualFlow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RationingJson {
    Lottery,
    ProRata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentSchemeJson {
    Sha256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MarketParamsJson {
    pub market: U64,
    pub base_lot_size: U64,
    pub tick_size: U64,
    pub band_half_width: u32,
    pub max_order_lots_log2: u32,
    pub max_orders_per_trader: u32,
    pub max_batch_envelopes: u32,
    pub max_order_lifetime: u32,
    pub maker_fee_bps: u32,
    pub taker_fee_bps: u32,
    pub flow: FlowJson,
    pub rationing: RationingJson,
    pub commitment_scheme: CommitmentSchemeJson,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnclavePlatform {
    Simulated,
    IntelTdx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuoteGeneration {
    Simulated,
    ConfigfsTsmUntestedOnHardware,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuoteVerification {
    SimulatedVendor,
    IntelDcap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeyGeneration {
    TrustedDealerFeldman,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MpcStatus {
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReferencePrice {
    Fixed,
    LastClearing,
    Operator,
    ModelledTlsnotary,
}

/// Every field is reported by the operator. The SDK upgrades `enclave` to
/// "verified by key committee" only via V-14.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Trust {
    pub enclave: EnclavePlatform,
    pub quote_generation: QuoteGeneration,
    pub quote_verification: QuoteVerification,
    pub key_generation: KeyGeneration,
    /// Always `false`: no DKG is implemented.
    #[schemars(extend("const" = false))]
    pub dkg: bool,
    pub mpc: MpcStatus,
    pub reference_price: ReferencePrice,
    pub receipt_quorum: u32,
    pub registered_executors: u32,
    /// Human-readable, rendered verbatim on /privacy.
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfileJson {
    Local,
    Devnet,
    Production,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Cluster {
    #[serde(rename = "localnet")]
    Localnet,
    #[serde(rename = "devnet")]
    Devnet,
    #[serde(rename = "mainnet-beta")]
    MainnetBeta,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InfoLimits {
    pub submit_max_body_bytes: u32,
    pub session_max_ttl_s: u32,
}

/// `GET /v1/info`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Info {
    pub api_version: String,
    /// Always 1.
    #[schemars(extend("const" = 1))]
    pub protocol_version: u32,
    /// Always 2.
    #[schemars(extend("const" = 2))]
    pub header_version: u32,
    pub node_version: String,
    pub git_sha: String,
    pub profile: ProfileJson,
    pub cluster: Cluster,
    pub genesis_hash: B58,
    pub program_id: B58,
    pub server_time_ms: u64,
    pub markets: Vec<B58>,
    pub trust: Trust,
    pub limits: InfoLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OverallStatus {
    Ok,
    Degraded,
    Down,
    Recovering,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    Ok,
    Degraded,
    Down,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StatusComponent {
    /// `api|store|chain_rpc|dealer|enclave:<n>|pipeline:<market>|epoch_keys:<market>`.
    pub name: String,
    pub status: ComponentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub since_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MarketState {
    Running,
    Paused,
    Draining,
    Fenced,
    Recovering,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Intake {
    Open,
    Paused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MarketStatus {
    pub market: B58,
    pub state: MarketState,
    pub intake: Intake,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<PauseReason>,
    pub current_epoch: Option<U64>,
    pub last_committed: U64,
    pub last_settled: U64,
    pub settlement_lag: u32,
    pub keys_ready_ahead: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NoticeLevel {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Notice {
    pub level: NoticeLevel,
    pub message: String,
    pub since_ms: u64,
}

/// `GET /v1/status`. Also the payload of `status.changed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Status {
    pub status: OverallStatus,
    pub server_time_ms: u64,
    pub components: Vec<StatusComponent>,
    pub markets: Vec<MarketStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<Notice>,
}

/// `GET /v1/time`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Time {
    pub server_time_ms: u64,
    pub slot: U64,
}

/// `{ items }` responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "{T}Items")]
pub struct Items<T> {
    pub items: Vec<T>,
}

/// Paginated responses, newest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "{T}Page")]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_before: Option<U64>,
}

/// An item of `GET /v1/markets`. Symbols are display hints only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MarketSummary {
    pub market: B58,
    pub name: String,
    pub base_symbol: String,
    pub quote_symbol: String,
    pub state: MarketState,
    pub halted: bool,
    pub last_clearing: Option<Vec<Clearing>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommitteeMemberView {
    pub index: u32,
    pub identity: Hex32,
    pub transport: Hex32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommitteeView {
    pub digest: Hex32,
    pub description_b64: B64,
    pub threshold: u32,
    pub members: Vec<CommitteeMemberView>,
    /// Graceful rotation.
    pub prev_digest: Option<Hex32>,
    pub prev_description_b64: Option<B64>,
    /// Signed ReleasePolicyStatements (V-14).
    pub policies_b64: Vec<B64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TimingView {
    pub epoch_interval_ms: u32,
    pub beacon_delay_slots: u32,
    pub exec_timeout_slots: U64,
    pub settle_timeout_slots: U64,
    pub timelock_slots: U64,
    pub max_park_ahead_epochs: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PaddingView {
    PowerOfTwo { min: u32 },
    Fixed { n: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AckView {
    Immediate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdlePolicy {
    Commit,
    Extend,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RelayPolicyView {
    pub padding: PaddingView,
    pub ack: AckView,
    pub max_envelopes_per_wallet_per_epoch: u32,
    pub max_parked_per_wallet: u32,
    pub min_available_value_quote: U64,
    pub min_value_per_envelope_quote: U64,
    pub require_trader_account: bool,
    pub idle_policy: IdlePolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MintAuthority {
    pub mint: Option<B58>,
    pub freeze: Option<B58>,
}

/// Display only. V-1 re-reads the mints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MintAuthorities {
    pub base: MintAuthority,
    pub quote: MintAuthority,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BookLabel {
    pub book: Book,
    pub label: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    SetRelay,
    SetExecutors,
    SetCommitteeDigest,
    SetAdmin,
    SetTimings,
    SetTimelock,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PendingChangeView {
    pub kind: ChangeKind,
    pub eta_slot: U64,
    pub payload_b64: B64,
    pub due: bool,
}

/// Display only. V-16 re-reads ProgramData.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramView {
    pub upgrade_authority: Option<B58>,
    pub last_deploy_slot: U64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MarketChainState {
    pub last_committed: U64,
    pub last_settled: U64,
    pub state_root: Hex32,
    pub prev_receipt: Hex32,
    pub context_slot: U64,
}

/// `GET /v1/markets/{market}`. Clients re-read the Market account from
/// their own RPC and compare (V-1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MarketDetail {
    #[serde(flatten)]
    pub summary: MarketSummary,
    pub market_id: U64,
    pub creator: B58,
    pub admin: B58,
    pub params: MarketParamsJson,
    pub params_b64: B64,
    pub params_digest: Hex32,
    pub base_mint: B58,
    pub quote_mint: B58,
    pub base_vault: B58,
    pub quote_vault: B58,
    pub base_decimals: u32,
    pub quote_decimals: u32,
    pub relay: B58,
    pub executors: Vec<B58>,
    pub receipt_quorum: u32,
    pub committee: CommitteeView,
    pub timing: TimingView,
    pub relay_policy: RelayPolicyView,
    /// V-1 recomputes market_id = LE64(H(MARKET_ID, program || creator || salt)).
    pub market_id_salt: Hex32,
    pub session_domains: Vec<String>,
    pub mint_authorities: MintAuthorities,
    pub books: Vec<BookLabel>,
    pub pending_change: Option<PendingChangeView>,
    pub program: ProgramView,
    pub chain: MarketChainState,
}

/// `GET /v1/markets/{market}/epochs/{epoch}/key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EpochKey {
    pub epoch: U64,
    pub epoch_pk: Hex32,
    pub committee_digest: Hex32,
    /// `EpochKeyBundle`.
    pub bundle_b64: B64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Observation {
    pub source: u32,
    pub tick: U64,
    pub time: U64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PriceCommitmentView {
    pub digest: Hex32,
    pub reference: U64,
    pub source: ReferencePrice,
    pub observations: Vec<Observation>,
    pub commitment_b64: B64,
}

/// Deliberately coarse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RealSlotsLeft {
    Available,
    Low,
    Full,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpenEpoch {
    pub epoch: U64,
    pub opens_at_ms: u64,
    pub cutoff_ms: u64,
    pub band: Band,
    pub binding: Hex32,
    pub terms_digest: Hex32,
    pub price_commitment: PriceCommitmentView,
    /// Relay-signed `EpochAnnouncement`.
    pub announcement_b64: B64,
    pub key: EpochKey,
    pub real_slots_left: RealSlotsLeft,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EpochPhaseRef {
    pub epoch: U64,
    pub phase: PublicPhase,
}

/// `GET /v1/markets/{market}/epochs/current`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CurrentEpoch {
    pub market: B58,
    pub server_time_ms: u64,
    pub intake: Intake,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<PauseReason>,
    pub open: Option<OpenEpoch>,
    /// Epochs open+1..= open+max_park_ahead_epochs that have verified bundles.
    pub park_window: Vec<EpochKey>,
    pub previous: Option<EpochPhaseRef>,
    pub inflight: Option<EpochPhaseRef>,
    /// Chain slot the node's view is based on (V-1 compares at this slot).
    pub context_slot: U64,
}

/// An item of `GET /v1/markets/{market}/epochs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EpochSummary {
    pub market: B58,
    pub epoch: U64,
    pub phase: PublicPhase,
    pub opens_at_ms: u64,
    pub cutoff_ms: u64,
    /// Includes cover.
    pub envelope_count: Option<u32>,
    pub clearing: Option<Vec<Clearing>>,
    pub fill_count: Option<u32>,
    pub terminal_at_ms: Option<u64>,
    pub abort_reason: Option<AbortReason>,
    pub tee_platform: Option<EnclavePlatform>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Quorum {
    pub have: u32,
    pub need: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BatchView {
    pub address: B58,
    pub status: String,
    pub root: Hex32,
    pub count: u32,
    pub terms_digest: Hex32,
    pub commit_slot: U64,
    pub commit_signature: B58Sig,
    pub beacon: Option<Hex32>,
    pub beacon_slots: Option<[U64; 2]>,
    pub reveal_slot: Option<U64>,
    pub header_digest: Option<Hex32>,
    pub receipt_digest: Option<Hex32>,
    pub outcome_digest: Option<Hex32>,
    pub cosigners: Vec<B58>,
    pub quorum: Quorum,
    pub settlement_count: Option<u32>,
    pub fees: Option<U64>,
    pub context_slot: U64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptBackend {
    Tee,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OutcomeView {
    pub header_digest: Hex32,
    pub clearing: Vec<Clearing>,
    pub fill_count: u32,
    pub fills_root: Hex32,
    pub cancelled_root: Hex32,
    pub next_state_root: Hex32,
    pub settlement_count: u32,
    pub settlement_root: Hex32,
    pub fees: U64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptView {
    pub version: u32,
    pub digest: Hex32,
    pub backend: ReceiptBackend,
    pub executor: B58,
    pub attestation: Hex32,
    pub proof: Hex32,
    pub trace: Hex32,
    pub outcome: OutcomeView,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Posted,
    Verifying,
    Verified,
    Applying,
    Settled,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementView {
    pub status: SettlementStatus,
    pub verified: u32,
    pub applied: u32,
    pub total: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TxKind {
    Commit,
    Reveal,
    Post,
    Cosign,
    Verify,
    Finalize,
    Apply,
    Close,
    Abort,
    Reclaim,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TxView {
    pub op: TxKind,
    pub signature: B58Sig,
    pub slot: Option<U64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AbortView {
    pub reason: AbortReason,
    pub detail: String,
}

/// `GET /v1/markets/{market}/epochs/{epoch}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EpochDetail {
    #[serde(flatten)]
    pub summary: EpochSummary,
    pub band: Band,
    pub terms_digest: Hex32,
    pub announcement_b64: B64,
    pub key: EpochKey,
    pub batch: Option<BatchView>,
    /// True once the quorum is on chain.
    pub artifacts_public: bool,
    pub header_b64: Option<B64>,
    pub receipt_b64: Option<B64>,
    pub receipt: Option<ReceiptView>,
    pub settlement: Option<SettlementView>,
    pub txs: Vec<TxView>,
    pub abort: Option<AbortView>,
}

/// `GET /v1/markets/{market}/epochs/{epoch}/leaves`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Leaves {
    pub market: B58,
    pub epoch: U64,
    pub root: Hex32,
    pub count: u32,
    /// count x (C32 || envelope_digest32), sorted.
    pub leaves_b64: B64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CosignatureView {
    pub executor: B58,
    pub signature: Hex64,
}

/// `GET /v1/markets/{market}/epochs/{epoch}/artifacts`, public once the
/// receipt quorum is on chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Artifacts {
    pub market: B58,
    pub epoch: U64,
    pub header_b64: B64,
    pub receipt_b64: B64,
    /// `ExecutionArtifacts`.
    pub artifacts_b64: B64,
    pub attestation_b64: Option<B64>,
    pub attestation_platform: EnclavePlatform,
    pub cosignatures: Vec<CosignatureView>,
}

/// An item of `GET /v1/markets/{market}/clearing`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TapeRow {
    pub epoch: U64,
    pub cutoff_ms: u64,
    pub phase: PublicPhase,
    pub clearing: Vec<Clearing>,
    pub matched_lots: U64,
    pub fill_count: u32,
    pub envelope_count: u32,
    pub terminal_at_ms: Option<u64>,
}

/// An item of `GET /v1/executors`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutorRegistration {
    pub market: B58,
    pub executor: B58,
    pub seal_key: Hex32,
    pub platform: EnclavePlatform,
    pub measurement: Hex32,
    pub nonce: Hex32,
    pub evidence_b64: B64,
    pub registered: bool,
    pub label: String,
}

/// An item of `GET /v1/markets/{market}/committee/policies`: a signed
/// `ReleasePolicyStatement` (V-14).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyStatementView {
    pub member: u32,
    pub statement_b64: B64,
}

/// `GET /v1/sessions/nonce`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionNonce {
    /// 16 bytes.
    pub nonce: Hex,
    pub expires_at_ms: u64,
    pub domain: String,
    pub uri: String,
    pub chain_id: String,
    pub statement: String,
    /// Always 1.
    #[schemars(extend("const" = 1))]
    pub template_version: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantMethodJson {
    SignIn,
    SignMessage,
}

/// `POST /v1/sessions`: `CreateSessionRequest & CreateSessionOptions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionRequest {
    pub wallet: B58,
    /// Exact signed UTF-8, at most 1024 bytes.
    pub message: String,
    pub signature_b64: B64,
    pub method: GrantMethodJson,
    /// E.g. the slot of the deposit that made the wallet eligible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_context_slot: Option<U64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Quotas {
    pub max_envelopes_per_wallet_per_epoch: u32,
    pub max_parked_per_wallet: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Usage {
    pub epoch: U64,
    pub used: u32,
    pub parked: u32,
}

/// `POST /v1/sessions` and `GET /v1/sessions/current`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Session {
    pub session_key: Hex32,
    pub wallet: B58,
    pub market: Option<B58>,
    pub expires_at_ms: u64,
    pub quotas: Quotas,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Older sessions revoked to stay within max_per_wallet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evicted: Option<u32>,
}

/// `POST /v1/markets/{market}/submissions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubmitRequest {
    /// 386-byte `Submission`, trader = session key.
    pub submission_b64: B64,
}

/// `POST /v1/markets/{market}/submissions/batch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubmitBatchRequest {
    /// 1..= max_park_ahead_epochs + 1 submissions, one order's epochs.
    pub submissions_b64: Vec<B64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubmitStatus {
    Accepted,
    Parked,
}

/// `202` of `POST /v1/markets/{market}/submissions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SubmitResult {
    pub status: SubmitStatus,
    pub market: B58,
    pub epoch: U64,
    pub commitment: Hex32,
    pub envelope_digest: Hex32,
    pub received_at_ms: u64,
    /// 201-byte `InclusionPromiseV2`.
    pub promise_b64: B64,
    pub duplicate: bool,
}

/// `Problem & { refusal_b64?: B64 }`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SubmitItemError {
    #[serde(flatten)]
    pub problem: Problem,
    /// Relay-signed `RelayRefusal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_b64: Option<B64>,
}

impl From<Problem> for SubmitItemError {
    /// Lifts the relay-signed refusal of the problem's details, if any, to
    /// the item's `refusal_b64`.
    fn from(problem: Problem) -> Self {
        let refusal_b64 = problem
            .parsed_details()
            .ok()
            .flatten()
            .and_then(|d| d.refusal().cloned());
        SubmitItemError {
            problem,
            refusal_b64,
        }
    }
}

/// An item of the `207` of `POST /v1/markets/{market}/submissions/batch`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubmitItemResult {
    Ok(SubmitResult),
    Error(SubmitItemError),
}

/// An item of `GET /v1/markets/{market}/parked`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ParkedItem {
    pub epoch: U64,
    pub commitment: Hex32,
}

/// `POST /v1/markets/{market}/parked/retract`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetractRequest {
    pub commitment: Hex32,
}

/// Result of `POST /v1/markets/{market}/parked/retract`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RetractResult {
    pub removed_epochs: Vec<U64>,
    pub kept_open_epoch: Option<U64>,
}
