//! `timescales-node`: relay, epoch coordinator, chain driver, settlement
//! watchdog and public API for a set of markets (section D).
//!
//! The engine (one [`market::MarketActor`] per market, jobs, recovery,
//! sessions, intake, execution dispatch, settlement) and the HTTP layer
//! ([`api`]) meet only at [`NodeApi`].

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod api;
pub mod app;
pub mod archive;
pub mod chain;
pub mod clock;
pub mod config;
pub mod events;
pub mod exec;
pub mod handle;
pub mod intake;
pub mod keys;
pub mod market;
pub mod reference;
pub mod sessions;
pub mod settle;
pub mod telemetry;

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use thiserror::Error;
use timescales_chain::{MarketChain, SolanaRpc, TxSigner};
use timescales_core::OrderCommitment;
use timescales_core::crypto::Keypair;
use timescales_service::api::{
    CreateSessionRequest, CurrentEpoch, ErrorCode, Info, MarketDetail, MarketSummary, ParkedItem,
    RetractResult, Session, SessionNonce, Status, StreamEvent, SubmitResult,
};
use timescales_service::store::node::{NodeRepo, Phase};
use timescales_service::store::{BackupReport, SecretSealer};
use timescales_service::wire::{
    EnclaveIdentity, EnvelopeSigner, EpochKeyBundle, ExecutePosted, ExecuteReady, ExecuteRequest,
    PublishRequest,
};
use tokio::sync::broadcast;
use zeroize::Zeroizing;

pub use clock::{Clock, ManualClock, SystemClock};
pub use config::NodeConfig;
pub use handle::NodeHandle;
pub use timescales_chain::Address;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Size of the runtime's blocking pool. Submission verification may
/// hold half of it, so closes, header assembly and store reads still get
/// threads under a flood of submissions.
pub const MAX_BLOCKING_THREADS: usize = 64;

#[derive(Debug, Error)]
pub enum ExecClientError {
    #[error("enclave {0} unknown")]
    UnknownEnclave(usize),
    #[error(transparent)]
    Client(#[from] timescales_service::ClientError),
    #[error("decode: {0}")]
    Decode(#[from] timescales_core::DecodeError),
    /// An `ErrorResponse` from the enclave (BindingMismatch, BalanceMismatch,
    /// KeyUnavailable, PostFailed, OutcomeMismatch, QuorumPending,...).
    #[error("enclave refused: {code}: {detail}")]
    Refused { code: String, detail: String },
}

/// Client of the enclave services, by index into `[[execution.enclave]]`.
pub trait ExecClient: Send + Sync {
    fn execute(
        &self,
        enclave: usize,
        req: Arc<ExecuteRequest>,
    ) -> BoxFuture<'_, Result<ExecuteReady, ExecClientError>>;
    fn publish(
        &self,
        enclave: usize,
        req: PublishRequest,
    ) -> BoxFuture<'_, Result<ExecutePosted, ExecClientError>>;
    fn identity(&self, enclave: usize) -> BoxFuture<'_, Result<EnclaveIdentity, ExecClientError>>;
}

pub struct NodeKeys {
    pub relay: Arc<dyn TxSigner>,
    /// The relay key again: signs promises, announcements and refusals.
    pub relay_signing: Arc<Keypair>,
    pub cranker: Arc<dyn TxSigner>,
    pub service: Arc<dyn EnvelopeSigner>,
    pub kek: Arc<dyn SecretSealer>,
    pub nonce_key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for NodeKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeKeys")
            .field("relay", &self.relay.address())
            .field("service", &self.service.public())
            .finish_non_exhaustive()
    }
}

pub struct NodeDeps {
    pub chains: BTreeMap<Address, Arc<dyn MarketChain>>,
    pub rpc: Arc<dyn SolanaRpc>,
    pub store: NodeRepo,
    pub exec: Arc<dyn ExecClient>,
    pub clock: Arc<dyn Clock>,
    pub keys: NodeKeys,
}

impl core::fmt::Debug for NodeDeps {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeDeps")
            .field("markets", &self.chains.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum NodeError {
    #[error(transparent)]
    Store(#[from] timescales_service::store::StoreError),
    #[error(transparent)]
    Chain(#[from] timescales_chain::ChainError),
    #[error(transparent)]
    Config(#[from] timescales_service::ConfigError),
    #[error("market {0:?} unknown")]
    MarketUnknown(Address),
    #[error("{code:?}: {detail}")]
    Api { code: ErrorCode, detail: String },
    #[error("shutting down")]
    ShuttingDown,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("{code:?}: {detail}")]
    Refused { code: ErrorCode, detail: String },
    #[error(transparent)]
    Node(#[from] NodeError),
}

/// The authenticated session behind a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionRef {
    pub session_key: [u8; 32],
    pub wallet: Address,
    pub market: Option<Address>,
}

/// A submission as the API layer hands it to the engine. Intake decodes
/// `raw` again and verifies its signature on the verification pool before
/// anything else, so `inner` is only a convenience for the caller.
/// [`NodeHandle::verify_submission`] builds one from the request bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSubmission {
    /// The exact 386 bytes.
    pub raw: Vec<u8>,
    pub inner: timescales_service::relay::VerifiedSubmission,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SubmitError {
    pub code: ErrorCode,
    pub details: serde_json::Value,
    pub retry_after_ms: Option<u64>,
    /// Relay-signed `RelayRefusal`.
    pub refusal: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EventsSince {
    Events {
        events: Vec<StreamEvent>,
        head_seq: u64,
    },
    TooOld {
        head_seq: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminCmd {
    Status,
    Pause(Address),
    Resume(Address),
    Drain(Address),
    SetReference(Address, u64),
    Abort(Address, u64),
    Backup,
}

/// One market as the admin status reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminMarketStatus {
    pub market: Address,
    pub state: String,
    pub epochs: Vec<(u64, Phase)>,
    pub settlement_lag: u64,
    pub keys_ready_ahead: u32,
    pub relay_balance_lamports: u64,
    pub cranker_balance_lamports: u64,
    pub pending_change: Option<u8>,
    pub last_errors: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminStatus {
    pub markets: Vec<AdminMarketStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminReply {
    Status(AdminStatus),
    Ok,
    Refused {
        reason: String,
        runbook: &'static str,
    },
    Backup(BackupReport),
}

/// The only interface between engine and API (object-safe, so the engine
/// and the HTTP layer are built in parallel). DTOs are the service API's.
pub trait NodeApi: Send + Sync {
    fn info(&self) -> Info;
    fn status(&self) -> Status;
    fn markets(&self) -> Vec<MarketSummary>;
    fn market(&self, m: Address) -> Option<MarketDetail>;
    /// From a watch channel. No actor round trip.
    fn current(&self, m: Address) -> Option<CurrentEpoch>;
    fn submit(
        &self,
        m: Address,
        items: Vec<VerifiedSubmission>,
        session: SessionRef,
    ) -> BoxFuture<'_, Vec<Result<SubmitResult, SubmitError>>>;
    fn parked(
        &self,
        m: Address,
        session: SessionRef,
    ) -> BoxFuture<'_, Result<Vec<ParkedItem>, NodeError>>;
    fn retract_parked(
        &self,
        m: Address,
        session: SessionRef,
        c: OrderCommitment,
    ) -> BoxFuture<'_, Result<RetractResult, NodeError>>;
    fn session_nonce(&self) -> BoxFuture<'_, Result<SessionNonce, NodeError>>;
    fn create_session(
        &self,
        req: CreateSessionRequest,
        min_context_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Session, SessionError>>;
    fn session(&self, key: [u8; 32]) -> BoxFuture<'_, Result<Option<Session>, NodeError>>;
    fn revoke_session(&self, key: [u8; 32]) -> BoxFuture<'_, Result<(), NodeError>>;
    fn events(&self) -> broadcast::Receiver<Arc<events::LiveEvent>>;
    fn events_since(
        &self,
        seq: u64,
        topics: Vec<String>,
    ) -> BoxFuture<'_, Result<EventsSince, NodeError>>;
    /// Changes on every boot and on restore.
    fn stream_id(&self) -> [u8; 16];
    /// Read side ("public reads").
    fn store(&self) -> &NodeRepo;
    fn put_key_bundle(&self, m: Address, b: EpochKeyBundle)
    -> BoxFuture<'_, Result<(), NodeError>>;
    fn admin(&self, cmd: AdminCmd) -> BoxFuture<'_, Result<AdminReply, NodeError>>;
}

/// Starts every market of `cfg` over `deps`: start-up recovery per
/// market, then the actors, their jobs and chain watchers. The HTTP layer
/// is not started here. It is built over the returned handle.
pub async fn start(cfg: NodeConfig, deps: NodeDeps) -> Result<NodeHandle, NodeError> {
    handle::start(cfg, deps).await
}
