//! Solana access for the Timescales services.
//!
//! * [`SolanaRpc`] is the only way any service talks to a cluster. Two
//!   implementations: [`HttpRpc`] over `solana-rpc-client` (feature
//!   `rpc-client`, the default) and [`MinimalRpc`], a small hand-written
//!   JSON-RPC client that keeps the enclave's TCB small (feature
//!   `rpc-minimal`). [`QuorumRpc`] reads from several providers and answers
//!   only when they agree.
//! * [`TxSender`] signs, sends and confirms transactions, recording each one
//!   in a [`TxJournal`] before it is sent, so a restart can resolve every
//!   transaction whose outcome it did not see.
//! * [`MarketChain`] is one idempotent observe-then-act operation per
//!   program flow. [`SolanaMarketChain`] implements it.
//!
//! Test support: [`LiteSvmRpc`] (feature `litesvm`) runs the real program in
//! LiteSVM and emulates commitment levels, and [`FaultyRpc`] (feature
//! `test-util`) injects faults into any provider.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::program::errors::ProgramKind;
use crate::program::{
    AbortReason, BatchAccount, BatchStatus, ClientError, MarketAccount, TimescalesProgramError,
    TraderAccount,
};
use thiserror::Error;
use timescales_auction::collateral::{Balance, BalanceSheet};
use timescales_auction::settlement::SettlementBatch;
use timescales_core::{BaseAtoms, Hash32, QuoteAtoms, TraderId};
use tokio::sync::mpsc;
use tokio::time::Instant;

mod market;
mod providers;
mod sender;
mod signer;
mod wire;

pub use market::{MarketChainConfig, SolanaMarketChain};
#[cfg(feature = "rpc-client")]
pub use providers::HttpRpc;
#[cfg(any(feature = "rpc-client", feature = "rpc-minimal"))]
pub use providers::RpcErrorCount;
#[cfg(feature = "test-util")]
pub use providers::{FaultyRpc, RpcMethod};
#[cfg(feature = "rpc-minimal")]
pub use providers::{HttpReply, HttpTransport, MinimalRpc, ReqwestTransport};
#[cfg(feature = "litesvm")]
pub use providers::{LiteSvmConfig, LiteSvmRpc, settlement_program_so};
pub use providers::{ProviderError, QuorumRpc};
pub use sender::{SendOptions, TxSender};
pub use signer::FileSigner;

pub type Address = [u8; 32];

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Processed,
    Confirmed,
    Finalized,
}

impl Level {
    /// The JSON-RPC commitment name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Level::Processed => "processed",
            Level::Confirmed => "confirmed",
            Level::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountData {
    pub owner: Address,
    pub lamports: u64,
    pub data: Vec<u8>,
    pub context_slot: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    DataSize(u64),
    Memcmp { offset: u64, bytes: Vec<u8> },
}

/// Why a transaction failed, as far as the cluster reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxErrorDetail {
    /// Index of the failing instruction, when the error names one.
    pub ix_index: Option<u8>,
    /// `Custom(code)` of an instruction error.
    pub custom: Option<u32>,
    /// The cluster's error: the variant name for a unit error such as
    /// `BlockhashNotFound`, otherwise the error's compact JSON as the RPC
    /// encodes it, e.g. `{"InstructionError":[2,{"Custom":6014}]}`.
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxStatus {
    pub slot: u64,
    pub level: Level,
    pub err: Option<TxErrorDetail>,
}

/// Result of `simulateTransaction`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Simulation {
    pub units: Option<u64>,
    pub logs: Vec<String>,
    pub err: Option<TxErrorDetail>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RpcError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("HTTP status {0}")]
    Http(u16),
    #[error("rate limited")]
    RateLimited,
    #[error("timed out")]
    Timeout,
    #[error("RPC error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("node has not reached slot {min_slot}")]
    MinContextSlot { min_slot: u64 },
    #[error("malformed response: {0}")]
    Decode(String),
    #[error("providers disagree")]
    Disagree,
    #[error("no provider available")]
    Unavailable,
    /// `sendTransaction` simulated the transaction first and the simulation
    /// failed, so the node did not forward it.
    #[error("preflight failed: {}", .err.message)]
    Preflight {
        err: TxErrorDetail,
        logs: Vec<String>,
    },
}

impl RpcError {
    /// The `kind` label of `timescales_chain_rpc_errors_total`.
    pub const fn kind(&self) -> &'static str {
        match self {
            RpcError::Transport(_) => "transport",
            RpcError::Http(_) => "http",
            RpcError::RateLimited => "rate_limited",
            RpcError::Timeout => "timeout",
            RpcError::Rpc { .. } => "rpc",
            RpcError::MinContextSlot { .. } => "min_context_slot",
            RpcError::Decode(_) => "decode",
            RpcError::Disagree => "disagree",
            RpcError::Unavailable => "unavailable",
            RpcError::Preflight { .. } => "preflight",
        }
    }

    /// The endpoint did not answer the request: a transport failure, a
    /// timeout, HTTP 429 or a 5xx status. These failures count towards
    /// failover. A JSON-RPC error does not, because the node answered it.
    pub const fn is_transport(&self) -> bool {
        matches!(
            self,
            RpcError::Transport(_) | RpcError::Timeout | RpcError::RateLimited
        ) || matches!(self, RpcError::Http(status) if *status >= 500)
    }

    /// The node answered `sendTransaction` with a JSON-RPC error, so it did
    /// not forward the transaction. After any other failure the transaction
    /// may or may not have been forwarded.
    pub const fn refused_send(&self) -> bool {
        matches!(
            self,
            RpcError::Rpc { .. } | RpcError::MinContextSlot { .. } | RpcError::Preflight { .. }
        )
    }
}

#[allow(clippy::type_complexity)]
pub trait SolanaRpc: Send + Sync + 'static {
    fn get_account(
        &self,
        key: Address,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AccountData>, RpcError>>;
    fn get_multiple_accounts(
        &self,
        keys: Vec<Address>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<Option<AccountData>>), RpcError>>;
    fn get_program_accounts(
        &self,
        program: Address,
        filters: Vec<Filter>,
        slice: Option<(usize, usize)>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<(Address, Vec<u8>)>), RpcError>>;
    /// The blockhash and its `last_valid_block_height`.
    fn latest_blockhash(&self, level: Level) -> BoxFuture<'_, Result<([u8; 32], u64), RpcError>>;
    fn send_transaction(
        &self,
        wire: Vec<u8>,
        skip_preflight: bool,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<[u8; 64], RpcError>>;
    /// Units, logs and error.
    fn simulate_transaction(&self, wire: Vec<u8>) -> BoxFuture<'_, Result<Simulation, RpcError>>;
    fn signature_statuses(
        &self,
        sigs: Vec<[u8; 64]>,
    ) -> BoxFuture<'_, Result<Vec<Option<TxStatus>>, RpcError>>;
    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>>;
    fn block_height(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>>;
    fn genesis_hash(&self) -> BoxFuture<'_, Result<[u8; 32], RpcError>>;
    fn recent_prioritization_fees(
        &self,
        writable: Vec<Address>,
    ) -> BoxFuture<'_, Result<Vec<u64>, RpcError>>;
    fn minimum_balance_for_rent_exemption(
        &self,
        len: usize,
    ) -> BoxFuture<'_, Result<u64, RpcError>>;
}

/// Signs transaction messages. Remote signing (KMS, HSM) would implement
/// this trait.
pub trait TxSigner: Send + Sync {
    fn address(&self) -> Address;
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("invalid keypair bytes")]
    InvalidKeypair,
}

/// The program flow a transaction belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxOp {
    Commit,
    Reveal,
    Post,
    Cosign,
    Verify,
    Finalize,
    Apply,
    Close,
    Abort,
    ApplyChange,
    Reclaim,
    Admin,
}

impl TxOp {
    /// The name stored in journals and shown by the API.
    pub const fn as_str(self) -> &'static str {
        match self {
            TxOp::Commit => "commit",
            TxOp::Reveal => "reveal",
            TxOp::Post => "post",
            TxOp::Cosign => "cosign",
            TxOp::Verify => "verify",
            TxOp::Finalize => "finalize",
            TxOp::Apply => "apply",
            TxOp::Close => "close",
            TxOp::Abort => "abort",
            TxOp::ApplyChange => "apply_change",
            TxOp::Reclaim => "reclaim",
            TxOp::Admin => "admin",
        }
    }
}

/// One signed transaction, recorded before it is sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRecord {
    /// Assigned by the journal. `None` before `before_send`.
    pub id: Option<i64>,
    pub market: Address,
    pub epoch: Option<u64>,
    pub op: TxOp,
    pub signature: [u8; 64],
    pub last_valid_block_height: u64,
    pub sent_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxOutcome {
    Landed {
        slot: u64,
    },
    Failed {
        slot: u64,
        err: TxErrorDetail,
    },
    /// The signature did not land and never will: its blockhash expired, or
    /// the RPC node refused the transaction (preflight or another JSON-RPC
    /// error) and so never forwarded it.
    Expired,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("journal: {0}")]
pub struct JournalError(pub String);

pub trait TxJournal: Send + Sync {
    /// Durable BEFORE `sendTransaction`.
    fn before_send(&self, rec: TxRecord) -> BoxFuture<'_, Result<i64, JournalError>>;
    fn resolved(&self, id: i64, outcome: TxOutcome) -> BoxFuture<'_, Result<(), JournalError>>;
    fn pending(&self) -> BoxFuture<'_, Result<Vec<TxRecord>, JournalError>>;
    /// The highest slot of a transaction recorded as landed or failed, 0
    /// when there is none. A restarted sender reads no state older than
    /// this.
    fn last_landed_slot(&self) -> BoxFuture<'_, Result<u64, JournalError>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeMode {
    Fixed(u64),
    Recent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeePolicy {
    pub mode: FeeMode,
    pub percentile: u8,
    pub max_micro_lamports: u64,
    pub cu_margin_pct: u8,
}

/// A transaction that landed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Landed {
    pub signature: [u8; 64],
    pub slot: u64,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TxError {
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("building the transaction: {0}")]
    Build(#[from] ClientError),
    /// The simulation that sizes the compute budget, or the node's preflight,
    /// failed. Nothing was sent, or the node refused to forward it.
    #[error("simulation failed: {}", .err.message)]
    Preflight {
        err: TxErrorDetail,
        logs: Vec<String>,
    },
    /// The transaction landed and failed (its fee was charged).
    #[error("transaction failed at slot {slot}: {}", .err.message)]
    Failed {
        signature: [u8; 64],
        slot: u64,
        err: TxErrorDetail,
    },
    #[error("blockhash expired before the transaction landed")]
    Expired { signature: [u8; 64] },
    #[error("not confirmed before the deadline")]
    Timeout { signature: [u8; 64] },
    /// An idempotent operation used up its attempts. The job retries
    /// later. `last` describes the last failure.
    #[error("gave up after {attempts} attempts: {last}")]
    GaveUp { attempts: u32, last: String },
}

/// Condition [`MarketChain::wait_batch`] waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchPredicate {
    Exists,
    /// Status reached or passed (by program order).
    AtLeast(BatchStatus),
    /// Settled or aborted.
    Terminal,
    /// At least this many live co-signature bits.
    CosignsAtLeast(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettleStage {
    Verifying,
    Finalizing,
    Applying,
    Closing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettleProgress {
    pub stage: SettleStage,
    pub done: u32,
    pub total: u32,
}

/// Every flow is observe-then-act and idempotent.
pub trait MarketChain: Send + Sync {
    fn address(&self) -> Address;
    fn market(&self, level: Level) -> BoxFuture<'_, Result<MarketAccount, ChainError>>;
    fn batch(
        &self,
        epoch: u64,
        level: Level,
    ) -> BoxFuture<'_, Result<Option<BatchAccount>, ChainError>>;
    /// Every trader account of the market, read at a slot at or after
    /// `min_slot`. Used by node and enclave.
    fn trader_snapshot(&self, min_slot: u64) -> BoxFuture<'_, Result<TraderSnapshot, ChainError>>;
    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, ChainError>>;
    fn ensure_committed(
        &self,
        epoch: u64,
        root: Hash32,
        count: u32,
        terms: Hash32,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<CommitOutcome, ChainError>>;
    fn ensure_revealed(
        &self,
        epoch: u64,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<RevealOutcome, ChainError>>;
    fn wait_batch(
        &self,
        epoch: u64,
        until: BatchPredicate,
        level: Level,
        deadline: Instant,
    ) -> BoxFuture<'_, Result<BatchAccount, ChainError>>;
    fn ensure_posted(
        &self,
        epoch: u64,
        header: [u8; 283],
        receipt: Vec<u8>,
        poster: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<PostOutcome, ChainError>>;
    /// Submits one CoSignReceipt per (executor, signature). Anyone may pay
    /// (`payer`), the signature is the co-signer's.
    fn ensure_cosigned(
        &self,
        epoch: u64,
        cosigs: Vec<(Address, [u8; 64])>,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<Vec<CosignOutcome>, ChainError>>;
    /// Returns a slot at or after the batch's close: the CloseBatch slot
    /// when this call closed the batch or no later batch has been committed
    /// since, otherwise the slot at which this call found it settled.
    fn ensure_settled(
        &self,
        epoch: u64,
        settlement: Arc<SettlementBatch>,
        payer: Arc<dyn TxSigner>,
        progress: mpsc::Sender<SettleProgress>,
    ) -> BoxFuture<'_, Result<u64, ChainError>>;
    fn ensure_aborted(
        &self,
        epoch: u64,
        reason: AbortReason,
        signer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<AbortOutcome, ChainError>>;
    fn ensure_change_applied(
        &self,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<ChangeOutcome, ChainError>>;
    fn ensure_reclaimed(
        &self,
        epoch: u64,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<(), ChainError>>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    Committed {
        slot: u64,
    },
    Equivocation {
        onchain_root: Hash32,
    },
    OutOfOrder {
        last_committed: u64,
        last_settled: u64,
    },
    InFlight {
        last_committed: u64,
        last_settled: u64,
    },
    ChangeDue {
        kind: u8,
    },
    Halted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevealOutcome {
    Revealed { beacon: Hash32, slot: u64 },
    NotReady { slots_left: u64 },
    Expired,
    Terminal(BatchStatus),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostOutcome {
    Posted { slot: u64 },
    AlreadyPosted { same_receipt: bool },
    WrongStatus(BatchStatus),
    Rejected(TimescalesProgramError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CosignOutcome {
    Cosigned { slot: u64 },
    AlreadyCosigned,
    OutcomeMismatch,
    WrongStatus(BatchStatus),
    Rejected(TimescalesProgramError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbortOutcome {
    Aborted {
        reason: AbortReason,
    },
    AlreadyTerminal(BatchStatus),
    NotAllowedYet {
        slots_left: u64,
    },
    /// The batch moved past the state this abort reason applies to (e.g.
    /// exec_timeout after ReceiptPosted). The caller re-derives its phase.
    Superseded(BatchStatus),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeOutcome {
    Applied { kind: u8 },
    NothingDue,
    NotYet { slots_left: u64 },
    InFlight,
}

/// One Trader account's snapshot inputs (bytes 36..148).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraderEntry {
    pub owner: Address,
    pub base: u64,
    pub quote: u64,
    pub requested_base: u64,
    pub requested_quote: u64,
    pub request_epoch: u64,
    pub last_leaf_epoch: u64,
    pub last_change_slot: u64,
    pub floor_epoch: u64,
    pub floor_base: u64,
    pub floor_quote: u64,
}

impl TraderEntry {
    /// Bytes of the `dataSlice` a snapshot reads: Trader bytes 36..148.
    pub const SLICE_LEN: usize = 112;
    /// Offset of the slice in the Trader account.
    pub const SLICE_OFFSET: usize = 36;

    /// Decodes Trader bytes 36..148: the owner, then ten little-endian u64.
    pub fn decode_slice(d: &[u8]) -> Result<Self, ClientError> {
        let d: &[u8; Self::SLICE_LEN] = d.try_into().map_err(|_| ClientError::Malformed)?;
        let (owner, rest) = d.split_first_chunk::<32>().ok_or(ClientError::Malformed)?;
        let (words, _) = rest.as_chunks::<8>();
        let word = |i: usize| words.get(i).map(|w| u64::from_le_bytes(*w));
        let field = |i: usize| word(i).ok_or(ClientError::Malformed);
        Ok(TraderEntry {
            owner: *owner,
            base: field(0)?,
            quote: field(1)?,
            requested_base: field(2)?,
            requested_quote: field(3)?,
            request_epoch: field(4)?,
            last_leaf_epoch: field(5)?,
            last_change_slot: field(6)?,
            floor_epoch: field(7)?,
            floor_base: field(8)?,
            floor_quote: field(9)?,
        })
    }

    /// Available balance for batch `epoch`, as `crate::program::available`
    /// computes it for a whole account.
    pub fn available(&self, epoch: u64) -> (u64, u64) {
        let account = TraderAccount {
            bump: 0,
            layout_version: crate::program::LAYOUT_VERSION,
            market: [0; 32],
            owner: self.owner,
            base: self.base,
            quote: self.quote,
            requested_base: self.requested_base,
            requested_quote: self.requested_quote,
            request_epoch: self.request_epoch,
            last_leaf_epoch: self.last_leaf_epoch,
            last_change_slot: self.last_change_slot,
            floor_epoch: self.floor_epoch,
            floor_base: self.floor_base,
            floor_quote: self.floor_quote,
        };
        crate::program::available(&account, epoch)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraderSnapshot {
    pub slot: u64,
    pub traders: Vec<TraderEntry>,
}

impl TraderSnapshot {
    /// Available balances, capped at `i64::MAX`.
    pub fn balance_sheet(&self, epoch: u64) -> BalanceSheet {
        self.traders
            .iter()
            .map(|t| {
                let (base, quote) = t.available(epoch);
                (
                    TraderId(t.owner),
                    Balance {
                        base: BaseAtoms(base),
                        quote: QuoteAtoms(quote),
                    },
                )
            })
            .collect()
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("instruction {ix} failed in {program:?}: {code} ({name})")]
    Program {
        ix: u8,
        program: ProgramKind,
        code: u32,
        name: &'static str,
    },
    #[error(transparent)]
    Tx(#[from] TxError),
    #[error("decoding account data: {0}")]
    Decode(ClientError),
    #[error("inconsistent chain state: {0}")]
    Inconsistent(&'static str),
    #[error("providers disagree")]
    Disagree,
}

pub mod program;
