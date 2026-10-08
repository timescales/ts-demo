//! [`SolanaRpc`](crate::SolanaRpc) implementations.

#[cfg(any(feature = "rpc-client", feature = "rpc-minimal"))]
mod failover;
#[cfg(feature = "test-util")]
mod faulty;
#[cfg(feature = "rpc-client")]
mod http;
#[cfg(feature = "litesvm")]
mod litesvm;
#[cfg(feature = "rpc-minimal")]
mod minimal;
mod quorum;

use thiserror::Error;

/// Solana JSON-RPC error codes that change the meaning of a failure
/// (`solana-rpc-client-api` `custom_error`).
#[cfg(any(feature = "rpc-client", feature = "rpc-minimal"))]
pub(crate) mod codes {
    /// `sendTransaction` simulated the transaction and did not forward it.
    pub(crate) const PREFLIGHT_FAILURE: i64 = -32002;
    pub(crate) const MIN_CONTEXT_SLOT_NOT_REACHED: i64 = -32016;
}

#[cfg(any(feature = "rpc-client", feature = "rpc-minimal"))]
pub use failover::RpcErrorCount;
#[cfg(feature = "test-util")]
pub use faulty::{FaultyRpc, RpcMethod};
#[cfg(feature = "rpc-client")]
pub use http::HttpRpc;
#[cfg(feature = "litesvm")]
pub use litesvm::{LiteSvmConfig, LiteSvmRpc, settlement_program_so};
#[cfg(feature = "rpc-minimal")]
pub use minimal::{HttpReply, HttpTransport, MinimalRpc, ReqwestTransport};
pub use quorum::QuorumRpc;

/// A provider that cannot be constructed from its configuration.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProviderError {
    #[error("no RPC URL or provider configured")]
    NoProviders,
    #[error("a quorum of {agree} needs 1 to {providers} agreeing providers")]
    Agree { agree: usize, providers: usize },
    #[error("building the HTTP client: {0}")]
    Client(String),
}
