//! Enclave host service around `TeeExecutor`: remote key-release
//! members, the provenance and balance-sheet checks, quorum before
//! publication, and the reveal and settlement backstops.
//!
//! Two platforms: **simulated** (an ordinary process, the host operator can
//! read every order it executes. Feature `sim-platform`) and Intel TDX
//! (quotes through configfs-tsm, untested on hardware, feature `tdx-tsm`).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

mod balance;
pub mod config;
mod ed25519;
mod http;
mod journal;
mod metrics;
mod platform;
mod provenance;
pub mod remote;
pub mod run;
mod service;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;

use std::path::PathBuf;
use std::sync::Arc;

use thiserror::Error;
use timescales_core::crypto::Signature;
use timescales_executor::tee::Enclave;
use timescales_service::BuildInfo;
use timescales_service::wire::EnvelopeSigner;

pub use config::{EnclaveConfig, EnclaveFile};
pub use http::router;
pub use journal::TxLog;
pub use metrics::EnclaveMetrics;
#[cfg(feature = "sim-platform")]
pub use platform::keygen_simulated;
pub use service::EnclaveService;
pub use timescales_service::wire::EnclaveIdentity;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlatformMode {
    Simulated {
        key_file: PathBuf,
        vendor_seed_file: PathBuf,
    },
    IntelTdx {
        configfs_root: PathBuf,
    },
}

#[derive(Debug, Error)]
pub enum EnclaveError {
    #[error("epoch binding does not match the bundle and committee")]
    BindingMismatch,
    #[error("balance sheet disagrees with chain state for {traders} trader(s)")]
    BalanceMismatch { traders: u32 },
    #[error("epoch key unavailable: {0}")]
    KeyUnavailable(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("too many executions in flight")]
    Busy,
    #[error("posting failed: {0}")]
    PostFailed(String),
    /// Another outcome was posted. Carries this enclave's signed receipt.
    #[error("another outcome was posted")]
    OutcomeMismatch { receipt: Vec<u8> },
    #[error("co-signatures do not form a quorum")]
    QuorumInvalid,
    #[error("quorum not yet on chain")]
    QuorumPending,
    #[error("no completed execution for this header")]
    NotExecuted,
    /// The platform produced no quote.
    #[error("quote: {0}")]
    Quote(String),
    #[error(transparent)]
    Chain(#[from] timescales_chain::ChainError),
    #[error(transparent)]
    Config(#[from] timescales_service::ConfigError),
}

/// The enclave's typed envelope signer: envelopes are signed with the
/// executor key only through `Enclave::sign_rpc_envelope`, which fixes the
/// `RPC_ENVELOPE` domain, so the key never signs a raw digest for the host.
#[derive(Debug, Clone)]
pub struct EnclaveEnvelopeSigner(pub Arc<Enclave>);

impl EnvelopeSigner for EnclaveEnvelopeSigner {
    fn public(&self) -> [u8; 32] {
        self.0.executor_id().0
    }

    fn sign_envelope(&self, bytes_before_sig: &[u8]) -> Signature {
        self.0.sign_rpc_envelope(bytes_before_sig)
    }
}

/// What this binary was built with.
pub fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
        git_sha: option_env!("TIMESCALES_GIT_SHA").unwrap_or("unknown"),
        simulation: timescales_executor::tee::SIMULATION_BUILD,
        sim_platform: timescales_executor::attestation::SIM_PLATFORM_BUILD,
    }
}

/// Milliseconds since the Unix epoch.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
