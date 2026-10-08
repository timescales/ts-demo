//! Key-release committee member and trusted Feldman dealer (section E).
//!
//! **The dealer is trusted**: it sees every epoch secret it deals
//! (`key_generation: "trusted_dealer_feldman"`, no DKG). Members hold
//! one share per epoch, verify it against the dealer's Feldman commitments,
//! and release it only to an attested, registered executor for a batch whose
//! header and epoch binding match finalized chain state.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod chain;
pub mod config;
pub mod dealer;
mod http;
mod limiter;
pub mod member;
pub mod metrics;
pub mod service;
pub mod verifier;

use std::future::Future;
use std::pin::Pin;

use thiserror::Error;
use timescales_chain::program::MarketAccount;
use timescales_chain::{Address, Level};
use timescales_core::EpochId;
use timescales_executor::tee::ReleaseContext;

pub use chain::RpcKrcChain;
pub use config::{DealerConfig, MemberConfig};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Error)]
pub enum KrcError {
    #[error(transparent)]
    Chain(#[from] timescales_chain::ChainError),
    #[error(transparent)]
    Rpc(#[from] timescales_chain::RpcError),
    #[error(transparent)]
    Store(#[from] timescales_service::store::StoreError),
    #[error(transparent)]
    Wire(#[from] timescales_service::wire::WireError),
    #[error(transparent)]
    Config(#[from] timescales_service::ConfigError),
    #[error("market {0:?} not configured")]
    UnknownMarket(Address),
    #[error("chain state not final or providers disagree")]
    NotFinal,
}

/// Chain reads of a member.
pub trait KrcChain: Send + Sync {
    /// One consistent finalized read per release (Market + Batch, via
    /// QuorumRpc), plus the halt flag at confirmed.
    fn release_context(
        &self,
        m: Address,
        e: EpochId,
    ) -> BoxFuture<'_, Result<ReleaseContext, KrcError>>;
    fn market(&self, m: Address, level: Level) -> BoxFuture<'_, Result<MarketAccount, KrcError>>;
}

/// Milliseconds since the Unix epoch.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Base58 of a 32-byte key, as configuration files and logs write it.
pub(crate) fn b58(key: &[u8; 32]) -> String {
    bs58::encode(key).into_string()
}
