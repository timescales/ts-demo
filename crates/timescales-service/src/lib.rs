//! Plumbing shared by `timescales-node`, `timescales-krc`,
//! `timescales-enclave` and `timescales-admin`.
//!
//! * configuration: TOML with `deny_unknown_fields`, profile rules, and the
//!   refusal to run a non-production profile on mainnet-beta.
//! * Key files: raw key material with permission checks (no Solana types).
//! * telemetry, `wallet_tag`, the Prometheus registry and the ops router
//!   (`/livez`, `/readyz`, `/metrics`).
//! * [`SignedEnvelope`](crate::wire::SignedEnvelope) over HTTP: the axum
//!   extractor that checks the 94-byte prefix before reading the body, and
//!   [`SignedClient`] with optional mutual TLS.
//! * [`BuildInfo`] and the production refusal of simulation builds.
//! * [`rules`] that every service's configuration shares.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

mod client;
mod config;
mod envelope;
pub mod keys;
mod ops;
pub mod rules;
mod telemetry;
pub mod tls;

use std::future::Future;
use std::pin::Pin;

pub use client::{ClientError, RESPONSE_SKEW_MS, SignedClient};
pub use config::{
    BuildInfo, ConfigError, ConfigIssue, MAINNET_BETA_GENESIS_HASH, Profile, Validate,
    check_cluster_profile, load_config, refuse_simulation,
};
pub use envelope::{
    ENVELOPE_CONTENT_TYPE, EnvelopeAuth, EnvelopeRejection, HttpLimits, SenderPolicy,
    VerifiedEnvelope, sealed_response, sealed_response_with_status,
};
pub use keys::{Kek, KeyError};
pub use ops::{
    Metrics, OPENMETRICS_CONTENT_TYPE, Readiness, ReadinessProbe, ops_router, shutdown_signal,
};
pub use telemetry::{
    LogFormat, TelemetryConfig, TelemetryError, TelemetryGuard, init_telemetry, wallet_tag,
};
pub use tls::TlsConfig;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub mod api;
#[cfg(feature = "simulation")]
pub mod p2p;
pub mod relay;
pub mod store;
pub mod wire;
