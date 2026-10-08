//! The confidential executor interface.
//!
//! Every backend (local reference, TEE, MPC, proof-carrying) implements
//! [`ConfidentialExecutor`] and must produce the same
//! [`ExecutionOutcome`](timescales_auction::receipts::ExecutionOutcome) for the same batch.
//! Backends differ in *who can see the plaintext* and *what evidence comes
//! with the receipt*, never in matching semantics.
//!
//! The plaintext pipeline in [`pipeline`] is the single implementation of
//! those semantics for every backend that sees plaintext (reference and TEE).
//! The MPC backend re-implements them over secret shares and is checked
//! against this pipeline by differential tests.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod codec;
pub mod keys;
pub mod pipeline;
mod reference;

pub use keys::KeyProvider;
#[cfg(feature = "simulation")]
pub use keys::LocalKeySchedule;
pub use pipeline::{
    Finalized, PlainExecution, check_header, check_header_commitments, execute_opened, finalize,
    open_envelopes, order_seed,
};
pub use reference::ReferenceExecutor;

use std::borrow::Cow;
use std::future::Future;
use std::time::Duration;

use thiserror::Error;
use timescales_auction::BatchHeader;
use timescales_auction::collateral::BalanceSheet;
use timescales_auction::orderbook::OrderStateTable;
use timescales_auction::receipts::{BackendKind, ExecutionArtifacts, ExecutionReceipt};
use timescales_core::intent::{MaskedIntent, SealedEnvelope};

/// Whether this build includes simulation-only components.
pub const SIMULATION_BUILD: bool = cfg!(feature = "simulation");

#[cfg(feature = "simulation")]
#[used]
static SIMULATION_MARKER: [u8; 29] = *b"timescales:SIMULATION_BUILD=1";

/// A sealed batch plus the public state it executes against.
///
/// Inputs come in two encodings: sealed envelopes (for backends that
/// decrypt) and masked intents (for the MPC committee). A batch may carry
/// either or both. When both are present they carry the same commitments in
/// the same order, and that lets a scheduler fail over between
/// backends without asking traders to resubmit.
#[derive(Clone, Debug)]
pub struct ExecutionBatch {
    pub header: BatchHeader,
    pub envelopes: Vec<SealedEnvelope>,
    pub masked: Vec<MaskedIntent>,
    pub balances: BalanceSheet,
    pub prior_state: OrderStateTable,
}

impl timescales_core::Encode for ExecutionBatch {
    fn encode(&self, out: &mut Vec<u8>) {
        self.header.encode(out);
        timescales_core::encoding::put_seq(out, &self.envelopes);
        timescales_core::encoding::put_seq(out, &self.masked);
        self.balances.encode(out);
        self.prior_state.encode(out);
    }
}

impl timescales_core::Decode for ExecutionBatch {
    fn decode(r: &mut timescales_core::Reader<'_>) -> Result<Self, timescales_core::DecodeError> {
        let max = timescales_core::MAX_BATCH_ENVELOPES as usize;
        Ok(ExecutionBatch {
            header: BatchHeader::decode(r)?,
            envelopes: r.seq(max)?,
            masked: r.seq(max)?,
            balances: BalanceSheet::decode(r)?,
            prior_state: OrderStateTable::decode(r)?,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExecutionMetrics {
    /// Wall-clock time per pipeline stage, in execution order. Owned names
    /// let decoded results carry stage names too.
    pub stages: Vec<(Cow<'static, str>, Duration)>,
    /// Orders admitted to matching. Backends that evaluate admission
    /// obliviously (MPC) report the orders that passed the public checks,
    /// since collateral and self-trade outcomes are never revealed to them.
    pub accepted: usize,
    pub rejected: usize,
    /// Envelope indices (batch order) that did not authenticate as an intent
    /// of their submitter: they did not decrypt, parse, open their
    /// commitment or carry a valid intent signature, or their intent's
    /// trader is not the wallet admitted for them. Never collateral,
    /// self-trade or matching reasons.
    pub unauthenticated: Vec<u32>,
}

impl ExecutionMetrics {
    pub fn total(&self) -> Duration {
        self.stages.iter().map(|(_, d)| *d).sum()
    }

    pub fn stage(&self, name: &str) -> Option<Duration> {
        self.stages.iter().find(|(n, _)| n == name).map(|(_, d)| *d)
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionResult {
    pub receipt: ExecutionReceipt,
    pub artifacts: ExecutionArtifacts,
    pub metrics: ExecutionMetrics,
    /// Canonical encoding of the attestation the receipt's `attestation`
    /// digest commits to, for backends that attest.
    pub attestation: Option<Vec<u8>>,
    /// Proof the receipt's `proof` digest commits to, if one was produced.
    pub proof: Option<ProofArtifact>,
}

/// A proof produced over a plaintext execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofArtifact {
    pub digest: timescales_core::Hash32,
    pub bytes: Vec<u8>,
}

/// Produces a proof from a plaintext execution. Runs wherever the plaintext
/// lives (inside the enclave on the TEE path).
///
/// Returns `None` when proving is deferred: the receipt is then signed
/// without a proof digest and the proof is delivered later.
pub trait PlainProver: Send + Sync {
    fn prove(
        &self,
        header: &BatchHeader,
        prior: &OrderStateTable,
        plain: &PlainExecution,
    ) -> Result<Option<ProofArtifact>, ExecutorError>;
}

/// Why a backend has no decryption key for an epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyFailure {
    pub reason: String,
    /// For a threshold release: every committee member that did not
    /// contribute a usable share, in member order.
    pub members: Vec<MemberFailure>,
}

impl KeyFailure {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            members: Vec::new(),
        }
    }
}

impl core::fmt::Display for KeyFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.reason)?;
        for m in &self.members {
            write!(f, "; member {}: {}", m.member, m.detail)?;
        }
        Ok(())
    }
}

impl From<&str> for KeyFailure {
    fn from(reason: &str) -> Self {
        Self::new(reason)
    }
}

/// One key-release member's part in a failed release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberFailure {
    /// 1-based member index.
    pub member: u8,
    /// The member's refusal code (the `ReleaseRefusal` numbering, 1..=
    /// 20), or `None` when the member answered with a share the executor
    /// rejected.
    pub refusal: Option<u8>,
    pub detail: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutorError {
    #[error("batch header inconsistent: {0}")]
    BadHeader(&'static str),
    #[error("decryption key unavailable: {0}")]
    KeyUnavailable(KeyFailure),
    #[error("attestation rejected: {0}")]
    Attestation(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("protocol aborted: {0}")]
    Aborted(String),
    #[error("execution was cancelled")]
    Cancelled,
}

/// Run `f` on Tokio's blocking pool. The task owns everything it touches,
/// so dropping the returned future only discards the result. Work not yet
/// started in a later call never starts. A panic in `f` is an execution
/// error, not a transient one, so schedulers do not retry it.
pub async fn spawn_blocking<T, F>(f: F) -> Result<T, ExecutorError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ExecutorError> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) if e.is_panic() => Err(ExecutorError::Execution("executor task panicked".into())),
        Err(_) => Err(ExecutorError::Cancelled),
    }
}

/// Executes one sealed batch and returns a signed receipt.
///
/// Implementations must be cancellation safe: dropping the returned future
/// at any await point may waste work but must not leave shared state
/// half-updated or release key material.
pub trait ConfidentialExecutor: Send + Sync {
    fn backend(&self) -> BackendKind;

    fn execute(
        &self,
        batch: ExecutionBatch,
    ) -> impl Future<Output = Result<ExecutionResult, ExecutorError>> + Send;
}

pub mod attestation;
#[cfg(feature = "mpc-simulation")]
pub mod mpc;
pub mod policy;
pub mod tee;
