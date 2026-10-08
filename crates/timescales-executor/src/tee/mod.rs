//! TEE execution backend.
//!
//! ```text
//! Attestation -> Measurement -> Policy evaluation -> Key release
//!   -> Confidential execution -> Receipt
//! ```
//!
//! 1. The executor checks the batch header against its inputs and, for a
//!    version 2 header, the epoch binding against the announced key and
//!    the committee.
//! 2. It asks every committee member for a fresh nonce.
//! 3. The enclave produces evidence binding its sealing key, receipt key,
//!    the header digest, all nonces and the committee digest.
//! 4. Members check the request against chain state, verify and appraise
//!    the evidence, and return their share sealed to the enclave.
//! 5. The enclave checks every share against the dealer's Feldman
//!    commitments, combines `t` valid ones, checks the result against the
//!    published public key, opens the envelopes, derives the order seed,
//!    executes the plaintext pipeline, drops the secret, and signs the
//!    receipt. The receipt commits to the attestation digest.
//!
//! The TEE carries confidentiality only. Correctness of settlement does not
//! rest on it: conservation is re-checked on chain, and markets that need
//! it attach a SNARK (the `zk` module).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod codec;
pub mod committee;
pub mod enclave;
#[cfg(feature = "simulation")]
mod local;
#[cfg(feature = "tdx-tsm")]
pub mod tsm;

#[cfg(feature = "fault-injection")]
pub use committee::MemberFault;
pub use committee::{
    BatchView, BoxFuture, ChainView, CommitteeError, HeldAnnouncement, KeyReleaseMember,
    KeyReleaseRequest, KeyReleaseService, MAX_COMMITTEE, MAX_RELEASES_PER_EPOCH, NonceLimits,
    ReleaseContext, ReleaseError, SealedShare,
};
#[cfg(feature = "simulation")]
pub use committee::{DealtEpoch, EpochKeyDealer, InMemoryChain, InProcessMember};
pub use enclave::{
    Enclave, EpochKey, QuoteError, Quoter, ReconstructError, Reconstructed, RunInputs,
    ShareRejection, program_measurement,
};
#[cfg(feature = "simulation")]
pub use local::{LocalTeeDeployment, PublishedEpochKeys};
#[cfg(feature = "tdx-tsm")]
pub use tsm::TsmQuoter;

use std::sync::Arc;
#[cfg(feature = "fault-injection")]
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::pipeline::check_header;
use crate::{
    ConfidentialExecutor, ExecutionBatch, ExecutionMetrics, ExecutionResult, ExecutorError,
    KeyFailure, KeyProvider, MemberFailure, PlainProver, spawn_blocking,
};
use futures::future::join_all;
use timescales_auction::epoch_binding;
use timescales_auction::receipts::BackendKind;
use timescales_core::{Encode, HEADER_VERSION_ENVELOPE_BOUND, Hash32, TraderId};

/// Whether this build includes simulation-only components.
pub const SIMULATION_BUILD: bool = cfg!(feature = "simulation");

#[cfg(feature = "simulation")]
#[used]
static SIMULATION_MARKER: [u8; 29] = *b"timescales:SIMULATION_BUILD=1";

/// Faults the enclave host can inject in tests.
#[cfg(feature = "fault-injection")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnclaveFault {
    #[default]
    None,
    /// The host kills the enclave before it asks for keys.
    CrashBeforeKeyRequest,
    /// The host kills the enclave after keys were released.
    CrashAfterKeyRelease,
}

/// Per-epoch inputs of a TEE execution that the batch does not carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochInputs {
    /// The market account address. Mixed into the order seed of a version
    /// 2 header.
    pub market_address: [u8; 32],
    /// The epoch's price commitment, from which members recompute the
    /// epoch binding.
    pub price_commitment: Hash32,
    /// The announced epoch key.
    pub key: EpochKey,
    /// Digest of the epoch-key announcement. A version 2 header's binding
    /// must name it.
    pub announcement_digest: Hash32,
    /// Provenance admission vector, one entry per envelope.
    pub admission: Option<Vec<Option<TraderId>>>,
}

/// A TEE execution and what its receipt does not carry. The envelopes that
/// did not authenticate, for `ExecuteReady.unauthenticated`, are in
/// `result.metrics.unauthenticated`.
#[derive(Debug)]
pub struct TeeExecution {
    pub result: ExecutionResult,
    /// Members whose shares were combined.
    pub used: Vec<u8>,
    /// Members that did not contribute a usable share, and why.
    pub member_failures: Vec<MemberFailure>,
}

pub struct TeeExecutor {
    enclave: Arc<Enclave>,
    committee: Vec<Arc<dyn KeyReleaseService>>,
    threshold: u8,
    keys: Arc<dyn KeyProvider>,
    timeout: Duration,
    committee_digest: Hash32,
    #[cfg(feature = "fault-injection")]
    fault: Mutex<EnclaveFault>,
    prover: Option<Arc<dyn PlainProver>>,
}

impl core::fmt::Debug for TeeExecutor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TeeExecutor")
            .field("enclave", &self.enclave)
            .field("committee", &self.committee.len())
            .field("threshold", &self.threshold)
            .finish()
    }
}

impl TeeExecutor {
    /// An executor over `committee`, which must list members in index order
    /// `1..=n` (`n <= 16`), with `1 <= threshold <= n`. `keys` publishes the
    /// epoch public keys (and commitments) batches run through
    /// [`ConfidentialExecutor::execute`] are checked against. `timeout`
    /// bounds every member call.
    pub fn new(
        enclave: Arc<Enclave>,
        committee: Vec<Arc<dyn KeyReleaseService>>,
        threshold: u8,
        keys: Arc<dyn KeyProvider>,
        timeout: Duration,
    ) -> Result<Self, CommitteeError> {
        let n = committee.len();
        if n > usize::from(MAX_COMMITTEE) || threshold == 0 || usize::from(threshold) > n {
            return Err(CommitteeError::Threshold { threshold, n });
        }
        for (position, m) in committee.iter().enumerate() {
            if usize::from(m.index()) != position + 1 {
                return Err(CommitteeError::IndexOrder {
                    position,
                    index: m.index(),
                });
            }
        }
        Ok(Self {
            enclave,
            committee,
            threshold,
            keys,
            timeout,
            committee_digest: Hash32::ZERO,
            #[cfg(feature = "fault-injection")]
            fault: Mutex::default(),
            prover: None,
        })
    }

    /// Digest of the committee the members serve. Bound into every
    /// key-release attestation and into the epoch binding of a version 2
    /// header.
    pub fn with_committee_digest(mut self, digest: Hash32) -> Self {
        self.committee_digest = digest;
        self
    }

    /// Produce a SNARK inside the enclave for every batch (TEE + ZK).
    pub fn with_prover(mut self, prover: Arc<dyn PlainProver>) -> Self {
        self.prover = Some(prover);
        self
    }

    pub fn enclave(&self) -> &Arc<Enclave> {
        &self.enclave
    }

    #[cfg(feature = "fault-injection")]
    pub fn set_fault(&self, f: EnclaveFault) {
        if let Ok(mut g) = self.fault.lock() {
            *g = f;
        }
    }

    #[cfg(feature = "fault-injection")]
    fn fault(&self) -> EnclaveFault {
        self.fault.lock().map(|g| *g).unwrap_or_default()
    }

    /// Execute a version 1 batch whose key [`KeyProvider`] publishes. A
    /// version 2 batch needs its epoch's price commitment and announcement:
    /// use [`Self::execute_epoch`].
    pub async fn execute_shared(
        &self,
        batch: Arc<ExecutionBatch>,
    ) -> Result<ExecutionResult, ExecutorError> {
        let h = &batch.header;
        if h.version == HEADER_VERSION_ENVELOPE_BOUND {
            return Err(ExecutorError::KeyUnavailable(KeyFailure::new(
                "a version 2 batch needs its epoch inputs",
            )));
        }
        let inputs = EpochInputs {
            market_address: [0; 32],
            price_commitment: h.price_commitment,
            key: EpochKey {
                epoch_pk: self.keys.epoch_public(h.market, h.epoch)?,
                commitments: self.keys.epoch_commitments(h.market, h.epoch)?,
            },
            announcement_digest: Hash32::ZERO,
            admission: None,
        };
        self.execute_epoch(batch, inputs).await.map(|e| e.result)
    }

    /// Execute one batch with its epoch inputs: check the
    /// header and the epoch binding, collect nonces, attest, collect
    /// shares, reconstruct the secret, run, sign. CPU-bound steps run on the
    /// blocking pool, so a caller that gives up between them stops the rest.
    pub async fn execute_epoch(
        &self,
        batch: Arc<ExecutionBatch>,
        inputs: EpochInputs,
    ) -> Result<TeeExecution, ExecutorError> {
        let header = batch.header;
        if header.version == HEADER_VERSION_ENVELOPE_BOUND {
            let binding = epoch_binding(
                &inputs.price_commitment,
                &inputs.announcement_digest,
                &self.committee_digest,
            );
            if header.price_commitment != binding {
                return Err(ExecutorError::BadHeader("epoch binding"));
            }
        }
        if inputs
            .admission
            .as_ref()
            .is_some_and(|a| a.len() != batch.envelopes.len())
        {
            return Err(ExecutorError::BadHeader(
                "admission vector does not match the envelopes",
            ));
        }

        let mut metrics = ExecutionMetrics::default();
        let t = Instant::now();
        let b = Arc::clone(&batch);
        spawn_blocking(move || {
            check_header(&b.header, &b.envelopes, &b.balances, &b.prior_state).map(|_| ())
        })
        .await?;
        metrics.stages.push(("check-header".into(), t.elapsed()));

        #[cfg(feature = "fault-injection")]
        if self.fault() == EnclaveFault::CrashBeforeKeyRequest {
            return Err(ExecutorError::Unavailable(
                "enclave terminated by host".into(),
            ));
        }

        let t = Instant::now();
        let challenges = join_all(self.committee.iter().map(|m| {
            let m = Arc::clone(m);
            let timeout = self.timeout;
            async move {
                tokio::time::timeout(timeout, m.challenge(header.market, header.epoch))
                    .await
                    .unwrap_or(Err(ReleaseError::Unavailable))
            }
        }))
        .await;
        // A member without a nonce gets a zero one. It is not asked to release.
        let nonces = challenges
            .iter()
            .map(|c| c.as_ref().copied().unwrap_or(Hash32::ZERO))
            .collect();
        let enclave = Arc::clone(&self.enclave);
        let committee_digest = self.committee_digest;
        let attestation = spawn_blocking(move || {
            enclave
                .try_attest_v2(&header, nonces, committee_digest)
                .map_err(|e| ExecutorError::Attestation(e.to_string()))
        })
        .await?;
        let attestation_digest = attestation.digest();
        let attestation_bytes = attestation.to_bytes();

        let request = KeyReleaseRequest {
            header,
            price_commitment: inputs.price_commitment,
            attestation,
        };
        let releases = join_all(
            self.committee
                .iter()
                .zip(&challenges)
                .map(|(m, challenge)| {
                    let m = Arc::clone(m);
                    let req = request.clone();
                    let timeout = self.timeout;
                    let challenge = challenge.clone();
                    async move {
                        challenge?;
                        tokio::time::timeout(timeout, m.release(req))
                            .await
                            .unwrap_or(Err(ReleaseError::Unavailable))
                    }
                }),
        )
        .await;
        let mut refused = Vec::new();
        let mut sealed = Vec::new();
        for (m, r) in self.committee.iter().zip(releases) {
            match r {
                Ok(s) if s.member == m.index() => sealed.push(s),
                Ok(_) => refused.push(MemberFailure {
                    member: m.index(),
                    refusal: None,
                    detail: ShareRejection::WrongMember.to_string(),
                }),
                Err(e) => refused.push(MemberFailure {
                    member: m.index(),
                    refusal: Some(e.code()),
                    detail: e.to_string(),
                }),
            }
        }

        let enclave = Arc::clone(&self.enclave);
        let threshold = self.threshold;
        let key = inputs.key.clone();
        let reconstructed = spawn_blocking(move || {
            Ok(enclave.reconstruct_threshold(&header, &key, threshold, &sealed))
        })
        .await?;
        let reconstructed = match reconstructed {
            Ok(r) => r,
            Err(e) => {
                let mut members = refused;
                members.extend(e.rejected().iter().map(|(member, why)| MemberFailure {
                    member: *member,
                    refusal: None,
                    detail: why.to_string(),
                }));
                members.sort_by_key(|m| m.member);
                return Err(ExecutorError::KeyUnavailable(KeyFailure {
                    reason: e.to_string(),
                    members,
                }));
            }
        };
        metrics.stages.push(("attest+release".into(), t.elapsed()));
        let Reconstructed {
            secret,
            used,
            rejected,
        } = reconstructed;
        let mut member_failures = refused;
        member_failures.extend(rejected.iter().map(|(member, why)| MemberFailure {
            member: *member,
            refusal: None,
            detail: why.to_string(),
        }));
        member_failures.sort_by_key(|m| m.member);

        #[cfg(feature = "fault-injection")]
        if self.fault() == EnclaveFault::CrashAfterKeyRelease {
            drop(secret);
            return Err(ExecutorError::Unavailable(
                "enclave terminated after key release".into(),
            ));
        }

        let enclave = Arc::clone(&self.enclave);
        let prover = self.prover.clone();
        let (receipt, plain, proof) = spawn_blocking(move || {
            let run = RunInputs {
                market_address: &inputs.market_address,
                admission: inputs.admission.as_deref(),
                attestation: attestation_digest,
            };
            enclave.execute(&batch, secret, run, prover.as_deref(), metrics)
        })
        .await?;
        Ok(TeeExecution {
            result: ExecutionResult {
                receipt,
                artifacts: plain.artifacts,
                metrics: plain.metrics,
                attestation: Some(attestation_bytes),
                proof,
            },
            used,
            member_failures,
        })
    }
}

impl ConfidentialExecutor for TeeExecutor {
    fn backend(&self) -> BackendKind {
        BackendKind::Tee
    }

    async fn execute(&self, batch: ExecutionBatch) -> Result<ExecutionResult, ExecutorError> {
        self.execute_shared(Arc::new(batch)).await
    }
}

#[cfg(test)]
mod tests;
