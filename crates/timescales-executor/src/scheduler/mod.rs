//! Execution scheduling.
//!
//! For each sealed batch the scheduler asks the market's
//! [`ExecutionPolicy`] for an ordered list of backends, tries them with a
//! timeout each, checks every receipt it gets back, and returns the first
//! valid one together with the record of what was tried.
//!
//! Failures are classified because they need different handling:
//!
//! * A bad header is the batch's fault: stop, no backend can run it.
//! * An MPC abort consumed the inputs' masks: never retry the committee on
//!   the same batch, move on.
//! * Unavailability or a timeout may be transient: retry up to the policy's
//!   attempt count with exponential backoff, then move on.
//! * Key unavailability and execution errors (panics included) are
//!   deterministic for a backend: move on.
//!
//! Each backend sits behind a circuit breaker: after
//! [`Scheduler::unhealthy_after`] consecutive failures it opens and the
//! backend is skipped. After the cooldown one probe is let through, and its
//! result closes or reopens the circuit.
//!
//! The batch is shared between attempts, never copied. The timeout drops the
//! in-flight future. Every executor runs its work as owned tasks on the
//! blocking pool, so a timed-out attempt may finish the step it is in but
//! starts no further one, and cannot corrupt state. A cancellation token
//! stops a run between and during attempts.
//!
//! With an MPC committee among the backends, a run of epoch `e` first drops
//! the committee's masks of epochs before `e`, whichever backend ran them.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(feature = "mpc-simulation")]
use crate::mpc::MpcExecutor;
use crate::policy::{ExecutionPolicy, ProofMode};
use crate::tee::TeeExecutor;
use crate::{ExecutionBatch, ExecutionResult, ExecutorError, KeyProvider, ReferenceExecutor};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use thiserror::Error;
use timescales_auction::receipts::BackendKind;
use timescales_core::{ExecutorId, Hash32};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    #[error("batch rejected by executor: {0}")]
    BadBatch(ExecutorError),
    #[error("every backend failed ({} attempts)", .0.len())]
    Exhausted(Vec<Attempt>),
    #[error("receipt from {backend:?} failed checks: {reason}")]
    BadReceipt {
        backend: BackendKind,
        reason: String,
    },
    #[error("execution policy not supported: {0}")]
    Config(&'static str),
    #[error("run cancelled")]
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub backend: BackendKind,
    pub error: Option<ExecutorError>,
    pub elapsed: Duration,
}

#[derive(Debug)]
pub struct Scheduled {
    pub result: ExecutionResult,
    pub backend: BackendKind,
    pub attempts: Vec<Attempt>,
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A backend reached over the network (an enclave service), object safe so
/// the node can hold any number of them.
pub trait RemoteBackend: Send + Sync {
    fn kind(&self) -> BackendKind;

    fn execute(
        &self,
        b: Arc<ExecutionBatch>,
    ) -> BoxFuture<'_, Result<ExecutionResult, ExecutorError>>;
}

/// Concrete backends. An enum rather than trait objects because the
/// in-process executor trait uses `async fn`.
pub enum Backend<K: KeyProvider + 'static> {
    Reference(Arc<ReferenceExecutor<K>>),
    Tee(Arc<TeeExecutor>),
    /// In-process MPC with a trusted dealer. Simulation only.
    #[cfg(feature = "mpc-simulation")]
    Mpc(MpcExecutor),
    Remote(Arc<dyn RemoteBackend>),
}

impl<K: KeyProvider + 'static> core::fmt::Debug for Backend<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Backend({:?})", self.kind())
    }
}

impl<K: KeyProvider + 'static> Backend<K> {
    pub fn kind(&self) -> BackendKind {
        match self {
            Backend::Reference(_) => BackendKind::Reference,
            Backend::Tee(_) => BackendKind::Tee,
            #[cfg(feature = "mpc-simulation")]
            Backend::Mpc(_) => BackendKind::Mpc,
            Backend::Remote(r) => r.kind(),
        }
    }

    async fn execute(&self, batch: Arc<ExecutionBatch>) -> Result<ExecutionResult, ExecutorError> {
        match self {
            Backend::Reference(e) => e.execute_shared(batch).await,
            Backend::Tee(e) => e.execute_shared(batch).await,
            #[cfg(feature = "mpc-simulation")]
            Backend::Mpc(e) => e.execute_shared(batch).await,
            Backend::Remote(r) => r.execute(batch).await,
        }
    }

    /// The key an in-process backend signs with. Remote ones are pinned to
    /// the market's registered executors instead.
    fn own_executor(&self) -> Option<ExecutorId> {
        match self {
            Backend::Reference(e) => Some(e.executor_id()),
            Backend::Tee(e) => Some(e.enclave().executor_id()),
            #[cfg(feature = "mpc-simulation")]
            Backend::Mpc(e) => Some(e.executor_id()),
            Backend::Remote(_) => None,
        }
    }
}

/// The executors whose receipts remote backends may return: the market's
/// registered executor set (`Market.executors`), swapped in whole whenever
/// the node reads a new one.
#[derive(Debug, Default)]
pub struct ExecutorPin(ArcSwap<BTreeSet<ExecutorId>>);

impl ExecutorPin {
    pub fn new(executors: impl IntoIterator<Item = ExecutorId>) -> Self {
        let pin = Self::default();
        pin.store(executors);
        pin
    }

    /// Replace the pinned set. The zero id (an empty executor slot) is never
    /// pinned.
    pub fn store(&self, executors: impl IntoIterator<Item = ExecutorId>) {
        let set = executors
            .into_iter()
            .filter(|e| *e != ExecutorId([0; 32]))
            .collect();
        self.0.store(Arc::new(set));
    }

    pub fn contains(&self, executor: &ExecutorId) -> bool {
        self.0.load().contains(executor)
    }

    pub fn snapshot(&self) -> Arc<BTreeSet<ExecutorId>> {
        self.0.load_full()
    }
}

/// Retry and circuit-breaker timing. Transient failures are
/// retried after `backoff`, doubling up to `max_backoff`. An open circuit
/// lets a probe through after `circuit_cooldown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetrySettings {
    pub backoff: Duration,
    pub max_backoff: Duration,
    pub circuit_cooldown: Duration,
}

impl Default for RetrySettings {
    fn default() -> Self {
        Self {
            backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(8),
            circuit_cooldown: Duration::from_secs(30),
        }
    }
}

impl RetrySettings {
    /// The wait before retry number `retry` (1 for the first retry).
    pub fn delay(&self, retry: u32) -> Duration {
        let factor = 1u32
            .checked_shl(retry.saturating_sub(1))
            .unwrap_or(u32::MAX);
        self.backoff
            .checked_mul(factor)
            .unwrap_or(self.max_backoff)
            .min(self.max_backoff)
    }
}

/// What a backend's circuit breaker currently allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Circuit {
    /// Attempts run. Consecutive failures are counted.
    Closed { failures: u32 },
    /// Attempts are skipped until the cooldown ends.
    Open { until: Instant },
    /// One probe may run. `probing` while it does.
    HalfOpen { probing: bool },
}

impl Default for Circuit {
    fn default() -> Self {
        Circuit::Closed { failures: 0 }
    }
}

/// The right to run one attempt on a backend. Reports its outcome to the
/// breaker. Dropped without an outcome (the run was cancelled), it frees a
/// probe slot without counting a failure.
struct Permit<'a> {
    circuits: &'a Mutex<BTreeMap<BackendKind, Circuit>>,
    kind: BackendKind,
    probe: bool,
    open_after: u32,
    cooldown: Duration,
    reported: bool,
}

impl Permit<'_> {
    fn succeeded(mut self) {
        self.reported = true;
        self.circuits
            .lock()
            .insert(self.kind, Circuit::Closed { failures: 0 });
    }

    fn failed(mut self) {
        self.reported = true;
        let mut circuits = self.circuits.lock();
        let c = circuits.entry(self.kind).or_default();
        let open = Circuit::Open {
            until: Instant::now() + self.cooldown,
        };
        *c = match *c {
            Circuit::Closed { failures } if failures + 1 < self.open_after => Circuit::Closed {
                failures: failures + 1,
            },
            Circuit::Closed { .. } | Circuit::HalfOpen { .. } => open,
            // Another run opened it meanwhile.
            Circuit::Open { until } => Circuit::Open { until },
        };
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if !self.reported && self.probe {
            self.circuits
                .lock()
                .insert(self.kind, Circuit::HalfOpen { probing: false });
        }
    }
}

pub struct Scheduler<K: KeyProvider + 'static> {
    policy: ExecutionPolicy,
    backends: BTreeMap<BackendKind, Backend<K>>,
    circuits: Mutex<BTreeMap<BackendKind, Circuit>>,
    retry: RetrySettings,
    pin: Option<Arc<ExecutorPin>>,
    /// Consecutive failures after which a backend's circuit opens.
    pub unhealthy_after: u32,
}

impl<K: KeyProvider + 'static> core::fmt::Debug for Scheduler<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scheduler")
            .field("policy", &self.policy)
            .field("backends", &self.backends.keys())
            .finish()
    }
}

fn check_policy(policy: &ExecutionPolicy) -> Result<(), SchedulerError> {
    if let ProofMode::Deferred { .. } = policy.proof {
        // Nothing tracks a deferred proof's window or penalises a missing
        // one, so accepting the mode would silently drop the requirement.
        return Err(SchedulerError::Config("deferred proofs are not tracked"));
    }
    Ok(())
}

impl<K: KeyProvider + 'static> Scheduler<K> {
    /// A scheduler over `backends`. A policy it cannot honour
    /// (`ProofMode::Deferred`) makes every run fail with
    /// [`SchedulerError::Config`]. [`Self::try_new`] refuses it up front.
    pub fn new(policy: ExecutionPolicy, backends: Vec<Backend<K>>) -> Self {
        Self {
            policy,
            backends: backends.into_iter().map(|b| (b.kind(), b)).collect(),
            circuits: Mutex::default(),
            retry: RetrySettings::default(),
            pin: None,
            unhealthy_after: 3,
        }
    }

    pub fn try_new(
        policy: ExecutionPolicy,
        backends: Vec<Backend<K>>,
    ) -> Result<Self, SchedulerError> {
        check_policy(&policy)?;
        Ok(Self::new(policy, backends))
    }

    pub fn with_retry(mut self, retry: RetrySettings) -> Self {
        self.retry = retry;
        self
    }

    /// Accept receipts from remote backends only if their executor is in
    /// `pin`. Without a pin, remote receipts are refused.
    pub fn with_executor_pin(mut self, pin: Arc<ExecutorPin>) -> Self {
        self.pin = Some(pin);
        self
    }

    /// The circuit of backend `k`.
    pub fn circuit(&self, k: BackendKind) -> Circuit {
        self.circuits.lock().get(&k).copied().unwrap_or_default()
    }

    /// Close backend `k`'s circuit (e.g. after an operator intervention).
    #[deprecated(
        note = "the circuit breaker recovers on its own through a half-open probe after the cooldown"
    )]
    pub fn reset_health(&self, k: BackendKind) {
        self.circuits.lock().insert(k, Circuit::default());
    }

    /// Backends a run may plan for: those whose circuit is not open, or
    /// whose cooldown is over.
    fn available(&self, now: Instant) -> BTreeSet<BackendKind> {
        let circuits = self.circuits.lock();
        self.backends
            .keys()
            .copied()
            .filter(|k| match circuits.get(k) {
                None | Some(Circuit::Closed { .. }) => true,
                Some(Circuit::Open { until }) => now >= *until,
                Some(Circuit::HalfOpen { probing }) => !probing,
            })
            .collect()
    }

    /// Take the right to attempt `kind` now, turning an expired open
    /// circuit into a half-open probe.
    fn permit(&self, kind: BackendKind, now: Instant) -> Option<Permit<'_>> {
        let mut circuits = self.circuits.lock();
        let c = circuits.entry(kind).or_default();
        let probe = match *c {
            Circuit::Closed { .. } => false,
            Circuit::Open { until } if now >= until => true,
            Circuit::HalfOpen { probing: false } => true,
            Circuit::Open { .. } | Circuit::HalfOpen { probing: true } => return None,
        };
        if probe {
            *c = Circuit::HalfOpen { probing: true };
        }
        Some(Permit {
            circuits: &self.circuits,
            kind,
            probe,
            open_after: self.unhealthy_after.max(1),
            cooldown: self.retry.circuit_cooldown,
            reported: false,
        })
    }

    /// Check a result on the blocking pool (recomputing roots and the
    /// settlement is linear in the batch).
    async fn check(
        &self,
        kind: BackendKind,
        backend: &Backend<K>,
        batch: &Arc<ExecutionBatch>,
        result: ExecutionResult,
    ) -> Result<ExecutionResult, String> {
        let allowed = match backend.own_executor() {
            Some(own) => Arc::new([own].into_iter().collect()),
            None => match &self.pin {
                Some(pin) => pin.snapshot(),
                None => return Err("no executor pin for a remote backend".into()),
            },
        };
        let batch = Arc::clone(batch);
        let proof = self.policy.proof;
        tokio::task::spawn_blocking(move || {
            check_result(kind, &allowed, proof, &batch, &result)?;
            Ok(result)
        })
        .await
        .map_err(|_| "receipt check did not complete".to_string())?
    }

    /// Drop the MPC committee's unconsumed masks of every epoch before
    /// `epoch`. A batch is committed only once its predecessor is terminal,
    /// so once epoch `e` runs no earlier block can be consumed. Without
    /// this, the blocks of epochs another backend ran stay until the
    /// committee itself runs a later epoch. Blocks of `epoch` stay for a
    /// rerun of the same batch. The committee serves this scheduler's market
    /// only, as its blocks are keyed by epoch alone.
    #[cfg(feature = "mpc-simulation")]
    async fn retire_masks(&self, epoch: timescales_core::EpochId) {
        let Some(Backend::Mpc(mpc)) = self.backends.get(&BackendKind::Mpc) else {
            return;
        };
        let Some(through) = epoch.0.checked_sub(1) else {
            return;
        };
        let committee = Arc::clone(mpc.committee());
        // A committee still busy with a timed-out attempt refuses. The next
        // run expires the same blocks.
        let _expired = tokio::task::spawn_blocking(move || {
            committee.expire_masks(timescales_core::EpochId(through))
        })
        .await;
    }

    pub async fn run(&self, batch: ExecutionBatch) -> Result<Scheduled, SchedulerError> {
        self.run_cancellable(batch, &CancellationToken::new()).await
    }

    /// [`Self::run`] that stops with [`SchedulerError::Cancelled`] as soon as
    /// `cancel` fires, during an attempt or a backoff.
    pub async fn run_cancellable(
        &self,
        batch: ExecutionBatch,
        cancel: &CancellationToken,
    ) -> Result<Scheduled, SchedulerError> {
        check_policy(&self.policy)?;
        #[cfg(feature = "mpc-simulation")]
        self.retire_masks(batch.header.epoch).await;
        let batch = Arc::new(batch);
        let plan = self.policy.plan(
            batch.envelopes.len().max(batch.masked.len()),
            &self.available(Instant::now()),
        );
        let mut attempts = Vec::new();
        for kind in plan {
            let Some(backend) = self.backends.get(&kind) else {
                continue;
            };
            for attempt in 0..u32::from(self.policy.attempts_per_backend.max(1)) {
                if attempt > 0
                    && cancel
                        .run_until_cancelled(tokio::time::sleep(self.retry.delay(attempt)))
                        .await
                        .is_none()
                {
                    return Err(SchedulerError::Cancelled);
                }
                let Some(permit) = self.permit(kind, Instant::now()) else {
                    break;
                };
                let t = Instant::now();
                let run = tokio::time::timeout(
                    self.policy.attempt_timeout,
                    backend.execute(Arc::clone(&batch)),
                );
                let Some(r) = cancel.run_until_cancelled(run).await else {
                    return Err(SchedulerError::Cancelled);
                };
                let elapsed = t.elapsed();
                let err = match r {
                    Ok(Ok(res)) => {
                        let checked = match cancel
                            .run_until_cancelled(self.check(kind, backend, &batch, res))
                            .await
                        {
                            Some(checked) => checked,
                            None => return Err(SchedulerError::Cancelled),
                        };
                        return match checked {
                            Ok(result) => {
                                permit.succeeded();
                                attempts.push(Attempt {
                                    backend: kind,
                                    error: None,
                                    elapsed,
                                });
                                Ok(Scheduled {
                                    result,
                                    backend: kind,
                                    attempts,
                                })
                            }
                            // A backend that signs bad receipts is not retried.
                            Err(reason) => {
                                permit.failed();
                                Err(SchedulerError::BadReceipt {
                                    backend: kind,
                                    reason,
                                })
                            }
                        };
                    }
                    Ok(Err(e)) => e,
                    Err(_) => ExecutorError::Unavailable("attempt timed out".into()),
                };
                permit.failed();
                attempts.push(Attempt {
                    backend: kind,
                    error: Some(err.clone()),
                    elapsed,
                });
                match err {
                    ExecutorError::BadHeader(_) => return Err(SchedulerError::BadBatch(err)),
                    ExecutorError::Unavailable(_) | ExecutorError::Cancelled => continue,
                    // Aborted MPC runs consumed their masks. Key and execution
                    // errors are deterministic for this backend.
                    _ => break,
                }
            }
        }
        Err(SchedulerError::Exhausted(attempts))
    }
}

/// Every check a receipt must pass before it is used: the backend
/// kind and the signing executor, the signature, the batch it names, the
/// artifacts against the outcome, the settlement against the fills, and the
/// proof the policy requires.
fn check_result(
    kind: BackendKind,
    allowed: &BTreeSet<ExecutorId>,
    proof: ProofMode,
    batch: &ExecutionBatch,
    r: &ExecutionResult,
) -> Result<(), String> {
    let receipt = &r.receipt;
    if receipt.backend != kind {
        return Err(format!("receipt names backend {:?}", receipt.backend));
    }
    if !allowed.contains(&receipt.executor) {
        return Err("receipt signed by an executor that is not pinned".into());
    }
    receipt.verify_signature().map_err(|e| e.to_string())?;
    let h = &batch.header;
    if receipt.outcome.header_digest != h.digest() {
        return Err("receipt is for another batch".into());
    }
    r.artifacts
        .check_against(&receipt.outcome)
        .map_err(|e| e.to_string())?;
    r.artifacts
        .check_settlement(&h.params, h.epoch)
        .map_err(|e| e.to_string())?;
    if proof == ProofMode::Synchronous {
        let delivered = r.proof.as_ref().map(|p| p.digest);
        if receipt.proof == Hash32::ZERO || delivered != Some(receipt.proof) {
            return Err("policy requires the proof the receipt commits to".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
