//! Remote backends through the scheduler: the executor pin, receipt checks
//! a signature alone cannot pass, retries with backoff, and cancellation.

#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use timescales_auction::receipts::{BackendKind, ExecutionReceipt};
use timescales_core::identity::ExecutorKey;
use timescales_core::{CommitmentScheme, ExecutorId, FlowMode};
use timescales_executor::policy::{ExecutionPolicy, ProofMode};
use timescales_executor::scheduler::{
    Backend, BoxFuture, Circuit, ExecutorPin, RemoteBackend, RetrySettings, Scheduler,
    SchedulerError,
};
use timescales_executor::workload::{WorkloadConfig, default_params, generate};
use timescales_executor::{
    ExecutionBatch, ExecutionResult, ExecutorError, LocalKeySchedule, ReferenceExecutor,
};
use tokio_util::sync::CancellationToken;

const SIGNER: [u8; 32] = [5; 32];

/// What the double does on its next call.
#[derive(Clone)]
enum Step {
    Run,
    Fail(ExecutorError),
    Hang,
    /// Moves one base atom between two settlement leaves (conserving) and
    /// signs the result anew: a valid signature over a settlement the
    /// fills do not imply.
    Redistribute,
}

struct Double {
    inner: ReferenceExecutor<LocalKeySchedule>,
    kind: BackendKind,
    script: Mutex<VecDeque<Step>>,
    calls: AtomicUsize,
}

impl Double {
    fn new(kind: BackendKind, script: impl IntoIterator<Item = Step>) -> Arc<Self> {
        Arc::new(Self {
            inner: ReferenceExecutor::new(
                Arc::new(LocalKeySchedule::new([4; 32])),
                ExecutorKey::from_seed(SIGNER),
            ),
            kind,
            script: Mutex::new(script.into_iter().collect()),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl RemoteBackend for Double {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn execute(
        &self,
        b: Arc<ExecutionBatch>,
    ) -> BoxFuture<'_, Result<ExecutionResult, ExecutorError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let step = self.script.lock().pop_front().unwrap_or(Step::Run);
            match step {
                Step::Run => self.inner.execute_shared(b).await,
                Step::Fail(e) => Err(e),
                Step::Hang => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    Err(ExecutorError::Unavailable("woke up".into()))
                }
                Step::Redistribute => {
                    let mut r = self.inner.execute_shared(b).await?;
                    let deltas = &mut r.artifacts.settlement.deltas;
                    assert!(deltas.len() >= 2, "the batch trades");
                    deltas[0].base += 1;
                    deltas[1].base -= 1;
                    let mut outcome = r.receipt.outcome.clone();
                    outcome.settlement_root = r.artifacts.settlement.root();
                    r.receipt = ExecutionReceipt::sign(
                        &ExecutorKey::from_seed(SIGNER),
                        outcome,
                        r.receipt.backend,
                        r.receipt.attestation,
                        r.receipt.proof,
                        r.receipt.trace,
                    );
                    Ok(r)
                }
            }
        })
    }
}

fn batch() -> ExecutionBatch {
    let mut params = default_params(FlowMode::DualFlow, CommitmentScheme::Sha256);
    params.band_half_width = 4;
    let mut cfg = WorkloadConfig::new(params, 60, 3);
    cfg.traders = 20;
    generate(&cfg, &LocalKeySchedule::new([4; 32])).batch
}

fn policy(attempts: u8) -> ExecutionPolicy {
    ExecutionPolicy {
        backends: vec![BackendKind::Tee],
        proof: ProofMode::None,
        attempts_per_backend: attempts,
        attempt_timeout: Duration::from_secs(60),
        mpc_max_batch: 0,
    }
}

const FAST: RetrySettings = RetrySettings {
    backoff: Duration::from_millis(5),
    max_backoff: Duration::from_millis(20),
    circuit_cooldown: Duration::from_secs(30),
};

fn scheduler(
    remote: &Arc<Double>,
    attempts: u8,
    pin: Option<Arc<ExecutorPin>>,
) -> Scheduler<LocalKeySchedule> {
    let s = Scheduler::new(
        policy(attempts),
        vec![Backend::Remote(Arc::clone(remote) as Arc<dyn RemoteBackend>)],
    )
    .with_retry(FAST);
    match pin {
        Some(p) => s.with_executor_pin(p),
        None => s,
    }
}

fn pinned() -> Arc<ExecutorPin> {
    Arc::new(ExecutorPin::new([ExecutorKey::from_seed(SIGNER).id()]))
}

fn bad_receipt(r: Result<timescales_executor::scheduler::Scheduled, SchedulerError>) -> String {
    match r {
        Err(SchedulerError::BadReceipt { reason, .. }) => reason,
        other => panic!("expected a bad receipt, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_receipts_need_a_pinned_executor() {
    // Reference receipts, so the kind matches.
    let remote = Double::new(BackendKind::Reference, []);
    let mut p = policy(1);
    p.backends = vec![BackendKind::Reference];
    let unpinned: Scheduler<LocalKeySchedule> = Scheduler::new(
        p.clone(),
        vec![Backend::Remote(
            Arc::clone(&remote) as Arc<dyn RemoteBackend>
        )],
    );
    assert!(bad_receipt(unpinned.run(batch()).await).contains("no executor pin"));

    let pin = Arc::new(ExecutorPin::new([ExecutorId([9; 32]), ExecutorId([0; 32])]));
    let s: Scheduler<LocalKeySchedule> = Scheduler::new(
        p,
        vec![Backend::Remote(
            Arc::clone(&remote) as Arc<dyn RemoteBackend>
        )],
    )
    .with_executor_pin(Arc::clone(&pin));
    assert!(bad_receipt(s.run(batch()).await).contains("not pinned"));
    assert!(!pin.contains(&ExecutorId([0; 32])));
    // The market registered the executor: the swapped-in set takes effect.
    pin.store([ExecutorId([9; 32]), ExecutorKey::from_seed(SIGNER).id()]);
    assert!(s.run(batch()).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_receipt_naming_another_backend_is_refused() {
    // The double says Tee but returns reference receipts.
    let remote = Double::new(BackendKind::Tee, []);
    let s = scheduler(&remote, 1, Some(pinned()));
    assert!(bad_receipt(s.run(batch()).await).contains("backend"));
    assert!(matches!(
        s.circuit(BackendKind::Tee),
        Circuit::Closed { failures: 1 }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_settlement_the_fills_do_not_imply_is_refused() {
    let remote = Double::new(BackendKind::Reference, [Step::Redistribute]);
    let mut p = policy(1);
    p.backends = vec![BackendKind::Reference];
    let s: Scheduler<LocalKeySchedule> = Scheduler::new(
        p,
        vec![Backend::Remote(
            Arc::clone(&remote) as Arc<dyn RemoteBackend>
        )],
    )
    .with_executor_pin(pinned());
    let reason = bad_receipt(s.run(batch()).await);
    assert!(reason.contains("settlement of the fills"), "{reason}");
}

#[tokio::test(flavor = "multi_thread")]
async fn transient_failures_are_retried_and_others_are_not() {
    let remote = Double::new(
        BackendKind::Reference,
        [
            Step::Fail(ExecutorError::Unavailable("busy".into())),
            Step::Fail(ExecutorError::Cancelled),
        ],
    );
    let mut p = policy(3);
    p.backends = vec![BackendKind::Reference];
    let s: Scheduler<LocalKeySchedule> = Scheduler::new(
        p.clone(),
        vec![Backend::Remote(
            Arc::clone(&remote) as Arc<dyn RemoteBackend>
        )],
    )
    .with_retry(FAST)
    .with_executor_pin(pinned());
    let r = s.run(batch()).await.unwrap();
    assert_eq!(r.attempts.len(), 3);
    assert_eq!(remote.calls(), 3);

    // An execution error (a panic in the executor, say) is not retried.
    let remote = Double::new(
        BackendKind::Reference,
        [Step::Fail(ExecutorError::Execution(
            "executor task panicked".into(),
        ))],
    );
    let s: Scheduler<LocalKeySchedule> = Scheduler::new(
        p,
        vec![Backend::Remote(
            Arc::clone(&remote) as Arc<dyn RemoteBackend>
        )],
    )
    .with_retry(FAST)
    .with_executor_pin(pinned());
    match s.run(batch()).await {
        Err(SchedulerError::Exhausted(a)) => assert_eq!(a.len(), 1),
        other => panic!("{other:?}"),
    }
    assert_eq!(remote.calls(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn retries_back_off_exponentially() {
    let r = RetrySettings::default();
    let delays: Vec<u64> = (1..=7)
        .map(|n| u64::try_from(r.delay(n).as_millis()).unwrap())
        .collect();
    assert_eq!(delays, vec![500, 1_000, 2_000, 4_000, 8_000, 8_000, 8_000]);
    assert_eq!(r.delay(64), Duration::from_secs(8));

    let remote = Double::new(
        BackendKind::Reference,
        [
            Step::Fail(ExecutorError::Unavailable("1".into())),
            Step::Fail(ExecutorError::Unavailable("2".into())),
        ],
    );
    let mut p = policy(3);
    p.backends = vec![BackendKind::Reference];
    let s: Scheduler<LocalKeySchedule> = Scheduler::new(
        p,
        vec![Backend::Remote(
            Arc::clone(&remote) as Arc<dyn RemoteBackend>
        )],
    )
    .with_retry(RetrySettings {
        backoff: Duration::from_millis(40),
        max_backoff: Duration::from_millis(60),
        circuit_cooldown: Duration::from_secs(30),
    })
    .with_executor_pin(pinned());
    let t = Instant::now();
    assert!(s.run(batch()).await.is_ok());
    // 40 ms before the second attempt, 60 (capped from 80) before the third.
    assert!(
        t.elapsed() >= Duration::from_millis(100),
        "{:?}",
        t.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cancellation_stops_a_run_in_an_attempt_or_a_backoff() {
    let remote = Double::new(BackendKind::Reference, [Step::Hang]);
    let mut p = policy(2);
    p.backends = vec![BackendKind::Reference];
    let s: Scheduler<LocalKeySchedule> = Scheduler::new(
        p.clone(),
        vec![Backend::Remote(
            Arc::clone(&remote) as Arc<dyn RemoteBackend>
        )],
    )
    .with_executor_pin(pinned());
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });
    let t = Instant::now();
    assert_eq!(
        s.run_cancellable(batch(), &cancel).await.unwrap_err(),
        SchedulerError::Cancelled
    );
    assert!(t.elapsed() < Duration::from_secs(30));
    // An abandoned attempt is not counted against the backend.
    assert_eq!(
        s.circuit(BackendKind::Reference),
        Circuit::Closed { failures: 0 }
    );

    let remote = Double::new(
        BackendKind::Reference,
        [Step::Fail(ExecutorError::Unavailable("busy".into()))],
    );
    let s: Scheduler<LocalKeySchedule> = Scheduler::new(
        p,
        vec![Backend::Remote(
            Arc::clone(&remote) as Arc<dyn RemoteBackend>
        )],
    )
    .with_retry(RetrySettings {
        backoff: Duration::from_secs(3600),
        max_backoff: Duration::from_secs(3600),
        ..FAST
    })
    .with_executor_pin(pinned());
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });
    assert_eq!(
        s.run_cancellable(batch(), &cancel).await.unwrap_err(),
        SchedulerError::Cancelled
    );
    assert_eq!(remote.calls(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_abandoned_probe_frees_the_half_open_slot() {
    let remote = Double::new(
        BackendKind::Reference,
        [
            Step::Fail(ExecutorError::Unavailable("1".into())),
            Step::Hang,
        ],
    );
    let mut p = policy(1);
    p.backends = vec![BackendKind::Reference];
    let mut s: Scheduler<LocalKeySchedule> = Scheduler::new(
        p,
        vec![Backend::Remote(
            Arc::clone(&remote) as Arc<dyn RemoteBackend>
        )],
    )
    .with_retry(RetrySettings {
        circuit_cooldown: Duration::from_millis(20),
        ..FAST
    })
    .with_executor_pin(pinned());
    s.unhealthy_after = 1;
    assert!(s.run(batch()).await.is_err());
    assert!(matches!(
        s.circuit(BackendKind::Reference),
        Circuit::Open { .. }
    ));
    tokio::time::sleep(Duration::from_millis(30)).await;
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });
    assert_eq!(
        s.run_cancellable(batch(), &cancel).await.unwrap_err(),
        SchedulerError::Cancelled
    );
    assert_eq!(
        s.circuit(BackendKind::Reference),
        Circuit::HalfOpen { probing: false }
    );
    // The next run probes and closes the circuit.
    assert!(s.run(batch()).await.is_ok());
    assert_eq!(
        s.circuit(BackendKind::Reference),
        Circuit::Closed { failures: 0 }
    );
}
