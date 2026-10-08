//! Implements the crate's async trait with a body that awaits before it uses
//! its argument, and runs it through the scheduler as `Backend::Remote`.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use timescales_auction::receipts::BackendKind;
use timescales_core::identity::ExecutorKey;
use timescales_core::{CommitmentScheme, FlowMode};
use timescales_executor::policy::{ExecutionPolicy, ProofMode};
use timescales_executor::scheduler::{Backend, BoxFuture, ExecutorPin, RemoteBackend, Scheduler};
use timescales_executor::workload::{WorkloadConfig, default_params, generate};
use timescales_executor::{
    ExecutionBatch, ExecutionResult, ExecutorError, KeyProvider, LocalKeySchedule,
    ReferenceExecutor,
};

/// A "remote" backend that runs the reference executor in process.
struct InProcess(ReferenceExecutor<LocalKeySchedule>);

impl RemoteBackend for InProcess {
    fn kind(&self) -> BackendKind {
        BackendKind::Reference
    }

    fn execute(
        &self,
        b: Arc<ExecutionBatch>,
    ) -> BoxFuture<'_, Result<ExecutionResult, ExecutorError>> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            self.0.execute_shared(b).await
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_backend_runs_through_the_scheduler() {
    let keys = Arc::new(LocalKeySchedule::new([4; 32]));
    let cfg = WorkloadConfig::new(
        default_params(FlowMode::DualFlow, CommitmentScheme::Sha256),
        40,
        3,
    );
    let w = generate(&cfg, keys.as_ref());
    assert!(keys.epoch_public(cfg.params.market, cfg.epoch).is_ok());
    let executor = ExecutorKey::from_seed([5; 32]);
    let pin = Arc::new(ExecutorPin::new([executor.id()]));
    let remote: Arc<dyn RemoteBackend> =
        Arc::new(InProcess(ReferenceExecutor::new(keys.clone(), executor)));
    let scheduler: Scheduler<LocalKeySchedule> = Scheduler::new(
        ExecutionPolicy {
            backends: vec![BackendKind::Reference],
            proof: ProofMode::None,
            attempts_per_backend: 1,
            attempt_timeout: Duration::from_secs(60),
            mpc_max_batch: 0,
        },
        vec![Backend::Remote(remote)],
    )
    .with_executor_pin(pin);
    let s = scheduler.run(w.batch.clone()).await.unwrap();
    assert_eq!(s.backend, BackendKind::Reference);
    assert_eq!(
        s.result.receipt.outcome.header_digest,
        w.batch.header.digest()
    );
}
