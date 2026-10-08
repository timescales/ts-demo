//! Implements the crate's async trait with a body that awaits before it uses
//! its argument, so an unimplementable signature fails to compile here.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use timescales_auction::receipts::BackendKind;
use timescales_core::identity::ExecutorKey;
use timescales_executor::{
    ConfidentialExecutor, ExecutionBatch, ExecutionResult, ExecutorError, LocalKeySchedule,
    ReferenceExecutor,
};

/// Yields once, then delegates.
struct Deferred<E>(E);

impl<E: ConfidentialExecutor> ConfidentialExecutor for Deferred<E> {
    fn backend(&self) -> BackendKind {
        self.0.backend()
    }

    async fn execute(&self, batch: ExecutionBatch) -> Result<ExecutionResult, ExecutorError> {
        tokio::task::yield_now().await;
        self.0.execute(batch).await
    }
}

#[test]
fn confidential_executor_is_implementable() {
    let inner = ReferenceExecutor::new(
        Arc::new(LocalKeySchedule::new([1; 32])),
        ExecutorKey::from_seed([2; 32]),
    );
    let e = Deferred(inner);
    assert_eq!(e.backend(), BackendKind::Reference);
}
