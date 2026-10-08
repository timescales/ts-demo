//! Local reference executor.
//!
//! Runs the plaintext pipeline in-process with keys from a [`KeyProvider`].
//! Provides no confidentiality from its operator. It exists to define
//! correct behaviour and to anchor differential tests.

use std::sync::Arc;
use std::time::Instant;

use timescales_auction::orderbook::RejectReason;
use timescales_auction::receipts::{BackendKind, ExecutionReceipt};
use timescales_core::identity::ExecutorKey;
use timescales_core::intent::PrivateIntent;
use timescales_core::{ExecutorId, HEADER_VERSION_ENVELOPE_BOUND, Hash32, PriceBand, TraderId};

use crate::pipeline::{check_header, execute_opened, open_envelopes, order_seed};
use crate::{
    ConfidentialExecutor, ExecutionBatch, ExecutionMetrics, ExecutionResult, ExecutorError,
    KeyFailure, KeyProvider, PlainProver, spawn_blocking,
};

pub struct ReferenceExecutor<K> {
    keys: Arc<K>,
    signer: Arc<ExecutorKey>,
    prover: Option<Arc<dyn PlainProver>>,
    market_address: Option<[u8; 32]>,
}

impl<K> core::fmt::Debug for ReferenceExecutor<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReferenceExecutor")
            .field("executor", &self.signer.id())
            .finish()
    }
}

/// What opening a batch hands to the rest of the pipeline.
struct Opened {
    band: PriceBand,
    seed: Hash32,
    intents: Vec<Result<PrivateIntent, RejectReason>>,
    metrics: ExecutionMetrics,
}

impl<K: KeyProvider + 'static> ReferenceExecutor<K> {
    pub fn new(keys: Arc<K>, signer: ExecutorKey) -> Self {
        Self {
            keys,
            signer: Arc::new(signer),
            prover: None,
            market_address: None,
        }
    }

    /// Prove every batch synchronously before signing its receipt.
    pub fn with_prover(mut self, prover: Arc<dyn PlainProver>) -> Self {
        self.prover = Some(prover);
        self
    }

    /// The market account address, which the canonical order of a version 2
    /// header depends on. Without it version 2 headers are refused.
    pub fn with_market_address(mut self, address: [u8; 32]) -> Self {
        self.market_address = Some(address);
        self
    }

    pub fn executor_id(&self) -> ExecutorId {
        self.signer.id()
    }

    /// Synchronous entry point.
    pub fn execute_blocking(
        &self,
        batch: &ExecutionBatch,
    ) -> Result<ExecutionResult, ExecutorError> {
        self.execute_admitted(batch, None)
    }

    /// [`Self::execute_blocking`] with a provenance admission vector:
    /// a Place or Cancel at index `i` runs only if `admission[i]` is its
    /// trader. The result's metrics list the envelopes that did not
    /// authenticate.
    pub fn execute_admitted(
        &self,
        batch: &ExecutionBatch,
        admission: Option<&[Option<TraderId>]>,
    ) -> Result<ExecutionResult, ExecutorError> {
        let opened = open(self.keys.as_ref(), self.market_address, batch)?;
        finish(
            &self.signer,
            self.prover.as_deref(),
            batch,
            opened,
            admission,
        )
    }

    /// Execute a shared batch. Opening and execution run as separate tasks
    /// on the blocking pool, so a caller that gives up between them stops
    /// the second one from starting.
    pub async fn execute_shared(
        &self,
        batch: Arc<ExecutionBatch>,
    ) -> Result<ExecutionResult, ExecutorError> {
        let keys = Arc::clone(&self.keys);
        let address = self.market_address;
        let b = Arc::clone(&batch);
        let opened = spawn_blocking(move || open(keys.as_ref(), address, &b)).await?;
        let signer = Arc::clone(&self.signer);
        let prover = self.prover.clone();
        spawn_blocking(move || finish(&signer, prover.as_deref(), &batch, opened, None)).await
    }
}

fn open<K: KeyProvider>(
    keys: &K,
    market_address: Option<[u8; 32]>,
    batch: &ExecutionBatch,
) -> Result<Opened, ExecutorError> {
    let h = &batch.header;
    let mut metrics = ExecutionMetrics::default();
    let t = Instant::now();
    let band = check_header(h, &batch.envelopes, &batch.balances, &batch.prior_state)?;
    metrics.stages.push(("check-header".into(), t.elapsed()));

    let address = match (h.version, market_address) {
        (HEADER_VERSION_ENVELOPE_BOUND, None) => {
            return Err(ExecutorError::KeyUnavailable(KeyFailure::new(
                "header version 2 needs the market address for its epoch seed",
            )));
        }
        (_, address) => address.unwrap_or([0; 32]),
    };
    let t = Instant::now();
    let key = keys.epoch_key(h.market, h.epoch)?;
    let intents = open_envelopes(&key, h.params.commitment_scheme, &batch.envelopes);
    let seed = order_seed(h, &key, &address);
    drop(key);
    metrics.stages.push(("open".into(), t.elapsed()));
    Ok(Opened {
        band,
        seed,
        intents,
        metrics,
    })
}

fn finish(
    signer: &ExecutorKey,
    prover: Option<&dyn PlainProver>,
    batch: &ExecutionBatch,
    opened: Opened,
    admission: Option<&[Option<TraderId>]>,
) -> Result<ExecutionResult, ExecutorError> {
    let h = &batch.header;
    let mut plain = execute_opened(
        batch,
        &opened.band,
        &opened.seed,
        opened.intents,
        admission,
        opened.metrics,
    )?;
    let proof = match prover {
        Some(p) => {
            let t = Instant::now();
            let a = p.prove(h, &batch.prior_state, &plain)?;
            plain.metrics.stages.push(("prove".into(), t.elapsed()));
            a
        }
        None => None,
    };
    let receipt = ExecutionReceipt::sign(
        signer,
        plain.outcome,
        BackendKind::Reference,
        Hash32::ZERO,
        proof.as_ref().map_or(Hash32::ZERO, |p| p.digest),
        plain.trace.digest(),
    );
    Ok(ExecutionResult {
        receipt,
        artifacts: plain.artifacts,
        metrics: plain.metrics,
        attestation: None,
        proof,
    })
}

impl<K: KeyProvider + 'static> ConfidentialExecutor for ReferenceExecutor<K> {
    fn backend(&self) -> BackendKind {
        BackendKind::Reference
    }

    async fn execute(&self, batch: ExecutionBatch) -> Result<ExecutionResult, ExecutorError> {
        self.execute_shared(Arc::new(batch)).await
    }
}
