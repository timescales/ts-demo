use std::sync::{Arc, OnceLock};

use crate::prover::Keys;
use crate::verifier::{ProofBundle, ShapedVerifyingKey, VerifyError};
use crate::workload::{WorkloadConfig, default_params, generate};
use crate::{ConfidentialExecutor, ExecutorError, LocalKeySchedule, ReferenceExecutor};
use rand::SeedableRng;
use timescales_core::identity::ExecutorKey;
use timescales_core::{CommitmentScheme, FlowMode, Lots};

use super::*;

const CAPACITY: usize = 14;

fn config(flow: FlowMode, seed: u64) -> WorkloadConfig {
    let mut p = default_params(flow, CommitmentScheme::PoseidonBn254);
    p.band_half_width = 2;
    p.max_order_lots_log2 = 6;
    let mut c = WorkloadConfig::new(p, 12, seed);
    c.traders = 7;
    c.max_quantity = 20;
    c.cancel_pct = 0;
    c
}

fn keys(flow: FlowMode) -> Arc<Keys> {
    static SINGLE: OnceLock<Arc<Keys>> = OnceLock::new();
    static DUAL: OnceLock<Arc<Keys>> = OnceLock::new();
    let cell = if flow == FlowMode::SingleBook {
        &SINGLE
    } else {
        &DUAL
    };
    cell.get_or_init(|| {
        let cfg = config(flow, 0);
        let lk = LocalKeySchedule::new([1; 32]);
        let w = generate(&cfg, &lk);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        Arc::new(Keys::setup(shape_for(&w.batch.header, CAPACITY), &mut rng).expect("setup"))
    })
    .clone()
}

async fn run(
    flow: FlowMode,
    seed: u64,
) -> (crate::workload::Workload, crate::ExecutionResult, Arc<Keys>) {
    let k = keys(flow);
    let lk = Arc::new(LocalKeySchedule::new([1; 32]));
    let w = generate(&config(flow, seed), lk.as_ref());
    let exec = ReferenceExecutor::new(lk, ExecutorKey::from_seed([4; 32]))
        .with_prover(Arc::new(Groth16Prover::new(k.clone())));
    let r = exec
        .execute(w.batch.clone())
        .await
        .expect("execute with proof");
    (w, r, k)
}

fn verify(
    w: &crate::workload::Workload,
    r: &crate::ExecutionResult,
    k: &Keys,
    artifacts: &timescales_auction::receipts::ExecutionArtifacts,
) -> Result<(), VerifyError> {
    let p = r.proof.as_ref().expect("proof");
    let bundle = ProofBundle::from_bytes(&p.bytes)?;
    let vk = ShapedVerifyingKey::from_bytes(k.shape, &k.vk_bytes())?;
    let commitments: Vec<_> = w.batch.envelopes.iter().map(|e| e.commitment).collect();
    vk.verify(
        &bundle,
        &w.batch.header,
        &commitments,
        &w.batch.prior_state,
        artifacts,
        &r.receipt.outcome.clearing,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn honest_proof_verifies_and_is_bound_to_receipt() {
    for flow in [FlowMode::SingleBook, FlowMode::DualFlow] {
        let (w, r, k) = run(flow, 3).await;
        let p = r.proof.as_ref().unwrap();
        assert_eq!(r.receipt.proof, p.digest);
        assert_eq!(
            ProofBundle::from_bytes(&p.bytes).unwrap().digest(),
            p.digest
        );
        verify(&w, &r, &k, &r.artifacts).expect("verifies");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn altered_fills_do_not_verify() {
    let mut found = None;
    for seed in 1..40 {
        let x = run(FlowMode::SingleBook, seed).await;
        if !x.1.artifacts.fills.is_empty() {
            found = Some(x);
            break;
        }
    }
    let (w, r, k) = found.expect("some seed trades");
    let mut a = r.artifacts.clone();
    a.fills[0].quantity = Lots(a.fills[0].quantity.0 + 1);
    assert_eq!(verify(&w, &r, &k, &a), Err(VerifyError::Invalid));
    let mut a = r.artifacts.clone();
    a.fills.remove(0);
    assert_eq!(verify(&w, &r, &k, &a), Err(VerifyError::Invalid));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_different_clearing_price_has_no_witness() {
    let k = keys(FlowMode::SingleBook);
    let lk = Arc::new(LocalKeySchedule::new([1; 32]));
    let w = generate(&config(FlowMode::SingleBook, 5), lk.as_ref());
    let exec = ReferenceExecutor::new(lk, ExecutorKey::from_seed([4; 32]));
    let r = exec.execute(w.batch.clone()).await.unwrap();
    // Rebuild the plaintext execution and try to prove a shifted price.
    let key = crate::KeyProvider::epoch_key(
        &LocalKeySchedule::new([1; 32]),
        w.batch.header.market,
        w.batch.header.epoch,
    )
    .unwrap();
    let opened = crate::open_envelopes(
        &key,
        w.batch.header.params.commitment_scheme,
        &w.batch.envelopes,
    );
    let plain = crate::execute_opened(
        &w.batch,
        &w.batch.header.band,
        &w.batch.header.seed(),
        opened,
        None,
        Default::default(),
    )
    .unwrap();
    assert_eq!(plain.outcome, r.receipt.outcome);
    let (mut c, _) = circuit_for(k.shape, &w.batch.header, &w.batch.prior_state, &plain).unwrap();
    assert!(crate::prover::is_satisfied(c.clone()).unwrap());
    c.books[0].0 = (c.books[0].0 + 1) % w.batch.header.band.ticks();
    assert!(!crate::prover::is_satisfied(c).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn sha256_markets_are_refused() {
    let lk = Arc::new(LocalKeySchedule::new([1; 32]));
    let mut cfg = config(FlowMode::SingleBook, 2);
    cfg.params.commitment_scheme = CommitmentScheme::Sha256;
    let w = generate(&cfg, lk.as_ref());
    let exec = ReferenceExecutor::new(lk, ExecutorKey::from_seed([4; 32]))
        .with_prover(Arc::new(Groth16Prover::new(keys(FlowMode::SingleBook))));
    assert!(matches!(
        exec.execute(w.batch.clone()).await,
        Err(ExecutorError::Execution(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn deferred_proof_arrives_after_receipt() {
    let k = keys(FlowMode::DualFlow);
    let lk = Arc::new(LocalKeySchedule::new([1; 32]));
    let w = generate(&config(FlowMode::DualFlow, 9), lk.as_ref());
    let deferred = Arc::new(DeferredProver::new(k.clone()));
    let exec =
        ReferenceExecutor::new(lk, ExecutorKey::from_seed([4; 32])).with_prover(deferred.clone());
    let r = exec.execute(w.batch.clone()).await.unwrap();
    assert_eq!(
        r.receipt.proof,
        Hash32::ZERO,
        "deferred receipts carry no proof digest"
    );
    let d = deferred
        .next(std::time::Duration::from_secs(600))
        .expect("proof delivered");
    assert_eq!(d.header, w.batch.header.digest());
    let bundle = d.bundle.unwrap();
    let vk = ShapedVerifyingKey::from_bytes(k.shape, &k.vk_bytes()).unwrap();
    let commitments: Vec<_> = w.batch.envelopes.iter().map(|e| e.commitment).collect();
    vk.verify(
        &bundle,
        &w.batch.header,
        &commitments,
        &w.batch.prior_state,
        &r.artifacts,
        &r.receipt.outcome.clearing,
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn tee_with_proof() {
    let k = keys(FlowMode::DualFlow);
    let dep = crate::tee::LocalTeeDeployment::new(3, 2, 4);
    let cfg = config(FlowMode::DualFlow, 11);
    dep.prepare_epoch(cfg.params.market, cfg.epoch);
    let w = generate(&cfg, dep.keys.as_ref());
    dep.commit(&w.batch.header);
    let LocalTeeDeployment { executor, .. } = dep;
    let exec = executor.with_prover(Arc::new(Groth16Prover::new(k.clone())));
    let r = exec.execute(w.batch.clone()).await.unwrap();
    assert_ne!(r.receipt.proof, Hash32::ZERO);
    verify(&w, &r, &k, &r.artifacts).unwrap();
}

#[test]
fn deferred_queues_are_bounded() {
    let k = keys(FlowMode::DualFlow);
    let lk = LocalKeySchedule::new([1; 32]);
    let w = generate(&config(FlowMode::DualFlow, 9), &lk);
    let key =
        crate::KeyProvider::epoch_key(&lk, w.batch.header.market, w.batch.header.epoch).unwrap();
    let opened = crate::open_envelopes(
        &key,
        w.batch.header.params.commitment_scheme,
        &w.batch.envelopes,
    );
    let plain = crate::execute_opened(
        &w.batch,
        &w.batch.header.band,
        &w.batch.header.seed(),
        opened,
        None,
        Default::default(),
    )
    .unwrap();

    // A worker that reports when it picks a job and waits to be released.
    let (started_tx, started) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = Mutex::new(released);
    let prover = DeferredProver::spawn(k, 1, 1, move |_, _, _| {
        let _ = started_tx.send(());
        let _ = released.lock().unwrap().recv();
        Err(ExecutorError::Execution("stub".into()))
    });
    let (h, prior) = (&w.batch.header, &w.batch.prior_state);
    assert_eq!(prover.prove(h, prior, &plain), Ok(None));
    started.recv().unwrap();
    // One job in the worker and one in the queue: the next is refused.
    assert_eq!(prover.prove(h, prior, &plain), Ok(None));
    assert_eq!(
        prover.prove(h, prior, &plain),
        Err(ExecutorError::Unavailable("proof queue full".into()))
    );
    release.send(()).unwrap();
    started.recv().unwrap();
    release.send(()).unwrap();
    // Nobody collected the first proof. It gives way to the second.
    let deadline = Instant::now() + Duration::from_secs(10);
    while prover.dropped() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(prover.dropped(), 1);
    assert!(prover.next(Duration::from_secs(1)).is_some());
    assert!(prover.next(Duration::from_millis(10)).is_none());
}

use crate::tee::LocalTeeDeployment;
