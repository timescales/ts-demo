//! H3 for the MPC backend: identical outcomes to the reference executor.

use std::sync::Arc;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_core::identity::ExecutorKey;
use timescales_core::{CommitmentScheme, FlowMode};
use timescales_executor::mpc::{
    Fault, LtCircuit, MpcCommittee, MpcConfig, MpcExecutor, NetworkModel,
};
use timescales_executor::workload::{
    Funding, WorkloadConfig, attach_masked, default_params, generate,
};
use timescales_executor::{
    ConfidentialExecutor, ExecutorError, LocalKeySchedule, ReferenceExecutor,
};

fn small_params(flow: FlowMode) -> timescales_core::MarketParams {
    let mut p = default_params(flow, CommitmentScheme::Sha256);
    p.band_half_width = 6;
    p
}

async fn compare(
    cfg: WorkloadConfig,
    mpc: MpcConfig,
) -> (
    timescales_executor::ExecutionResult,
    timescales_executor::ExecutionResult,
    Arc<MpcCommittee>,
) {
    let keys = Arc::new(LocalKeySchedule::new([3; 32]));
    let mut w = generate(&cfg, keys.as_ref());
    let committee = Arc::new(MpcCommittee::new(mpc, ExecutorKey::from_seed([8; 32])));
    attach_masked(&mut w, &committee);
    let reference = ReferenceExecutor::new(keys, ExecutorKey::from_seed([9; 32]));
    let r = reference.execute(w.batch.clone()).await.expect("reference");
    let m = MpcExecutor::new(committee.clone())
        .execute(w.batch.clone())
        .await
        .expect("mpc");
    (r, m, committee)
}

#[tokio::test(flavor = "multi_thread")]
async fn mpc_equals_reference_across_flows_and_funding() {
    let cases = [
        (FlowMode::SingleBook, Funding::Rich, 120, 1u64),
        (FlowMode::DualFlow, Funding::Rich, 150, 2),
        (FlowMode::DualFlow, Funding::Tight(50), 150, 3),
        (FlowMode::SingleBook, Funding::Tight(70), 100, 4),
    ];
    for (flow, funding, n, seed) in cases {
        let mut cfg = WorkloadConfig::new(small_params(flow), n, seed);
        cfg.funding = funding;
        // Enough traders that self-trade prevention removes some orders but
        // not all of them.
        cfg.traders = n / 3;
        cfg.cancel_pct = 5;
        cfg.noop_pct = 5;
        cfg.max_quantity = 40;
        let (r, m, committee) = compare(
            cfg,
            MpcConfig {
                dealer_seed: Some(ChaCha20Rng::seed_from_u64(seed).get_seed()),
                ..MpcConfig::default()
            },
        )
        .await;
        assert_eq!(
            r.receipt.outcome, m.receipt.outcome,
            "flow {flow:?} funding {funding:?} seed {seed}"
        );
        assert_eq!(r.artifacts, m.artifacts);
        assert!(
            !m.artifacts.fills.is_empty(),
            "case {seed} produced no trades; workload not exercising matching"
        );
        let rep = committee.last_report().expect("report");
        assert!(rep.meter.comparisons > 0 && rep.preprocessing.triples > 0);
        assert!(rep.online_latency(&NetworkModel::WAN) > rep.online_latency(&NetworkModel::LAN));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn circuits_and_security_modes_agree() {
    for (circuit, authenticated) in [(LtCircuit::Ripple, true), (LtCircuit::LogDepth, false)] {
        let mut cfg = WorkloadConfig::new(small_params(FlowMode::DualFlow), 80, 11);
        cfg.traders = 10;
        let mpc = MpcConfig {
            circuit,
            authenticated,
            parties: 4,
            dealer_seed: Some(ChaCha20Rng::seed_from_u64(5).get_seed()),
        };
        let (r, m, _) = compare(cfg, mpc).await;
        assert_eq!(r.receipt.outcome, m.receipt.outcome);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn node_failure_and_tampering_abort() {
    let keys = Arc::new(LocalKeySchedule::new([3; 32]));
    let mut cfg = WorkloadConfig::new(small_params(FlowMode::SingleBook), 40, 21);
    cfg.traders = 8;
    let mut w = generate(&cfg, keys.as_ref());
    let committee = Arc::new(MpcCommittee::new(
        MpcConfig::default(),
        ExecutorKey::from_seed([8; 32]),
    ));
    attach_masked(&mut w, &committee);
    let exec = MpcExecutor::new(committee.clone());

    committee.set_fault(Some(Fault::Crash { party: 1, round: 5 }));
    assert!(matches!(
        exec.execute(w.batch.clone()).await,
        Err(ExecutorError::Aborted(_))
    ));

    // Masks are single use: a retry with the same inputs is refused rather
    // than silently computing on reused randomness.
    committee.set_fault(None);
    let retry = exec.execute(w.batch.clone()).await.expect("retry runs");
    assert_eq!(
        retry.metrics.accepted, 0,
        "consumed masks must not be reused"
    );

    let mut w2 = generate(
        &WorkloadConfig {
            seed: 22,
            ..cfg.clone()
        },
        keys.as_ref(),
    );
    attach_masked(&mut w2, &committee);
    committee.set_fault(Some(Fault::CorruptOpenings { party: 2, round: 3 }));
    assert!(matches!(
        exec.execute(w2.batch.clone()).await,
        Err(ExecutorError::Aborted(_))
    ));
}
