use std::sync::Arc;
use std::time::Duration;

use crate::mpc::{Fault, MpcCommittee, MpcConfig};
use crate::tee::{EnclaveFault, LocalTeeDeployment, MemberFault, PublishedEpochKeys};
use crate::workload::{WorkloadConfig, attach_masked, default_params, generate};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use timescales_core::identity::ExecutorKey;
use timescales_core::{CommitmentScheme, EpochId, FlowMode, TraderId};

use super::*;

fn policy(order: Vec<BackendKind>, timeout: Duration) -> ExecutionPolicy {
    ExecutionPolicy {
        backends: order,
        proof: ProofMode::None,
        attempts_per_backend: 2,
        attempt_timeout: timeout,
        mpc_max_batch: 10_000,
    }
}

struct Setup {
    dep: LocalTeeDeployment,
    committee: Arc<MpcCommittee>,
    batch: ExecutionBatch,
}

fn setup(seed: u64) -> Setup {
    let dep = LocalTeeDeployment::new(3, 2, seed);
    let mut p = default_params(FlowMode::DualFlow, CommitmentScheme::Sha256);
    p.band_half_width = 4;
    let mut cfg = WorkloadConfig::new(p, 60, seed);
    cfg.traders = 25;
    dep.prepare_epoch(cfg.params.market, cfg.epoch);
    let mut w = generate(&cfg, dep.keys.as_ref());
    let committee = Arc::new(MpcCommittee::new(
        MpcConfig {
            dealer_seed: Some(ChaCha20Rng::seed_from_u64(seed).get_seed()),
            ..MpcConfig::default()
        },
        ExecutorKey::from_seed([3; 32]),
    ));
    attach_masked(&mut w, &committee);
    dep.commit(&w.batch.header);
    Setup {
        dep,
        committee,
        batch: w.batch,
    }
}

/// Short backoff so retries do not slow the tests down.
const FAST: RetrySettings = RetrySettings {
    backoff: Duration::from_millis(5),
    max_backoff: Duration::from_millis(20),
    circuit_cooldown: Duration::from_secs(30),
};

fn scheduler(
    s: Setup,
    order: Vec<BackendKind>,
    timeout: Duration,
) -> (
    Scheduler<PublishedEpochKeys>,
    Arc<TeeExecutor>,
    Arc<MpcCommittee>,
    ExecutionBatch,
) {
    let Setup {
        dep,
        committee,
        batch,
    } = s;
    let tee = Arc::new(dep.executor);
    let backends = vec![
        Backend::Tee(tee.clone()),
        Backend::Mpc(MpcExecutor::new(committee.clone())),
    ];
    (
        Scheduler::new(policy(order, timeout), backends).with_retry(FAST),
        tee,
        committee,
        batch,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn primary_backend_serves() {
    let (s, _, _, batch) = scheduler(
        setup(1),
        vec![BackendKind::Tee, BackendKind::Mpc],
        Duration::from_secs(30),
    );
    let r = s.run(batch).await.unwrap();
    assert_eq!(r.backend, BackendKind::Tee);
    assert_eq!(r.attempts.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn tee_outage_fails_over_to_mpc_with_identical_outcome() {
    let (s, tee, _, batch) = scheduler(
        setup(2),
        vec![BackendKind::Tee, BackendKind::Mpc],
        Duration::from_secs(60),
    );
    let reference = s.run(batch.clone()).await.unwrap().result.receipt.outcome;
    tee.set_fault(EnclaveFault::CrashAfterKeyRelease);
    let r = s.run(batch).await.unwrap();
    assert_eq!(r.backend, BackendKind::Mpc);
    assert_eq!(
        r.attempts
            .iter()
            .filter(|a| a.backend == BackendKind::Tee)
            .count(),
        2,
        "transient TEE failure is retried"
    );
    assert_eq!(r.result.receipt.outcome, reference);
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_key_release_times_out_and_fails_over() {
    let st = setup(3);
    for m in &st.dep.members {
        m.set_fault(MemberFault::Slow(Duration::from_secs(10)));
    }
    let (s, _, _, batch) = scheduler(
        st,
        vec![BackendKind::Tee, BackendKind::Mpc],
        Duration::from_millis(300),
    );
    let mut p = policy(
        vec![BackendKind::Tee, BackendKind::Mpc],
        Duration::from_millis(300),
    );
    p.attempts_per_backend = 1;
    let s = Scheduler { policy: p, ..s };
    // The TEE attempt must time out. Whether the MPC attempt fits in the
    // same budget depends on the build profile, so both endings are valid as
    // long as every failure is a timeout.
    let r = s.run(batch).await;
    match r {
        Ok(r) => assert_eq!(r.backend, BackendKind::Mpc),
        Err(SchedulerError::Exhausted(a)) => {
            assert!(
                a.iter()
                    .all(|x| matches!(x.error, Some(ExecutorError::Unavailable(_))))
            );
        }
        Err(e) => panic!("unexpected {e:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mpc_abort_is_not_retried_and_everything_failing_is_reported() {
    let (s, tee, committee, batch) = scheduler(
        setup(4),
        vec![BackendKind::Mpc, BackendKind::Tee],
        Duration::from_secs(60),
    );
    committee.set_fault(Some(Fault::Crash { party: 0, round: 2 }));
    tee.set_fault(EnclaveFault::CrashBeforeKeyRequest);
    match s.run(batch).await {
        Err(SchedulerError::Exhausted(a)) => {
            assert_eq!(
                a.iter().filter(|x| x.backend == BackendKind::Mpc).count(),
                1
            );
            assert_eq!(
                a.iter().filter(|x| x.backend == BackendKind::Tee).count(),
                2
            );
        }
        other => panic!("expected exhaustion, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_batch_stops_immediately() {
    let (s, _, _, mut batch) = scheduler(
        setup(5),
        vec![BackendKind::Tee, BackendKind::Mpc],
        Duration::from_secs(60),
    );
    batch.header.batch_root.0[0] ^= 1;
    assert!(matches!(
        s.run(batch).await,
        Err(SchedulerError::BadBatch(ExecutorError::BadHeader(_)))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_failures_mark_backend_unhealthy() {
    let (s, tee, _, batch) = scheduler(setup(6), vec![BackendKind::Tee], Duration::from_secs(60));
    tee.set_fault(EnclaveFault::CrashBeforeKeyRequest);
    let _ = s.run(batch.clone()).await;
    let _ = s.run(batch.clone()).await;
    // Three failures open the circuit (the fourth attempt is not made), so
    // the plan is empty now.
    assert!(matches!(s.circuit(BackendKind::Tee), Circuit::Open { .. }));
    match s.run(batch.clone()).await {
        Err(SchedulerError::Exhausted(a)) => assert!(a.is_empty()),
        other => panic!("{other:?}"),
    }
    // The deprecated reset still closes it.
    #[allow(deprecated)]
    s.reset_health(BackendKind::Tee);
    assert_eq!(s.circuit(BackendKind::Tee), Circuit::Closed { failures: 0 });
    tee.set_fault(EnclaveFault::None);
    assert!(s.run(batch).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_circuit_lets_one_probe_through_after_the_cooldown() {
    let (s, tee, _, batch) = scheduler(setup(7), vec![BackendKind::Tee], Duration::from_secs(60));
    let s = s.with_retry(RetrySettings {
        circuit_cooldown: Duration::from_millis(50),
        ..FAST
    });
    tee.set_fault(EnclaveFault::CrashBeforeKeyRequest);
    let _ = s.run(batch.clone()).await;
    let _ = s.run(batch.clone()).await;
    assert!(matches!(s.circuit(BackendKind::Tee), Circuit::Open { .. }));
    tokio::time::sleep(Duration::from_millis(60)).await;
    // The probe fails: open again, one attempt only.
    match s.run(batch.clone()).await {
        Err(SchedulerError::Exhausted(a)) => assert_eq!(a.len(), 1),
        other => panic!("{other:?}"),
    }
    assert!(matches!(s.circuit(BackendKind::Tee), Circuit::Open { .. }));
    tokio::time::sleep(Duration::from_millis(60)).await;
    tee.set_fault(EnclaveFault::None);
    assert!(s.run(batch).await.is_ok());
    assert_eq!(s.circuit(BackendKind::Tee), Circuit::Closed { failures: 0 });
}

#[tokio::test(flavor = "multi_thread")]
async fn a_run_drops_the_mpc_masks_of_earlier_epochs() {
    let (s, _, committee, batch) = scheduler(
        setup(10),
        vec![BackendKind::Tee, BackendKind::Mpc],
        Duration::from_secs(60),
    );
    let e = batch.header.epoch.0;
    let trader = TraderId([9; 32]);
    committee
        .request_masks_for(trader, EpochId(e - 1), 4)
        .unwrap();
    committee
        .request_masks_for(trader, EpochId(e + 1), 4)
        .unwrap();
    let before = committee.outstanding_masks().unwrap();
    let r = s.run(batch).await.unwrap();
    assert_eq!(r.backend, BackendKind::Tee);
    // Only the earlier epoch's block went: the blocks of the epoch that ran
    // stay for a rerun, and the next epoch's are untouched.
    assert_eq!(committee.outstanding_masks().unwrap(), before - 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn receipts_must_come_from_the_backend_that_ran() {
    let st = setup(8);
    let (s, _, _, batch) = scheduler(st, vec![BackendKind::Tee], Duration::from_secs(60));
    let r = s.run(batch.clone()).await.unwrap();
    let own = BTreeSet::from([r.result.receipt.executor]);
    assert!(check_result(BackendKind::Tee, &own, ProofMode::None, &batch, &r.result).is_ok());
    // Another kind, another executor, another batch.
    assert!(check_result(BackendKind::Mpc, &own, ProofMode::None, &batch, &r.result).is_err());
    assert!(
        check_result(
            BackendKind::Tee,
            &BTreeSet::new(),
            ProofMode::None,
            &batch,
            &r.result
        )
        .is_err()
    );
    let mut other = batch.clone();
    other.header.prev_receipt = Hash32([1; 32]);
    assert!(check_result(BackendKind::Tee, &own, ProofMode::None, &other, &r.result).is_err());
    // A synchronous proof policy needs the proof the receipt commits to.
    assert!(
        check_result(
            BackendKind::Tee,
            &own,
            ProofMode::Synchronous,
            &batch,
            &r.result
        )
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deferred_proofs_are_a_configuration_error() {
    let st = setup(9);
    let (s, _, _, batch) = scheduler(st, vec![BackendKind::Tee], Duration::from_secs(60));
    let mut p = policy(vec![BackendKind::Tee], Duration::from_secs(60));
    p.proof = ProofMode::Deferred { window_epochs: 4 };
    let s = Scheduler {
        policy: p.clone(),
        ..s
    };
    assert!(matches!(s.run(batch).await, Err(SchedulerError::Config(_))));
    assert!(matches!(
        Scheduler::<PublishedEpochKeys>::try_new(p, Vec::new()),
        Err(SchedulerError::Config(_))
    ));
}
