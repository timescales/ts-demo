use std::sync::Arc;

use crate::attestation::Measurement;
use crate::workload::{WorkloadConfig, default_params, generate};
use crate::{ConfidentialExecutor, ExecutorError, KeyProvider, ReferenceExecutor};
use rand::SeedableRng;
use timescales_core::crypto::{EpochSecret, ScalarSealSecret, SealSecret};
use timescales_core::identity::ExecutorKey;
use timescales_core::{CommitmentScheme, EpochId, ExecutorId, FlowMode, MarketId};

use super::*;
use crate::tee::committee::KeyReleaseRequest;

/// Key provider holding one known secret, for the reference side of
/// differential tests.
struct OneKey(SealSecret);

impl KeyProvider for OneKey {
    fn epoch_public(&self, _: MarketId, _: EpochId) -> Result<[u8; 32], ExecutorError> {
        Ok(self.0.public())
    }
    fn epoch_secret(&self, _: MarketId, _: EpochId) -> Result<SealSecret, ExecutorError> {
        Ok(SealSecret::from_bytes(self.0.to_bytes()))
    }
    fn epoch_key(&self, _: MarketId, _: EpochId) -> Result<EpochSecret, ExecutorError> {
        Ok(EpochSecret::Threshold(ScalarSealSecret::from_x25519(
            &self.0,
        )))
    }
}

fn workload(dep: &LocalTeeDeployment, n: usize, seed: u64) -> crate::workload::Workload {
    let cfg = WorkloadConfig::new(
        default_params(FlowMode::DualFlow, CommitmentScheme::Sha256),
        n,
        seed,
    );
    dep.prepare_epoch(cfg.params.market, cfg.epoch);
    generate(&cfg, dep.keys.as_ref())
}

fn key_failure(err: ExecutorError) -> KeyFailure {
    match err {
        ExecutorError::KeyUnavailable(f) => f,
        other => panic!("expected KeyUnavailable, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tee_outcome_equals_reference_outcome() {
    let dep = LocalTeeDeployment::new(5, 3, 1);
    let cfg = WorkloadConfig::new(
        default_params(FlowMode::DualFlow, CommitmentScheme::Sha256),
        600,
        7,
    );
    let sk = dep.prepare_epoch_with_secret(cfg.params.market, cfg.epoch);
    let w = generate(&cfg, dep.keys.as_ref());
    assert!(dep.commit(&w.batch.header));

    let tee = dep.executor.execute(w.batch.clone()).await.expect("tee");
    tee.receipt.verify_signature().unwrap();
    assert_eq!(tee.receipt.backend, BackendKind::Tee);
    assert_ne!(tee.receipt.attestation, Hash32::ZERO);
    let att = tee.attestation.as_ref().expect("attestation bytes");
    assert_eq!(
        timescales_core::crypto::hash(timescales_core::crypto::domain::ATTESTATION_REPORT, att),
        tee.receipt.attestation
    );

    let reference = ReferenceExecutor::new(Arc::new(OneKey(sk)), ExecutorKey::from_seed([1; 32]));
    let r = reference.execute(w.batch.clone()).await.expect("reference");
    assert_eq!(tee.receipt.outcome, r.receipt.outcome);
    assert_eq!(tee.receipt.trace, r.receipt.trace);
    assert_eq!(tee.artifacts, r.artifacts);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_keys_before_batch_root_is_committed() {
    let dep = LocalTeeDeployment::new(3, 2, 2);
    let w = workload(&dep, 50, 1);
    let f = key_failure(dep.executor.execute(w.batch.clone()).await.unwrap_err());
    assert_eq!(f.members.len(), 3);
    assert!(
        f.members
            .iter()
            .all(|m| m.refusal == Some(ReleaseError::NotCommitted.code())),
        "{f}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn equivocated_root_is_refused() {
    let dep = LocalTeeDeployment::new(3, 2, 3);
    let w = workload(&dep, 50, 2);
    let mut other = w.batch.header;
    other.batch_root.0[0] ^= 1;
    assert!(dep.commit(&other));
    // The relay cannot later commit a different root for the same epoch.
    assert!(!dep.commit(&w.batch.header));
    let f = key_failure(dep.executor.execute(w.batch.clone()).await.unwrap_err());
    assert!(
        f.members
            .iter()
            .all(|m| m.refusal == Some(ReleaseError::HeaderMismatch.code()))
    );
}

fn deployment_with(measurement: Measurement, debug: bool, svn: u16) -> LocalTeeDeployment {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(9);
    let vendor = crate::attestation::simulated::SimulatedVendor::new(&mut rng, 5);
    let platform = Arc::new(vendor.platform(&mut rng, svn));
    LocalTeeDeployment::with_enclave(3, 2, rng, vendor, platform, measurement, debug).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_code_debug_mode_and_stale_tcb_get_no_keys() {
    use crate::attestation::TcbStatus;
    use crate::policy::PolicyViolation;

    let cases = [
        (
            deployment_with(Measurement::of_program("evil", "1", b""), false, 5),
            PolicyViolation::Measurement,
        ),
        (
            deployment_with(program_measurement(), true, 5),
            PolicyViolation::Debug,
        ),
        (
            deployment_with(program_measurement(), false, 4),
            PolicyViolation::Tcb(TcbStatus::OutOfDate),
        ),
    ];
    for (dep, violation) in cases {
        let w = workload(&dep, 20, 3);
        dep.commit(&w.batch.header);
        let f = key_failure(dep.executor.execute(w.batch.clone()).await.unwrap_err());
        let expected = ReleaseError::Policy(violation);
        assert_eq!(f.members.len(), 3);
        for m in &f.members {
            assert_eq!(m.refusal, Some(expected.code()));
            assert_eq!(m.detail, expected.to_string());
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn threshold_of_members_is_enough_and_necessary() {
    let dep = LocalTeeDeployment::new(5, 3, 4);
    let w = workload(&dep, 40, 4);
    dep.commit(&w.batch.header);
    dep.members[0].set_fault(MemberFault::Offline);
    dep.members[1].set_fault(MemberFault::Offline);
    let ok = dep
        .executor
        .execute_shared(Arc::new(w.batch.clone()))
        .await
        .unwrap();
    assert!(ok.receipt.verify_signature().is_ok());
    dep.members[2].set_fault(MemberFault::Offline);
    let f = key_failure(dep.executor.execute(w.batch.clone()).await.unwrap_err());
    let offline: Vec<u8> = f
        .members
        .iter()
        .filter(|m| m.refusal == Some(ReleaseError::Unavailable.code()))
        .map(|m| m.member)
        .collect();
    assert_eq!(offline, vec![1, 2, 3], "{f}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_corrupt_share_is_dropped_on_its_own() {
    let dep = LocalTeeDeployment::new(5, 3, 5);
    let w = workload(&dep, 40, 5);
    dep.commit(&w.batch.header);
    dep.members[0].set_fault(MemberFault::CorruptShare);
    dep.members[3].set_fault(MemberFault::CorruptShare);
    let h = w.batch.header;
    let inputs = EpochInputs {
        market_address: [0; 32],
        price_commitment: h.price_commitment,
        key: EpochKey {
            epoch_pk: dep.keys.epoch_public(h.market, h.epoch).unwrap(),
            commitments: dep.keys.epoch_commitments(h.market, h.epoch).unwrap(),
        },
        announcement_digest: Hash32::ZERO,
        admission: None,
    };
    assert_eq!(inputs.key.commitments.len(), 3);
    let run = dep
        .executor
        .execute_epoch(Arc::new(w.batch.clone()), inputs)
        .await
        .unwrap();
    assert_eq!(run.used, vec![2, 3, 5]);
    let rejected: Vec<(u8, Option<u8>, String)> = run
        .member_failures
        .iter()
        .map(|m| (m.member, m.refusal, m.detail.clone()))
        .collect();
    let inconsistent = ShareRejection::Inconsistent.to_string();
    assert_eq!(
        rejected,
        vec![(1, None, inconsistent.clone()), (4, None, inconsistent)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_commitments_corrupt_shares_are_searched_around() {
    let dep = LocalTeeDeployment::new(5, 3, 6);
    let cfg = WorkloadConfig::new(
        default_params(FlowMode::DualFlow, CommitmentScheme::Sha256),
        30,
        6,
    );
    let pk = dep.prepare_epoch(cfg.params.market, cfg.epoch);
    // Publish the key alone, as a directory that does not carry the
    // commitments would.
    dep.keys.publish(cfg.params.market, cfg.epoch, pk);
    let w = generate(&cfg, dep.keys.as_ref());
    dep.commit(&w.batch.header);
    dep.members[1].set_fault(MemberFault::CorruptShare);
    dep.members[2].set_fault(MemberFault::CorruptShare);
    assert!(dep.executor.execute(w.batch.clone()).await.is_ok());
    // With three corrupt shares no three shares reconstruct the key.
    dep.members[4].set_fault(MemberFault::CorruptShare);
    let f = key_failure(dep.executor.execute(w.batch.clone()).await.unwrap_err());
    assert_eq!(
        f.reason,
        ReconstructError::KeyMismatch { rejected: vec![] }.to_string()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_release_request_is_refused() {
    let dep = LocalTeeDeployment::new(3, 2, 6);
    let w = workload(&dep, 10, 6);
    dep.commit(&w.batch.header);
    let h = w.batch.header;
    let enclave = dep.executor.enclave();
    let handles: Vec<_> = dep
        .members
        .iter()
        .map(|m| m.serve(enclave.executor_id()))
        .collect();
    let mut nonces = Vec::new();
    for m in &handles {
        nonces.push(m.challenge(h.market, h.epoch).await.unwrap());
    }
    let req = KeyReleaseRequest {
        header: h,
        price_commitment: h.price_commitment,
        attestation: enclave.attest_v2(&h, nonces, Hash32::ZERO),
    };
    assert!(handles[0].release(req.clone()).await.is_ok());
    assert_eq!(
        handles[0].release(req.clone()).await,
        Err(ReleaseError::BadNonce)
    );
    // Another executor's channel cannot present this enclave's attestation.
    let other = dep.members[1].serve(ExecutorId([7; 32]));
    assert_eq!(other.release(req).await, Err(ReleaseError::Unauthenticated));
}

#[tokio::test(flavor = "multi_thread")]
async fn host_crashes_surface_as_unavailable() {
    let dep = LocalTeeDeployment::new(3, 2, 7);
    let w = workload(&dep, 10, 7);
    dep.commit(&w.batch.header);
    for f in [
        EnclaveFault::CrashBeforeKeyRequest,
        EnclaveFault::CrashAfterKeyRelease,
    ] {
        dep.executor.set_fault(f);
        assert!(matches!(
            dep.executor.execute(w.batch.clone()).await,
            Err(ExecutorError::Unavailable(_))
        ));
    }
    dep.executor.set_fault(EnclaveFault::None);
    assert!(dep.executor.execute(w.batch.clone()).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn version_2_batches_need_their_epoch_inputs() {
    let dep = LocalTeeDeployment::new(3, 2, 8);
    let w = workload(&dep, 10, 8);
    let mut b = w.batch.clone();
    b.header.version = timescales_core::HEADER_VERSION_ENVELOPE_BOUND;
    assert!(matches!(
        dep.executor.execute(b).await,
        Err(ExecutorError::KeyUnavailable(_))
    ));
}

#[test]
fn dealing_an_epoch_twice_keeps_the_first_key() {
    let dep = LocalTeeDeployment::new(3, 2, 9);
    let (m, e) = (MarketId(1), EpochId(4));
    let first = dep.prepare_epoch(m, e);
    assert_eq!(dep.prepare_epoch(m, e), first);
    let sk = SealSecret::from_bytes([3; 32]);
    dep.install_epoch_secret(m, e, &sk);
    assert_eq!(dep.keys.epoch_public(m, e).unwrap(), first);
    assert!(dep.members.iter().all(|x| x.holds(m, e)));
}

#[test]
fn invalid_committees_are_refused() {
    assert_eq!(
        LocalTeeDeployment::try_new(3, 0, 1).unwrap_err(),
        CommitteeError::Threshold { threshold: 0, n: 3 }
    );
    assert_eq!(
        LocalTeeDeployment::try_new(3, 4, 1).unwrap_err(),
        CommitteeError::Threshold { threshold: 4, n: 3 }
    );
    assert_eq!(
        LocalTeeDeployment::try_new(17, 9, 1).unwrap_err(),
        CommitteeError::MemberIndex(17)
    );
}
