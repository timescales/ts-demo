//! The enclave boundary: typed signatures only, attestation binding,
//! failing quoters, and share reconstruction with per-share verdicts.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_auction::BatchHeader;
use timescales_auction::receipts::cosign_digest;
use timescales_core::crypto::threshold::{
    ScalarShare, decompress_canonical, edwards_u, verify_share,
};
use timescales_core::crypto::{
    EpochSecret, ScalarSealSecret, SealSecret, domain, hash, seal, verify_digest,
};
use timescales_core::identity::ExecutorKey;
use timescales_core::{CommitmentScheme, EpochId, Hash32, MarketId, Tick};
use timescales_executor::attestation::{
    Evidence, Measurement, Platform, nonces_digest, report_data_v2,
};
use timescales_executor::tee::{
    DealtEpoch, Enclave, EpochKey, EpochKeyDealer, KeyReleaseService, LocalTeeDeployment,
    QuoteError, Quoter, ReconstructError, SealedShare, ShareRejection, TeeExecutor,
};
use timescales_executor::workload::default_params;
use timescales_executor::{ExecutorError, KeyProvider};

/// Echoes the report data as the quote.
struct EchoQuotes;

impl Quoter for EchoQuotes {
    fn quote(&self, _: Measurement, _: bool, report_data: [u8; 64]) -> Evidence {
        Evidence {
            platform: Platform::Simulated,
            quote: report_data.to_vec(),
        }
    }
}

/// A quoter whose device is gone.
struct BrokenQuotes;

impl Quoter for BrokenQuotes {
    fn quote(&self, _: Measurement, _: bool, _: [u8; 64]) -> Evidence {
        Evidence {
            platform: Platform::IntelTdx,
            quote: Vec::new(),
        }
    }

    fn try_quote(&self, _: Measurement, _: bool, _: [u8; 64]) -> Result<Evidence, QuoteError> {
        Err(QuoteError("no quote device".into()))
    }
}

fn header() -> BatchHeader {
    let params = default_params(
        timescales_core::FlowMode::DualFlow,
        CommitmentScheme::Sha256,
    );
    BatchHeader::assemble(
        params,
        EpochId(4),
        params.band(Tick(1_000)).unwrap(),
        Hash32::ZERO,
        &[],
        Hash32([1; 32]),
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
    )
}

fn enclave_with(seal: [u8; 32], signer: [u8; 32]) -> Enclave {
    Enclave::boot_with_keys(
        Arc::new(EchoQuotes),
        Measurement(Hash32([3; 32])),
        false,
        SealSecret::from_bytes(seal),
        ExecutorKey::from_seed(signer),
    )
}

#[test]
fn persisted_keys_give_the_same_identity() {
    let a = enclave_with([1; 32], [2; 32]);
    let b = enclave_with([1; 32], [2; 32]);
    assert_eq!(a.executor_id(), ExecutorKey::from_seed([2; 32]).id());
    assert_eq!(a.executor_id(), b.executor_id());
    assert_eq!(a.seal_key(), SealSecret::from_bytes([1; 32]).public());
    assert_eq!(a.measurement(), Measurement(Hash32([3; 32])));
    let fresh = Enclave::boot(Arc::new(EchoQuotes), Measurement(Hash32([3; 32])), false);
    assert_ne!(fresh.executor_id(), a.executor_id());
}

#[test]
fn typed_signatures_fix_their_domain() {
    let e = enclave_with([1; 32], [2; 32]);
    let key = e.executor_id().0;
    let bytes = b"envelope bytes before the signature";
    let sig = e.sign_rpc_envelope(bytes);
    verify_digest(&key, &hash(domain::RPC_ENVELOPE, bytes), &sig).unwrap();
    // The same bytes under any other domain do not verify.
    assert!(verify_digest(&key, &hash(domain::RECEIPT_COSIGN, bytes), &sig).is_err());

    let market = [7; 32];
    let (hd, od) = (Hash32([8; 32]), Hash32([9; 32]));
    let cosig = e.sign_cosign(&market, EpochId(4), &hd, &od);
    verify_digest(&key, &cosign_digest(&market, EpochId(4), &hd, &od), &cosig).unwrap();
    assert!(verify_digest(&key, &cosign_digest(&market, EpochId(5), &hd, &od), &cosig).is_err());
}

#[test]
fn attestation_binds_keys_header_nonces_and_committee() {
    let e = enclave_with([1; 32], [2; 32]);
    let h = header();
    let nonces = vec![Hash32([4; 32]), Hash32([5; 32])];
    let committee = Hash32([6; 32]);
    let att = e.attest_v2(&h, nonces.clone(), committee);
    let expected = report_data_v2(
        &e.seal_key(),
        &e.executor_id(),
        &h.digest(),
        &nonces_digest(&nonces),
        &committee,
    );
    assert_eq!(att.evidence.quote, expected.to_vec());
    assert_eq!(att.expected_report_data(), expected);
    assert_eq!(
        (
            att.executor,
            att.seal_key,
            att.header_digest,
            att.committee_digest
        ),
        (e.executor_id(), e.seal_key(), h.digest(), committee)
    );
    assert_eq!(e.try_attest_v2(&h, nonces, committee).unwrap(), att);
}

#[tokio::test]
async fn a_failing_quoter_is_an_attestation_error() {
    let broken = Enclave::boot(Arc::new(BrokenQuotes), Measurement(Hash32::ZERO), false);
    assert_eq!(
        broken.try_attest_v2(&header(), Vec::new(), Hash32::ZERO),
        Err(QuoteError("no quote device".into()))
    );

    let dep = LocalTeeDeployment::new(3, 2, 1);
    let committee: Vec<Arc<dyn KeyReleaseService>> = dep
        .members
        .iter()
        .map(|m| Arc::new(m.serve(broken.executor_id())) as Arc<dyn KeyReleaseService>)
        .collect();
    let h = header();
    dep.keys.publish(h.market, h.epoch, [9; 32]);
    let tee = TeeExecutor::new(
        Arc::new(broken),
        committee,
        2,
        dep.keys.clone(),
        Duration::from_secs(1),
    )
    .unwrap();
    // The batch itself is consistent. Only the quote fails.
    let mut batch = timescales_executor::ExecutionBatch {
        header: h,
        envelopes: Vec::new(),
        masked: Vec::new(),
        balances: Default::default(),
        prior_state: Default::default(),
    };
    batch.header.balances_root = batch.balances.root();
    batch.header.prior_state_root = batch.prior_state.root();
    assert!(matches!(
        tee.execute_shared(Arc::new(batch)).await,
        Err(ExecutorError::Attestation(_))
    ));
}

/// Seal `plaintext` to the enclave as member `member` would.
fn sealed(e: &Enclave, h: &BatchHeader, member: u8, plaintext: &[u8]) -> SealedShare {
    let mut info = b"key-release".to_vec();
    info.extend_from_slice(&h.market.0.to_le_bytes());
    info.extend_from_slice(&h.epoch.0.to_le_bytes());
    SealedShare {
        member,
        sealed: seal(
            &mut ChaCha20Rng::seed_from_u64(u64::from(member)),
            &e.seal_key(),
            &info,
            h.digest().as_bytes(),
            plaintext,
        )
        .unwrap(),
    }
}

fn share_plaintext(s: &ScalarShare) -> Vec<u8> {
    let mut pt = vec![s.index];
    pt.extend_from_slice(&s.value.to_bytes());
    pt
}

fn dealing(seed: u64) -> DealtEpoch {
    EpochKeyDealer {
        threshold: 3,
        members: 5,
    }
    .deal(&mut ChaCha20Rng::seed_from_u64(seed))
    .unwrap()
}

#[test]
fn reconstruction_drops_bad_shares_one_by_one() {
    let e = enclave_with([1; 32], [2; 32]);
    let h = header();
    let d = dealing(1);
    let key = EpochKey {
        epoch_pk: d.public,
        commitments: d.commitments.clone(),
    };
    let mut wrong_value = share_plaintext(&d.shares[1]);
    wrong_value[1] ^= 1;
    let mut non_canonical = vec![3];
    non_canonical.extend_from_slice(&[0xff; 32]);
    let releases = vec![
        sealed(&e, &h, 1, &share_plaintext(&d.shares[0])),
        sealed(&e, &h, 2, &wrong_value),
        sealed(&e, &h, 3, &non_canonical),
        // Member 4 claims member 5's evaluation point.
        sealed(&e, &h, 4, &share_plaintext(&d.shares[4])),
        // Sealed to another enclave.
        sealed(
            &enclave_with([9; 32], [2; 32]),
            &h,
            5,
            &share_plaintext(&d.shares[4]),
        ),
        sealed(&e, &h, 1, &share_plaintext(&d.shares[0])),
    ];
    match e.reconstruct_threshold(&h, &key, 3, &releases) {
        Err(ReconstructError::NotEnoughShares {
            usable,
            threshold,
            rejected,
        }) => {
            assert_eq!((usable, threshold), (1, 3));
            assert_eq!(
                rejected,
                vec![
                    (2, ShareRejection::Inconsistent),
                    (3, ShareRejection::NotCanonical),
                    (4, ShareRejection::WrongMember),
                    (5, ShareRejection::Unopened),
                    (1, ShareRejection::Duplicate),
                ]
            );
        }
        other => panic!("expected NotEnoughShares, got {other:?}"),
    }

    // With three honest shares among them the key comes back, from the
    // first three valid ones.
    let releases = vec![
        sealed(&e, &h, 1, &share_plaintext(&d.shares[0])),
        sealed(&e, &h, 2, &wrong_value),
        sealed(&e, &h, 3, &share_plaintext(&d.shares[2])),
        sealed(&e, &h, 4, &share_plaintext(&d.shares[3])),
        sealed(&e, &h, 5, &share_plaintext(&d.shares[4])),
    ];
    let r = e.reconstruct_threshold(&h, &key, 3, &releases).unwrap();
    assert_eq!(r.used, vec![1, 3, 4]);
    assert_eq!(r.rejected, vec![(2, ShareRejection::Inconsistent)]);
    assert_eq!(r.secret.public(), d.public);
    assert!(matches!(*r.secret, EpochSecret::Threshold(_)));
}

#[test]
fn reconstruction_stops_after_threshold_valid_shares() {
    let e = enclave_with([1; 32], [2; 32]);
    let h = header();
    let d = dealing(2);
    let key = EpochKey {
        epoch_pk: d.public,
        commitments: d.commitments.clone(),
    };
    let releases: Vec<_> = d
        .shares
        .iter()
        .map(|s| sealed(&e, &h, s.index, &share_plaintext(s)))
        .collect();
    let r = e.reconstruct_threshold(&h, &key, 3, &releases).unwrap();
    assert_eq!(r.used, vec![1, 2, 3]);
    assert!(r.rejected.is_empty());
}

#[test]
fn announcements_that_cannot_match_are_refused() {
    let e = enclave_with([1; 32], [2; 32]);
    let h = header();
    let d = dealing(3);
    let releases: Vec<_> = d
        .shares
        .iter()
        .map(|s| sealed(&e, &h, s.index, &share_plaintext(s)))
        .collect();
    // Commitments of another threshold, or not points at all.
    let short = EpochKey {
        epoch_pk: d.public,
        commitments: d.commitments[..2].to_vec(),
    };
    assert_eq!(
        e.reconstruct_threshold(&h, &short, 3, &releases)
            .unwrap_err(),
        ReconstructError::Commitments
    );
    let mut garbage = d.commitments.clone();
    garbage[1] = [0xff; 32];
    let garbage = EpochKey {
        epoch_pk: d.public,
        commitments: garbage,
    };
    assert_eq!(
        e.reconstruct_threshold(&h, &garbage, 3, &releases)
            .unwrap_err(),
        ReconstructError::Commitments
    );
    // Consistent shares of a key other than the announced one.
    let other = EpochKey {
        epoch_pk: dealing(4).public,
        commitments: d.commitments.clone(),
    };
    assert!(matches!(
        e.reconstruct_threshold(&h, &other, 3, &releases),
        Err(ReconstructError::KeyMismatch { .. })
    ));
    assert_eq!(
        e.reconstruct_threshold(
            &h,
            &EpochKey {
                epoch_pk: d.public,
                commitments: vec![]
            },
            0,
            &releases
        )
        .unwrap_err(),
        ReconstructError::Commitments
    );
}

#[test]
fn without_commitments_a_subset_search_finds_the_key() {
    let e = enclave_with([1; 32], [2; 32]);
    let h = header();
    let d = dealing(5);
    let key = EpochKey {
        epoch_pk: d.public,
        commitments: Vec::new(),
    };
    let mut releases: Vec<_> = d
        .shares
        .iter()
        .map(|s| sealed(&e, &h, s.index, &share_plaintext(s)))
        .collect();
    let mut bad = share_plaintext(&d.shares[0]);
    bad[2] ^= 1;
    releases[0] = sealed(&e, &h, 1, &bad);
    let r = e.reconstruct_threshold(&h, &key, 3, &releases).unwrap();
    assert_eq!(r.used, vec![2, 3, 4]);
    assert_eq!(r.secret.public(), d.public);
}

#[test]
fn dealt_shares_verify_and_a_given_secret_is_shared_exactly() {
    let d = dealing(6);
    let points: Vec<_> = d
        .commitments
        .iter()
        .map(|c| decompress_canonical(c).unwrap())
        .collect();
    assert!(d.shares.iter().all(|s| verify_share(s, &points)));
    assert_eq!(edwards_u(&d.commitments[0]), Some(d.public));

    let sk = SealSecret::from_bytes([0x42; 32]);
    let secret = ScalarSealSecret::from_x25519(&sk);
    let given = EpochKeyDealer {
        threshold: 2,
        members: 3,
    }
    .deal_secret(&mut ChaCha20Rng::seed_from_u64(7), &secret)
    .unwrap();
    assert_eq!(given.public, sk.public());
    assert_eq!(edwards_u(&given.commitments[0]), Some(sk.public()));
    let points: Vec<_> = given
        .commitments
        .iter()
        .map(|c| decompress_canonical(c).unwrap())
        .collect();
    assert!(given.shares.iter().all(|s| verify_share(s, &points)));
    for pair in [[0, 1], [0, 2], [1, 2]] {
        let picked: Vec<_> = pair.iter().map(|&i| given.shares[i].clone()).collect();
        assert_eq!(
            *timescales_core::crypto::threshold::lagrange_combine(&picked),
            *secret.scalar()
        );
    }
    assert!(
        EpochKeyDealer {
            threshold: 4,
            members: 3
        }
        .deal(&mut ChaCha20Rng::seed_from_u64(8))
        .is_err()
    );
}

#[test]
fn published_keys_carry_commitments_and_no_secret() {
    let dep = LocalTeeDeployment::new(3, 2, 2);
    let (m, e) = (MarketId(1), EpochId(1));
    assert!(dep.keys.epoch_public(m, e).is_err());
    let pk = dep.prepare_epoch(m, e);
    assert_eq!(dep.keys.epoch_public(m, e).unwrap(), pk);
    assert_eq!(dep.keys.epoch_commitments(m, e).unwrap().len(), 2);
    assert!(matches!(
        dep.keys.epoch_secret(m, e),
        Err(ExecutorError::KeyUnavailable(_))
    ));
}
