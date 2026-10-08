//! Report data layouts: each binds every input under its own
//! domain tag and leaves the second half of the 64 bytes zero.

use timescales_core::crypto::{Hasher, domain};
use timescales_core::{ExecutorId, Hash32};
use timescales_executor::attestation::{
    Evidence, ExecutorAttestationV2, Platform, nonces_digest, registration_report_data,
    report_data, report_data_v2,
};

const SEAL: [u8; 32] = [1; 32];
const EXECUTOR: ExecutorId = ExecutorId([2; 32]);
const HEADER: Hash32 = Hash32([3; 32]);
const NONCES: Hash32 = Hash32([4; 32]);
const COMMITTEE: Hash32 = Hash32([5; 32]);

fn first_half(rd: &[u8; 64]) -> Hash32 {
    assert_eq!(rd[32..], [0u8; 32], "second half is zero");
    let mut h = [0u8; 32];
    h.copy_from_slice(&rd[..32]);
    Hash32(h)
}

#[test]
fn v2_is_the_tagged_hash_of_its_five_inputs() {
    let rd = report_data_v2(&SEAL, &EXECUTOR, &HEADER, &NONCES, &COMMITTEE);
    let expected = Hasher::new(domain::REPORT_DATA_V2)
        .chain(&SEAL)
        .chain(EXECUTOR.as_bytes())
        .chain(HEADER.as_bytes())
        .chain(NONCES.as_bytes())
        .chain(COMMITTEE.as_bytes())
        .finalize();
    assert_eq!(first_half(&rd), expected);
}

#[test]
fn v2_binds_every_input_and_differs_from_v1() {
    let base = report_data_v2(&SEAL, &EXECUTOR, &HEADER, &NONCES, &COMMITTEE);
    let other = Hash32([9; 32]);
    for changed in [
        report_data_v2(&[9; 32], &EXECUTOR, &HEADER, &NONCES, &COMMITTEE),
        report_data_v2(&SEAL, &ExecutorId([9; 32]), &HEADER, &NONCES, &COMMITTEE),
        report_data_v2(&SEAL, &EXECUTOR, &other, &NONCES, &COMMITTEE),
        report_data_v2(&SEAL, &EXECUTOR, &HEADER, &other, &COMMITTEE),
        report_data_v2(&SEAL, &EXECUTOR, &HEADER, &NONCES, &other),
    ] {
        assert_ne!(changed, base);
    }
    assert_ne!(report_data(&SEAL, &EXECUTOR, &HEADER, &NONCES), base);
}

#[test]
fn registration_is_the_tagged_hash_of_its_inputs() {
    let program = [6; 32];
    let market = [7; 32];
    let nonce = [8; 32];
    let rd = registration_report_data(&SEAL, &EXECUTOR, &program, &market, &nonce);
    let expected = Hasher::new(domain::EXECUTOR_REGISTRATION)
        .chain(&SEAL)
        .chain(EXECUTOR.as_bytes())
        .chain(&program)
        .chain(&market)
        .chain(&nonce)
        .finalize();
    assert_eq!(first_half(&rd), expected);
    assert_ne!(
        registration_report_data(&SEAL, &EXECUTOR, &program, &[0; 32], &nonce),
        rd
    );
    assert_ne!(
        registration_report_data(&SEAL, &EXECUTOR, &program, &market, &[0; 32]),
        rd
    );
}

#[test]
fn nonces_are_bound_in_member_order() {
    let a = Hash32([1; 32]);
    let b = Hash32([2; 32]);
    assert_ne!(nonces_digest(&[a, b]), nonces_digest(&[b, a]));
    assert_ne!(nonces_digest(&[a]), nonces_digest(&[a, Hash32::ZERO]));
}

#[test]
fn attestation_expects_the_report_data_of_its_own_fields() {
    let att = ExecutorAttestationV2 {
        executor: EXECUTOR,
        seal_key: SEAL,
        header_digest: HEADER,
        nonces: vec![Hash32([1; 32]), Hash32([2; 32])],
        committee_digest: COMMITTEE,
        evidence: Evidence {
            platform: Platform::Simulated,
            quote: Vec::new(),
        },
    };
    assert_eq!(
        att.expected_report_data(),
        report_data_v2(
            &SEAL,
            &EXECUTOR,
            &HEADER,
            &nonces_digest(&att.nonces),
            &COMMITTEE
        )
    );
    let mut forged = att.clone();
    forged.committee_digest = Hash32([9; 32]);
    assert_ne!(forged.expected_report_data(), att.expected_report_data());
    assert_ne!(forged.digest(), att.digest());
}

#[test]
fn measurement_set_digest_commits_to_the_sorted_set() {
    use std::collections::BTreeSet;

    use timescales_executor::attestation::{Measurement, measurement_set_digest};

    let a = Measurement(Hash32([1; 32]));
    let b = Measurement(Hash32([2; 32]));
    let set: BTreeSet<_> = [b, a].into_iter().collect();
    let expected = Hasher::new(domain::RELEASE_POLICY)
        .chain(b"measurements")
        .chain(&2u32.to_le_bytes())
        .chain(a.0.as_bytes())
        .chain(b.0.as_bytes())
        .finalize();
    assert_eq!(measurement_set_digest(&set), expected);
    assert_ne!(measurement_set_digest(&BTreeSet::new()), expected);
}
