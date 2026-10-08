use timescales_core::crypto::{Hasher, domain};
use timescales_core::{Decode, DecodeError, Encode, Hash32};
use timescales_service::wire::{
    CommitteeDescription, CommitteeMember, MAX_COMMITTEE, ReleasePolicyStatement, WireError,
};

use crate::common::{Committee, MARKET, keypair, policy_statement};

fn invalid(c: &CommitteeDescription) -> &'static str {
    match c.validate() {
        Err(WireError::Committee(why)) => why,
        other => panic!("expected an invalid committee, got {other:?}"),
    }
}

#[test]
fn the_default_shapes_validate() {
    for (t, n) in [
        (1, 1),
        (2, 2),
        (2, 3),
        (3, 4),
        (3, 5),
        (8, 15),
        (9, 16),
        (16, 16),
    ] {
        assert!(Committee::new(t, n).desc.validate().is_ok(), "t={t} n={n}");
    }
}

#[test]
fn two_disjoint_quorums_are_refused() {
    for (t, n) in [(1, 2), (2, 4), (3, 6), (8, 16)] {
        let c = Committee::new(t, n).desc;
        assert_eq!(
            invalid(&c),
            "two disjoint quorums are possible (n > 2t - 1)",
            "t={t} n={n}"
        );
    }
}

#[test]
fn thresholds_and_sizes_are_bounded() {
    let mut c = Committee::new(2, 3).desc;
    c.threshold = 0;
    assert_eq!(invalid(&c), "threshold out of range");
    c.threshold = 4;
    assert_eq!(invalid(&c), "threshold out of range");
    let mut empty = Committee::new(1, 1).desc;
    empty.members.clear();
    assert_eq!(invalid(&empty), "threshold out of range");
    let mut big = Committee::new(16, 16).desc;
    let mut extra = big.members[15];
    extra.index = 17;
    extra.identity = keypair(200).public();
    extra.transport = [0x77; 32];
    big.members.push(extra);
    big.threshold = 16;
    assert_eq!(invalid(&big), "threshold out of range");
}

#[test]
fn member_indices_run_from_one_in_order() {
    let mut c = Committee::new(2, 3).desc;
    c.members.swap(0, 1);
    assert_eq!(invalid(&c), "member indices must be 1..=n in order");
    let mut c = Committee::new(2, 3).desc;
    c.members[0].index = 0;
    assert_eq!(invalid(&c), "member indices must be 1..=n in order");
    let mut c = Committee::new(2, 3).desc;
    c.members[2].index = 4;
    assert_eq!(invalid(&c), "member indices must be 1..=n in order");
}

#[test]
fn member_keys_are_non_zero_valid_and_distinct() {
    let mut c = Committee::new(2, 3).desc;
    c.members[1].identity = [0; 32];
    assert_eq!(invalid(&c), "zero member key");
    let mut c = Committee::new(2, 3).desc;
    c.members[1].transport = [0; 32];
    assert_eq!(invalid(&c), "zero member key");

    let mut c = Committee::new(2, 3).desc;
    let mut off_curve = [0u8; 32];
    off_curve[0] = 2;
    c.members[2].identity = off_curve;
    assert_eq!(invalid(&c), "member identity is not a valid point");
    let mut c = Committee::new(2, 3).desc;
    let mut non_canonical = [0xff; 32];
    non_canonical[0] = 0xee;
    non_canonical[31] = 0x7f;
    c.members[2].identity = non_canonical;
    assert_eq!(invalid(&c), "member identity is not a valid point");

    let mut c = Committee::new(2, 3).desc;
    c.members[2].identity = c.members[0].identity;
    assert_eq!(invalid(&c), "duplicate member key");
    let mut c = Committee::new(2, 3).desc;
    c.members[2].transport = c.members[1].transport;
    assert_eq!(invalid(&c), "duplicate member key");
    let mut c = Committee::new(2, 3).desc;
    c.members[0].transport = c.members[2].identity;
    assert_eq!(invalid(&c), "duplicate member key");
}

#[test]
fn only_version_one_validates() {
    let mut c = Committee::new(2, 3).desc;
    c.version = 2;
    assert!(matches!(c.validate(), Err(WireError::Version(2))));
}

#[test]
fn the_digest_hashes_the_encoding_under_the_committee_tag() {
    let c = Committee::new(2, 3).desc;
    let bytes = c.to_bytes();
    assert_eq!(
        c.digest(),
        Hasher::new(domain::COMMITTEE).chain(&bytes).finalize()
    );
    let mut other = c.clone();
    other.threshold = 3;
    assert_ne!(other.digest(), c.digest());
    let mut other = c.clone();
    other.market[0] ^= 1;
    assert_ne!(other.digest(), c.digest());
    let mut other = c.clone();
    other.members[1].transport[0] ^= 1;
    assert_ne!(other.digest(), c.digest());
}

#[test]
fn members_are_found_by_index() {
    let c = Committee::new(3, 5).desc;
    assert_eq!(c.member(4).map(|m| m.index), Some(4));
    assert_eq!(c.member(0), None);
    assert_eq!(c.member(6), None);
}

#[test]
fn the_committee_codec_round_trips_within_its_bounds() {
    let c = Committee::new(3, 5).desc;
    let bytes = c.to_bytes();
    assert_eq!(bytes.len(), 1 + 32 + 1 + 4 + 5 * 65);
    assert_eq!(bytes[0], CommitteeDescription::VERSION);
    assert_eq!(&bytes[1..33], &MARKET);
    assert_eq!(bytes[33], 3);
    assert_eq!(CommitteeDescription::decode_exact(&bytes), Ok(c));

    let one = Committee::new(1, 1).desc;
    assert_eq!(one.to_bytes().len(), CommitteeDescription::MIN_ENCODED_LEN);
    let full = Committee::new(16, 16).desc;
    assert_eq!(full.to_bytes().len(), 1_078);
    assert_eq!(
        CommitteeDescription::decode_exact(&full.to_bytes()),
        Ok(full)
    );
    assert_eq!(CommitteeMember::ENCODED_LEN, 65);
}

#[test]
fn the_committee_codec_refuses_bad_lengths_versions_and_trailing_bytes() {
    let c = Committee::new(2, 3).desc;
    let mut bytes = c.to_bytes();
    bytes[34..38].copy_from_slice(&(MAX_COMMITTEE as u32 + 1).to_le_bytes());
    assert_eq!(
        CommitteeDescription::decode_exact(&bytes),
        Err(DecodeError::LengthExceeded {
            len: MAX_COMMITTEE + 1,
            max: MAX_COMMITTEE
        })
    );
    let mut empty = c.to_bytes()[..38].to_vec();
    empty[34..38].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        CommitteeDescription::decode_exact(&empty),
        Err(DecodeError::InvalidValue("CommitteeDescription.members"))
    );
    let mut bytes = c.to_bytes();
    bytes[0] = 2;
    assert_eq!(
        CommitteeDescription::decode_exact(&bytes),
        Err(DecodeError::InvalidValue("CommitteeDescription.version"))
    );
    let mut bytes = c.to_bytes();
    bytes.push(0);
    assert_eq!(
        CommitteeDescription::decode_exact(&bytes),
        Err(DecodeError::TrailingBytes(1))
    );
    assert!(matches!(
        CommitteeDescription::decode_exact(&bytes[..bytes.len() - 2]),
        Err(DecodeError::UnexpectedEof { .. })
    ));
}

#[test]
fn policy_statements_are_signed_by_the_member_identity() {
    let committee = Committee::new(2, 3);
    let p = committee.policy(2);
    assert!(p.verify(&committee.identity(2).public()).is_ok());
    assert!(matches!(
        p.verify(&committee.identity(1).public()),
        Err(WireError::BadSignature)
    ));
    let bytes = p.to_bytes();
    assert_eq!(bytes.len(), ReleasePolicyStatement::ENCODED_LEN);
    assert_eq!(bytes.len(), 221);
    assert_eq!(
        p.digest(),
        Hasher::new(domain::RELEASE_POLICY)
            .chain(&bytes[..221 - 64])
            .finalize()
    );
    let mut tampered = p.clone();
    tampered.allow_debug = true;
    assert_ne!(tampered.digest(), p.digest());
    assert!(matches!(
        tampered.verify(&committee.identity(2).public()),
        Err(WireError::BadSignature)
    ));
    let mut tampered = p.clone();
    tampered.from_epoch.0 += 1;
    assert!(matches!(
        tampered.verify(&committee.identity(2).public()),
        Err(WireError::BadSignature)
    ));
}

#[test]
fn policy_statements_name_only_known_platforms() {
    let committee = Committee::new(2, 3);
    let both =
        ReleasePolicyStatement::PLATFORM_SIMULATED | ReleasePolicyStatement::PLATFORM_INTEL_TDX;
    let mut p = policy_statement(1, committee.desc.digest());
    p.platforms = both;
    let p = p.sign(committee.identity(1));
    assert!(p.verify(&committee.identity(1).public()).is_ok());
    assert_eq!(
        ReleasePolicyStatement::decode_exact(&p.to_bytes()),
        Ok(p.clone())
    );

    let mut odd = policy_statement(1, committee.desc.digest());
    odd.platforms = 4;
    let odd = odd.sign(committee.identity(1));
    assert!(matches!(
        odd.verify(&committee.identity(1).public()),
        Err(WireError::Policy("unknown platform bits"))
    ));
    assert_eq!(
        ReleasePolicyStatement::decode_exact(&odd.to_bytes()),
        Err(DecodeError::InvalidValue(
            "ReleasePolicyStatement.platforms"
        ))
    );
}

#[test]
fn the_policy_codec_round_trips_and_refuses_bad_bools_versions_and_trailing_bytes() {
    let committee = Committee::new(2, 3);
    let p = committee.policy(3);
    let bytes = p.to_bytes();
    assert_eq!(ReleasePolicyStatement::decode_exact(&bytes), Ok(p.clone()));

    // allow_debug follows version, market, member, committee digest,
    // platforms and the measurement set digest.
    let debug_at = 1 + 32 + 1 + 32 + 1 + 32;
    let mut bad = bytes.clone();
    bad[debug_at] = 2;
    assert_eq!(
        ReleasePolicyStatement::decode_exact(&bad),
        Err(DecodeError::InvalidTag { ty: "bool", tag: 2 })
    );
    let mut bad = bytes.clone();
    bad[0] = 0;
    assert_eq!(
        ReleasePolicyStatement::decode_exact(&bad),
        Err(DecodeError::InvalidValue("ReleasePolicyStatement.version"))
    );
    let mut v2 = p.clone();
    v2.version = 2;
    assert!(matches!(
        v2.verify(&committee.identity(3).public()),
        Err(WireError::Version(2))
    ));
    let mut long = bytes.clone();
    long.push(1);
    assert_eq!(
        ReleasePolicyStatement::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
    assert!(matches!(
        ReleasePolicyStatement::decode_exact(&bytes[..220]),
        Err(DecodeError::UnexpectedEof { .. })
    ));
}

#[test]
fn signing_a_statement_keeps_its_fields() {
    let committee = Committee::new(2, 3);
    let unsigned = policy_statement(2, Hash32([1; 32]));
    let signed = unsigned.clone().sign(committee.identity(2));
    assert_eq!(signed.digest(), unsigned.digest());
    assert_eq!(
        ReleasePolicyStatement {
            signature: unsigned.signature,
            ..signed
        },
        unsigned
    );
}
