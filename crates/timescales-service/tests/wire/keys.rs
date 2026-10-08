use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use timescales_core::crypto::threshold::ScalarShare;
use timescales_core::crypto::{Hasher, SealSecret, SealedBox, domain, seal};
use timescales_core::{Decode, DecodeError, Encode, EpochId, Hash32};
use timescales_executor::tee::codec::SHARE_CIPHERTEXT_LEN;
use timescales_service::wire::{
    AnnouncementQuery, AnnouncementReply, EpochKeyAck, EpochKeyAnnouncement, EpochKeyBundle,
    KeyScheme, MAX_COMMITTEE, ShareDelivery, WireError, ack_digest,
};

use crate::common::{Committee, Dealing, EPOCH, MARKET, rng, share_matches};

fn feldman(t: u8, n: u8) -> (Committee, Dealing, EpochKeyAnnouncement) {
    let committee = Committee::new(t, n);
    let dealing = Dealing::new(u64::from(t) * 31 + u64::from(n), t);
    let ann = dealing.announcement(&committee.desc);
    (committee, dealing, ann)
}

fn dev_announcement(committee: &Committee) -> EpochKeyAnnouncement {
    EpochKeyAnnouncement {
        version: EpochKeyAnnouncement::VERSION,
        market: MARKET,
        epoch: EPOCH,
        committee_digest: committee.desc.digest(),
        scheme: KeyScheme::DevX25519,
        epoch_pk: SealSecret::generate(&mut rng(5)).public(),
        commitments: Vec::new(),
    }
}

fn digests(c: &Committee) -> Vec<Hash32> {
    vec![c.desc.digest()]
}

#[test]
fn feldman_announcements_pass_the_structure_check() {
    for (t, n) in [(1, 1), (2, 3), (3, 5), (16, 16)] {
        let (committee, _, ann) = feldman(t, n);
        assert!(ann.check_structure(committee.desc.threshold, false).is_ok());
    }
}

#[test]
fn the_commitment_count_is_the_threshold() {
    let (_, _, ann) = feldman(2, 3);
    for t in [0u8, 1, 3] {
        assert!(matches!(
            ann.check_structure(t, false),
            Err(WireError::Committee(
                "commitment count differs from the threshold"
            ))
        ));
    }
}

#[test]
fn every_commitment_must_be_a_canonical_point() {
    let (_, _, ann) = feldman(3, 5);
    // y = 2 has no x on the curve.
    let mut y2 = [0u8; 32];
    y2[0] = 2;
    // x = 0 with the sign bit set, a non-canonical encoding of (0, 1).
    let mut negative_zero = [0u8; 32];
    negative_zero[0] = 1;
    negative_zero[31] = 0x80;
    for (at, bytes) in [(2, y2), (1, negative_zero), (0, negative_zero)] {
        let mut bad = ann.clone();
        bad.commitments[at] = bytes;
        assert!(matches!(
            bad.check_structure(3, false),
            Err(WireError::BadPoint("commitment is not a canonical point"))
        ));
    }
    assert!(CompressedEdwardsY(negative_zero).decompress().is_some());
}

#[test]
fn c0_must_be_in_the_prime_order_subgroup_and_not_the_identity() {
    let (_, dealing, ann) = feldman(2, 3);
    let c0 = dealing.coefficients[0] * ED25519_BASEPOINT_POINT;

    let mut torsion = ann.clone();
    let mixed = c0 + EIGHT_TORSION[1];
    torsion.commitments[0] = mixed.compress().to_bytes();
    // Even with epoch_pk matching u of the mixed point.
    torsion.epoch_pk = mixed.to_montgomery().to_bytes();
    assert!(matches!(
        torsion.check_structure(2, false),
        Err(WireError::BadPoint(
            "C_0 is the identity or has a torsion component"
        ))
    ));

    let mut identity = ann.clone();
    identity.commitments[0] = EdwardsPoint::default().compress().to_bytes();
    assert!(matches!(
        identity.check_structure(2, false),
        Err(WireError::BadPoint(
            "C_0 is the identity or has a torsion component"
        ))
    ));
}

#[test]
fn later_commitments_must_be_prime_order_points_too() {
    let (_, _, ann) = feldman(3, 5);
    let identity = EdwardsPoint::default().compress().to_bytes();
    let c1 = CompressedEdwardsY(ann.commitments[1]).decompress().unwrap();
    let mixed = (c1 + EIGHT_TORSION[2]).compress().to_bytes();
    let order_two = EIGHT_TORSION[4].compress().to_bytes();
    // An identity leading commitment lowers the degree of the polynomial.
    for (at, bytes) in [(2, identity), (1, identity), (1, mixed), (2, order_two)] {
        let mut bad = ann.clone();
        bad.commitments[at] = bytes;
        assert!(matches!(
            bad.check_structure(3, false),
            Err(WireError::BadPoint(
                "commitment is the identity or has a torsion component"
            ))
        ));
    }
}

#[test]
fn the_epoch_key_must_be_u_of_c0() {
    let (_, _, ann) = feldman(2, 3);
    let mut wrong = ann.clone();
    wrong.epoch_pk[0] ^= 1;
    assert!(matches!(
        wrong.check_structure(2, false),
        Err(WireError::BadPoint("epoch_pk is not u(C_0)"))
    ));
    let mut swapped = ann.clone();
    swapped.commitments.swap(0, 1);
    assert!(matches!(
        swapped.check_structure(2, false),
        Err(WireError::BadPoint("epoch_pk is not u(C_0)"))
    ));
}

#[test]
fn dev_keys_are_accepted_only_where_simulation_is() {
    let committee = Committee::new(2, 3);
    let dev = dev_announcement(&committee);
    assert!(matches!(
        dev.check_structure(2, false),
        Err(WireError::Scheme)
    ));
    assert!(dev.check_structure(2, true).is_ok());
    let mut with_commitments = dev.clone();
    with_commitments.commitments = Dealing::new(1, 2).commitments();
    assert!(matches!(
        with_commitments.check_structure(2, true),
        Err(WireError::Committee(
            "dev announcements carry no commitments"
        ))
    ));
    let mut v2 = dev;
    v2.version = 2;
    assert!(matches!(
        v2.check_structure(2, true),
        Err(WireError::Version(2))
    ));
}

#[test]
fn the_announcement_digest_hashes_its_encoding() {
    let (_, _, ann) = feldman(3, 5);
    let bytes = ann.to_bytes();
    assert_eq!(bytes.len(), 1 + 32 + 8 + 32 + 1 + 32 + 4 + 3 * 32);
    assert_eq!(
        ann.digest(),
        Hasher::new(domain::EPOCH_KEY).chain(&bytes).finalize()
    );
}

#[test]
fn the_announcement_codec_round_trips_within_its_bounds() {
    let (_, _, ann) = feldman(3, 5);
    assert_eq!(
        EpochKeyAnnouncement::decode_exact(&ann.to_bytes()),
        Ok(ann.clone())
    );
    let (_, _, full) = feldman(16, 16);
    assert_eq!(full.to_bytes().len(), 622);
    assert_eq!(
        EpochKeyAnnouncement::decode_exact(&full.to_bytes()),
        Ok(full)
    );
    let dev = dev_announcement(&Committee::new(2, 3));
    assert_eq!(dev.to_bytes().len(), EpochKeyAnnouncement::MIN_ENCODED_LEN);
    assert_eq!(EpochKeyAnnouncement::decode_exact(&dev.to_bytes()), Ok(dev));

    let count_at = 1 + 32 + 8 + 32 + 1 + 32;
    let mut bytes = ann.to_bytes();
    bytes[count_at..count_at + 4].copy_from_slice(&(MAX_COMMITTEE as u32 + 1).to_le_bytes());
    assert_eq!(
        EpochKeyAnnouncement::decode_exact(&bytes),
        Err(DecodeError::LengthExceeded {
            len: MAX_COMMITTEE + 1,
            max: MAX_COMMITTEE
        })
    );
    let scheme_at = 1 + 32 + 8 + 32;
    let mut bytes = ann.to_bytes();
    bytes[scheme_at] = 2;
    assert_eq!(
        EpochKeyAnnouncement::decode_exact(&bytes),
        Err(DecodeError::InvalidTag {
            ty: "KeyScheme",
            tag: 2
        })
    );
    let mut bytes = ann.to_bytes();
    bytes[0] = 2;
    assert_eq!(
        EpochKeyAnnouncement::decode_exact(&bytes),
        Err(DecodeError::InvalidValue("EpochKeyAnnouncement.version"))
    );
    let mut bytes = ann.to_bytes();
    bytes.push(0);
    assert_eq!(
        EpochKeyAnnouncement::decode_exact(&bytes),
        Err(DecodeError::TrailingBytes(1))
    );
}

#[test]
fn acks_sign_the_announcement_and_the_policy_digest() {
    let (committee, _, ann) = feldman(2, 3);
    let policy = committee.policy(1).digest();
    let ack = EpochKeyAck::sign(1, &ann.digest(), policy, committee.identity(1));
    assert_eq!(
        ack_digest(&ann.digest(), &policy),
        Hasher::new(domain::EPOCH_KEY_ACK)
            .chain(ann.digest().as_bytes())
            .chain(policy.as_bytes())
            .finalize()
    );
    assert!(
        ack.verify(&ann.digest(), &committee.identity(1).public())
            .is_ok()
    );
    assert!(matches!(
        ack.verify(&Hash32([0; 32]), &committee.identity(1).public()),
        Err(WireError::BadSignature)
    ));
    let mut other_policy = ack;
    other_policy.policy_digest = committee.policy(2).digest();
    assert!(matches!(
        other_policy.verify(&ann.digest(), &committee.identity(1).public()),
        Err(WireError::BadSignature)
    ));

    let bytes = ack.to_bytes();
    assert_eq!(bytes.len(), EpochKeyAck::ENCODED_LEN);
    assert_eq!(bytes.len(), 97);
    assert_eq!(EpochKeyAck::decode_exact(&bytes), Ok(ack));
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        EpochKeyAck::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
}

#[test]
fn a_bundle_with_t_valid_acks_yields_the_key_and_the_policies() {
    let (committee, dealing, ann) = feldman(3, 5);
    for acked in [vec![1u8, 3, 5], vec![1, 2, 3, 4, 5], vec![2, 4, 5]] {
        let bundle = committee.bundle(&ann, &acked);
        let (pk, policies) = bundle
            .verify(&committee.desc, &digests(&committee), false)
            .unwrap();
        assert_eq!(pk, dealing.epoch_pk());
        let expected: Vec<(u8, Hash32)> = acked
            .iter()
            .map(|m| (*m, committee.policy(*m).digest()))
            .collect();
        assert_eq!(policies, expected);
    }
}

#[test]
fn fewer_than_t_acks_are_not_enough() {
    let (committee, _, ann) = feldman(3, 5);
    let bundle = committee.bundle(&ann, &[2, 4]);
    assert!(matches!(
        bundle.verify(&committee.desc, &digests(&committee), false),
        Err(WireError::Threshold { got: 2, need: 3 })
    ));
}

#[test]
fn the_committee_must_be_the_announced_and_anchored_one() {
    let (committee, _, ann) = feldman(2, 3);
    let bundle = committee.bundle(&ann, &[1, 2]);
    let other = Committee::new(2, 3);
    let mut other_desc = other.desc.clone();
    other_desc.members[0].transport[0] ^= 1;
    assert!(matches!(
        bundle.verify(&other_desc, &[other_desc.digest()], false),
        Err(WireError::CommitteeMismatch)
    ));
    assert!(matches!(
        bundle.verify(&committee.desc, &[Hash32([9; 32])], false),
        Err(WireError::CommitteeMismatch)
    ));
    // The previous committee digest on chain is accepted too.
    assert!(
        bundle
            .verify(
                &committee.desc,
                &[Hash32([9; 32]), committee.desc.digest()],
                false
            )
            .is_ok()
    );

    let mut elsewhere = committee.desc.clone();
    elsewhere.market[0] ^= 1;
    let ann_elsewhere = EpochKeyAnnouncement {
        committee_digest: elsewhere.digest(),
        ..ann.clone()
    };
    let bundle = committee.bundle(&ann_elsewhere, &[1, 2]);
    assert!(matches!(
        bundle.verify(&elsewhere, &[elsewhere.digest()], false),
        Err(WireError::CommitteeMismatch)
    ));
}

#[test]
fn an_invalid_committee_never_verifies_a_bundle() {
    let (committee, _, ann) = feldman(2, 3);
    let mut loose = committee.desc.clone();
    loose.threshold = 1;
    let ann = EpochKeyAnnouncement {
        committee_digest: loose.digest(),
        commitments: ann.commitments[..1].to_vec(),
        ..ann
    };
    let bundle = committee.bundle(&ann, &[1]);
    assert!(matches!(
        bundle.verify(&loose, &[loose.digest()], false),
        Err(WireError::Committee(_))
    ));
}

#[test]
fn acks_must_come_from_members_with_valid_signatures() {
    let (committee, _, ann) = feldman(2, 3);
    let mut unknown = committee.bundle(&ann, &[1, 2]);
    unknown.acks[1].member = 7;
    assert!(matches!(
        unknown.verify(&committee.desc, &digests(&committee), false),
        Err(WireError::UnknownMember(7))
    ));
    let mut forged = committee.bundle(&ann, &[1, 2]);
    forged.acks[1] = EpochKeyAck::sign(
        2,
        &ann.digest(),
        committee.policy(2).digest(),
        committee.identity(3),
    );
    assert!(matches!(
        forged.verify(&committee.desc, &digests(&committee), false),
        Err(WireError::BadSignature)
    ));
    // One bad ack spoils the bundle even with t good ones beside it.
    let mut spoiled = committee.bundle(&ann, &[1, 2, 3]);
    spoiled.acks[2].signature.0[0] ^= 1;
    assert!(matches!(
        spoiled.verify(&committee.desc, &digests(&committee), false),
        Err(WireError::BadSignature)
    ));
    let mut other_ann = committee.bundle(&ann, &[1, 2]);
    other_ann.acks[0] = EpochKeyAck::sign(
        1,
        &Hash32([1; 32]),
        committee.policy(1).digest(),
        committee.identity(1),
    );
    assert!(matches!(
        other_ann.verify(&committee.desc, &digests(&committee), false),
        Err(WireError::BadSignature)
    ));
}

#[test]
fn acks_are_distinct_and_ordered_by_member() {
    let (committee, _, ann) = feldman(2, 3);
    let duplicate = committee.bundle(&ann, &[2, 2]);
    assert!(matches!(
        duplicate.verify(&committee.desc, &digests(&committee), false),
        Err(WireError::Committee(
            "acks are not in increasing member order"
        ))
    ));
    let unordered = committee.bundle(&ann, &[3, 1]);
    assert!(matches!(
        unordered.verify(&committee.desc, &digests(&committee), false),
        Err(WireError::Committee(
            "acks are not in increasing member order"
        ))
    ));
    assert_eq!(
        EpochKeyBundle::decode_exact(&unordered.to_bytes()),
        Err(DecodeError::InvalidValue("EpochKeyBundle.acks"))
    );
    assert_eq!(
        EpochKeyBundle::decode_exact(&duplicate.to_bytes()),
        Err(DecodeError::InvalidValue("EpochKeyBundle.acks"))
    );
}

#[test]
fn an_ack_under_a_foreign_policy_digest_is_reported_as_signed() {
    let (committee, _, ann) = feldman(2, 3);
    let mut bundle = committee.bundle(&ann, &[1, 2]);
    // Member 2 vouches under member 3's statement. The bundle verifies, and
    // the caller sees which policy each member named.
    let foreign = committee.policy(3).digest();
    bundle.acks[1] = EpochKeyAck::sign(2, &ann.digest(), foreign, committee.identity(2));
    let (_, policies) = bundle
        .verify(&committee.desc, &digests(&committee), false)
        .unwrap();
    assert_eq!(policies[1], (2, foreign));
    assert_ne!(policies[1].1, committee.policy(2).digest());
}

#[test]
fn dev_bundles_verify_only_when_allowed() {
    let committee = Committee::new(2, 3);
    let dev = dev_announcement(&committee);
    let bundle = committee.bundle(&dev, &[1, 3]);
    assert!(matches!(
        bundle.verify(&committee.desc, &digests(&committee), false),
        Err(WireError::Scheme)
    ));
    let (pk, _) = bundle
        .verify(&committee.desc, &digests(&committee), true)
        .unwrap();
    assert_eq!(pk, dev.epoch_pk);
}

#[test]
fn the_bundle_codec_round_trips_within_its_bounds() {
    let (committee, _, ann) = feldman(3, 5);
    let bundle = committee.bundle(&ann, &[1, 2, 5]);
    assert_eq!(
        EpochKeyBundle::decode_exact(&bundle.to_bytes()),
        Ok(bundle.clone())
    );

    let (full_committee, _, full_ann) = feldman(16, 16);
    let members: Vec<u8> = (1..=16).collect();
    let full = full_committee.bundle(&full_ann, &members);
    assert_eq!(full.to_bytes().len(), 2_178);
    assert_eq!(EpochKeyBundle::decode_exact(&full.to_bytes()), Ok(full));

    let ack_count_at = ann.to_bytes().len();
    let mut bytes = bundle.to_bytes();
    bytes[ack_count_at..ack_count_at + 4]
        .copy_from_slice(&(MAX_COMMITTEE as u32 + 1).to_le_bytes());
    assert!(matches!(
        EpochKeyBundle::decode_exact(&bytes),
        Err(DecodeError::LengthExceeded { .. })
    ));
    let mut bytes = bundle.to_bytes();
    bytes.push(0);
    assert_eq!(
        EpochKeyBundle::decode_exact(&bytes),
        Err(DecodeError::TrailingBytes(1))
    );
    let dev = EpochKeyBundle {
        announcement: dev_announcement(&committee),
        acks: Vec::new(),
    };
    assert_eq!(dev.to_bytes().len(), EpochKeyBundle::MIN_ENCODED_LEN);
}

#[test]
fn a_share_delivery_opens_only_for_its_member() {
    let (committee, dealing, ann) = feldman(3, 5);
    let mut r = rng(77);
    for m in 1..=5u8 {
        let share = dealing.share(m);
        let d = ShareDelivery::seal(
            &mut r,
            ann.clone(),
            &committee.desc.members[usize::from(m) - 1],
            &share,
        )
        .unwrap();
        assert_eq!(d.member, m);
        assert_eq!(d.sealed.ciphertext.len(), SHARE_CIPHERTEXT_LEN);
        let opened = d.open(committee.transport(m)).unwrap();
        assert_eq!(opened.index, m);
        assert_eq!(opened.value, share.value);
        assert!(share_matches(&opened, &ann.commitments));
        let other = if m == 1 { 2 } else { 1 };
        assert!(matches!(
            d.open(committee.transport(other)),
            Err(WireError::Decode(DecodeError::InvalidValue(
                "ShareDelivery.sealed"
            )))
        ));
    }
}

#[test]
fn a_share_delivery_is_bound_to_its_announcement_and_member() {
    let (committee, dealing, ann) = feldman(2, 3);
    let d = ShareDelivery::seal(
        &mut rng(1),
        ann.clone(),
        &committee.desc.members[1],
        &dealing.share(2),
    )
    .unwrap();
    let sealed_err = |d: &ShareDelivery, m: u8| {
        matches!(
            d.open(committee.transport(m)),
            Err(WireError::Decode(DecodeError::InvalidValue(
                "ShareDelivery.sealed"
            )))
        )
    };
    let mut later = d.clone();
    later.announcement.epoch = EpochId(EPOCH.0 + 1);
    assert!(sealed_err(&later, 2));
    let mut rekeyed = d.clone();
    rekeyed.announcement.epoch_pk[0] ^= 1;
    assert!(sealed_err(&rekeyed, 2));
    let mut relabelled = d.clone();
    relabelled.member = 3;
    assert!(sealed_err(&relabelled, 2));
    let mut flipped = d.clone();
    flipped.sealed.ciphertext[0] ^= 1;
    assert!(sealed_err(&flipped, 2));
}

#[test]
fn a_share_is_sealed_only_to_its_own_member() {
    let (committee, dealing, ann) = feldman(2, 3);
    assert!(matches!(
        ShareDelivery::seal(
            &mut rng(1),
            ann.clone(),
            &committee.desc.members[0],
            &dealing.share(2)
        ),
        Err(WireError::UnknownMember(2))
    ));
    let zero = ScalarShare {
        index: 0,
        value: dealing.share(1).value,
    };
    let mut member_zero = committee.desc.members[0];
    member_zero.index = 0;
    assert!(matches!(
        ShareDelivery::seal(&mut rng(1), ann.clone(), &member_zero, &zero),
        Err(WireError::UnknownMember(0))
    ));
    let mut low_order = committee.desc.members[0];
    low_order.transport = [0; 32];
    assert!(matches!(
        ShareDelivery::seal(&mut rng(1), ann, &low_order, &dealing.share(1)),
        Err(WireError::BadPoint("member transport key"))
    ));
}

/// A box the dealer could have sealed, with an arbitrary plaintext.
fn sealed_plaintext(
    committee: &Committee,
    ann: &EpochKeyAnnouncement,
    member: u8,
    pt: &[u8],
) -> ShareDelivery {
    let mut info = domain::KRC_SHARE.to_vec();
    info.extend_from_slice(&ann.market);
    info.extend_from_slice(&ann.epoch.0.to_le_bytes());
    info.push(member);
    let to = committee.transport(member).public();
    ShareDelivery {
        announcement: ann.clone(),
        member,
        sealed: seal(&mut rng(3), &to, &info, ann.digest().as_bytes(), pt).unwrap(),
    }
}

#[test]
fn share_plaintexts_are_checked() {
    let (committee, dealing, ann) = feldman(2, 3);
    let mut pt = vec![2u8];
    pt.extend_from_slice(dealing.share(2).value.as_bytes());
    let good = sealed_plaintext(&committee, &ann, 2, &pt);
    assert_eq!(
        good.open(committee.transport(2)).unwrap().value,
        dealing.share(2).value
    );

    let mut other_index = pt.clone();
    other_index[0] = 3;
    assert!(matches!(
        sealed_plaintext(&committee, &ann, 2, &other_index).open(committee.transport(2)),
        Err(WireError::UnknownMember(3))
    ));
    let mut not_reduced = vec![2u8];
    not_reduced.extend_from_slice(&[0xff; 32]);
    assert!(matches!(
        sealed_plaintext(&committee, &ann, 2, &not_reduced).open(committee.transport(2)),
        Err(WireError::Decode(DecodeError::InvalidValue(
            "ShareDelivery plaintext"
        )))
    ));
    assert!(matches!(
        sealed_plaintext(&committee, &ann, 2, &pt[..32]).open(committee.transport(2)),
        Err(WireError::Decode(DecodeError::InvalidValue(
            "ShareDelivery plaintext"
        )))
    ));
    assert!(matches!(
        sealed_plaintext(&committee, &ann, 2, &[]).open(committee.transport(2)),
        Err(WireError::Decode(DecodeError::InvalidValue(
            "ShareDelivery plaintext"
        )))
    ));
}

#[test]
fn the_share_delivery_codec_round_trips_within_its_bounds() {
    let (committee, dealing, ann) = feldman(3, 5);
    let d = ShareDelivery::seal(
        &mut rng(2),
        ann,
        &committee.desc.members[2],
        &dealing.share(3),
    )
    .unwrap();
    let bytes = d.to_bytes();
    assert_eq!(ShareDelivery::decode_exact(&bytes), Ok(d.clone()));
    let decoded = ShareDelivery::decode_exact(&bytes).unwrap();
    assert_eq!(
        decoded.open(committee.transport(3)).unwrap().value,
        dealing.share(3).value
    );

    let (full_committee, full_dealing, full_ann) = feldman(16, 16);
    let full = ShareDelivery::seal(
        &mut rng(2),
        full_ann,
        &full_committee.desc.members[15],
        &full_dealing.share(16),
    )
    .unwrap();
    assert_eq!(full.to_bytes().len(), 708);

    for len in [16, SHARE_CIPHERTEXT_LEN - 1, SHARE_CIPHERTEXT_LEN + 1] {
        let odd = ShareDelivery {
            sealed: SealedBox {
                ephemeral: d.sealed.ephemeral,
                ciphertext: vec![0; len],
            },
            ..d.clone()
        };
        assert_eq!(
            ShareDelivery::decode_exact(&odd.to_bytes()),
            Err(DecodeError::InvalidValue("ShareDelivery.sealed"))
        );
    }
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        ShareDelivery::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
    let dev = ShareDelivery {
        announcement: dev_announcement(&committee),
        ..d
    };
    assert_eq!(dev.to_bytes().len(), ShareDelivery::MIN_ENCODED_LEN);
}

#[test]
fn announcement_queries_and_replies_round_trip() {
    let q = AnnouncementQuery {
        market: MARKET,
        epoch: EPOCH,
    };
    assert_eq!(q.to_bytes().len(), AnnouncementQuery::ENCODED_LEN);
    assert_eq!(q.to_bytes().len(), 40);
    assert_eq!(AnnouncementQuery::decode_exact(&q.to_bytes()), Ok(q));
    let mut long = q.to_bytes();
    long.push(0);
    assert_eq!(
        AnnouncementQuery::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );

    let none = AnnouncementReply(None);
    assert_eq!(none.to_bytes(), vec![0]);
    assert_eq!(AnnouncementReply::decode_exact(&[0]), Ok(none));

    let (committee, _, ann) = feldman(16, 16);
    let ack = EpochKeyAck::sign(
        4,
        &ann.digest(),
        committee.policy(4).digest(),
        committee.identity(4),
    );
    let some = AnnouncementReply(Some((ann, ack)));
    let bytes = some.to_bytes();
    assert_eq!(bytes.len(), 720);
    assert_eq!(AnnouncementReply::decode_exact(&bytes), Ok(some));

    let mut bad = bytes.clone();
    bad[0] = 2;
    assert_eq!(
        AnnouncementReply::decode_exact(&bad),
        Err(DecodeError::InvalidTag { ty: "bool", tag: 2 })
    );
    assert_eq!(
        AnnouncementReply::decode_exact(&[0, 0]),
        Err(DecodeError::TrailingBytes(1))
    );
    assert!(matches!(
        AnnouncementReply::decode_exact(&bytes[..bytes.len() - 1]),
        Err(DecodeError::UnexpectedEof { .. })
    ));
}
