//! Every decoder against its own encoder. A sample of each message
//! round-trips. Every truncation and a trailing byte are refused. Mutated,
//! spliced and random bytes never panic, and whatever they decode to encodes
//! back to exactly those bytes, so each value has one encoding.

use std::sync::LazyLock;

use proptest::prelude::*;
use proptest::sample::Index;
use timescales_core::crypto::{SealedBox, Signature};
use timescales_core::{Decode, DecodeError, Encode, ExecutorId, Hash32, Tick};
use timescales_executor::attestation::{Evidence, ExecutorAttestationV2, Platform};
use timescales_executor::tee::{ReleaseError, SealedShare};
use timescales_service::wire::{
    AnnouncementFields, AnnouncementQuery, AnnouncementReply, ChallengeRequest, ChallengeResponse,
    CommitteeDescription, EnclaveRefusal, EpochAnnouncement, EpochKeyAck, EpochKeyAnnouncement,
    EpochKeyBundle, ErrorResponse, ExecutePosted, ExecuteReady, ExecuteRequest, GrantRecord,
    MessageKind, PostedTx, Provenance, ProvenanceEntry, PublishRequest, RelayRefusal,
    ReleasePolicyStatement, ReleaseRefusal, ReleaseRequest, ReleaseResponse, ShareDelivery,
    SignedEnvelope,
};

use crate::common::{Committee, Dealing, EPOCH, MARKET, envelope, header_v2, keypair, params, rng};
use crate::execute::{posted, provenance, request};
use crate::release::share;

type Recode = fn(&[u8]) -> Result<Vec<u8>, DecodeError>;

fn recode<T: Encode + Decode>(bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {
    T::decode_exact(bytes).map(|v| v.to_bytes())
}

struct Case {
    name: &'static str,
    bytes: Vec<u8>,
    recode: Recode,
}

fn case<T: Encode + Decode>(name: &'static str, value: &T) -> Case {
    Case {
        name,
        bytes: value.to_bytes(),
        recode: recode::<T>,
    }
}

fn cases() -> Vec<Case> {
    let committee = Committee::new(2, 3);
    let dealing = Dealing::new(5, 2);
    let ann = dealing.announcement(&committee.desc);
    let ack = EpochKeyAck::sign(
        2,
        &ann.digest(),
        committee.policy(2).digest(),
        committee.identity(2),
    );
    let delivery = ShareDelivery::seal(
        &mut rng(9),
        ann.clone(),
        &committee.desc.members[0],
        &dealing.share(1),
    )
    .unwrap();
    let header = header_v2(&[envelope(1), envelope(2)], Hash32([0x0b; 32]));
    let attestation = ExecutorAttestationV2 {
        executor: ExecutorId([1; 32]),
        seal_key: [2; 32],
        header_digest: header.digest(),
        nonces: vec![Hash32([3; 32]); 3],
        committee_digest: committee.desc.digest(),
        evidence: Evidence {
            platform: Platform::IntelTdx,
            quote: vec![4; 40],
        },
    };
    let release: ReleaseRequest = ReleaseRequest {
        header,
        price_commitment: Hash32([5; 32]),
        attestation: attestation.clone(),
    };
    let announcement = EpochAnnouncement::sign(
        AnnouncementFields {
            market: MARKET,
            epoch: EPOCH,
            opens_at_ms: 1_800_000_000_000,
            cutoff_ms: 1_800_000_002_000,
            band: params().band(Tick(1_000)).unwrap(),
            price_commitment: Hash32([6; 32]),
            key_digest: ann.digest(),
            committee_digest: committee.desc.digest(),
        },
        &keypair(11),
    );
    let envelope_sample = SignedEnvelope::seal(
        MessageKind::ReleaseResponse,
        &keypair(1),
        keypair(2).public(),
        1_800_000_000_000,
        &mut rng(3),
        ReleaseResponse::Share(share()).to_bytes(),
    );

    vec![
        case("SignedEnvelope", &envelope_sample),
        case::<CommitteeDescription>("CommitteeDescription", &committee.desc),
        case::<ReleasePolicyStatement>("ReleasePolicyStatement", &committee.policy(1)),
        case::<EpochKeyAnnouncement>("EpochKeyAnnouncement", &ann),
        case("EpochKeyAck", &ack),
        case::<EpochKeyBundle>("EpochKeyBundle", &committee.bundle(&ann, &[1, 3])),
        case("ShareDelivery", &delivery),
        case(
            "AnnouncementQuery",
            &AnnouncementQuery {
                market: MARKET,
                epoch: EPOCH,
            },
        ),
        case("AnnouncementReply", &AnnouncementReply(Some((ann, ack)))),
        case("AnnouncementReply (none)", &AnnouncementReply(None)),
        case(
            "ChallengeRequest",
            &ChallengeRequest {
                market: MARKET,
                epoch: EPOCH,
                executor: ExecutorId([7; 32]),
            },
        ),
        case(
            "ChallengeResponse",
            &ChallengeResponse {
                member: 2,
                market: MARKET,
                epoch: EPOCH,
                nonce: Hash32([8; 32]),
                expires_at_ms: 1_800_000_060_000,
            },
        ),
        case::<ReleaseRequest>("ReleaseRequest", &release),
        case::<ExecutorAttestationV2>("ExecutorAttestationV2", &attestation),
        case("ReleaseResponse (share)", &ReleaseResponse::Share(share())),
        case(
            "ReleaseResponse (refused)",
            &ReleaseResponse::refused(ReleaseRefusal::HeaderPinned, "pinned"),
        ),
        case::<SealedShare>("SealedShare", &share()),
        case::<SealedBox>("SealedBox", &share().sealed),
        case(
            "ReleaseError",
            &ReleaseError::Attestation(
                timescales_executor::attestation::AttestationError::CollateralExpired {
                    expires_at: 1_752_920_163,
                    now: 1_752_920_164,
                },
            ),
        ),
        case::<Provenance>("Provenance", &provenance(4, 2)),
        case::<GrantRecord>("GrantRecord", &provenance(1, 1).grants[0]),
        case(
            "ProvenanceEntry",
            &ProvenanceEntry {
                grant: ProvenanceEntry::NO_GRANT,
                session_signature: Signature([9; 64]),
            },
        ),
        case::<ExecuteRequest>("ExecuteRequest", &request(3)),
        case(
            "ExecuteReady",
            &ExecuteReady {
                executor: ExecutorId([1; 32]),
                header_digest: Hash32([2; 32]),
                outcome_digest: Hash32([3; 32]),
                cosign: Signature([4; 64]),
                unauthenticated: vec![0, 2],
            },
        ),
        case(
            "PublishRequest",
            &PublishRequest {
                market: MARKET,
                epoch: EPOCH,
                header_digest: Hash32([5; 32]),
                cosigs: vec![(ExecutorId([6; 32]), Signature([7; 64]))],
            },
        ),
        case(
            "PostedTx",
            &PostedTx {
                signature: [8; 64],
                slot: 9,
            },
        ),
        case::<ExecutePosted>("ExecutePosted", &posted(2, 1, 40)),
        case(
            "ErrorResponse",
            &ErrorResponse::refused(EnclaveRefusal::BalanceMismatch, "2 traders"),
        ),
        case(
            "ErrorResponse (outcome mismatch)",
            &ErrorResponse::outcome_mismatch(posted(1, 0, 0).receipt, "another outcome"),
        ),
        case("EpochAnnouncement", &announcement),
        case(
            "RelayRefusal",
            &RelayRefusal::sign(MARKET, EPOCH, envelope(3).digest(), 2, 7, &keypair(11)),
        ),
    ]
}

static CASES: LazyLock<Vec<Case>> = LazyLock::new(cases);

#[test]
fn samples_round_trip() {
    for c in CASES.iter() {
        assert_eq!((c.recode)(&c.bytes).as_ref(), Ok(&c.bytes), "{}", c.name);
    }
}

#[test]
fn every_truncation_is_refused() {
    for c in CASES.iter() {
        for len in 0..c.bytes.len() {
            assert!(
                (c.recode)(&c.bytes[..len]).is_err(),
                "{}: {len} of {} bytes decoded",
                c.name,
                c.bytes.len()
            );
        }
    }
}

#[test]
fn a_trailing_byte_is_refused() {
    for c in CASES.iter() {
        let mut long = c.bytes.clone();
        long.push(0);
        assert_eq!(
            (c.recode)(&long),
            Err(DecodeError::TrailingBytes(1)),
            "{}",
            c.name
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn mutated_bytes_decode_only_to_their_own_encoding(
        which in any::<Index>(),
        at in any::<Index>(),
        byte in any::<u8>(),
    ) {
        let c = which.get(&CASES);
        let mut bytes = c.bytes.clone();
        let at = at.index(bytes.len());
        bytes[at] = byte;
        if let Ok(again) = (c.recode)(&bytes) {
            prop_assert_eq!(again, bytes, "{}", c.name);
        }
    }

    #[test]
    fn spliced_bytes_decode_only_to_their_own_encoding(
        which in any::<Index>(),
        at in any::<Index>(),
        byte in any::<u8>(),
        insert in any::<bool>(),
    ) {
        let c = which.get(&CASES);
        let mut bytes = c.bytes.clone();
        if insert {
            bytes.insert(at.index(bytes.len() + 1), byte);
        } else {
            bytes.remove(at.index(bytes.len()));
        }
        if let Ok(again) = (c.recode)(&bytes) {
            prop_assert_eq!(again, bytes, "{}", c.name);
        }
    }

    #[test]
    fn random_bytes_decode_only_to_their_own_encoding(
        which in any::<Index>(),
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let c = which.get(&CASES);
        if let Ok(again) = (c.recode)(&bytes) {
            prop_assert_eq!(again, bytes, "{}", c.name);
        }
    }
}
