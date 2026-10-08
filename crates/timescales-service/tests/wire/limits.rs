//! `MessageKind::max_body` against the largest message of each kind, and the
//! sizes each kind declares.

use std::collections::BTreeSet;
use std::sync::Arc;

use timescales_core::crypto::{SealedBox, Signature};
use timescales_core::{Encode, EpochId, ExecutorId, Hash32};
use timescales_executor::attestation::{Evidence, MAX_EVIDENCE_LEN, Measurement, Platform};
use timescales_executor::tee::codec::SHARE_CIPHERTEXT_LEN;
use timescales_executor::tee::{Enclave, Quoter, SealedShare};
use timescales_service::wire::{
    AnnouncementFields, AnnouncementQuery, AnnouncementReply, ChallengeRequest, ChallengeResponse,
    CommitteeDescription, EpochAnnouncement, EpochKeyAck, EpochKeyAnnouncement, ExecuteReady,
    ExecuteRequest, GrantMethod, GrantRecord, MAX_COSIGS, MAX_EXECUTE_ENVELOPES, MAX_GRANT_TEXT,
    MAX_GRANTS, MAX_REFUSAL_DETAIL, MAX_UNAUTHENTICATED, MessageKind, Provenance, ProvenanceEntry,
    PublishRequest, RelayRefusal, ReleasePolicyStatement, ReleaseRefusal, ReleaseRequest,
    ReleaseResponse, ShareDelivery,
};

use crate::common::{Committee, Dealing, EPOCH, MARKET, batch, header_v2, keypair, params, rng};

#[test]
fn kinds_have_distinct_codes_and_the_b6_body_limits() {
    let codes: BTreeSet<u8> = MessageKind::ALL.iter().map(|k| *k as u8).collect();
    assert_eq!(codes, (1..=15).collect());
    for k in MessageKind::ALL {
        assert_eq!(MessageKind::from_u8(k as u8), Some(k));
    }
    assert_eq!(MessageKind::from_u8(0), None);
    assert_eq!(MessageKind::from_u8(16), None);

    let kib = 1024;
    let expected = [
        (MessageKind::ShareDelivery, 2 * kib),
        (MessageKind::EpochKeyAck, 128),
        (MessageKind::ChallengeRequest, 256),
        (MessageKind::ChallengeResponse, 256),
        (MessageKind::ReleaseRequest, 18 * kib),
        (MessageKind::ReleaseResponse, 512),
        (MessageKind::ExecuteRequest, 16 * kib * kib),
        (MessageKind::ExecuteReady, 8 * kib),
        (MessageKind::PublishRequest, kib),
        (MessageKind::ExecutePosted, 8 * kib * kib),
        (MessageKind::KeyBundlePut, 4 * kib),
        (MessageKind::AnnouncementQuery, 64),
        (MessageKind::AnnouncementReply, kib),
        (MessageKind::Empty, 0),
        (MessageKind::ErrorResponse, 512),
    ];
    for (kind, max) in expected {
        assert_eq!(kind.max_body(), max, "{kind:?}");
    }
}

fn fits(kind: MessageKind, encoded: &[u8], b6_max: usize) {
    assert_eq!(encoded.len(), b6_max, "{kind:?}: max size");
    assert!(
        encoded.len() <= kind.max_body(),
        "{kind:?}: {} bytes exceed {}",
        encoded.len(),
        kind.max_body()
    );
}

struct EchoQuotes;

impl Quoter for EchoQuotes {
    fn quote(&self, _: Measurement, _: bool, report_data: [u8; 64]) -> Evidence {
        Evidence {
            platform: Platform::IntelTdx,
            quote: report_data.to_vec(),
        }
    }
}

#[test]
fn the_largest_message_of_each_kind_fits_its_body_limit() {
    let committee = Committee::new(16, 16);
    let dealing = Dealing::new(4, 16);
    let ann = dealing.announcement(&committee.desc);
    let ack = EpochKeyAck::sign(
        16,
        &ann.digest(),
        committee.policy(16).digest(),
        committee.identity(16),
    );

    let delivery = ShareDelivery::seal(
        &mut rng(1),
        ann.clone(),
        &committee.desc.members[15],
        &dealing.share(16),
    )
    .unwrap();
    fits(MessageKind::ShareDelivery, &delivery.to_bytes(), 708);
    fits(MessageKind::EpochKeyAck, &ack.to_bytes(), 97);

    let challenge = ChallengeRequest {
        market: MARKET,
        epoch: EPOCH,
        executor: ExecutorId([1; 32]),
    };
    fits(MessageKind::ChallengeRequest, &challenge.to_bytes(), 72);
    let response = ChallengeResponse {
        member: 1,
        market: MARKET,
        epoch: EPOCH,
        nonce: Hash32([2; 32]),
        expires_at_ms: 3,
    };
    fits(MessageKind::ChallengeResponse, &response.to_bytes(), 81);

    let enclave = Enclave::boot(Arc::new(EchoQuotes), Measurement(Hash32::ZERO), false);
    let header = header_v2(&[], Hash32::ZERO);
    let mut release = ReleaseRequest {
        price_commitment: Hash32::ZERO,
        attestation: enclave.attest_v2(&header, vec![Hash32::ZERO; 16], Hash32::ZERO),
        header,
    };
    release.attestation.evidence.quote = vec![0; MAX_EVIDENCE_LEN];
    fits(MessageKind::ReleaseRequest, &release.to_bytes(), 17_348);

    let refused = ReleaseResponse::refused(ReleaseRefusal::Policy, &"x".repeat(MAX_REFUSAL_DETAIL));
    fits(MessageKind::ReleaseResponse, &refused.to_bytes(), 262);
    let share = ReleaseResponse::Share(SealedShare {
        member: 1,
        sealed: SealedBox {
            ephemeral: [1; 32],
            ciphertext: vec![0; SHARE_CIPHERTEXT_LEN],
        },
    });
    assert!(share.to_bytes().len() < refused.to_bytes().len());

    let ready = ExecuteReady {
        executor: ExecutorId([1; 32]),
        header_digest: Hash32([2; 32]),
        outcome_digest: Hash32([3; 32]),
        cosign: Signature([4; 64]),
        unauthenticated: vec![0; MAX_UNAUTHENTICATED],
    };
    fits(MessageKind::ExecuteReady, &ready.to_bytes(), 4_260);

    let members: Vec<u8> = (1..=16).collect();
    let bundle = committee.bundle(&ann, &members);
    fits(MessageKind::KeyBundlePut, &bundle.to_bytes(), 2_178);

    let publish = PublishRequest {
        market: MARKET,
        epoch: EPOCH,
        header_digest: Hash32([5; 32]),
        cosigs: vec![(ExecutorId([6; 32]), Signature([7; 64])); MAX_COSIGS],
    };
    fits(MessageKind::PublishRequest, &publish.to_bytes(), 748);

    let query = AnnouncementQuery {
        market: MARKET,
        epoch: EPOCH,
    };
    fits(MessageKind::AnnouncementQuery, &query.to_bytes(), 40);
    let reply = AnnouncementReply(Some((ann, ack)));
    fits(MessageKind::AnnouncementReply, &reply.to_bytes(), 720);
}

#[test]
fn the_public_statements_have_their_b6_sizes() {
    let committee = Committee::new(16, 16);
    assert_eq!(committee.desc.to_bytes().len(), 1_078);
    let ann = Dealing::new(4, 16).announcement(&committee.desc);
    assert_eq!(ann.to_bytes().len(), 622);
    assert_eq!(committee.policy(1).to_bytes().len(), 221);
    let a = EpochAnnouncement::sign(
        AnnouncementFields {
            market: MARKET,
            epoch: EpochId(1),
            opens_at_ms: 0,
            cutoff_ms: 1,
            band: params().band(timescales_core::Tick(500)).unwrap(),
            price_commitment: Hash32::ZERO,
            key_digest: ann.digest(),
            committee_digest: committee.desc.digest(),
        },
        &keypair(1),
    );
    assert_eq!(a.to_bytes().len(), 273);
    let r = RelayRefusal::sign(MARKET, EpochId(1), Hash32::ZERO, 1, 0, &keypair(1));
    assert_eq!(r.to_bytes().len(), 177);
    assert_eq!(EpochAnnouncement::ENCODED_LEN, 273);
    assert_eq!(RelayRefusal::ENCODED_LEN, 177);
    assert_eq!(ReleasePolicyStatement::ENCODED_LEN, 221);
    assert_eq!(CommitteeDescription::MIN_ENCODED_LEN, 103);
    assert_eq!(EpochKeyAnnouncement::MIN_ENCODED_LEN, 110);
}

#[test]
fn a_full_execute_request_fits_with_room_for_balances() {
    let mut req = ExecuteRequest {
        version: ExecuteRequest::VERSION,
        market: MARKET,
        commit_slot: 1,
        batch: batch(MAX_EXECUTE_ENVELOPES, 0),
        bundle: {
            let c = Committee::new(16, 16);
            let ann = Dealing::new(4, 16).announcement(&c.desc);
            c.bundle(&ann, &(1..=16).collect::<Vec<u8>>())
        },
        committee: Committee::new(16, 16).desc,
        price_commitment: Hash32::ZERO,
        provenance: Provenance {
            grants: (0..MAX_GRANTS)
                .map(|_| GrantRecord {
                    text: "x".repeat(MAX_GRANT_TEXT),
                    signature: Signature([1; 64]),
                    method: GrantMethod::SignIn,
                })
                .collect(),
            entries: vec![
                ProvenanceEntry {
                    grant: 0,
                    session_signature: Signature([2; 64]),
                };
                MAX_EXECUTE_ENVELOPES
            ],
        },
    };
    let without_balances = req.to_bytes().len();
    assert!(without_balances < 2 * 1024 * 1024, "{without_balances}");
    // The rest of the 16 MiB body is room for about 300,000 balance entries.
    let room = MessageKind::ExecuteRequest.max_body() - without_balances;
    assert!(room / 48 > 300_000);
    req.batch = batch(MAX_EXECUTE_ENVELOPES, 1_000);
    assert!(req.to_bytes().len() <= MessageKind::ExecuteRequest.max_body());
}
