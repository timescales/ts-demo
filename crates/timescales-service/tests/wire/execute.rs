use timescales_auction::receipts::{
    BackendKind, ExecutionArtifacts, ExecutionOutcome, ExecutionReceipt, commitments_root,
    fills_root,
};
use timescales_core::crypto::Signature;
use timescales_core::{
    BookId, ClearingPrice, Decode, DecodeError, Encode, ExecutorId, Fill, Hash32, Lots, MarketId,
    OrderCommitment, Role, Side, Tick, TraderId,
};
use timescales_service::wire::{
    EnclaveRefusal, ErrorResponse, ExecutePosted, ExecuteReady, ExecuteRequest, GrantMethod,
    GrantRecord, MAX_COSIGS, MAX_ERROR_DETAIL, MAX_EXECUTE_ENVELOPES, MAX_GRANT_TEXT, MAX_GRANTS,
    MAX_POSTED_ATTESTATION_LEN, MAX_UNAUTHENTICATED, MessageKind, PostedTx, Provenance,
    ProvenanceEntry, PublishRequest,
};

use crate::common::{Committee, Dealing, EPOCH, MARKET, batch};

fn grant(i: usize) -> GrantRecord {
    GrantRecord {
        text: format!("grant {i}"),
        signature: Signature([u8::try_from(i % 256).unwrap(); 64]),
        method: if i.is_multiple_of(2) {
            GrantMethod::SignIn
        } else {
            GrantMethod::SignMessage
        },
    }
}

pub(crate) fn provenance(envelopes: usize, grants: usize) -> Provenance {
    Provenance {
        grants: (0..grants).map(grant).collect(),
        entries: (0..envelopes)
            .map(|i| ProvenanceEntry {
                grant: if grants == 0 || i % 3 == 2 {
                    ProvenanceEntry::NO_GRANT
                } else {
                    u32::try_from(i % grants).unwrap()
                },
                session_signature: Signature([7; 64]),
            })
            .collect(),
    }
}

pub(crate) fn request(envelopes: usize) -> ExecuteRequest {
    let committee = Committee::new(2, 3);
    let ann = Dealing::new(9, 2).announcement(&committee.desc);
    ExecuteRequest {
        version: ExecuteRequest::VERSION,
        market: MARKET,
        commit_slot: 123_456,
        batch: batch(envelopes, 3),
        bundle: committee.bundle(&ann, &[1, 3]),
        committee: committee.desc.clone(),
        price_commitment: Hash32([0x9c; 32]),
        provenance: provenance(envelopes, 2),
    }
}

/// Offset of the envelope count: version, market, commit slot, header.
const ENVELOPE_COUNT_AT: usize = 1 + 32 + 8 + 283;

#[test]
fn provenance_round_trips() {
    let p = provenance(10, 4);
    assert_eq!(Provenance::decode_exact(&p.to_bytes()), Ok(p));
    let empty = provenance(0, 0);
    assert_eq!(empty.to_bytes().len(), Provenance::MIN_ENCODED_LEN);
    assert_eq!(ProvenanceEntry::ENCODED_LEN, 68);
    let g = GrantRecord {
        text: String::new(),
        ..grant(0)
    };
    assert_eq!(g.to_bytes().len(), GrantRecord::MIN_ENCODED_LEN);
}

#[test]
fn provenance_bounds_grants_and_texts() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(MAX_GRANTS as u32 + 1).to_le_bytes());
    assert_eq!(
        Provenance::decode_exact(&bytes),
        Err(DecodeError::LengthExceeded {
            len: MAX_GRANTS + 1,
            max: MAX_GRANTS
        })
    );
    let long = Provenance {
        grants: vec![GrantRecord {
            text: "x".repeat(MAX_GRANT_TEXT + 1),
            ..grant(0)
        }],
        entries: Vec::new(),
    };
    assert!(matches!(
        Provenance::decode_exact(&long.to_bytes()),
        Err(DecodeError::LengthExceeded { .. })
    ));
    let longest = Provenance {
        grants: vec![GrantRecord {
            text: "x".repeat(MAX_GRANT_TEXT),
            ..grant(0)
        }],
        entries: Vec::new(),
    };
    assert_eq!(Provenance::decode_exact(&longest.to_bytes()), Ok(longest));

    let mut bytes = provenance(1, 1).to_bytes();
    bytes[8] = 0xff;
    assert_eq!(
        Provenance::decode_exact(&bytes),
        Err(DecodeError::InvalidValue("GrantRecord.text"))
    );
    let mut bytes = provenance(1, 1).to_bytes();
    let method_at = 4 + 4 + "grant 0".len() + 64;
    bytes[method_at] = 2;
    assert_eq!(
        Provenance::decode_exact(&bytes),
        Err(DecodeError::InvalidTag {
            ty: "GrantMethod",
            tag: 2
        })
    );
}

#[test]
fn provenance_entries_name_a_listed_grant_or_none() {
    let mut p = provenance(3, 2);
    p.entries[0].grant = 2;
    assert_eq!(
        Provenance::decode_exact(&p.to_bytes()),
        Err(DecodeError::InvalidValue("Provenance.entries"))
    );
    p.entries[0].grant = ProvenanceEntry::NO_GRANT;
    assert_eq!(Provenance::decode_exact(&p.to_bytes()), Ok(p));
}

#[test]
fn execute_requests_round_trip() {
    let req = request(5);
    let bytes = req.to_bytes();
    let back = ExecuteRequest::decode_exact(&bytes).unwrap();
    assert_eq!(back.to_bytes(), bytes);
    assert_eq!(back.market, req.market);
    assert_eq!(back.commit_slot, req.commit_slot);
    assert_eq!(back.batch.header, req.batch.header);
    assert_eq!(back.batch.envelopes, req.batch.envelopes);
    assert!(back.batch.masked.is_empty());
    assert_eq!(back.batch.balances, req.batch.balances);
    assert_eq!(back.batch.balances.len(), 3);
    assert_eq!(back.bundle, req.bundle);
    assert_eq!(back.committee, req.committee);
    assert_eq!(back.price_commitment, req.price_commitment);
    assert_eq!(back.provenance, req.provenance);
    assert_eq!(
        &bytes[ENVELOPE_COUNT_AT..ENVELOPE_COUNT_AT + 4],
        &5u32.to_le_bytes()
    );
}

#[test]
fn execute_requests_carry_at_most_the_settlement_bound_of_envelopes() {
    let full = request(MAX_EXECUTE_ENVELOPES);
    let bytes = full.to_bytes();
    assert_eq!(
        ExecuteRequest::decode_exact(&bytes).unwrap().to_bytes(),
        bytes
    );

    let mut over = request(0).to_bytes();
    over[ENVELOPE_COUNT_AT..ENVELOPE_COUNT_AT + 4]
        .copy_from_slice(&(MAX_EXECUTE_ENVELOPES as u32 + 1).to_le_bytes());
    assert_eq!(
        ExecuteRequest::decode_exact(&over).map(|_| ()),
        Err(DecodeError::LengthExceeded {
            len: MAX_EXECUTE_ENVELOPES + 1,
            max: MAX_EXECUTE_ENVELOPES
        })
    );
    // A count within the bound that the input cannot hold is refused before
    // anything is reserved.
    let mut short = request(0).to_bytes();
    short[ENVELOPE_COUNT_AT..ENVELOPE_COUNT_AT + 4].copy_from_slice(&1000u32.to_le_bytes());
    assert!(matches!(
        ExecuteRequest::decode_exact(&short),
        Err(DecodeError::UnexpectedEof { .. })
    ));
}

#[test]
fn execute_requests_carry_no_masked_intents() {
    let mut bytes = request(0).to_bytes();
    let masked_at = ENVELOPE_COUNT_AT + 4;
    bytes[masked_at..masked_at + 4].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        ExecuteRequest::decode_exact(&bytes).map(|_| ()),
        Err(DecodeError::LengthExceeded { len: 1, max: 0 })
    );
}

#[test]
fn execute_requests_have_one_provenance_entry_per_envelope() {
    let mut req = request(4);
    req.provenance.entries.pop();
    assert_eq!(
        ExecuteRequest::decode_exact(&req.to_bytes()).map(|_| ()),
        Err(DecodeError::InvalidValue("ExecuteRequest.provenance"))
    );
    let mut req = request(4);
    req.provenance = provenance(5, 2);
    assert_eq!(
        ExecuteRequest::decode_exact(&req.to_bytes()).map(|_| ()),
        Err(DecodeError::InvalidValue("ExecuteRequest.provenance"))
    );
}

#[test]
fn execute_requests_refuse_other_versions_and_trailing_bytes() {
    let mut bytes = request(1).to_bytes();
    bytes[0] = 2;
    assert_eq!(
        ExecuteRequest::decode_exact(&bytes).map(|_| ()),
        Err(DecodeError::InvalidValue("ExecuteRequest.version"))
    );
    let mut bytes = request(1).to_bytes();
    bytes.push(0);
    assert_eq!(
        ExecuteRequest::decode_exact(&bytes).map(|_| ()),
        Err(DecodeError::TrailingBytes(1))
    );
    bytes.truncate(bytes.len() - 2);
    assert!(matches!(
        ExecuteRequest::decode_exact(&bytes),
        Err(DecodeError::UnexpectedEof { .. })
    ));
}

#[test]
fn the_smallest_execute_request() {
    let committee = Committee::new(1, 1);
    let req = ExecuteRequest {
        version: ExecuteRequest::VERSION,
        market: MARKET,
        commit_slot: 0,
        batch: batch(0, 0),
        bundle: timescales_service::wire::EpochKeyBundle {
            announcement: timescales_service::wire::EpochKeyAnnouncement {
                version: 1,
                market: MARKET,
                epoch: EPOCH,
                committee_digest: committee.desc.digest(),
                scheme: timescales_service::wire::KeyScheme::DevX25519,
                epoch_pk: [9; 32],
                commitments: Vec::new(),
            },
            acks: Vec::new(),
        },
        committee: committee.desc,
        price_commitment: Hash32::ZERO,
        provenance: provenance(0, 0),
    };
    assert_eq!(req.to_bytes().len(), ExecuteRequest::MIN_ENCODED_LEN);
    assert_eq!(
        ExecuteRequest::decode_exact(&req.to_bytes())
            .unwrap()
            .to_bytes(),
        req.to_bytes()
    );
}

#[test]
fn ready_responses_round_trip_within_their_bounds() {
    let r = ExecuteReady {
        executor: ExecutorId([1; 32]),
        header_digest: Hash32([2; 32]),
        outcome_digest: Hash32([3; 32]),
        cosign: Signature([4; 64]),
        unauthenticated: vec![0, 7, 1023],
    };
    assert_eq!(ExecuteReady::decode_exact(&r.to_bytes()), Ok(r.clone()));
    let empty = ExecuteReady {
        unauthenticated: Vec::new(),
        ..r.clone()
    };
    assert_eq!(empty.to_bytes().len(), ExecuteReady::MIN_ENCODED_LEN);
    let full = ExecuteReady {
        unauthenticated: (0..MAX_UNAUTHENTICATED as u32).collect(),
        ..r.clone()
    };
    assert_eq!(full.to_bytes().len(), 4_260);
    assert_eq!(ExecuteReady::decode_exact(&full.to_bytes()), Ok(full));

    let over = ExecuteReady {
        unauthenticated: vec![0; MAX_UNAUTHENTICATED + 1],
        ..r.clone()
    };
    assert_eq!(
        ExecuteReady::decode_exact(&over.to_bytes()),
        Err(DecodeError::LengthExceeded {
            len: MAX_UNAUTHENTICATED + 1,
            max: MAX_UNAUTHENTICATED
        })
    );
    let mut hostile = empty.to_bytes();
    let n = hostile.len();
    hostile[n - 4..].copy_from_slice(&1000u32.to_le_bytes());
    assert!(matches!(
        ExecuteReady::decode_exact(&hostile),
        Err(DecodeError::UnexpectedEof { .. })
    ));
    let mut long = r.to_bytes();
    long.push(0);
    assert_eq!(
        ExecuteReady::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
}

#[test]
fn publish_requests_round_trip_within_their_bounds() {
    let p = PublishRequest {
        market: MARKET,
        epoch: EPOCH,
        header_digest: Hash32([1; 32]),
        cosigs: (0..MAX_COSIGS)
            .map(|i| (ExecutorId([i as u8; 32]), Signature([i as u8; 64])))
            .collect(),
    };
    let bytes = p.to_bytes();
    assert_eq!(bytes.len(), 748);
    assert_eq!(PublishRequest::decode_exact(&bytes), Ok(p.clone()));
    let alone = PublishRequest {
        cosigs: Vec::new(),
        ..p.clone()
    };
    assert_eq!(alone.to_bytes().len(), PublishRequest::MIN_ENCODED_LEN);
    assert_eq!(PublishRequest::decode_exact(&alone.to_bytes()), Ok(alone));

    let mut over = p.clone();
    over.cosigs.push((ExecutorId([9; 32]), Signature([9; 64])));
    assert_eq!(
        PublishRequest::decode_exact(&over.to_bytes()),
        Err(DecodeError::LengthExceeded {
            len: MAX_COSIGS + 1,
            max: MAX_COSIGS
        })
    );
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        PublishRequest::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
}

fn settlement_bytes(fees: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&21u64.to_le_bytes());
    b.extend_from_slice(&EPOCH.0.to_le_bytes());
    b.extend_from_slice(&2u32.to_le_bytes());
    for (trader, base, quote) in [(1u8, 3_000i64, -3_005i64), (2, -3_000, 3_000)] {
        b.extend_from_slice(&[trader; 32]);
        b.extend_from_slice(&base.to_le_bytes());
        b.extend_from_slice(&quote.to_le_bytes());
    }
    b.extend_from_slice(&fees.to_le_bytes());
    b
}

pub(crate) fn posted(fills: usize, cosigned: usize, attestation: usize) -> ExecutePosted {
    let artifacts = ExecutionArtifacts {
        fills: (0..fills)
            .map(|i| Fill {
                commitment: OrderCommitment([i as u8; 32]),
                trader: TraderId([1; 32]),
                book: BookId::MakerAskTakerBid,
                side: Side::Buy,
                role: Role::Taker,
                quantity: Lots(3),
                tick: Tick(100),
            })
            .collect(),
        cancelled: vec![OrderCommitment([0xcc; 32])],
        settlement: Decode::decode_exact(&settlement_bytes(5)).unwrap(),
    };
    let receipt = ExecutionReceipt {
        version: 1,
        outcome: ExecutionOutcome {
            market: MarketId(21),
            epoch: EPOCH,
            header_digest: Hash32([1; 32]),
            clearing: vec![ClearingPrice {
                book: BookId::MakerAskTakerBid,
                tick: Tick(100),
                volume: Lots(3),
            }],
            fill_count: fills as u32,
            fills_root: fills_root(&artifacts.fills),
            cancelled_root: commitments_root(&artifacts.cancelled),
            next_state_root: Hash32([2; 32]),
            settlement_count: 2,
            settlement_root: artifacts.settlement.root(),
            fees: artifacts.settlement.fees,
        },
        backend: BackendKind::Tee,
        executor: ExecutorId([3; 32]),
        attestation: Hash32([4; 32]),
        proof: Hash32::ZERO,
        trace: Hash32([5; 32]),
        signature: Signature([6; 64]),
    };
    ExecutePosted {
        receipt,
        artifacts,
        attestation: vec![0xa7; attestation],
        posted: PostedTx {
            signature: [8; 64],
            slot: 99,
        },
        cosigned: (0..cosigned)
            .map(|i| PostedTx {
                signature: [i as u8; 64],
                slot: 100 + i as u64,
            })
            .collect(),
    }
}

#[test]
fn posted_results_round_trip_within_their_bounds() {
    let p = posted(2, 1, 300);
    let back = ExecutePosted::decode_exact(&p.to_bytes()).unwrap();
    assert_eq!(back, p);
    assert!(back.artifacts.check_against(&back.receipt.outcome).is_ok());
    let full = posted(4, MAX_COSIGS, MAX_POSTED_ATTESTATION_LEN);
    assert_eq!(ExecutePosted::decode_exact(&full.to_bytes()), Ok(full));
    assert_eq!(PostedTx::ENCODED_LEN, 72);

    let too_many = posted(1, MAX_COSIGS + 1, 0);
    assert_eq!(
        ExecutePosted::decode_exact(&too_many.to_bytes()),
        Err(DecodeError::LengthExceeded {
            len: MAX_COSIGS + 1,
            max: MAX_COSIGS
        })
    );
    let too_long = posted(1, 0, MAX_POSTED_ATTESTATION_LEN + 1);
    assert_eq!(
        ExecutePosted::decode_exact(&too_long.to_bytes()),
        Err(DecodeError::LengthExceeded {
            len: MAX_POSTED_ATTESTATION_LEN + 1,
            max: MAX_POSTED_ATTESTATION_LEN
        })
    );
    let mut long = p.to_bytes();
    long.push(0);
    assert_eq!(
        ExecutePosted::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
    // The backend tag follows version and outcome in the receipt.
    let mut bad = p.to_bytes();
    let tag_at = 1 + p.receipt.outcome.to_bytes().len();
    bad[tag_at] = 9;
    assert_eq!(
        ExecutePosted::decode_exact(&bad),
        Err(DecodeError::InvalidTag {
            ty: "BackendKind",
            tag: 9
        })
    );
}

#[test]
fn the_smallest_posted_result() {
    let mut p = posted(0, 0, 0);
    p.receipt.outcome.clearing.clear();
    p.artifacts.cancelled.clear();
    p.artifacts.settlement = Decode::decode_exact(&{
        let mut b = Vec::new();
        b.extend_from_slice(&21u64.to_le_bytes());
        b.extend_from_slice(&EPOCH.0.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b
    })
    .unwrap();
    assert_eq!(p.to_bytes().len(), ExecutePosted::MIN_ENCODED_LEN);
    assert_eq!(ExecutePosted::decode_exact(&p.to_bytes()), Ok(p));
}

#[test]
fn enclave_refusals_are_numbered_from_one() {
    for (i, code) in EnclaveRefusal::ALL.into_iter().enumerate() {
        assert_eq!(usize::from(code as u8), i + 1);
        assert_eq!(EnclaveRefusal::from_u8(code as u8), Some(code));
    }
    assert_eq!(EnclaveRefusal::from_u8(0), None);
    assert_eq!(EnclaveRefusal::from_u8(11), None);
}

#[test]
fn error_responses_round_trip_and_carry_a_receipt_only_on_outcome_mismatch() {
    for code in EnclaveRefusal::ALL {
        if code == EnclaveRefusal::OutcomeMismatch {
            continue;
        }
        let e = ErrorResponse::refused(code, "3 traders");
        assert_eq!(ErrorResponse::decode_exact(&e.to_bytes()), Ok(e));
    }
    let bare = ErrorResponse::refused(EnclaveRefusal::Busy, "");
    assert_eq!(bare.to_bytes().len(), ErrorResponse::MIN_ENCODED_LEN);

    let receipt = posted(2, 0, 0).receipt;
    let mismatch = ErrorResponse::outcome_mismatch(receipt.clone(), "posted another outcome");
    assert_eq!(
        ErrorResponse::decode_exact(&mismatch.to_bytes()),
        Ok(mismatch.clone())
    );

    // A receipt without the mismatch code, or the code without one.
    let stray = ErrorResponse {
        code: EnclaveRefusal::PostFailed,
        detail: String::new(),
        receipt: Some(receipt),
    };
    let missing = ErrorResponse {
        code: EnclaveRefusal::OutcomeMismatch,
        detail: String::new(),
        receipt: None,
    };
    for bad in [stray, missing] {
        assert_eq!(
            ErrorResponse::decode_exact(&bad.to_bytes()),
            Err(DecodeError::InvalidValue("ErrorResponse.receipt"))
        );
    }

    let mut unknown = bare.to_bytes();
    unknown[0] = 11;
    assert_eq!(
        ErrorResponse::decode_exact(&unknown),
        Err(DecodeError::InvalidTag {
            ty: "EnclaveRefusal",
            tag: 11
        })
    );
    let mut flag = bare.to_bytes();
    *flag.last_mut().unwrap() = 2;
    assert_eq!(
        ErrorResponse::decode_exact(&flag),
        Err(DecodeError::InvalidTag { ty: "bool", tag: 2 })
    );
}

#[test]
fn error_response_details_are_bounded_and_fit_the_envelope() {
    let long = "é".repeat(MAX_ERROR_DETAIL);
    let cut = ErrorResponse::refused(EnclaveRefusal::BalanceMismatch, &long);
    assert_eq!(cut.detail, "é".repeat(MAX_ERROR_DETAIL / 2));
    let mut over = ErrorResponse::refused(EnclaveRefusal::BadRequest, "");
    over.detail = "x".repeat(MAX_ERROR_DETAIL + 1);
    // Encoding cuts what a struct literal let through.
    assert_eq!(
        ErrorResponse::decode_exact(&over.to_bytes())
            .unwrap()
            .detail
            .len(),
        MAX_ERROR_DETAIL
    );
    let mut bytes = Vec::new();
    bytes.push(EnclaveRefusal::BadRequest as u8);
    bytes.extend_from_slice(&u32::try_from(MAX_ERROR_DETAIL + 1).unwrap().to_le_bytes());
    bytes.extend_from_slice(&[b'x'; MAX_ERROR_DETAIL + 1]);
    bytes.push(0);
    assert_eq!(
        ErrorResponse::decode_exact(&bytes),
        Err(DecodeError::LengthExceeded {
            len: MAX_ERROR_DETAIL + 1,
            max: MAX_ERROR_DETAIL
        })
    );

    // The largest one: a full detail and a receipt with two clearing prices.
    let mut receipt = posted(2, 0, 0).receipt;
    receipt.outcome.clearing.push(receipt.outcome.clearing[0]);
    let largest = ErrorResponse::outcome_mismatch(receipt, &"x".repeat(MAX_ERROR_DETAIL));
    assert!(largest.to_bytes().len() <= MessageKind::ErrorResponse.max_body());
}
