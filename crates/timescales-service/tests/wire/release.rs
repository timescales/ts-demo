use std::sync::Arc;

use timescales_core::crypto::{SealSecret, seal};
use timescales_core::{Decode, DecodeError, Encode, ExecutorId, Hash32};
use timescales_executor::attestation::{Evidence, MAX_EVIDENCE_LEN, Measurement, Platform};
use timescales_executor::tee::{Enclave, Quoter, ReleaseError, SealedShare};
use timescales_service::wire::{
    ChallengeRequest, ChallengeResponse, MAX_REFUSAL_DETAIL, MessageKind, ReleaseRefusal,
    ReleaseRequest, ReleaseResponse,
};

use crate::common::{EPOCH, MARKET, envelope, header_v2, rng};

pub(crate) fn share() -> SealedShare {
    let mut r = rng(6);
    let enclave = SealSecret::generate(&mut r);
    SealedShare {
        member: 2,
        sealed: seal(&mut r, &enclave.public(), b"key-release", b"aad", &[7; 33]).unwrap(),
    }
}

#[test]
fn challenges_round_trip_at_their_fixed_sizes() {
    let req = ChallengeRequest {
        market: MARKET,
        epoch: EPOCH,
        executor: ExecutorId([5; 32]),
    };
    let bytes = req.to_bytes();
    assert_eq!(bytes.len(), ChallengeRequest::ENCODED_LEN);
    assert_eq!(bytes.len(), 72);
    assert_eq!(ChallengeRequest::decode_exact(&bytes), Ok(req));

    let resp = ChallengeResponse {
        member: 3,
        market: MARKET,
        epoch: EPOCH,
        nonce: Hash32([8; 32]),
        expires_at_ms: 1_800_000_060_000,
    };
    let bytes = resp.to_bytes();
    assert_eq!(bytes.len(), ChallengeResponse::ENCODED_LEN);
    assert_eq!(bytes.len(), 81);
    assert_eq!(ChallengeResponse::decode_exact(&bytes), Ok(resp));

    let mut long = req.to_bytes();
    long.push(0);
    assert_eq!(
        ChallengeRequest::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
    assert!(matches!(
        ChallengeRequest::decode_exact(&long[..71]),
        Err(DecodeError::UnexpectedEof { .. })
    ));
    let mut long = resp.to_bytes();
    long.push(0);
    assert_eq!(
        ChallengeResponse::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
}

#[test]
fn shares_and_refusals_round_trip() {
    let s = ReleaseResponse::Share(share());
    let bytes = s.to_bytes();
    assert_eq!(bytes[0], 0);
    assert_eq!(bytes.len(), 1 + SealedShare::ENCODED_LEN);
    assert_eq!(ReleaseResponse::decode_exact(&bytes), Ok(s));

    for code in ReleaseRefusal::ALL {
        let r = ReleaseResponse::refused(code, "member says no");
        let bytes = r.to_bytes();
        assert_eq!(&bytes[..2], &[1, code as u8]);
        assert_eq!(ReleaseResponse::decode_exact(&bytes), Ok(r));
    }
    let bare = ReleaseResponse::refused(ReleaseRefusal::NoShare, "");
    assert_eq!(bare.to_bytes().len(), ReleaseResponse::MIN_ENCODED_LEN);
}

#[test]
fn refusal_details_are_bounded() {
    let longest = ReleaseResponse::refused(ReleaseRefusal::Policy, &"x".repeat(MAX_REFUSAL_DETAIL));
    let bytes = longest.to_bytes();
    assert_eq!(bytes.len(), 262);
    assert_eq!(ReleaseResponse::decode_exact(&bytes), Ok(longest));

    let cut = ReleaseResponse::refused(ReleaseRefusal::Policy, &"€".repeat(100));
    let ReleaseResponse::Refused { detail, .. } = &cut else {
        unreachable!()
    };
    assert_eq!(detail.len(), 255);
    // Encoding cuts a detail built by hand as well.
    let by_hand = ReleaseResponse::Refused {
        code: ReleaseRefusal::Halted,
        detail: "y".repeat(400),
    };
    let decoded = ReleaseResponse::decode_exact(&by_hand.to_bytes()).unwrap();
    assert_eq!(
        decoded,
        ReleaseResponse::Refused {
            code: ReleaseRefusal::Halted,
            detail: "y".repeat(MAX_REFUSAL_DETAIL)
        }
    );

    let mut over = vec![1u8, ReleaseRefusal::Halted as u8];
    over.extend_from_slice(&(MAX_REFUSAL_DETAIL as u32 + 1).to_le_bytes());
    over.extend(std::iter::repeat_n(b'z', MAX_REFUSAL_DETAIL + 1));
    assert_eq!(
        ReleaseResponse::decode_exact(&over),
        Err(DecodeError::LengthExceeded {
            len: MAX_REFUSAL_DETAIL + 1,
            max: MAX_REFUSAL_DETAIL
        })
    );
    let mut not_utf8 = vec![1u8, ReleaseRefusal::Halted as u8];
    not_utf8.extend_from_slice(&1u32.to_le_bytes());
    not_utf8.push(0xff);
    assert_eq!(
        ReleaseResponse::decode_exact(&not_utf8),
        Err(DecodeError::InvalidValue("ReleaseResponse.detail"))
    );
}

#[test]
fn unknown_tags_and_codes_are_refused() {
    assert_eq!(
        ReleaseResponse::decode_exact(&[2]),
        Err(DecodeError::InvalidTag {
            ty: "ReleaseResponse",
            tag: 2
        })
    );
    for code in [0u8, 21, 255] {
        let mut bytes = vec![1u8, code];
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            ReleaseResponse::decode_exact(&bytes),
            Err(DecodeError::InvalidTag {
                ty: "ReleaseRefusal",
                tag: code
            })
        );
        assert_eq!(ReleaseRefusal::from_u8(code), None);
    }
    let mut bytes = ReleaseResponse::refused(ReleaseRefusal::NotFinal, "").to_bytes();
    bytes.push(0);
    assert_eq!(
        ReleaseResponse::decode_exact(&bytes),
        Err(DecodeError::TrailingBytes(1))
    );
    let mut bytes = ReleaseResponse::Share(share()).to_bytes();
    bytes.truncate(40);
    assert!(matches!(
        ReleaseResponse::decode_exact(&bytes),
        Err(DecodeError::UnexpectedEof { .. })
    ));
}

#[test]
fn every_refusal_maps_to_its_release_error_and_back() {
    for (i, code) in ReleaseRefusal::ALL.into_iter().enumerate() {
        assert_eq!(code as usize, i + 1);
        assert_eq!(ReleaseRefusal::from_u8(code as u8), Some(code));
        let e = ReleaseError::from(code);
        assert_eq!(e.code(), code as u8);
        assert_eq!(ReleaseRefusal::from(&e), code);
        assert_eq!(
            ReleaseResponse::refused(code, "d").into_result(),
            Err(e.clone())
        );
    }
    assert!(matches!(
        ReleaseError::from(ReleaseRefusal::Attestation),
        ReleaseError::Attestation(_)
    ));
    assert!(matches!(
        ReleaseError::from(ReleaseRefusal::Policy),
        ReleaseError::Policy(_)
    ));
    assert_eq!(
        ReleaseError::from(ReleaseRefusal::HeaderPinned),
        ReleaseError::HeaderPinned
    );
    assert_eq!(ReleaseResponse::Share(share()).into_result(), Ok(share()));
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
fn release_requests_travel_whole() {
    let enclave = Enclave::boot(Arc::new(EchoQuotes), Measurement(Hash32([1; 32])), false);
    let envelopes: Vec<_> = (0..4).map(envelope).collect();
    let header = header_v2(&envelopes, Hash32([2; 32]));
    let req: ReleaseRequest = ReleaseRequest {
        price_commitment: Hash32([3; 32]),
        attestation: enclave.attest_v2(&header, vec![Hash32([4; 32]); 5], Hash32([5; 32])),
        header,
    };
    let bytes = req.to_bytes();
    let back = ReleaseRequest::decode_exact(&bytes).unwrap();
    assert_eq!(back.to_bytes(), bytes);
    assert_eq!(back.attestation.header_digest, back.header.digest());
    assert!(bytes.len() <= MessageKind::ReleaseRequest.max_body());

    let mut largest = back;
    largest.attestation.nonces = vec![Hash32([6; 32]); 16];
    largest.attestation.evidence.quote = vec![0; MAX_EVIDENCE_LEN];
    assert_eq!(largest.to_bytes().len(), 17_348);
}
