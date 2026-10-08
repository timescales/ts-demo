//! Canonical encodings of key-release requests, sealed shares and release
//! errors.
//!
//! ```text
//! KeyReleaseRequest = header(283) || price_commitment32 || ExecutorAttestationV2
//! SealedShare       = member u8 || SealedBox (plaintext index u8 || scalar32)
//! ReleaseError      = code u8 (1..= 20) || [AttestationError | PolicyViolation]
//! ```
//!
//! Release error codes are the `ReleaseRefusal` numbering of
//! the wire types, so a member's refusal and an executor's error name a
//! cause the same way. Code 15 (`Attestation`) is followed by the
//! attestation error and code 16 (`Policy`) by the policy violation:
//!
//! ```text
//! AttestationError = 0 Malformed | 1 UnsupportedPlatform || platform u8 | 2 BadEndorsement
//!                  | 3 BadSignature | 4 Revoked | 5 Backend || bytes text (<= 256)
//!                  | 6 CollateralExpired || expires_at u64 || now u64
//! PolicyViolation  = 0 Platform || platform u8 | 1 Measurement | 2 Tcb || tcb u8 | 3 Debug
//!                  | 4 ReportData | 5 BlockedPlatform | 6 MrConfigId | 7 Xfam
//!                  | 8 TdAttributes | 9 MissingTdFields
//! TcbStatus        = 0 UpToDate | 1 SwHardeningNeeded | 2 ConfigurationNeeded
//!                  | 3 OutOfDate | 4 Revoked
//! ```
//!
//! `Malformed` names its cause with a `&'static str` that cannot be rebuilt
//! from bytes, so only the variant travels and it decodes as
//! [`MALFORMED_REMOTE`]. A `Backend` text longer than 256 bytes is cut at a
//! character boundary.

use crate::attestation::{AttestationError, ExecutorAttestationV2, Platform, TcbStatus};
use crate::policy::PolicyViolation;
use timescales_auction::BatchHeader;
use timescales_core::crypto::{SealedBox, TAG_LEN};
use timescales_core::{
    Decode, DecodeError, Encode, Hash32, Reader,
    encoding::{put_bytes, put_u8, put_u64},
};

use crate::tee::{KeyReleaseRequest, ReleaseError, SealedShare};

/// Encoded length of a batch header (versions 1 and 2).
pub const HEADER_LEN: usize = 283;
/// A released share's plaintext: `index u8 || scalar32`.
pub const SHARE_PLAINTEXT_LEN: usize = 1 + 32;
/// Its ciphertext: the plaintext and the Poly1305 tag.
pub const SHARE_CIPHERTEXT_LEN: usize = SHARE_PLAINTEXT_LEN + TAG_LEN;
/// Longest error text a release error carries.
pub const MAX_ERROR_TEXT: usize = 256;
/// What a decoded `AttestationError::Malformed` says.
pub const MALFORMED_REMOTE: &str = "reported by a remote party";
/// The `Backend` text of an attestation refusal rebuilt from its code.
pub const REFUSED_BY_MEMBER: &str = "refused by the key-release member";

impl KeyReleaseRequest {
    /// An attestation without nonces or evidence.
    pub const MIN_ENCODED_LEN: usize = HEADER_LEN + 32 + ExecutorAttestationV2::MIN_ENCODED_LEN;
}

impl SealedShare {
    pub const ENCODED_LEN: usize = 1 + 32 + 4 + SHARE_CIPHERTEXT_LEN;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
}

impl ReleaseError {
    pub const MIN_ENCODED_LEN: usize = 1;

    /// The cause as a code, numbered like `timescales_service::wire::ReleaseRefusal`.
    pub fn code(&self) -> u8 {
        match self {
            ReleaseError::Unavailable => 1,
            ReleaseError::Unauthenticated => 2,
            ReleaseError::RateLimited => 3,
            ReleaseError::BadRequest => 4,
            ReleaseError::NotRegistered => 5,
            ReleaseError::CommitteeMismatch => 6,
            ReleaseError::BadNonce => 7,
            ReleaseError::NotCommitted => 8,
            ReleaseError::BeaconMissing => 9,
            ReleaseError::NotFinal => 10,
            ReleaseError::EpochClosed => 11,
            ReleaseError::HeaderMismatch => 12,
            ReleaseError::PrevNotTerminal => 13,
            ReleaseError::HeaderPinned => 14,
            ReleaseError::Attestation(_) => 15,
            ReleaseError::Policy(_) => 16,
            ReleaseError::TooManyReleases => 17,
            ReleaseError::NoShare => 18,
            ReleaseError::Halted => 19,
            ReleaseError::BindingMismatch => 20,
        }
    }

    /// The error for a refusal code from a remote member. A code names no
    /// inner cause, so 15 and 16 come back as placeholders:
    /// `Attestation(Backend("refused by the key-release member"))` and
    /// `Policy(Measurement)`. The member's own text travels beside the
    /// code. `None` for codes outside 1..= 20.
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => ReleaseError::Unavailable,
            2 => ReleaseError::Unauthenticated,
            3 => ReleaseError::RateLimited,
            4 => ReleaseError::BadRequest,
            5 => ReleaseError::NotRegistered,
            6 => ReleaseError::CommitteeMismatch,
            7 => ReleaseError::BadNonce,
            8 => ReleaseError::NotCommitted,
            9 => ReleaseError::BeaconMissing,
            10 => ReleaseError::NotFinal,
            11 => ReleaseError::EpochClosed,
            12 => ReleaseError::HeaderMismatch,
            13 => ReleaseError::PrevNotTerminal,
            14 => ReleaseError::HeaderPinned,
            15 => {
                ReleaseError::Attestation(AttestationError::Backend(REFUSED_BY_MEMBER.to_owned()))
            }
            16 => ReleaseError::Policy(PolicyViolation::Measurement),
            17 => ReleaseError::TooManyReleases,
            18 => ReleaseError::NoShare,
            19 => ReleaseError::Halted,
            20 => ReleaseError::BindingMismatch,
            _ => return None,
        })
    }
}

impl Encode for KeyReleaseRequest {
    fn encode(&self, out: &mut Vec<u8>) {
        let KeyReleaseRequest {
            header,
            price_commitment,
            attestation,
        } = self;
        header.encode(out);
        price_commitment.encode(out);
        attestation.encode(out);
    }
}

impl Decode for KeyReleaseRequest {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(KeyReleaseRequest {
            header: BatchHeader::decode(r)?,
            price_commitment: Hash32::decode(r)?,
            attestation: ExecutorAttestationV2::decode(r)?,
        })
    }
}

impl Encode for SealedShare {
    fn encode(&self, out: &mut Vec<u8>) {
        let SealedShare { member, sealed } = self;
        put_u8(out, *member);
        sealed.encode(out);
    }
}

impl Decode for SealedShare {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let member = r.u8()?;
        let sealed = SealedBox::decode(r)?;
        if sealed.ciphertext.len() != SHARE_CIPHERTEXT_LEN {
            return Err(DecodeError::InvalidValue("SealedShare.sealed"));
        }
        Ok(SealedShare { member, sealed })
    }
}

impl Encode for ReleaseError {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.code());
        match self {
            ReleaseError::Attestation(e) => encode_attestation_error(e, out),
            ReleaseError::Policy(v) => encode_policy_violation(v, out),
            _ => {}
        }
    }
}

impl Decode for ReleaseError {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            15 => Ok(ReleaseError::Attestation(decode_attestation_error(r)?)),
            16 => Ok(ReleaseError::Policy(decode_policy_violation(r)?)),
            tag => ReleaseError::from_code(tag).ok_or(DecodeError::InvalidTag {
                ty: "ReleaseError",
                tag,
            }),
        }
    }
}

fn encode_attestation_error(e: &AttestationError, out: &mut Vec<u8>) {
    match e {
        AttestationError::Malformed(_) => put_u8(out, 0),
        AttestationError::UnsupportedPlatform(p) => {
            put_u8(out, 1);
            put_u8(out, *p as u8);
        }
        AttestationError::BadEndorsement => put_u8(out, 2),
        AttestationError::BadSignature => put_u8(out, 3),
        AttestationError::Revoked => put_u8(out, 4),
        AttestationError::Backend(text) => {
            put_u8(out, 5);
            put_bytes(out, truncate_utf8(text, MAX_ERROR_TEXT).as_bytes());
        }
        AttestationError::CollateralExpired { expires_at, now } => {
            put_u8(out, 6);
            put_u64(out, *expires_at);
            put_u64(out, *now);
        }
    }
}

fn decode_attestation_error(r: &mut Reader<'_>) -> Result<AttestationError, DecodeError> {
    Ok(match r.u8()? {
        0 => AttestationError::Malformed(MALFORMED_REMOTE),
        1 => AttestationError::UnsupportedPlatform(decode_platform(r)?),
        2 => AttestationError::BadEndorsement,
        3 => AttestationError::BadSignature,
        4 => AttestationError::Revoked,
        5 => AttestationError::Backend(
            String::from_utf8(r.bytes(MAX_ERROR_TEXT)?)
                .map_err(|_| DecodeError::InvalidValue("AttestationError.text"))?,
        ),
        6 => AttestationError::CollateralExpired {
            expires_at: r.u64()?,
            now: r.u64()?,
        },
        tag => {
            return Err(DecodeError::InvalidTag {
                ty: "AttestationError",
                tag,
            });
        }
    })
}

fn encode_policy_violation(v: &PolicyViolation, out: &mut Vec<u8>) {
    match v {
        PolicyViolation::Platform(p) => {
            put_u8(out, 0);
            put_u8(out, *p as u8);
        }
        PolicyViolation::Measurement => put_u8(out, 1),
        PolicyViolation::Tcb(t) => {
            put_u8(out, 2);
            put_u8(out, tcb_code(*t));
        }
        PolicyViolation::Debug => put_u8(out, 3),
        PolicyViolation::ReportData => put_u8(out, 4),
        PolicyViolation::BlockedPlatform => put_u8(out, 5),
        PolicyViolation::MrConfigId => put_u8(out, 6),
        PolicyViolation::Xfam => put_u8(out, 7),
        PolicyViolation::TdAttributes => put_u8(out, 8),
        PolicyViolation::MissingTdFields => put_u8(out, 9),
    }
}

fn decode_policy_violation(r: &mut Reader<'_>) -> Result<PolicyViolation, DecodeError> {
    Ok(match r.u8()? {
        0 => PolicyViolation::Platform(decode_platform(r)?),
        1 => PolicyViolation::Measurement,
        2 => PolicyViolation::Tcb(decode_tcb(r)?),
        3 => PolicyViolation::Debug,
        4 => PolicyViolation::ReportData,
        5 => PolicyViolation::BlockedPlatform,
        6 => PolicyViolation::MrConfigId,
        7 => PolicyViolation::Xfam,
        8 => PolicyViolation::TdAttributes,
        9 => PolicyViolation::MissingTdFields,
        tag => {
            return Err(DecodeError::InvalidTag {
                ty: "PolicyViolation",
                tag,
            });
        }
    })
}

fn decode_platform(r: &mut Reader<'_>) -> Result<Platform, DecodeError> {
    let tag = r.u8()?;
    Platform::from_u8(tag).ok_or(DecodeError::InvalidTag {
        ty: "Platform",
        tag,
    })
}

fn tcb_code(t: TcbStatus) -> u8 {
    match t {
        TcbStatus::UpToDate => 0,
        TcbStatus::SwHardeningNeeded => 1,
        TcbStatus::ConfigurationNeeded => 2,
        TcbStatus::OutOfDate => 3,
        TcbStatus::Revoked => 4,
    }
}

fn decode_tcb(r: &mut Reader<'_>) -> Result<TcbStatus, DecodeError> {
    Ok(match r.u8()? {
        0 => TcbStatus::UpToDate,
        1 => TcbStatus::SwHardeningNeeded,
        2 => TcbStatus::ConfigurationNeeded,
        3 => TcbStatus::OutOfDate,
        4 => TcbStatus::Revoked,
        tag => {
            return Err(DecodeError::InvalidTag {
                ty: "TcbStatus",
                tag,
            });
        }
    })
}

/// The longest prefix of `s` that fits in `max` bytes and ends on a
/// character boundary.
fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::attestation::{Evidence, Measurement};
    use rand::SeedableRng;
    use timescales_auction::BatchLeaf;
    use timescales_core::crypto::{SealSecret, open, seal};
    use timescales_core::{
        CommitmentScheme, EpochId, FeeBps, FlowMode, MarketId, MarketParams, OrderCommitment,
        Rationing, Tick, encoding::put_u32,
    };

    use super::*;
    use crate::tee::{Enclave, Quoter};

    struct NoQuotes;

    impl Quoter for NoQuotes {
        fn quote(&self, _: Measurement, _: bool, report_data: [u8; 64]) -> Evidence {
            Evidence {
                platform: Platform::Simulated,
                quote: report_data.to_vec(),
            }
        }
    }

    fn params() -> MarketParams {
        MarketParams {
            market: MarketId(9),
            base_lot_size: 1_000,
            tick_size: 10,
            band_half_width: 4,
            max_order_lots_log2: 20,
            max_orders_per_trader: 8,
            max_batch_envelopes: 1024,
            max_order_lifetime: 16,
            maker_fee: FeeBps(0),
            taker_fee: FeeBps(5),
            flow: FlowMode::DualFlow,
            rationing: Rationing::ProRata,
            commitment_scheme: CommitmentScheme::Sha256,
        }
    }

    fn header() -> BatchHeader {
        let p = params();
        let band = p.band(Tick(100)).unwrap();
        let leaves = [BatchLeaf {
            commitment: OrderCommitment([1; 32]),
            envelope_digest: Hash32([2; 32]),
        }];
        BatchHeader::assemble_v2(
            p,
            EpochId(5),
            band,
            Hash32([3; 32]),
            &leaves,
            Hash32([4; 32]),
            Hash32([5; 32]),
            Hash32([6; 32]),
            Hash32([7; 32]),
        )
    }

    fn request(nonces: usize) -> KeyReleaseRequest {
        let enclave = Enclave::boot(Arc::new(NoQuotes), Measurement(Hash32([8; 32])), false);
        let h = header();
        let nonces = (0..nonces).map(|i| Hash32([i as u8; 32])).collect();
        KeyReleaseRequest {
            price_commitment: Hash32([9; 32]),
            attestation: enclave.attest_v2(&h, nonces, Hash32([10; 32])),
            header: h,
        }
    }

    fn all_errors() -> Vec<ReleaseError> {
        let mut v = vec![
            ReleaseError::Unavailable,
            ReleaseError::Unauthenticated,
            ReleaseError::RateLimited,
            ReleaseError::BadRequest,
            ReleaseError::NotRegistered,
            ReleaseError::CommitteeMismatch,
            ReleaseError::BadNonce,
            ReleaseError::NotCommitted,
            ReleaseError::BeaconMissing,
            ReleaseError::NotFinal,
            ReleaseError::EpochClosed,
            ReleaseError::HeaderMismatch,
            ReleaseError::PrevNotTerminal,
            ReleaseError::HeaderPinned,
            ReleaseError::TooManyReleases,
            ReleaseError::NoShare,
            ReleaseError::Halted,
            ReleaseError::BindingMismatch,
        ];
        v.extend(
            [
                AttestationError::Malformed(MALFORMED_REMOTE),
                AttestationError::UnsupportedPlatform(Platform::AwsNitro),
                AttestationError::BadEndorsement,
                AttestationError::BadSignature,
                AttestationError::Revoked,
                AttestationError::Backend("quote verification failed".into()),
                AttestationError::CollateralExpired {
                    expires_at: 1_752_920_163,
                    now: u64::MAX,
                },
            ]
            .map(ReleaseError::Attestation),
        );
        v.extend(
            [
                PolicyViolation::Platform(Platform::IntelTdx),
                PolicyViolation::Measurement,
                PolicyViolation::Tcb(TcbStatus::UpToDate),
                PolicyViolation::Tcb(TcbStatus::SwHardeningNeeded),
                PolicyViolation::Tcb(TcbStatus::ConfigurationNeeded),
                PolicyViolation::Tcb(TcbStatus::OutOfDate),
                PolicyViolation::Tcb(TcbStatus::Revoked),
                PolicyViolation::Debug,
                PolicyViolation::ReportData,
                PolicyViolation::BlockedPlatform,
                PolicyViolation::MrConfigId,
                PolicyViolation::Xfam,
                PolicyViolation::TdAttributes,
                PolicyViolation::MissingTdFields,
            ]
            .map(ReleaseError::Policy),
        );
        v
    }

    #[test]
    fn codec_header_len_matches_the_header_encoding() {
        assert_eq!(header().to_bytes().len(), HEADER_LEN);
        let mut v1 = header();
        v1.version = 1;
        assert_eq!(v1.to_bytes().len(), HEADER_LEN);
    }

    #[test]
    fn codec_release_request_round_trips() {
        let req = request(3);
        let bytes = req.to_bytes();
        let back = KeyReleaseRequest::decode_exact(&bytes).unwrap();
        assert_eq!(back.header, req.header);
        assert_eq!(back.price_commitment, req.price_commitment);
        assert_eq!(back.attestation, req.attestation);
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!(back.attestation.header_digest, back.header.digest());
    }

    #[test]
    fn codec_release_request_min_and_max_lengths() {
        let mut req = request(0);
        req.attestation.evidence.quote.clear();
        assert_eq!(req.to_bytes().len(), KeyReleaseRequest::MIN_ENCODED_LEN);
        //  #13: 17,348 bytes with 16 nonces and the largest evidence.
        let mut req = request(16);
        req.attestation.evidence.quote = vec![0; crate::attestation::MAX_EVIDENCE_LEN];
        assert_eq!(req.to_bytes().len(), 17_348);
        assert_eq!(
            KeyReleaseRequest::decode_exact(&req.to_bytes())
                .unwrap()
                .to_bytes(),
            req.to_bytes()
        );
    }

    #[test]
    fn codec_release_request_rejects_bad_headers_and_trailing_bytes() {
        let mut bytes = request(1).to_bytes();
        bytes[0] = 3;
        assert_eq!(
            KeyReleaseRequest::decode_exact(&bytes).map(|_| ()),
            Err(DecodeError::InvalidValue("BatchHeader.version"))
        );
        let mut bytes = request(1).to_bytes();
        bytes.push(0);
        assert_eq!(
            KeyReleaseRequest::decode_exact(&bytes).map(|_| ()),
            Err(DecodeError::TrailingBytes(1))
        );
        bytes.truncate(bytes.len() - 2);
        assert!(matches!(
            KeyReleaseRequest::decode_exact(&bytes),
            Err(DecodeError::UnexpectedEof { .. })
        ));
        let mut bytes = request(0).to_bytes();
        let nonce_count = HEADER_LEN + 32 + 96;
        bytes[nonce_count..nonce_count + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            KeyReleaseRequest::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded { .. })
        ));
    }

    #[test]
    fn codec_sealed_share_round_trips_and_opens() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(3);
        let enclave_key = SealSecret::generate(&mut rng);
        let pt = [7u8; SHARE_PLAINTEXT_LEN];
        let share = SealedShare {
            member: 2,
            sealed: seal(&mut rng, &enclave_key.public(), b"key-release", b"aad", &pt).unwrap(),
        };
        let bytes = share.to_bytes();
        assert_eq!(bytes.len(), SealedShare::ENCODED_LEN);
        let back = SealedShare::decode_exact(&bytes).unwrap();
        assert_eq!(back, share);
        let opened = open(
            &enclave_key,
            &back.sealed.ephemeral,
            b"key-release",
            b"aad",
            &back.sealed.ciphertext,
        )
        .unwrap();
        assert_eq!(opened.as_slice(), pt);
    }

    #[test]
    fn codec_sealed_share_requires_a_share_sized_ciphertext() {
        for len in [TAG_LEN, SHARE_CIPHERTEXT_LEN - 1, SHARE_CIPHERTEXT_LEN + 1] {
            let share = SealedShare {
                member: 1,
                sealed: SealedBox {
                    ephemeral: [1; 32],
                    ciphertext: vec![0; len],
                },
            };
            assert_eq!(
                SealedShare::decode_exact(&share.to_bytes()),
                Err(DecodeError::InvalidValue("SealedShare.sealed"))
            );
        }
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&[0; 32]);
        put_u32(&mut bytes, u32::MAX);
        assert!(matches!(
            SealedShare::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded { .. })
        ));
        let share = SealedShare {
            member: 1,
            sealed: SealedBox {
                ephemeral: [1; 32],
                ciphertext: vec![0; SHARE_CIPHERTEXT_LEN],
            },
        };
        let mut bytes = share.to_bytes();
        bytes.push(9);
        assert_eq!(
            SealedShare::decode_exact(&bytes),
            Err(DecodeError::TrailingBytes(1))
        );
    }

    #[test]
    fn codec_release_errors_round_trip_with_their_cause() {
        for e in all_errors() {
            let bytes = e.to_bytes();
            assert_eq!(bytes[0], e.code());
            assert_eq!(ReleaseError::decode_exact(&bytes), Ok(e.clone()), "{e:?}");
        }
        let codes: Vec<u8> = all_errors().iter().map(ReleaseError::code).collect();
        for c in 1..=20u8 {
            assert!(codes.contains(&c), "code {c} unused");
        }
        assert_eq!(
            ReleaseError::decode_exact(&[ReleaseError::Unavailable.code()]),
            Ok(ReleaseError::Unavailable)
        );
        assert_eq!(ReleaseError::MIN_ENCODED_LEN, 1);
    }

    #[test]
    fn codec_release_error_codes_invert() {
        for e in all_errors() {
            let back = ReleaseError::from_code(e.code()).unwrap();
            assert_eq!(back.code(), e.code());
        }
        assert_eq!(ReleaseError::from_code(0), None);
        assert_eq!(ReleaseError::from_code(21), None);
        assert_eq!(
            ReleaseError::from_code(15),
            Some(ReleaseError::Attestation(AttestationError::Backend(
                REFUSED_BY_MEMBER.to_owned()
            )))
        );
        assert_eq!(
            ReleaseError::from_code(16),
            Some(ReleaseError::Policy(PolicyViolation::Measurement))
        );
    }

    #[test]
    fn codec_release_error_texts_are_bounded() {
        let e = ReleaseError::Attestation(AttestationError::Malformed("short quote"));
        assert_eq!(
            ReleaseError::decode_exact(&e.to_bytes()),
            Ok(ReleaseError::Attestation(AttestationError::Malformed(
                MALFORMED_REMOTE
            )))
        );

        let long = "é".repeat(200);
        let e = ReleaseError::Attestation(AttestationError::Backend(long.clone()));
        let Ok(ReleaseError::Attestation(AttestationError::Backend(text))) =
            ReleaseError::decode_exact(&e.to_bytes())
        else {
            panic!("backend text did not survive");
        };
        assert_eq!(text.len(), MAX_ERROR_TEXT);
        assert!(long.starts_with(&text));

        let mut bytes = vec![15u8, 5];
        put_u32(&mut bytes, MAX_ERROR_TEXT as u32 + 1);
        bytes.extend(std::iter::repeat_n(b'a', MAX_ERROR_TEXT + 1));
        assert!(matches!(
            ReleaseError::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded { .. })
        ));

        let mut bytes = vec![15u8, 5];
        put_u32(&mut bytes, 2);
        bytes.extend_from_slice(&[0xc3, 0x28]);
        assert_eq!(
            ReleaseError::decode_exact(&bytes),
            Err(DecodeError::InvalidValue("AttestationError.text"))
        );
    }

    #[test]
    fn codec_release_errors_reject_unknown_tags() {
        for (bytes, ty, tag) in [
            (vec![0u8], "ReleaseError", 0),
            (vec![21], "ReleaseError", 21),
            (vec![15, 7], "AttestationError", 7),
            (vec![15, 1, 4], "Platform", 4),
            (vec![16, 10], "PolicyViolation", 10),
            (vec![16, 0, 9], "Platform", 9),
            (vec![16, 2, 5], "TcbStatus", 5),
        ] {
            assert_eq!(
                ReleaseError::decode_exact(&bytes),
                Err(DecodeError::InvalidTag { ty, tag })
            );
        }
        assert_eq!(
            ReleaseError::decode_exact(&[1, 0]),
            Err(DecodeError::TrailingBytes(1))
        );
        assert!(matches!(
            ReleaseError::decode_exact(&[16]),
            Err(DecodeError::UnexpectedEof { .. })
        ));
        // An expiry carries both times.
        assert!(matches!(
            ReleaseError::decode_exact(&[15, 6, 1, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }
}
