//! Key release between an enclave and a committee member.
//!
//! ```text
//! ChallengeRequest  = market32 || epoch u64 || executor32                         (72 B)
//! ChallengeResponse = member u8 || market32 || epoch u64 || nonce32 || expires_at_ms u64   (81 B)
//! ReleaseRequest    = KeyReleaseRequest (codec in the executor tee module)
//! ReleaseResponse   = 0 || SealedShare  |  1 || code u8 || bytes detail (UTF-8, <= 256)
//! ```
//!
//! Refusals travel as a successful response with tag 1 inside a
//! member-signed envelope, so an enclave can prove which member refused and
//! why.

use timescales_core::{
    Decode, DecodeError, Encode, EpochId, ExecutorId, Hash32, Reader,
    encoding::{put_bytes, put_u8},
};
use timescales_executor::tee::{ReleaseError, SealedShare};

use crate::wire::text::{read_utf8, truncate_utf8};

/// Longest refusal detail.
pub const MAX_REFUSAL_DETAIL: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeRequest {
    pub market: [u8; 32],
    pub epoch: EpochId,
    pub executor: ExecutorId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeResponse {
    pub member: u8,
    pub market: [u8; 32],
    pub epoch: EpochId,
    pub nonce: Hash32,
    pub expires_at_ms: u64,
}

/// `{ header, price_commitment, attestation: ExecutorAttestationV2 }`.
pub type ReleaseRequest = timescales_executor::tee::KeyReleaseRequest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseResponse {
    Share(SealedShare),
    Refused {
        code: ReleaseRefusal,
        /// At most 256 bytes.
        detail: String,
    },
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseRefusal {
    Unavailable = 1,
    Unauthenticated = 2,
    RateLimited = 3,
    BadRequest = 4,
    NotRegistered = 5,
    CommitteeMismatch = 6,
    BadNonce = 7,
    NotCommitted = 8,
    BeaconMissing = 9,
    NotFinal = 10,
    EpochClosed = 11,
    HeaderMismatch = 12,
    PrevNotTerminal = 13,
    HeaderPinned = 14,
    Attestation = 15,
    Policy = 16,
    TooManyReleases = 17,
    NoShare = 18,
    Halted = 19,
    BindingMismatch = 20,
}

impl ReleaseRefusal {
    pub const ALL: [ReleaseRefusal; 20] = [
        ReleaseRefusal::Unavailable,
        ReleaseRefusal::Unauthenticated,
        ReleaseRefusal::RateLimited,
        ReleaseRefusal::BadRequest,
        ReleaseRefusal::NotRegistered,
        ReleaseRefusal::CommitteeMismatch,
        ReleaseRefusal::BadNonce,
        ReleaseRefusal::NotCommitted,
        ReleaseRefusal::BeaconMissing,
        ReleaseRefusal::NotFinal,
        ReleaseRefusal::EpochClosed,
        ReleaseRefusal::HeaderMismatch,
        ReleaseRefusal::PrevNotTerminal,
        ReleaseRefusal::HeaderPinned,
        ReleaseRefusal::Attestation,
        ReleaseRefusal::Policy,
        ReleaseRefusal::TooManyReleases,
        ReleaseRefusal::NoShare,
        ReleaseRefusal::Halted,
        ReleaseRefusal::BindingMismatch,
    ];

    pub fn from_u8(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code).checked_sub(1)?).copied()
    }
}

/// The executor-side error for a member's refusal. A code names no inner
/// cause, so `Attestation` and `Policy` carry the placeholders of
/// `ReleaseError::from_code`. The member's text is in the response's
/// `detail`.
impl From<ReleaseRefusal> for ReleaseError {
    fn from(refusal: ReleaseRefusal) -> Self {
        // Refusals and release errors share one numbering, so every refusal
        // has an error.
        ReleaseError::from_code(refusal as u8).unwrap_or(ReleaseError::BadRequest)
    }
}

/// The refusal a member sends for an error of the release core.
impl From<&ReleaseError> for ReleaseRefusal {
    fn from(e: &ReleaseError) -> Self {
        match e {
            ReleaseError::Unavailable => ReleaseRefusal::Unavailable,
            ReleaseError::Unauthenticated => ReleaseRefusal::Unauthenticated,
            ReleaseError::RateLimited => ReleaseRefusal::RateLimited,
            ReleaseError::BadRequest => ReleaseRefusal::BadRequest,
            ReleaseError::NotRegistered => ReleaseRefusal::NotRegistered,
            ReleaseError::CommitteeMismatch => ReleaseRefusal::CommitteeMismatch,
            ReleaseError::BadNonce => ReleaseRefusal::BadNonce,
            ReleaseError::NotCommitted => ReleaseRefusal::NotCommitted,
            ReleaseError::BeaconMissing => ReleaseRefusal::BeaconMissing,
            ReleaseError::NotFinal => ReleaseRefusal::NotFinal,
            ReleaseError::EpochClosed => ReleaseRefusal::EpochClosed,
            ReleaseError::HeaderMismatch => ReleaseRefusal::HeaderMismatch,
            ReleaseError::PrevNotTerminal => ReleaseRefusal::PrevNotTerminal,
            ReleaseError::HeaderPinned => ReleaseRefusal::HeaderPinned,
            ReleaseError::Attestation(_) => ReleaseRefusal::Attestation,
            ReleaseError::Policy(_) => ReleaseRefusal::Policy,
            ReleaseError::TooManyReleases => ReleaseRefusal::TooManyReleases,
            ReleaseError::NoShare => ReleaseRefusal::NoShare,
            ReleaseError::Halted => ReleaseRefusal::Halted,
            ReleaseError::BindingMismatch => ReleaseRefusal::BindingMismatch,
        }
    }
}

impl ChallengeRequest {
    pub const ENCODED_LEN: usize = 32 + 8 + 32;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
}

impl ChallengeResponse {
    pub const ENCODED_LEN: usize = 1 + 32 + 8 + 32 + 8;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
}

impl ReleaseResponse {
    /// A refusal with an empty detail.
    pub const MIN_ENCODED_LEN: usize = 1 + 1 + 4;

    /// A refusal. `detail` is cut to 256 bytes at a character boundary.
    pub fn refused(code: ReleaseRefusal, detail: &str) -> Self {
        ReleaseResponse::Refused {
            code,
            detail: truncate_utf8(detail, MAX_REFUSAL_DETAIL).to_owned(),
        }
    }

    /// The share, or the refusal as the executor's error type.
    pub fn into_result(self) -> Result<SealedShare, ReleaseError> {
        match self {
            ReleaseResponse::Share(s) => Ok(s),
            ReleaseResponse::Refused { code, .. } => Err(code.into()),
        }
    }
}

impl Encode for ChallengeRequest {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.market);
        self.epoch.encode(out);
        self.executor.encode(out);
    }
}

impl Decode for ChallengeRequest {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ChallengeRequest {
            market: r.array()?,
            epoch: EpochId::decode(r)?,
            executor: ExecutorId::decode(r)?,
        })
    }
}

impl Encode for ChallengeResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.member);
        out.extend_from_slice(&self.market);
        self.epoch.encode(out);
        self.nonce.encode(out);
        self.expires_at_ms.encode(out);
    }
}

impl Decode for ChallengeResponse {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ChallengeResponse {
            member: r.u8()?,
            market: r.array()?,
            epoch: EpochId::decode(r)?,
            nonce: Hash32::decode(r)?,
            expires_at_ms: r.u64()?,
        })
    }
}

impl Encode for ReleaseRefusal {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for ReleaseRefusal {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let tag = r.u8()?;
        Self::from_u8(tag).ok_or(DecodeError::InvalidTag {
            ty: "ReleaseRefusal",
            tag,
        })
    }
}

impl Encode for ReleaseResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            ReleaseResponse::Share(s) => {
                put_u8(out, 0);
                s.encode(out);
            }
            ReleaseResponse::Refused { code, detail } => {
                put_u8(out, 1);
                code.encode(out);
                put_bytes(out, truncate_utf8(detail, MAX_REFUSAL_DETAIL).as_bytes());
            }
        }
    }
}

impl Decode for ReleaseResponse {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(ReleaseResponse::Share(SealedShare::decode(r)?)),
            1 => Ok(ReleaseResponse::Refused {
                code: ReleaseRefusal::decode(r)?,
                detail: read_utf8(r, MAX_REFUSAL_DETAIL, "ReleaseResponse.detail")?,
            }),
            tag => Err(DecodeError::InvalidTag {
                ty: "ReleaseResponse",
                tag,
            }),
        }
    }
}
