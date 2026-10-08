//! Masked intents for the MPC path.
//!
//! An MPC committee never receives ciphertexts it can decrypt. Instead the
//! trader obtains a block of one-time masks `r_j` from preprocessing (the
//! committee holds authenticated shares of them) and publishes
//! `d_j = x_j - r_j` for its secret input vector `x`. The masked values are a
//! one-time pad: they reveal nothing about `x` and need no further
//! encryption.
//!
//! Fields that the MPC path treats as public (trader, nonce, validity
//! window, intent kind) travel in clear. The commitment is the same
//! commitment the trader would put in a sealed envelope, so a batch can carry
//! both encodings and fail over between backends. The committee cannot check
//! that the masked vector opens the commitment. The binding is the trader's
//! signature over both.

use crate::crypto::{Hasher, Signature, domain};
use crate::identity::{TraderKey, verify_trader};
use crate::{
    Decode, DecodeError, Encode, EpochId, Hash32, MarketId, OrderCommitment, Reader, TraderId,
    encoding::{put_seq, put_u8},
};

use crate::intent::IntentError;
use crate::intent::intent::Cancel;

/// Upper bound on masked vector length. Generous for `K <= 1025`.
pub const MAX_MASKED_LEN: usize = 4 * 1026 + 64;

/// Field element encoded as a little-endian `u128` (the committee's field
/// is defined in the executor's `mpc` module).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FieldBytes(pub u128);

impl Encode for FieldBytes {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
}

impl Decode for FieldBytes {
    const MIN_ENCODED_LEN: usize = 16;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(FieldBytes(u128::from_le_bytes(r.array()?)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskedPlace {
    pub trader: TraderId,
    pub nonce: u64,
    pub valid_from: EpochId,
    pub expires_at: EpochId,
    /// First index of the mask block this input consumes.
    pub mask_offset: u64,
    pub values: Vec<FieldBytes>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaskedBody {
    Noop,
    Place(MaskedPlace),
    Cancel(Cancel),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskedIntent {
    pub market: MarketId,
    pub epoch: EpochId,
    pub commitment: OrderCommitment,
    pub body: MaskedBody,
    /// Trader signature over [`MaskedIntent::signing_digest`]. Zero for Noop.
    pub signature: Signature,
}

impl MaskedIntent {
    pub fn signing_digest(
        market: MarketId,
        epoch: EpochId,
        commitment: &OrderCommitment,
        body: &MaskedBody,
    ) -> Hash32 {
        let mut b = Vec::new();
        market.encode(&mut b);
        epoch.encode(&mut b);
        commitment.encode(&mut b);
        body.encode(&mut b);
        Hasher::new(domain::INTENT_SIGNATURE)
            .chain(b"masked")
            .chain(&b)
            .finalize()
    }

    pub fn sign(
        key: &TraderKey,
        market: MarketId,
        epoch: EpochId,
        commitment: OrderCommitment,
        body: MaskedBody,
    ) -> Self {
        let d = Self::signing_digest(market, epoch, &commitment, &body);
        Self {
            market,
            epoch,
            commitment,
            signature: key.sign(&d),
            body,
        }
    }

    pub fn noop(market: MarketId, epoch: EpochId, commitment: OrderCommitment) -> Self {
        Self {
            market,
            epoch,
            commitment,
            body: MaskedBody::Noop,
            signature: Signature([0; 64]),
        }
    }

    pub fn trader(&self) -> Option<TraderId> {
        match &self.body {
            MaskedBody::Noop => None,
            MaskedBody::Place(p) => Some(p.trader),
            MaskedBody::Cancel(c) => Some(c.trader),
        }
    }

    /// Check the trader's signature over [`Self::signing_digest`]. Cover
    /// (`Noop`) names no trader, and its signature field must be all zero,
    /// as [`Self::noop`] builds it.
    pub fn verify_signature(&self) -> Result<(), IntentError> {
        let Some(t) = self.trader() else {
            return if self.signature.0 == [0u8; 64] {
                Ok(())
            } else {
                Err(IntentError::BadSignature)
            };
        };
        let d = Self::signing_digest(self.market, self.epoch, &self.commitment, &self.body);
        verify_trader(&t, &d, &self.signature).map_err(|_| IntentError::BadSignature)
    }
}

impl Encode for MaskedBody {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            MaskedBody::Noop => put_u8(out, 0),
            MaskedBody::Place(p) => {
                put_u8(out, 1);
                p.trader.encode(out);
                p.nonce.encode(out);
                p.valid_from.encode(out);
                p.expires_at.encode(out);
                p.mask_offset.encode(out);
                put_seq(out, &p.values);
            }
            MaskedBody::Cancel(c) => {
                put_u8(out, 2);
                c.encode(out);
            }
        }
    }
}

impl Decode for MaskedBody {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(MaskedBody::Noop),
            1 => Ok(MaskedBody::Place(MaskedPlace {
                trader: TraderId::decode(r)?,
                nonce: r.u64()?,
                valid_from: EpochId::decode(r)?,
                expires_at: EpochId::decode(r)?,
                mask_offset: r.u64()?,
                values: r.seq(MAX_MASKED_LEN)?,
            })),
            2 => Ok(MaskedBody::Cancel(Cancel::decode(r)?)),
            tag => Err(DecodeError::InvalidTag {
                ty: "MaskedBody",
                tag,
            }),
        }
    }
}

impl Encode for MaskedIntent {
    fn encode(&self, out: &mut Vec<u8>) {
        self.market.encode(out);
        self.epoch.encode(out);
        self.commitment.encode(out);
        self.body.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for MaskedIntent {
    const MIN_ENCODED_LEN: usize = 8 + 8 + 32 + 1 + 64;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(MaskedIntent {
            market: MarketId::decode(r)?,
            epoch: EpochId::decode(r)?,
            commitment: OrderCommitment::decode(r)?,
            body: MaskedBody::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}
