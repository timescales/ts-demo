//! Private intents: what a trader actually wants, before encryption.

use crate::commitment::{CommitmentError, Committable, Salt, commit, verify};
use crate::crypto::{Signature, domain, hash};
use crate::identity::{TraderKey, verify_trader_message};
use crate::{
    CommitmentScheme, Decode, DecodeError, Encode, EpochId, Hash32, MarketId, Order,
    OrderCommitment, Reader, TraderId, encoding::put_u8,
};
use rand_core::{CryptoRng, RngCore};

use crate::intent::IntentError;

/// Withdraws a previously submitted order before it executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cancel {
    pub market: MarketId,
    pub trader: TraderId,
    pub nonce: u64,
    pub target: OrderCommitment,
    /// Batch the cancel is for. A cancel outside its batch is ignored.
    pub epoch: EpochId,
}

impl Cancel {
    pub const ENCODED_LEN: usize = 8 + 32 + 8 + 32 + 8;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IntentBody {
    /// Cover traffic. Indistinguishable from real intents once sealed.
    Noop,
    Place(Order),
    Cancel(Cancel),
}

impl IntentBody {
    pub fn trader(&self) -> Option<TraderId> {
        match self {
            IntentBody::Noop => None,
            IntentBody::Place(o) => Some(o.trader),
            IntentBody::Cancel(c) => Some(c.trader),
        }
    }

    pub fn market(&self) -> Option<MarketId> {
        match self {
            IntentBody::Noop => None,
            IntentBody::Place(o) => Some(o.market),
            IntentBody::Cancel(c) => Some(c.market),
        }
    }
}

impl Encode for Cancel {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.market.encode(out);
        self.trader.encode(out);
        self.nonce.encode(out);
        self.target.encode(out);
        self.epoch.encode(out);
    }
}

impl Decode for Cancel {
    const MIN_ENCODED_LEN: usize = Cancel::ENCODED_LEN;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Cancel {
            market: MarketId::decode(r)?,
            trader: TraderId::decode(r)?,
            nonce: r.u64()?,
            target: OrderCommitment::decode(r)?,
            epoch: EpochId::decode(r)?,
        })
    }
}

impl Encode for IntentBody {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            IntentBody::Noop => put_u8(out, 0),
            IntentBody::Place(o) => {
                put_u8(out, 1);
                o.encode(out);
            }
            IntentBody::Cancel(c) => {
                put_u8(out, 2);
                c.encode(out);
            }
        }
    }
}

impl Decode for IntentBody {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(IntentBody::Noop),
            1 => Ok(IntentBody::Place(Order::decode(r)?)),
            2 => Ok(IntentBody::Cancel(Cancel::decode(r)?)),
            tag => Err(DecodeError::InvalidTag {
                ty: "IntentBody",
                tag,
            }),
        }
    }
}

impl Committable for Cancel {
    const KIND: u8 = 2;

    fn commitment_bytes(&self, out: &mut Vec<u8>) {
        self.encode(out);
    }

    fn commitment_limbs(&self) -> Vec<u64> {
        let mut v = vec![self.market.0];
        v.extend(limbs(&self.trader.0));
        v.push(self.nonce);
        v.extend(limbs(&self.target.0));
        v.push(self.epoch.0);
        v
    }
}

/// Wrapper so the commitment kind tag is applied consistently for any body.
#[derive(Debug)]
struct NoopBody;

impl Committable for NoopBody {
    const KIND: u8 = 0;

    fn commitment_bytes(&self, _out: &mut Vec<u8>) {}

    fn commitment_limbs(&self) -> Vec<u64> {
        Vec::new()
    }
}

fn limbs(b: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, o) in out.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i * 8..i * 8 + 8]);
        *o = u64::from_le_bytes(w);
    }
    out
}

pub fn commit_body(
    scheme: CommitmentScheme,
    body: &IntentBody,
    salt: &Salt,
) -> Result<OrderCommitment, IntentError> {
    let c = match body {
        IntentBody::Noop => commit(scheme, &NoopBody, salt),
        IntentBody::Place(o) => commit(scheme, o, salt),
        IntentBody::Cancel(c) => commit(scheme, c, salt),
    };
    c.map_err(IntentError::Commitment)
}

/// The trader signs the commitment, which already binds body and salt.
pub fn signature_digest(commitment: &OrderCommitment) -> Hash32 {
    hash(domain::INTENT_SIGNATURE, commitment.as_bytes())
}

/// The text the trader's wallet signs for an intent: the signature digest as
/// a short code. Wallets refuse to sign raw bytes that could be a
/// transaction, so the digest travels inside readable UTF-8.
pub fn signed_message(commitment: &OrderCommitment) -> Vec<u8> {
    format!(
        "Timescales order\nCode: {}\nSign this only on the Timescales app.",
        signature_digest(commitment)
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
    .into_bytes()
}

/// A decrypted, cryptographically checked intent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateIntent {
    pub body: IntentBody,
    pub salt: Salt,
    /// All-zero for `Noop`.
    pub signature: Signature,
}

/// Prints nothing of the intent: not even its kind, which would tell cover
/// traffic from real orders in a log.
impl core::fmt::Debug for PrivateIntent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrivateIntent(..)")
    }
}

impl PrivateIntent {
    pub fn place<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &TraderKey,
        scheme: CommitmentScheme,
        order: Order,
    ) -> Result<(Self, OrderCommitment), IntentError> {
        if order.trader != key.id() {
            return Err(IntentError::WrongSigner);
        }
        Self::signed(rng, key, scheme, IntentBody::Place(order))
    }

    pub fn cancel<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &TraderKey,
        scheme: CommitmentScheme,
        cancel: Cancel,
    ) -> Result<(Self, OrderCommitment), IntentError> {
        if cancel.trader != key.id() {
            return Err(IntentError::WrongSigner);
        }
        Self::signed(rng, key, scheme, IntentBody::Cancel(cancel))
    }

    pub fn noop<R: RngCore + CryptoRng>(
        rng: &mut R,
        scheme: CommitmentScheme,
    ) -> Result<(Self, OrderCommitment), IntentError> {
        let salt = random_salt(rng);
        let c = commit_body(scheme, &IntentBody::Noop, &salt)?;
        Ok((
            Self {
                body: IntentBody::Noop,
                salt,
                signature: Signature([0; 64]),
            },
            c,
        ))
    }

    fn signed<R: RngCore + CryptoRng>(
        rng: &mut R,
        key: &TraderKey,
        scheme: CommitmentScheme,
        body: IntentBody,
    ) -> Result<(Self, OrderCommitment), IntentError> {
        let salt = random_salt(rng);
        let c = commit_body(scheme, &body, &salt)?;
        let signature = key.sign_message(&signed_message(&c));
        Ok((
            Self {
                body,
                salt,
                signature,
            },
            c,
        ))
    }

    /// Check that this intent opens `commitment` and, unless it is cover
    /// traffic, carries a valid signature by the trader it names.
    pub fn verify(
        &self,
        scheme: CommitmentScheme,
        commitment: &OrderCommitment,
    ) -> Result<(), IntentError> {
        // The recomputed commitment is derived from the plaintext, so it is
        // compared in constant time.
        let opened = match &self.body {
            IntentBody::Noop => verify(scheme, commitment, &NoopBody, &self.salt),
            IntentBody::Place(o) => verify(scheme, commitment, o, &self.salt),
            IntentBody::Cancel(c) => verify(scheme, commitment, c, &self.salt),
        };
        match opened {
            Ok(()) => {}
            Err(CommitmentError::Mismatch) => return Err(IntentError::CommitmentMismatch),
            Err(e) => return Err(IntentError::Commitment(e)),
        }
        match self.body.trader() {
            None => Ok(()),
            Some(t) => verify_trader_message(&t, &signed_message(commitment), &self.signature)
                .map_err(|_| IntentError::BadSignature),
        }
    }
}

fn random_salt<R: RngCore + CryptoRng>(rng: &mut R) -> Salt {
    let mut s = [0u8; 32];
    rng.fill_bytes(&mut s);
    Salt(s)
}

impl Encode for PrivateIntent {
    fn encode(&self, out: &mut Vec<u8>) {
        self.body.encode(out);
        out.extend_from_slice(&self.salt.0);
        self.signature.encode(out);
    }
}

impl Decode for PrivateIntent {
    const MIN_ENCODED_LEN: usize = 1 + 32 + 64;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(PrivateIntent {
            body: IntentBody::decode(r)?,
            salt: Salt(r.array()?),
            signature: Signature::decode(r)?,
        })
    }
}
