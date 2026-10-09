//! Fixed-size sealed envelopes.
//!
//! Every envelope in every market is exactly [`ENVELOPE_LEN`] bytes regardless
//! of what it carries (placement, cancel or cover traffic), so the transport
//! and the chain learn nothing from length. The plaintext is the canonical
//! intent encoding followed by zero padding. Non-zero padding is rejected so
//! each plaintext has exactly one valid encoding.

use crate::crypto::{
    CryptoError, EpochSecret, Hasher, SealSecret, TAG_LEN, Zeroizing, domain, open, seal,
};
use crate::{
    CommitmentScheme, Decode, DecodeError, Encode, EpochId, Hash32, MarketId, Order,
    OrderCommitment, PROTOCOL_VERSION, Reader, encoding::put_u8,
};
use rand_core::{CryptoRng, RngCore};

use crate::intent::IntentError;
use crate::intent::intent::{Cancel, PrivateIntent};

/// Fixed plaintext size. Large enough for the largest intent body plus salt
/// and signature. The slack is padding.
pub const PLAINTEXT_LEN: usize = 192;
pub const CIPHERTEXT_LEN: usize = PLAINTEXT_LEN + TAG_LEN;
/// version + market + epoch + commitment + ephemeral key + ciphertext.
pub const ENVELOPE_LEN: usize = 1 + 8 + 8 + 32 + 32 + CIPHERTEXT_LEN;
/// version + market + epoch + commitment, authenticated with every box.
const AAD_LEN: usize = 1 + 8 + 8 + 32;
/// "envelope" + market + epoch, the KDF context of every box.
const KDF_INFO_LEN: usize = 8 + 8 + 8;

const MAX_INTENT_LEN: usize = 1 + max(Order::ENCODED_LEN, Cancel::ENCODED_LEN) + 32 + 64;
const _: () = assert!(MAX_INTENT_LEN <= PLAINTEXT_LEN);

const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    pub version: u8,
    pub market: MarketId,
    pub epoch: EpochId,
    pub commitment: OrderCommitment,
    pub ephemeral: [u8; 32],
    pub ciphertext: [u8; CIPHERTEXT_LEN],
}

impl core::fmt::Debug for SealedEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedEnvelope")
            .field("market", &self.market)
            .field("epoch", &self.epoch)
            .field("commitment", &self.commitment)
            .finish_non_exhaustive()
    }
}

impl SealedEnvelope {
    /// Authenticated header. Moving an envelope to another market or epoch, or
    /// pairing it with another commitment, breaks decryption.
    fn aad(
        version: u8,
        market: MarketId,
        epoch: EpochId,
        commitment: &OrderCommitment,
    ) -> [u8; AAD_LEN] {
        let mut a = [0u8; AAD_LEN];
        a[0] = version;
        a[1..9].copy_from_slice(&market.get().to_le_bytes());
        a[9..17].copy_from_slice(&epoch.get().to_le_bytes());
        a[17..].copy_from_slice(&commitment.0);
        a
    }

    fn kdf_info(market: MarketId, epoch: EpochId) -> [u8; KDF_INFO_LEN] {
        let mut i = [0u8; KDF_INFO_LEN];
        i[..8].copy_from_slice(b"envelope");
        i[8..16].copy_from_slice(&market.get().to_le_bytes());
        i[16..].copy_from_slice(&epoch.get().to_le_bytes());
        i
    }

    /// `H(ENVELOPE_COMMITMENT, encoding)`: what header v2 batch leaves, v2
    /// promises and the relay's dedup bind next to the order commitment.
    pub fn digest(&self) -> Hash32 {
        Hasher::new(domain::ENVELOPE_COMMITMENT)
            .chain(&self.to_bytes())
            .finalize()
    }

    /// Encrypt `intent` to the batch key for (`market`, `epoch`).
    pub fn seal<R: RngCore + CryptoRng>(
        rng: &mut R,
        market: MarketId,
        epoch: EpochId,
        epoch_key: &[u8; 32],
        commitment: OrderCommitment,
        intent: &PrivateIntent,
    ) -> Result<Self, IntentError> {
        // Sized up front: growing the buffer would leave a copy of the
        // plaintext in freed memory.
        let mut pt = Zeroizing::new(Vec::with_capacity(PLAINTEXT_LEN));
        intent.encode(&mut pt);
        debug_assert!(pt.len() <= PLAINTEXT_LEN);
        pt.resize(PLAINTEXT_LEN, 0);
        let aad = Self::aad(PROTOCOL_VERSION, market, epoch, &commitment);
        let sealed = seal(rng, epoch_key, &Self::kdf_info(market, epoch), &aad, &pt)
            .map_err(IntentError::Crypto)?;
        let mut ciphertext = [0u8; CIPHERTEXT_LEN];
        ciphertext.copy_from_slice(&sealed.ciphertext);
        Ok(Self {
            version: PROTOCOL_VERSION,
            market,
            epoch,
            commitment,
            ephemeral: sealed.ephemeral,
            ciphertext,
        })
    }

    /// Decrypt with a locally held X25519 key, parse, and check the
    /// commitment opening and signature.
    pub fn open(
        &self,
        key: &SealSecret,
        scheme: CommitmentScheme,
    ) -> Result<PrivateIntent, IntentError> {
        self.open_using(scheme, |eph, info, aad, ct| open(key, eph, info, aad, ct))
    }

    /// [`Self::open`] with an epoch secret, either a dev key or a
    /// threshold-dealt scalar (which also refuses ephemeral keys outside the
    /// prime-order subgroup).
    pub fn open_with(
        &self,
        key: &EpochSecret,
        scheme: CommitmentScheme,
    ) -> Result<PrivateIntent, IntentError> {
        self.open_using(scheme, |eph, info, aad, ct| {
            key.open_box(eph, info, aad, ct)
        })
    }

    fn open_using(
        &self,
        scheme: CommitmentScheme,
        decrypt: impl FnOnce(&[u8; 32], &[u8], &[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>,
    ) -> Result<PrivateIntent, IntentError> {
        if self.version != PROTOCOL_VERSION {
            return Err(IntentError::UnsupportedVersion(self.version));
        }
        let aad = Self::aad(self.version, self.market, self.epoch, &self.commitment);
        let pt = decrypt(
            &self.ephemeral,
            &Self::kdf_info(self.market, self.epoch),
            &aad,
            &self.ciphertext,
        )
        .map_err(IntentError::Crypto)?;
        let mut r = Reader::new(&pt);
        let intent = PrivateIntent::decode(&mut r).map_err(IntentError::Malformed)?;
        let rest = r.take(r.remaining()).map_err(IntentError::Malformed)?;
        if rest.iter().any(|b| *b != 0) {
            return Err(IntentError::Malformed(DecodeError::InvalidValue(
                "non-zero padding",
            )));
        }
        intent.verify(scheme, &self.commitment)?;
        Ok(intent)
    }
}

impl Encode for SealedEnvelope {
    fn encoded_len(&self) -> usize {
        ENVELOPE_LEN
    }

    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.market.encode(out);
        self.epoch.encode(out);
        self.commitment.encode(out);
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(&self.ciphertext);
    }
}

impl Decode for SealedEnvelope {
    const MIN_ENCODED_LEN: usize = ENVELOPE_LEN;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(SealedEnvelope {
            version: r.u8()?,
            market: MarketId::decode(r)?,
            epoch: EpochId::decode(r)?,
            commitment: OrderCommitment::decode(r)?,
            ephemeral: r.array()?,
            ciphertext: r.array()?,
        })
    }
}
