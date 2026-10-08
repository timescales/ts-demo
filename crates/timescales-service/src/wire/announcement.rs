//! Relay-signed public statements: epoch announcements and refusals.
//!
//! ```text
//! EpochAnnouncement = ver u8 (1) || market32 || epoch u64 || opens_at_ms u64 || cutoff_ms u64
//!                     || PriceBand(24) || price_commitment32 || key_digest32 || committee_digest32
//!                     || relay32 || sig64
//! RelayRefusal      = market32 || epoch u64 || envelope_digest32 || code u8 || at_ms u64 || relay32 || sig64
//! ```
//!
//! Both are signed by the relay key over the bytes before the signature,
//! under `EPOCH_ANNOUNCEMENT` and `RELAY_REFUSAL` respectively. Either is
//! portable evidence: an announcement whose terms differ from the committed
//! `terms_digest`, or a refusal of intake the relay later denies.

use timescales_auction::{epoch_binding, terms_digest};
use timescales_core::crypto::{Hasher, Keypair, Signature, domain, verify_digest};
use timescales_core::{
    Decode, DecodeError, Encode, EpochId, Hash32, PriceBand, Reader, encoding::put_u8,
};

use crate::wire::WireError;

/// Relay-signed public announcement of an epoch's terms (evidence if the
/// committed terms differ).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochAnnouncement {
    pub version: u8,
    pub market: [u8; 32],
    pub epoch: EpochId,
    pub opens_at_ms: u64,
    pub cutoff_ms: u64,
    pub band: PriceBand,
    pub price_commitment: Hash32,
    pub key_digest: Hash32,
    pub committee_digest: Hash32,
    pub relay: [u8; 32],
    pub signature: Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnnouncementFields {
    pub market: [u8; 32],
    pub epoch: EpochId,
    pub opens_at_ms: u64,
    pub cutoff_ms: u64,
    pub band: PriceBand,
    pub price_commitment: Hash32,
    pub key_digest: Hash32,
    pub committee_digest: Hash32,
}

impl EpochAnnouncement {
    pub const VERSION: u8 = 1;
    pub const ENCODED_LEN: usize = 1 + 32 + 8 + 8 + 8 + 24 + 32 + 32 + 32 + 32 + 64;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;

    pub fn sign(fields: AnnouncementFields, relay: &Keypair) -> Self {
        let AnnouncementFields {
            market,
            epoch,
            opens_at_ms,
            cutoff_ms,
            band,
            price_commitment,
            key_digest,
            committee_digest,
        } = fields;
        let mut a = EpochAnnouncement {
            version: Self::VERSION,
            market,
            epoch,
            opens_at_ms,
            cutoff_ms,
            band,
            price_commitment,
            key_digest,
            committee_digest,
            relay: relay.public(),
            signature: Signature([0; 64]),
        };
        a.signature = relay.sign_digest(&a.signing_digest());
        a
    }

    /// `H(EPOCH_ANNOUNCEMENT, bytes before sig)`, what the relay signs.
    pub fn signing_digest(&self) -> Hash32 {
        Hasher::new(domain::EPOCH_ANNOUNCEMENT)
            .chain(&self.bytes_before_sig())
            .finalize()
    }

    /// The relay's signature (by the key in `relay`). The caller compares
    /// `relay` with `Market.relay`.
    pub fn verify(&self) -> Result<(), WireError> {
        if self.version != Self::VERSION {
            return Err(WireError::Version(self.version));
        }
        verify_digest(&self.relay, &self.signing_digest(), &self.signature)
            .map_err(|_| WireError::BadSignature)
    }

    /// `timescales_auction::epoch_binding(price_commitment, key_digest,
    /// committee_digest)`.
    pub fn binding(&self) -> Hash32 {
        epoch_binding(
            &self.price_commitment,
            &self.key_digest,
            &self.committee_digest,
        )
    }

    /// `timescales_auction::terms_digest(band, binding)`.
    pub fn terms_digest(&self) -> Hash32 {
        terms_digest(&self.band, &self.binding())
    }

    fn bytes_before_sig(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN - 64);
        put_u8(&mut out, self.version);
        out.extend_from_slice(&self.market);
        self.epoch.encode(&mut out);
        self.opens_at_ms.encode(&mut out);
        self.cutoff_ms.encode(&mut out);
        self.band.encode(&mut out);
        self.price_commitment.encode(&mut out);
        self.key_digest.encode(&mut out);
        self.committee_digest.encode(&mut out);
        out.extend_from_slice(&self.relay);
        out
    }
}

impl Encode for EpochAnnouncement {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes_before_sig());
        self.signature.encode(out);
    }
}

impl Decode for EpochAnnouncement {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.u8()? != Self::VERSION {
            return Err(DecodeError::InvalidValue("EpochAnnouncement.version"));
        }
        Ok(EpochAnnouncement {
            version: Self::VERSION,
            market: r.array()?,
            epoch: EpochId::decode(r)?,
            opens_at_ms: r.u64()?,
            cutoff_ms: r.u64()?,
            band: PriceBand::decode(r)?,
            price_commitment: Hash32::decode(r)?,
            key_digest: Hash32::decode(r)?,
            committee_digest: Hash32::decode(r)?,
            relay: r.array()?,
            signature: Signature::decode(r)?,
        })
    }
}

/// Relay-signed refusal (BATCH_FULL, INTAKE_PAUSED, QUOTA_EXCEEDED,
/// EPOCH_CLOSED): portable evidence of refused intake. The signature is over
/// H(RELAY_REFUSAL, bytes before sig). `code` is one of the constants below.
/// 0 is reserved, and decoding does not restrict it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayRefusal {
    pub market: [u8; 32],
    pub epoch: EpochId,
    pub envelope_digest: Hash32,
    pub code: u8,
    pub at_ms: u64,
    pub relay: [u8; 32],
    pub signature: Signature,
}

impl RelayRefusal {
    pub const ENCODED_LEN: usize = 32 + 8 + 32 + 1 + 8 + 32 + 64;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;

    /// The epoch's batch has no room left.
    pub const BATCH_FULL: u8 = 1;
    /// Intake of the market is paused.
    pub const INTAKE_PAUSED: u8 = 2;
    /// A quota of the submitting wallet is used up.
    pub const QUOTA_EXCEEDED: u8 = 3;
    /// The epoch closed before the envelope arrived.
    pub const EPOCH_CLOSED: u8 = 4;

    pub fn sign(
        market: [u8; 32],
        epoch: EpochId,
        envelope_digest: Hash32,
        code: u8,
        at_ms: u64,
        relay: &Keypair,
    ) -> Self {
        let mut r = RelayRefusal {
            market,
            epoch,
            envelope_digest,
            code,
            at_ms,
            relay: relay.public(),
            signature: Signature([0; 64]),
        };
        r.signature = relay.sign_digest(&r.signing_digest());
        r
    }

    /// `H(RELAY_REFUSAL, bytes before sig)`.
    pub fn signing_digest(&self) -> Hash32 {
        Hasher::new(domain::RELAY_REFUSAL)
            .chain(&self.bytes_before_sig())
            .finalize()
    }

    /// The relay's signature (by the key in `relay`).
    pub fn verify(&self) -> Result<(), WireError> {
        verify_digest(&self.relay, &self.signing_digest(), &self.signature)
            .map_err(|_| WireError::BadSignature)
    }

    fn bytes_before_sig(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN - 64);
        out.extend_from_slice(&self.market);
        self.epoch.encode(&mut out);
        self.envelope_digest.encode(&mut out);
        put_u8(&mut out, self.code);
        self.at_ms.encode(&mut out);
        out.extend_from_slice(&self.relay);
        out
    }
}

impl Encode for RelayRefusal {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes_before_sig());
        self.signature.encode(out);
    }
}

impl Decode for RelayRefusal {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(RelayRefusal {
            market: r.array()?,
            epoch: EpochId::decode(r)?,
            envelope_digest: Hash32::decode(r)?,
            code: r.u8()?,
            at_ms: r.u64()?,
            relay: r.array()?,
            signature: Signature::decode(r)?,
        })
    }
}
