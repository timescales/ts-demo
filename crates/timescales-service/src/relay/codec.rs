//! Canonical encodings of relay messages: inclusion promises v1 and v2 and
//! the persisted closed batch.
//!
//! ```text
//! InclusionPromiseV2 = ver u8 (2) || market32 || epoch u64 || C32 || envelope_digest32 || relay32 || sig64
//! InclusionPromise   = market u64 || epoch u64 || C32 || relay32 || sig64
//! ClosedBatch        = ver u8 (1) || market u64 || market32 || epoch u64 || params46 || band24
//!                      || price_commitment32 || binding32 || opens_at u64 || cutoff u64
//!                      || seq<SealedEnvelope> (<= 1024) || seq<submitter32> (= envelope count)
//!                      || real u32 || cover u32
//! ```
//!
//! A closed batch does not store its leaves or root: decoding recomputes
//! them from the envelopes, so a stored batch cannot disagree with the root
//! the node commits. Cover envelopes, and only they, have an all-zero
//! submitter, so `cover` counts the zero submitters.

use timescales_auction::{BatchLeaf, batch_root_v2};
use timescales_core::crypto::Signature;
use timescales_core::intent::{ENVELOPE_LEN, SealedEnvelope};
use timescales_core::{
    Decode, DecodeError, Encode, EpochId, Hash32, MAX_SETTLEMENT_DELTAS, MarketId, MarketParams,
    OrderCommitment, PriceBand, Reader,
    encoding::{put_seq, put_u8, put_u32},
};

use crate::relay::{ClosedBatch, InclusionPromise, InclusionPromiseV2};

/// Most envelopes a closed batch holds: one settlement leaf each at most.
pub const MAX_CLOSED_ENVELOPES: usize = MAX_SETTLEMENT_DELTAS as usize;

impl InclusionPromise {
    pub const ENCODED_LEN: usize = 8 + 8 + 32 + 32 + 64;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
}

impl InclusionPromiseV2 {
    /// The version byte that opens every encoded v2 promise.
    pub const VERSION: u8 = 2;
    pub const ENCODED_LEN: usize = 1 + 32 + 8 + 32 + 32 + 32 + 64;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
}

impl ClosedBatch {
    pub const VERSION: u8 = 1;
    /// An empty batch.
    pub const MIN_ENCODED_LEN: usize = 1 + 8 + 32 + 8 + 46 + 24 + 32 + 32 + 8 + 8 + 4 + 4 + 4 + 4;
}

impl Encode for InclusionPromise {
    fn encode(&self, out: &mut Vec<u8>) {
        let InclusionPromise {
            market,
            epoch,
            commitment,
            relay,
            signature,
        } = self;
        market.encode(out);
        epoch.encode(out);
        commitment.encode(out);
        out.extend_from_slice(relay);
        signature.encode(out);
    }
}

impl Decode for InclusionPromise {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(InclusionPromise {
            market: MarketId::decode(r)?,
            epoch: EpochId::decode(r)?,
            commitment: OrderCommitment::decode(r)?,
            relay: r.array()?,
            signature: Signature::decode(r)?,
        })
    }
}

impl Encode for InclusionPromiseV2 {
    fn encode(&self, out: &mut Vec<u8>) {
        let InclusionPromiseV2 {
            market,
            epoch,
            commitment,
            envelope_digest,
            relay,
            signature,
        } = self;
        put_u8(out, Self::VERSION);
        out.extend_from_slice(market);
        epoch.encode(out);
        commitment.encode(out);
        envelope_digest.encode(out);
        out.extend_from_slice(relay);
        signature.encode(out);
    }
}

impl Decode for InclusionPromiseV2 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.u8()? != Self::VERSION {
            return Err(DecodeError::InvalidValue("InclusionPromiseV2.version"));
        }
        Ok(InclusionPromiseV2 {
            market: r.array()?,
            epoch: EpochId::decode(r)?,
            commitment: OrderCommitment::decode(r)?,
            envelope_digest: Hash32::decode(r)?,
            relay: r.array()?,
            signature: Signature::decode(r)?,
        })
    }
}

impl Encode for ClosedBatch {
    fn encode(&self, out: &mut Vec<u8>) {
        let ClosedBatch {
            market_address,
            epoch,
            params,
            band,
            price_commitment,
            binding,
            opens_at_ms,
            cutoff_ms,
            envelopes,
            submitters,
            leaves: _,
            root: _,
            real,
            cover,
        } = self;
        put_u8(out, Self::VERSION);
        params.market.encode(out);
        out.extend_from_slice(market_address);
        epoch.encode(out);
        params.encode(out);
        band.encode(out);
        price_commitment.encode(out);
        binding.encode(out);
        opens_at_ms.encode(out);
        cutoff_ms.encode(out);
        put_seq(out, envelopes);
        put_seq(out, submitters);
        put_u32(out, *real);
        put_u32(out, *cover);
    }
}

impl Decode for ClosedBatch {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.u8()? != Self::VERSION {
            return Err(DecodeError::InvalidValue("ClosedBatch.version"));
        }
        let market = MarketId::decode(r)?;
        let market_address = r.array()?;
        let epoch = EpochId::decode(r)?;
        let params = MarketParams::decode(r)?;
        if params.market != market {
            return Err(DecodeError::InvalidValue("ClosedBatch.market"));
        }
        let band = PriceBand::decode(r)?;
        let price_commitment = Hash32::decode(r)?;
        let binding = Hash32::decode(r)?;
        let opens_at_ms = r.u64()?;
        let cutoff_ms = r.u64()?;

        let count = r.len_prefix(MAX_CLOSED_ENVELOPES)?;
        if count > r.remaining() / ENVELOPE_LEN {
            return Err(DecodeError::UnexpectedEof {
                needed: count.saturating_mul(ENVELOPE_LEN),
                remaining: r.remaining(),
            });
        }
        let mut envelopes = Vec::with_capacity(count);
        for _ in 0..count {
            let e = SealedEnvelope::decode(r)?;
            if e.market != market || e.epoch != epoch {
                return Err(DecodeError::InvalidValue("ClosedBatch.envelopes"));
            }
            envelopes.push(e);
        }
        if r.len_prefix(MAX_CLOSED_ENVELOPES)? != count {
            return Err(DecodeError::InvalidValue("ClosedBatch.submitters"));
        }
        let mut submitters = Vec::with_capacity(count);
        for _ in 0..count {
            submitters.push(r.array()?);
        }
        let real = r.u32()?;
        let cover = r.u32()?;
        if real
            .checked_add(cover)
            .and_then(|n| usize::try_from(n).ok())
            != Some(count)
        {
            return Err(DecodeError::InvalidValue("ClosedBatch.counts"));
        }
        // Cover, and only cover, has no submitter.
        let unsubmitted = submitters.iter().filter(|s| **s == [0; 32]).count();
        if usize::try_from(cover).ok() != Some(unsubmitted) {
            return Err(DecodeError::InvalidValue("ClosedBatch.cover"));
        }

        let mut leaves: Vec<BatchLeaf> = envelopes.iter().map(BatchLeaf::of).collect();
        leaves.sort_unstable_by_key(BatchLeaf::to_bytes);
        let root = batch_root_v2(&leaves);
        Ok(ClosedBatch {
            market_address,
            epoch,
            params,
            band,
            price_commitment,
            binding,
            opens_at_ms,
            cutoff_ms,
            envelopes,
            submitters,
            leaves,
            root,
            real,
            cover,
        })
    }
}

#[cfg(test)]
mod tests {
    use timescales_auction::epoch_binding;
    use timescales_core::intent::CIPHERTEXT_LEN;
    use timescales_core::{CommitmentScheme, FeeBps, FlowMode, Rationing, Tick};

    use super::*;

    fn params() -> MarketParams {
        MarketParams {
            market: MarketId(12),
            base_lot_size: 1_000,
            tick_size: 10,
            band_half_width: 8,
            max_order_lots_log2: 20,
            max_orders_per_trader: 16,
            max_batch_envelopes: 1024,
            max_order_lifetime: 32,
            maker_fee: FeeBps(1),
            taker_fee: FeeBps(4),
            flow: FlowMode::DualFlow,
            rationing: Rationing::ProRata,
            commitment_scheme: CommitmentScheme::Sha256,
        }
    }

    fn envelope(i: usize) -> SealedEnvelope {
        let b = (i % 251) as u8;
        SealedEnvelope {
            version: 1,
            market: MarketId(12),
            epoch: EpochId(30),
            commitment: OrderCommitment([b; 32]),
            ephemeral: [b.wrapping_add(1); 32],
            ciphertext: [b.wrapping_add(2); CIPHERTEXT_LEN],
        }
    }

    fn closed(real: usize, cover: usize) -> ClosedBatch {
        let envelopes: Vec<SealedEnvelope> = (0..real + cover).map(envelope).collect();
        let submitters = (0..real + cover)
            .map(|i| {
                if i < real {
                    [(i % 200) as u8 + 1; 32]
                } else {
                    [0; 32]
                }
            })
            .collect();
        let mut leaves: Vec<BatchLeaf> = envelopes.iter().map(BatchLeaf::of).collect();
        leaves.sort_unstable_by_key(BatchLeaf::to_bytes);
        let p = params();
        let price_commitment = Hash32([3; 32]);
        ClosedBatch {
            market_address: [44; 32],
            epoch: EpochId(30),
            params: p,
            band: p.band(Tick(1_000)).unwrap(),
            price_commitment,
            binding: epoch_binding(&price_commitment, &Hash32([4; 32]), &Hash32([5; 32])),
            opens_at_ms: 1_700_000_000_000,
            cutoff_ms: 1_700_000_002_000,
            envelopes,
            submitters,
            root: batch_root_v2(&leaves),
            leaves,
            real: u32::try_from(real).unwrap(),
            cover: u32::try_from(cover).unwrap(),
        }
    }

    fn same(a: &ClosedBatch, b: &ClosedBatch) {
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert_eq!(a.leaves, b.leaves);
        assert_eq!(a.root, b.root);
    }

    #[test]
    fn codec_promise_v1_round_trips() {
        let p = InclusionPromise {
            market: MarketId(1),
            epoch: EpochId(2),
            commitment: OrderCommitment([3; 32]),
            relay: [4; 32],
            signature: Signature([5; 64]),
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), InclusionPromise::ENCODED_LEN);
        assert_eq!(bytes.len(), 144);
        assert_eq!(InclusionPromise::decode_exact(&bytes), Ok(p));
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            InclusionPromise::decode_exact(&long),
            Err(DecodeError::TrailingBytes(1))
        );
        assert!(matches!(
            InclusionPromise::decode_exact(&bytes[..143]),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn codec_promise_v2_round_trips_with_its_version_byte() {
        let p = InclusionPromiseV2 {
            market: [1; 32],
            epoch: EpochId(2),
            commitment: OrderCommitment([3; 32]),
            envelope_digest: envelope(3).digest(),
            relay: [4; 32],
            signature: Signature([5; 64]),
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), InclusionPromiseV2::ENCODED_LEN);
        assert_eq!(bytes.len(), 201);
        assert_eq!(bytes[0], 2);
        assert_eq!(&bytes[1..33], &[1; 32]);
        assert_eq!(InclusionPromiseV2::decode_exact(&bytes), Ok(p));

        for v in [0u8, 1, 3] {
            let mut b = bytes.clone();
            b[0] = v;
            assert_eq!(
                InclusionPromiseV2::decode_exact(&b),
                Err(DecodeError::InvalidValue("InclusionPromiseV2.version"))
            );
        }
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            InclusionPromiseV2::decode_exact(&long),
            Err(DecodeError::TrailingBytes(1))
        );
    }

    #[test]
    fn codec_closed_batch_round_trips_and_recomputes_leaves() {
        let cb = closed(5, 3);
        let bytes = cb.to_bytes();
        let back = ClosedBatch::decode_exact(&bytes).unwrap();
        same(&back, &cb);
        assert_eq!(back.market_address, cb.market_address);
        assert_eq!(back.submitters, cb.submitters);
        assert_eq!((back.real, back.cover), (5, 3));
        assert!(
            back.leaves
                .windows(2)
                .all(|w| w[0].to_bytes() <= w[1].to_bytes())
        );
    }

    #[test]
    fn codec_closed_batch_does_not_trust_stored_leaves() {
        let mut cb = closed(2, 2);
        cb.root = Hash32([0xee; 32]);
        cb.leaves.clear();
        let back = ClosedBatch::decode_exact(&cb.to_bytes()).unwrap();
        same(&back, &closed(2, 2));
    }

    #[test]
    fn codec_closed_batch_min_and_max_lengths() {
        let empty = closed(0, 0);
        assert_eq!(empty.to_bytes().len(), ClosedBatch::MIN_ENCODED_LEN);
        same(
            &ClosedBatch::decode_exact(&empty.to_bytes()).unwrap(),
            &empty,
        );

        let full = closed(1000, MAX_CLOSED_ENVELOPES - 1000);
        let bytes = full.to_bytes();
        assert_eq!(
            bytes.len(),
            ClosedBatch::MIN_ENCODED_LEN + MAX_CLOSED_ENVELOPES * (ENVELOPE_LEN + 32)
        );
        same(&ClosedBatch::decode_exact(&bytes).unwrap(), &full);
    }

    #[test]
    fn codec_closed_batch_bounds_envelopes_before_allocating() {
        let cb = closed(0, 0);
        let count_at = ClosedBatch::MIN_ENCODED_LEN - 16;
        let mut bytes = cb.to_bytes();
        bytes[count_at..count_at + 4]
            .copy_from_slice(&(MAX_CLOSED_ENVELOPES as u32 + 1).to_le_bytes());
        assert_eq!(
            ClosedBatch::decode_exact(&bytes).map(|_| ()),
            Err(DecodeError::LengthExceeded {
                len: MAX_CLOSED_ENVELOPES + 1,
                max: MAX_CLOSED_ENVELOPES
            })
        );
        let mut bytes = cb.to_bytes();
        bytes[count_at..count_at + 4].copy_from_slice(&1000u32.to_le_bytes());
        assert!(matches!(
            ClosedBatch::decode_exact(&bytes),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn codec_closed_batch_checks_counts_and_consistency() {
        let mut cb = closed(2, 1);
        cb.real = 3;
        assert_eq!(
            ClosedBatch::decode_exact(&cb.to_bytes()).map(|_| ()),
            Err(DecodeError::InvalidValue("ClosedBatch.counts"))
        );
        let mut cb = closed(2, 1);
        cb.cover = u32::MAX;
        assert_eq!(
            ClosedBatch::decode_exact(&cb.to_bytes()).map(|_| ()),
            Err(DecodeError::InvalidValue("ClosedBatch.counts"))
        );
        let mut cb = closed(2, 1);
        cb.submitters.pop();
        assert_eq!(
            ClosedBatch::decode_exact(&cb.to_bytes()).map(|_| ()),
            Err(DecodeError::InvalidValue("ClosedBatch.submitters"))
        );
        // The cover count is the number of envelopes nobody submitted.
        let mut relabelled = closed(2, 1);
        (relabelled.real, relabelled.cover) = (1, 2);
        let mut anonymous = closed(2, 1);
        anonymous.submitters[0] = [0; 32];
        let mut claimed = closed(2, 1);
        claimed.submitters[2] = [5; 32];
        for cb in [relabelled, anonymous, claimed] {
            assert_eq!(
                ClosedBatch::decode_exact(&cb.to_bytes()).map(|_| ()),
                Err(DecodeError::InvalidValue("ClosedBatch.cover"))
            );
        }
        let mut cb = closed(2, 1);
        cb.envelopes[1].epoch = EpochId(31);
        assert_eq!(
            ClosedBatch::decode_exact(&cb.to_bytes()).map(|_| ()),
            Err(DecodeError::InvalidValue("ClosedBatch.envelopes"))
        );
        let mut cb = closed(2, 1);
        cb.envelopes[0].market = MarketId(13);
        assert_eq!(
            ClosedBatch::decode_exact(&cb.to_bytes()).map(|_| ()),
            Err(DecodeError::InvalidValue("ClosedBatch.envelopes"))
        );
    }

    #[test]
    fn codec_closed_batch_rejects_bad_versions_tags_and_markets() {
        let cb = closed(1, 1);
        let mut bytes = cb.to_bytes();
        bytes[0] = 2;
        assert_eq!(
            ClosedBatch::decode_exact(&bytes).map(|_| ()),
            Err(DecodeError::InvalidValue("ClosedBatch.version"))
        );
        let mut bytes = cb.to_bytes();
        bytes[1] ^= 1;
        assert_eq!(
            ClosedBatch::decode_exact(&bytes).map(|_| ()),
            Err(DecodeError::InvalidValue("ClosedBatch.market"))
        );
        // The last byte of the parameters is the commitment scheme tag.
        let scheme_at = 1 + 8 + 32 + 8 + 45;
        let mut bytes = cb.to_bytes();
        bytes[scheme_at] = 7;
        assert_eq!(
            ClosedBatch::decode_exact(&bytes).map(|_| ()),
            Err(DecodeError::InvalidTag {
                ty: "CommitmentScheme",
                tag: 7
            })
        );
        let mut bytes = cb.to_bytes();
        bytes.push(0);
        assert_eq!(
            ClosedBatch::decode_exact(&bytes).map(|_| ()),
            Err(DecodeError::TrailingBytes(1))
        );
        bytes.truncate(bytes.len() - 2);
        assert!(matches!(
            ClosedBatch::decode_exact(&bytes),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }
}
