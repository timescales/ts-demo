//! Canonical encoding of price commitments.
//!
//! `market u64 || epoch u64 || reference u64 || seq<(source u32 || tick u64 ||
//! time u64)> (<= 64) || proofs32`. The encoding carries exactly the fields
//! [`PriceCommitment::digest`] hashes, so a decoded commitment has the same
//! digest as the one that was encoded.

use crate::{
    Decode, DecodeError, Encode, EpochId, Hash32, MarketId, Reader, Tick,
    encoding::{put_seq, put_u32},
};

use crate::oracle::{Observation, PriceCommitment};

/// Most observations one commitment may carry (one per configured source).
pub const MAX_OBSERVATIONS: usize = 64;

impl Observation {
    pub const ENCODED_LEN: usize = 4 + 8 + 8;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
}

impl PriceCommitment {
    /// No observations.
    pub const MIN_ENCODED_LEN: usize = 8 + 8 + 8 + 4 + 32;
}

impl Encode for Observation {
    fn encode(&self, out: &mut Vec<u8>) {
        let Observation { source, tick, time } = self;
        put_u32(out, *source);
        tick.encode(out);
        time.encode(out);
    }
}

impl Decode for Observation {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Observation {
            source: r.u32()?,
            tick: Tick::decode(r)?,
            time: r.u64()?,
        })
    }
}

impl Encode for PriceCommitment {
    fn encode(&self, out: &mut Vec<u8>) {
        let PriceCommitment {
            market,
            epoch,
            reference,
            observations,
            proofs,
        } = self;
        market.encode(out);
        epoch.encode(out);
        reference.encode(out);
        put_seq(out, observations);
        proofs.encode(out);
    }
}

impl Decode for PriceCommitment {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(PriceCommitment {
            market: MarketId::decode(r)?,
            epoch: EpochId::decode(r)?,
            reference: Tick::decode(r)?,
            observations: r.seq(MAX_OBSERVATIONS)?,
            proofs: Hash32::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment(n: usize) -> PriceCommitment {
        PriceCommitment {
            market: MarketId(3),
            epoch: EpochId(41),
            reference: Tick(10_005),
            observations: (0..n)
                .map(|i| Observation {
                    source: i as u32 + 1,
                    tick: Tick(10_000 + i as u64),
                    time: 1_700_000_000 + i as u64,
                })
                .collect(),
            proofs: Hash32([7; 32]),
        }
    }

    #[test]
    fn codec_round_trips_and_keeps_the_digest() {
        let pc = commitment(5);
        let back = PriceCommitment::decode_exact(&pc.to_bytes()).unwrap();
        assert_eq!(back, pc);
        assert_eq!(back.digest(), pc.digest());
    }

    #[test]
    fn codec_min_and_max_lengths() {
        let empty = commitment(0);
        assert_eq!(empty.to_bytes().len(), PriceCommitment::MIN_ENCODED_LEN);
        assert_eq!(
            PriceCommitment::decode_exact(&empty.to_bytes()).unwrap(),
            empty
        );
        //  #19: 1,340 bytes with the most observations.
        let full = commitment(MAX_OBSERVATIONS);
        assert_eq!(full.to_bytes().len(), 1_340);
        assert_eq!(
            PriceCommitment::decode_exact(&full.to_bytes()).unwrap(),
            full
        );
    }

    #[test]
    fn codec_bounds_the_observation_count_before_allocating() {
        let mut bytes = commitment(0).to_bytes();
        bytes[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            PriceCommitment::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded {
                len: u32::MAX as usize,
                max: MAX_OBSERVATIONS
            })
        );
        let mut bytes = commitment(MAX_OBSERVATIONS).to_bytes();
        bytes[24..28].copy_from_slice(&(MAX_OBSERVATIONS as u32 + 1).to_le_bytes());
        assert!(matches!(
            PriceCommitment::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded { .. })
        ));
    }

    #[test]
    fn codec_rejects_trailing_and_missing_bytes() {
        let mut bytes = commitment(2).to_bytes();
        bytes.push(0);
        assert_eq!(
            PriceCommitment::decode_exact(&bytes),
            Err(DecodeError::TrailingBytes(1))
        );
        bytes.truncate(bytes.len() - 2);
        assert!(matches!(
            PriceCommitment::decode_exact(&bytes),
            Err(DecodeError::UnexpectedEof { .. })
        ));
        let o = Observation {
            source: 1,
            tick: Tick(2),
            time: 3,
        };
        assert_eq!(o.to_bytes().len(), Observation::ENCODED_LEN);
        assert_eq!(Observation::decode_exact(&o.to_bytes()).unwrap(), o);
    }
}
