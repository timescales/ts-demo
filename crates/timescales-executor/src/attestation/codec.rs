//! Canonical encodings of the attestation messages.
//!
//! `ExecutorAttestationV2` is
//! `executor32 || seal_key32 || header_digest32 || seq<nonce32> (<= 16) ||
//! committee_digest32 || Evidence`, and `Evidence` is
//! `platform u8 || bytes quote (<= 16 KiB)`. The in-process TEE path hashes
//! this encoding into the receipt's attestation digest.

use timescales_core::{Decode, DecodeError, Encode, ExecutorId, Hash32, Reader, encoding::put_seq};

use crate::attestation::{Evidence, ExecutorAttestationV2};

/// Most key-release members a committee can have (`n <= 16`).
pub const MAX_ATTESTED_NONCES: usize = 16;

impl Evidence {
    /// Platform tag and an empty quote.
    pub const MIN_ENCODED_LEN: usize = 1 + 4;
}

impl ExecutorAttestationV2 {
    /// No nonces and empty evidence.
    pub const MIN_ENCODED_LEN: usize = 32 + 32 + 32 + 4 + 32 + Evidence::MIN_ENCODED_LEN;
}

impl Encode for ExecutorAttestationV2 {
    fn encode(&self, out: &mut Vec<u8>) {
        let ExecutorAttestationV2 {
            executor,
            seal_key,
            header_digest,
            nonces,
            committee_digest,
            evidence,
        } = self;
        executor.encode(out);
        out.extend_from_slice(seal_key);
        header_digest.encode(out);
        put_seq(out, nonces);
        committee_digest.encode(out);
        evidence.encode(out);
    }
}

impl Decode for ExecutorAttestationV2 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ExecutorAttestationV2 {
            executor: ExecutorId::decode(r)?,
            seal_key: r.array()?,
            header_digest: Hash32::decode(r)?,
            nonces: r.seq(MAX_ATTESTED_NONCES)?,
            committee_digest: Hash32::decode(r)?,
            evidence: Evidence::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use timescales_core::encoding::{put_u8, put_u32};

    use super::*;
    use crate::attestation::simulated::SimulatedVendor;
    use crate::attestation::{MAX_EVIDENCE_LEN, Measurement, Platform, QuoteVerifier};

    fn attestation(nonces: usize, quote_len: usize) -> ExecutorAttestationV2 {
        ExecutorAttestationV2 {
            executor: ExecutorId([1; 32]),
            seal_key: [2; 32],
            header_digest: Hash32([3; 32]),
            nonces: (0..nonces).map(|i| Hash32([i as u8; 32])).collect(),
            committee_digest: Hash32([4; 32]),
            evidence: Evidence {
                platform: Platform::IntelTdx,
                quote: vec![9; quote_len],
            },
        }
    }

    #[test]
    fn codec_round_trips_with_real_simulated_evidence() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(11);
        let vendor = SimulatedVendor::new(&mut rng, 3);
        let platform = vendor.platform(&mut rng, 3);
        let mut att = attestation(3, 0);
        att.evidence = platform.quote(
            Measurement(Hash32([5; 32])),
            false,
            att.expected_report_data(),
        );
        let back = ExecutorAttestationV2::decode_exact(&att.to_bytes()).unwrap();
        assert_eq!(back, att);
        assert_eq!(back.digest(), att.digest());
        let report = vendor.verifier().verify(&back.evidence).unwrap();
        assert_eq!(report.report_data, att.expected_report_data());
    }

    #[test]
    fn codec_min_and_max_lengths() {
        let empty = attestation(0, 0);
        assert_eq!(
            empty.to_bytes().len(),
            ExecutorAttestationV2::MIN_ENCODED_LEN
        );
        assert_eq!(
            ExecutorAttestationV2::decode_exact(&empty.to_bytes()).unwrap(),
            empty
        );
        //  #13: the largest attestation inside a ReleaseRequest.
        let full = attestation(MAX_ATTESTED_NONCES, MAX_EVIDENCE_LEN);
        assert_eq!(full.to_bytes().len(), 17_033);
        assert_eq!(
            ExecutorAttestationV2::decode_exact(&full.to_bytes()).unwrap(),
            full
        );
    }

    #[test]
    fn codec_bounds_nonces_and_evidence_before_allocating() {
        let mut bytes = attestation(0, 0).to_bytes();
        // The nonce count sits after executor, seal key and header digest.
        bytes[96..100].copy_from_slice(&(MAX_ATTESTED_NONCES as u32 + 1).to_le_bytes());
        assert_eq!(
            ExecutorAttestationV2::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded {
                len: MAX_ATTESTED_NONCES + 1,
                max: MAX_ATTESTED_NONCES
            })
        );

        let mut quote = Vec::new();
        put_u8(&mut quote, Platform::Simulated as u8);
        put_u32(&mut quote, u32::MAX);
        assert_eq!(
            Evidence::decode_exact(&quote),
            Err(DecodeError::LengthExceeded {
                len: u32::MAX as usize,
                max: MAX_EVIDENCE_LEN
            })
        );
    }

    #[test]
    fn codec_rejects_an_unknown_platform_tag() {
        let mut bytes = attestation(1, 4).to_bytes();
        let tag_at = bytes.len() - 4 - 4 - 1;
        bytes[tag_at] = 4;
        assert_eq!(
            ExecutorAttestationV2::decode_exact(&bytes),
            Err(DecodeError::InvalidTag {
                ty: "Platform",
                tag: 4
            })
        );
    }

    #[test]
    fn codec_rejects_trailing_and_missing_bytes() {
        let mut bytes = attestation(2, 8).to_bytes();
        bytes.push(0);
        assert_eq!(
            ExecutorAttestationV2::decode_exact(&bytes),
            Err(DecodeError::TrailingBytes(1))
        );
        bytes.truncate(bytes.len() - 2);
        assert!(matches!(
            ExecutorAttestationV2::decode_exact(&bytes),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }
}
