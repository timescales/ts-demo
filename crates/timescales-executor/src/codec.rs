//! Canonical encodings of execution results and proof artifacts.
//!
//! ```text
//! ExecutionResult = receipt || artifacts || u8 || [bytes attestation (<= 64 KiB)]
//!                   || u8 || [ProofArtifact] || u32 accepted || u32 rejected
//!                   || seq<u32> unauthenticated (<= 1024)
//!                   || seq<(bytes name (<= 32) || u64 us)> (<= 32)
//! ProofArtifact   = digest32 || bytes proof (<= 1 MiB)
//! ```
//!
//! Metrics are diagnostics, so their encoding saturates instead of failing:
//! counts above `u32::MAX` are written as `u32::MAX`, stage names are cut to
//! 32 bytes at a character boundary, durations are kept in whole
//! microseconds, and only the first 32 stages are written. A header
//! version 2 batch holds at most 1024 envelopes, so its unauthenticated
//! indices always fit. For larger version 1 batches only the first 1024 are
//! written.

use std::borrow::Cow;
use std::time::Duration;

use timescales_auction::receipts::{ExecutionArtifacts, ExecutionReceipt};
use timescales_core::{
    Decode, DecodeError, Encode, Hash32, MAX_SETTLEMENT_DELTAS, Reader,
    encoding::{put_bool, put_bytes, put_u32, put_u64},
};

use crate::{ExecutionMetrics, ExecutionResult, ProofArtifact};

/// Largest attestation a result carries.
pub const MAX_RESULT_ATTESTATION_LEN: usize = 64 * 1024;
/// Largest proof a result carries.
pub const MAX_PROOF_LEN: usize = 1024 * 1024;
/// Most unauthenticated envelope indices a result reports.
pub const MAX_UNAUTHENTICATED: usize = MAX_SETTLEMENT_DELTAS as usize;
/// Most pipeline stages a result reports.
pub const MAX_STAGES: usize = 32;
/// Longest stage name.
pub const MAX_STAGE_NAME_LEN: usize = 32;

impl ProofArtifact {
    pub const MIN_ENCODED_LEN: usize = 32 + 4;
}

impl ExecutionResult {
    /// A receipt without clearing prices (390 bytes), empty artifacts (36),
    /// both option flags, both counts and two empty lists.
    pub const MIN_ENCODED_LEN: usize = 390 + 36 + 1 + 1 + 4 + 4 + 4 + 4;
}

impl Encode for ProofArtifact {
    fn encode(&self, out: &mut Vec<u8>) {
        let ProofArtifact { digest, bytes } = self;
        digest.encode(out);
        put_bytes(out, bytes);
    }
}

impl Decode for ProofArtifact {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ProofArtifact {
            digest: Hash32::decode(r)?,
            bytes: r.bytes(MAX_PROOF_LEN)?,
        })
    }
}

impl Encode for ExecutionResult {
    fn encode(&self, out: &mut Vec<u8>) {
        let ExecutionResult {
            receipt,
            artifacts,
            metrics,
            attestation,
            proof,
        } = self;
        let ExecutionMetrics {
            stages,
            accepted,
            rejected,
            unauthenticated,
        } = metrics;
        receipt.encode(out);
        artifacts.encode(out);
        put_bool(out, attestation.is_some());
        if let Some(a) = attestation {
            put_bytes(out, a);
        }
        put_bool(out, proof.is_some());
        if let Some(p) = proof {
            p.encode(out);
        }
        put_u32(out, saturating_u32(*accepted));
        put_u32(out, saturating_u32(*rejected));
        let unauthenticated = &unauthenticated[..unauthenticated.len().min(MAX_UNAUTHENTICATED)];
        put_u32(out, saturating_u32(unauthenticated.len()));
        for i in unauthenticated {
            put_u32(out, *i);
        }
        let stages = &stages[..stages.len().min(MAX_STAGES)];
        put_u32(out, saturating_u32(stages.len()));
        for (name, took) in stages {
            put_bytes(out, truncate_utf8(name, MAX_STAGE_NAME_LEN).as_bytes());
            put_u64(out, u64::try_from(took.as_micros()).unwrap_or(u64::MAX));
        }
    }
}

impl Decode for ExecutionResult {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let receipt = ExecutionReceipt::decode(r)?;
        let artifacts = ExecutionArtifacts::decode(r)?;
        let attestation = if r.bool()? {
            Some(r.bytes(MAX_RESULT_ATTESTATION_LEN)?)
        } else {
            None
        };
        let proof = if r.bool()? {
            Some(ProofArtifact::decode(r)?)
        } else {
            None
        };
        let accepted = widen(r.u32()?);
        let rejected = widen(r.u32()?);
        let count = r.len_prefix(MAX_UNAUTHENTICATED)?;
        let mut unauthenticated = Vec::with_capacity(count.min(r.remaining() / 4));
        for _ in 0..count {
            unauthenticated.push(r.u32()?);
        }
        let count = r.len_prefix(MAX_STAGES)?;
        let mut stages = Vec::with_capacity(count);
        for _ in 0..count {
            let name = String::from_utf8(r.bytes(MAX_STAGE_NAME_LEN)?)
                .map_err(|_| DecodeError::InvalidValue("ExecutionResult.stage"))?;
            stages.push((Cow::Owned(name), Duration::from_micros(r.u64()?)));
        }
        Ok(ExecutionResult {
            receipt,
            artifacts,
            metrics: ExecutionMetrics {
                stages,
                accepted,
                rejected,
                unauthenticated,
            },
            attestation,
            proof,
        })
    }
}

fn saturating_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn widen(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
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
    use timescales_auction::receipts::{
        BackendKind, ExecutionOutcome, commitments_root, fills_root,
    };
    use timescales_auction::settlement::{AccountDelta, SettlementBatch};
    use timescales_core::crypto::Signature;
    use timescales_core::{
        BookId, ClearingPrice, EpochId, ExecutorId, Fill, Lots, MarketId, OrderCommitment,
        QuoteAtoms, Role, Side, Tick, TraderId,
    };

    use super::*;

    fn artifacts(fills: usize) -> ExecutionArtifacts {
        let fills = (0..fills)
            .map(|i| Fill {
                commitment: OrderCommitment([i as u8; 32]),
                trader: TraderId([7; 32]),
                book: BookId::MakerAskTakerBid,
                side: Side::Buy,
                role: Role::Taker,
                quantity: Lots(3),
                tick: Tick(100),
            })
            .collect();
        ExecutionArtifacts {
            fills,
            cancelled: vec![OrderCommitment([9; 32])],
            settlement: SettlementBatch {
                market: MarketId(1),
                epoch: EpochId(2),
                deltas: vec![
                    AccountDelta {
                        trader: TraderId([1; 32]),
                        base: 3_000,
                        quote: -3_005,
                    },
                    AccountDelta {
                        trader: TraderId([2; 32]),
                        base: -3_000,
                        quote: 3_000,
                    },
                ],
                fees: QuoteAtoms(5),
            },
        }
    }

    fn receipt(clearing: usize, a: &ExecutionArtifacts) -> ExecutionReceipt {
        ExecutionReceipt {
            version: 1,
            outcome: ExecutionOutcome {
                market: MarketId(1),
                epoch: EpochId(2),
                header_digest: Hash32([3; 32]),
                clearing: (0..clearing)
                    .map(|i| ClearingPrice {
                        book: BookId::DUAL[i % 2],
                        tick: Tick(100),
                        volume: Lots(3),
                    })
                    .collect(),
                fill_count: u32::try_from(a.fills.len()).unwrap(),
                fills_root: fills_root(&a.fills),
                cancelled_root: commitments_root(&a.cancelled),
                next_state_root: Hash32([4; 32]),
                settlement_count: u32::try_from(a.settlement.deltas.len()).unwrap(),
                settlement_root: a.settlement.root(),
                fees: a.settlement.fees,
            },
            backend: BackendKind::Tee,
            executor: ExecutorId([5; 32]),
            attestation: Hash32([6; 32]),
            proof: Hash32([7; 32]),
            trace: Hash32([8; 32]),
            signature: Signature([9; 64]),
        }
    }

    fn full() -> ExecutionResult {
        let artifacts = artifacts(2);
        ExecutionResult {
            receipt: receipt(2, &artifacts),
            artifacts,
            metrics: ExecutionMetrics {
                stages: vec![
                    (Cow::Borrowed("open"), Duration::from_micros(1_250)),
                    (Cow::Owned("match".to_owned()), Duration::from_secs(2)),
                ],
                accepted: 2,
                rejected: 1,
                unauthenticated: vec![0, 3],
            },
            attestation: Some(vec![1, 2, 3]),
            proof: Some(ProofArtifact {
                digest: Hash32([10; 32]),
                bytes: vec![4; 100],
            }),
        }
    }

    fn minimal() -> ExecutionResult {
        let artifacts = ExecutionArtifacts {
            fills: Vec::new(),
            cancelled: Vec::new(),
            settlement: SettlementBatch {
                market: MarketId(1),
                epoch: EpochId(2),
                deltas: Vec::new(),
                fees: QuoteAtoms(0),
            },
        };
        ExecutionResult {
            receipt: receipt(0, &artifacts),
            artifacts,
            metrics: ExecutionMetrics::default(),
            attestation: None,
            proof: None,
        }
    }

    fn same(a: &ExecutionResult, b: &ExecutionResult) {
        assert_eq!(a.receipt, b.receipt);
        assert_eq!(a.artifacts, b.artifacts);
        assert_eq!(a.metrics.stages, b.metrics.stages);
        assert_eq!(a.metrics.accepted, b.metrics.accepted);
        assert_eq!(a.metrics.rejected, b.metrics.rejected);
        assert_eq!(a.metrics.unauthenticated, b.metrics.unauthenticated);
        assert_eq!(a.attestation, b.attestation);
        assert_eq!(a.proof, b.proof);
    }

    /// Offset of the attestation flag: right after receipt and artifacts.
    fn optional_parts_at(r: &ExecutionResult) -> usize {
        r.receipt.to_bytes().len() + r.artifacts.to_bytes().len()
    }

    #[test]
    fn codec_execution_result_round_trips() {
        let r = full();
        let bytes = r.to_bytes();
        let back = ExecutionResult::decode_exact(&bytes).unwrap();
        same(&back, &r);
        assert_eq!(back.to_bytes(), bytes);
        assert!(back.artifacts.check_against(&back.receipt.outcome).is_ok());
        assert_eq!(back.metrics.stage("match"), Some(Duration::from_secs(2)));
    }

    #[test]
    fn codec_execution_result_min_length() {
        let r = minimal();
        assert_eq!(r.to_bytes().len(), ExecutionResult::MIN_ENCODED_LEN);
        same(&ExecutionResult::decode_exact(&r.to_bytes()).unwrap(), &r);
    }

    #[test]
    fn codec_execution_result_bounds_attestation_and_proof() {
        let mut r = minimal();
        r.attestation = Some(vec![0; MAX_RESULT_ATTESTATION_LEN]);
        r.proof = Some(ProofArtifact {
            digest: Hash32::ZERO,
            bytes: vec![0; MAX_PROOF_LEN],
        });
        same(&ExecutionResult::decode_exact(&r.to_bytes()).unwrap(), &r);

        let mut r = minimal();
        r.attestation = Some(vec![0; MAX_RESULT_ATTESTATION_LEN + 1]);
        assert!(matches!(
            ExecutionResult::decode_exact(&r.to_bytes()),
            Err(DecodeError::LengthExceeded { .. })
        ));
        let mut r = minimal();
        r.proof = Some(ProofArtifact {
            digest: Hash32::ZERO,
            bytes: vec![0; MAX_PROOF_LEN + 1],
        });
        assert!(matches!(
            ExecutionResult::decode_exact(&r.to_bytes()),
            Err(DecodeError::LengthExceeded { .. })
        ));

        // A hostile attestation length is refused before anything is read.
        let r = minimal();
        let mut bytes = r.to_bytes();
        let at = optional_parts_at(&r);
        bytes[at] = 1;
        bytes.splice(at + 1..at + 1, u32::MAX.to_le_bytes());
        assert_eq!(
            ExecutionResult::decode_exact(&bytes).map(|_| ()),
            Err(DecodeError::LengthExceeded {
                len: u32::MAX as usize,
                max: MAX_RESULT_ATTESTATION_LEN
            })
        );
    }

    #[test]
    fn codec_execution_result_rejects_bad_option_flags() {
        let r = minimal();
        for offset in [0, 1] {
            let mut bytes = r.to_bytes();
            bytes[optional_parts_at(&r) + offset] = 2;
            assert_eq!(
                ExecutionResult::decode_exact(&bytes).map(|_| ()),
                Err(DecodeError::InvalidTag { ty: "bool", tag: 2 })
            );
        }
    }

    #[test]
    fn codec_execution_result_bounds_unauthenticated_indices() {
        let mut r = minimal();
        r.metrics.unauthenticated = (0..MAX_UNAUTHENTICATED as u32).collect();
        let bytes = r.to_bytes();
        same(&ExecutionResult::decode_exact(&bytes).unwrap(), &r);

        // A version 1 batch can have more. Only the first 1024 are written.
        r.metrics.unauthenticated.push(MAX_UNAUTHENTICATED as u32);
        assert_eq!(r.to_bytes(), bytes);

        let r = minimal();
        let unauthenticated_at = optional_parts_at(&r) + 1 + 1 + 4 + 4;
        let mut bytes = r.to_bytes();
        bytes[unauthenticated_at..unauthenticated_at + 4]
            .copy_from_slice(&(MAX_UNAUTHENTICATED as u32 + 1).to_le_bytes());
        assert!(matches!(
            ExecutionResult::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded { .. })
        ));
        // A count the rest of the input cannot hold is a short read.
        let mut bytes = r.to_bytes();
        bytes[unauthenticated_at..unauthenticated_at + 4]
            .copy_from_slice(&(MAX_UNAUTHENTICATED as u32).to_le_bytes());
        assert!(matches!(
            ExecutionResult::decode_exact(&bytes),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn codec_execution_result_saturates_metrics() {
        let mut r = minimal();
        r.metrics.stages = (0..MAX_STAGES + 3)
            .map(|i| {
                (
                    Cow::Owned(format!("{}{i}", "é".repeat(20))),
                    Duration::from_nanos(1_500),
                )
            })
            .collect();
        let back = ExecutionResult::decode_exact(&r.to_bytes()).unwrap();
        assert_eq!(back.metrics.stages.len(), MAX_STAGES);
        for (name, took) in &back.metrics.stages {
            assert!(name.len() <= MAX_STAGE_NAME_LEN);
            assert_eq!(name.as_ref(), "é".repeat(16));
            assert_eq!(*took, Duration::from_micros(1));
        }
    }

    #[test]
    fn codec_execution_result_bounds_stages_on_decode() {
        let r = minimal();
        let stages_at = r.to_bytes().len() - 4;
        let mut bytes = r.to_bytes();
        bytes[stages_at..].copy_from_slice(&(MAX_STAGES as u32 + 1).to_le_bytes());
        assert!(matches!(
            ExecutionResult::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded { .. })
        ));
        let mut bytes = r.to_bytes();
        bytes[stages_at..].copy_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&(MAX_STAGE_NAME_LEN as u32 + 1).to_le_bytes());
        bytes.extend(std::iter::repeat_n(b'a', MAX_STAGE_NAME_LEN + 1));
        bytes.extend_from_slice(&0u64.to_le_bytes());
        assert!(matches!(
            ExecutionResult::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded { .. })
        ));
        let mut bytes = r.to_bytes();
        bytes[stages_at..].copy_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0xff);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            ExecutionResult::decode_exact(&bytes).map(|_| ()),
            Err(DecodeError::InvalidValue("ExecutionResult.stage"))
        );
    }

    #[test]
    fn codec_execution_result_rejects_trailing_and_missing_bytes() {
        let mut bytes = full().to_bytes();
        bytes.push(0);
        assert_eq!(
            ExecutionResult::decode_exact(&bytes).map(|_| ()),
            Err(DecodeError::TrailingBytes(1))
        );
        bytes.truncate(bytes.len() - 2);
        assert!(matches!(
            ExecutionResult::decode_exact(&bytes),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn codec_proof_artifact_round_trips_within_its_bound() {
        let p = ProofArtifact {
            digest: Hash32([1; 32]),
            bytes: Vec::new(),
        };
        assert_eq!(p.to_bytes().len(), ProofArtifact::MIN_ENCODED_LEN);
        assert_eq!(ProofArtifact::decode_exact(&p.to_bytes()), Ok(p));
        let mut bytes = Hash32::ZERO.to_bytes();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            ProofArtifact::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded {
                len: u32::MAX as usize,
                max: MAX_PROOF_LEN
            })
        );
    }
}
