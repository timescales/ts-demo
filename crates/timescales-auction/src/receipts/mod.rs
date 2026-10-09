//! Execution outcomes, traces and receipts.
//!
//! * [`ExecutionOutcome`] is the backend-independent result of a batch. Two
//!   correct executors given the same batch produce byte-identical outcomes.
//!   The differential tests compare exactly this.
//! * [`ExecutionArtifacts`] are the full lists the outcome's roots commit to.
//!   They are published alongside the receipt (data availability) and are
//!   what settlement consumes.
//! * [`ExecutionTrace`] is a hash chain over the executor's internal steps.
//!   It is backend specific and is only committed to, never compared.
//! * [`ExecutionReceipt`] binds an outcome to the executor that produced it,
//!   its attestation, an optional proof, and its trace, under the executor's
//!   signature. It is compact on purpose: the settlement program recomputes
//!   its digest on chain.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use crate::settlement::{SettlementBatch, settle};
use thiserror::Error;
use timescales_core::crypto::{Hasher, Signature, domain};
use timescales_core::identity::{ExecutorKey, verify_executor};
use timescales_core::merkle::MerkleTree;
use timescales_core::{
    ClearingPrice, Decode, DecodeError, Encode, EpochId, ExecutorId, Fill, Hash32,
    MAX_SETTLEMENT_DELTAS, MarketId, MarketParams, OrderCommitment, PROTOCOL_VERSION, QuoteAtoms,
    Reader,
    encoding::{put_seq, put_u8, put_u32},
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("receipt signature invalid")]
    BadSignature,
    #[error("receipt does not match {0}")]
    Mismatch(&'static str),
    #[error("unsupported receipt version {0}")]
    Version(u8),
    #[error("receipt exceeds the limit on {0}")]
    Limit(&'static str),
}

/// At most one clearing price per book, and a batch has at most two books.
pub const MAX_CLEARING_PRICES: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BackendKind {
    Reference = 0,
    Tee = 1,
    Mpc = 2,
}

impl BackendKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Reference),
            1 => Some(Self::Tee),
            2 => Some(Self::Mpc),
            _ => None,
        }
    }
}

pub fn fills_root(fills: &[Fill]) -> Hash32 {
    MerkleTree::from_encoded(fills).root()
}

pub fn commitments_root(cs: &[OrderCommitment]) -> Hash32 {
    let leaves: Vec<&[u8]> = cs.iter().map(|c| c.as_bytes().as_slice()).collect();
    MerkleTree::from_data(&leaves).root()
}

/// What a co-signing executor signs to endorse a posted receipt:
/// `H(RECEIPT_COSIGN, market address || epoch || header digest || outcome digest)`.
/// The program checks it in `CoSignReceipt`, so the layout is fixed.
pub fn cosign_digest(
    market: &[u8; 32],
    epoch: EpochId,
    header_digest: &Hash32,
    outcome_digest: &Hash32,
) -> Hash32 {
    Hasher::new(domain::RECEIPT_COSIGN)
        .chain(market)
        .chain(&epoch.to_bytes())
        .chain(header_digest.as_bytes())
        .chain(outcome_digest.as_bytes())
        .finalize()
}

/// Backend-independent result of executing one batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub market: MarketId,
    pub epoch: EpochId,
    pub header_digest: Hash32,
    pub clearing: Vec<ClearingPrice>,
    pub fill_count: u32,
    pub fills_root: Hash32,
    pub cancelled_root: Hash32,
    pub next_state_root: Hash32,
    pub settlement_count: u32,
    pub settlement_root: Hash32,
    pub fees: QuoteAtoms,
}

impl ExecutionOutcome {
    /// Encoded size with no clearing prices.
    const MIN_LEN: usize = 8 + 8 + 32 + 4 + 4 + 32 + 32 + 32 + 4 + 32 + 8;

    pub fn digest(&self) -> Hash32 {
        Hasher::new(domain::OUTCOME)
            .chain(&self.to_bytes())
            .finalize()
    }
}

/// Lists committed to by an outcome's roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionArtifacts {
    pub fills: Vec<Fill>,
    pub cancelled: Vec<OrderCommitment>,
    pub settlement: SettlementBatch,
}

impl ExecutionArtifacts {
    /// Check that the artifacts are exactly what `outcome` commits to, and
    /// that the outcome fits what the settlement program accepts: at most
    /// [`MAX_SETTLEMENT_DELTAS`] settlement leaves and one clearing price
    /// per book. It does not recompute the settlement from the fills. That
    /// is [`Self::check_settlement`].
    pub fn check_against(&self, outcome: &ExecutionOutcome) -> Result<(), ReceiptError> {
        if outcome.clearing.len() > MAX_CLEARING_PRICES {
            return Err(ReceiptError::Limit("clearing prices"));
        }
        if outcome.settlement_count > MAX_SETTLEMENT_DELTAS {
            return Err(ReceiptError::Limit("settlement deltas"));
        }
        if self.settlement.market != outcome.market || self.settlement.epoch != outcome.epoch {
            return Err(ReceiptError::Mismatch("settlement batch"));
        }
        if fills_root(&self.fills) != outcome.fills_root
            || self.fills.len() != outcome.fill_count as usize
        {
            return Err(ReceiptError::Mismatch("fills"));
        }
        if commitments_root(&self.cancelled) != outcome.cancelled_root {
            return Err(ReceiptError::Mismatch("cancelled"));
        }
        if self.settlement.root() != outcome.settlement_root
            || self.settlement.deltas.len() != outcome.settlement_count as usize
            || self.settlement.fees != outcome.fees
        {
            return Err(ReceiptError::Mismatch("settlement"));
        }
        self.settlement
            .check_canonical()
            .map_err(|_| ReceiptError::Mismatch("settlement order"))?;
        self.settlement
            .check_conservation()
            .map_err(|_| ReceiptError::Mismatch("conservation"))
    }

    /// Recompute the settlement from the fills under `params` for `epoch`
    /// and require it to equal the published one, so the balance changes are
    /// exactly what the fills imply.
    pub fn check_settlement(
        &self,
        params: &MarketParams,
        epoch: EpochId,
    ) -> Result<(), ReceiptError> {
        match settle(params, epoch, &self.fills) {
            Ok(recomputed) if recomputed == self.settlement => Ok(()),
            _ => Err(ReceiptError::Mismatch("settlement of the fills")),
        }
    }
}

impl Encode for ExecutionArtifacts {
    fn encode(&self, out: &mut Vec<u8>) {
        put_seq(out, &self.fills);
        put_seq(out, &self.cancelled);
        self.settlement.encode(out);
    }
}

impl Decode for ExecutionArtifacts {
    const MIN_ENCODED_LEN: usize = 4 + 4 + SettlementBatch::MIN_ENCODED_LEN;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let max = timescales_core::MAX_BATCH_ENVELOPES as usize;
        Ok(ExecutionArtifacts {
            fills: r.seq(max)?,
            cancelled: r.seq(max)?,
            settlement: SettlementBatch::decode(r)?,
        })
    }
}

/// Hash chain over labelled execution steps.
#[derive(Clone, Debug)]
pub struct ExecutionTrace {
    head: Hash32,
    steps: Vec<(&'static str, Hash32)>,
}

impl Default for ExecutionTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionTrace {
    pub fn new() -> Self {
        Self {
            head: Hash32::ZERO,
            steps: Vec::new(),
        }
    }

    pub fn record(&mut self, label: &'static str, data: &[u8]) {
        let d = Hasher::new(domain::TRACE)
            .chain(label.as_bytes())
            .chain(data)
            .finalize();
        self.head = Hasher::new(domain::TRACE)
            .chain(self.head.as_bytes())
            .chain(d.as_bytes())
            .finalize();
        self.steps.push((label, d));
    }

    pub fn digest(&self) -> Hash32 {
        self.head
    }

    pub fn steps(&self) -> &[(&'static str, Hash32)] {
        &self.steps
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionReceipt {
    pub version: u8,
    pub outcome: ExecutionOutcome,
    pub backend: BackendKind,
    pub executor: ExecutorId,
    /// Digest of the executor's attestation evidence, zero if none.
    pub attestation: Hash32,
    /// Digest of an accompanying execution proof, zero if none.
    pub proof: Hash32,
    pub trace: Hash32,
    pub signature: Signature,
}

impl ExecutionReceipt {
    pub fn signing_digest(
        outcome: &ExecutionOutcome,
        backend: BackendKind,
        executor: &ExecutorId,
        attestation: &Hash32,
        proof: &Hash32,
        trace: &Hash32,
    ) -> Hash32 {
        let mut b = Vec::with_capacity(512);
        put_u8(&mut b, PROTOCOL_VERSION);
        outcome.encode(&mut b);
        put_u8(&mut b, backend as u8);
        executor.encode(&mut b);
        attestation.encode(&mut b);
        proof.encode(&mut b);
        trace.encode(&mut b);
        Hasher::new(domain::RECEIPT).chain(&b).finalize()
    }

    pub fn sign(
        key: &ExecutorKey,
        outcome: ExecutionOutcome,
        backend: BackendKind,
        attestation: Hash32,
        proof: Hash32,
        trace: Hash32,
    ) -> Self {
        let executor = key.id();
        let d = Self::signing_digest(&outcome, backend, &executor, &attestation, &proof, &trace);
        Self {
            version: PROTOCOL_VERSION,
            outcome,
            backend,
            executor,
            attestation,
            proof,
            trace,
            signature: key.sign(&d),
        }
    }

    pub fn digest(&self) -> Hash32 {
        Self::signing_digest(
            &self.outcome,
            self.backend,
            &self.executor,
            &self.attestation,
            &self.proof,
            &self.trace,
        )
    }

    pub fn verify_signature(&self) -> Result<(), ReceiptError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ReceiptError::Version(self.version));
        }
        verify_executor(&self.executor, &self.digest(), &self.signature)
            .map_err(|_| ReceiptError::BadSignature)
    }

    /// Whether `self` and `other` prove that their executor equivocated:
    /// both validly signed by the same key, for the same batch header, with
    /// different outcomes. Anyone holding the pair can check this from
    /// public data, so the pair is a transferable fraud proof. Receipts that
    /// differ only in attestation, proof or trace are not equivocation.
    pub fn equivocates_with(&self, other: &Self) -> bool {
        self.executor == other.executor
            && self.outcome.market == other.outcome.market
            && self.outcome.epoch == other.outcome.epoch
            && self.outcome.header_digest == other.outcome.header_digest
            && self.outcome.digest() != other.outcome.digest()
            && self.verify_signature().is_ok()
            && other.verify_signature().is_ok()
    }
}

impl Encode for ExecutionOutcome {
    fn encode(&self, out: &mut Vec<u8>) {
        self.market.encode(out);
        self.epoch.encode(out);
        self.header_digest.encode(out);
        put_seq(out, &self.clearing);
        put_u32(out, self.fill_count);
        self.fills_root.encode(out);
        self.cancelled_root.encode(out);
        self.next_state_root.encode(out);
        put_u32(out, self.settlement_count);
        self.settlement_root.encode(out);
        self.fees.encode(out);
    }
}

impl Decode for ExecutionOutcome {
    const MIN_ENCODED_LEN: usize = ExecutionOutcome::MIN_LEN;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ExecutionOutcome {
            market: MarketId::decode(r)?,
            epoch: EpochId::decode(r)?,
            header_digest: Hash32::decode(r)?,
            clearing: r.seq(2)?,
            fill_count: r.u32()?,
            fills_root: Hash32::decode(r)?,
            cancelled_root: Hash32::decode(r)?,
            next_state_root: Hash32::decode(r)?,
            settlement_count: r.u32()?,
            settlement_root: Hash32::decode(r)?,
            fees: QuoteAtoms::decode(r)?,
        })
    }
}

impl Encode for ExecutionReceipt {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.outcome.encode(out);
        put_u8(out, self.backend as u8);
        self.executor.encode(out);
        self.attestation.encode(out);
        self.proof.encode(out);
        self.trace.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for ExecutionReceipt {
    const MIN_ENCODED_LEN: usize = 1 + ExecutionOutcome::MIN_LEN + 1 + 4 * 32 + 64;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let version = r.u8()?;
        let outcome = ExecutionOutcome::decode(r)?;
        let tag = r.u8()?;
        let backend = BackendKind::from_u8(tag).ok_or(DecodeError::InvalidTag {
            ty: "BackendKind",
            tag,
        })?;
        Ok(ExecutionReceipt {
            version,
            outcome,
            backend,
            executor: ExecutorId::decode(r)?,
            attestation: Hash32::decode(r)?,
            proof: Hash32::decode(r)?,
            trace: Hash32::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use timescales_core::{BookId, Lots, Tick};

    fn outcome() -> ExecutionOutcome {
        ExecutionOutcome {
            market: MarketId(1),
            epoch: EpochId(2),
            header_digest: Hash32([1; 32]),
            clearing: vec![ClearingPrice {
                book: BookId::Single,
                tick: Tick(10),
                volume: Lots(3),
            }],
            fill_count: 0,
            fills_root: fills_root(&[]),
            cancelled_root: commitments_root(&[]),
            next_state_root: Hash32::ZERO,
            settlement_count: 0,
            settlement_root: Hash32::ZERO,
            fees: QuoteAtoms(0),
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(5);
        let k = ExecutorKey::generate(&mut rng);
        let r = ExecutionReceipt::sign(
            &k,
            outcome(),
            BackendKind::Tee,
            Hash32([2; 32]),
            Hash32::ZERO,
            Hash32([3; 32]),
        );
        assert!(r.verify_signature().is_ok());
        let decoded = ExecutionReceipt::decode_exact(&r.to_bytes()).unwrap();
        assert_eq!(decoded, r);
        let mut t = r.clone();
        t.outcome.fees = QuoteAtoms(1);
        assert_eq!(t.verify_signature(), Err(ReceiptError::BadSignature));
        let mut t = r;
        t.backend = BackendKind::Reference;
        assert_eq!(t.verify_signature(), Err(ReceiptError::BadSignature));
    }

    #[test]
    fn conflicting_signed_outcomes_are_a_fraud_proof() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(6);
        let k = ExecutorKey::generate(&mut rng);
        let sign = |k: &ExecutorKey, o: ExecutionOutcome, proof: Hash32| {
            ExecutionReceipt::sign(k, o, BackendKind::Tee, Hash32::ZERO, proof, Hash32::ZERO)
        };
        let a = sign(&k, outcome(), Hash32::ZERO);
        let mut other = outcome();
        other.clearing[0].volume = Lots(2);
        let b = sign(&k, other.clone(), Hash32::ZERO);
        assert!(a.equivocates_with(&b) && b.equivocates_with(&a));

        // Same outcome with a proof attached later is not equivocation.
        assert!(!a.equivocates_with(&sign(&k, outcome(), Hash32([4; 32]))));
        // Another batch, or another executor, is not either.
        let mut elsewhere = other.clone();
        elsewhere.header_digest = Hash32([9; 32]);
        assert!(!a.equivocates_with(&sign(&k, elsewhere, Hash32::ZERO)));
        let k2 = ExecutorKey::generate(&mut rng);
        assert!(!a.equivocates_with(&sign(&k2, other, Hash32::ZERO)));
        // A forged second signature proves nothing.
        let mut forged = b;
        forged.signature.0[0] ^= 1;
        assert!(!a.equivocates_with(&forged));
    }

    #[test]
    fn trace_is_order_sensitive() {
        let mut a = ExecutionTrace::new();
        a.record("x", b"1");
        a.record("y", b"2");
        let mut b = ExecutionTrace::new();
        b.record("y", b"2");
        b.record("x", b"1");
        assert_ne!(a.digest(), b.digest());
    }
}
