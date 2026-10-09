//! Verification of SNARK-backed batch outcomes.
//!
//! A proof says: *for the envelopes of this batch in canonical order, with
//! these public admission flags and prior fills, there exist openings of the
//! admitted commitments such that the clearing prices, volumes and fills in
//! the receipt are exactly the result of the protocol's clearing and
//! allocation rules.* Concretely the circuit (the `prover` module) enforces:
//!
//! * Every admitted commitment opens (Poseidon) to an order whose limit,
//!   side, role, kind and quantity are the ones used below.
//! * Each order's band slot follows the clamping rules.
//! * Curves are the sums of remaining quantities.
//! * Each book's clearing slot is the unique optimum of the clearing key.
//! * Fills follow price priority then lottery priority at the clearing
//!   level.
//! * The published transcript commits to all of the above.
//!
//! It does **not** prove: signature checks, collateral admission, self-trade
//! prevention or nonce rules. Admission flags are public inputs, so a prover
//! that wrongly excludes an order is caught by that order's trader, not by
//! the proof. Settlement re-checks conservation independently.
//!
//! Groth16 needs a circuit-specific trusted setup. Keys produced by
//! the prover locally are for experiments only.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use thiserror::Error;
use timescales_auction::orderbook::OrderStateTable;
use timescales_auction::receipts::ExecutionArtifacts;
use timescales_auction::{BatchHeader, canonical_order_by};
use timescales_core::commitment::poseidon;
use timescales_core::crypto::{Hasher, domain};
use timescales_core::{BookId, FlowMode, Hash32, OrderCommitment, Role, Side};

/// Largest circuit capacity a bundle or key may claim: no batch holds more
/// envelopes than this, so no honest circuit is wider.
pub const MAX_CAPACITY: usize = timescales_core::MAX_BATCH_ENVELOPES as usize;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifyError {
    #[error("proof does not verify")]
    Invalid,
    #[error("malformed proof or key: {0}")]
    Malformed(&'static str),
    #[error("proof shape does not fit this batch: {0}")]
    Shape(&'static str),
    #[error("commitment is not a field element")]
    Commitment,
}

/// Static parameters a circuit (and its keys) is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CircuitShape {
    /// Envelopes per batch, padded.
    pub capacity: usize,
    /// Band ticks `K`.
    pub ticks: u32,
    pub qty_bits: u8,
    pub flow: FlowMode,
}

impl CircuitShape {
    /// Bit width of any curve value: `capacity * 2^qty_bits`.
    pub fn curve_bits(&self) -> u32 {
        let cap_bits = usize::BITS - self.capacity.max(1).saturating_sub(1).leading_zeros();
        u32::from(self.qty_bits) + cap_bits + 1
    }

    pub fn books(&self) -> &'static [BookId] {
        BookId::books(self.flow)
    }
}

/// Group index used by both the MPC encoding and the circuit.
pub fn group(role: Role, side: Side) -> u8 {
    (role as u8) * 2 + side as u8
}

/// One transcript entry per envelope, in canonical order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptEntry {
    pub commitment: Fr,
    pub filled: u64,
    pub admitted: bool,
    pub fill: u64,
    /// `1 + group` for filled orders, `0` otherwise.
    pub tag: u8,
}

impl TranscriptEntry {
    pub fn padding() -> Self {
        Self {
            commitment: Fr::from(0u64),
            filled: 0,
            admitted: false,
            fill: 0,
            tag: 0,
        }
    }

    pub fn fields(&self) -> [Fr; 5] {
        [
            self.commitment,
            Fr::from(self.filled),
            Fr::from(u64::from(self.admitted)),
            Fr::from(self.fill),
            Fr::from(u64::from(self.tag)),
        ]
    }
}

pub fn transcript(entries: &[TranscriptEntry]) -> Fr {
    let mut sponge = PoseidonSponge::new(poseidon::config());
    let all: Vec<Fr> = entries.iter().flat_map(TranscriptEntry::fields).collect();
    sponge.absorb(&all);
    sponge.squeeze_native_field_elements(1)[0]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub transcript: Fr,
    pub lo: u64,
    /// `(clearing slot, volume)` per book, in `BookId` order.
    pub books: Vec<(u32, u64)>,
}

impl PublicInputs {
    pub fn to_field_elements(&self) -> Vec<Fr> {
        let mut v = vec![self.transcript, Fr::from(self.lo)];
        for (s, vol) in &self.books {
            v.push(Fr::from(u64::from(*s)));
            v.push(Fr::from(*vol));
        }
        v
    }
}

/// Rebuild the transcript entries a proof must match from public data:
/// the batch's commitments, the prior state, the admission flags and the
/// receipt's fills.
pub fn entries_from_public(
    header: &BatchHeader,
    commitments: &[OrderCommitment],
    prior: &OrderStateTable,
    admitted: &[bool],
    artifacts: &ExecutionArtifacts,
    capacity: usize,
) -> Result<Vec<TranscriptEntry>, VerifyError> {
    if capacity > MAX_CAPACITY {
        return Err(VerifyError::Shape("capacity"));
    }
    if commitments.len() != admitted.len() || commitments.len() > capacity {
        return Err(VerifyError::Shape("admission flags or capacity"));
    }
    let order = canonical_order_by(&header.seed(), commitments, |c| *c, |c| c.0.to_vec());
    let mut fills = std::collections::BTreeMap::new();
    for f in &artifacts.fills {
        fills.insert(f.commitment, (f.quantity.0, 1 + group(f.role, f.side)));
    }
    let mut out = Vec::with_capacity(capacity);
    for (k, (i, _)) in order.into_iter().enumerate() {
        let c = commitments[i];
        // Only an admitted entry can carry a fill. This keeps duplicates of
        // one commitment unambiguous.
        let (fill, tag) = if admitted[k] {
            fills.get(&c).copied().unwrap_or((0, 0))
        } else {
            (0, 0)
        };
        out.push(TranscriptEntry {
            commitment: poseidon::from_commitment(&c).ok_or(VerifyError::Commitment)?,
            filled: prior.get(&c).map_or(0, |e| e.filled.0),
            admitted: admitted[k],
            fill,
            tag,
        });
    }
    out.resize(capacity, TranscriptEntry::padding());
    Ok(out)
}

/// A proof plus what the verifier needs besides the receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofBundle {
    pub shape: CircuitShape,
    /// Admission flag per envelope, in canonical order.
    pub admitted: Vec<bool>,
    /// Compressed Groth16 proof.
    pub proof: Vec<u8>,
}

impl ProofBundle {
    pub fn digest(&self) -> Hash32 {
        let mut h = Hasher::new(domain::PROOF)
            .chain(&(self.shape.capacity as u64).to_le_bytes())
            .chain(&self.shape.ticks.to_le_bytes())
            .chain(&[self.shape.qty_bits, self.shape.flow as u8]);
        let bits: Vec<u8> = self.admitted.iter().map(|b| u8::from(*b)).collect();
        h.update(&(bits.len() as u64).to_le_bytes());
        h.update(&bits);
        h.update(&self.proof);
        h.finalize()
    }
}

impl ProofBundle {
    /// `capacity u32 | ticks u32 | qty_bits u8 | flow u8 | n u32 | flags | proof`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(
            &u32::try_from(self.shape.capacity)
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        v.extend_from_slice(&self.shape.ticks.to_le_bytes());
        v.push(self.shape.qty_bits);
        v.push(self.shape.flow as u8);
        v.extend_from_slice(
            &u32::try_from(self.admitted.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        v.extend(self.admitted.iter().map(|b| u8::from(*b)));
        v.extend_from_slice(&self.proof);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, VerifyError> {
        let bad = || VerifyError::Malformed("bundle");
        let u32_at = |at: usize| -> Result<u32, VerifyError> {
            Ok(u32::from_le_bytes(
                b.get(at..at + 4)
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?,
            ))
        };
        let capacity = u32_at(0)? as usize;
        if capacity > MAX_CAPACITY {
            return Err(bad());
        }
        let ticks = u32_at(4)?;
        let qty_bits = *b.get(8).ok_or_else(bad)?;
        let flow = match b.get(9) {
            Some(0) => FlowMode::SingleBook,
            Some(1) => FlowMode::DualFlow,
            _ => return Err(bad()),
        };
        let n = u32_at(10)? as usize;
        if n > capacity {
            return Err(bad());
        }
        let flags = b.get(14..14 + n).ok_or_else(bad)?;
        if flags.iter().any(|x| *x > 1) {
            return Err(bad());
        }
        Ok(ProofBundle {
            shape: CircuitShape {
                capacity,
                ticks,
                qty_bits,
                flow,
            },
            admitted: flags.iter().map(|x| *x == 1).collect(),
            proof: b[14 + n..].to_vec(),
        })
    }
}

pub fn decode_proof(bytes: &[u8]) -> Result<Proof<Bn254>, VerifyError> {
    Proof::deserialize_compressed(bytes).map_err(|_| VerifyError::Malformed("proof"))
}

pub fn encode_proof(p: &Proof<Bn254>) -> Vec<u8> {
    let mut v = Vec::new();
    p.serialize_compressed(&mut v)
        .unwrap_or_else(|_| unreachable!("writing to a Vec"));
    v
}

pub fn decode_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, VerifyError> {
    VerifyingKey::deserialize_compressed(bytes).map_err(|_| VerifyError::Malformed("verifying key"))
}

/// Pairings that depend only on the key, done once per key rather than once
/// per proof.
pub fn prepare_vk(vk: &VerifyingKey<Bn254>) -> Result<PreparedVerifyingKey<Bn254>, VerifyError> {
    Groth16::<Bn254>::process_vk(vk).map_err(|_| VerifyError::Malformed("verifying key"))
}

pub fn verify_proof(
    vk: &PreparedVerifyingKey<Bn254>,
    inputs: &PublicInputs,
    proof: &Proof<Bn254>,
) -> Result<(), VerifyError> {
    match Groth16::<Bn254>::verify_with_processed_vk(vk, &inputs.to_field_elements(), proof) {
        Ok(true) => Ok(()),
        Ok(false) => Err(VerifyError::Invalid),
        Err(_) => Err(VerifyError::Malformed("verification")),
    }
}

/// A verifying key together with the circuit shape it was generated for.
/// Verifying through it refuses a bundle of any other shape before anything
/// is allocated for the bundle's claimed capacity.
#[derive(Clone, Debug)]
pub struct ShapedVerifyingKey {
    shape: CircuitShape,
    vk: VerifyingKey<Bn254>,
    prepared: PreparedVerifyingKey<Bn254>,
}

impl ShapedVerifyingKey {
    /// Fails if the shape is wider than [`MAX_CAPACITY`] or the key's
    /// number of public inputs does not fit the shape's books.
    pub fn new(shape: CircuitShape, vk: VerifyingKey<Bn254>) -> Result<Self, VerifyError> {
        if shape.capacity > MAX_CAPACITY {
            return Err(VerifyError::Shape("capacity"));
        }
        // transcript, lo, then (slot, volume) per book. Plus the constant.
        if vk.gamma_abc_g1.len() != 3 + 2 * shape.books().len() {
            return Err(VerifyError::Malformed(
                "verifying key does not fit the shape",
            ));
        }
        let prepared = prepare_vk(&vk)?;
        Ok(Self {
            shape,
            vk,
            prepared,
        })
    }

    pub fn from_bytes(shape: CircuitShape, vk_bytes: &[u8]) -> Result<Self, VerifyError> {
        Self::new(shape, decode_vk(vk_bytes)?)
    }

    pub fn shape(&self) -> &CircuitShape {
        &self.shape
    }

    pub fn vk(&self) -> &VerifyingKey<Bn254> {
        &self.vk
    }

    /// [`verify_bundle`] for a bundle that must have exactly this key's shape.
    pub fn verify(
        &self,
        bundle: &ProofBundle,
        header: &BatchHeader,
        commitments: &[OrderCommitment],
        prior: &OrderStateTable,
        artifacts: &ExecutionArtifacts,
        clearing: &[timescales_core::ClearingPrice],
    ) -> Result<(), VerifyError> {
        if bundle.shape != self.shape {
            return Err(VerifyError::Shape("bundle shape differs from the key's"));
        }
        verify_bundle_prepared(
            &self.prepared,
            bundle,
            header,
            commitments,
            prior,
            artifacts,
            clearing,
        )
    }
}

/// Verify a bundle against a batch and its receipt artifacts.
///
/// The bundle's shape is checked against the batch, not against the key.
/// With only the key at hand, the allocation for the claimed capacity is
/// bounded by [`MAX_CAPACITY`]. [`ShapedVerifyingKey::verify`] also pins
/// the shape to the key's.
pub fn verify_bundle(
    vk: &VerifyingKey<Bn254>,
    bundle: &ProofBundle,
    header: &BatchHeader,
    commitments: &[OrderCommitment],
    prior: &OrderStateTable,
    artifacts: &ExecutionArtifacts,
    clearing: &[timescales_core::ClearingPrice],
) -> Result<(), VerifyError> {
    verify_bundle_prepared(
        &prepare_vk(vk)?,
        bundle,
        header,
        commitments,
        prior,
        artifacts,
        clearing,
    )
}

/// [`verify_bundle`] with the key's pairings already done.
pub fn verify_bundle_prepared(
    vk: &PreparedVerifyingKey<Bn254>,
    bundle: &ProofBundle,
    header: &BatchHeader,
    commitments: &[OrderCommitment],
    prior: &OrderStateTable,
    artifacts: &ExecutionArtifacts,
    clearing: &[timescales_core::ClearingPrice],
) -> Result<(), VerifyError> {
    if bundle.shape.ticks != header.band.ticks() || bundle.shape.flow != header.params.flow {
        return Err(VerifyError::Shape("band or flow"));
    }
    let entries = entries_from_public(
        header,
        commitments,
        prior,
        &bundle.admitted,
        artifacts,
        bundle.shape.capacity,
    )?;
    let books = clearing
        .iter()
        .map(|c| {
            let slot = c
                .tick
                .0
                .checked_sub(header.band.lo.0)
                .and_then(|s| u32::try_from(s).ok())
                .ok_or(VerifyError::Shape("clearing tick outside the band"))?;
            Ok((slot, c.volume.0))
        })
        .collect::<Result<_, VerifyError>>()?;
    let inputs = PublicInputs {
        transcript: transcript(&entries),
        lo: header.band.lo.0,
        books,
    };
    verify_proof(vk, &inputs, &decode_proof(&bundle.proof)?)
}
