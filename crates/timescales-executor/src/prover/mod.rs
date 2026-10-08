//! Groth16 proving for batch auctions.
//!
//! [`AuctionCircuit`] encodes the clearing and allocation rules for one
//! batch (all books). Keys are circuit specific: one pair per
//! [`CircuitShape`]. `setup` here samples toxic waste locally and is only
//! suitable for experiments. A deployment needs a setup ceremony or a
//! universal-setup proof system.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod circuit;

pub use circuit::{AuctionCircuit, EntryInput, OrderWitness};

use crate::verifier::{CircuitShape, PublicInputs, encode_proof};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("synthesis failed: {0}")]
    Synthesis(String),
    #[error("key serialization: {0}")]
    Serialization(String),
    #[error("invalid circuit shape: {0}")]
    Shape(&'static str),
}

pub struct Keys {
    pub shape: CircuitShape,
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keys")
            .field("shape", &self.shape)
            .finish_non_exhaustive()
    }
}

impl Keys {
    pub fn setup<R: RngCore + CryptoRng>(
        shape: CircuitShape,
        rng: &mut R,
    ) -> Result<Self, ProverError> {
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(AuctionCircuit::blank(shape)?, rng)
            .map_err(|e| ProverError::Synthesis(e.to_string()))?;
        Ok(Self { shape, pk, vk })
    }

    pub fn vk_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.vk
            .serialize_compressed(&mut v)
            .unwrap_or_else(|_| unreachable!());
        v
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ProverError> {
        let mut v = Vec::new();
        self.pk
            .serialize_uncompressed(&mut v)
            .map_err(|e| ProverError::Serialization(e.to_string()))?;
        Ok(v)
    }

    pub fn from_bytes(shape: CircuitShape, bytes: &[u8]) -> Result<Self, ProverError> {
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(bytes)
            .map_err(|e| ProverError::Serialization(e.to_string()))?;
        let vk = pk.vk.clone();
        Ok(Self { shape, pk, vk })
    }
}

/// Number of constraints for a shape. Useful for sizing experiments.
pub fn constraint_count(shape: CircuitShape) -> Result<usize, ProverError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    AuctionCircuit::blank(shape)?
        .generate_constraints(cs.clone())
        .map_err(|e| ProverError::Synthesis(e.to_string()))?;
    cs.finalize();
    Ok(cs.num_constraints())
}

/// Check a witness without proving (fast feedback in tests).
pub fn is_satisfied(circuit: AuctionCircuit) -> Result<bool, ProverError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .map_err(|e| ProverError::Synthesis(e.to_string()))?;
    cs.is_satisfied()
        .map_err(|e| ProverError::Synthesis(e.to_string()))
}

pub fn public_inputs(c: &AuctionCircuit) -> PublicInputs {
    PublicInputs {
        transcript: c.transcript,
        lo: c.lo,
        books: c.books.clone(),
    }
}

/// Prove. Returns the compressed proof.
pub fn prove<R: RngCore + CryptoRng>(
    keys: &Keys,
    circuit: AuctionCircuit,
    rng: &mut R,
) -> Result<Vec<u8>, ProverError> {
    let proof = Groth16::<Bn254>::prove(&keys.pk, circuit, rng)
        .map_err(|e| ProverError::Synthesis(e.to_string()))?;
    Ok(encode_proof(&proof))
}
