//! The enclave boundary.
//!
//! Everything in [`Enclave`] stands for code and state inside the TEE: the
//! sealing key shares are encrypted to, the receipt-signing key, and the
//! epoch secret while a batch runs. Both keys are generated inside at boot
//! (or, on the simulated platform only, loaded from the host's key file)
//! and only their public halves leave, bound into attestation evidence. The
//! executor key signs only through typed methods that fix their domain:
//! receipts, co-signatures and RPC envelopes.
//!
//! The quoting interface is [`Quoter`]. The simulator implements it with a
//! `SimulatedPlatform`. A TDX guest implements it over configfs-tsm
//! (`TsmQuoter`, feature `tdx-tsm`, untested on hardware).

use std::convert::Infallible;
use std::sync::Arc;

#[cfg(feature = "simulation")]
use crate::attestation::simulated::SimulatedPlatform;
use crate::attestation::{
    Evidence, ExecutorAttestation, ExecutorAttestationV2, Measurement, nonces_digest, report_data,
    report_data_v2,
};
use crate::pipeline::{PlainExecution, check_header, execute_opened, open_envelopes};
use crate::{
    ExecutionBatch, ExecutionMetrics, ExecutorError, PlainProver, ProofArtifact, order_seed,
};
use thiserror::Error;
use timescales_auction::BatchHeader;
use timescales_auction::receipts::{BackendKind, ExecutionReceipt, cosign_digest};
use timescales_core::crypto::threshold::{
    ScalarShare, decompress_canonical, lagrange_combine, verify_share, x25519_public,
};
use timescales_core::crypto::{
    EpochSecret, ScalarSealSecret, SealSecret, Signature, Zeroizing, domain, hash, open,
};
use timescales_core::identity::ExecutorKey;
use timescales_core::{EpochId, ExecutorId, Hash32, TraderId};

use crate::tee::committee::{SealedShare, share_info};

/// Identity of the program the enclave runs. In simulated mode this is the
/// measurement members allow: a hash of the crate name and version, not an
/// image measurement. A TDX build is identified by MRTD and RTMRs instead.
pub fn program_measurement() -> Measurement {
    Measurement::of_program(
        "timescales-executor-tee",
        env!("CARGO_PKG_VERSION"),
        b"pipeline/v1",
    )
}

/// Why no quote was produced.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("quote generation failed: {0}")]
pub struct QuoteError(pub String);

/// Produces attestation evidence over 64 bytes of report data.
pub trait Quoter: Send + Sync {
    fn quote(&self, measurement: Measurement, debug: bool, report_data: [u8; 64]) -> Evidence;

    /// [`Self::quote`] for quoters that can fail (hardware interfaces).
    /// The enclave quotes through this method.
    fn try_quote(
        &self,
        measurement: Measurement,
        debug: bool,
        report_data: [u8; 64],
    ) -> Result<Evidence, QuoteError> {
        Ok(self.quote(measurement, debug, report_data))
    }
}

#[cfg(feature = "simulation")]
impl Quoter for SimulatedPlatform {
    fn quote(&self, measurement: Measurement, debug: bool, report_data: [u8; 64]) -> Evidence {
        SimulatedPlatform::quote(self, measurement, debug, report_data)
    }
}

/// An announced epoch key as the enclave checks released shares against
/// it: the X25519 public key traders sealed to and, for a Feldman dealing,
/// the commitments `C_0..= C_{t-1}` (empty for a dev key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochKey {
    pub epoch_pk: [u8; 32],
    pub commitments: Vec<[u8; 32]>,
}

/// Why the enclave did not use a released share.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ShareRejection {
    #[error("share did not open under the enclave's seal key and this header")]
    Unopened,
    #[error("share names another member")]
    WrongMember,
    #[error("share is not a canonical scalar")]
    NotCanonical,
    #[error("member released more than one share")]
    Duplicate,
    #[error("share does not verify against the announced commitments")]
    Inconsistent,
}

/// A reconstructed epoch secret.
#[derive(Debug)]
pub struct Reconstructed {
    pub secret: Zeroizing<EpochSecret>,
    /// Members whose shares were combined.
    pub used: Vec<u8>,
    /// Members whose shares were dropped, and why.
    pub rejected: Vec<(u8, ShareRejection)>,
}

/// Why the epoch secret could not be reconstructed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReconstructError {
    #[error("announced commitments are malformed or do not match the threshold")]
    Commitments,
    #[error("{usable} usable shares, {threshold} needed")]
    NotEnoughShares {
        usable: usize,
        threshold: u8,
        rejected: Vec<(u8, ShareRejection)>,
    },
    #[error("shares do not reconstruct the announced key")]
    KeyMismatch { rejected: Vec<(u8, ShareRejection)> },
}

impl ReconstructError {
    /// Members whose shares were dropped, and why.
    pub fn rejected(&self) -> &[(u8, ShareRejection)] {
        match self {
            ReconstructError::Commitments => &[],
            ReconstructError::NotEnoughShares { rejected, .. }
            | ReconstructError::KeyMismatch { rejected } => rejected,
        }
    }
}

/// What a batch run needs besides the batch and its key.
#[derive(Clone, Copy, Debug)]
pub struct RunInputs<'a> {
    /// Mixed into the order seed of a version 2 header.
    pub market_address: &'a [u8; 32],
    /// Provenance admission vector, one entry per envelope.
    pub admission: Option<&'a [Option<TraderId>]>,
    /// Digest of the attestation the receipt commits to.
    pub attestation: Hash32,
}

pub struct Enclave {
    quoter: Arc<dyn Quoter>,
    measurement: Measurement,
    debug: bool,
    seal: SealSecret,
    signer: ExecutorKey,
}

impl core::fmt::Debug for Enclave {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Enclave")
            .field("executor", &self.signer.id())
            .field("debug", &self.debug)
            .finish()
    }
}

impl Enclave {
    /// Boot an enclave running `measurement`. Keys are drawn from the OS RNG.
    pub fn boot(quoter: Arc<dyn Quoter>, measurement: Measurement, debug: bool) -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            quoter,
            measurement,
            debug,
            seal: SealSecret::generate(&mut rng),
            signer: ExecutorKey::generate(&mut rng),
        }
    }

    /// Boot with keys persisted by the host (simulated platform only: a TDX
    /// enclave draws fresh keys at every boot).
    pub fn boot_with_keys(
        quoter: Arc<dyn Quoter>,
        measurement: Measurement,
        debug: bool,
        seal: SealSecret,
        signer: ExecutorKey,
    ) -> Self {
        Self {
            quoter,
            measurement,
            debug,
            seal,
            signer,
        }
    }

    /// Signs `H(RPC_ENVELOPE, bytes_before_sig)` with the executor key. The
    /// enclave's only route to envelope signatures: the domain is fixed here.
    pub fn sign_rpc_envelope(&self, bytes_before_sig: &[u8]) -> Signature {
        self.signer
            .sign(&hash(domain::RPC_ENVELOPE, bytes_before_sig))
    }

    /// Co-signature over an outcome this enclave computed itself.
    pub fn sign_cosign(
        &self,
        market: &[u8; 32],
        epoch: EpochId,
        header_digest: &Hash32,
        outcome_digest: &Hash32,
    ) -> Signature {
        self.signer
            .sign(&cosign_digest(market, epoch, header_digest, outcome_digest))
    }

    pub fn executor_id(&self) -> ExecutorId {
        self.signer.id()
    }

    pub fn seal_key(&self) -> [u8; 32] {
        self.seal.public()
    }

    pub fn measurement(&self) -> Measurement {
        self.measurement
    }

    /// Evidence binding this enclave's keys to `header` and the nonces.
    pub fn attest(&self, header: &BatchHeader, nonces: Vec<Hash32>) -> ExecutorAttestation {
        let header_digest = header.digest();
        let seal_key = self.seal.public();
        let executor = self.signer.id();
        let rd = report_data(
            &seal_key,
            &executor,
            &header_digest,
            &nonces_digest(&nonces),
        );
        let evidence = self.quoter.quote(self.measurement, self.debug, rd);
        ExecutorAttestation {
            executor,
            seal_key,
            header_digest,
            nonces,
            evidence,
        }
    }

    /// Key-release evidence: binds the keys, the header, the members'
    /// nonces and the digest of the committee the enclave was given.
    pub fn attest_v2(
        &self,
        header: &BatchHeader,
        nonces: Vec<Hash32>,
        committee_digest: Hash32,
    ) -> ExecutorAttestationV2 {
        let quoted = self.attestation_v2(header, nonces, committee_digest, |rd| {
            Ok::<_, Infallible>(self.quoter.quote(self.measurement, self.debug, rd))
        });
        match quoted {
            Ok(att) => att,
            Err(never) => match never {},
        }
    }

    /// [`Self::attest_v2`] through [`Quoter::try_quote`].
    pub fn try_attest_v2(
        &self,
        header: &BatchHeader,
        nonces: Vec<Hash32>,
        committee_digest: Hash32,
    ) -> Result<ExecutorAttestationV2, QuoteError> {
        self.attestation_v2(header, nonces, committee_digest, |rd| {
            self.quoter.try_quote(self.measurement, self.debug, rd)
        })
    }

    fn attestation_v2<E>(
        &self,
        header: &BatchHeader,
        nonces: Vec<Hash32>,
        committee_digest: Hash32,
        quote: impl FnOnce([u8; 64]) -> Result<Evidence, E>,
    ) -> Result<ExecutorAttestationV2, E> {
        let header_digest = header.digest();
        let seal_key = self.seal.public();
        let executor = self.signer.id();
        let evidence = quote(report_data_v2(
            &seal_key,
            &executor,
            &header_digest,
            &nonces_digest(&nonces),
            &committee_digest,
        ))?;
        Ok(ExecutorAttestationV2 {
            executor,
            seal_key,
            header_digest,
            nonces,
            committee_digest,
            evidence,
        })
    }

    /// Open released shares and reconstruct the epoch secret.
    ///
    /// With commitments, every share is checked on its own against them, so
    /// bad shares are dropped in O(n) and the first `t` valid ones are
    /// combined. Without commitments (a dev key), subsets of `threshold`
    /// shares are tried one at a time until one reproduces the public key,
    /// which costs up to C(n, t) combinations. Either way the result must
    /// satisfy `x25519_public(s) == epoch_pk`. Share plaintexts and the
    /// secret are wiped when dropped.
    pub fn reconstruct_threshold(
        &self,
        header: &BatchHeader,
        key: &EpochKey,
        threshold: u8,
        sealed: &[SealedShare],
    ) -> Result<Reconstructed, ReconstructError> {
        let t = usize::from(threshold);
        if t == 0 || (!key.commitments.is_empty() && key.commitments.len() != t) {
            return Err(ReconstructError::Commitments);
        }
        let points = key
            .commitments
            .iter()
            .map(decompress_canonical)
            .collect::<Option<Vec<_>>>()
            .ok_or(ReconstructError::Commitments)?;

        let info = share_info(header.market, header.epoch);
        let aad = header.digest();
        let mut shares: Vec<ScalarShare> = Vec::with_capacity(sealed.len());
        let mut rejected = Vec::new();
        for s in sealed {
            if shares.iter().any(|o| o.index == s.member)
                || rejected.iter().any(|(m, _)| *m == s.member)
            {
                rejected.push((s.member, ShareRejection::Duplicate));
                continue;
            }
            let share = match self.open_share(s, &info, &aad) {
                Ok(share) => share,
                Err(why) => {
                    rejected.push((s.member, why));
                    continue;
                }
            };
            if !points.is_empty() {
                if !verify_share(&share, &points) {
                    rejected.push((s.member, ShareRejection::Inconsistent));
                    continue;
                }
                if shares.len() == t {
                    // Enough verified shares already. Later ones are not
                    // needed.
                    continue;
                }
            }
            shares.push(share);
        }
        if shares.len() < t {
            return Err(ReconstructError::NotEnoughShares {
                usable: shares.len(),
                threshold,
                rejected,
            });
        }

        let found = if points.is_empty() {
            Combinations::new(shares.len(), t).find_map(|subset| {
                let picked: Vec<ScalarShare> = subset.iter().map(|&i| shares[i].clone()).collect();
                let s = lagrange_combine(&picked);
                (x25519_public(&s) == key.epoch_pk)
                    .then(|| (s, picked.iter().map(|p| p.index).collect()))
            })
        } else {
            let s = lagrange_combine(&shares[..t]);
            (x25519_public(&s) == key.epoch_pk)
                .then(|| (s, shares[..t].iter().map(|p| p.index).collect()))
        };
        let Some((s, used)) = found else {
            return Err(ReconstructError::KeyMismatch { rejected });
        };
        Ok(Reconstructed {
            secret: Zeroizing::new(EpochSecret::Threshold(ScalarSealSecret::from_scalar(*s))),
            used,
            rejected,
        })
    }

    /// Open one released share: `index || scalar` sealed to this enclave's
    /// seal key under the header digest.
    fn open_share(
        &self,
        s: &SealedShare,
        info: &[u8],
        aad: &Hash32,
    ) -> Result<ScalarShare, ShareRejection> {
        let pt = open(
            &self.seal,
            &s.sealed.ephemeral,
            info,
            aad.as_bytes(),
            &s.sealed.ciphertext,
        )
        .map_err(|_| ShareRejection::Unopened)?;
        if pt.len() != 33 {
            return Err(ShareRejection::Unopened);
        }
        if pt[0] != s.member {
            return Err(ShareRejection::WrongMember);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&pt[1..]);
        ScalarShare::from_bytes(s.member, &bytes).ok_or(ShareRejection::NotCanonical)
    }

    /// Run the batch with the reconstructed secret and sign the receipt. The
    /// secret is dropped (and wiped) once the envelopes are open and the
    /// order seed is derived.
    pub fn execute(
        &self,
        batch: &ExecutionBatch,
        key: Zeroizing<EpochSecret>,
        inputs: RunInputs<'_>,
        prover: Option<&dyn PlainProver>,
        mut metrics: ExecutionMetrics,
    ) -> Result<(ExecutionReceipt, PlainExecution, Option<ProofArtifact>), ExecutorError> {
        let h = &batch.header;
        let band = check_header(h, &batch.envelopes, &batch.balances, &batch.prior_state)?;
        let t = std::time::Instant::now();
        let opened = open_envelopes(&key, h.params.commitment_scheme, &batch.envelopes);
        let seed = order_seed(h, &key, inputs.market_address);
        drop(key);
        metrics.stages.push(("open".into(), t.elapsed()));
        let mut plain = execute_opened(batch, &band, &seed, opened, inputs.admission, metrics)?;
        // The prover sees plaintext, so it runs inside the boundary.
        let proof = match prover {
            Some(p) => {
                let t = std::time::Instant::now();
                let a = p.prove(h, &batch.prior_state, &plain)?;
                plain.metrics.stages.push(("prove".into(), t.elapsed()));
                a
            }
            None => None,
        };
        let receipt = ExecutionReceipt::sign(
            &self.signer,
            plain.outcome.clone(),
            BackendKind::Tee,
            inputs.attestation,
            proof.as_ref().map_or(Hash32::ZERO, |p| p.digest),
            plain.trace.digest(),
        );
        Ok((receipt, plain, proof))
    }
}

/// The `k`-subsets of `0..n` in lexicographic order, produced one at a
/// time so a search can stop at the first match.
struct Combinations {
    n: usize,
    next: Option<Vec<usize>>,
}

impl Combinations {
    fn new(n: usize, k: usize) -> Self {
        Self {
            n,
            next: (k <= n).then(|| (0..k).collect()),
        }
    }
}

impl Iterator for Combinations {
    type Item = Vec<usize>;

    fn next(&mut self) -> Option<Vec<usize>> {
        let current = self.next.take()?;
        let k = current.len();
        let mut following = current.clone();
        // Rightmost position that can still move right.
        if let Some(i) = (0..k).rev().find(|&i| following[i] < self.n - k + i) {
            following[i] += 1;
            for j in i + 1..k {
                following[j] = following[j - 1] + 1;
            }
            self.next = Some(following);
        }
        Some(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsets_in_lexicographic_order() {
        let all: Vec<_> = Combinations::new(4, 2).collect();
        assert_eq!(
            all,
            vec![
                vec![0, 1],
                vec![0, 2],
                vec![0, 3],
                vec![1, 2],
                vec![1, 3],
                vec![2, 3]
            ]
        );
        assert_eq!(
            Combinations::new(3, 3).collect::<Vec<_>>(),
            vec![vec![0, 1, 2]]
        );
        assert_eq!(Combinations::new(3, 0).count(), 1);
        assert_eq!(Combinations::new(2, 3).count(), 0);
        assert_eq!(Combinations::new(16, 8).count(), 12_870);
    }
}
