//! Proof-carrying execution.
//!
//! [`Groth16Prover`] turns a plaintext execution into an
//! [`AuctionCircuit`](crate::prover::AuctionCircuit) witness and proves it.
//! It plugs into any executor that holds plaintext (reference, or inside a
//! TEE) through `crate::PlainProver`.
//!
//! Proof modes:
//!
//! * **synchronous** - the receipt is signed only once the proof exists, and
//!   commits to its digest. Settlement can require it.
//! * **deferred** - the receipt is signed immediately. The proof is produced
//!   by a worker and delivered later. Settlement proceeds on the receipt and
//!   the market treats a missing proof after the window as an executor
//!   fault. This trades public verifiability at settlement time for
//!   latency. The window is the exposure. Both queues are bounded: a full
//!   job queue refuses new batches (backpressure on the executor), and
//!   finished proofs nobody collects are dropped oldest first.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::prover::{AuctionCircuit, EntryInput, Keys, OrderWitness};
use crate::verifier::{CircuitShape, ProofBundle, TranscriptEntry, group, transcript};
use crate::{ExecutorError, PlainExecution, PlainProver, ProofArtifact};
use rand::SeedableRng;
use timescales_auction::BatchHeader;
use timescales_auction::orderbook::{Disposition, OrderStateTable};
use timescales_core::commitment::poseidon;
use timescales_core::intent::IntentBody;
use timescales_core::{CommitmentScheme, Hash32, Rationing};

/// Shape that fits a batch header with room for `capacity` envelopes.
pub fn shape_for(header: &BatchHeader, capacity: usize) -> CircuitShape {
    CircuitShape {
        capacity,
        ticks: header.band.ticks(),
        qty_bits: header.params.max_order_lots_log2,
        flow: header.params.flow,
    }
}

/// Build the witness for `plain`. Fails if the market cannot be proven
/// with this circuit (wrong commitment scheme, pro-rata rationing, batch
/// larger than the shape).
pub fn circuit_for(
    shape: CircuitShape,
    header: &BatchHeader,
    prior: &OrderStateTable,
    plain: &PlainExecution,
) -> Result<(AuctionCircuit, Vec<bool>), ExecutorError> {
    let unsupported = |m: &str| ExecutorError::Execution(format!("cannot prove: {m}"));
    if header.params.commitment_scheme != CommitmentScheme::PoseidonBn254 {
        return Err(unsupported("market does not use Poseidon commitments"));
    }
    if header.params.rationing != Rationing::Lottery {
        return Err(unsupported("circuit implements lottery rationing only"));
    }
    if plain.candidates.len() > shape.capacity
        || shape.ticks != header.band.ticks()
        || shape.flow != header.params.flow
    {
        return Err(unsupported("batch does not fit the circuit shape"));
    }
    let fills: BTreeMap<_, _> = plain
        .artifacts
        .fills
        .iter()
        .map(|f| (f.commitment, *f))
        .collect();
    let mut entries = Vec::with_capacity(shape.capacity);
    let mut admitted = Vec::with_capacity(plain.candidates.len());
    for (cand, (_, disp)) in plain.candidates.iter().zip(&plain.validated.dispositions) {
        let is_admitted = *disp == Disposition::Accepted;
        let commitment = poseidon::from_commitment(&cand.commitment)
            .ok_or_else(|| unsupported("commitment not canonical"))?;
        let (fill, tag) = match (is_admitted, fills.get(&cand.commitment)) {
            (true, Some(f)) => (f.quantity.0, 1 + group(f.role, f.side)),
            _ => (0, 0),
        };
        let order = match (&cand.intent, is_admitted) {
            (Ok(pi), true) => match pi.body {
                IntentBody::Place(o) => Some(OrderWitness {
                    order: o,
                    salt: pi.salt,
                    group: usize::from(group(o.role, o.side)),
                    slot: o.slot(&header.band),
                }),
                _ => return Err(unsupported("admitted entry is not a placement")),
            },
            _ => None,
        };
        let entry = TranscriptEntry {
            commitment,
            filled: prior.get(&cand.commitment).map_or(0, |e| e.filled.0),
            admitted: is_admitted,
            fill,
            tag,
        };
        entries.push(EntryInput { entry, order });
        admitted.push(is_admitted);
    }
    entries.resize(shape.capacity, EntryInput::padding());
    let t: Vec<TranscriptEntry> = entries.iter().map(|e| e.entry).collect();
    let books = plain
        .outcome
        .clearing
        .iter()
        .map(|c| {
            (
                u32::try_from(c.tick.0 - header.band.lo.0).unwrap_or(u32::MAX),
                c.volume.0,
            )
        })
        .collect();
    Ok((
        AuctionCircuit {
            shape,
            lo: header.band.lo.0,
            entries,
            books,
            transcript: transcript(&t),
        },
        admitted,
    ))
}

fn prove_bundle(
    keys: &Keys,
    circuit: AuctionCircuit,
    admitted: Vec<bool>,
) -> Result<ProofBundle, ExecutorError> {
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let shape = circuit.shape;
    let proof = crate::prover::prove(keys, circuit, &mut rng)
        .map_err(|e| ExecutorError::Execution(e.to_string()))?;
    Ok(ProofBundle {
        shape,
        admitted,
        proof,
    })
}

pub fn artifact(bundle: &ProofBundle) -> ProofArtifact {
    ProofArtifact {
        digest: bundle.digest(),
        bytes: bundle.to_bytes(),
    }
}

/// Synchronous Groth16 proving.
pub struct Groth16Prover {
    keys: Arc<Keys>,
}

impl core::fmt::Debug for Groth16Prover {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Groth16Prover")
            .field("shape", &self.keys.shape)
            .finish()
    }
}

impl Groth16Prover {
    pub fn new(keys: Arc<Keys>) -> Self {
        Self { keys }
    }
}

impl PlainProver for Groth16Prover {
    fn prove(
        &self,
        header: &BatchHeader,
        prior: &OrderStateTable,
        plain: &PlainExecution,
    ) -> Result<Option<ProofArtifact>, ExecutorError> {
        let (c, admitted) = circuit_for(self.keys.shape, header, prior, plain)?;
        Ok(Some(artifact(&prove_bundle(&self.keys, c, admitted)?)))
    }
}

/// A proof that finished in the background.
#[derive(Clone, Debug)]
pub struct DeferredProof {
    pub header: Hash32,
    pub bundle: Result<ProofBundle, ExecutorError>,
    /// Time from hand-off to completion.
    pub lag: Duration,
}

type Job = (Hash32, AuctionCircuit, Vec<bool>, Instant);

/// Jobs waiting for the worker, by default.
pub const DEFAULT_JOB_QUEUE: usize = 4;
/// Finished proofs kept for [`DeferredProver::next`], by default.
pub const DEFAULT_RESULT_QUEUE: usize = 16;

/// Finished proofs, oldest first, at most `bound` of them.
struct Results {
    queue: Mutex<VecDeque<DeferredProof>>,
    ready: Condvar,
    bound: usize,
    dropped: Mutex<u64>,
}

impl Results {
    fn push(&self, proof: DeferredProof) {
        let Ok(mut q) = self.queue.lock() else {
            return;
        };
        while q.len() >= self.bound {
            q.pop_front();
            if let Ok(mut d) = self.dropped.lock() {
                *d += 1;
            }
        }
        q.push_back(proof);
        self.ready.notify_one();
    }
}

/// Deferred proving: witness built synchronously (cheap, inside the
/// boundary), proof computed by a worker thread.
pub struct DeferredProver {
    keys: Arc<Keys>,
    jobs: Mutex<SyncSender<Job>>,
    done: Arc<Results>,
    _worker: JoinHandle<()>,
}

impl core::fmt::Debug for DeferredProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeferredProver")
            .field("shape", &self.keys.shape)
            .finish_non_exhaustive()
    }
}

impl DeferredProver {
    pub fn new(keys: Arc<Keys>) -> Self {
        Self::with_bounds(keys, DEFAULT_JOB_QUEUE, DEFAULT_RESULT_QUEUE)
    }

    /// At most `jobs` batches wait for the worker (at least one), and at
    /// most `results` finished proofs wait for [`Self::next`] (at least
    /// one).
    pub fn with_bounds(keys: Arc<Keys>, jobs: usize, results: usize) -> Self {
        Self::spawn(keys, jobs, results, prove_bundle)
    }

    fn spawn(
        keys: Arc<Keys>,
        jobs: usize,
        results: usize,
        prove: impl Fn(&Keys, AuctionCircuit, Vec<bool>) -> Result<ProofBundle, ExecutorError>
        + Send
        + 'static,
    ) -> Self {
        let (tx, rx) = sync_channel::<Job>(jobs.max(1));
        let done = Arc::new(Results {
            queue: Mutex::default(),
            ready: Condvar::new(),
            bound: results.max(1),
            dropped: Mutex::default(),
        });
        let k = Arc::clone(&keys);
        let out = Arc::clone(&done);
        // The worker stops when the prover, and with it the job sender, is
        // dropped.
        let worker = std::thread::spawn(move || {
            for (header, circuit, admitted, queued) in rx {
                let bundle = prove(&k, circuit, admitted);
                out.push(DeferredProof {
                    header,
                    bundle,
                    lag: queued.elapsed(),
                });
            }
        });
        Self {
            keys,
            jobs: Mutex::new(tx),
            done,
            _worker: worker,
        }
    }

    /// Block until the next deferred proof completes or `timeout` passes.
    pub fn next(&self, timeout: Duration) -> Option<DeferredProof> {
        let q = self.done.queue.lock().ok()?;
        let (mut q, _) = self
            .done
            .ready
            .wait_timeout_while(q, timeout, |q| q.is_empty())
            .ok()?;
        q.pop_front()
    }

    /// Finished proofs dropped because nobody collected them in time.
    pub fn dropped(&self) -> u64 {
        self.done.dropped.lock().map_or(0, |d| *d)
    }
}

impl PlainProver for DeferredProver {
    /// Queues the witness for the worker. A full queue is
    /// `ExecutorError::Unavailable`, so a scheduler retries the batch later
    /// instead of piling up plaintext witnesses.
    fn prove(
        &self,
        header: &BatchHeader,
        prior: &OrderStateTable,
        plain: &PlainExecution,
    ) -> Result<Option<ProofArtifact>, ExecutorError> {
        let (c, admitted) = circuit_for(self.keys.shape, header, prior, plain)?;
        let sent = self
            .jobs
            .lock()
            .map_err(|_| ExecutorError::Unavailable("proof queue poisoned".into()))?
            .try_send((header.digest(), c, admitted, Instant::now()));
        match sent {
            Ok(()) => Ok(None),
            Err(TrySendError::Full(_)) => {
                Err(ExecutorError::Unavailable("proof queue full".into()))
            }
            Err(TrySendError::Disconnected(_)) => {
                Err(ExecutorError::Unavailable("proof worker stopped".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests;
