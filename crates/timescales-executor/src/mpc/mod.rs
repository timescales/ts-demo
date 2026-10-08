//! MPC execution backend.
//!
//! A committee of `m` parties runs the batch auction over authenticated
//! additive shares (SPDZ-style MACs, security with abort against up to
//! `m - 1` corrupted parties). Preprocessing comes from a trusted dealer.
//! See `dealer` for what that does and does not model.
//!
//! The parties are simulated in one process. Local computation is measured.
//! Communication is counted in rounds and bytes and converted to latency
//! with a [`NetworkModel`]. Reported "online time" is
//! `measured compute / m + modelled network`, and every table that uses it
//! says so.
//!
//! The committee's receipt is signed with a single committee key standing
//! in for a threshold signature.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod auction;
pub mod dealer;
pub mod encoding;
pub mod engine;
pub mod field;
pub mod shares;

pub use auction::AuctionOutput;
pub use dealer::{Dealer, MaskLimits, MaskRefusal, PreprocessingCounts};
pub use encoding::{Layout, MaskSource, mask_order, try_mask_order};
#[cfg(feature = "fault-injection")]
pub use engine::Fault;
pub use engine::{Engine, LtCircuit, Meter, MpcError, NetworkModel};
pub use field::Fp;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::pipeline::{check_header_commitments, finalize};
use crate::{
    ConfidentialExecutor, ExecutionBatch, ExecutionMetrics, ExecutionResult, ExecutorError,
    spawn_blocking,
};
use thiserror::Error;
use timescales_auction::receipts::{BackendKind, ExecutionReceipt};
use timescales_core::crypto::{Hasher, domain};
use timescales_core::identity::ExecutorKey;
use timescales_core::intent::masked::MAX_MASKED_LEN;
use timescales_core::{EpochId, ExecutorId, Hash32, PROTOCOL_VERSION, TraderId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpcConfig {
    pub parties: usize,
    /// MACs and MAC checks (active security with abort). Off measures the
    /// semi-honest cost.
    pub authenticated: bool,
    pub circuit: LtCircuit,
    /// Seed of the dealer's RNG. `None` draws it from the OS: anyone who
    /// knows the seed can recompute every input mask.
    pub dealer_seed: Option<[u8; 32]>,
}

impl Default for MpcConfig {
    fn default() -> Self {
        Self {
            parties: 3,
            authenticated: true,
            circuit: LtCircuit::LogDepth,
            dealer_seed: None,
        }
    }
}

/// Measurements from the last batch.
#[derive(Clone, Debug, Default)]
pub struct MpcReport {
    pub parties: usize,
    pub meter: Meter,
    pub phases: Vec<(&'static str, Meter)>,
    pub preprocessing: PreprocessingCounts,
    /// Dealer wall time while the batch ran (not representative of real
    /// preprocessing. See `dealer`).
    pub dealer_time: Duration,
    /// Wall time of the simulation excluding dealer work. All parties run
    /// in this process, so per-party compute is this divided by `parties`.
    pub simulated_compute: Duration,
    pub accepted: usize,
    pub rejected: usize,
}

impl MpcReport {
    pub fn per_party_compute(&self) -> Duration {
        self.simulated_compute / u32::try_from(self.parties.max(1)).unwrap_or(1)
    }

    /// Estimated online latency under `net`.
    pub fn online_latency(&self, net: &NetworkModel) -> Duration {
        self.per_party_compute() + net.overhead(&self.meter, self.parties)
    }
}

/// A committee configuration that cannot run.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    #[error("MPC needs at least two parties, not {0}")]
    Parties(usize),
}

/// The committee: preprocessing state persists across batches because input
/// masks are handed out before the batch runs.
pub struct MpcCommittee {
    config: MpcConfig,
    dealer: Mutex<Option<Dealer>>,
    signer: ExecutorKey,
    /// Mask length each epoch's band implies, where known.
    layouts: Mutex<BTreeMap<EpochId, usize>>,
    #[cfg(feature = "fault-injection")]
    fault: Mutex<Option<Fault>>,
    last: Mutex<Option<MpcReport>>,
}

impl core::fmt::Debug for MpcCommittee {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MpcCommittee")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Puts the dealer back into the committee when a run ends, however it
/// ends: a panic inside the protocol must not leave the committee busy
/// for good.
struct DealerLease<'a> {
    slot: &'a Mutex<Option<Dealer>>,
    engine: Option<Engine>,
}

impl DealerLease<'_> {
    fn engine(&mut self) -> &mut Engine {
        match self.engine.as_mut() {
            Some(e) => e,
            None => unreachable!("the engine is taken only on drop"),
        }
    }
}

impl Drop for DealerLease<'_> {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.take() {
            let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(engine.into_dealer());
        }
    }
}

impl MpcCommittee {
    /// # Panics
    ///
    /// If `config.parties < 2`. [`Self::try_new`] reports that instead.
    pub fn new(config: MpcConfig, signer: ExecutorKey) -> Self {
        match Self::try_new(config, signer) {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        }
    }

    pub fn try_new(config: MpcConfig, signer: ExecutorKey) -> Result<Self, ConfigError> {
        if config.parties < 2 {
            return Err(ConfigError::Parties(config.parties));
        }
        let dealer = Dealer::new(config.parties, config.authenticated, config.dealer_seed);
        Ok(Self {
            config,
            dealer: Mutex::new(Some(dealer)),
            signer,
            layouts: Mutex::default(),
            #[cfg(feature = "fault-injection")]
            fault: Mutex::default(),
            last: Mutex::default(),
        })
    }

    pub fn config(&self) -> MpcConfig {
        self.config
    }

    /// Bound the mask values handed out and not taken or expired yet
    /// ([`MaskLimits::default`] otherwise).
    pub fn with_mask_limits(mut self, limits: MaskLimits) -> Self {
        let slot = self.dealer.get_mut().unwrap_or_else(|e| e.into_inner());
        *slot = slot.take().map(|d| d.with_mask_limits(limits));
        self
    }

    /// The key the committee signs receipts with.
    pub fn executor_id(&self) -> ExecutorId {
        self.signer.id()
    }

    #[cfg(feature = "fault-injection")]
    pub fn set_fault(&self, f: Option<Fault>) {
        if let Ok(mut g) = self.fault.lock() {
            *g = f;
        }
    }

    pub fn last_report(&self) -> Option<MpcReport> {
        self.last.lock().ok().and_then(|g| g.clone())
    }

    fn dealer(&self) -> Result<MutexGuard<'_, Option<Dealer>>, ExecutorError> {
        self.dealer
            .lock()
            .map_err(|_| ExecutorError::Unavailable("committee poisoned".into()))
    }

    /// Masks for `epoch` must have `layout.len` values: the one length
    /// the epoch's band allows.
    pub fn expect_layout(&self, epoch: EpochId, layout: &Layout) {
        if let Ok(mut l) = self.layouts.lock() {
            l.insert(epoch, layout.len());
        }
    }

    /// Hand a trader a fresh mask block of `len` values, `1..=
    /// MAX_MASKED_LEN` (the longest masked placement an envelope can carry),
    /// within the committee's [`MaskLimits`]. The block is not tied to an
    /// epoch, so only taking it releases it. Orders use
    /// [`Self::request_masks_for`].
    pub fn request_masks(
        &self,
        owner: TraderId,
        len: usize,
    ) -> Result<(u64, Vec<Fp>), ExecutorError> {
        check_mask_len(len)?;
        let mut g = self.dealer()?;
        let d = g
            .as_mut()
            .ok_or_else(|| ExecutorError::Unavailable("committee busy".into()))?;
        d.try_input_masks(owner, len).map_err(refused)
    }

    /// [`Self::request_masks`] for an order in `epoch`. The block expires
    /// with the epoch, and if [`Self::expect_layout`] named the epoch's
    /// length, `len` must be it.
    pub fn request_masks_for(
        &self,
        owner: TraderId,
        epoch: EpochId,
        len: usize,
    ) -> Result<(u64, Vec<Fp>), ExecutorError> {
        check_mask_len(len)?;
        let expected = self
            .layouts
            .lock()
            .map_err(|_| ExecutorError::Unavailable("committee poisoned".into()))?
            .get(&epoch)
            .copied();
        if expected.is_some_and(|l| l != len) {
            return Err(ExecutorError::Execution(format!(
                "mask length {len} does not match the epoch's layout"
            )));
        }
        let mut g = self.dealer()?;
        let d = g
            .as_mut()
            .ok_or_else(|| ExecutorError::Unavailable("committee busy".into()))?;
        d.input_masks_for(owner, epoch, len).map_err(refused)
    }

    /// Drop the unconsumed mask blocks of every epoch up to `through` (call
    /// when an epoch is terminal). Returns how many were dropped. A run of
    /// an epoch's batch does this for that epoch itself.
    pub fn expire_masks(&self, through: EpochId) -> Result<usize, ExecutorError> {
        if let Ok(mut l) = self.layouts.lock() {
            l.retain(|e, _| *e > through);
        }
        let mut g = self.dealer()?;
        let d = g
            .as_mut()
            .ok_or_else(|| ExecutorError::Unavailable("committee busy".into()))?;
        Ok(d.expire_masks(through))
    }

    /// Mask blocks handed out and not consumed or expired yet.
    pub fn outstanding_masks(&self) -> Result<usize, ExecutorError> {
        let g = self.dealer()?;
        let d = g
            .as_ref()
            .ok_or_else(|| ExecutorError::Unavailable("committee busy".into()))?;
        Ok(d.outstanding_masks())
    }

    fn run_blocking(&self, batch: &ExecutionBatch) -> Result<ExecutionResult, ExecutorError> {
        let h = &batch.header;
        // A version 2 root binds envelope digests, which masked inputs do
        // not carry. Such batches have no masked encoding.
        if h.version != PROTOCOL_VERSION {
            return Err(ExecutorError::Execution(
                "MPC backend runs version 1 headers only".into(),
            ));
        }
        let commitments: Vec<_> = batch.masked.iter().map(|m| m.commitment).collect();
        if !batch.envelopes.is_empty()
            && batch
                .envelopes
                .iter()
                .map(|e| e.commitment)
                .ne(commitments.iter().copied())
        {
            return Err(ExecutorError::BadHeader(
                "masked and sealed inputs disagree",
            ));
        }
        let band = check_header_commitments(h, &commitments, &batch.balances, &batch.prior_state)?;
        if h.params.rationing != timescales_core::Rationing::Lottery {
            return Err(ExecutorError::Unavailable(
                "MPC backend implements lottery rationing only".into(),
            ));
        }

        let mut dealer = self
            .dealer()?
            .take()
            .ok_or_else(|| ExecutorError::Unavailable("committee busy".into()))?;
        dealer.reset_counts();
        let mut lease = DealerLease {
            slot: &self.dealer,
            engine: Some(Engine::with_dealer(dealer, self.config.circuit)),
        };
        #[cfg(feature = "fault-injection")]
        lease
            .engine()
            .set_fault(self.fault.lock().ok().and_then(|g| *g));
        let t = Instant::now();
        let result = auction::run(
            lease.engine(),
            h,
            &band,
            &batch.masked,
            &batch.balances,
            &batch.prior_state,
        );
        let wall = t.elapsed();
        let engine = lease.engine();
        let meter = engine.meter();
        let preprocessing = engine.preprocessing();
        let dealer_time = engine.dealer_time();
        let parties = engine.parties();
        // The run consumed this epoch's masks, used or not.
        engine.dealer().expire_masks(h.epoch);
        drop(lease);
        if let Ok(mut l) = self.layouts.lock() {
            l.retain(|e, _| *e > h.epoch);
        }
        let out = result.map_err(|e| match e {
            MpcError::PartyUnavailable { .. } | MpcError::MacCheckFailed => {
                ExecutorError::Aborted(e.to_string())
            }
            other => ExecutorError::Execution(other.to_string()),
        })?;
        let report = MpcReport {
            parties,
            meter,
            phases: out.phases.clone(),
            preprocessing,
            dealer_time,
            simulated_compute: wall.saturating_sub(dealer_time),
            accepted: out.accepted,
            rejected: out.rejected,
        };

        let t = Instant::now();
        let fin = finalize(
            h,
            out.fills,
            out.clearing,
            out.cancelled,
            &batch.balances,
            &batch.prior_state,
        )?;
        let mut metrics = ExecutionMetrics::default();
        metrics.stages.push(("mpc".into(), wall));
        metrics.stages.push(("settle".into(), t.elapsed()));
        metrics.accepted = out.accepted;
        metrics.rejected = out.rejected;

        let mut tr = Hasher::new(domain::TRACE).chain(h.digest().as_bytes());
        for (name, m) in &report.phases {
            tr.update(name.as_bytes());
            tr.update(&m.rounds.to_le_bytes());
            tr.update(&m.opened.to_le_bytes());
        }
        let receipt = ExecutionReceipt::sign(
            &self.signer,
            fin.outcome,
            BackendKind::Mpc,
            Hash32::ZERO,
            Hash32::ZERO,
            tr.finalize(),
        );
        if let Ok(mut g) = self.last.lock() {
            *g = Some(report);
        }
        Ok(ExecutionResult {
            receipt,
            artifacts: fin.artifacts,
            metrics,
            attestation: None,
            proof: None,
        })
    }
}

/// The pool frees up as blocks are taken or expire.
fn refused(e: MaskRefusal) -> ExecutorError {
    ExecutorError::Unavailable(e.to_string())
}

fn check_mask_len(len: usize) -> Result<(), ExecutorError> {
    if len == 0 || len > MAX_MASKED_LEN {
        return Err(ExecutorError::Execution(format!(
            "mask length {len} outside 1..={MAX_MASKED_LEN}"
        )));
    }
    Ok(())
}

impl MaskSource for &MpcCommittee {
    fn masks(
        &mut self,
        owner: TraderId,
        epoch: EpochId,
        len: usize,
    ) -> Result<(u64, Vec<Fp>), ExecutorError> {
        self.request_masks_for(owner, epoch, len)
    }
}

/// [`ConfidentialExecutor`] over a shared committee.
#[derive(Clone, Debug)]
pub struct MpcExecutor {
    committee: Arc<MpcCommittee>,
}

impl MpcExecutor {
    pub fn new(committee: Arc<MpcCommittee>) -> Self {
        Self { committee }
    }

    pub fn committee(&self) -> &Arc<MpcCommittee> {
        &self.committee
    }

    pub fn executor_id(&self) -> ExecutorId {
        self.committee.executor_id()
    }

    /// Run a shared batch on the blocking pool. A panic in the protocol is
    /// an execution error, which schedulers do not retry, and the dealer is
    /// back in the committee before it surfaces.
    pub async fn execute_shared(
        &self,
        batch: Arc<ExecutionBatch>,
    ) -> Result<ExecutionResult, ExecutorError> {
        let c = Arc::clone(&self.committee);
        spawn_blocking(move || c.run_blocking(&batch)).await
    }
}

impl ConfidentialExecutor for MpcExecutor {
    fn backend(&self) -> BackendKind {
        BackendKind::Mpc
    }

    async fn execute(&self, batch: ExecutionBatch) -> Result<ExecutionResult, ExecutorError> {
        self.execute_shared(Arc::new(batch)).await
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    #[test]
    fn a_run_that_panics_hands_the_dealer_back() {
        let c = MpcCommittee::new(
            MpcConfig {
                dealer_seed: Some([1; 32]),
                ..MpcConfig::default()
            },
            ExecutorKey::from_seed([1; 32]),
        );
        let (offset, _) = c.request_masks(TraderId([1; 32]), 4).unwrap();
        let run = catch_unwind(AssertUnwindSafe(|| {
            let dealer = c.dealer.lock().unwrap().take().unwrap();
            let mut lease = DealerLease {
                slot: &c.dealer,
                engine: Some(Engine::with_dealer(dealer, LtCircuit::LogDepth)),
            };
            assert_eq!(lease.engine().parties(), 3);
            panic!("protocol bug");
        }));
        assert!(run.is_err());
        // Not busy, and the state survived: the block handed out earlier is
        // still there.
        let mut g = c.dealer.lock().unwrap();
        let d = g.as_mut().expect("dealer returned");
        assert!(d.take_masks(&TraderId([1; 32]), offset, 4).is_some());
    }
}
