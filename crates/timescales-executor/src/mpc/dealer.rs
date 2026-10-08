//! Preprocessing by a trusted dealer.
//!
//! The online protocol consumes Beaver triples, random bits, bounded random
//! values and input masks, all authenticated under the global MAC key. Here
//! a dealer who knows the key produces them. This is a *simulation of the
//! offline phase*: it reproduces what the online phase consumes and lets us
//! count it, but its cost says nothing about dealer-free preprocessing
//! (OT- or HE-based, e.g. MASCOT or Overdrive), which is far more expensive.
//! A deployment with a trusted dealer must also trust it never to collude.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;
use timescales_core::{EpochId, TraderId};

use crate::mpc::field::Fp;
use crate::mpc::shares::Shared;

/// What the online phase consumed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreprocessingCounts {
    pub triples: u64,
    pub bits: u64,
    pub bounded_randoms: u64,
    pub input_masks: u64,
    pub mac_check_randoms: u64,
}

/// Bounds on the input masks a dealer has handed out and not seen consumed
/// or expired, in mask values: what the committee keeps grows with values
/// (`parties` shares and as many MAC shares per value, 16 bytes each), not
/// with blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskLimits {
    /// Over all owners.
    pub total: usize,
    /// For one owner, so that one trader cannot hold the whole pool.
    pub per_owner: usize,
}

impl Default for MaskLimits {
    /// 2^23 values in all, enough for the CLI's largest masked batch
    /// (20 000 orders of 284 values under the default band) and 768 MiB of
    /// shares with MACs at three parties, and 2^20 per owner.
    fn default() -> Self {
        Self {
            total: 1 << 23,
            per_owner: 1 << 20,
        }
    }
}

/// A mask request the dealer refused.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MaskRefusal {
    #[error("{held} mask values outstanding, {requested} more would exceed {limit}")]
    Total {
        held: usize,
        requested: usize,
        limit: usize,
    },
    #[error("owner holds {held} mask values, {requested} more would exceed {limit}")]
    Owner {
        held: usize,
        requested: usize,
        limit: usize,
    },
}

struct MaskBlock {
    owner: TraderId,
    shared: Shared,
    /// The epoch the masks were requested for, if known. Such blocks expire
    /// with it.
    epoch: Option<EpochId>,
}

pub struct Dealer {
    parties: usize,
    authenticated: bool,
    alpha: Fp,
    alpha_shares: Vec<Fp>,
    rng: ChaCha20Rng,
    pub(crate) counts: PreprocessingCounts,
    pub(crate) elapsed: Duration,
    masks: BTreeMap<u64, MaskBlock>,
    next_mask: u64,
    limits: MaskLimits,
    /// Values in `masks`, in all and per owner.
    held: usize,
    held_by: BTreeMap<TraderId, usize>,
}

impl core::fmt::Debug for Dealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dealer")
            .field("parties", &self.parties)
            .field("counts", &self.counts)
            .finish_non_exhaustive()
    }
}

impl Dealer {
    /// A dealer for `parties` parties. `seed` makes its whole output
    /// reproducible (simulations and the CLI's committed samples). `None`
    /// draws the seed from the OS, which is the only safe choice anywhere
    /// the masks protect real orders.
    pub fn new(parties: usize, authenticated: bool, seed: Option<[u8; 32]>) -> Self {
        let mut rng = match seed {
            Some(s) => ChaCha20Rng::from_seed(s),
            None => ChaCha20Rng::from_entropy(),
        };
        let alpha_shares: Vec<Fp> = (0..parties).map(|_| Fp::random(&mut rng)).collect();
        let alpha = alpha_shares.iter().copied().sum();
        Self {
            parties,
            authenticated,
            alpha,
            alpha_shares,
            rng,
            counts: PreprocessingCounts::default(),
            elapsed: Duration::ZERO,
            masks: BTreeMap::new(),
            next_mask: 0,
            limits: MaskLimits::default(),
            held: 0,
            held_by: BTreeMap::new(),
        }
    }

    pub fn with_mask_limits(mut self, limits: MaskLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn mask_limits(&self) -> MaskLimits {
        self.limits
    }

    pub fn parties(&self) -> usize {
        self.parties
    }

    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    /// Reset consumption counters, e.g. between benchmark runs.
    pub fn reset_counts(&mut self) {
        self.counts = PreprocessingCounts::default();
        self.elapsed = Duration::ZERO;
    }

    pub fn alpha_shares(&self) -> &[Fp] {
        &self.alpha_shares
    }

    pub fn counts(&self) -> PreprocessingCounts {
        self.counts
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Additive shares of `values` with MAC shares of `alpha * values`.
    fn share(&mut self, values: &[Fp]) -> Shared {
        let n = self.parties;
        let mut s = Shared::zeros(n, values.len(), self.authenticated);
        for (j, x) in values.iter().enumerate() {
            let mut acc = Fp::ZERO;
            for i in 0..n - 1 {
                let r = Fp::random(&mut self.rng);
                s.v[i][j] = r;
                acc += r;
            }
            s.v[n - 1][j] = *x - acc;
            if self.authenticated {
                let mac = self.alpha * *x;
                let mut acc = Fp::ZERO;
                for i in 0..n - 1 {
                    let r = Fp::random(&mut self.rng);
                    s.m[i][j] = r;
                    acc += r;
                }
                s.m[n - 1][j] = mac - acc;
            }
        }
        s
    }

    pub fn triples(&mut self, len: usize) -> (Shared, Shared, Shared) {
        let t = Instant::now();
        let a: Vec<Fp> = (0..len).map(|_| Fp::random(&mut self.rng)).collect();
        let b: Vec<Fp> = (0..len).map(|_| Fp::random(&mut self.rng)).collect();
        let c: Vec<Fp> = a.iter().zip(&b).map(|(x, y)| *x * *y).collect();
        let out = (self.share(&a), self.share(&b), self.share(&c));
        self.counts.triples += len as u64;
        self.elapsed += t.elapsed();
        out
    }

    /// Uniform random bits.
    pub fn bits(&mut self, len: usize) -> Shared {
        let t = Instant::now();
        let v: Vec<Fp> = (0..len)
            .map(|_| {
                if self.rng.r#gen::<bool>() {
                    Fp::ONE
                } else {
                    Fp::ZERO
                }
            })
            .collect();
        let out = self.share(&v);
        self.counts.bits += len as u64;
        self.elapsed += t.elapsed();
        out
    }

    /// Uniform in `[0, 2^bits)`.
    pub fn bounded(&mut self, len: usize, bits: u32) -> Shared {
        let t = Instant::now();
        let v: Vec<Fp> = (0..len)
            .map(|_| Fp::random_bits(&mut self.rng, bits))
            .collect();
        let out = self.share(&v);
        self.counts.bounded_randoms += len as u64;
        self.elapsed += t.elapsed();
        out
    }

    /// Public random coefficients for a MAC check, as from a coin toss.
    pub fn coins(&mut self, len: usize) -> Vec<Fp> {
        self.counts.mac_check_randoms += len as u64;
        (0..len).map(|_| Fp::random(&mut self.rng)).collect()
    }

    /// Allocate an input-mask block for `owner`. The mask values go to the
    /// trader in the clear. The committee keeps authenticated shares.
    ///
    /// The block counts towards the [`MaskLimits`] but is issued whatever
    /// they say: this is for inputs the caller takes back at once
    /// (benchmarks, engine tests). Requests from traders go through
    /// [`Self::try_input_masks`] or [`Self::input_masks_for`].
    pub fn input_masks(&mut self, owner: TraderId, len: usize) -> (u64, Vec<Fp>) {
        self.issue_masks(owner, None, len)
    }

    /// [`Self::input_masks`] within the [`MaskLimits`]. The block is not
    /// tied to an epoch, so only taking it releases it.
    pub fn try_input_masks(
        &mut self,
        owner: TraderId,
        len: usize,
    ) -> Result<(u64, Vec<Fp>), MaskRefusal> {
        self.check_limits(&owner, len)?;
        Ok(self.issue_masks(owner, None, len))
    }

    /// [`Self::try_input_masks`] for an order in `epoch`. The block is
    /// dropped by [`Self::expire_masks`] once that epoch is over.
    pub fn input_masks_for(
        &mut self,
        owner: TraderId,
        epoch: EpochId,
        len: usize,
    ) -> Result<(u64, Vec<Fp>), MaskRefusal> {
        self.check_limits(&owner, len)?;
        Ok(self.issue_masks(owner, Some(epoch), len))
    }

    fn check_limits(&self, owner: &TraderId, len: usize) -> Result<(), MaskRefusal> {
        if self.held.saturating_add(len) > self.limits.total {
            return Err(MaskRefusal::Total {
                held: self.held,
                requested: len,
                limit: self.limits.total,
            });
        }
        let owned = self.held_by.get(owner).copied().unwrap_or(0);
        if owned.saturating_add(len) > self.limits.per_owner {
            return Err(MaskRefusal::Owner {
                held: owned,
                requested: len,
                limit: self.limits.per_owner,
            });
        }
        Ok(())
    }

    fn issue_masks(
        &mut self,
        owner: TraderId,
        epoch: Option<EpochId>,
        len: usize,
    ) -> (u64, Vec<Fp>) {
        let t = Instant::now();
        let values: Vec<Fp> = (0..len).map(|_| Fp::random(&mut self.rng)).collect();
        let shared = self.share(&values);
        let offset = self.next_mask;
        self.next_mask += len as u64;
        self.masks.insert(
            offset,
            MaskBlock {
                owner,
                shared,
                epoch,
            },
        );
        self.held += len;
        *self.held_by.entry(owner).or_default() += len;
        self.counts.input_masks += len as u64;
        self.elapsed += t.elapsed();
        (offset, values)
    }

    /// Committee side: take the shares of a mask block, once, for its owner.
    /// The block is removed. A request for another owner or length leaves it
    /// in place for the rightful one.
    pub fn take_masks(&mut self, owner: &TraderId, offset: u64, len: usize) -> Option<Shared> {
        let block = self.masks.get(&offset)?;
        if block.owner != *owner || block.shared.len() != len {
            return None;
        }
        let block = self.masks.remove(&offset)?;
        release(&mut self.held, &mut self.held_by, &block);
        Some(block.shared)
    }

    /// Drop the unconsumed blocks requested for epochs up to `through`.
    /// Returns how many were dropped.
    pub fn expire_masks(&mut self, through: EpochId) -> usize {
        let before = self.masks.len();
        let (held, held_by) = (&mut self.held, &mut self.held_by);
        self.masks.retain(|_, b| {
            let keep = b.epoch.is_none_or(|e| e > through);
            if !keep {
                release(held, held_by, b);
            }
            keep
        });
        before - self.masks.len()
    }

    /// Mask blocks handed out and not consumed yet.
    pub fn outstanding_masks(&self) -> usize {
        self.masks.len()
    }

    /// Mask values in those blocks.
    pub fn outstanding_mask_values(&self) -> usize {
        self.held
    }
}

fn release(held: &mut usize, held_by: &mut BTreeMap<TraderId, usize>, block: &MaskBlock) {
    let len = block.shared.len();
    *held -= len;
    if let Some(n) = held_by.get_mut(&block.owner) {
        *n -= len;
        if *n == 0 {
            held_by.remove(&block.owner);
        }
    }
}
