//! The settlement chain as the batch commitment authority.
//!
//! A relay commits each batch root once. The chain refuses a second,
//! different root for the same (market, epoch) and later records a beacon
//! value that was not known before the commit. Executors and key-release
//! members read committed batches back.

#[cfg(feature = "simulation")]
use std::collections::BTreeMap;
#[cfg(feature = "simulation")]
use std::sync::RwLock;

#[cfg(feature = "simulation")]
use timescales_core::crypto::{Hasher, domain};
use timescales_core::{EpochId, Hash32, MarketId};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CommitError {
    #[error("a different root is already committed for this epoch")]
    Equivocation,
    #[error("epoch is not after the last committed epoch")]
    OutOfOrder,
    #[error("chain unavailable")]
    Unavailable,
}

/// Lifecycle of a committed batch, in the order the program moves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommittedStatus {
    Committed,
    BeaconRevealed,
    ReceiptPosted,
    Verified,
    Settled,
    Aborted,
}

/// What the chain records about one committed batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedBatch {
    pub root: Hash32,
    pub count: u32,
    /// `terms_digest` the relay committed with the root (zero where the
    /// commitment authority does not record terms).
    pub terms: Hash32,
    /// Set once the beacon is revealed.
    pub beacon: Option<Hash32>,
    pub status: CommittedStatus,
}

pub trait ChainView: Send + Sync {
    fn committed_batch(&self, market: MarketId, epoch: EpochId) -> Option<CommittedBatch>;

    fn committed_root(&self, market: MarketId, epoch: EpochId) -> Option<Hash32> {
        self.committed_batch(market, epoch).map(|b| b.root)
    }
}

pub trait BatchCommitter: ChainView {
    /// Commit `root` over `count` envelopes for (market, epoch) and return the
    /// beacon. Committing the same root and count again is idempotent and
    /// returns the same beacon.
    fn commit_root(
        &self,
        market: MarketId,
        epoch: EpochId,
        root: Hash32,
        count: u32,
    ) -> Result<Hash32, CommitError>;
}

/// Map-backed chain for tests and the local demo. The beacon is derived
/// from a secret seed and the committed root, standing in for a value the
/// relay cannot predict (a slot hash or a VRF output), and is revealed at
/// commit, so a commit lands as `BeaconRevealed`. Anyone who knows the seed
/// can predict every beacon, so this exists for simulations only.
///
/// Like the program, it refuses a second, different batch for an epoch
/// (`Equivocation`) and an epoch below the market's latest committed one
/// (`OutOfOrder`). It does not model settlement, so it accepts gaps between
/// epochs and does not wait for the previous batch to be terminal, and it
/// records zero `terms`.
#[cfg(feature = "simulation")]
#[derive(Debug)]
pub struct InMemoryChain {
    seed: [u8; 32],
    batches: RwLock<BTreeMap<(MarketId, EpochId), CommittedBatch>>,
}

#[cfg(feature = "simulation")]
impl InMemoryChain {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            batches: RwLock::default(),
        }
    }

    /// Record a root. `false` if the commit is refused.
    pub fn commit(&self, market: MarketId, epoch: EpochId, root: Hash32, count: u32) -> bool {
        self.commit_root(market, epoch, root, count).is_ok()
    }

    /// Record a batch whose beacon was fixed elsewhere (a batch built outside
    /// a relay, e.g. by the workload generator). `false` if a different batch
    /// is already committed for (market, epoch), or if the epoch is below
    /// the market's latest committed one.
    pub fn commit_revealed(
        &self,
        market: MarketId,
        epoch: EpochId,
        root: Hash32,
        count: u32,
        beacon: Hash32,
    ) -> bool {
        let Ok(mut m) = self.batches.write() else {
            return false;
        };
        let batch = CommittedBatch {
            root,
            count,
            terms: Hash32::ZERO,
            beacon: Some(beacon),
            status: CommittedStatus::BeaconRevealed,
        };
        match m.get(&(market, epoch)) {
            Some(b) => *b == batch,
            None if below_latest(&m, market, epoch) => false,
            None => {
                m.insert((market, epoch), batch);
                true
            }
        }
    }

    pub fn beacon(&self, market: MarketId, epoch: EpochId) -> Option<Hash32> {
        self.committed_batch(market, epoch).and_then(|b| b.beacon)
    }
}

/// `epoch` is below the latest epoch committed for `market`.
#[cfg(feature = "simulation")]
fn below_latest(
    batches: &BTreeMap<(MarketId, EpochId), CommittedBatch>,
    market: MarketId,
    epoch: EpochId,
) -> bool {
    batches
        .range((market, EpochId(0))..=(market, EpochId(u64::MAX)))
        .next_back()
        .is_some_and(|((_, latest), _)| epoch < *latest)
}

#[cfg(feature = "simulation")]
impl ChainView for InMemoryChain {
    fn committed_batch(&self, market: MarketId, epoch: EpochId) -> Option<CommittedBatch> {
        self.batches
            .read()
            .ok()
            .and_then(|m| m.get(&(market, epoch)).copied())
    }
}

#[cfg(feature = "simulation")]
impl BatchCommitter for InMemoryChain {
    fn commit_root(
        &self,
        market: MarketId,
        epoch: EpochId,
        root: Hash32,
        count: u32,
    ) -> Result<Hash32, CommitError> {
        let mut m = self.batches.write().map_err(|_| CommitError::Unavailable)?;
        if let Some(b) = m.get(&(market, epoch)) {
            return match b.beacon {
                Some(beacon) if b.root == root && b.count == count => Ok(beacon),
                _ => Err(CommitError::Equivocation),
            };
        }
        if below_latest(&m, market, epoch) {
            return Err(CommitError::OutOfOrder);
        }
        let beacon = Hasher::new(domain::BATCH_SEED)
            .chain(b"in-memory-beacon")
            .chain(&self.seed)
            .chain(&market.0.to_le_bytes())
            .chain(&epoch.0.to_le_bytes())
            .chain(root.as_bytes())
            .finalize();
        m.insert(
            (market, epoch),
            CommittedBatch {
                root,
                count,
                terms: Hash32::ZERO,
                beacon: Some(beacon),
                status: CommittedStatus::BeaconRevealed,
            },
        );
        Ok(beacon)
    }
}
