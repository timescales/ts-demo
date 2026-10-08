//! Per-epoch state machine.
//!
//! ```text
//! Open --cutoff--> Sealed --execute--> Executed --settle--> Settled
//!   \                 \                    \
//!    `-------------- abort ---------------> Failed
//! ```
//!
//! Transitions are only allowed forward. Timing is expressed in
//! milliseconds since an arbitrary origin supplied by the caller. The state
//! machine itself never reads a clock, which keeps it deterministic under
//! test and replay.

use std::collections::BTreeSet;

use thiserror::Error;
use timescales_core::intent::SealedEnvelope;
use timescales_core::{
    EpochId, HEADER_VERSION_ENVELOPE_BOUND, Hash32, MarketId, OrderCommitment, PROTOCOL_VERSION,
};

use crate::{BatchHeader, BatchLeaf, batch_root, batch_root_v2};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuctionError {
    #[error("envelope arrived after cutoff ({now_ms} >= {cutoff_ms})")]
    AfterCutoff { now_ms: u64, cutoff_ms: u64 },
    #[error("envelope arrived before the epoch opened")]
    BeforeOpen,
    #[error("envelope is for market {got:?}, expected {expected:?}")]
    WrongMarket { expected: MarketId, got: MarketId },
    #[error("envelope is for epoch {got:?}, expected {expected:?}")]
    WrongEpoch { expected: EpochId, got: EpochId },
    #[error("duplicate commitment")]
    Duplicate,
    #[error("batch is full")]
    Full,
    #[error("invalid transition from {from:?}")]
    InvalidTransition { from: &'static str },
    #[error("header does not match collected envelopes")]
    HeaderMismatch,
    #[error("epoch window is empty: cutoff {cutoff_ms} is not after opening {opens_at_ms}")]
    EmptyWindow { opens_at_ms: u64, cutoff_ms: u64 },
}

/// Timing of one batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuctionEpoch {
    pub epoch: EpochId,
    pub opens_at_ms: u64,
    pub cutoff_ms: u64,
}

impl AuctionEpoch {
    /// Fixed-interval schedule: epoch `e` covers `[origin + e*interval, origin + (e+1)*interval)`.
    pub fn fixed(origin_ms: u64, interval_ms: u64, epoch: EpochId) -> Self {
        let opens = origin_ms.saturating_add(epoch.0.saturating_mul(interval_ms));
        Self {
            epoch,
            opens_at_ms: opens,
            cutoff_ms: opens.saturating_add(interval_ms),
        }
    }

    /// The window `[opens_at_ms, cutoff_ms)` admits at least one instant.
    pub fn check(&self) -> Result<(), AuctionError> {
        if self.cutoff_ms > self.opens_at_ms {
            Ok(())
        } else {
            Err(AuctionError::EmptyWindow {
                opens_at_ms: self.opens_at_ms,
                cutoff_ms: self.cutoff_ms,
            })
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    Open,
    Sealed {
        header: BatchHeader,
    },
    Executed {
        header: BatchHeader,
        receipt: Hash32,
    },
    Settled {
        header: BatchHeader,
        receipt: Hash32,
    },
    Failed {
        reason: String,
    },
}

impl Phase {
    fn name(&self) -> &'static str {
        match self {
            Phase::Open => "Open",
            Phase::Sealed { .. } => "Sealed",
            Phase::Executed { .. } => "Executed",
            Phase::Settled { .. } => "Settled",
            Phase::Failed { .. } => "Failed",
        }
    }
}

/// What makes a second envelope a duplicate.
#[derive(Debug)]
enum Seen {
    /// Header version 1: one envelope per commitment.
    Commitments(BTreeSet<OrderCommitment>),
    /// Header version 2: one envelope per leaf `(commitment, envelope
    /// digest)`. Envelopes that carry the same commitment but differ in any
    /// byte are different leaves, so nobody can keep a trader's envelope out
    /// by submitting another one under its commitment first.
    Leaves(BTreeSet<BatchLeaf>),
}

#[derive(Debug)]
pub struct Auction {
    market: MarketId,
    timing: AuctionEpoch,
    max_envelopes: u32,
    envelopes: Vec<SealedEnvelope>,
    seen: Seen,
    phase: Phase,
}

impl Auction {
    /// A header version 1 batch: duplicates are envelopes with an equal
    /// commitment.
    pub fn new(market: MarketId, timing: AuctionEpoch, max_envelopes: u32) -> Self {
        Self::with(
            market,
            timing,
            max_envelopes,
            Seen::Commitments(BTreeSet::new()),
        )
    }

    /// A header version 2 (envelope-bound) batch: duplicates are envelopes
    /// with an equal `(commitment, envelope digest)` leaf.
    pub fn new_v2(market: MarketId, timing: AuctionEpoch, max_envelopes: u32) -> Self {
        Self::with(market, timing, max_envelopes, Seen::Leaves(BTreeSet::new()))
    }

    fn with(market: MarketId, timing: AuctionEpoch, max_envelopes: u32, seen: Seen) -> Self {
        Self {
            market,
            timing,
            max_envelopes,
            envelopes: Vec::new(),
            seen,
            phase: Phase::Open,
        }
    }

    /// The header version this auction seals.
    pub fn header_version(&self) -> u8 {
        match self.seen {
            Seen::Commitments(_) => PROTOCOL_VERSION,
            Seen::Leaves(_) => HEADER_VERSION_ENVELOPE_BOUND,
        }
    }

    pub fn phase(&self) -> &Phase {
        &self.phase
    }

    pub fn timing(&self) -> AuctionEpoch {
        self.timing
    }

    pub fn envelopes(&self) -> &[SealedEnvelope] {
        &self.envelopes
    }

    pub fn commitments(&self) -> Vec<OrderCommitment> {
        self.envelopes.iter().map(|e| e.commitment).collect()
    }

    /// The root a header for the collected envelopes must carry.
    fn root(&self) -> Hash32 {
        match &self.seen {
            Seen::Commitments(_) => batch_root(&self.commitments()),
            Seen::Leaves(leaves) => {
                let leaves: Vec<BatchLeaf> = leaves.iter().copied().collect();
                batch_root_v2(&leaves)
            }
        }
    }

    /// Accept an envelope during the open window.
    pub fn submit(&mut self, now_ms: u64, env: SealedEnvelope) -> Result<(), AuctionError> {
        if self.phase != Phase::Open {
            return Err(AuctionError::InvalidTransition {
                from: self.phase.name(),
            });
        }
        if now_ms < self.timing.opens_at_ms {
            return Err(AuctionError::BeforeOpen);
        }
        if now_ms >= self.timing.cutoff_ms {
            return Err(AuctionError::AfterCutoff {
                now_ms,
                cutoff_ms: self.timing.cutoff_ms,
            });
        }
        if env.market != self.market {
            return Err(AuctionError::WrongMarket {
                expected: self.market,
                got: env.market,
            });
        }
        if env.epoch != self.timing.epoch {
            return Err(AuctionError::WrongEpoch {
                expected: self.timing.epoch,
                got: env.epoch,
            });
        }
        if self.envelopes.len() >= self.max_envelopes as usize {
            return Err(AuctionError::Full);
        }
        let fresh = match &mut self.seen {
            Seen::Commitments(seen) => seen.insert(env.commitment),
            Seen::Leaves(seen) => seen.insert(BatchLeaf::of(&env)),
        };
        if !fresh {
            return Err(AuctionError::Duplicate);
        }
        self.envelopes.push(env);
        Ok(())
    }

    /// Close the batch. `header` must describe exactly the collected set,
    /// with this auction's header version and root.
    pub fn seal(&mut self, now_ms: u64, header: BatchHeader) -> Result<(), AuctionError> {
        if self.phase != Phase::Open {
            return Err(AuctionError::InvalidTransition {
                from: self.phase.name(),
            });
        }
        if now_ms < self.timing.cutoff_ms {
            return Err(AuctionError::InvalidTransition {
                from: "Open (before cutoff)",
            });
        }
        if header.version != self.header_version()
            || header.market != self.market
            || header.epoch != self.timing.epoch
            || header.envelope_count as usize != self.envelopes.len()
            || header.batch_root != self.root()
        {
            return Err(AuctionError::HeaderMismatch);
        }
        self.phase = Phase::Sealed { header };
        Ok(())
    }

    pub fn mark_executed(&mut self, receipt: Hash32) -> Result<(), AuctionError> {
        match &self.phase {
            Phase::Sealed { header } => {
                self.phase = Phase::Executed {
                    header: *header,
                    receipt,
                };
                Ok(())
            }
            p => Err(AuctionError::InvalidTransition { from: p.name() }),
        }
    }

    pub fn mark_settled(&mut self) -> Result<(), AuctionError> {
        match &self.phase {
            Phase::Executed { header, receipt } => {
                self.phase = Phase::Settled {
                    header: *header,
                    receipt: *receipt,
                };
                Ok(())
            }
            p => Err(AuctionError::InvalidTransition { from: p.name() }),
        }
    }

    /// Abort from any non-terminal phase. Funds are untouched: nothing is
    /// settled until `Settled`.
    pub fn abort(&mut self, reason: impl Into<String>) -> Result<(), AuctionError> {
        match self.phase {
            Phase::Settled { .. } | Phase::Failed { .. } => Err(AuctionError::InvalidTransition {
                from: self.phase.name(),
            }),
            _ => {
                self.phase = Phase::Failed {
                    reason: reason.into(),
                };
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use timescales_core::{CommitmentScheme, FeeBps, FlowMode, MarketParams, Rationing, Tick};

    use super::*;

    fn params() -> MarketParams {
        MarketParams {
            market: MarketId(1),
            base_lot_size: 1,
            tick_size: 1,
            band_half_width: 4,
            max_order_lots_log2: 16,
            max_orders_per_trader: 8,
            max_batch_envelopes: 1024,
            max_order_lifetime: 2,
            maker_fee: FeeBps(0),
            taker_fee: FeeBps(0),
            flow: FlowMode::SingleBook,
            rationing: Rationing::Lottery,
            commitment_scheme: CommitmentScheme::Sha256,
        }
    }

    fn env(epoch: u64, c: u8) -> SealedEnvelope {
        SealedEnvelope {
            version: 1,
            market: MarketId(1),
            epoch: EpochId(epoch),
            commitment: OrderCommitment([c; 32]),
            ephemeral: [0; 32],
            ciphertext: [0; timescales_core::intent::CIPHERTEXT_LEN],
        }
    }

    #[test]
    fn rejects_post_cutoff_and_wrong_epoch() {
        let t = AuctionEpoch::fixed(0, 100, EpochId(3));
        assert_eq!((t.opens_at_ms, t.cutoff_ms), (300, 400));
        let mut a = Auction::new(MarketId(1), t, 10);
        assert_eq!(a.submit(299, env(3, 1)), Err(AuctionError::BeforeOpen));
        assert!(a.submit(300, env(3, 1)).is_ok());
        assert_eq!(a.submit(310, env(3, 1)), Err(AuctionError::Duplicate));
        assert!(matches!(
            a.submit(310, env(4, 2)),
            Err(AuctionError::WrongEpoch { .. })
        ));
        assert!(matches!(
            a.submit(400, env(3, 2)),
            Err(AuctionError::AfterCutoff { .. })
        ));
    }

    #[test]
    fn full_batch() {
        let mut a = Auction::new(MarketId(1), AuctionEpoch::fixed(0, 100, EpochId(0)), 1);
        assert!(a.submit(0, env(0, 1)).is_ok());
        assert_eq!(a.submit(0, env(0, 2)), Err(AuctionError::Full));
    }

    #[test]
    fn transitions_are_forward_only() {
        let mut a = Auction::new(MarketId(1), AuctionEpoch::fixed(0, 100, EpochId(0)), 4);
        assert!(a.mark_executed(Hash32::ZERO).is_err());
        assert!(a.abort("relay down").is_ok());
        assert!(a.abort("again").is_err());
        assert!(a.submit(0, env(0, 1)).is_err());
    }

    #[test]
    fn v2_dedups_on_the_leaf_not_the_commitment() {
        let t = AuctionEpoch::fixed(0, 100, EpochId(3));
        let mut other = env(3, 1);
        other.ciphertext[0] ^= 1;

        let mut v1 = Auction::new(MarketId(1), t, 10);
        assert!(v1.submit(300, env(3, 1)).is_ok());
        assert_eq!(v1.submit(300, other.clone()), Err(AuctionError::Duplicate));

        let mut v2 = Auction::new_v2(MarketId(1), t, 10);
        assert!(v2.submit(300, env(3, 1)).is_ok());
        assert!(
            v2.submit(300, other).is_ok(),
            "same commitment, other bytes"
        );
        assert_eq!(v2.submit(300, env(3, 1)), Err(AuctionError::Duplicate));
        assert_eq!(v2.envelopes().len(), 2);
        assert_eq!(
            (v1.header_version(), v2.header_version()),
            (PROTOCOL_VERSION, HEADER_VERSION_ENVELOPE_BOUND)
        );
    }

    #[test]
    fn seal_requires_the_auction_header_version_and_root() {
        let t = AuctionEpoch::fixed(0, 100, EpochId(3));
        let envs = [env(3, 1), env(3, 2)];
        let leaves = crate::batch_leaves(&envs);
        let params = params();
        let band = params.band(Tick(50)).unwrap();
        let v1_header = BatchHeader::assemble(
            params,
            t.epoch,
            band,
            Hash32::ZERO,
            &[envs[0].commitment, envs[1].commitment],
            Hash32::ZERO,
            Hash32::ZERO,
            Hash32::ZERO,
            Hash32::ZERO,
        );
        let v2_header = BatchHeader::assemble_v2(
            params,
            t.epoch,
            band,
            Hash32([9; 32]),
            &leaves,
            Hash32::ZERO,
            Hash32::ZERO,
            Hash32::ZERO,
            Hash32::ZERO,
        );
        let fill = |a: &mut Auction| {
            for e in &envs {
                a.submit(300, e.clone()).unwrap();
            }
        };

        let mut a = Auction::new_v2(MarketId(1), t, 10);
        fill(&mut a);
        assert_eq!(a.seal(400, v1_header), Err(AuctionError::HeaderMismatch));
        let mut wrong_root = v2_header;
        wrong_root.batch_root = v1_header.batch_root;
        assert_eq!(a.seal(400, wrong_root), Err(AuctionError::HeaderMismatch));
        assert_eq!(a.seal(400, v2_header), Ok(()));

        let mut a = Auction::new(MarketId(1), t, 10);
        fill(&mut a);
        assert_eq!(a.seal(400, v2_header), Err(AuctionError::HeaderMismatch));
        assert_eq!(a.seal(400, v1_header), Ok(()));
    }

    #[test]
    fn empty_windows_are_refused() {
        assert!(AuctionEpoch::fixed(0, 100, EpochId(1)).check().is_ok());
        assert_eq!(
            AuctionEpoch::fixed(0, 0, EpochId(1)).check(),
            Err(AuctionError::EmptyWindow {
                opens_at_ms: 0,
                cutoff_ms: 0
            })
        );
    }
}
