//! The simulated commitment authority: what it records, and the commits it
//! refuses.

#![allow(clippy::unwrap_used)]

use timescales_auction::{
    BatchCommitter, ChainView, CommitError, CommittedBatch, CommittedStatus, InMemoryChain,
};
use timescales_core::{EpochId, Hash32, MarketId};

const M: MarketId = MarketId(1);

fn root(b: u8) -> Hash32 {
    Hash32([b; 32])
}

#[test]
fn commit_records_the_batch_with_its_beacon() {
    let chain = InMemoryChain::new([0x5a; 32]);
    assert_eq!(chain.committed_batch(M, EpochId(1)), None);
    assert_eq!(chain.committed_root(M, EpochId(1)), None);

    let beacon = chain.commit_root(M, EpochId(1), root(1), 8).unwrap();
    assert_eq!(
        chain.committed_batch(M, EpochId(1)),
        Some(CommittedBatch {
            root: root(1),
            count: 8,
            terms: Hash32::ZERO,
            beacon: Some(beacon),
            status: CommittedStatus::BeaconRevealed,
        })
    );
    assert_eq!(chain.committed_root(M, EpochId(1)), Some(root(1)));
    assert_eq!(chain.beacon(M, EpochId(1)), Some(beacon));

    // The beacon depends on the seed, the market, the epoch and the root.
    let other_seed = InMemoryChain::new([0x5b; 32]);
    assert_ne!(
        other_seed.commit_root(M, EpochId(1), root(1), 8).unwrap(),
        beacon
    );
    let fresh = InMemoryChain::new([0x5a; 32]);
    assert_ne!(
        fresh.commit_root(M, EpochId(1), root(2), 8).unwrap(),
        beacon
    );
    assert_ne!(
        fresh
            .commit_root(MarketId(2), EpochId(1), root(1), 8)
            .unwrap(),
        beacon
    );
}

#[test]
fn recommit_is_idempotent_and_a_different_batch_is_equivocation() {
    let chain = InMemoryChain::new([0x5a; 32]);
    let beacon = chain.commit_root(M, EpochId(3), root(1), 8).unwrap();
    assert_eq!(chain.commit_root(M, EpochId(3), root(1), 8), Ok(beacon));
    assert!(chain.commit(M, EpochId(3), root(1), 8));
    assert_eq!(
        chain.commit_root(M, EpochId(3), root(2), 8),
        Err(CommitError::Equivocation)
    );
    assert_eq!(
        chain.commit_root(M, EpochId(3), root(1), 9),
        Err(CommitError::Equivocation)
    );
    assert!(!chain.commit_revealed(M, EpochId(3), root(1), 8, Hash32([7; 32])));
    assert_eq!(chain.committed_root(M, EpochId(3)), Some(root(1)));
}

#[test]
fn epochs_below_the_latest_commit_are_out_of_order() {
    let chain = InMemoryChain::new([0x5a; 32]);
    chain.commit_root(M, EpochId(5), root(5), 1).unwrap();
    // Gaps are allowed (no settlement is modelled), going back is not.
    chain.commit_root(M, EpochId(7), root(7), 1).unwrap();
    assert_eq!(
        chain.commit_root(M, EpochId(6), root(6), 1),
        Err(CommitError::OutOfOrder)
    );
    assert!(!chain.commit_revealed(M, EpochId(4), root(4), 1, Hash32::ZERO));
    assert_eq!(chain.committed_batch(M, EpochId(6)), None);
    // Other markets keep their own sequence.
    assert!(chain.commit(MarketId(2), EpochId(1), root(1), 1));
    // Committed epochs still answer idempotently.
    assert!(chain.commit(M, EpochId(5), root(5), 1));
}

#[test]
fn revealed_commits_keep_the_given_beacon() {
    let chain = InMemoryChain::new([0x5a; 32]);
    assert!(chain.commit_revealed(M, EpochId(2), root(2), 4, Hash32([9; 32])));
    assert!(chain.commit_revealed(M, EpochId(2), root(2), 4, Hash32([9; 32])));
    assert_eq!(chain.beacon(M, EpochId(2)), Some(Hash32([9; 32])));
    // A relay commit of the same root and count returns the recorded beacon.
    assert_eq!(
        chain.commit_root(M, EpochId(2), root(2), 4),
        Ok(Hash32([9; 32]))
    );
}

#[test]
fn statuses_follow_the_program_order() {
    use CommittedStatus::*;
    // Batch.status bytes 1..=6.
    let order = [
        Committed,
        BeaconRevealed,
        ReceiptPosted,
        Verified,
        Settled,
        Aborted,
    ];
    assert!(order.windows(2).all(|w| w[0] < w[1]));
}
