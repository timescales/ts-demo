//! Every error variant this crate defines comes out of a real path.
//! The matches have no wildcard arm, so a new variant does not compile until
//! it is named here, and the comparisons then fail until a case produces it.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use timescales_auction::{
    Auction, AuctionEpoch, AuctionError, BatchCommitter, BatchHeader, CommitError, InMemoryChain,
    batch_leaves,
};
use timescales_core::intent::{CIPHERTEXT_LEN, SealedEnvelope};
use timescales_core::{
    CommitmentScheme, EpochId, FeeBps, FlowMode, Hash32, MarketId, MarketParams, OrderCommitment,
    PROTOCOL_VERSION, Rationing, Tick,
};

fn auction_variant(e: &AuctionError) -> &'static str {
    match e {
        AuctionError::AfterCutoff { .. } => "AfterCutoff",
        AuctionError::BeforeOpen => "BeforeOpen",
        AuctionError::WrongMarket { .. } => "WrongMarket",
        AuctionError::WrongEpoch { .. } => "WrongEpoch",
        AuctionError::Duplicate => "Duplicate",
        AuctionError::Full => "Full",
        AuctionError::InvalidTransition { .. } => "InvalidTransition",
        AuctionError::HeaderMismatch => "HeaderMismatch",
        AuctionError::EmptyWindow { .. } => "EmptyWindow",
    }
}

fn commit_variant(e: &CommitError) -> &'static str {
    match e {
        CommitError::Equivocation => "Equivocation",
        CommitError::OutOfOrder => "OutOfOrder",
        CommitError::Unavailable => "Unavailable",
    }
}

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

fn envelope(market: u64, epoch: u64, c: u8) -> SealedEnvelope {
    SealedEnvelope {
        version: PROTOCOL_VERSION,
        market: MarketId(market),
        epoch: EpochId(epoch),
        commitment: OrderCommitment([c; 32]),
        ephemeral: [c; 32],
        ciphertext: [0; CIPHERTEXT_LEN],
    }
}

#[test]
fn every_auction_error_is_produced() {
    let window = AuctionEpoch {
        epoch: EpochId(3),
        opens_at_ms: 100,
        cutoff_ms: 200,
    };
    let mut a = Auction::new_v2(MarketId(1), window, 2);
    let mut errors = vec![
        a.submit(99, envelope(1, 3, 1)).unwrap_err(),
        a.submit(200, envelope(1, 3, 1)).unwrap_err(),
        a.submit(150, envelope(2, 3, 1)).unwrap_err(),
        a.submit(150, envelope(1, 4, 1)).unwrap_err(),
    ];
    a.submit(150, envelope(1, 3, 1)).unwrap();
    errors.push(a.submit(150, envelope(1, 3, 1)).unwrap_err());
    a.submit(150, envelope(1, 3, 2)).unwrap();
    errors.push(a.submit(150, envelope(1, 3, 3)).unwrap_err());

    // A header for a set other than the collected one.
    let p = params();
    let header = BatchHeader::assemble_v2(
        p,
        window.epoch,
        p.band(Tick(50)).unwrap(),
        Hash32([0xb1; 32]),
        &batch_leaves(&[envelope(1, 3, 1)]),
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
    );
    errors.push(a.seal(150, header).unwrap_err());
    errors.push(a.seal(200, header).unwrap_err());
    let empty = AuctionEpoch {
        cutoff_ms: 100,
        ..window
    };
    errors.push(empty.check().unwrap_err());

    let produced: BTreeSet<&str> = errors.iter().map(auction_variant).collect();
    let all = [
        "AfterCutoff",
        "BeforeOpen",
        "WrongMarket",
        "WrongEpoch",
        "Duplicate",
        "Full",
        "InvalidTransition",
        "HeaderMismatch",
        "EmptyWindow",
    ];
    assert_eq!(produced, all.into_iter().collect::<BTreeSet<_>>());
}

/// `Unavailable` is a lost connection to the commitment authority. The
/// in-memory chain has none to lose. Timescales-relay's variant test produces
/// it (a seal without a committer).
#[test]
fn every_commit_error_of_the_in_memory_chain_is_produced() {
    let chain = InMemoryChain::new([0x5a; 32]);
    chain
        .commit_root(MarketId(1), EpochId(5), Hash32([5; 32]), 1)
        .unwrap();
    let errors = [
        chain
            .commit_root(MarketId(1), EpochId(5), Hash32([6; 32]), 1)
            .unwrap_err(),
        chain
            .commit_root(MarketId(1), EpochId(4), Hash32([4; 32]), 1)
            .unwrap_err(),
    ];
    let produced: BTreeSet<&str> = errors.iter().map(commit_variant).collect();
    assert_eq!(produced, ["Equivocation", "OutOfOrder"].into());
}
