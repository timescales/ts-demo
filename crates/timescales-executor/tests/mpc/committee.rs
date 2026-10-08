//! Committee hardening: configuration checks, OS-seeded preprocessing,
//! bounded and expiring mask blocks, fallible mask requests.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_auction::BatchHeader;
use timescales_auction::collateral::{Balance, BalanceSheet};
use timescales_auction::orderbook::OrderStateTable;
use timescales_core::identity::{ExecutorKey, TraderKey};
use timescales_core::intent::PrivateIntent;
use timescales_core::intent::masked::MAX_MASKED_LEN;
use timescales_core::{
    BaseAtoms, CommitmentScheme, EpochId, FeeBps, FlowMode, Hash32, Lots, MarketId, MarketParams,
    Order, OrderKind, QuoteAtoms, Rationing, Role, Side, Tick, TraderId,
};
use timescales_executor::mpc::{
    ConfigError, Dealer, Layout, MaskLimits, MaskRefusal, MpcCommittee, MpcConfig, MpcExecutor,
    mask_order, try_mask_order,
};
use timescales_executor::{ExecutionBatch, ExecutorError};

const EPOCH: EpochId = EpochId(3);

fn committee(seed: Option<[u8; 32]>) -> MpcCommittee {
    MpcCommittee::new(
        MpcConfig {
            dealer_seed: seed,
            ..MpcConfig::default()
        },
        ExecutorKey::from_seed([8; 32]),
    )
}

fn params() -> MarketParams {
    MarketParams {
        market: MarketId(1),
        base_lot_size: 1_000,
        tick_size: 100,
        band_half_width: 3,
        max_order_lots_log2: 8,
        max_orders_per_trader: 4,
        max_batch_envelopes: 64,
        max_order_lifetime: 4,
        maker_fee: FeeBps(0),
        taker_fee: FeeBps(0),
        flow: FlowMode::SingleBook,
        rationing: Rationing::Lottery,
        commitment_scheme: CommitmentScheme::Sha256,
    }
}

#[test]
fn fewer_than_two_parties_is_a_configuration_error() {
    for parties in [0, 1] {
        assert_eq!(
            MpcCommittee::try_new(
                MpcConfig {
                    parties,
                    ..MpcConfig::default()
                },
                ExecutorKey::from_seed([1; 32]),
            )
            .unwrap_err(),
            ConfigError::Parties(parties)
        );
    }
}

#[test]
#[should_panic(expected = "at least two parties")]
fn new_panics_on_a_one_party_committee() {
    let _ = MpcCommittee::new(
        MpcConfig {
            parties: 1,
            ..MpcConfig::default()
        },
        ExecutorKey::from_seed([1; 32]),
    );
}

#[test]
fn without_a_seed_the_dealer_draws_from_the_os() {
    let owner = TraderId([1; 32]);
    let a = committee(None).request_masks(owner, 8).unwrap();
    let b = committee(None).request_masks(owner, 8).unwrap();
    assert_ne!(a.1, b.1);
    let seeded = committee(Some([4; 32])).request_masks(owner, 8).unwrap();
    assert_eq!(
        seeded,
        committee(Some([4; 32])).request_masks(owner, 8).unwrap()
    );
    assert_eq!(MpcConfig::default().dealer_seed, None);
}

#[test]
fn mask_lengths_are_bounded_and_follow_the_epoch_layout() {
    let c = committee(Some([1; 32]));
    let owner = TraderId([1; 32]);
    for len in [0, MAX_MASKED_LEN + 1] {
        assert!(matches!(
            c.request_masks(owner, len),
            Err(ExecutorError::Execution(_))
        ));
        assert!(c.request_masks_for(owner, EPOCH, len).is_err());
    }
    assert!(c.request_masks(owner, MAX_MASKED_LEN).is_ok());

    let p = params();
    let layout = Layout::new(&p.band(Tick(100)).unwrap(), p.max_order_lots_log2);
    c.expect_layout(EPOCH, &layout);
    assert!(c.request_masks_for(owner, EPOCH, layout.len() + 1).is_err());
    assert!(c.request_masks_for(owner, EPOCH, layout.len()).is_ok());
    // Other epochs are not constrained by this layout.
    assert!(c.request_masks_for(owner, EpochId(4), 7).is_ok());
}

#[test]
fn blocks_are_removed_when_taken_and_left_for_their_owner() {
    let mut d = Dealer::new(3, true, Some([2; 32]));
    let owner = TraderId([1; 32]);
    let (off, _) = d.input_masks(owner, 5);
    assert_eq!(d.outstanding_masks(), 1);
    assert!(d.take_masks(&TraderId([2; 32]), off, 5).is_none());
    assert!(d.take_masks(&owner, off, 4).is_none());
    assert_eq!(d.outstanding_masks(), 1);
    assert!(d.take_masks(&owner, off, 5).is_some());
    assert_eq!(d.outstanding_masks(), 0);
    assert!(d.take_masks(&owner, off, 5).is_none());
}

#[test]
fn blocks_expire_with_their_epoch() {
    let c = committee(Some([1; 32]));
    let owner = TraderId([1; 32]);
    c.request_masks_for(owner, EpochId(3), 4).unwrap();
    c.request_masks_for(owner, EpochId(5), 4).unwrap();
    c.request_masks(owner, 4).unwrap();
    assert_eq!(c.outstanding_masks().unwrap(), 3);
    assert_eq!(c.expire_masks(EpochId(4)).unwrap(), 1);
    assert_eq!(c.outstanding_masks().unwrap(), 2);
    assert_eq!(c.expire_masks(EpochId(9)).unwrap(), 1);
    // A block requested without an epoch is never expired by epoch.
    assert_eq!(c.outstanding_masks().unwrap(), 1);
}

fn limited(total: usize, per_owner: usize) -> MpcCommittee {
    committee(Some([1; 32])).with_mask_limits(MaskLimits { total, per_owner })
}

#[test]
fn outstanding_mask_values_are_bounded_per_owner_and_overall() {
    let c = limited(20, 12);
    let (a, b, d) = (TraderId([1; 32]), TraderId([2; 32]), TraderId([3; 32]));
    c.request_masks_for(a, EPOCH, 8).unwrap();
    c.request_masks(a, 4).unwrap();
    assert!(matches!(
        c.request_masks_for(a, EPOCH, 1),
        Err(ExecutorError::Unavailable(_))
    ));
    c.request_masks_for(b, EpochId(EPOCH.0 + 1), 8).unwrap();
    // 20 values held: nobody gets more, whatever the epoch.
    assert!(matches!(
        c.request_masks(d, 1),
        Err(ExecutorError::Unavailable(_))
    ));
    assert!(c.request_masks_for(d, EpochId(EPOCH.0 + 2), 1).is_err());
    assert_eq!(c.outstanding_masks().unwrap(), 3);

    // Expiring the epoch frees its values for everyone, including `a`.
    assert_eq!(c.expire_masks(EPOCH).unwrap(), 1);
    c.request_masks_for(d, EpochId(EPOCH.0 + 1), 4).unwrap();
    c.request_masks_for(a, EpochId(EPOCH.0 + 1), 4).unwrap();
    assert!(c.request_masks_for(a, EpochId(EPOCH.0 + 1), 4).is_err());
}

#[test]
fn taking_a_block_releases_its_values() {
    let mut d = Dealer::new(3, true, Some([2; 32])).with_mask_limits(MaskLimits {
        total: 10,
        per_owner: 6,
    });
    let owner = TraderId([1; 32]);
    let (off, _) = d.input_masks_for(owner, EPOCH, 6).unwrap();
    assert_eq!(d.outstanding_mask_values(), 6);
    assert_eq!(
        d.try_input_masks(owner, 1),
        Err(MaskRefusal::Owner {
            held: 6,
            requested: 1,
            limit: 6
        })
    );
    // A take by someone else or for another length releases nothing.
    assert!(d.take_masks(&TraderId([2; 32]), off, 6).is_none());
    assert!(d.take_masks(&owner, off, 5).is_none());
    assert_eq!(d.outstanding_mask_values(), 6);
    assert!(d.take_masks(&owner, off, 6).is_some());
    assert_eq!(d.outstanding_mask_values(), 0);
    d.try_input_masks(owner, 6).unwrap();
    assert_eq!(
        d.try_input_masks(TraderId([2; 32]), 5),
        Err(MaskRefusal::Total {
            held: 6,
            requested: 5,
            limit: 10
        })
    );

    // The engine's own inputs are issued past the limits but count
    // towards them until taken.
    let other = TraderId([2; 32]);
    let (off, _) = d.input_masks(other, 8);
    assert_eq!(d.outstanding_mask_values(), 14);
    assert!(d.try_input_masks(other, 1).is_err());
    assert!(d.take_masks(&other, off, 8).is_some());
    assert!(d.try_input_masks(other, 4).is_ok());
}

fn order(t: &TraderKey, side: Side, limit: u64) -> Order {
    Order {
        market: params().market,
        trader: t.id(),
        nonce: 1,
        side,
        role: Role::Taker,
        kind: OrderKind::Limit,
        limit: Tick(limit),
        quantity: Lots(3),
        valid_from: EPOCH,
        expires_at: EPOCH,
    }
}

/// A two-order masked batch: one buy and one crossing sell.
fn masked_batch(c: &MpcCommittee) -> ExecutionBatch {
    let p = params();
    let band = p.band(Tick(100)).unwrap();
    let layout = Layout::new(&band, p.max_order_lots_log2);
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let mut source = c;
    let mut masked = Vec::new();
    let mut commitments = Vec::new();
    let mut balances = BalanceSheet::default();
    for (seed, side, limit) in [(1u8, Side::Buy, 101), (2, Side::Sell, 99)] {
        let t = TraderKey::from_seed([seed; 32]);
        let o = order(&t, side, limit);
        let (_, commitment) = PrivateIntent::place(&mut rng, &t, p.commitment_scheme, o).unwrap();
        masked
            .push(try_mask_order(&mut source, &t, &o, commitment, &band, &layout, EPOCH).unwrap());
        commitments.push(commitment);
        balances.set(
            t.id(),
            Balance {
                base: BaseAtoms(1 << 40),
                quote: QuoteAtoms(1 << 40),
            },
        );
    }
    let prior = OrderStateTable::default();
    let header = BatchHeader::assemble(
        p,
        EPOCH,
        band,
        Hash32::ZERO,
        &commitments,
        Hash32([3; 32]),
        prior.root(),
        balances.root(),
        Hash32::ZERO,
    );
    ExecutionBatch {
        header,
        envelopes: Vec::new(),
        masked,
        balances,
        prior_state: prior,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_run_consumes_and_expires_its_epochs_masks() {
    let c = Arc::new(committee(Some([6; 32])));
    let batch = masked_batch(&c);
    // A trader who requested masks for this epoch but did not submit, and
    // one who masks ahead for the next epoch.
    c.request_masks_for(TraderId([7; 32]), EPOCH, 4).unwrap();
    c.request_masks_for(TraderId([7; 32]), EpochId(EPOCH.0 + 1), 4)
        .unwrap();
    assert_eq!(c.outstanding_masks().unwrap(), 4);
    let exec = MpcExecutor::new(Arc::clone(&c));
    assert_eq!(exec.executor_id(), ExecutorKey::from_seed([8; 32]).id());
    let r = exec.execute_shared(Arc::new(batch)).await.unwrap();
    assert_eq!(r.artifacts.fills.len(), 2);
    assert_eq!(r.receipt.executor, exec.executor_id());
    assert_eq!(c.outstanding_masks().unwrap(), 1);
}

#[test]
fn a_refused_mask_request_is_an_error_or_a_documented_panic() {
    let c = committee(Some([1; 32]));
    let p = params();
    let band = p.band(Tick(100)).unwrap();
    let layout = Layout::new(&band, p.max_order_lots_log2);
    // The committee expects another length for the epoch.
    c.expect_layout(EPOCH, &Layout::new(&band, p.max_order_lots_log2 + 1));
    let t = TraderKey::from_seed([1; 32]);
    let o = order(&t, Side::Buy, 101);
    let (_, commitment) = PrivateIntent::place(
        &mut ChaCha20Rng::seed_from_u64(1),
        &t,
        p.commitment_scheme,
        o,
    )
    .unwrap();
    let mut source = &c;
    assert!(try_mask_order(&mut source, &t, &o, commitment, &band, &layout, EPOCH).is_err());
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mask_order(&mut source, &t, &o, commitment, &band, &layout, EPOCH)
    }));
    assert!(panicked.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn version_2_batches_are_not_for_the_committee() {
    let c = Arc::new(committee(Some([6; 32])));
    let mut batch = masked_batch(&c);
    batch.header.version = 2;
    assert!(matches!(
        MpcExecutor::new(Arc::clone(&c))
            .execute_shared(Arc::new(batch))
            .await,
        Err(ExecutorError::Execution(_))
    ));
    // Refused before the run: the masks are still there.
    assert_eq!(c.outstanding_masks().unwrap(), 2);
}
