//! The reference execution path, end to end:
//! encrypted order -> commitment -> batch -> matching -> receipt ->
//! verification -> settlement.

use std::collections::HashMap;
use std::sync::Arc;

use rand::SeedableRng;
use rand::seq::SliceRandom;
use timescales_core::identity::ExecutorKey;
use timescales_core::intent::IntentBody;
use timescales_core::{CommitmentScheme, FlowMode, Order, OrderCommitment, Side};
use timescales_executor::workload::{Funding, WorkloadConfig, default_params, generate};
use timescales_executor::{
    ConfidentialExecutor, ExecutorError, LocalKeySchedule, ReferenceExecutor,
};

fn executor(keys: &Arc<LocalKeySchedule>) -> ReferenceExecutor<LocalKeySchedule> {
    ReferenceExecutor::new(Arc::clone(keys), ExecutorKey::from_seed([42; 32]))
}

fn keys() -> Arc<LocalKeySchedule> {
    Arc::new(LocalKeySchedule::new([7; 32]))
}

fn orders_by_commitment(
    w: &timescales_executor::workload::Workload,
) -> HashMap<OrderCommitment, Order> {
    w.intents
        .iter()
        .filter_map(|(pi, c)| match pi.body {
            IntentBody::Place(o) => Some((*c, o)),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_dual_flow() {
    let keys = keys();
    let mut cfg = WorkloadConfig::new(
        default_params(FlowMode::DualFlow, CommitmentScheme::Sha256),
        2_000,
        1,
    );
    cfg.noop_pct = 5;
    cfg.cancel_pct = 3;
    let w = generate(&cfg, keys.as_ref());
    let balances = w.batch.balances.clone();
    let res = executor(&keys)
        .execute(w.batch.clone())
        .await
        .expect("execute");

    // Receipt is signed and its roots match the published artifacts.
    res.receipt.verify_signature().expect("signature");
    res.artifacts
        .check_against(&res.receipt.outcome)
        .expect("artifacts");
    assert_eq!(res.receipt.outcome.header_digest, w.batch.header.digest());

    // Something actually traded in both books.
    assert_eq!(res.receipt.outcome.clearing.len(), 2);
    assert!(res.receipt.outcome.clearing.iter().all(|c| c.volume.0 > 0));

    // Every fill respects its order's limit and quantity.
    let orders = orders_by_commitment(&w);
    for f in &res.artifacts.fills {
        let o = orders[&f.commitment];
        assert_eq!(o.trader, f.trader);
        assert!(f.quantity <= o.quantity);
        assert!(f.tick >= w.batch.header.band.lo && f.tick <= w.batch.header.band.hi);
        match o.side {
            Side::Buy => assert!(f.tick <= o.effective_limit(), "buy above limit"),
            Side::Sell => assert!(f.tick >= o.effective_limit(), "sell below limit"),
        }
    }

    // Per book, buy volume == sell volume == reported volume.
    for c in &res.receipt.outcome.clearing {
        let (mut b, mut s) = (0u64, 0u64);
        for f in res.artifacts.fills.iter().filter(|f| f.book == c.book) {
            assert_eq!(f.tick, c.tick);
            match f.side {
                Side::Buy => b += f.quantity.0,
                Side::Sell => s += f.quantity.0,
            }
        }
        assert_eq!((b, s), (c.volume.0, c.volume.0));
    }

    // Settlement conserves and nobody goes negative.
    res.artifacts
        .settlement
        .check_conservation()
        .expect("conservation");
    res.artifacts.settlement.apply(&balances).expect("solvent");
    assert!(res.metrics.accepted > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn deterministic_replay_and_arrival_order_independence() {
    let keys = keys();
    let cfg = WorkloadConfig::new(
        default_params(FlowMode::SingleBook, CommitmentScheme::Sha256),
        800,
        2,
    );
    let w = generate(&cfg, keys.as_ref());
    let a = executor(&keys).execute(w.batch.clone()).await.unwrap();
    let b = executor(&keys).execute(w.batch.clone()).await.unwrap();
    assert_eq!(a.receipt.outcome, b.receipt.outcome);
    assert_eq!(a.receipt.trace, b.receipt.trace);

    // The relay's arrival order must not matter: the root is over the set.
    let mut shuffled = w.batch.clone();
    shuffled
        .envelopes
        .shuffle(&mut rand_chacha::ChaCha20Rng::seed_from_u64(9));
    let c = executor(&keys).execute(shuffled).await.unwrap();
    assert_eq!(a.receipt.outcome, c.receipt.outcome);
}

#[tokio::test(flavor = "multi_thread")]
async fn tight_funding_never_overdraws() {
    let keys = keys();
    let mut cfg = WorkloadConfig::new(
        default_params(FlowMode::DualFlow, CommitmentScheme::Sha256),
        1_500,
        3,
    );
    cfg.funding = Funding::Tight(60);
    cfg.traders = 40;
    let w = generate(&cfg, keys.as_ref());
    let res = executor(&keys).execute(w.batch.clone()).await.unwrap();
    assert!(
        res.metrics.rejected > 0,
        "expected some collateral rejections"
    );
    res.artifacts
        .settlement
        .apply(&w.batch.balances)
        .expect("solvent");
}

#[tokio::test(flavor = "multi_thread")]
async fn inconsistent_header_is_refused() {
    let keys = keys();
    let cfg = WorkloadConfig::new(
        default_params(FlowMode::SingleBook, CommitmentScheme::Sha256),
        50,
        4,
    );
    let w = generate(&cfg, keys.as_ref());

    let mut dropped = w.batch.clone();
    dropped.envelopes.pop();
    assert!(matches!(
        executor(&keys).execute(dropped).await,
        Err(ExecutorError::BadHeader(_))
    ));

    let mut swapped = w.batch.clone();
    swapped.header.batch_root.0[0] ^= 1;
    assert!(matches!(
        executor(&keys).execute(swapped).await,
        Err(ExecutorError::BadHeader("batch root"))
    ));

    let mut rich = w.batch.clone();
    let (t, b) = rich.balances.iter().next().map(|(t, b)| (*t, *b)).unwrap();
    rich.balances.set(
        t,
        timescales_auction::collateral::Balance {
            quote: timescales_core::QuoteAtoms(b.quote.0 + 1),
            ..b
        },
    );
    assert!(matches!(
        executor(&keys).execute(rich).await,
        Err(ExecutorError::BadHeader("balances root"))
    ));
}
