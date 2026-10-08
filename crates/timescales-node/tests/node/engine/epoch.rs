//! Full epochs with a receipt quorum of two, and the epoch that
//! follows on the carried state.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::time::Duration;

use timescales_auction::orderbook::OrderStateTable;
use timescales_chain::program::BatchStatus;
use timescales_core::{Decode, MarketId, Role, Side};
use timescales_node::NodeApi;
use timescales_service::store::node::Phase;

use crate::support::enclave::{HANG, Mode};
use crate::support::world::{Options, World, epoch_of};

#[tokio::test(start_paused = true)]
async fn a_full_epoch_with_a_quorum_of_two() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    let mut events = w.node().events();
    w.deal(1..=6).await;
    let maker = w.trader(10_000, 0).await;
    let taker = w.trader(0, 1_000_000).await;
    let e = w.fresh_epoch().await;
    let pk = w.epoch_pk(e);
    let mid = MarketId(w.market_id);
    let (sell, _) = maker.order(&w.relay_cfg, mid, e, &pk, Side::Sell, Role::Maker, 100, 5);
    let (buy, _) = taker.order(&w.relay_cfg, mid, e, &pk, Side::Buy, Role::Taker, 100, 5);
    let r = w
        .node()
        .submit(w.market, vec![sell], maker.session.unwrap())
        .await;
    assert!(r[0].is_ok(), "{r:?}");
    let r = w
        .node()
        .submit(w.market, vec![buy], taker.session.unwrap())
        .await;
    let accepted = r[0].clone().unwrap();
    w.to_cutoff().await;
    // The promise is the relay's, for this market, epoch and envelope.
    let promise =
        timescales_service::relay::InclusionPromiseV2::decode_exact(&accepted.promise_b64.0)
            .unwrap();
    assert!(promise.verify());
    assert_eq!(promise.epoch.0, e);

    let row = w.phase(e, &[Phase::Settled, Phase::Aborted]).await;
    assert_eq!(row.phase, Phase::Settled, "{row:?}");
    let b = w.batch(e).await.unwrap();
    assert_eq!(b.status, BatchStatus::Settled);
    assert!(b.cosign_bitmap.count_ones() >= 2, "quorum on chain");
    assert!(row.artifacts_public);
    assert_eq!(w.market_account().await.last_settled, e);
    assert_eq!(w.trader_account(maker.id()).await.base, 10_000 - 5);
    assert_eq!(w.trader_account(taker.id()).await.base, 5);

    // Every attempt row was written, and two agreeing executions came back
    // before the poster published.
    let attempts = w.node().store().attempts(w.market, e).await.unwrap();
    let ready = attempts
        .iter()
        .filter(|a| a.result.as_deref() == Some("ready"))
        .count();
    assert!(ready >= 2, "{attempts:?}");
    assert_eq!(w.enclaves.publishes_for(e), 1, "one PublishRequest");
    // The first ready enclave in dispatch order (the designated poster
    // whenever it is among the quorum) was asked to publish.
    let first = designated_poster(&w, e);
    let poster = (0..w.opts.enclaves)
        .map(|k| (first + k) % w.opts.enclaves)
        .find(|i| {
            attempts
                .iter()
                .any(|a| a.enclave == i.to_string() && a.result.as_deref() == Some("ready"))
        })
        .unwrap();
    assert_eq!(published(&w, poster, e), 1, "{attempts:?}");

    // The carried state the next epoch executes against is the chain's.
    let (tbl, root, confirmed) = w
        .node()
        .store()
        .order_state(w.market, e)
        .await
        .unwrap()
        .unwrap();
    assert!(confirmed);
    assert_eq!(OrderStateTable::decode_exact(&tbl).unwrap().root(), root);
    assert_eq!(root, w.market_account().await.state_root);

    // Public artifacts and the stream.
    assert!(
        w.node()
            .store()
            .public_artifacts(w.market, e)
            .await
            .unwrap()
            .is_some()
    );
    // The settle job publishes after it writes the row.
    let mut kinds = BTreeSet::new();
    w.wait(
        "epoch.settled",
        std::time::Duration::from_secs(60),
        async |_| {
            while let Ok(ev) = events.try_recv() {
                if epoch_of(&ev.event) == Some(e) || ev.event.kind().starts_with("key") {
                    kinds.insert(ev.event.kind());
                }
            }
            kinds.contains("epoch.settled").then_some(())
        },
    )
    .await;
    for k in [
        "epoch.opened",
        "epoch.closed",
        "epoch.committed",
        "epoch.revealed",
        "epoch.executing",
        "epoch.quorum",
        "epoch.posted",
        "epoch.settled",
        "key.published",
    ] {
        assert!(kinds.contains(k), "{k} missing from {kinds:?}");
    }

    // The next epoch settles on top of this one (an idle epoch commits a
    // cover-only batch).
    w.phase(e + 1, &[Phase::Open]).await;
    w.to_cutoff().await;
    let next = w.phase(e + 1, &[Phase::Settled]).await;
    assert_eq!(next.phase, Phase::Settled);
    assert_eq!(w.market_account().await.last_settled, e + 1);
}

/// The enclave `Enclaves::eligible` puts first for epoch `e`: every test
/// enclave is registered, so the rotation is by `e mod n`.
fn designated_poster(w: &World, e: u64) -> usize {
    usize::try_from(e % u64::try_from(w.opts.enclaves).unwrap()).unwrap()
}

fn published(w: &World, i: usize, e: u64) -> usize {
    w.enclaves.list[i]
        .published
        .lock()
        .iter()
        .filter(|p| **p == e)
        .count()
}

/// With a quorum of two and one spare, a designated
/// poster that never answers neither holds the epoch until
/// `attempt_timeout_ms` nor gets the `PublishRequest`. The next ready
/// enclave in dispatch order publishes, and the hung attempt is recorded.
#[tokio::test(start_paused = true)]
async fn a_hung_enclave_does_not_hold_the_quorum() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    w.deal(1..=6).await;
    let e = w.fresh_epoch().await;
    let hung = designated_poster(&w, e);
    w.enclaves.list[hung].set_mode(Mode::Hang);
    w.to_cutoff().await;

    w.phase(e, &[Phase::Executing, Phase::Posted, Phase::Settled])
        .await;
    let executing = tokio::time::Instant::now();
    let row = w
        .phase(e, &[Phase::Posted, Phase::Settled, Phase::Aborted])
        .await;
    let took = executing.elapsed();
    assert_ne!(row.phase, Phase::Aborted, "{row:?}");
    let timeout = Duration::from_millis(w.cfg.execution.attempt_timeout_ms);
    assert!(
        took < timeout / 10,
        "posted after {took:?} (timeout {timeout:?})"
    );
    assert!(took < HANG);

    let row = w.phase(e, &[Phase::Settled]).await;
    assert!(row.artifacts_public);
    assert!(w.batch(e).await.unwrap().cosign_bitmap.count_ones() >= 2);

    // The hung enclave was asked to execute but never to publish. The
    // next one in dispatch order was.
    assert!(w.enclaves.list[hung].executes.load(Ordering::Relaxed) >= 1);
    assert_eq!(published(&w, hung, e), 0);
    let next = (hung + 1) % w.opts.enclaves;
    assert_eq!(published(&w, next, e), 1);
    let attempts = w.node().store().attempts(w.market, e).await.unwrap();
    let hung_rows: Vec<_> = attempts
        .iter()
        .filter(|a| a.enclave == hung.to_string())
        .collect();
    assert_eq!(hung_rows.len(), 1, "{attempts:?}");
    assert_eq!(hung_rows[0].result.as_deref(), Some("abandoned"));
    let ready = attempts
        .iter()
        .filter(|a| a.result.as_deref() == Some("ready"))
        .count();
    assert_eq!(ready, 2, "{attempts:?}");
}
