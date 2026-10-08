//! Fault injection: ambiguities (a transaction that lands while its sender
//! sees an error: commit, reveal, cosign, every settlement step, abort and
//! ApplyChange. A reclaim needs 1024 settled epochs and is not reached),
//! intake pauses (pipeline backlog, missing epoch keys, halt), fencing on
//! equivocation, and governance: pending and due changes, applied between
//! batches before the next commit, and a relay rotation that drains the
//! old key.

use std::time::Duration;

use timescales_chain::program::{BatchStatus, GovernanceChange};
use timescales_chain::{CommitOutcome, RpcError, RpcMethod};
use timescales_core::{Hash32, MarketId, Role, Side};
use timescales_node::NodeApi;
use timescales_node::market::Mode as MarketMode;
use timescales_service::api::{ErrorCode, Event, PauseReason};
use timescales_service::store::node::Phase;
use timescales_service::wire::RelayRefusal;

use crate::support::enclave::Mode;
use crate::support::svm;
use crate::support::trader::Trader;
use crate::support::world::{Options, World};

async fn crossing(w: &World) -> (u64, Trader, Trader) {
    let maker = w.trader(10_000, 0).await;
    let taker = w.trader(0, 1_000_000).await;
    let e = w.fresh_epoch().await;
    let pk = w.epoch_pk(e);
    let mid = MarketId(w.market_id);
    let (sell, _) = maker.order(&w.relay_cfg, mid, e, &pk, Side::Sell, Role::Maker, 100, 5);
    let (buy, _) = taker.order(&w.relay_cfg, mid, e, &pk, Side::Buy, Role::Taker, 100, 5);
    assert!(
        w.node()
            .submit(w.market, vec![sell], maker.session.unwrap())
            .await[0]
            .is_ok()
    );
    assert!(
        w.node()
            .submit(w.market, vec![buy], taker.session.unwrap())
            .await[0]
            .is_ok()
    );
    (e, maker, taker)
}

/// The next transaction the node sends lands, but the node sees a timeout.
fn drop_next_response(w: &World) {
    w.node_rpc.drop_response_after_send(1, RpcError::Timeout);
}

/// Transactions the node has sent so far.
fn sends(w: &World) -> u64 {
    w.node_rpc.calls(RpcMethod::SendTransaction)
}

/// Every journalled transaction, in send order: `(op, status)`.
async fn journal(w: &World) -> Vec<(String, String)> {
    w.node()
        .store()
        .store()
        .read(|c| {
            let mut q = c.prepare("SELECT op, status FROM txs ORDER BY id")?;
            let rows = q
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .unwrap()
}

/// Landed transactions of `op` journalled for epoch `e`.
async fn landed(w: &World, e: u64, op: &str) -> usize {
    w.node()
        .store()
        .txs_for(w.market, e)
        .await
        .unwrap()
        .iter()
        .filter(|t| t.op == op && t.status == "landed")
        .count()
}

#[tokio::test(start_paused = true)]
async fn ambiguous_sends_complete_once() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    w.deal(1..=6).await;
    let (e, maker, _) = crossing(&w).await;
    // The poster posts without sending co-signatures: the node sends the
    // missing CoSignReceipt itself.
    w.enclaves.list[0].set_mode(Mode::PostOnly);
    w.enclaves.list[1].set_mode(Mode::PostOnly);
    w.enclaves.list[2].set_mode(Mode::PostOnly);

    // CommitBatch: lands, the node sees a timeout.
    drop_next_response(&w);
    w.to_cutoff().await;
    w.phase(e, &[Phase::Committed, Phase::Snapshotted]).await;
    let row = w.row(e).await.unwrap();
    assert_eq!(
        Some(w.batch(e).await.unwrap().root),
        row.root,
        "the same root"
    );
    // RevealBeacon.
    drop_next_response(&w);
    w.phase(e, &[Phase::Revealed, Phase::Sealed, Phase::Executing])
        .await;
    // CoSignReceipt (sent by the node).
    drop_next_response(&w);
    w.phase(e, &[Phase::Posted]).await;
    // Every settlement transaction (verify chunks, finalize, apply chunks,
    // close) lands while the node sees a timeout.
    let before = sends(&w);
    w.node_rpc.drop_response_after_send(64, RpcError::Timeout);
    let row = w.phase(e, &[Phase::Settled, Phase::Aborted]).await;
    w.node_rpc.clear();
    assert_eq!(row.phase, Phase::Settled);
    let mut settle_landed = 0;
    for op in ["verify", "finalize", "apply", "close"] {
        settle_landed += landed(&w, e, op).await;
    }
    assert_eq!(landed(&w, e, "finalize").await, 1);
    assert!(landed(&w, e, "verify").await >= 1 && landed(&w, e, "apply").await >= 1);
    // No step was sent again: one send per landed transaction.
    assert_eq!(sends(&w) - before, u64::try_from(settle_landed).unwrap());
    assert_eq!(w.trader_account(maker.id()).await.base, 10_000 - 5);
    let b = w.batch(e).await.unwrap();
    assert!(b.cosign_bitmap.count_ones() >= 2);
    assert!(landed(&w, e, "commit").await <= 1);
    // One CoSignReceipt per co-signer at most, though one answer was lost.
    assert!(landed(&w, e, "cosign").await < w.enclaves.list.len());
    assert!(w.node_rpc.calls(RpcMethod::SendTransaction) > 0);
}

#[tokio::test(start_paused = true)]
async fn backlog_and_missing_keys_pause_intake() {
    // A long execution deadline: e stays in flight for the whole test.
    let mut w = World::new(Options {
        exec_timeout: 20_000,
        ..Options::default()
    })
    .await;
    w.start_node().await.unwrap();
    w.deal(1..=3).await;
    let t = w.trader(0, 100_000).await;
    // Epoch e stays in flight (no enclave answers), e + 1 closes behind it.
    w.enclaves.set_all(Mode::Offline);
    let e = w.fresh_epoch().await;
    w.to_cutoff().await;
    w.phase(e + 1, &[Phase::Open]).await;
    w.to_cutoff().await;
    w.phase(e + 1, &[Phase::Closed]).await;
    let v = w
        .wait(
            "backlog pause",
            Duration::from_secs(30),
            async |w: &World| {
                let v = w.view();
                (v.pause == Some(PauseReason::PipelineBacklog)).then_some(v)
            },
        )
        .await;
    assert!(v.open.is_none());
    // A submission for the epoch that cannot open: INTAKE_PAUSED, signed.
    let pk = w.epoch_pk(e + 2);
    let (o, _) = t.order(
        &w.relay_cfg,
        MarketId(w.market_id),
        e + 2,
        &pk,
        Side::Buy,
        Role::Taker,
        100,
        1,
    );
    let r = w.node().submit(w.market, vec![o], t.session.unwrap()).await;
    let err = r[0].clone().unwrap_err();
    assert_eq!(err.code, ErrorCode::IntakePaused);
    assert_eq!(err.details["reason"], "pipeline_backlog");
    let refusal = timescales_core::Decode::decode_exact(err.refusal.as_deref().unwrap());
    let refusal: RelayRefusal = refusal.unwrap();
    assert_eq!(refusal.code, RelayRefusal::INTAKE_PAUSED);
    refusal.verify().unwrap();

    // The enclaves come back: e settles, e + 1 commits, and e + 2 has no
    // key (only epochs through 3 were dealt).
    w.enclaves.set_all(Mode::Normal);
    w.phase(e, &[Phase::Settled, Phase::Aborted]).await;
    if e + 2 > 3 {
        w.wait("key pause", Duration::from_secs(120), async |w: &World| {
            (w.view().pause == Some(PauseReason::EpochKeyUnavailable)).then_some(())
        })
        .await;
        w.deal(e + 2..=e + 3).await;
    }
    let next = w.phase(e + 2, &[Phase::Open]).await;
    assert_eq!(next.epoch, e + 2);
}

#[tokio::test(start_paused = true)]
async fn a_halt_stops_intake_until_lifted() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    w.deal(1..=4).await;
    let (e, maker, taker) = crossing(&w).await;
    w.set_halted(true).await;
    w.wait(
        "halt observed",
        Duration::from_secs(30),
        async |w: &World| w.view().halted.then_some(()),
    )
    .await;
    let pk = w.epoch_pk(e);
    let (o, _) = maker.order(
        &w.relay_cfg,
        MarketId(w.market_id),
        e,
        &pk,
        Side::Sell,
        Role::Maker,
        101,
        1,
    );
    let r = w
        .node()
        .submit(w.market, vec![o], maker.session.unwrap())
        .await;
    assert_eq!(r[0].clone().unwrap_err().code, ErrorCode::MarketHalted);
    w.to_cutoff().await;
    w.phase(e, &[Phase::Closed]).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        w.row(e).await.unwrap().phase,
        Phase::Closed,
        "no commit while halted"
    );
    assert_eq!(w.view().pause, Some(PauseReason::Halted));
    w.set_halted(false).await;
    let row = w.phase(e, &[Phase::Settled]).await;
    assert_eq!(row.phase, Phase::Settled);
    assert_eq!(w.trader_account(taker.id()).await.base, 5);
}

#[tokio::test(start_paused = true)]
async fn equivocation_fences_the_market() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    w.deal(1..=4).await;
    let (e, _, _) = crossing(&w).await;
    // Another process with the relay key commits epoch e first, with another
    // root, while this node cannot reach the cluster.
    w.node_rpc.fail_next(
        RpcMethod::SendTransaction,
        100_000,
        RpcError::Transport("cut off".into()),
    );
    w.to_cutoff().await;
    w.phase(e, &[Phase::Committing]).await;
    let (relay, _) = svm::key(w.relay_seed);
    let row = w.row(e).await.unwrap();
    let other = w
        .chain
        .ensure_committed(
            e,
            Hash32([0xee; 32]),
            row.envelope_count.unwrap(),
            row.terms_digest.unwrap(),
            relay,
        )
        .await
        .unwrap();
    assert!(matches!(other, CommitOutcome::Committed { .. }));
    w.node_rpc.clear();
    w.wait("fenced", Duration::from_secs(60), async |w: &World| {
        matches!(w.view().mode, MarketMode::Fenced(_)).then_some(())
    })
    .await;
    let metrics = w.metrics.clone().unwrap();
    let detected = metrics
        .equivocation_detected
        .get_or_create(&metrics.market(&w.market))
        .get();
    assert_eq!(detected, 1);
    assert_eq!(w.view().pause, Some(PauseReason::Fenced));
    let t = w.trader(0, 100_000).await;
    let pk = w.epoch_pk(e + 1);
    let (o, _) = t.order(
        &w.relay_cfg,
        MarketId(w.market_id),
        e + 1,
        &pk,
        Side::Buy,
        Role::Taker,
        100,
        1,
    );
    let r = w.node().submit(w.market, vec![o], t.session.unwrap()).await;
    assert_eq!(r[0].clone().unwrap_err().code, ErrorCode::MarketUnavailable);
    // Restarting does not unfence: the table fences the same cell again.
    w.crash().await;
    w.start_node().await.unwrap();
    w.wait(
        "fenced again",
        Duration::from_secs(60),
        async |w: &World| matches!(w.view().mode, MarketMode::Fenced(_)).then_some(()),
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_due_change_is_applied_before_the_next_commit() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    let mut events = w.node().events();
    w.deal(1..=6).await;
    let (e, _, _) = crossing(&w).await;
    // A between-batches change, due after the 20-slot timelock.
    let change = GovernanceChange::SetTimings {
        beacon_delay_slots: 5,
        exec_timeout_slots: 200,
        settle_timeout_slots: 2_000,
    };
    let ix = timescales_chain::program::propose_change(
        &w.program,
        &w.admin.address(),
        &w.market,
        &change,
    )
    .unwrap();
    svm::send(&w.sender, vec![ix], &w.admin, vec![]).await;
    // e closes after the 20-slot timelock, with the change due: the node
    // applies it (ApplyChange) before committing, or CommitBatch would fail
    // with ChangeDue. The ApplyChange lands while the node sees a timeout.
    let sent = journal(&w).await.len();
    drop_next_response(&w);
    w.to_cutoff().await;
    w.phase(e, &[Phase::Settled]).await;
    let after = journal(&w).await;
    assert_eq!(
        after[sent],
        ("apply_change".to_owned(), "landed".to_owned()),
        "{after:?}"
    );
    assert_eq!(after[sent + 1].0, "commit");
    assert_eq!(after.iter().filter(|t| t.0 == "apply_change").count(), 1);
    w.phase(e + 1, &[Phase::Open]).await;
    w.to_cutoff().await;
    w.phase(e + 1, &[Phase::Settled]).await;
    let m = w.market_account().await;
    assert!(m.pending.is_none());
    assert_eq!(m.beacon_delay_slots, 5);
    assert_eq!(m.exec_timeout_slots, 200);
    let mut pending = false;
    let mut applied = false;
    while let Ok(ev) = events.try_recv() {
        match ev.event {
            Event::GovernancePending { .. } => pending = true,
            Event::GovernanceApplied { .. } => applied = true,
            _ => {}
        }
    }
    assert!(pending && applied, "pending {pending}, applied {applied}");
    assert_eq!(w.batch(e).await.unwrap().status, BatchStatus::Settled);
    assert_eq!(w.batch(e + 1).await.unwrap().status, BatchStatus::Settled);
}

#[tokio::test(start_paused = true)]
async fn an_applied_set_relay_drains_the_old_key() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    let mut events = w.node().events();
    w.deal(1..=6).await;
    let (e, _, _) = crossing(&w).await;
    let new_relay = [9; 32];
    let change = GovernanceChange::SetRelay(new_relay);
    let ix = timescales_chain::program::propose_change(
        &w.program,
        &w.admin.address(),
        &w.market,
        &change,
    )
    .unwrap();
    svm::send(&w.sender, vec![ix], &w.admin, vec![]).await;
    let t = w.trader(0, 100_000).await;
    let s = t.session.unwrap();
    // e closes after the 20-slot timelock: the node applies the due change
    // before committing, and from then on the chain no longer takes its key.
    w.to_cutoff().await;
    w.wait(
        "the relay rotated",
        Duration::from_secs(120),
        async |w: &World| (w.view().pause == Some(PauseReason::Draining)).then_some(()),
    )
    .await;
    assert_eq!(w.market_account().await.relay, new_relay);
    assert_eq!(w.view().mode, MarketMode::Draining);

    // Nothing is promised with the old key, into any epoch.
    let mid = MarketId(w.market_id);
    for epoch in [e, e + 1] {
        let pk = w.epoch_pk(epoch);
        let (o, _) = t.order(
            &w.relay_cfg,
            mid,
            epoch,
            &pk,
            Side::Buy,
            Role::Taker,
            100,
            1,
        );
        let r = w.node().submit(w.market, vec![o], s).await;
        let err = r[0].clone().unwrap_err();
        assert_eq!(err.code, ErrorCode::Draining);
        assert!(err.refusal.is_none());
    }
    // An operator resume does not reopen intake under the old key.
    w.node()
        .admin(timescales_node::AdminCmd::Resume(w.market))
        .await
        .unwrap();
    // No epoch opens and the closed one waits for the restart with the new
    // key instead of a CommitBatch the program would refuse.
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(w.view().open.is_none());
    assert_eq!(w.view().pause, Some(PauseReason::Draining));
    for later in [e + 1, e + 2] {
        assert_eq!(w.row(later).await.unwrap().phase, Phase::Scheduled);
    }
    assert_eq!(w.row(e).await.unwrap().phase, Phase::Closed);
    assert!(w.batch(e).await.is_none());
    assert_eq!(landed(&w, e, "commit").await, 0);
    assert!(w.node().parked(w.market, s).await.unwrap().is_empty());

    let mut drained = false;
    let mut applied = false;
    while let Ok(ev) = events.try_recv() {
        match ev.event {
            Event::MarketStateChanged { state, .. } => {
                drained |= state == timescales_service::api::MarketState::Draining;
            }
            Event::GovernanceApplied { .. } => applied = true,
            _ => {}
        }
    }
    assert!(drained && applied, "drained {drained}, applied {applied}");
}

#[tokio::test(start_paused = true)]
async fn the_platform_check_covers_every_enclave() {
    use timescales_executor::attestation::Platform;
    use timescales_node::app::{PlatformCheck, platform_check, platform_verdict};
    use timescales_node::config::ExpectedPlatform;
    use timescales_service::Profile;

    let w = World::new(Options::default()).await;
    assert_eq!(
        w.cfg.execution.expected_platform,
        ExpectedPlatform::Simulated
    );
    let exec: &dyn timescales_node::ExecClient = &*w.enclaves;
    // No identity route: a warning outside production. Production refuses
    // unless the operator overrides it.
    let check = platform_check(&w.cfg, exec).await;
    assert_eq!(check.unverified.len(), w.enclaves.list.len());
    assert!(check.mismatched.is_empty());
    assert_eq!(platform_verdict(&w.cfg, &check).unwrap().len(), 1);
    let mut prod = w.cfg.clone();
    prod.node.profile = Profile::Production;
    assert!(platform_verdict(&prod, &check).is_err());
    prod.execution.allow_unverified_platform = true;
    assert_eq!(platform_verdict(&prod, &check).unwrap().len(), 1);

    for e in &w.enclaves.list {
        *e.platform.lock() = Some(Platform::Simulated);
    }
    let check = platform_check(&w.cfg, exec).await;
    assert_eq!(check, PlatformCheck::default());
    assert!(platform_verdict(&w.cfg, &check).unwrap().is_empty());

    // One enclave on another platform than configured: never starts, not
    // even with the override.
    *w.enclaves.list[1].platform.lock() = Some(Platform::IntelTdx);
    let check = platform_check(&w.cfg, exec).await;
    assert_eq!(check.mismatched.len(), 1, "{check:?}");
    assert!(check.unverified.is_empty());
    assert!(platform_verdict(&w.cfg, &check).is_err());
    assert!(platform_verdict(&prod, &check).is_err());
}

#[tokio::test(start_paused = true)]
async fn an_ambiguous_abort_lands_once() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    w.deal(1..=3).await;
    let (e, maker, _) = crossing(&w).await;
    // No enclave answers: e aborts with exec_timeout after the reveal.
    w.enclaves.set_all(Mode::Offline);
    w.to_cutoff().await;
    w.status(e, |b| b.status == BatchStatus::BeaconRevealed)
        .await;
    w.phase(e, &[Phase::Executing]).await;
    let before = sends(&w);
    drop_next_response(&w);
    let row = w.phase(e, &[Phase::Aborted]).await;
    assert_eq!(
        row.abort_reason,
        Some(timescales_chain::program::AbortReason::ExecTimeout as u8)
    );
    assert_eq!(w.batch(e).await.unwrap().status, BatchStatus::Aborted);
    assert_eq!(landed(&w, e, "abort").await, 1);
    assert_eq!(sends(&w) - before, 1);
    assert_eq!(w.trader_account(maker.id()).await.base, 10_000);
}
