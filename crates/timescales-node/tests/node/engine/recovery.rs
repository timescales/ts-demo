//! Crash recovery: the cells of the table that are not a fence.
//!
//! Injected one by one: every `closed`, `committing`, `committed` /
//! `snapshotted`, `revealed` / `sealed` / `executing`, `posted` and
//! `aborting` cell that is not a fence (the `committed` row through its
//! `snapshotted` copy, the `revealed` / `sealed` row through a rolled-back
//! `executing` copy), the `open` cell, and the "keep" cells of `scheduled`,
//! `settled` and `aborted` (both also reclaimed). AHEAD is exercised through
//! `open` x Settled and `scheduled` x Committed in one test. Its other
//! columns go through the same adoption code and are not injected
//! separately.
//!
//! Each case runs one epoch with a crossing pair of orders, captures a
//! consistent copy of the node's database in the cell's persisted phase,
//! drives the chain to the cell's status (holding it there with enclave or
//! RPC faults, or with the harness acting as another cranker), crashes the
//! node, restores the copy - the database is now behind the chain exactly
//! as in the cell - and restarts. The epoch must end as the table says:
//! settled with the fills applied once, or aborted.

use std::sync::Arc;
use std::time::Duration;

use timescales_chain::program::{AbortReason, BatchStatus};
use timescales_chain::{AbortOutcome, RpcError, RpcMethod};
use timescales_core::{MarketId, Role, Side};
use timescales_node::NodeApi;
use timescales_node::market::REVEAL_WINDOW;
use timescales_node::market::recover::{Action, ChainState, action};
use timescales_service::store::node::{NodeRepo, Phase};
use timescales_service::store::{Schema, Store, StoreOptions};

use crate::support::enclave::Mode;
use crate::support::svm;
use crate::support::trader::Trader;
use crate::support::world::{Options, World};

/// Where the copy of the database is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Copy {
    Open,
    Closed,
    Committing,
    Snapshotted,
    /// The executing copy with its attempts removed and the phase set back
    /// to `sealed` (or `revealed`, also without the sealed batch): the
    /// database of a node that crashed before dispatching.
    Rolled(Phase),
    Executing,
    Posted,
    Aborting,
    /// `aborting` with the batch still committed: a beacon_expired abort,
    /// or (`relay`) a relay abort decided inside the relay window whose
    /// transaction was never sent. The restart comes after the window.
    AbortingCommitted {
        relay: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ends {
    Settled,
    Aborted,
}

struct Case {
    copy: Copy,
    chain: ChainState,
    ends: Ends,
}

fn blocked() -> RpcError {
    RpcError::Transport("node cut off".into())
}

/// The node cannot send any transaction until `unblock`.
fn block(w: &World) {
    w.node_rpc
        .fail_next(RpcMethod::SendTransaction, 100_000, blocked());
}

fn unblock(w: &World) {
    w.node_rpc.clear();
}

struct Run {
    w: World,
    e: u64,
    maker: Trader,
    taker: Trader,
}

async fn setup() -> Run {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    w.deal(1..=8).await;
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
    Run { w, e, maker, taker }
}

/// Moves time to `e`'s cutoff if `e` is still open (never past a later
/// epoch's cutoff: that would also run out the in-flight deadlines).
async fn close(w: &World, e: u64) {
    if w.row(e).await.is_some_and(|r| r.phase == Phase::Open) {
        w.to_cutoff().await;
    }
}

/// The chain's batch of `e` at `status` (or past it).
async fn reach(w: &World, e: u64, status: BatchStatus) {
    w.status(e, |b| b.status >= status).await;
}

/// The harness verifies and finalizes the posted batch, as another
/// cranker would.
async fn verify(w: &World, e: u64) {
    let s = w
        .enclaves
        .artifacts(e)
        .expect("an enclave executed the epoch")
        .settlement;
    let leaves = timescales_chain::program::leaves(&s).unwrap();
    let ix = timescales_chain::program::verify_deltas(
        &w.program,
        &w.admin.address(),
        &w.market,
        e,
        &leaves,
    )
    .unwrap();
    svm::send(&w.sender, vec![ix], &w.admin, vec![]).await;
    let batch = timescales_chain::program::batch_pda(&w.program, &w.market, e)
        .unwrap()
        .0;
    let fin =
        timescales_chain::program::finalize(&w.program, &w.admin.address(), &w.market, &batch);
    svm::send(&w.sender, vec![fin], &w.admin, vec![]).await;
    reach(w, e, BatchStatus::Verified).await;
}

async fn settle(w: &World, e: u64) {
    let s = w
        .enclaves
        .artifacts(e)
        .expect("an enclave executed the epoch")
        .settlement;
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    w.chain
        .ensure_settled(e, Arc::new(s), w.admin.clone(), tx)
        .await
        .unwrap();
    reach(w, e, BatchStatus::Settled).await;
}

/// Commits `e` with the closed batch the node holds, as another
/// incarnation of this node would have sent it: same root, same relay key.
async fn commit_as_the_relay(w: &World, e: u64) {
    let row = w.row(e).await.unwrap();
    let (relay, _) = svm::key(w.relay_seed);
    w.chain
        .ensure_committed(
            e,
            row.root.unwrap(),
            row.envelope_count.unwrap(),
            row.terms_digest.unwrap(),
            relay,
        )
        .await
        .unwrap();
}

/// Lets slots pass until `slot`.
async fn until_slot(w: &World, slot: u64) {
    while w.svm.current_slot() < slot {
        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Executes the epoch on enclave 0 with enclave 1 co-signing, as an
/// enclave that got the request would on its own.
async fn foreign_post(w: &World, e: u64) {
    w.enclaves.set_all(Mode::Normal);
    let req = w
        .enclaves
        .request(e)
        .expect("the node dispatched the epoch");
    w.enclaves.execute_and_post(0, req, &[1]).await.unwrap();
    reach(w, e, BatchStatus::ReceiptPosted).await;
}

/// Rolls a copied database back from `executing` to `to`.
async fn roll_back(path: &std::path::Path, market: [u8; 32], e: u64, to: Phase) {
    let store = Store::open(path, Schema::Node, StoreOptions::default()).unwrap();
    let repo = NodeRepo::new(store);
    let code = i64::from(to.code());
    let epoch = i64::try_from(e).unwrap();
    let drop_sealed = to == Phase::Revealed;
    repo.store()
        .write(move |tx| {
            tx.execute(
                "DELETE FROM attempts WHERE market = ?1 AND epoch = ?2",
                (market, epoch),
            )?;
            if drop_sealed {
                tx.execute(
                    "DELETE FROM sealed WHERE market = ?1 AND epoch = ?2",
                    (market, epoch),
                )?;
                tx.execute(
                    "UPDATE epochs SET header = NULL WHERE market = ?1 AND epoch = ?2",
                    (market, epoch),
                )?;
            }
            tx.execute(
                "UPDATE epochs SET phase = ?3 WHERE market = ?1 AND epoch = ?2",
                (market, epoch, code),
            )?;
            Ok(())
        })
        .await
        .unwrap();
    drop(repo);
}

/// Sets a copied database's epoch `e` to `aborting(reason)`.
async fn set_aborting(path: &std::path::Path, market: [u8; 32], e: u64, reason: AbortReason) {
    let store = Store::open(path, Schema::Node, StoreOptions::default()).unwrap();
    let repo = NodeRepo::new(store);
    let code = i64::from(Phase::Aborting.code());
    let epoch = i64::try_from(e).unwrap();
    let reason = i64::from(reason as u8);
    repo.store()
        .write(move |tx| {
            tx.execute(
                "UPDATE epochs SET phase = ?3, abort_reason = ?4 WHERE market = ?1 AND epoch = ?2",
                (market, epoch, code, reason),
            )?;
            Ok(())
        })
        .await
        .unwrap();
    drop(repo);
}

async fn run(case: Case) {
    let Run {
        mut w,
        e,
        maker,
        taker,
    } = setup().await;

    // 1. Reach the persisted phase of the cell and copy the database.
    let copy = match case.copy {
        Copy::Open => w.copy_db("cell").await,
        Copy::Closed => {
            w.set_halted(true).await;
            w.to_cutoff().await;
            w.phase(e, &[Phase::Closed]).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert_eq!(w.row(e).await.unwrap().phase, Phase::Closed);
            w.copy_db("cell").await
        }
        Copy::Committing => {
            block(&w);
            w.to_cutoff().await;
            w.phase(e, &[Phase::Committing]).await;
            w.copy_db("cell").await
        }
        Copy::Snapshotted => {
            w.to_cutoff().await;
            // The snapshot needs no transaction. The reveal does.
            w.phase(e, &[Phase::Committed, Phase::Snapshotted]).await;
            block(&w);
            w.phase(e, &[Phase::Snapshotted]).await;
            w.copy_db("cell").await
        }
        Copy::Executing | Copy::Rolled(_) => {
            w.enclaves.set_all(Mode::Offline);
            w.to_cutoff().await;
            w.phase(e, &[Phase::Executing]).await;
            let path = w.copy_db("cell").await;
            if let Copy::Rolled(to) = case.copy {
                roll_back(&path, w.market, e, to).await;
            }
            path
        }
        Copy::Posted => {
            w.to_cutoff().await;
            w.phase(e, &[Phase::Executing]).await;
            block(&w);
            w.phase(e, &[Phase::Posted]).await;
            w.copy_db("cell").await
        }
        Copy::AbortingCommitted { relay } => {
            block(&w);
            w.to_cutoff().await;
            w.phase(e, &[Phase::Committing]).await;
            commit_as_the_relay(&w, e).await;
            reach(&w, e, BatchStatus::Committed).await;
            if relay {
                // The database of a node that decided on a relay abort
                // inside the window and crashed before sending it.
                let path = w.copy_db("cell").await;
                set_aborting(&path, w.market, e, AbortReason::Relay).await;
                path
            } else {
                // The node cannot send the reveal. Once the window is over
                // it decides on beacon_expired.
                let b = w.batch(e).await.unwrap();
                let d = u64::from(w.market_account().await.beacon_delay_slots);
                until_slot(&w, b.commit_slot + d + REVEAL_WINDOW + 2).await;
                let row = w.phase(e, &[Phase::Aborting]).await;
                assert_eq!(row.abort_reason, Some(AbortReason::BeaconExpired as u8));
                w.copy_db("cell").await
            }
        }
        Copy::Aborting => {
            w.enclaves.set_all(Mode::Offline);
            w.to_cutoff().await;
            reach(&w, e, BatchStatus::BeaconRevealed).await;
            block(&w);
            let b = w.batch(e).await.unwrap();
            let m = w.market_account().await;
            until_slot(&w, b.reveal_slot + m.exec_timeout_slots + 2).await;
            w.phase(e, &[Phase::Aborting]).await;
            w.copy_db("cell").await
        }
    };

    // 2. Drive the chain to the cell's status, then crash.
    if case.copy == Copy::Closed && case.chain != ChainState::NoBatch {
        // The halt held the epoch at closed. The commit lands as the node
        // would send it. The node itself stays cut off until the branch
        // below lets it advance the chain further.
        block(&w);
        w.set_halted(false).await;
        commit_as_the_relay(&w, e).await;
        reach(&w, e, BatchStatus::Committed).await;
    }
    match case.chain {
        ChainState::NoBatch => {}
        ChainState::Committed => {
            if case.copy == Copy::Committing {
                commit_as_the_relay(&w, e).await;
            }
            reach(&w, e, BatchStatus::Committed).await;
            if case.copy == (Copy::AbortingCommitted { relay: true }) {
                // Past the relay window, inside the reveal window: the
                // relay abort is no longer legal, the reveal still is.
                let b = w.batch(e).await.unwrap();
                let d = u64::from(w.market_account().await.beacon_delay_slots);
                until_slot(&w, b.commit_slot + d + 1).await;
                assert!(w.svm.current_slot() < b.commit_slot + d + REVEAL_WINDOW);
            }
        }
        ChainState::BeaconRevealed => {
            if case.copy != Copy::Aborting {
                unblock(&w);
                w.enclaves.set_all(Mode::Offline);
                if w.view().halted {
                    w.set_halted(false).await;
                }
                close(&w, e).await;
                reach(&w, e, BatchStatus::BeaconRevealed).await;
            }
        }
        ChainState::ReceiptPosted | ChainState::Verified | ChainState::Settled => {
            if case.copy == Copy::Aborting {
                foreign_post(&w, e).await;
            } else if case.copy != Copy::Posted {
                unblock(&w);
                w.enclaves.set_all(Mode::Normal);
                close(&w, e).await;
                w.phase(e, &[Phase::Executing, Phase::Posted]).await;
                block(&w);
                reach(&w, e, BatchStatus::ReceiptPosted).await;
                let m = w.market_account().await;
                w.status(e, |b| m.quorum_met(b.cosign_bitmap)).await;
            }
            if case.chain >= ChainState::Verified {
                verify(&w, e).await;
            }
            if case.chain == ChainState::Settled {
                settle(&w, e).await;
            }
        }
        ChainState::Aborted => {
            if case.copy == Copy::Aborting || case.copy == Copy::Posted {
                let reason = if case.copy == Copy::Posted {
                    let b = w.batch(e).await.unwrap();
                    let m = w.market_account().await;
                    until_slot(&w, b.receipt_slot + m.settle_timeout_slots + 2).await;
                    AbortReason::SettleTimeout
                } else {
                    AbortReason::ExecTimeout
                };
                let out = w
                    .chain
                    .ensure_aborted(e, reason, w.admin.clone())
                    .await
                    .unwrap();
                assert!(matches!(out, AbortOutcome::Aborted { .. }), "{out:?}");
            } else {
                unblock(&w);
                w.enclaves.set_all(Mode::Offline);
                close(&w, e).await;
                reach(&w, e, BatchStatus::BeaconRevealed).await;
                let b = w.batch(e).await.unwrap();
                let m = w.market_account().await;
                until_slot(&w, b.reveal_slot + m.exec_timeout_slots + 2).await;
            }
            reach(&w, e, BatchStatus::Aborted).await;
        }
        ChainState::NoBatchCommitted => unreachable!("a fence cell"),
    }
    w.crash().await;

    // 3. The database is the copy. The chain is where it is.
    w.restore_db(&copy);
    let restored = {
        let store = Store::open(&w.db_path(), Schema::Node, StoreOptions::default()).unwrap();
        NodeRepo::new(store)
            .epoch(w.market, e)
            .await
            .unwrap()
            .unwrap()
    };
    let observed = match w.batch(e).await {
        Some(b) => b.status.into_state(),
        None => ChainState::NoBatch,
    };
    assert_eq!(observed, case.chain, "the chain is in the cell's column");
    let cell = action(Some(restored.phase), observed);
    assert_ne!(cell, Action::Fence);
    assert_ne!(cell, Action::Ahead);

    // 4. Restart with every fault cleared.
    unblock(&w);
    w.enclaves.set_all(Mode::Normal);
    if w.market_account().await.halted {
        w.set_halted(false).await;
    }
    w.start_node().await.unwrap();
    if restored.phase == Phase::Open {
        w.to_cutoff().await;
    }
    let row = w.phase(e, &[Phase::Settled, Phase::Aborted]).await;
    match case.ends {
        Ends::Settled => {
            assert_eq!(
                row.phase,
                Phase::Settled,
                "{:?} x {:?}: {row:?}",
                case.copy,
                case.chain
            );
            assert_eq!(w.batch(e).await.unwrap().status, BatchStatus::Settled);
            // The fills applied once.
            assert_eq!(w.trader_account(maker.id()).await.base, 10_000 - 5);
            assert_eq!(w.trader_account(taker.id()).await.base, 5);
            let (_, root, confirmed) = w
                .node()
                .store()
                .order_state(w.market, e)
                .await
                .unwrap()
                .unwrap();
            assert!(confirmed);
            if w.market_account().await.last_settled == e {
                assert_eq!(root, w.market_account().await.state_root);
            }
        }
        Ends::Aborted => {
            assert_eq!(
                row.phase,
                Phase::Aborted,
                "{:?} x {:?}: {row:?}",
                case.copy,
                case.chain
            );
            assert_eq!(w.trader_account(maker.id()).await.base, 10_000);
            if let Copy::AbortingCommitted { .. } = case.copy {
                // A relay abort that missed its window becomes a
                // beacon_expired abort. The beacon is never revealed.
                let b = w.batch(e).await.unwrap();
                assert_eq!(b.abort_reason, Some(AbortReason::BeaconExpired));
                assert_eq!(b.reveal_slot, 0);
            }
        }
    }
    // The batch committed is the closed batch the database holds.
    let b = w.batch(e).await.unwrap();
    assert_eq!(Some(b.root), row.root);
    // The market keeps going.
    w.phase(
        e + 1,
        &[
            Phase::Open,
            Phase::Closed,
            Phase::Committing,
            Phase::Committed,
        ],
    )
    .await;
}

trait IntoState {
    fn into_state(self) -> ChainState;
}

impl IntoState for BatchStatus {
    fn into_state(self) -> ChainState {
        match self {
            BatchStatus::Committed => ChainState::Committed,
            BatchStatus::BeaconRevealed => ChainState::BeaconRevealed,
            BatchStatus::ReceiptPosted => ChainState::ReceiptPosted,
            BatchStatus::Verified => ChainState::Verified,
            BatchStatus::Settled => ChainState::Settled,
            BatchStatus::Aborted => ChainState::Aborted,
        }
    }
}

macro_rules! cells {
    ($($name:ident: $copy:expr, $chain:ident, $ends:ident;)*) => {
        $(
            #[tokio::test(start_paused = true)]
            async fn $name() {
                run(Case { copy: $copy, chain: ChainState::$chain, ends: Ends::$ends }).await;
            }
        )*
    };
}

cells! {
    open_no_batch_restores_the_relay: Copy::Open, NoBatch, Settled;
    closed_no_batch_waits_for_the_slot: Copy::Closed, NoBatch, Settled;
    committing_no_batch_resends_the_same_root: Copy::Committing, NoBatch, Settled;
    committing_committed_adopts: Copy::Committing, Committed, Settled;
    committing_revealed_adopts_and_snaps: Copy::Committing, BeaconRevealed, Settled;
    committing_posted_adopts_and_fetches: Copy::Committing, ReceiptPosted, Settled;
    committing_verified_adopts_fetches_and_settles: Copy::Committing, Verified, Settled;
    committing_settled_adopts_and_fetches: Copy::Committing, Settled, Settled;
    committing_aborted_adopts_the_abort: Copy::Committing, Aborted, Aborted;
    snapshotted_committed_snaps: Copy::Snapshotted, Committed, Settled;
    snapshotted_revealed_waits_for_finality: Copy::Snapshotted, BeaconRevealed, Settled;
    snapshotted_posted_fetches: Copy::Snapshotted, ReceiptPosted, Settled;
    snapshotted_verified_fetches_and_settles: Copy::Snapshotted, Verified, Settled;
    snapshotted_settled_fetches: Copy::Snapshotted, Settled, Settled;
    snapshotted_aborted_marks_aborted: Copy::Snapshotted, Aborted, Aborted;
    revealed_revealed_executes: Copy::Rolled(Phase::Revealed), BeaconRevealed, Settled;
    sealed_revealed_executes: Copy::Rolled(Phase::Sealed), BeaconRevealed, Settled;
    sealed_posted_fetches: Copy::Rolled(Phase::Sealed), ReceiptPosted, Settled;
    sealed_verified_fetches_and_settles: Copy::Rolled(Phase::Sealed), Verified, Settled;
    sealed_settled_fetches: Copy::Rolled(Phase::Sealed), Settled, Settled;
    sealed_aborted_marks_aborted: Copy::Rolled(Phase::Sealed), Aborted, Aborted;
    executing_revealed_executes: Copy::Executing, BeaconRevealed, Settled;
    executing_posted_fetches: Copy::Executing, ReceiptPosted, Settled;
    executing_verified_fetches_and_settles: Copy::Executing, Verified, Settled;
    executing_settled_fetches: Copy::Executing, Settled, Settled;
    executing_aborted_marks_aborted: Copy::Executing, Aborted, Aborted;
    posted_posted_settles: Copy::Posted, ReceiptPosted, Settled;
    posted_verified_settles: Copy::Posted, Verified, Settled;
    posted_settled_marks_settled: Copy::Posted, Settled, Settled;
    posted_aborted_marks_aborted: Copy::Posted, Aborted, Aborted;
    closed_committed_adopts: Copy::Closed, Committed, Settled;
    closed_revealed_adopts_and_snaps: Copy::Closed, BeaconRevealed, Settled;
    closed_posted_adopts_and_fetches: Copy::Closed, ReceiptPosted, Settled;
    closed_verified_adopts_fetches_and_settles: Copy::Closed, Verified, Settled;
    closed_settled_adopts_and_fetches: Copy::Closed, Settled, Settled;
    closed_aborted_adopts_the_abort: Copy::Closed, Aborted, Aborted;
    aborting_committed_aborts: Copy::AbortingCommitted { relay: false }, Committed, Aborted;
    aborting_committed_late_relay_abort_waits_for_beacon_expired:
        Copy::AbortingCommitted { relay: true }, Committed, Aborted;
    aborting_revealed_aborts: Copy::Aborting, BeaconRevealed, Aborted;
    aborting_posted_is_superseded_and_fetches: Copy::Aborting, ReceiptPosted, Settled;
    aborting_verified_is_superseded_and_settles: Copy::Aborting, Verified, Settled;
    aborting_settled_is_superseded: Copy::Aborting, Settled, Settled;
    aborting_aborted_marks_aborted: Copy::Aborting, Aborted, Aborted;
}

///  AHEAD: a database older than the chain refuses to start. With
/// `accept_chain_ahead` it adopts what the chain holds, aborts what it
/// cannot run, and continues once `recover-state` rebuilt the carried
/// state from the archive.
#[tokio::test(start_paused = true)]
async fn a_database_behind_the_chain() {
    let Run {
        mut w, e, maker, ..
    } = setup().await;
    let copy = w.copy_db("behind").await;
    w.to_cutoff().await;
    w.phase(e, &[Phase::Settled]).await;
    w.phase(e + 1, &[Phase::Open]).await;
    w.to_cutoff().await;
    reach(&w, e + 1, BatchStatus::Committed).await;
    w.crash().await;
    w.restore_db(&copy);

    let refused = w.start_node().await;
    let err = refused.expect_err("the chain is ahead");
    assert!(err.to_string().contains("--accept-chain-ahead"), "{err}");
    w.crash().await;

    // The operator rebuilds the carried state, then starts with the flag.
    {
        let store = Store::open(&w.db_path(), Schema::Node, StoreOptions::default()).unwrap();
        let repo = NodeRepo::new(store);
        let archive = timescales_node::archive::Archive::new(&w.dir.path().join("data"));
        let m = w.market_account().await;
        let rebuilt =
            timescales_node::app::rebuild_carried_state(&repo, &archive, w.market, &w.params, &m)
                .await
                .unwrap();
        assert_eq!(rebuilt.map(|r| r.0), Some(e));
    }
    let mut cfg = w.cfg.clone();
    cfg.node.accept_chain_ahead = true;
    w.start_node_with(cfg).await.unwrap();
    assert_eq!(w.row(e).await.unwrap().phase, Phase::Settled);
    let adopted = w.phase(e + 1, &[Phase::Aborted]).await;
    assert_eq!(adopted.phase, Phase::Aborted);
    // The market moves on from there. Nothing was executed twice.
    w.phase(e + 2, &[Phase::Open]).await;
    w.to_cutoff().await;
    w.phase(e + 2, &[Phase::Settled]).await;
    assert_eq!(w.trader_account(maker.id()).await.base, 10_000 - 5);
}

///  "keep": terminal epochs (settled and aborted, each also with its
/// batch account reclaimed) and scheduled ones are left as they are. The
/// scheduled epochs' bundles are verified again and the market goes on.
///
/// The program reclaims a batch account only `BATCH_RETENTION` (1024)
/// settled epochs later, so the harness removes the account from the SVM
/// directly to stand for the reclaim.
#[tokio::test(start_paused = true)]
async fn terminal_and_scheduled_epochs_are_kept() {
    let Run {
        mut w, e, maker, ..
    } = setup().await;
    w.to_cutoff().await;
    w.phase(e, &[Phase::Settled]).await;
    // e + 1 aborts: no enclave answers before the execution deadline.
    w.phase(e + 1, &[Phase::Open]).await;
    w.enclaves.set_all(Mode::Offline);
    w.to_cutoff().await;
    reach(&w, e + 1, BatchStatus::BeaconRevealed).await;
    let b = w.batch(e + 1).await.unwrap();
    let m = w.market_account().await;
    until_slot(&w, b.reveal_slot + m.exec_timeout_slots + 2).await;
    w.phase(e + 1, &[Phase::Aborted]).await;
    let scheduled = w.row(e + 3).await.unwrap();
    assert_eq!(scheduled.phase, Phase::Scheduled);
    w.crash().await;

    let pda = timescales_chain::program::batch_pda(&w.program, &w.market, e)
        .unwrap()
        .0;
    w.svm
        .with_svm(|svm| svm.set_account(pda.into(), Default::default()))
        .unwrap();
    // Confirmed reads lag the live state by a slot.
    until_slot(&w, w.svm.current_slot() + 2).await;
    assert!(w.batch(e).await.is_none());
    assert!(w.market_account().await.last_committed > e);
    assert_eq!(
        action(Some(Phase::Settled), ChainState::NoBatchCommitted),
        Action::KeepReclaimed
    );
    assert_eq!(
        action(Some(Phase::Aborted), ChainState::Aborted),
        Action::Keep
    );
    assert_eq!(
        action(Some(Phase::Scheduled), ChainState::NoBatch),
        Action::Keep
    );

    w.enclaves.set_all(Mode::Normal);
    w.start_node().await.unwrap();
    assert_eq!(w.row(e).await.unwrap().phase, Phase::Settled);
    assert_eq!(w.row(e + 1).await.unwrap().phase, Phase::Aborted);
    assert_eq!(w.row(e + 3).await.unwrap(), scheduled);
    w.phase(e + 2, &[Phase::Open]).await;
    w.to_cutoff().await;
    w.phase(e + 2, &[Phase::Settled]).await;
    assert_eq!(w.row(e).await.unwrap().phase, Phase::Settled);
    assert_eq!(w.trader_account(maker.id()).await.base, 10_000 - 5);

    // Aborted with its batch account reclaimed: kept as well.
    w.crash().await;
    let pda = timescales_chain::program::batch_pda(&w.program, &w.market, e + 1)
        .unwrap()
        .0;
    w.svm
        .with_svm(|svm| svm.set_account(pda.into(), Default::default()))
        .unwrap();
    until_slot(&w, w.svm.current_slot() + 2).await;
    assert!(w.batch(e + 1).await.is_none());
    assert_eq!(
        action(Some(Phase::Aborted), ChainState::NoBatchCommitted),
        Action::KeepReclaimed
    );
    w.start_node().await.unwrap();
    assert_eq!(w.row(e + 1).await.unwrap().phase, Phase::Aborted);
    assert_eq!(w.row(e + 2).await.unwrap().phase, Phase::Settled);
    w.phase(e + 3, &[Phase::Open]).await;
    w.to_cutoff().await;
    w.phase(e + 3, &[Phase::Settled]).await;
    assert_eq!(w.row(e + 1).await.unwrap().phase, Phase::Aborted);
    assert_eq!(w.trader_account(maker.id()).await.base, 10_000 - 5);
}
