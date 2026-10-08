//! `SolanaMarketChain` against the real settlement program in LiteSVM: one
//! full epoch with a receipt quorum of two, then the typed outcomes of every
//! operation (table). Commitment levels, slot time and blockhash expiry
//! are emulated by `LiteSvmRpc`. Tokio time is paused, so slots pass as the
//! adapter sleeps.

#![cfg(all(feature = "litesvm", feature = "test-util"))]
#![allow(clippy::unwrap_used)]

use super::common;

use std::sync::Arc;
use std::time::Duration;

use common::svm::{Net, Setup, next_state_root, root, terms};
use timescales_auction::collateral::Balance;
use timescales_chain::program::{
    AbortReason, BatchStatus, GovernanceChange, TimescalesProgramError,
};
use timescales_chain::{
    AbortOutcome, BatchPredicate, ChainError, ChangeOutcome, CommitOutcome, CosignOutcome, Level,
    MarketChain, PostOutcome, RevealOutcome, RpcError, SettleProgress, SettleStage, TxOp,
    TxOutcome,
};
use timescales_core::{BaseAtoms, Hash32, QuoteAtoms, TraderId};
use tokio::sync::mpsc;
use tokio::time::Instant;

fn drain(rx: &mut mpsc::Receiver<SettleProgress>) -> Vec<SettleProgress> {
    let mut out = Vec::new();
    while let Ok(p) = rx.try_recv() {
        out.push(p);
    }
    out
}

async fn commit(n: &Net, epoch: u64, count: u32) -> u64 {
    match n
        .chain
        .ensure_committed(epoch, root(epoch), count, terms(), n.relay.clone())
        .await
        .unwrap()
    {
        CommitOutcome::Committed { slot } => slot,
        other => panic!("commit {epoch}: {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_full_epoch_with_a_quorum_of_two() {
    let n = Net::new(Setup::default()).await;
    let (a, b) = (
        n.trader(1_000, 100_000).await,
        n.trader(1_000, 100_000).await,
    );
    let setup_rows = n.journal.len();
    let s = n.settlement(1, &[(a.id(), 10, -1_002), (b.id(), -10, 1_000)], 2);

    let commit_slot = commit(&n, 1, 2).await;
    assert_eq!(
        n.chain
            .ensure_committed(1, root(1), 2, terms(), n.relay.clone())
            .await,
        Ok(CommitOutcome::Committed { slot: commit_slot }),
        "a committed epoch is done"
    );

    // Every Trader of the market at a slot at or after the commit.
    let snapshot = n.chain.trader_snapshot(commit_slot).await.unwrap();
    assert!(snapshot.slot >= commit_slot);
    let mut owners = vec![a.id(), b.id()];
    owners.sort_unstable();
    assert_eq!(
        snapshot.traders.iter().map(|t| t.owner).collect::<Vec<_>>(),
        owners
    );
    let sheet = snapshot.balance_sheet(1);
    let full = Balance {
        base: BaseAtoms(1_000),
        quote: QuoteAtoms(100_000),
    };
    assert_eq!(sheet.get(&TraderId(a.id())), full);
    assert_eq!(sheet.get(&TraderId(b.id())), full);

    let RevealOutcome::Revealed {
        beacon,
        slot: reveal_slot,
    } = n.reveal(1).await
    else {
        panic!("not revealed")
    };
    let batch = n.batch_account(1).await;
    assert_eq!(batch.status, BatchStatus::BeaconRevealed);
    assert_eq!((batch.beacon, batch.reveal_slot), (beacon, reveal_slot));
    assert!(reveal_slot > commit_slot + 2 * 4);

    // Executor 0 posts from its enclave's fee payer. Executor 1 co-signs,
    // paid by the node's cranker.
    let (header, receipt) = n.post_args(1, 0, &s).await;
    let posted = n
        .chain
        .ensure_posted(1, header, receipt.clone(), n.posters[0].clone())
        .await
        .unwrap();
    let PostOutcome::Posted { slot: receipt_slot } = posted else {
        panic!("{posted:?}")
    };
    assert_eq!(
        n.chain
            .ensure_posted(1, header, receipt, n.posters[0].clone())
            .await,
        Ok(PostOutcome::AlreadyPosted { same_receipt: true })
    );
    let batch = n.batch_account(1).await;
    assert_eq!(
        (batch.status, batch.receipt_slot, batch.cosign_bitmap),
        (BatchStatus::ReceiptPosted, receipt_slot, 0b001)
    );

    let cosig = n.cosignature(1, 1).await;
    let cosigned = n
        .chain
        .ensure_cosigned(1, vec![cosig], n.cranker.clone())
        .await
        .unwrap();
    assert!(
        matches!(cosigned[..], [CosignOutcome::Cosigned { .. }]),
        "{cosigned:?}"
    );
    assert_eq!(
        n.chain
            .ensure_cosigned(1, vec![cosig], n.cranker.clone())
            .await,
        Ok(vec![CosignOutcome::AlreadyCosigned])
    );
    let batch = n
        .chain
        .wait_batch(
            1,
            BatchPredicate::CosignsAtLeast(2),
            Level::Confirmed,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(batch.cosign_bitmap, 0b011);

    let (tx, mut rx) = mpsc::channel(64);
    let closed = n
        .chain
        .ensure_settled(1, Arc::new(s.clone()), n.cranker.clone(), tx)
        .await
        .unwrap();
    let stages: Vec<SettleStage> = drain(&mut rx).into_iter().map(|p| p.stage).collect();
    assert_eq!(
        stages,
        [
            SettleStage::Verifying,
            SettleStage::Finalizing,
            SettleStage::Applying,
            SettleStage::Closing,
            SettleStage::Closing
        ]
    );
    let m = n.market_account().await;
    assert_eq!((m.last_committed, m.last_settled), (1, 1));
    assert_eq!(m.last_progress_slot, closed);
    assert_eq!((m.fees_accrued, m.state_root), (2, next_state_root(1)));
    assert_eq!(m.prev_receipt, n.batch_account(1).await.receipt);
    assert_eq!(n.batch_account(1).await.status, BatchStatus::Settled);

    let (tx, _rx) = mpsc::channel(4);
    assert_eq!(
        n.chain
            .ensure_settled(1, Arc::new(s.clone()), n.cranker.clone(), tx)
            .await,
        Ok(closed),
        "a settled epoch is done, with the same close slot"
    );

    let after = n.chain.trader_snapshot(closed).await.unwrap();
    let sheet = after.balance_sheet(2);
    assert_eq!(
        sheet.get(&TraderId(a.id())),
        Balance {
            base: BaseAtoms(1_010),
            quote: QuoteAtoms(98_998)
        }
    );
    assert_eq!(
        sheet.get(&TraderId(b.id())),
        Balance {
            base: BaseAtoms(990),
            quote: QuoteAtoms(101_000)
        }
    );

    // The previous batch is terminal, so the next epoch commits.
    let commit_slot = commit(&n, 2, 1).await;
    // The market no longer holds epoch 1's close slot: the answer is the
    // slot the settled batch was observed at, after the close.
    let (tx, _rx) = mpsc::channel(4);
    let observed = n
        .chain
        .ensure_settled(1, Arc::new(s), n.cranker.clone(), tx)
        .await
        .unwrap();
    assert!(observed >= commit_slot && commit_slot >= closed);

    // One journal row per transaction, each durable before its send. All
    // landed but possibly the second commit: its compute-unit limit came
    // from the first, and if epoch 2's batch PDA costs more to derive the
    // node's preflight refuses it (never forwarded, so `Expired`) and the
    // sender sizes it again.
    let rows = n.journal.rows();
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.sends_before, i as u64, "row {i}");
        assert_eq!(row.record.market, n.market);
    }
    let refused: Vec<_> = rows
        .iter()
        .filter(|r| !matches!(r.outcome, Some(TxOutcome::Landed { .. })))
        .collect();
    assert!(refused.len() <= 1, "{refused:?}");
    for r in refused {
        assert_eq!(
            (r.record.op, r.record.epoch, &r.outcome),
            (TxOp::Commit, Some(2), &Some(TxOutcome::Expired))
        );
    }
    let landed: Vec<(TxOp, Option<u64>)> = rows[setup_rows..]
        .iter()
        .filter(|r| matches!(r.outcome, Some(TxOutcome::Landed { .. })))
        .map(|r| (r.record.op, r.record.epoch))
        .collect();
    assert_eq!(
        landed,
        [
            (TxOp::Commit, Some(1)),
            (TxOp::Reveal, Some(1)),
            (TxOp::Post, Some(1)),
            (TxOp::Cosign, Some(1)),
            (TxOp::Verify, Some(1)),
            (TxOp::Finalize, Some(1)),
            (TxOp::Apply, Some(1)),
            (TxOp::Close, Some(1)),
            (TxOp::Commit, Some(2))
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn settlement_sends_only_the_leaves_its_bitmaps_miss() {
    let n = Net::new(Setup {
        quorum: 1,
        ..Setup::default()
    })
    .await;
    // Twelve traders: three verify transactions of four leaves each.
    let mut traders = Vec::new();
    for _ in 0..12 {
        traders.push(n.trader(1_000, 100_000).await);
    }
    let deltas: Vec<_> = traders
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let sign = if i % 2 == 0 { 1 } else { -1 };
            (t.id(), sign * 3, -sign * 300)
        })
        .collect();
    let s = n.settlement(1, &deltas, 0);
    commit(&n, 1, 12).await;
    n.reveal(1).await;
    let (header, receipt) = n.post_args(1, 0, &s).await;
    n.chain
        .ensure_posted(1, header, receipt, n.posters[0].clone())
        .await
        .unwrap();

    // Someone else already verified the first four leaves.
    let leaves = timescales_chain::program::leaves(&s).unwrap();
    let ix = timescales_chain::program::verify_deltas(
        &n.program,
        &n.cranker.address(),
        &n.market,
        1,
        &leaves[..4],
    )
    .unwrap();
    n.send(vec![ix], &n.cranker.clone()).await;
    n.wait_slots(1).await;
    assert_eq!(
        n.batch_account(1).await.missing_verified(),
        (4..12).collect::<Vec<_>>()
    );

    let rows = n.journal.len();
    let (tx, mut rx) = mpsc::channel(64);
    n.chain
        .ensure_settled(1, Arc::new(s), n.cranker.clone(), tx)
        .await
        .unwrap();
    let progress = drain(&mut rx);
    assert_eq!(
        progress[0],
        SettleProgress {
            stage: SettleStage::Verifying,
            done: 4,
            total: 12
        }
    );
    let count = |op| n.journal.ops_since(rows, op).len();
    assert_eq!(
        count(TxOp::Verify),
        2,
        "eight missing leaves, four per chunk"
    );
    assert_eq!(count(TxOp::Apply), 3);
    assert_eq!((count(TxOp::Finalize), count(TxOp::Close)), (1, 1));
    assert_eq!(n.batch_account(1).await.status, BatchStatus::Settled);
}

#[tokio::test(start_paused = true)]
async fn commit_outcomes() {
    let n = Net::new(Setup::default()).await;
    assert_eq!(
        n.chain
            .ensure_committed(2, root(2), 1, terms(), n.relay.clone())
            .await,
        Ok(CommitOutcome::OutOfOrder {
            last_committed: 0,
            last_settled: 0
        })
    );
    commit(&n, 1, 1).await;
    assert_eq!(
        n.chain
            .ensure_committed(1, root(9), 1, terms(), n.relay.clone())
            .await,
        Ok(CommitOutcome::Equivocation {
            onchain_root: root(1)
        })
    );
    assert_eq!(
        n.chain
            .ensure_committed(1, root(1), 1, Hash32([3; 32]), n.relay.clone())
            .await,
        Ok(CommitOutcome::Equivocation {
            onchain_root: root(1)
        }),
        "other terms under the same root are equivocation too"
    );
    assert_eq!(
        n.chain
            .ensure_committed(2, root(2), 1, terms(), n.relay.clone())
            .await,
        Ok(CommitOutcome::InFlight {
            last_committed: 1,
            last_settled: 0
        })
    );

    // Epoch 1 ends. A due between-batches change blocks epoch 2.
    assert_eq!(
        n.chain
            .ensure_aborted(1, AbortReason::Relay, n.relay.clone())
            .await,
        Ok(AbortOutcome::Aborted {
            reason: AbortReason::Relay
        })
    );
    n.propose(&GovernanceChange::SetCommitteeDigest(Hash32([0xc1; 32])))
        .await;
    assert!(matches!(
        n.chain.ensure_change_applied(n.cranker.clone()).await,
        Ok(ChangeOutcome::NotYet { .. })
    ));
    n.wait_slots(n.setup.timelock + 2).await;
    assert_eq!(
        n.chain
            .ensure_committed(2, root(2), 1, terms(), n.relay.clone())
            .await,
        Ok(CommitOutcome::ChangeDue { kind: 3 })
    );
    assert_eq!(
        n.chain.ensure_change_applied(n.cranker.clone()).await,
        Ok(ChangeOutcome::Applied { kind: 3 })
    );
    assert_eq!(
        n.chain.ensure_change_applied(n.cranker.clone()).await,
        Ok(ChangeOutcome::NothingDue)
    );
    assert_eq!(
        n.market_account().await.committee_digest,
        Hash32([0xc1; 32])
    );

    n.set_halted(true).await;
    n.wait_slots(1).await;
    assert_eq!(
        n.chain
            .ensure_committed(2, root(2), 1, terms(), n.relay.clone())
            .await,
        Ok(CommitOutcome::Halted)
    );
    n.set_halted(false).await;
    n.wait_slots(1).await;
    commit(&n, 2, 1).await;

    // Only the relay may commit. The program's refusal is attributed.
    n.chain
        .ensure_aborted(2, AbortReason::Relay, n.relay.clone())
        .await
        .unwrap();
    assert_eq!(
        n.chain
            .ensure_committed(3, root(3), 1, terms(), n.cranker.clone())
            .await,
        Err(ChainError::Program {
            ix: 2,
            program: timescales_chain::program::errors::ProgramKind::Settlement,
            code: TimescalesProgramError::Unauthorised.code(),
            name: "Unauthorised"
        })
    );
}

#[tokio::test(start_paused = true)]
async fn a_change_waits_for_the_batch_in_flight() {
    let n = Net::new(Setup::default()).await;
    commit(&n, 1, 1).await;
    n.propose(&GovernanceChange::SetRelay(n.cranker.address()))
        .await;
    n.wait_slots(n.setup.timelock + 2).await;
    assert_eq!(
        n.chain.ensure_change_applied(n.cranker.clone()).await,
        Ok(ChangeOutcome::InFlight)
    );
    n.chain
        .ensure_aborted(1, AbortReason::Admin, n.admin.clone())
        .await
        .unwrap();
    assert_eq!(
        n.chain.ensure_change_applied(n.cranker.clone()).await,
        Ok(ChangeOutcome::Applied { kind: 1 })
    );
    assert_eq!(n.market_account().await.relay, n.cranker.address());
}

#[tokio::test(start_paused = true)]
async fn reveal_outcomes() {
    let n = Net::new(Setup::default()).await;
    let commit_slot = commit(&n, 1, 1).await;
    let RevealOutcome::NotReady { slots_left } =
        n.chain.ensure_revealed(1, n.cranker.clone()).await.unwrap()
    else {
        panic!("revealed right after the commit")
    };
    assert!(slots_left <= 2 * 4 + 1, "{slots_left}");
    assert!(matches!(n.reveal(1).await, RevealOutcome::Revealed { .. }));
    let revealed = n.batch_account(1).await;
    assert_eq!(
        n.chain.ensure_revealed(1, n.cranker.clone()).await,
        Ok(RevealOutcome::Revealed {
            beacon: revealed.beacon,
            slot: revealed.reveal_slot
        })
    );
    assert!(revealed.beacon_slot_a >= commit_slot + 4);
    assert!(revealed.beacon_slot_b >= commit_slot + 8);

    // Epoch 2 is never revealed in time.
    n.chain
        .ensure_aborted(1, AbortReason::Admin, n.admin.clone())
        .await
        .unwrap();
    let commit_slot = commit(&n, 2, 1).await;
    n.until_slot(commit_slot + 4 + 400 + 2).await;
    assert_eq!(
        n.chain.ensure_revealed(2, n.cranker.clone()).await,
        Ok(RevealOutcome::Expired)
    );
    assert_eq!(
        n.chain
            .ensure_aborted(2, AbortReason::BeaconExpired, n.cranker.clone())
            .await,
        Ok(AbortOutcome::Aborted {
            reason: AbortReason::BeaconExpired
        })
    );
    assert_eq!(
        n.chain.ensure_revealed(2, n.cranker.clone()).await,
        Ok(RevealOutcome::Terminal(BatchStatus::Aborted))
    );
}

#[tokio::test(start_paused = true)]
async fn post_and_cosign_outcomes() {
    let n = Net::new(Setup::default()).await;
    let (a, b) = (n.trader(100, 10_000).await, n.trader(100, 10_000).await);
    let s = n.settlement(1, &[(a.id(), 1, -100), (b.id(), -1, 100)], 0);
    commit(&n, 1, 2).await;

    // Nothing to post or co-sign before the reveal.
    let early = n.receipt(&n.executors[0], &[0; 283], &s);
    assert_eq!(
        n.chain
            .ensure_posted(1, [0; 283], early, n.posters[0].clone())
            .await,
        Ok(PostOutcome::WrongStatus(BatchStatus::Committed))
    );
    n.reveal(1).await;
    let (address, signature) = (n.executors[1].public(), [7; 64]);
    assert_eq!(
        n.chain
            .ensure_cosigned(1, vec![(address, signature)], n.cranker.clone())
            .await,
        Ok(vec![CosignOutcome::WrongStatus(
            BatchStatus::BeaconRevealed
        )])
    );

    // A receipt from a key that is not registered is the program's to
    // refuse.
    let stranger = timescales_core::crypto::Keypair::from_seed([0x77; 32]);
    let (header, _) = n.post_args(1, 0, &s).await;
    let foreign = n.receipt(&stranger, &header, &s);
    assert_eq!(
        n.chain
            .ensure_posted(1, header, foreign, n.posters[0].clone())
            .await,
        Ok(PostOutcome::Rejected(
            TimescalesProgramError::UnknownExecutor
        ))
    );

    let (header, receipt) = n.post_args(1, 0, &s).await;
    assert!(matches!(
        n.chain
            .ensure_posted(1, header, receipt, n.posters[0].clone())
            .await,
        Ok(PostOutcome::Posted { .. })
    ));
    // Executor 2's receipt arrives second.
    let (header, other) = n.post_args(1, 2, &s).await;
    assert_eq!(
        n.chain
            .ensure_posted(1, header, other, n.posters[2].clone())
            .await,
        Ok(PostOutcome::AlreadyPosted {
            same_receipt: false
        })
    );

    // A signature over anything but the posted outcome cannot co-sign it.
    let wrong = n.executors[1].sign_digest(&Hash32([0x99; 32])).0;
    assert_eq!(
        n.chain
            .ensure_cosigned(1, vec![(address, wrong)], n.cranker.clone())
            .await,
        Ok(vec![CosignOutcome::OutcomeMismatch])
    );
    let (poster, poster_sig) = n.cosignature(1, 0).await;
    let (second, second_sig) = n.cosignature(1, 1).await;
    let outcomes = n
        .chain
        .ensure_cosigned(
            1,
            vec![(poster, poster_sig), (second, second_sig)],
            n.cranker.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        outcomes[0],
        CosignOutcome::AlreadyCosigned,
        "the poster's bit"
    );
    assert!(matches!(outcomes[1], CosignOutcome::Cosigned { .. }));
}

#[tokio::test(start_paused = true)]
async fn abort_outcomes_and_superseded_reasons() {
    let n = Net::new(Setup::default()).await;
    let (a, b) = (n.trader(100, 10_000).await, n.trader(100, 10_000).await);

    // The relay may abort only before the first beacon input exists.
    let commit_slot = commit(&n, 1, 2).await;
    n.until_slot(commit_slot + 4 + 2).await;
    assert_eq!(
        n.chain
            .ensure_aborted(1, AbortReason::Relay, n.relay.clone())
            .await,
        Ok(AbortOutcome::Superseded(BatchStatus::Committed))
    );
    let RevealOutcome::Revealed {
        slot: reveal_slot, ..
    } = n.reveal(1).await
    else {
        panic!("not revealed")
    };
    assert_eq!(
        n.chain
            .ensure_aborted(1, AbortReason::Relay, n.relay.clone())
            .await,
        Ok(AbortOutcome::Superseded(BatchStatus::BeaconRevealed))
    );
    assert_eq!(
        n.chain
            .ensure_aborted(1, AbortReason::BeaconExpired, n.cranker.clone())
            .await,
        Ok(AbortOutcome::Superseded(BatchStatus::BeaconRevealed))
    );
    match n
        .chain
        .ensure_aborted(1, AbortReason::ExecTimeout, n.cranker.clone())
        .await
        .unwrap()
    {
        AbortOutcome::NotAllowedYet { slots_left } => {
            let now = n.chain.slot(Level::Confirmed).await.unwrap();
            assert_eq!(now + slots_left, reveal_slot + n.setup.exec_timeout + 1);
        }
        other => panic!("{other:?}"),
    }

    // The receipt lands first: an exec timeout no longer applies.
    let s = n.settlement(1, &[(a.id(), 1, -100), (b.id(), -1, 100)], 0);
    let (header, receipt) = n.post_args(1, 0, &s).await;
    n.chain
        .ensure_posted(1, header, receipt, n.posters[0].clone())
        .await
        .unwrap();
    n.until_slot(reveal_slot + n.setup.exec_timeout + 2).await;
    assert_eq!(
        n.chain
            .ensure_aborted(1, AbortReason::ExecTimeout, n.cranker.clone())
            .await,
        Ok(AbortOutcome::Superseded(BatchStatus::ReceiptPosted))
    );
    // With the quorum met a quorum timeout no longer applies either.
    let cosig = n.cosignature(1, 1).await;
    n.chain
        .ensure_cosigned(1, vec![cosig], n.cranker.clone())
        .await
        .unwrap();
    assert_eq!(
        n.chain
            .ensure_aborted(1, AbortReason::QuorumTimeout, n.cranker.clone())
            .await,
        Ok(AbortOutcome::Superseded(BatchStatus::ReceiptPosted))
    );

    // Once a delta is applied nothing aborts the batch.
    let leaves = timescales_chain::program::leaves(&s).unwrap();
    let cranker = n.cranker.address();
    let verify =
        timescales_chain::program::verify_deltas(&n.program, &cranker, &n.market, 1, &leaves)
            .unwrap();
    let batch = n.batch_key(1);
    let finalize = timescales_chain::program::finalize(&n.program, &cranker, &n.market, &batch);
    let apply =
        timescales_chain::program::apply_deltas(&n.program, &cranker, &n.market, 1, &leaves[..1])
            .unwrap();
    n.send(vec![verify, finalize], &n.cranker.clone()).await;
    n.wait_slots(1).await;
    n.send(vec![apply], &n.cranker.clone()).await;
    n.wait_slots(1).await;
    assert_eq!(
        n.chain
            .ensure_aborted(1, AbortReason::Admin, n.admin.clone())
            .await,
        Ok(AbortOutcome::Superseded(BatchStatus::Verified))
    );
    let (tx, _rx) = mpsc::channel(8);
    n.chain
        .ensure_settled(1, Arc::new(s), n.cranker.clone(), tx)
        .await
        .unwrap();
    assert_eq!(
        n.chain
            .ensure_aborted(1, AbortReason::Admin, n.admin.clone())
            .await,
        Ok(AbortOutcome::AlreadyTerminal(BatchStatus::Settled))
    );

    // An exec timeout that applies, once its deadline passed. Then done.
    commit(&n, 2, 1).await;
    let RevealOutcome::Revealed {
        slot: reveal_slot, ..
    } = n.reveal(2).await
    else {
        panic!("not revealed")
    };
    n.until_slot(reveal_slot + n.setup.exec_timeout + 2).await;
    for _ in 0..2 {
        assert_eq!(
            n.chain
                .ensure_aborted(2, AbortReason::ExecTimeout, n.cranker.clone())
                .await,
            Ok(AbortOutcome::Aborted {
                reason: AbortReason::ExecTimeout
            })
        );
    }
    let (tx, _rx) = mpsc::channel(8);
    assert_eq!(
        n.chain
            .ensure_settled(2, Arc::new(n.settlement(2, &[], 0)), n.cranker.clone(), tx)
            .await,
        Err(ChainError::Inconsistent("batch was aborted"))
    );
}

#[tokio::test(start_paused = true)]
async fn wait_batch_polls_until_the_predicate_or_the_deadline() {
    let n = Net::new(Setup::default()).await;
    assert_eq!(
        n.chain
            .wait_batch(
                1,
                BatchPredicate::Exists,
                Level::Confirmed,
                Instant::now() + Duration::from_secs(2)
            )
            .await,
        Err(ChainError::Rpc(RpcError::Timeout))
    );
    commit(&n, 1, 1).await;
    let waiter = n.chain.wait_batch(
        1,
        BatchPredicate::AtLeast(BatchStatus::BeaconRevealed),
        Level::Finalized,
        Instant::now() + Duration::from_secs(60),
    );
    let (waited, revealed) = tokio::join!(waiter, n.reveal(1));
    let waited = waited.unwrap();
    let RevealOutcome::Revealed { slot, .. } = revealed else {
        panic!("not revealed")
    };
    assert_eq!(waited.reveal_slot, slot);
    // Seen at Finalized: the finalized view is 32 slots behind the reveal.
    assert!(n.svm.current_slot() >= slot + 32);
    let terminal = n.chain.wait_batch(
        1,
        BatchPredicate::Terminal,
        Level::Confirmed,
        Instant::now() + Duration::from_secs(10),
    );
    let abort = n
        .chain
        .ensure_aborted(1, AbortReason::Admin, n.admin.clone());
    let (terminal, aborted) = tokio::join!(terminal, abort);
    assert_eq!(terminal.unwrap().status, BatchStatus::Aborted);
    assert!(aborted.is_ok());
}

#[tokio::test(start_paused = true)]
async fn reclaim_after_the_retention() {
    let n = Net::new(Setup::default()).await;
    commit(&n, 1, 1).await;
    n.chain
        .ensure_aborted(1, AbortReason::Relay, n.relay.clone())
        .await
        .unwrap();
    assert_eq!(
        n.chain.ensure_reclaimed(1, n.cranker.clone()).await,
        Err(ChainError::Inconsistent("batch retention not reached"))
    );
    // 1024 more epochs, written straight into the market account: a
    // thousand real epochs would test nothing more here.
    let mut market = n.account(&n.market).unwrap();
    market.data[662..670].copy_from_slice(&1_025u64.to_le_bytes());
    market.data[670..678].copy_from_slice(&1_025u64.to_le_bytes());
    n.set_account(&n.market, market);
    n.wait_slots(2).await;

    let relay_before = n.account(&n.relay.address()).unwrap().lamports;
    let rent = n.account(&n.batch_key(1)).unwrap().lamports;
    assert_eq!(n.chain.ensure_reclaimed(1, n.cranker.clone()).await, Ok(()));
    assert_eq!(n.account(&n.batch_key(1)), None);
    assert_eq!(
        n.account(&n.relay.address()).unwrap().lamports,
        relay_before + rent
    );
    assert_eq!(n.chain.ensure_reclaimed(1, n.cranker.clone()).await, Ok(()));
    assert_eq!(n.chain.batch(1, Level::Confirmed).await, Ok(None));
}

#[tokio::test(start_paused = true)]
async fn the_snapshot_reserves_requested_withdrawals() {
    let n = Net::new(Setup::default()).await;
    let a = n.trader(500, 7_000).await;
    let b = n.trader(0, 0).await;
    // A requests while no batch is committed: the request epoch is 0, so
    // every later batch sees it reserved.
    let request =
        timescales_chain::program::request_withdraw(&n.program, &a.id(), &n.market, 200, 1_000)
            .unwrap();
    n.send(vec![request], &a.signer).await;
    let commit_slot = commit(&n, 1, 1).await;
    let snapshot = n.chain.trader_snapshot(commit_slot).await.unwrap();
    let sheet = snapshot.balance_sheet(1);
    assert_eq!(
        sheet.get(&TraderId(a.id())),
        Balance {
            base: BaseAtoms(300),
            quote: QuoteAtoms(6_000)
        }
    );
    // B is listed, with nothing available.
    assert_eq!(
        sheet
            .iter()
            .find(|(t, _)| **t == TraderId(b.id()))
            .map(|(_, v)| *v),
        Some(Balance::default())
    );
    let entry = snapshot.traders.iter().find(|t| t.owner == a.id()).unwrap();
    assert_eq!(
        (
            entry.requested_base,
            entry.requested_quote,
            entry.request_epoch
        ),
        (200, 1_000, 0)
    );
}
