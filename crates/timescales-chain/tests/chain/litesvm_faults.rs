//! `SolanaMarketChain` under faults, against the real program in LiteSVM:
//! every operation with its `sendTransaction` response lost after the
//! transaction reached the cluster, blockhash expiry, provider failover,
//! providers that are behind or disagree, and account decode checks.

#![cfg(all(feature = "litesvm", feature = "test-util"))]
#![allow(clippy::unwrap_used)]

use super::common;

use std::sync::Arc;
use std::time::Duration;

use common::svm::{Net, Setup, root, terms};
use solana_account::Account;
use solana_address::Address as SolAddress;
use timescales_chain::program::{
    AbortReason, BatchStatus, ClientError, GovernanceChange, TRADER_LEN,
};
use timescales_chain::{
    AbortOutcome, ChainError, ChangeOutcome, CommitOutcome, CosignOutcome, FaultyRpc, Level,
    LiteSvmRpc, MarketChain, PostOutcome, QuorumRpc, RevealOutcome, RpcError, RpcMethod,
    SolanaMarketChain, SolanaRpc, TxError, TxOp, TxOutcome, TxSender,
};
use tokio::sync::mpsc;

/// What happens to the response of a send that reached the cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// The response is lost. Signature statuses still answer, so the sender
    /// finds the transaction by polling.
    Dropped,
    /// The response is lost and nothing about the transaction can be read
    /// before the confirmation deadline: the sender reports the outcome
    /// unknown and the adapter has to observe the chain to learn it.
    Lost,
}

const FAULTS: [Fault; 2] = [Fault::Dropped, Fault::Lost];

fn setup() -> Setup {
    Setup {
        confirm_timeout: Duration::from_secs(4),
        ..Setup::default()
    }
}

/// Loses the responses of the next `sends` sends as `fault` says.
fn inject(n: &Net, fault: Fault, sends: usize) {
    n.faulty.drop_response_after_send(sends, RpcError::Timeout);
    if fault == Fault::Lost {
        n.faulty
            .fail_next(RpcMethod::BlockHeight, 1_000_000, RpcError::Timeout);
    }
}

/// Heals the provider and checks that each of `ops` went out exactly once
/// since journal row `mark`, and landed: an ambiguous send is never
/// repeated while its transaction may still land. After a lost outcome the
/// rows stay open until `resolve_pending` reads them.
async fn check_sent_once(n: &Net, fault: Fault, mark: usize, ops: &[TxOp]) {
    n.faulty.clear();
    let rows = n.journal.rows()[mark..].to_vec();
    assert_eq!(
        rows.iter().map(|r| r.record.op).collect::<Vec<_>>(),
        ops,
        "{fault:?}: {rows:?}"
    );
    if fault == Fault::Lost {
        assert!(rows.iter().all(|r| r.outcome.is_none()), "{rows:?}");
        let resolved = n.sender.resolve_pending().await.unwrap();
        assert_eq!(resolved.len(), ops.len());
        assert!(
            resolved
                .iter()
                .all(|(_, o)| matches!(o, TxOutcome::Landed { .. }))
        );
    }
    for row in &n.journal.rows()[mark..] {
        assert!(
            matches!(row.outcome, Some(TxOutcome::Landed { .. })),
            "{fault:?}: {row:?}"
        );
    }
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

/// Commits epoch 1 for two traders and returns its settlement.
async fn committed(n: &Net) -> (u64, timescales_auction::settlement::SettlementBatch) {
    let (a, b) = (n.trader(100, 10_000).await, n.trader(100, 10_000).await);
    let s = n.settlement(1, &[(a.id(), 1, -101), (b.id(), -1, 100)], 1);
    (commit(n, 1, 2).await, s)
}

async fn posted(n: &Net) -> timescales_auction::settlement::SettlementBatch {
    let (_, s) = committed(n).await;
    n.reveal(1).await;
    let (header, receipt) = n.post_args(1, 0, &s).await;
    n.chain
        .ensure_posted(1, header, receipt, n.posters[0].clone())
        .await
        .unwrap();
    s
}

#[tokio::test(start_paused = true)]
async fn ambiguous_commit() {
    for fault in FAULTS {
        let n = Net::new(setup()).await;
        let mark = n.journal.len();
        inject(&n, fault, 1);
        let out = n
            .chain
            .ensure_committed(1, root(1), 1, terms(), n.relay.clone())
            .await
            .unwrap();
        assert!(matches!(out, CommitOutcome::Committed { .. }), "{out:?}");
        check_sent_once(&n, fault, mark, &[TxOp::Commit]).await;
    }
}

#[tokio::test(start_paused = true)]
async fn ambiguous_reveal() {
    for fault in FAULTS {
        let n = Net::new(setup()).await;
        let commit_slot = commit(&n, 1, 1).await;
        n.until_slot(commit_slot + 2 * 4 + 3).await;
        let mark = n.journal.len();
        inject(&n, fault, 1);
        let out = n.chain.ensure_revealed(1, n.cranker.clone()).await.unwrap();
        assert!(matches!(out, RevealOutcome::Revealed { .. }), "{out:?}");
        check_sent_once(&n, fault, mark, &[TxOp::Reveal]).await;
    }
}

#[tokio::test(start_paused = true)]
async fn ambiguous_post() {
    for fault in FAULTS {
        let n = Net::new(setup()).await;
        let (_, s) = committed(&n).await;
        n.reveal(1).await;
        let (header, receipt) = n.post_args(1, 0, &s).await;
        let mark = n.journal.len();
        inject(&n, fault, 1);
        let out = n
            .chain
            .ensure_posted(1, header, receipt, n.posters[0].clone())
            .await
            .unwrap();
        // This call sent the receipt, whether or not it saw the response.
        let receipt_slot = n.batch_account(1).await.receipt_slot;
        assert_eq!(out, PostOutcome::Posted { slot: receipt_slot });
        check_sent_once(&n, fault, mark, &[TxOp::Post]).await;
    }
}

#[tokio::test(start_paused = true)]
async fn ambiguous_cosign() {
    for fault in FAULTS {
        let n = Net::new(setup()).await;
        posted(&n).await;
        let cosig = n.cosignature(1, 1).await;
        let mark = n.journal.len();
        inject(&n, fault, 1);
        let out = n
            .chain
            .ensure_cosigned(1, vec![cosig], n.cranker.clone())
            .await
            .unwrap();
        // The batch records the bit, not the slot of each co-signature: an
        // outcome learnt by observing is `AlreadyCosigned`.
        match fault {
            Fault::Dropped => assert!(matches!(out[..], [CosignOutcome::Cosigned { .. }])),
            Fault::Lost => assert_eq!(out, [CosignOutcome::AlreadyCosigned]),
        }
        assert_eq!(n.batch_account(1).await.cosign_bitmap, 0b011);
        check_sent_once(&n, fault, mark, &[TxOp::Cosign]).await;
    }
}

#[tokio::test(start_paused = true)]
async fn ambiguous_settlement_steps() {
    for fault in FAULTS {
        let n = Net::new(setup()).await;
        let s = posted(&n).await;
        let cosig = n.cosignature(1, 1).await;
        n.chain
            .ensure_cosigned(1, vec![cosig], n.cranker.clone())
            .await
            .unwrap();
        let mark = n.journal.len();
        // Verify, finalize, apply and close: every response lost.
        inject(&n, fault, 4);
        let (tx, _rx) = mpsc::channel(16);
        let closed = n
            .chain
            .ensure_settled(1, Arc::new(s), n.cranker.clone(), tx)
            .await
            .unwrap();
        assert_eq!(n.market_account().await.last_progress_slot, closed);
        assert_eq!(n.batch_account(1).await.status, BatchStatus::Settled);
        check_sent_once(
            &n,
            fault,
            mark,
            &[TxOp::Verify, TxOp::Finalize, TxOp::Apply, TxOp::Close],
        )
        .await;
    }
}

#[tokio::test(start_paused = true)]
async fn ambiguous_abort() {
    for fault in FAULTS {
        let n = Net::new(setup()).await;
        commit(&n, 1, 1).await;
        let mark = n.journal.len();
        inject(&n, fault, 1);
        assert_eq!(
            n.chain
                .ensure_aborted(1, AbortReason::Relay, n.relay.clone())
                .await,
            Ok(AbortOutcome::Aborted {
                reason: AbortReason::Relay
            })
        );
        check_sent_once(&n, fault, mark, &[TxOp::Abort]).await;
    }
}

#[tokio::test(start_paused = true)]
async fn ambiguous_apply_change() {
    for fault in FAULTS {
        let n = Net::new(setup()).await;
        n.propose(&GovernanceChange::SetTimelock(40)).await;
        n.wait_slots(n.setup.timelock + 2).await;
        let mark = n.journal.len();
        inject(&n, fault, 1);
        assert_eq!(
            n.chain.ensure_change_applied(n.cranker.clone()).await,
            Ok(ChangeOutcome::Applied { kind: 6 })
        );
        assert_eq!(n.market_account().await.timelock_slots, 40);
        check_sent_once(&n, fault, mark, &[TxOp::ApplyChange]).await;
    }
}

#[tokio::test(start_paused = true)]
async fn ambiguous_reclaim() {
    for fault in FAULTS {
        let n = Net::new(setup()).await;
        commit(&n, 1, 1).await;
        n.chain
            .ensure_aborted(1, AbortReason::Relay, n.relay.clone())
            .await
            .unwrap();
        let mut market = n.account(&n.market).unwrap();
        market.data[662..670].copy_from_slice(&1_025u64.to_le_bytes());
        market.data[670..678].copy_from_slice(&1_025u64.to_le_bytes());
        n.set_account(&n.market, market);
        n.wait_slots(2).await;
        let mark = n.journal.len();
        inject(&n, fault, 1);
        assert_eq!(n.chain.ensure_reclaimed(1, n.cranker.clone()).await, Ok(()));
        assert_eq!(n.account(&n.batch_key(1)), None);
        check_sent_once(&n, fault, mark, &[TxOp::Reclaim]).await;
    }
}

#[tokio::test(start_paused = true)]
async fn an_expired_send_is_replaced_after_observing() {
    // The confirmation deadline (30 s) is past the blockhash validity (40
    // slots of 400 ms), so the sender sees the expiry.
    let n = Net::new(Setup::default()).await;
    let mark = n.journal.len();
    // The send is swallowed before any leader sees it: only expiry can
    // tell, after `lastValidBlockHeight`.
    n.faulty.black_hole_sends(1);
    let out = n
        .chain
        .ensure_committed(1, root(1), 1, terms(), n.relay.clone())
        .await
        .unwrap();
    assert!(matches!(out, CommitOutcome::Committed { .. }));
    let rows = n.journal.ops_since(mark, TxOp::Commit);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].outcome, Some(TxOutcome::Expired));
    assert!(matches!(rows[1].outcome, Some(TxOutcome::Landed { .. })));
    // The replacement was signed over a later blockhash.
    assert!(rows[1].record.last_valid_block_height > rows[0].record.last_valid_block_height);
    assert_ne!(rows[0].record.signature, rows[1].record.signature);

    // The sender alone reports the expiry.
    n.faulty.black_hole_sends(1);
    let transfer =
        timescales_chain::program::system::transfer(&n.cranker.address(), &[5; 32], 1_000_000);
    let err = n
        .sender
        .send(TxOp::Admin, vec![transfer], n.cranker.clone(), vec![])
        .await
        .unwrap_err();
    assert!(matches!(err, TxError::Expired { .. }), "{err:?}");
    assert_eq!(
        n.journal.rows().last().unwrap().outcome,
        Some(TxOutcome::Expired)
    );
}

#[tokio::test(start_paused = true)]
async fn endpoint_failures_count_attempts_and_give_up() {
    let n = Net::new(setup()).await;
    n.faulty
        .fail_next(RpcMethod::GetMultipleAccounts, 1_000, RpcError::Http(503));
    let sends = n.sends();
    let reads = n.faulty.calls(RpcMethod::GetMultipleAccounts);
    let started = tokio::time::Instant::now();
    assert_eq!(
        n.chain
            .ensure_committed(1, root(1), 1, terms(), n.relay.clone())
            .await,
        Err(ChainError::Tx(TxError::GaveUp {
            attempts: n.setup.chain.max_attempts,
            last: "HTTP status 503".into()
        }))
    );
    assert_eq!(n.sends(), sends, "nothing is sent without an observation");
    assert_eq!(
        n.faulty.calls(RpcMethod::GetMultipleAccounts) - reads,
        u64::from(n.setup.chain.max_attempts),
        "one read per attempt"
    );
    // Eleven backoffs, each at most 8 s.
    assert!(started.elapsed() <= Duration::from_secs(8 * 11));
}

/// Two providers over one cluster.
fn pair(n: &Net) -> [Arc<FaultyRpc<LiteSvmRpc>>; 2] {
    [
        Arc::new(FaultyRpc::new(n.svm.clone())),
        Arc::new(FaultyRpc::new(n.svm.clone())),
    ]
}

fn chain_over(n: &Net, rpc: Arc<dyn SolanaRpc>) -> SolanaMarketChain {
    let sender = Arc::new(TxSender::new(
        rpc.clone(),
        n.setup.fees,
        n.journal.clone(),
        common::svm::SLOT_TIME,
        n.setup.confirm_timeout,
    ));
    SolanaMarketChain::new(rpc, sender, n.program, n.market, n.setup.chain)
}

#[tokio::test(start_paused = true)]
async fn writes_fail_over_to_the_next_provider() {
    let n = Net::new(setup()).await;
    let [a, b] = pair(&n);
    let quorum = QuorumRpc::new(vec![a.clone(), b.clone()], 1).unwrap();
    let chain = chain_over(&n, Arc::new(quorum));
    a.fail_next(
        RpcMethod::SendTransaction,
        3,
        RpcError::Transport("connection reset".into()),
    );
    assert!(matches!(
        chain
            .ensure_committed(1, root(1), 1, terms(), n.relay.clone())
            .await,
        Ok(CommitOutcome::Committed { .. })
    ));
    // The first provider answered the blockhash and the simulation, then
    // failed the send at the transport level.
    assert_eq!(a.calls(RpcMethod::LatestBlockhash), 1);
    assert_eq!(b.calls(RpcMethod::LatestBlockhash), 0);
    assert_eq!(a.calls(RpcMethod::SendTransaction), 1);
    assert_eq!(b.calls(RpcMethod::SendTransaction), 1);
    // The provider that answered keeps the writes.
    a.clear();
    loop {
        match chain.ensure_revealed(1, n.cranker.clone()).await.unwrap() {
            RevealOutcome::NotReady { slots_left } => n.wait_slots(slots_left).await,
            out => {
                assert!(matches!(out, RevealOutcome::Revealed { .. }));
                break;
            }
        }
    }
    assert_eq!(a.calls(RpcMethod::SendTransaction), 1);
    assert_eq!(b.calls(RpcMethod::SendTransaction), 2);
}

#[tokio::test(start_paused = true)]
async fn a_provider_behind_cannot_serve_older_state() {
    let n = Net::new(setup()).await;
    let commit_slot = commit(&n, 1, 1).await;
    assert!(n.chain.seen_slot() >= commit_slot);
    // Answered from the Finalized view, 32 slots back: before the commit.
    n.faulty.stale(true);
    assert_eq!(
        n.chain.batch(1, Level::Confirmed).await,
        Err(ChainError::Rpc(RpcError::MinContextSlot {
            min_slot: n.chain.seen_slot()
        }))
    );
    // A restarted process: a new sender and adapter, given the last landed
    // slot of its journal. The loop gives up rather than act on what such a
    // provider shows (three attempts, so the view cannot catch up
    // meanwhile).
    let fresh_sender = Arc::new(TxSender::new(
        n.faulty.clone(),
        n.setup.fees,
        n.journal.clone(),
        common::svm::SLOT_TIME,
        n.setup.confirm_timeout,
    ));
    let restarted = SolanaMarketChain::new(
        n.faulty.clone(),
        fresh_sender,
        n.program,
        n.market,
        timescales_chain::MarketChainConfig {
            max_attempts: 3,
            ..n.setup.chain
        },
    );
    assert_eq!(restarted.seen_slot(), 0);
    restarted.observe_from(n.chain.seen_slot());
    let err = restarted
        .ensure_revealed(1, n.cranker.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ChainError::Tx(TxError::GaveUp { attempts: 3, last }) if last.contains("has not reached slot")),
        "{err:?}"
    );
    // An adapter that shares a sender starts from the sender's landed slots.
    let sibling = SolanaMarketChain::new(
        n.faulty.clone(),
        n.sender.clone(),
        n.program,
        n.market,
        n.setup.chain,
    );
    assert!(sibling.seen_slot() >= commit_slot);
    // Once that view has caught up it answers again.
    n.until_slot(n.chain.seen_slot() + 33).await;
    assert!(n.chain.batch(1, Level::Confirmed).await.unwrap().is_some());

    // Behind a quorum of two out of three, one stale provider is outvoted.
    n.faulty.stale(false);
    let [a, b] = pair(&n);
    a.stale(true);
    let third = Arc::new(FaultyRpc::new(n.svm.clone()));
    let quorum = QuorumRpc::new(vec![a.clone(), b, third], 2).unwrap();
    let chain = chain_over(&n, Arc::new(quorum));
    assert!(chain.batch(1, Level::Confirmed).await.unwrap().is_some());
    assert!(a.calls(RpcMethod::GetMultipleAccounts) >= 1);
}

#[tokio::test(start_paused = true)]
async fn disagreeing_providers_stop_every_read() {
    let n = Net::new(setup()).await;
    n.trader(100, 100).await;
    let [a, b] = pair(&n);
    a.disagree(true);
    let quorum = Arc::new(QuorumRpc::new(vec![a, b], 2).unwrap());
    assert_eq!(quorum.genesis_hash().await, Err(RpcError::Disagree));
    let chain = chain_over(&n, quorum);
    assert_eq!(
        chain.market(Level::Confirmed).await,
        Err(ChainError::Disagree)
    );
    assert_eq!(chain.trader_snapshot(0).await, Err(ChainError::Disagree));
    assert_eq!(
        chain
            .ensure_committed(1, root(1), 1, terms(), n.relay.clone())
            .await,
        Err(ChainError::Tx(TxError::GaveUp {
            attempts: n.setup.chain.max_attempts,
            last: "providers disagree".into()
        }))
    );
}

fn program_account(data: Vec<u8>, owner: [u8; 32]) -> Account {
    Account {
        lamports: 10_000_000,
        data,
        owner: SolAddress::from(owner),
        executable: false,
        rent_epoch: 0,
    }
}

#[tokio::test(start_paused = true)]
async fn accounts_are_checked_before_they_are_trusted() {
    let n = Net::new(setup()).await;
    commit(&n, 1, 1).await;
    let market = n.account(&n.market).unwrap();
    let batch = n.account(&n.batch_key(1)).unwrap();
    let decode_failure = |r: Result<_, ChainError>| match r {
        Err(ChainError::Decode(ClientError::Malformed)) => {}
        other => panic!("{other:?}"),
    };

    // Owner.
    n.set_account(&n.market, program_account(market.data.clone(), [3; 32]));
    n.wait_slots(2).await;
    assert_eq!(
        n.chain.market(Level::Confirmed).await,
        Err(ChainError::Inconsistent(
            "market account is not owned by the program"
        ))
    );
    // Size, tag and layout version.
    let corruptions: [fn(&mut Vec<u8>); 3] = [
        |d| d.truncate(d.len() - 1),
        |d| d[0] = timescales_chain::program::TRADER_TAG,
        |d| d[2] = 1,
    ];
    for corrupt in corruptions {
        let mut data = market.data.clone();
        corrupt(&mut data);
        n.set_account(&n.market, program_account(data, n.program));
        n.wait_slots(2).await;
        decode_failure(n.chain.market(Level::Confirmed).await.map(|_| ()));
    }
    n.set_account(&n.market, market);

    // A batch of another epoch at this epoch's address.
    n.set_account(&n.batch_key(2), batch.clone());
    let mut wrong_tag = batch.clone();
    wrong_tag.data[0] = timescales_chain::program::MARKET_TAG;
    n.set_account(&n.batch_key(3), wrong_tag);
    // A closed batch that still holds lamports is no batch.
    n.set_account(
        &n.batch_key(4),
        program_account(vec![], timescales_chain::program::SYSTEM_PROGRAM),
    );
    n.wait_slots(2).await;
    assert_eq!(
        n.chain.batch(2, Level::Confirmed).await,
        Err(ChainError::Inconsistent(
            "batch account names another market or epoch"
        ))
    );
    decode_failure(n.chain.batch(3, Level::Confirmed).await.map(|_| ()));
    assert_eq!(n.chain.batch(4, Level::Confirmed).await, Ok(None));
    assert_eq!(n.batch_account(1).await.status, BatchStatus::Committed);

    // A market that does not exist.
    let missing = SolanaMarketChain::new(
        n.faulty.clone(),
        n.sender.clone(),
        n.program,
        [0x33; 32],
        n.setup.chain,
    );
    assert_eq!(
        missing.market(Level::Confirmed).await,
        Err(ChainError::Inconsistent("market account not found"))
    );
}

#[tokio::test(start_paused = true)]
async fn the_snapshot_filters_are_its_account_checks() {
    let n = Net::new(setup()).await;
    let t = n.trader(10, 20).await;
    let real = n
        .account(
            &timescales_chain::program::trader_pda(&n.program, &n.market, &t.id())
                .unwrap()
                .0,
        )
        .unwrap()
        .data;
    assert_eq!(real.len(), TRADER_LEN);
    let place = |seed: u8, data: Vec<u8>, owner: [u8; 32]| {
        n.set_account(&[seed; 32], program_account(data, owner));
    };
    let mut v1 = real.clone();
    v1[2] = 1;
    place(0xe1, v1, n.program);
    let mut longer = real.clone();
    longer.push(0);
    place(0xe2, longer, n.program);
    let mut other_market = real.clone();
    other_market[4..36].copy_from_slice(&[0x44; 32]);
    place(0xe3, other_market, n.program);
    let mut not_a_trader = real.clone();
    not_a_trader[0] = timescales_chain::program::BATCH_TAG;
    place(0xe4, not_a_trader, n.program);
    place(0xe5, real.clone(), [9; 32]);
    n.wait_slots(2).await;
    let snapshot = n.chain.trader_snapshot(0).await.unwrap();
    assert_eq!(
        snapshot.traders.iter().map(|e| e.owner).collect::<Vec<_>>(),
        vec![t.id()]
    );
    assert_eq!(
        (snapshot.traders[0].base, snapshot.traders[0].quote),
        (10, 20)
    );
    assert!(n.faulty.calls(RpcMethod::GetProgramAccounts) >= 1);

    // A second account for the same owner that passes every filter.
    place(0xe6, real, n.program);
    n.wait_slots(2).await;
    assert_eq!(
        n.chain.trader_snapshot(0).await,
        Err(ChainError::Inconsistent(
            "two Trader accounts with one owner"
        ))
    );
}
