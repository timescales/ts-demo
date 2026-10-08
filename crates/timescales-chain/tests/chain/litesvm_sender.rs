//! `TxSender` against the real program in LiteSVM: the journal row before
//! the send, compute-unit sizing by simulation, priority fees, refused and
//! failed transactions, extra signers and `resolve_pending`.

#![cfg(all(feature = "litesvm", feature = "test-util"))]
#![allow(clippy::unwrap_used)]

use super::common;

use std::sync::Arc;
use std::time::Duration;

use common::svm::{Net, SLOT_TIME, Setup, root, terms};
use parking_lot::Mutex;
use timescales_chain::program::{
    COMPUTE_BUDGET_PROGRAM, ClientError, Side, TimescalesProgramError,
};
use timescales_chain::{
    AccountData, Address, BoxFuture, CommitOutcome, FeeMode, FeePolicy, Filter, Level, MarketChain,
    RpcError, RpcMethod, Simulation, SolanaRpc, TxError, TxJournal, TxOp, TxOutcome, TxSender,
    TxStatus,
};

/// Delegates to the harness provider and keeps what the sender asked and
/// was told: simulated units, the writable accounts of fee queries and the
/// wire bytes of every send.
struct Recording {
    inner: Arc<dyn SolanaRpc>,
    simulated: Mutex<Vec<Option<u64>>>,
    fee_queries: Mutex<Vec<Vec<Address>>>,
    sent: Mutex<Vec<Vec<u8>>>,
}

impl Recording {
    fn new(inner: Arc<dyn SolanaRpc>) -> Self {
        Self {
            inner,
            simulated: Mutex::new(vec![]),
            fee_queries: Mutex::new(vec![]),
            sent: Mutex::new(vec![]),
        }
    }

    /// `(unit limit, unit price)` of the last send: its first two
    /// instructions are the compute-budget ones.
    fn last_budget(&self) -> (u32, u64) {
        let wire = self.sent.lock().last().cloned().unwrap();
        let tx: solana_transaction::Transaction = bincode::deserialize(&wire).unwrap();
        let keys = &tx.message.account_keys;
        let budget: Vec<&[u8]> = tx
            .message
            .instructions
            .iter()
            .filter(|ix| {
                keys[usize::from(ix.program_id_index)].to_bytes() == COMPUTE_BUDGET_PROGRAM
            })
            .map(|ix| ix.data.as_slice())
            .collect();
        let [limit, price] = budget[..] else {
            panic!("{budget:?}")
        };
        assert_eq!((limit[0], price[0]), (2, 3));
        (
            u32::from_le_bytes(limit[1..5].try_into().unwrap()),
            u64::from_le_bytes(price[1..9].try_into().unwrap()),
        )
    }
}

impl SolanaRpc for Recording {
    fn get_account(
        &self,
        key: Address,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AccountData>, RpcError>> {
        self.inner.get_account(key, level, min_slot)
    }

    fn get_multiple_accounts(
        &self,
        keys: Vec<Address>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<Option<AccountData>>), RpcError>> {
        self.inner.get_multiple_accounts(keys, level, min_slot)
    }

    fn get_program_accounts(
        &self,
        program: Address,
        filters: Vec<Filter>,
        slice: Option<(usize, usize)>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<(Address, Vec<u8>)>), RpcError>> {
        self.inner
            .get_program_accounts(program, filters, slice, level, min_slot)
    }

    fn latest_blockhash(&self, level: Level) -> BoxFuture<'_, Result<([u8; 32], u64), RpcError>> {
        self.inner.latest_blockhash(level)
    }

    fn send_transaction(
        &self,
        wire: Vec<u8>,
        skip_preflight: bool,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<[u8; 64], RpcError>> {
        self.sent.lock().push(wire.clone());
        self.inner.send_transaction(wire, skip_preflight, min_slot)
    }

    fn simulate_transaction(&self, wire: Vec<u8>) -> BoxFuture<'_, Result<Simulation, RpcError>> {
        Box::pin(async move {
            let sim = self.inner.simulate_transaction(wire).await?;
            self.simulated.lock().push(sim.units);
            Ok(sim)
        })
    }

    fn signature_statuses(
        &self,
        sigs: Vec<[u8; 64]>,
    ) -> BoxFuture<'_, Result<Vec<Option<TxStatus>>, RpcError>> {
        self.inner.signature_statuses(sigs)
    }

    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        self.inner.slot(level)
    }

    fn block_height(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        self.inner.block_height(level)
    }

    fn genesis_hash(&self) -> BoxFuture<'_, Result<[u8; 32], RpcError>> {
        self.inner.genesis_hash()
    }

    fn recent_prioritization_fees(
        &self,
        writable: Vec<Address>,
    ) -> BoxFuture<'_, Result<Vec<u64>, RpcError>> {
        self.fee_queries.lock().push(writable.clone());
        self.inner.recent_prioritization_fees(writable)
    }

    fn minimum_balance_for_rent_exemption(
        &self,
        len: usize,
    ) -> BoxFuture<'_, Result<u64, RpcError>> {
        self.inner.minimum_balance_for_rent_exemption(len)
    }
}

fn recording(n: &Net, fees: FeePolicy) -> (Arc<Recording>, TxSender) {
    let rec = Arc::new(Recording::new(n.faulty.clone()));
    let sender = TxSender::new(
        rec.clone(),
        fees,
        n.journal.clone(),
        SLOT_TIME,
        n.setup.confirm_timeout,
    );
    (rec, sender)
}

#[tokio::test(start_paused = true)]
async fn nothing_is_sent_before_the_journal_row_is_written() {
    let n = Net::new(Setup::default()).await;
    let (rows, sends) = (n.journal.len(), n.sends());
    n.journal.refuse_next();
    let transfer =
        timescales_chain::program::system::transfer(&n.cranker.address(), &[5; 32], 1_000_000);
    let err = n
        .sender
        .send(
            TxOp::Admin,
            vec![transfer.clone()],
            n.cranker.clone(),
            vec![],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TxError::Journal(_)), "{err:?}");
    assert_eq!((n.journal.len(), n.sends()), (rows, sends));
    let landed = n
        .sender
        .send(TxOp::Admin, vec![transfer], n.cranker.clone(), vec![])
        .await
        .unwrap();
    let row = n.journal.rows().pop().unwrap();
    assert_eq!(row.sends_before, sends);
    assert_eq!(row.record.signature, landed.signature);
    assert_eq!(row.outcome, Some(TxOutcome::Landed { slot: landed.slot }));
    assert_eq!(n.sender.last_landed_slot(), landed.slot);
}

#[tokio::test(start_paused = true)]
async fn compute_units_are_simulated_once_per_shape_with_the_margin() {
    let n = Net::new(Setup::default()).await;
    let (rec, sender) = recording(&n, n.setup.fees);
    let cranker = n.cranker.address();
    for amount in [1_000_000, 2_000_000] {
        let ix = timescales_chain::program::system::transfer(&cranker, &[5; 32], amount);
        sender
            .send(TxOp::Admin, vec![ix], n.cranker.clone(), vec![])
            .await
            .unwrap();
    }
    let simulated = rec.simulated.lock().clone();
    assert_eq!(simulated.len(), 1, "one simulation for one shape");
    let units = simulated[0].unwrap();
    let (limit, price) = rec.last_budget();
    assert_eq!(u64::from(limit), (units * 120).div_ceil(100));
    assert_eq!(price, 1_000);
    // Another shape (two instructions) is simulated again.
    let two = vec![
        timescales_chain::program::system::transfer(&cranker, &[5; 32], 1_000_000),
        timescales_chain::program::system::transfer(&cranker, &[6; 32], 1_000_000),
    ];
    sender
        .send(TxOp::Admin, two, n.cranker.clone(), vec![])
        .await
        .unwrap();
    assert_eq!(rec.simulated.lock().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_short_cached_limit_is_sized_again() {
    let n = Net::new(Setup::default()).await;
    let (rec, sender) = recording(&n, n.setup.fees);
    // Commits of different epochs share a shape, but the batch PDA's bump
    // search costs differ by epoch. Ending each batch with an admin abort
    // lets the next epoch commit.
    let mut resized = 0;
    for epoch in 1..=6 {
        let ix = timescales_chain::program::commit_batch(
            &n.program,
            &n.relay.address(),
            &n.market,
            epoch,
            &root(epoch),
            1,
            &terms(),
        )
        .unwrap();
        let rows = n.journal.len();
        sender
            .send(TxOp::Commit, vec![ix], n.relay.clone(), vec![])
            .await
            .unwrap();
        let new = &n.journal.rows()[rows..];
        match new {
            [landed] => assert!(matches!(landed.outcome, Some(TxOutcome::Landed { .. }))),
            [refused, landed] => {
                resized += 1;
                assert_eq!(refused.outcome, Some(TxOutcome::Expired));
                assert!(matches!(landed.outcome, Some(TxOutcome::Landed { .. })));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            n.chain
                .ensure_aborted(
                    epoch,
                    timescales_chain::program::AbortReason::Admin,
                    n.admin.clone()
                )
                .await,
            Ok(timescales_chain::AbortOutcome::Aborted {
                reason: timescales_chain::program::AbortReason::Admin
            })
        );
    }
    // Recorded here so a change in the program's costs shows up: at least
    // one epoch needed more than the limit cached before it.
    assert!(resized >= 1, "no epoch needed a larger limit");
    assert_eq!(rec.simulated.lock().len(), 1 + resized);
}

#[tokio::test(start_paused = true)]
async fn recent_fees_take_the_percentile_up_to_the_cap() {
    let n = Net::new(Setup::default()).await;
    let policy = FeePolicy {
        mode: FeeMode::Recent,
        percentile: 75,
        max_micro_lamports: 5_000,
        cu_margin_pct: 20,
    };
    let (rec, sender) = recording(&n, policy);
    let cranker = n.cranker.address();
    for (fees, expected) in [
        (vec![100, 9_000, 300, 200], 300),
        (vec![100, 9_000, 8_000, 7_000], 5_000),
        (vec![], 0),
    ] {
        n.svm.set_prioritization_fees(fees);
        let ix = timescales_chain::program::system::transfer(&cranker, &[5; 32], 1_000_000);
        sender
            .send(TxOp::Admin, vec![ix], n.cranker.clone(), vec![])
            .await
            .unwrap();
        assert_eq!(rec.last_budget().1, expected);
    }
    // Asked for the accounts the transaction writes, once each.
    let mut writable = vec![cranker, [5; 32]];
    writable.sort_unstable();
    assert!(rec.fee_queries.lock().iter().all(|q| *q == writable));
}

#[tokio::test(start_paused = true)]
async fn a_refused_preflight_is_journalled_as_never_landing() {
    let n = Net::new(Setup::default()).await;
    let commit = timescales_chain::program::commit_batch(
        &n.program,
        &n.relay.address(),
        &n.market,
        1,
        &root(1),
        1,
        &terms(),
    )
    .unwrap();
    n.sender
        .send(TxOp::Commit, vec![commit.clone()], n.relay.clone(), vec![])
        .await
        .unwrap();
    // Sized from the cache, so only the node's preflight sees that epoch 1
    // is taken.
    let sends = n.sends();
    let err = n
        .sender
        .send(TxOp::Commit, vec![commit], n.relay.clone(), vec![])
        .await
        .unwrap_err();
    let TxError::Preflight { err, logs } = err else {
        panic!("{err:?}")
    };
    assert_eq!(
        (err.ix_index, err.custom),
        (Some(2), Some(TimescalesProgramError::OutOfOrder.code()))
    );
    assert!(!logs.is_empty());
    assert_eq!(n.sends(), sends + 1);
    assert_eq!(
        n.journal.rows().last().unwrap().outcome,
        Some(TxOutcome::Expired)
    );

    // A shape without a cached limit is simulated first, and a failed
    // simulation stops before the journal: no batch 9 exists to reveal.
    let (rows, sends) = (n.journal.len(), n.sends());
    let reveal =
        timescales_chain::program::reveal_beacon(&n.program, &n.cranker.address(), &n.market, 9)
            .unwrap();
    let err = n
        .sender
        .send(TxOp::Reveal, vec![reveal], n.cranker.clone(), vec![])
        .await
        .unwrap_err();
    assert!(
        matches!(&err, TxError::Preflight { err, .. } if err.custom == Some(TimescalesProgramError::InvalidAccount.code())),
        "{err:?}"
    );
    assert_eq!((n.journal.len(), n.sends()), (rows, sends));
}

#[tokio::test(start_paused = true)]
async fn a_transaction_can_land_and_fail() {
    let n = Net::new(Setup::default()).await;
    // Halt the market in the processed state only: the Confirmed view the
    // simulation and preflight run on still has it open.
    let mut market = n.account(&n.market).unwrap();
    market.data[3] |= 1;
    n.set_account(&n.market, market);
    let commit = timescales_chain::program::commit_batch(
        &n.program,
        &n.relay.address(),
        &n.market,
        1,
        &root(1),
        1,
        &terms(),
    )
    .unwrap();
    let err = n
        .sender
        .send(TxOp::Commit, vec![commit], n.relay.clone(), vec![])
        .await
        .unwrap_err();
    let TxError::Failed { slot, err, .. } = err else {
        panic!("{err:?}")
    };
    assert_eq!(err.custom, Some(TimescalesProgramError::Halted.code()));
    assert_eq!(
        n.journal.rows().last().unwrap().outcome,
        Some(TxOutcome::Failed {
            slot,
            err: err.clone()
        })
    );
    assert_eq!(n.sender.last_landed_slot(), slot);

    // The adapter takes a landed `Halted` as a reason to look again, and
    // then sees the halt.
    let mut market = n.account(&n.market).unwrap();
    market.data[3] &= !1;
    n.set_account(&n.market, market);
    n.wait_slots(2).await;
    let mut market = n.account(&n.market).unwrap();
    market.data[3] |= 1;
    n.set_account(&n.market, market);
    assert_eq!(
        n.chain
            .ensure_committed(1, root(1), 1, terms(), n.relay.clone())
            .await,
        Ok(CommitOutcome::Halted)
    );
}

#[tokio::test(start_paused = true)]
async fn extra_signers_sign_after_the_payer() {
    let n = Net::new(Setup::default()).await;
    let t = n.trader(0, 0).await;
    // The trader deposits. The cranker pays the fee.
    let mut account = n.account(&t.base_ata).unwrap();
    account.data[64..72].copy_from_slice(&50u64.to_le_bytes());
    n.set_account(&t.base_ata, account);
    n.wait_slots(2).await;
    let deposit = timescales_chain::program::deposit(
        &n.program,
        &t.id(),
        &n.market,
        &t.base_ata,
        &n.base_vault,
        Side::Base,
        50,
    )
    .unwrap();
    let missing = n
        .sender
        .send(
            TxOp::Admin,
            vec![deposit.clone()],
            n.cranker.clone(),
            vec![],
        )
        .await
        .unwrap_err();
    assert_eq!(
        missing,
        TxError::Build(ClientError::InvalidArgument(
            "no signer for a required signature"
        ))
    );
    let before = n.account(&n.cranker.address()).unwrap().lamports;
    n.sender
        .send(
            TxOp::Admin,
            vec![deposit],
            n.cranker.clone(),
            vec![t.signer.clone()],
        )
        .await
        .unwrap();
    assert!(n.account(&n.cranker.address()).unwrap().lamports < before);
    n.wait_slots(2).await;
    let snapshot = n.chain.trader_snapshot(0).await.unwrap();
    assert_eq!(snapshot.traders[0].base, 50);
}

#[tokio::test(start_paused = true)]
async fn resolve_pending_reads_every_open_row() {
    let n = Net::new(Setup {
        confirm_timeout: Duration::from_secs(4),
        ..Setup::default()
    })
    .await;
    let cranker = n.cranker.address();
    // Each transfer a distinct amount, so each is a distinct transaction.
    let transfer =
        |k: u64| timescales_chain::program::system::transfer(&cranker, &[5; 32], 1_000_000 + k);

    // Never reached a leader, and the deadline came before the expiry.
    n.faulty.black_hole_sends(1);
    let err = n
        .sender
        .send(TxOp::Admin, vec![transfer(1)], n.cranker.clone(), vec![])
        .await
        .unwrap_err();
    assert!(matches!(err, TxError::Timeout { .. }), "{err:?}");
    // Landed, but neither the response nor any status came back in time.
    n.faulty.drop_response_after_send(1, RpcError::Timeout);
    n.faulty
        .fail_next(RpcMethod::BlockHeight, 1_000_000, RpcError::Timeout);
    let err = n
        .sender
        .send(TxOp::Admin, vec![transfer(2)], n.cranker.clone(), vec![])
        .await
        .unwrap_err();
    assert!(matches!(err, TxError::Timeout { .. }), "{err:?}");
    n.faulty.clear();

    let open = n
        .journal
        .rows()
        .into_iter()
        .filter(|r| r.outcome.is_none())
        .count();
    assert_eq!(open, 2);
    // A restarted sender resolves both: one landed, one past its last valid
    // block height.
    let restarted = TxSender::new(
        n.faulty.clone(),
        n.setup.fees,
        n.journal.clone(),
        SLOT_TIME,
        n.setup.confirm_timeout,
    );
    let rows = n.journal.rows();
    let (swallowed, lost) = (&rows[rows.len() - 2], &rows[rows.len() - 1]);
    let resolved = restarted.resolve_pending().await.unwrap();
    let outcome = |sig: [u8; 64]| {
        resolved
            .iter()
            .find(|(r, _)| r.signature == sig)
            .map(|(_, o)| o.clone())
    };
    assert_eq!(resolved.len(), 2);
    assert_eq!(
        outcome(swallowed.record.signature),
        Some(TxOutcome::Expired)
    );
    let Some(TxOutcome::Landed { slot }) = outcome(lost.record.signature) else {
        panic!("{resolved:?}")
    };
    assert_eq!(restarted.last_landed_slot(), slot);
    // The expiry is known only once the confirmed block height passed the
    // last valid one.
    assert!(
        n.svm.current_slot() - n.setup.cluster.confirmed_lag
            > swallowed.record.last_valid_block_height
    );
    assert!(n.journal.rows().iter().all(|r| r.outcome.is_some()));
    assert_eq!(restarted.resolve_pending().await.unwrap(), vec![]);
    // Another restart with nothing open starts from the journal's floor.
    let again = TxSender::new(
        n.faulty.clone(),
        n.setup.fees,
        n.journal.clone(),
        SLOT_TIME,
        n.setup.confirm_timeout,
    );
    assert_eq!(again.last_landed_slot(), 0);
    assert_eq!(again.resolve_pending().await.unwrap(), vec![]);
    let floor = n.journal.last_landed_slot().await.unwrap();
    assert!(floor >= slot);
    assert_eq!(again.last_landed_slot(), floor);

    // Without any answer it gives up after the confirmation timeout.
    n.faulty.black_hole_sends(1);
    n.sender
        .send(TxOp::Admin, vec![transfer(3)], n.cranker.clone(), vec![])
        .await
        .unwrap_err();
    n.faulty
        .fail_next(RpcMethod::BlockHeight, 1_000_000, RpcError::Http(503));
    assert_eq!(
        restarted.resolve_pending().await,
        Err(TxError::Rpc(RpcError::Http(503)))
    );
}
