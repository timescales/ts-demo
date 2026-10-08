//! What `LiteSvmRpc` emulates (commitment levels, statuses, blockhash
//! expiry, `minContextSlot`, SlotHashes) and what `FaultyRpc` injects.

#![cfg(all(feature = "litesvm", feature = "test-util"))]
#![allow(clippy::unwrap_used)]

use super::common;

use std::sync::Arc;
use std::time::Duration;

use common::svm::{Net, Setup, root, terms};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address as SolAddress;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use timescales_chain::program::SLOT_HASHES_SYSVAR;
use timescales_chain::{
    AccountData, FaultyRpc, Filter, Level, LiteSvmConfig, LiteSvmRpc, MarketChain, RevealOutcome,
    RpcError, RpcMethod, SolanaRpc, TxStatus,
};
use timescales_core::{EpochId, Hash32};

const START: u64 = 100;

/// A cluster with a manual clock: confirmed one slot, finalized four slots
/// behind, blockhashes valid for ten blocks.
fn cluster() -> (Arc<LiteSvmRpc>, Keypair) {
    let mut svm = LiteSVM::new();
    svm.warp_to_slot(START);
    let payer = Keypair::new_from_array([0x21; 32]);
    svm.set_account(
        payer.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: SolAddress::default(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let rpc = LiteSvmRpc::new(
        svm,
        LiteSvmConfig {
            confirmed_lag: 1,
            finalized_lag: 4,
            slot_time: None,
            blockhash_validity: 10,
            ..LiteSvmConfig::default()
        },
    );
    // Let the payer reach every view.
    rpc.advance(4);
    (Arc::new(rpc), payer)
}

fn transfer(payer: &Keypair, to: [u8; 32], lamports: u64, blockhash: [u8; 32]) -> Vec<u8> {
    let ix = solana_system_ix(payer.pubkey(), SolAddress::from(to), lamports);
    let message = Message::new_with_blockhash(
        &[ix],
        Some(&payer.pubkey()),
        &Hash::new_from_array(blockhash),
    );
    let tx = Transaction::new(&[payer], message, Hash::new_from_array(blockhash));
    bincode::serialize(&tx).unwrap()
}

fn solana_system_ix(
    from: SolAddress,
    to: SolAddress,
    lamports: u64,
) -> solana_instruction::Instruction {
    let ix =
        timescales_chain::program::system::transfer(&from.to_bytes(), &to.to_bytes(), lamports);
    solana_instruction::Instruction {
        program_id: SolAddress::from(ix.program),
        accounts: ix
            .accounts
            .iter()
            .map(|m| solana_instruction::AccountMeta {
                pubkey: SolAddress::from(m.key),
                is_signer: m.signer,
                is_writable: m.writable,
            })
            .collect(),
        data: ix.data,
    }
}

#[tokio::test]
async fn views_and_statuses_follow_the_commitment_levels() {
    let (rpc, payer) = cluster();
    let now = START + 4;
    assert_eq!(rpc.current_slot(), now);
    assert_eq!(rpc.slot(Level::Processed).await, Ok(now));
    assert_eq!(rpc.slot(Level::Confirmed).await, Ok(now - 1));
    assert_eq!(rpc.block_height(Level::Finalized).await, Ok(now - 4));

    let (blockhash, last_valid) = rpc.latest_blockhash(Level::Confirmed).await.unwrap();
    assert_eq!(last_valid, now - 1 + 10);
    let to = [0x55; 32];
    let wire = transfer(&payer, to, 2_000_000, blockhash);
    let sig = rpc
        .send_transaction(wire.clone(), false, None)
        .await
        .unwrap();
    assert_eq!(sig[..], wire[1..65]);

    let seen = |level| {
        let rpc = rpc.clone();
        async move { rpc.get_account(to, level, None).await.unwrap() }
    };
    assert_eq!(
        seen(Level::Processed).await,
        Some(AccountData {
            owner: [0; 32],
            lamports: 2_000_000,
            data: vec![],
            context_slot: now,
        })
    );
    assert_eq!(seen(Level::Confirmed).await, None);
    let status = |level| {
        Some(TxStatus {
            slot: now,
            level,
            err: None,
        })
    };
    assert_eq!(
        rpc.signature_statuses(vec![sig, [9; 64]]).await,
        Ok(vec![status(Level::Processed), None])
    );

    rpc.advance(1);
    assert_eq!(
        seen(Level::Confirmed).await.map(|a| a.context_slot),
        Some(now)
    );
    assert_eq!(seen(Level::Finalized).await, None);
    assert_eq!(
        rpc.signature_statuses(vec![sig]).await,
        Ok(vec![status(Level::Confirmed)])
    );
    rpc.advance(3);
    assert!(seen(Level::Finalized).await.is_some());
    assert_eq!(
        rpc.signature_statuses(vec![sig]).await,
        Ok(vec![status(Level::Finalized)])
    );

    // A view below `minContextSlot` refuses to answer.
    assert_eq!(
        rpc.get_account(to, Level::Finalized, Some(now + 1)).await,
        Err(RpcError::MinContextSlot { min_slot: now + 1 })
    );
    assert_eq!(
        rpc.send_transaction(wire.clone(), false, Some(now + 10))
            .await,
        Err(RpcError::MinContextSlot { min_slot: now + 10 })
    );
    // The same signature again.
    let Err(RpcError::Preflight { err, .. }) = rpc.send_transaction(wire, false, None).await else {
        panic!("a repeated signature was accepted")
    };
    assert_eq!(err.message, "AlreadyProcessed");

    // After its last valid block height a blockhash is unknown: preflight
    // refuses the transaction, and without preflight it is dropped.
    rpc.warp_slot(last_valid + 2);
    let late = transfer(&payer, to, 3_000_000, blockhash);
    let Err(RpcError::Preflight { err, .. }) =
        rpc.send_transaction(late.clone(), false, None).await
    else {
        panic!("an expired blockhash was accepted")
    };
    assert_eq!(err.message, "BlockhashNotFound");
    let sig = rpc.send_transaction(late, true, None).await.unwrap();
    assert_eq!(rpc.signature_statuses(vec![sig]).await, Ok(vec![None]));
    // `warp_slot` never moves back.
    rpc.warp_slot(START);
    assert_eq!(rpc.current_slot(), last_valid + 2);
}

#[tokio::test]
async fn reads_simulations_and_constants() {
    let (rpc, payer) = cluster();
    let (blockhash, _) = rpc.latest_blockhash(Level::Confirmed).await.unwrap();
    let sim = rpc
        .simulate_transaction(transfer(&payer, [0x56; 32], 2_000_000, blockhash))
        .await
        .unwrap();
    assert_eq!(sim.err, None);
    assert!(sim.units.unwrap() > 0);
    let sim = rpc
        .simulate_transaction(transfer(&payer, [0x56; 32], 1, blockhash))
        .await
        .unwrap();
    assert!(
        sim.err
            .unwrap()
            .message
            .contains("InsufficientFundsForRent")
    );
    assert_eq!(
        rpc.simulate_transaction(vec![1, 2, 3])
            .await
            .map(|_| ())
            .map_err(|e| e.kind()),
        Err("decode")
    );

    let oversized = vec![1u8; timescales_chain::program::MAX_TX_SIZE + 1];
    assert!(matches!(
        rpc.send_transaction(oversized, false, None).await,
        Err(RpcError::Rpc { code: -32602, .. })
    ));
    assert_eq!(rpc.genesis_hash().await, Ok(rpc.config().genesis_hash));
    // (128 + 148) x 6960, the Trader rent.
    assert_eq!(
        rpc.minimum_balance_for_rent_exemption(148).await,
        Ok(1_920_960)
    );
    rpc.set_prioritization_fees(vec![3, 1]);
    assert_eq!(rpc.recent_prioritization_fees(vec![]).await, Ok(vec![3, 1]));

    // Program accounts: filters, then the slice.
    let owner = [0x0a; 32];
    for (seed, data) in [
        (1u8, vec![1, 2, 3, 4]),
        (2, vec![1, 9, 3, 4]),
        (3, vec![1, 2, 3]),
    ] {
        rpc.with_svm(|svm| {
            svm.set_account(
                SolAddress::from([seed; 32]),
                Account {
                    lamports: 1_000_000,
                    data,
                    owner: SolAddress::from(owner),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        });
    }
    let filters = vec![
        Filter::DataSize(4),
        Filter::Memcmp {
            offset: 1,
            bytes: vec![2],
        },
    ];
    assert_eq!(
        rpc.get_program_accounts(owner, filters, Some((2, 8)), Level::Processed, None)
            .await,
        Ok((rpc.current_slot(), vec![([1; 32], vec![3, 4])]))
    );
    let (_, all) = rpc
        .get_program_accounts(owner, vec![], Some((5, 1)), Level::Processed, None)
        .await
        .unwrap();
    assert_eq!(all.len(), 3);
    assert!(
        all.iter().all(|(_, d)| d.is_empty()),
        "a slice past the end is empty"
    );
    let (_, confirmed) = rpc
        .get_program_accounts(owner, vec![], None, Level::Confirmed, None)
        .await
        .unwrap();
    assert!(confirmed.is_empty(), "set this slot, not yet confirmed");
}

#[tokio::test]
async fn slot_hashes_follow_the_clock_unless_set() {
    let (rpc, _) = cluster();
    let read = |rpc: Arc<LiteSvmRpc>| async move {
        rpc.get_account(SLOT_HASHES_SYSVAR, Level::Processed, None)
            .await
            .unwrap()
            .unwrap()
            .data
    };
    let now = rpc.current_slot();
    let data = read(rpc.clone()).await;
    assert_eq!(
        u64::from_le_bytes(data[..8].try_into().unwrap()),
        now.min(512)
    );
    for target in [now - 1, now - 3, 1] {
        assert_eq!(
            timescales_auction::slot_hashes_entry(&data, target),
            Some((target, Hash32(LiteSvmRpc::slot_hash(target))))
        );
    }
    assert_eq!(timescales_auction::slot_hashes_entry(&data, now), None);
    rpc.advance(1);
    let data = read(rpc.clone()).await;
    assert_eq!(
        timescales_auction::slot_hashes_entry(&data, now),
        Some((now, Hash32(LiteSvmRpc::slot_hash(now))))
    );

    rpc.set_slot_hashes(&[(90, [7; 32]), (80, [8; 32])]);
    rpc.advance(5);
    let data = read(rpc.clone()).await;
    assert_eq!(u64::from_le_bytes(data[..8].try_into().unwrap()), 2);
    assert_eq!(
        timescales_auction::slot_hashes_entry(&data, 81),
        Some((90, Hash32([7; 32])))
    );
    rpc.set_auto_slot_hashes(true);
    let data = read(rpc.clone()).await;
    assert_eq!(
        timescales_auction::slot_hashes_entry(&data, rpc.current_slot() - 1),
        Some((
            rpc.current_slot() - 1,
            Hash32(LiteSvmRpc::slot_hash(rpc.current_slot() - 1))
        ))
    );
}

#[tokio::test(start_paused = true)]
async fn the_program_reads_the_emulated_slot_hashes() {
    let n = Net::new(Setup::default()).await;
    let commit_slot = match n
        .chain
        .ensure_committed(1, root(1), 1, terms(), n.relay.clone())
        .await
        .unwrap()
    {
        timescales_chain::CommitOutcome::Committed { slot } => slot,
        other => panic!("{other:?}"),
    };
    // Target a (commit + 4) was skipped: the next produced slot stands in.
    let (a, b) = (commit_slot + 4, commit_slot + 8);
    let entries: Vec<(u64, [u8; 32])> = [b + 1, b, a + 2, a - 1]
        .into_iter()
        .map(|s| (s, LiteSvmRpc::slot_hash(s)))
        .collect();
    n.until_slot(b + 3).await;
    n.svm.set_slot_hashes(&entries);
    n.wait_slots(2).await;
    let RevealOutcome::Revealed { beacon, .. } = n.reveal(1).await else {
        panic!("not revealed")
    };
    let expected = timescales_auction::beacon_v2(
        &n.market,
        EpochId(1),
        &root(1),
        1,
        (a + 2, Hash32(LiteSvmRpc::slot_hash(a + 2))),
        (b, Hash32(LiteSvmRpc::slot_hash(b))),
    );
    assert_eq!(beacon, expected);
    let batch = n.batch_account(1).await;
    assert_eq!((batch.beacon_slot_a, batch.beacon_slot_b), (a + 2, b));
}

#[tokio::test(start_paused = true)]
async fn faults_are_aimed_per_method() {
    let (rpc, payer) = cluster();
    let faulty = FaultyRpc::new(rpc.clone());
    assert!(Arc::ptr_eq(faulty.inner(), &rpc));

    faulty.fail_next(RpcMethod::Slot, 2, RpcError::RateLimited);
    assert_eq!(
        faulty.slot(Level::Processed).await,
        Err(RpcError::RateLimited)
    );
    assert_eq!(
        faulty.slot(Level::Processed).await,
        Err(RpcError::RateLimited)
    );
    assert_eq!(faulty.slot(Level::Processed).await, Ok(rpc.current_slot()));
    assert_eq!(faulty.calls(RpcMethod::Slot), 3);
    assert_eq!(faulty.calls(RpcMethod::BlockHeight), 0);

    faulty.delay(RpcMethod::GenesisHash, Some(Duration::from_millis(250)));
    let started = tokio::time::Instant::now();
    faulty.genesis_hash().await.unwrap();
    assert!(started.elapsed() >= Duration::from_millis(250));
    faulty.delay(RpcMethod::GenesisHash, None);

    // Disagreement flips account bytes and the genesis hash.
    let key = payer.pubkey().to_bytes();
    let honest = rpc.get_account(key, Level::Processed, None).await.unwrap();
    faulty.disagree(true);
    let flipped = faulty
        .get_account(key, Level::Processed, None)
        .await
        .unwrap();
    assert_ne!(flipped, honest);
    assert_eq!(flipped.unwrap().lamports, honest.unwrap().lamports ^ 1);
    assert_ne!(faulty.genesis_hash().await, rpc.genesis_hash().await);
    // Stale answers come from one level lower.
    faulty.disagree(false);
    faulty.stale(true);
    assert_eq!(
        faulty.slot(Level::Confirmed).await,
        rpc.slot(Level::Finalized).await
    );
    faulty.clear();
    assert_eq!(
        faulty.slot(Level::Confirmed).await,
        rpc.slot(Level::Confirmed).await
    );
    assert_eq!(faulty.calls(RpcMethod::Slot), 5, "clear keeps the counts");

    // A dropped response: the cluster has the transaction.
    let (blockhash, _) = rpc.latest_blockhash(Level::Processed).await.unwrap();
    faulty.drop_response_after_send(1, RpcError::Transport("reset".into()));
    let wire = transfer(&payer, [0x57; 32], 2_000_000, blockhash);
    assert_eq!(
        faulty.send_transaction(wire.clone(), false, None).await,
        Err(RpcError::Transport("reset".into()))
    );
    let sig: [u8; 64] = wire[1..65].try_into().unwrap();
    assert!(rpc.signature_statuses(vec![sig]).await.unwrap()[0].is_some());
    // A black hole: the caller has a signature, the cluster nothing.
    faulty.black_hole_sends(1);
    let wire = transfer(&payer, [0x58; 32], 2_000_000, blockhash);
    let sig = faulty.send_transaction(wire, false, None).await.unwrap();
    assert_eq!(rpc.signature_statuses(vec![sig]).await, Ok(vec![None]));
    assert_eq!(faulty.calls(RpcMethod::SendTransaction), 2);
}

#[tokio::test(start_paused = true)]
async fn the_cluster_clock_runs_on_tokio_time() {
    let n = Net::new(Setup::default()).await;
    let start = n.svm.current_slot();
    tokio::time::sleep(Duration::from_millis(400 * 10)).await;
    assert_eq!(n.svm.current_slot(), start + 10);
    n.svm.warp_slot(start + 100);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(n.svm.current_slot(), start + 101);
    assert_eq!(n.chain.slot(Level::Confirmed).await, Ok(start + 100));
    // The program's Clock is the emulated slot: the commit records the slot
    // its transaction landed in.
    let commit = n
        .chain
        .ensure_committed(1, root(1), 1, terms(), n.relay.clone())
        .await
        .unwrap();
    let landed = n.journal.rows().last().unwrap().outcome.clone();
    let (
        timescales_chain::CommitOutcome::Committed { slot },
        Some(timescales_chain::TxOutcome::Landed { slot: landed }),
    ) = (commit, landed)
    else {
        panic!("not committed")
    };
    assert_eq!(slot, landed);
    assert!(slot >= start + 101);
}
