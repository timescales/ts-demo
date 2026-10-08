//! `legacy_tx_size` and `plan_delta_chunks` against real legacy
//! transactions: compiled by `solana-message`, serialized by
//! `solana-transaction` (bincode), at most 1232 bytes.

#![allow(clippy::unwrap_used)]

use super::common;

use common::{Rng, params, settlement, wire};
use timescales_chain::program::{
    AbortReason, GovernanceChange, InitMarketArgs, Ix, Key, Leaf, MAX_TX_SIZE, Side, abort_batch,
    accept_admin, apply_change, apply_deltas, batch_pda, cancel_change, cancel_withdraw_request,
    claim_fees, close_batch, close_trader, commit_batch, compute_budget, cosign_receipt, deposit,
    ed25519_verify, finalize, init_market, leaves, legacy_tx_size, market_pda, open_trader,
    plan_delta_chunks, post_receipt, propose_change, reclaim_batch, remove_executor,
    request_withdraw, reveal_beacon, set_halted, spl, system, verify_deltas, withdraw,
};
use timescales_core::Hash32;

const PROGRAM: Key = [0x50; 32];
const EPOCH: u64 = 9;

fn market() -> Key {
    market_pda(&PROGRAM, 77).unwrap().0
}

fn with_compute_budget(ixs: Vec<Ix>) -> Vec<Ix> {
    let mut all = vec![
        compute_budget::set_limit(400_000),
        compute_budget::set_price(1_000),
    ];
    all.extend(ixs);
    all
}

#[track_caller]
fn same_as_serialized(ixs: &[Ix], payer: &Key) -> usize {
    let (real, signatures) = wire(ixs, payer);
    assert_eq!(legacy_tx_size(ixs, payer, signatures), real);
    // Fewer signatures than signing keys cannot be: the count is raised.
    assert_eq!(legacy_tx_size(ixs, payer, 0), real);
    real
}

/// One transaction per builder, each paid for by its first signer.
fn one_per_builder(rng: &mut Rng) -> Vec<(Vec<Ix>, Key)> {
    let m = market();
    let b = batch_pda(&PROGRAM, &m, EPOCH).unwrap().0;
    let (owner, relay, cranker, admin) = (rng.key(), rng.key(), rng.key(), rng.key());
    let leaf = leaves(&settlement(rng, 5)).unwrap();
    let args = InitMarketArgs {
        salt: rng.key(),
        admin,
        relay,
        params: params(1),
        committee_digest: Hash32(rng.key()),
        beacon_delay_slots: 4,
        timelock_slots: 20,
        exec_timeout_slots: 150,
        settle_timeout_slots: 1_500,
        receipt_quorum: 2,
        executors: (0..8).map(|_| rng.key()).collect(),
    };
    let (mint, vault, ata) = (rng.key(), rng.key(), rng.key());
    let sig = [7u8; 64];
    let digest = Hash32(rng.key());
    vec![
        (
            vec![
                init_market(
                    &PROGRAM,
                    &owner,
                    &mint,
                    &rng.key(),
                    &vault,
                    &rng.key(),
                    &args,
                )
                .unwrap(),
            ],
            owner,
        ),
        (vec![open_trader(&PROGRAM, &owner, &m).unwrap()], owner),
        (
            vec![deposit(&PROGRAM, &owner, &m, &ata, &vault, Side::Quote, 5).unwrap()],
            owner,
        ),
        (
            vec![request_withdraw(&PROGRAM, &owner, &m, 1, 2).unwrap()],
            owner,
        ),
        (
            vec![cancel_withdraw_request(&PROGRAM, &owner, &m).unwrap()],
            owner,
        ),
        (
            vec![withdraw(&PROGRAM, &owner, &m, &vault, &ata, Side::Base).unwrap()],
            owner,
        ),
        (vec![close_trader(&PROGRAM, &owner, &m).unwrap()], owner),
        (
            vec![commit_batch(&PROGRAM, &relay, &m, EPOCH, &digest, 3, &digest).unwrap()],
            relay,
        ),
        (
            vec![reveal_beacon(&PROGRAM, &cranker, &m, EPOCH).unwrap()],
            cranker,
        ),
        (
            vec![
                ed25519_verify(&admin, &digest, &sig),
                post_receipt(&PROGRAM, &cranker, &m, EPOCH, &[1; 283], &[2; 407]).unwrap(),
            ],
            cranker,
        ),
        (
            vec![
                ed25519_verify(&admin, &digest, &sig),
                cosign_receipt(&PROGRAM, &cranker, &m, EPOCH).unwrap(),
            ],
            cranker,
        ),
        (
            vec![verify_deltas(&PROGRAM, &cranker, &m, EPOCH, &leaf[..3]).unwrap()],
            cranker,
        ),
        (vec![finalize(&PROGRAM, &cranker, &m, &b)], cranker),
        (
            vec![apply_deltas(&PROGRAM, &cranker, &m, EPOCH, &leaf[3..]).unwrap()],
            cranker,
        ),
        (vec![close_batch(&PROGRAM, &cranker, &m, &b)], cranker),
        (
            vec![abort_batch(&PROGRAM, &m, &b, &relay, AbortReason::Relay)],
            cranker,
        ),
        (vec![set_halted(&PROGRAM, &admin, &m, true)], admin),
        (
            vec![
                propose_change(
                    &PROGRAM,
                    &admin,
                    &m,
                    &GovernanceChange::SetExecutors {
                        keys: (0..8).map(|_| rng.key()).collect(),
                        quorum: 3,
                    },
                )
                .unwrap(),
            ],
            admin,
        ),
        (vec![apply_change(&PROGRAM, &cranker, &m)], cranker),
        (vec![cancel_change(&PROGRAM, &admin, &m)], admin),
        (vec![accept_admin(&PROGRAM, &owner, &m)], owner),
        (
            vec![remove_executor(&PROGRAM, &admin, &m, &rng.key())],
            admin,
        ),
        (
            vec![claim_fees(&PROGRAM, &admin, &m, &vault, &ata, 9)],
            admin,
        ),
        (
            vec![reclaim_batch(&PROGRAM, &cranker, &m, &b, &relay)],
            cranker,
        ),
        (
            vec![
                system::create_account(
                    &owner,
                    &mint,
                    1,
                    82,
                    &timescales_chain::program::TOKEN_PROGRAM,
                ),
                spl::initialize_mint2(&mint, &owner, Some(&admin), 6),
                spl::create_ata_idempotent(&owner, &owner, &mint),
                spl::mint_to(&mint, &ata, &owner, 10),
                spl::initialize_account3(&vault, &mint, &m),
                system::transfer(&owner, &relay, 1),
            ],
            owner,
        ),
    ]
}

#[test]
fn every_builder_matches_real_serialization() {
    let mut rng = Rng::new(1);
    for (ixs, payer) in one_per_builder(&mut rng) {
        same_as_serialized(&ixs, &payer);
        same_as_serialized(&with_compute_budget(ixs.clone()), &payer);
        // A fee payer that is not among the signers adds a key and a
        // signature.
        same_as_serialized(&ixs, &rng.key());
    }
}

#[test]
fn random_instruction_mixes_match_real_serialization() {
    let mut rng = Rng::new(2);
    let pool: Vec<(Vec<Ix>, Key)> = one_per_builder(&mut rng);
    for _ in 0..300 {
        let mut ixs = Vec::new();
        let mut payers = Vec::new();
        for _ in 0..1 + rng.below(4) {
            let (more, payer) = &pool[usize::try_from(rng.below(pool.len() as u64)).unwrap()];
            ixs.extend(more.iter().cloned());
            payers.push(*payer);
        }
        let payer = payers[usize::try_from(rng.below(payers.len() as u64)).unwrap()];
        same_as_serialized(&ixs, &payer);
    }
}

/// PostReceipt with 0, 1 and 2 clearing prices is 1128 / 1145 /
/// 1162 bytes, 1180 / 1197 / 1214 with the compute-budget instructions in
/// front. The poster pays.
#[test]
fn post_receipt_transactions_fit_one_packet() {
    let mut rng = Rng::new(3);
    let (cranker, executor) = (rng.key(), rng.key());
    let digest = Hash32(rng.key());
    for (k, plain, budgeted) in [(0usize, 1128, 1180), (1, 1145, 1197), (2, 1162, 1214)] {
        let receipt = vec![1u8; 390 + 17 * k];
        let ixs = vec![
            ed25519_verify(&executor, &digest, &[9; 64]),
            post_receipt(&PROGRAM, &cranker, &market(), EPOCH, &[2; 283], &receipt).unwrap(),
        ];
        assert_eq!(same_as_serialized(&ixs, &cranker), plain);
        let ixs = with_compute_budget(ixs);
        assert_eq!(same_as_serialized(&ixs, &cranker), budgeted);
        assert!(budgeted <= MAX_TX_SIZE);
    }
}

#[test]
fn commit_and_cosign_transaction_sizes() {
    let mut rng = Rng::new(4);
    let (relay, cranker) = (rng.key(), rng.key());
    let digest = Hash32(rng.key());
    let commit = vec![commit_batch(&PROGRAM, &relay, &market(), 1, &digest, 1, &digest).unwrap()];
    assert_eq!(same_as_serialized(&commit, &relay), 346);
    let cosign = vec![
        ed25519_verify(&rng.key(), &digest, &[1; 64]),
        cosign_receipt(&PROGRAM, &cranker, &market(), 1).unwrap(),
    ];
    assert_eq!(same_as_serialized(&cosign, &cranker), 450);
    assert_eq!(
        same_as_serialized(&with_compute_budget(cosign), &cranker),
        502
    );
}

fn delta_tx(chunk: &[Leaf], cranker: &Key, budget: bool, verify: bool) -> Vec<Ix> {
    let ix = if verify {
        verify_deltas(&PROGRAM, cranker, &market(), EPOCH, chunk).unwrap()
    } else {
        apply_deltas(&PROGRAM, cranker, &market(), EPOCH, chunk).unwrap()
    };
    if budget {
        with_compute_budget(vec![ix])
    } else {
        vec![ix]
    }
}

/// The plan covers the leaves in order, every transaction fits, and no
/// chunk could take the next leaf.
#[track_caller]
fn check_plan(all: &[Leaf], cranker: &Key, budget: bool) -> Vec<usize> {
    let plan = plan_delta_chunks(all, cranker, budget);
    let mut next = 0;
    for range in &plan {
        assert_eq!(range.start, next);
        assert!(range.end > range.start);
        next = range.end;
        for verify in [true, false] {
            let size = same_as_serialized(
                &delta_tx(&all[range.clone()], cranker, budget, verify),
                cranker,
            );
            assert!(size <= MAX_TX_SIZE, "{range:?}: {size} bytes");
        }
        if range.end < all.len() {
            let grown = delta_tx(&all[range.start..=range.end], cranker, budget, true);
            assert!(
                wire(&grown, cranker).0 > MAX_TX_SIZE,
                "{range:?} could take one more leaf"
            );
        }
    }
    assert_eq!(next, all.len());
    plan.iter().map(|r| r.len()).collect()
}

#[test]
fn delta_chunks_fit_and_are_maximal() {
    let mut rng = Rng::new(5);
    let cranker = rng.key();
    for n in [
        0usize, 1, 2, 3, 4, 5, 8, 9, 16, 17, 33, 64, 65, 100, 128, 129, 257, 513, 1024,
    ] {
        let all = leaves(&settlement(&mut rng, n)).unwrap();
        for budget in [true, false] {
            check_plan(&all, &cranker, budget);
        }
    }
}

/// With the compute-budget instructions, 4 / 3 / 2 leaves fit when
/// their paths have 4 / 7 / 10 hashes: the first leaves of trees with 9,
/// 65 and 513 leaves. Those counts are lower bounds: 5 leaves with 3-hash
/// paths (a tree of 8) fit.
#[test]
fn delta_chunk_sizes_by_path_length() {
    let mut rng = Rng::new(6);
    let cranker = rng.key();
    for (n, p, per_tx) in [
        (8usize, 3usize, 5usize),
        (9, 4, 4),
        (65, 7, 3),
        (513, 10, 2),
    ] {
        let all = leaves(&settlement(&mut rng, n)).unwrap();
        assert!(all[..per_tx + 1].iter().all(|l| l.path.len() == p));
        assert_eq!(check_plan(&all, &cranker, true)[0], per_tx, "n = {n}");
    }
    // A full batch needs about 512 transactions per pass.
    let full = leaves(&settlement(&mut rng, 1024)).unwrap();
    let chunks = plan_delta_chunks(&full, &cranker, true);
    assert_eq!(chunks.len(), 512);
}

#[test]
fn repeated_traders_count_once() {
    let mut rng = Rng::new(7);
    let cranker = rng.key();
    let mut all = leaves(&settlement(&mut rng, 40)).unwrap();
    let trader = all[0].delta.trader;
    for leaf in all.iter_mut().step_by(2) {
        leaf.delta.trader = trader;
    }
    for budget in [true, false] {
        check_plan(&all, &cranker, budget);
    }
}
