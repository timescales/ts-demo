//! Attacks and edge cases: pre-funded PDAs, duplicate traders,
//! withdrawals around a batch, one batch in flight, derived market
//! ids, closed-account re-creation, CloseTrader in flight, the
//! `last_change_slot` and floor writes, and input validation.

mod common;

use common::*;
use solana_instruction::{AccountMeta, Instruction};
use solana_signer::Signer;

fn system_transfer(
    from: &solana_address::Address,
    to: &solana_address::Address,
    lamports: u64,
) -> Instruction {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: system_program(),
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data,
    }
}

#[test]
fn lamports_sent_to_pdas_do_not_block_creation() {
    let mut env = Env::bare(Cfg::default());
    // Below rent for the market (topped up), above rent for the trader.
    // A System account must itself be rent exempt, hence 1,000,000.
    env.svm.airdrop(&env.market, 1_000_000).expect("airdrop");
    let args = env.init_args();
    let creator = env.creator.insecure_clone();
    ok(env.init_market(&args, &creator));
    let m = env.account(&env.market).expect("market");
    assert_eq!(m.owner, program_id());
    assert_eq!(m.lamports, env.svm.minimum_balance_for_rent_exemption(1103));

    let victim = env.wallet(0, 0);
    env.svm
        .airdrop(&victim.pda, 10_000_000_000)
        .expect("airdrop");
    let open = env.open_trader_ix(&victim.owner());
    ok(env.send(&[open], &[&victim.kp]));
    let t = env.account(&victim.pda).expect("trader");
    assert_eq!(
        (t.owner, t.data.len(), t.lamports),
        (program_id(), 148, 10_000_000_000)
    );

    let next = env.batch_pda(1);
    env.svm.airdrop(&next, 1_000_000).expect("airdrop");
    let s = Settlement::default();
    ok(env.commit_for(1, &s));
    let b = env.account(&next).expect("batch");
    assert_eq!(b.owner, program_id());
    assert_eq!(b.lamports, env.svm.minimum_balance_for_rent_exemption(688));
}

#[test]
fn a_second_leaf_for_the_same_trader_is_refused() {
    for same_instruction in [false, true] {
        let mut env = Env::new(Cfg::default());
        let a = env.trader(100, 100);
        let s = Settlement::new(&[(a.owner(), -10, 0), (a.owner(), 10, 0)], 0);
        env.post_with_quorum(1, &s);
        if same_instruction {
            fails(env.verify(1, &s, &[0, 1]), E::DuplicateTrader);
        } else {
            ok(env.verify(1, &s, &[0]));
            fails(env.verify(1, &s, &[1]), E::DuplicateTrader);
            fails(env.verify(1, &s, &[0]), E::DuplicateLeaf);
        }
    }
}

#[test]
fn withdraw_requests_around_a_batch_never_break_it() {
    let mut env = Env::new(Cfg::default());
    let a = env.trader(0, 1_000);
    let b = env.trader(1_000, 0);
    let s = Settlement::new(&[(a.owner(), 100, -500), (b.owner(), -100, 500)], 0);
    ok(env.commit_for(1, &s));
    // Between commit and post: a asks for everything. Nothing is debited and
    // nothing is reserved for the batch already committed.
    let req = env.request_withdraw_ix(&a, 0, 1_000);
    ok(env.send(&[req], &[&a.kp]));
    assert_eq!(env.trader_view(&a.owner()).request_epoch, 1);
    ok(env.reveal(1));
    let post = env.prepare(1, &s);
    ok(env.post(1, &post));
    env.verify_all(1, &s);
    ok(env.finalize(1));
    // Between verify and apply: b asks for all its base.
    let req = env.request_withdraw_ix(&b, 1_000, 0);
    ok(env.send(&[req], &[&b.kp]));
    let wd = env.withdraw_ix(&b, false);
    fails(env.send(&[wd], &[&b.kp]), E::WithdrawLocked);
    env.apply_all(1, &s);
    let wd = env.withdraw_ix(&a, true);
    fails(env.send(&[wd], &[&a.kp]), E::WithdrawLocked);
    ok(env.close_batch(1));

    // Payouts are min(requested, balance after the batch's fills).
    let wd = env.withdraw_ix(&a, true);
    ok(env.send(&[wd], &[&a.kp]));
    assert_eq!(env.token_amount(&a.quote_ata), 500);
    let wd = env.withdraw_ix(&b, false);
    ok(env.send(&[wd], &[&b.kp]));
    assert_eq!(env.token_amount(&b.base_ata), 900);

    // A request older than the batch is reserved for it.
    let req = env.request_withdraw_ix(&b, 0, 400);
    ok(env.send(&[req], &[&b.kp]));
    let s2 = Settlement::new(&[(b.owner(), 100, -200), (a.owner(), -100, 200)], 0);
    env.post_with_quorum(2, &s2);
    fails(env.verify(2, &s2, &[0]), E::Insolvent);
}

#[test]
fn one_batch_in_flight() {
    let mut env = Env::new(Cfg::default());
    let s = Settlement::default();
    ok(env.commit_for(1, &s));
    fails(env.commit_for(2, &s), E::InFlight);
    fails(env.commit_for(3, &s), E::OutOfOrder);
    fails(env.commit_for(1, &s), E::OutOfOrder);
    let m = env.market_view();
    assert!(m.last_settled <= m.last_committed && m.last_committed <= m.last_settled + 1);
}

#[test]
fn market_ids_are_derived_from_program_creator_and_salt() {
    let mut env = Env::bare(Cfg::default());
    let creator = env.creator.insecure_clone();
    let mut args = env.init_args();
    args.market_id += 1;
    args.params = params_bytes(args.market_id, 1024);
    fails(env.init_market(&args, &creator), E::InvalidMarketId);

    let args = env.init_args();
    ok(env.init_market(&args, &creator));
    // Someone else cannot claim the same id, even with the same salt.
    let squatter = env.funded();
    fails(env.init_market(&args, &squatter), E::InvalidMarketId);
    assert_ne!(
        derive_market_id(&squatter.pubkey(), &env.salt),
        env.market_id
    );
    // Re-initialising the existing market is refused.
    fails(env.init_market(&args, &creator), E::InvalidAccount);
}

#[test]
fn closed_accounts_that_receive_lamports_stay_recreatable() {
    let mut env = Env::new(Cfg::default());
    let t = env.trader(0, 0);
    let close = env.close_trader_ix(&t);
    let refund = system_transfer(&t.owner(), &t.pda, 1_000_000);
    ok(env.send(&[close, refund], &[&t.kp]));
    let acc = env.account(&t.pda).expect("kept alive by the transfer");
    assert_eq!(
        (acc.owner, acc.data.len(), acc.lamports),
        (system_program(), 0, 1_000_000)
    );
    let open = env.open_trader_ix(&t.owner());
    ok(env.send(&[open], &[&t.kp]));
    let v = env.trader_view(&t.owner());
    assert_eq!(
        (v.base, v.quote, v.last_leaf_epoch, v.floor_epoch),
        (0, 0, 0, 0)
    );
    assert_eq!(env.account(&t.pda).expect("trader").owner, program_id());

    // A reclaimed batch that receives lamports is a plain System account.
    env.run_epoch(1, &Settlement::default());
    for e in 2..=1025 {
        env.skip_epoch(e);
    }
    let reclaim = env.reclaim_ix(1, &env.relay.pubkey());
    let refund = system_transfer(&env.cranker.pubkey(), &env.batch_pda(1), 1_000_000);
    ok(env.crank(&[reclaim, refund]));
    let acc = env
        .account(&env.batch_pda(1))
        .expect("kept alive by the transfer");
    assert_eq!(
        (acc.owner, acc.data.len(), acc.lamports),
        (system_program(), 0, 1_000_000)
    );
}

#[test]
fn close_trader_while_a_batch_is_in_flight() {
    let mut env = Env::new(Cfg::default());
    let idle = env.trader(0, 0);
    let leafed = env.trader(0, 0);
    let full = env.trader(5, 0);
    let s = Settlement::new(&[(leafed.owner(), 0, 0)], 0);
    env.post_with_quorum(1, &s);
    env.verify_all(1, &s);
    let close = env.close_trader_ix(&idle);
    ok(env.send(&[close], &[&idle.kp]));
    let close = env.close_trader_ix(&leafed);
    fails(env.send(&[close], &[&leafed.kp]), E::InFlight);
    let close = env.close_trader_ix(&full);
    fails(env.send(&[close], &[&full.kp]), E::AccountNotEmpty);
    ok(env.finalize(1));
    env.apply_all(1, &s);
    ok(env.close_batch(1));
    let close = env.close_trader_ix(&leafed);
    ok(env.send(&[close], &[&leafed.kp]));
    let stranger = env.funded();
    let close = env.close_trader_ix(&full);
    let mut forged = close.clone();
    forged.accounts[0] = AccountMeta::new(stranger.pubkey(), true);
    fails(env.send(&[forged], &[&stranger]), E::Unauthorised);
}

#[test]
fn every_balance_change_writes_last_change_slot_and_the_floor() {
    let mut env = Env::new(Cfg::default());
    let dep = env.trader(1_000, 500);
    let req = env.trader(300, 300);
    let cancel = env.trader(200, 200);
    let wd = env.trader(400, 400);
    let applied = env.trader(50, 50);
    let other = env.trader(50, 50);
    for (ata, mint) in [
        (dep.base_ata, env.base_mint),
        (dep.quote_ata, env.quote_mint),
    ] {
        let acc = token_account(&mint, &dep.owner(), 1_000);
        env.svm.set_account(ata, acc).expect("top up");
    }
    // An older request: reserved for the coming batch, withdrawable during it.
    let r = env.request_withdraw_ix(&wd, 0, 100);
    ok(env.send(&[r], &[&wd.kp]));
    let r = env.request_withdraw_ix(&cancel, 0, 150);
    ok(env.send(&[r], &[&cancel.kp]));

    let s = Settlement::new(&[(applied.owner(), 5, -5), (other.owner(), -5, 5)], 0);
    ok(env.commit_for(1, &s));
    let at_commit: Vec<(u64, u64)> = [&dep, &req, &cancel, &wd, &applied]
        .iter()
        .map(|t| env.trader_view(&t.owner()).available(1))
        .collect();

    let step = |env: &mut Env, t: &TraderAcc, ixn: Instruction| {
        env.advance(3);
        ok(env.send(&[ixn], &[&t.kp]));
        let v = env.trader_view(&t.owner());
        assert_eq!(v.last_change_slot, env.slot());
        assert_eq!(v.floor_epoch, 1);
        v
    };
    let ixn = env.deposit_ix(&dep, true, 70);
    let v = step(&mut env, &dep, ixn);
    assert_eq!((v.floor_base, v.floor_quote), at_commit[0]);
    let ixn = env.deposit_ix(&dep, false, 30);
    let v = step(&mut env, &dep, ixn);
    assert_eq!(
        (v.floor_base, v.floor_quote),
        at_commit[0],
        "first change only"
    );

    let ixn = env.request_withdraw_ix(&req, 300, 0);
    let v = step(&mut env, &req, ixn);
    assert_eq!((v.floor_base, v.floor_quote), at_commit[1]);

    let ixn = env.cancel_request_ix(&cancel);
    let v = step(&mut env, &cancel, ixn);
    assert_eq!((v.floor_base, v.floor_quote), at_commit[2]);
    assert_eq!(at_commit[2], (200, 50));

    let ixn = env.withdraw_ix(&wd, true);
    let v = step(&mut env, &wd, ixn);
    assert_eq!((v.floor_base, v.floor_quote), at_commit[3]);
    assert_eq!((v.quote, at_commit[3]), (300, (400, 300)));

    let late = env.wallet(0, 0);
    env.advance(2);
    let open = env.open_trader_ix(&late.owner());
    ok(env.send(&[open], &[&late.kp]));
    let v = env.trader_view(&late.owner());
    assert_eq!(v.last_change_slot, env.slot());
    assert_eq!((v.floor_epoch, v.floor_base, v.floor_quote), (0, 0, 0));

    ok(env.reveal(1));
    let post = env.prepare(1, &s);
    ok(env.post(1, &post));
    env.verify_all(1, &s);
    ok(env.finalize(1));
    env.advance(1);
    env.apply_all(1, &s);
    let v = env.trader_view(&applied.owner());
    assert_eq!(v.last_change_slot, env.slot());
    assert_eq!(
        (v.floor_epoch, v.floor_base, v.floor_quote),
        (1, at_commit[4].0, at_commit[4].1)
    );
    assert_eq!((v.base, v.quote), (55, 45));

    // With nothing in flight the floor is left alone.
    ok(env.close_batch(1));
    let ixn = env.deposit_ix(&dep, true, 1);
    env.advance(1);
    ok(env.send(&[ixn], &[&dep.kp]));
    assert_eq!(env.trader_view(&dep.owner()).floor_epoch, 1);
}

#[test]
fn trader_instruction_validation() {
    let mut env = Env::new(Cfg::default());
    let a = env.trader(100, 100);
    let b = env.trader(0, 0);

    let req = env.request_withdraw_ix(&a, 0, 0);
    fails(env.send(&[req], &[&a.kp]), E::NothingToWithdraw);
    let req = env.request_withdraw_ix(&a, 101, 0);
    fails(env.send(&[req], &[&a.kp]), E::Insolvent);
    let req = env.request_withdraw_ix(&a, 10, 0);
    ok(env.send(&[req], &[&a.kp]));
    let req = env.request_withdraw_ix(&a, 0, 10);
    fails(env.send(&[req], &[&a.kp]), E::WithdrawPending);
    let cancel = env.cancel_request_ix(&a);
    ok(env.send(&[cancel], &[&a.kp]));
    let wd = env.withdraw_ix(&a, false);
    fails(env.send(&[wd], &[&a.kp]), E::NothingToWithdraw);
    let close = env.close_trader_ix(&a);
    fails(env.send(&[close], &[&a.kp]), E::AccountNotEmpty);

    // Someone else's account, a zero amount, a wrong vault.
    let mut forged = env.deposit_ix(&a, true, 1);
    forged.accounts[0] = AccountMeta::new_readonly(b.owner(), true);
    fails(env.send(&[forged], &[&b.kp]), E::Unauthorised);
    let zero = env.deposit_ix(&a, true, 0);
    fails(env.send(&[zero], &[&a.kp]), E::InvalidInstruction);
    let mut wrong_vault = env.deposit_ix(&a, true, 1);
    wrong_vault.accounts[4] = AccountMeta::new(env.base_vault, false);
    fails(env.send(&[wrong_vault], &[&a.kp]), E::InvalidAccount);
    let mut bad_flag = env.deposit_ix(&a, true, 1);
    bad_flag.data[1] = 2;
    fails(env.send(&[bad_flag], &[&a.kp]), E::InvalidInstruction);
    let unknown = ix(vec![24], vec![]);
    fails(env.send(&[unknown], &[&a.kp]), E::InvalidInstruction);
    let mut trailing = env.cancel_request_ix(&a);
    trailing.data.push(0);
    fails(env.send(&[trailing], &[&a.kp]), E::InvalidInstruction);

    // A v1 account (or any non-Market data) in the market slot.
    let mut fake = env.account(&env.market).expect("market");
    fake.data[0] = 0x01;
    let fake_addr = solana_address::Address::new_unique();
    env.svm.set_account(fake_addr, fake).expect("set");
    let mut v1 = env.cancel_request_ix(&a);
    v1.accounts[1] = AccountMeta::new_readonly(fake_addr, false);
    fails(env.send(&[v1], &[&a.kp]), E::InvalidAccount);

    // Deposits are capped at i64::MAX.
    let rich = env.wallet(0, u64::MAX);
    let open = env.open_trader_ix(&rich.owner());
    ok(env.send(&[open], &[&rich.kp]));
    let cap = env.deposit_ix(&rich, true, i64::MAX as u64);
    ok(env.send(&[cap], &[&rich.kp]));
    let over = env.deposit_ix(&rich, true, 1);
    fails(env.send(&[over], &[&rich.kp]), E::BalanceCap);
}

#[test]
fn balance_overflow_is_refused_at_verify_and_apply() {
    let mut env = Env::new(Cfg::default());
    let a = env.trader(10, 10);
    let b = env.trader(10, 10);
    let s = Settlement::new(&[(a.owner(), 2, 0), (b.owner(), -2, 0)], 0);
    env.post_with_quorum(1, &s);
    // Unreachable with real vaults. Written directly to reach the
    // defence-in-depth check.
    env.poke(&a.pda, 68, &(u64::MAX - 1).to_le_bytes());
    fails(env.verify(1, &s, &[0]), E::Overflow);
    env.poke(&a.pda, 68, &10u64.to_le_bytes());
    env.verify_all(1, &s);
    ok(env.finalize(1));
    env.poke(&a.pda, 68, &(u64::MAX - 1).to_le_bytes());
    fails(env.apply(1, &s, &[0]), E::Overflow);
    env.poke(&a.pda, 68, &10u64.to_le_bytes());
    env.poke(&b.pda, 68, &1u64.to_le_bytes());
    fails(env.apply(1, &s, &[1]), E::Insolvent);
}

#[test]
fn commit_validation() {
    let mut env = Env::new(Cfg {
        max_envelopes: 8,
        ..Cfg::default()
    });
    let root = [7u8; 32];
    fails(env.commit(1, &root, 0), E::InvalidBatchCount);
    fails(env.commit(1, &root, 9), E::InvalidBatchCount);
    fails(env.commit(1, &[0; 32], 1), E::InvalidInstruction);
    let stranger = env.funded();
    let mut forged = env.commit_ix(1, &root, 1, &terms());
    forged.accounts[0] = AccountMeta::new(stranger.pubkey(), true);
    fails(env.send(&[forged], &[&stranger]), E::Unauthorised);
    ok(env.commit(1, &root, 8));
    let b = env.batch_view(1);
    assert_eq!(
        (b.status, b.epoch, b.root, b.count, b.commit_slot),
        (COMMITTED, 1, root, 8, env.slot())
    );
    assert_eq!(
        key_at(&env.account(&env.batch_pda(1)).expect("batch").data, 84),
        terms()
    );
    assert_eq!(
        key_at(&env.account(&env.batch_pda(1)).expect("batch").data, 8),
        env.market.to_bytes()
    );
}

#[test]
fn init_market_validation() {
    type Mutation = Box<dyn Fn(&mut InitArgs)>;
    let cases: Vec<(&str, Mutation, E)> = vec![
        (
            "no executors",
            Box::new(|a| a.executors.clear()),
            E::InvalidConfig,
        ),
        (
            "nine executors",
            Box::new(|a| a.executors = (0..9).map(|i| [i + 1; 32]).collect()),
            E::InvalidConfig,
        ),
        (
            "duplicate executors",
            Box::new(|a| a.executors = vec![[1; 32], [1; 32]]),
            E::InvalidConfig,
        ),
        (
            "zero executor",
            Box::new(|a| a.executors = vec![[0; 32]]),
            E::InvalidConfig,
        ),
        (
            "quorum above n",
            Box::new(|a| a.quorum = 2),
            E::InvalidConfig,
        ),
        ("zero quorum", Box::new(|a| a.quorum = 0), E::InvalidConfig),
        (
            "zero admin",
            Box::new(|a| a.admin = [0; 32]),
            E::InvalidConfig,
        ),
        (
            "zero relay",
            Box::new(|a| a.relay = [0; 32]),
            E::InvalidConfig,
        ),
        (
            "zero committee",
            Box::new(|a| a.committee_digest = [0; 32]),
            E::InvalidConfig,
        ),
        ("d = 3", Box::new(|a| a.beacon_delay = 3), E::InvalidConfig),
        (
            "d = 65",
            Box::new(|a| a.beacon_delay = 65),
            E::InvalidConfig,
        ),
        (
            "exec 149",
            Box::new(|a| a.exec_timeout = 149),
            E::InvalidConfig,
        ),
        (
            "settle < 2 exec",
            Box::new(|a| a.settle_timeout = 299),
            E::InvalidConfig,
        ),
        (
            "timelock above max",
            Box::new(|a| a.timelock = 2_592_001),
            E::InvalidConfig,
        ),
        (
            "params of another market",
            Box::new(|a| a.params[0] ^= 1),
            E::InvalidParams,
        ),
        (
            "1025 envelopes",
            Box::new(|a| a.params[31..35].copy_from_slice(&1025u32.to_le_bytes())),
            E::InvalidParams,
        ),
        ("poseidon", Box::new(|a| a.params[45] = 1), E::InvalidParams),
        (
            "zero tick",
            Box::new(|a| a.params[16..24].copy_from_slice(&0u64.to_le_bytes())),
            E::InvalidParams,
        ),
    ];
    for (name, mutate, err) in cases {
        let mut env = Env::bare(Cfg::default());
        let mut args = env.init_args();
        mutate(&mut args);
        let creator = env.creator.insecure_clone();
        let r = env.init_market(&args, &creator);
        assert!(r.is_err(), "{name}");
        fails(r, err);
    }
}

#[test]
fn init_market_token_account_validation() {
    type Corrupt = Box<dyn Fn(&mut Env) -> (solana_address::Address, solana_address::Address)>;
    let cases: Vec<(&str, Corrupt)> = vec![
        (
            "vault with a delegate",
            Box::new(|env| {
                let mut v = env.account(&env.base_vault).expect("vault");
                v.data[72] = 1;
                env.svm.set_account(env.base_vault, v).expect("set");
                (env.base_vault, env.quote_vault)
            }),
        ),
        (
            "vault with a close authority",
            Box::new(|env| {
                let mut v = env.account(&env.quote_vault).expect("vault");
                v.data[129] = 1;
                env.svm.set_account(env.quote_vault, v).expect("set");
                (env.base_vault, env.quote_vault)
            }),
        ),
        (
            "vault owned by someone else",
            Box::new(|env| {
                let v = solana_address::Address::new_unique();
                let owner = solana_address::Address::new_unique();
                env.svm
                    .set_account(v, token_account(&env.base_mint, &owner, 0))
                    .expect("set");
                (v, env.quote_vault)
            }),
        ),
        (
            "vault of the wrong mint",
            Box::new(|env| (env.quote_vault, env.quote_vault)),
        ),
        (
            "same vault twice",
            Box::new(|env| (env.base_vault, env.base_vault)),
        ),
        (
            "frozen vault",
            Box::new(|env| {
                let mut v = env.account(&env.base_vault).expect("vault");
                v.data[108] = 2;
                env.svm.set_account(env.base_vault, v).expect("set");
                (env.base_vault, env.quote_vault)
            }),
        ),
        (
            "uninitialized mint",
            Box::new(|env| {
                let mut m = env.account(&env.base_mint).expect("mint");
                m.data[45] = 0;
                env.svm.set_account(env.base_mint, m).expect("set");
                (env.base_vault, env.quote_vault)
            }),
        ),
        (
            "same mint twice",
            Box::new(|env| {
                env.quote_mint = env.base_mint;
                (env.base_vault, env.quote_vault)
            }),
        ),
    ];
    for (name, corrupt) in cases {
        let mut env = Env::bare(Cfg::default());
        let (bv, qv) = corrupt(&mut env);
        let args = env.init_args();
        let creator = env.creator.insecure_clone();
        let ixn = env.init_market_ix_with(&args, &creator.pubkey(), bv, qv);
        let r = env.send(&[ixn], &[&creator]);
        assert!(r.is_err(), "{name}");
        fails(r, E::InvalidTokenAccount);
    }
}

#[test]
fn proofs_conservation_and_completeness() {
    let mut env = Env::new(Cfg::default());
    let a = env.trader(100, 100);
    let b = env.trader(100, 100);
    let c = env.trader(100, 100);

    // A conserving batch: tampered leaves and paths fail their proofs.
    let s = Settlement::new(&[(a.owner(), 5, -5), (b.owner(), -5, 5)], 0);
    env.post_with_quorum(1, &s);
    let mut tampered = env.verify_ix(1, &s, &[0]);
    tampered.data[2 + 4 + 32] ^= 1;
    fails(env.crank(&[tampered]), E::BadProof);
    let mut wrong_path = env.verify_ix(1, &s, &[0]);
    let last = wrong_path.data.len() - 1;
    wrong_path.data[last] ^= 1;
    fails(env.crank(&[wrong_path]), E::BadProof);
    let mut out_of_range = env.verify_ix(1, &s, &[1]);
    out_of_range.data[2..6].copy_from_slice(&2u32.to_le_bytes());
    fails(env.crank(&[out_of_range]), E::BadProof);
    fails(env.apply(1, &s, &[0]), E::WrongStatus);
    ok(env.verify(1, &s, &[0]));
    fails(env.finalize(1), E::Incomplete);
    ok(env.verify(1, &s, &[1]));
    ok(env.finalize(1));
    fails(env.verify(1, &s, &[0]), E::WrongStatus);
    ok(env.apply(1, &s, &[0]));
    fails(env.close_batch(1), E::Incomplete);
    let mut tampered = env.apply_ix(1, &s, &[1]);
    tampered.data[2 + 4 + 32 + 8] ^= 1;
    fails(env.crank(&[tampered]), E::BadProof);
    fails(env.apply(1, &s, &[0]), E::DuplicateLeaf);
    ok(env.apply(1, &s, &[1]));
    ok(env.close_batch(1));
    fails(env.close_batch(1), E::WrongStatus);

    // Signed by a registered executor but not conserving: base, then fees.
    for (deltas, fees) in [
        (vec![(a.owner(), 5, 0), (c.owner(), -4, 0)], 0),
        (vec![(a.owner(), 0, -10), (c.owner(), 0, 5)], 4),
    ] {
        let mut fork = env.fork();
        let s = Settlement::new(&deltas, fees);
        fork.post_with_quorum(2, &s);
        fork.verify_all(2, &s);
        fails(fork.finalize(2), E::NotConserved);
    }
}
