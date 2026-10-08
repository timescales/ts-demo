//! Governance: timelocked changes, between-batches kinds, `ChangeDue`
//! including the atomic `[CloseBatch, CommitBatch]` starvation attempt,
//! `SetTimelock` on a localnet build, committee rotation, the two-step
//! admin, immediate halt and executor removal, the halt matrix row by row
//! and fee claims.

mod common;

use common::*;
use solana_signer::Signer;

const SET_RELAY: u8 = 1;
const SET_EXECUTORS: u8 = 2;
const SET_COMMITTEE: u8 = 3;
const SET_ADMIN: u8 = 4;
const SET_TIMINGS: u8 = 5;
const SET_TIMELOCK: u8 = 6;

fn timings(d: u16, exec: u64, settle: u64) -> Vec<u8> {
    let mut p = d.to_le_bytes().to_vec();
    p.extend_from_slice(&exec.to_le_bytes());
    p.extend_from_slice(&settle.to_le_bytes());
    p
}

fn executors_payload(keys: &[[u8; 32]], quorum: u8) -> Vec<u8> {
    let mut p = vec![keys.len() as u8];
    for k in keys {
        p.extend_from_slice(k);
    }
    p.push(quorum);
    p
}

fn propose(env: &mut Env, kind: u8, payload: &[u8]) -> TxResult {
    let p = env.propose_ix(&env.admin.pubkey(), kind, payload);
    env.admin_send(p)
}

fn apply(env: &mut Env) -> TxResult {
    let a = env.apply_change_ix(&env.cranker.pubkey());
    env.crank(&[a])
}

#[test]
fn propose_wait_apply_cancel() {
    let mut env = Env::new(Cfg::default());
    let new_relay = env.funded().pubkey().to_bytes();
    fails(apply(&mut env), E::NoPendingChange);
    let c = env.cancel_change_ix(&env.admin.pubkey());
    fails(env.admin_send(c), E::NoPendingChange);

    let stranger = env.funded();
    let p = env.propose_ix(&stranger.pubkey(), SET_RELAY, &new_relay);
    fails(env.send(&[p], &[&stranger]), E::Unauthorised);

    ok(propose(&mut env, SET_RELAY, &new_relay));
    let m = env.market_view();
    assert_eq!(
        (m.pending_kind, m.pending_eta),
        (SET_RELAY, env.slot() + 20)
    );
    fails(propose(&mut env, SET_RELAY, &new_relay), E::ChangePending);
    env.advance(19);
    fails(apply(&mut env), E::Timelocked);
    env.advance(1);
    ok(apply(&mut env));
    let m = env.market_view();
    assert_eq!((m.relay, m.pending_kind), (new_relay, 0));

    ok(propose(&mut env, SET_RELAY, &[7; 32]));
    let c = env.cancel_change_ix(&env.admin.pubkey());
    ok(env.admin_send(c));
    assert_eq!(env.market_view().pending_kind, 0);
    env.advance(100);
    fails(apply(&mut env), E::NoPendingChange);
}

#[test]
fn payloads_are_validated() {
    let mut env = Env::new(Cfg::default());
    let k = |i: u8| [i; 32];
    let cases: Vec<(u8, Vec<u8>)> = vec![
        (0, vec![]),
        (7, vec![1; 8]),
        (SET_RELAY, vec![0; 32]),
        (SET_RELAY, vec![1; 31]),
        (SET_RELAY, vec![1; 33]),
        (SET_EXECUTORS, executors_payload(&[], 1)),
        (SET_EXECUTORS, executors_payload(&[k(1), k(1)], 1)),
        (SET_EXECUTORS, executors_payload(&[k(1), [0; 32]], 1)),
        (SET_EXECUTORS, executors_payload(&[k(1)], 2)),
        (SET_EXECUTORS, executors_payload(&[k(1)], 0)),
        (SET_COMMITTEE, vec![0; 32]),
        (SET_ADMIN, vec![0; 32]),
        (SET_TIMINGS, timings(3, 150, 300)),
        (SET_TIMINGS, timings(4, 216_001, 1_296_000)),
        (SET_TIMINGS, timings(4, 150, 299)),
        (SET_TIMELOCK, 2_592_001u64.to_le_bytes().to_vec()),
        (SET_TIMELOCK, vec![0; 7]),
    ];
    for (kind, payload) in cases {
        let r = propose(&mut env, kind, &payload);
        assert!(r.is_err(), "kind {kind} payload {payload:?}");
        fails(r, E::InvalidConfig);
    }
    // Longer than the 262-byte payload slot: malformed instruction.
    fails(
        propose(&mut env, SET_RELAY, &[1; 263]),
        E::InvalidInstruction,
    );
    ok(propose(
        &mut env,
        SET_EXECUTORS,
        &executors_payload(&(1..=8).map(k).collect::<Vec<_>>(), 8),
    ));
}

#[test]
fn between_batches_kinds_wait_for_the_batch_in_flight() {
    for (kind, payload) in [
        (SET_RELAY, vec![9; 32]),
        (SET_EXECUTORS, executors_payload(&[[9; 32]], 1)),
        (SET_COMMITTEE, vec![9; 32]),
        (SET_TIMINGS, timings(8, 750, 9_000)),
    ] {
        let mut env = Env::new(Cfg::default());
        ok(propose(&mut env, kind, &payload));
        ok(env.commit_for(1, &Settlement::default()));
        env.advance(20);
        fails(apply(&mut env), E::InFlight);
        let admin = env.admin.insecure_clone();
        ok(env.abort(1, &admin, 1));
        ok(apply(&mut env));
    }
    // Admin and timelock changes apply in flight.
    for (kind, payload) in [
        (SET_ADMIN, vec![9; 32]),
        (SET_TIMELOCK, 100u64.to_le_bytes().to_vec()),
    ] {
        let mut env = Env::new(Cfg::default());
        ok(propose(&mut env, kind, &payload));
        ok(env.commit_for(1, &Settlement::default()));
        env.advance(20);
        ok(apply(&mut env));
    }
}

#[test]
fn a_due_change_cannot_be_starved() {
    let mut env = Env::new(Cfg::default());
    let s = Settlement::default();
    env.post_with_quorum(1, &s);
    env.verify_all(1, &s);
    ok(env.finalize(1));
    let new_relay = env.funded();
    ok(propose(&mut env, SET_RELAY, &new_relay.pubkey().to_bytes()));

    // Not yet due: closing and committing in one transaction works.
    let relay = env.relay.insecure_clone();
    let close_by_relay = |env: &Env| {
        let mut close = env.close_batch_ix(1);
        close.accounts[0] = solana_instruction::AccountMeta::new_readonly(relay.pubkey(), true);
        close
    };
    let mut early = env.fork();
    let close = close_by_relay(&early);
    let commit = early.commit_ix(2, &[2; 32], 1, &terms());
    ok(early.send(&[close, commit], &[&relay]));

    env.advance(20);
    let close = close_by_relay(&env);
    let commit = env.commit_ix(2, &[2; 32], 1, &terms());
    let r = env.send(&[close, commit], &[&relay]);
    assert_eq!(r.as_ref().err().and_then(|f| f.index), Some(1));
    fails(r, E::ChangeDue);
    ok(env.close_batch(1));
    fails(env.commit(2, &[2; 32], 1), E::ChangeDue);
    ok(apply(&mut env));
    env.relay = new_relay;
    ok(env.commit(2, &[2; 32], 1));
    // A due admin or timelock change does not block commits.
    let mut env2 = Env::new(Cfg::default());
    ok(propose(&mut env2, SET_ADMIN, &[5; 32]));
    env2.advance(20);
    ok(env2.commit_for(1, &s));
}

#[test]
fn timelock_changes() {
    let mut env = Env::new(Cfg::default());
    // The loaded program is the localnet build (scripts/build-program.sh),
    // whose minimum is 0. The production minimum is a unit test of
    // `constants::MIN_TIMELOCK`.
    ok(propose(&mut env, SET_TIMELOCK, &0u64.to_le_bytes()));
    // A decrease waits for the old timelock.
    env.advance(19);
    fails(apply(&mut env), E::Timelocked);
    env.advance(1);
    ok(apply(&mut env));
    assert_eq!(env.market_view().timelock, 0);
    ok(propose(&mut env, SET_TIMELOCK, &2_592_000u64.to_le_bytes()));
    ok(apply(&mut env));
    assert_eq!(env.market_view().timelock, 2_592_000);

    // InitMarket accepts timelock 0 on this build too.
    let mut env = Env::new(Cfg {
        timelock: 0,
        ..Cfg::default()
    });
    assert_eq!(env.market_view().timelock, 0);
    ok(propose(&mut env, SET_RELAY, &[3; 32]));
    ok(apply(&mut env));
}

#[test]
fn committee_rotation_keeps_the_previous_digest() {
    let mut env = Env::new(Cfg::default());
    let first = env.committee;
    ok(propose(&mut env, SET_COMMITTEE, &[0xd2; 32]));
    env.advance(20);
    ok(apply(&mut env));
    let m = env.market_view();
    assert_eq!(
        (m.committee_digest, m.prev_committee_digest),
        ([0xd2; 32], first)
    );
    ok(propose(&mut env, SET_COMMITTEE, &[0xd3; 32]));
    env.advance(20);
    ok(apply(&mut env));
    let m = env.market_view();
    assert_eq!(
        (m.committee_digest, m.prev_committee_digest),
        ([0xd3; 32], [0xd2; 32])
    );
}

#[test]
fn executors_and_timings_are_rewritten() {
    let mut env = Env::new(Cfg {
        executors: 3,
        quorum: 2,
        ..Cfg::default()
    });
    ok(propose(
        &mut env,
        SET_EXECUTORS,
        &executors_payload(&[[0xe1; 32], [0xe2; 32]], 1),
    ));
    env.advance(20);
    ok(apply(&mut env));
    let m = env.market_view();
    assert_eq!((m.executor_count, m.receipt_quorum), (2, 1));
    assert_eq!(&m.executors[..3], &[[0xe1; 32], [0xe2; 32], [0; 32]]);
    ok(propose(&mut env, SET_TIMINGS, &timings(8, 750, 9_000)));
    env.advance(20);
    ok(apply(&mut env));
    let m = env.market_view();
    assert_eq!(
        (m.beacon_delay, m.exec_timeout, m.settle_timeout),
        (8, 750, 9_000)
    );
}

#[test]
fn admin_is_two_step() {
    let mut env = Env::new(Cfg::default());
    let next = env.funded();
    ok(propose(&mut env, SET_ADMIN, &next.pubkey().to_bytes()));
    env.advance(20);
    ok(apply(&mut env));
    let m = env.market_view();
    assert_eq!(
        (m.admin, m.pending_admin),
        (env.admin.pubkey().to_bytes(), next.pubkey().to_bytes())
    );
    let stranger = env.funded();
    let a = env.accept_admin_ix(&stranger.pubkey());
    fails(env.send(&[a], &[&stranger]), E::NotPendingAdmin);
    let a = env.accept_admin_ix(&next.pubkey());
    ok(env.send(&[a], &[&next]));
    let m = env.market_view();
    assert_eq!(
        (m.admin, m.pending_admin),
        (next.pubkey().to_bytes(), [0; 32])
    );
    let a = env.accept_admin_ix(&next.pubkey());
    fails(env.send(&[a], &[&next]), E::NotPendingAdmin);
    let h = env.set_halted_ix(&env.admin.pubkey(), true);
    fails(env.admin_send(h), E::Unauthorised);
    env.admin = next;
    let h = env.set_halted_ix(&env.admin.pubkey(), true);
    ok(env.admin_send(h));
}

#[test]
fn halt_and_remove_executor_are_immediate() {
    let mut env = Env::new(Cfg {
        executors: 2,
        quorum: 1,
        ..Cfg::default()
    });
    let h = env.set_halted_ix(&env.admin.pubkey(), true);
    ok(env.admin_send(h));
    assert!(env.market_view().halted);
    let mut bad = env.set_halted_ix(&env.admin.pubkey(), true);
    bad.data[1] = 2;
    fails(env.admin_send(bad), E::InvalidInstruction);
    let h = env.set_halted_ix(&env.admin.pubkey(), false);
    ok(env.admin_send(h));
    assert!(!env.market_view().halted);

    let key = executor_id(&executor_key(1));
    let r = env.remove_executor_ix(&env.admin.pubkey(), &key);
    ok(env.admin_send(r));
    let m = env.market_view();
    assert_eq!(
        (m.executor_count, m.receipt_quorum, m.executors[1]),
        (1, 1, [0; 32])
    );
    let r = env.remove_executor_ix(&env.admin.pubkey(), &key);
    fails(env.admin_send(r), E::UnknownExecutor);
    let r = env.remove_executor_ix(&env.admin.pubkey(), &[0; 32]);
    fails(env.admin_send(r), E::UnknownExecutor);
    let stranger = env.funded();
    let r = env.remove_executor_ix(&stranger.pubkey(), &executor_id(&executor_key(0)));
    fails(env.send(&[r], &[&stranger]), E::Unauthorised);
}

fn halt(env: &mut Env) {
    let h = env.set_halted_ix(&env.admin.pubkey(), true);
    ok(env.admin_send(h));
}

#[test]
fn halt_matrix() {
    let mut env = Env::new(Cfg {
        executors: 2,
        quorum: 2,
        ..Cfg::default()
    });
    let a = env.trader(100, 100);
    let b = env.trader(100, 100);
    let s = Settlement::new(&[(a.owner(), 1, -1), (b.owner(), -1, 1)], 0);

    // Refused while halted.
    let mut f = env.fork();
    halt(&mut f);
    let d = f.deposit_ix(&a, true, 1);
    fails(f.send(&[d], &[&a.kp]), E::Halted);
    fails(f.commit_for(1, &s), E::Halted);

    let mut revealed = env.fork();
    ok(revealed.commit_for(1, &s));
    // RevealBeacon is allowed while halted.
    let mut f = revealed.fork();
    halt(&mut f);
    ok(f.reveal(1));
    ok(revealed.reveal(1));
    let mut f = revealed.fork();
    let post = f.prepare(1, &s);
    halt(&mut f);
    fails(f.post(1, &post), E::Halted);

    let mut posted = revealed.fork();
    let post = posted.prepare(1, &s);
    ok(posted.post(1, &post));
    let mut f = posted.fork();
    halt(&mut f);
    fails(f.cosign(1, 1), E::Halted);
    ok(posted.cosign(1, 1));
    let mut f = posted.fork();
    halt(&mut f);
    fails(f.verify(1, &s, &[0]), E::Halted);
    posted.verify_all(1, &s);
    let mut f = posted.fork();
    halt(&mut f);
    fails(f.finalize(1), E::Halted);
    ok(posted.finalize(1));
    let mut f = posted.fork();
    halt(&mut f);
    fails(f.apply(1, &s, &[0]), E::Halted);
    // Once applying has started it finishes, and the batch closes.
    ok(posted.apply(1, &s, &[0]));
    halt(&mut posted);
    ok(posted.apply(1, &s, &[1]));
    ok(posted.close_batch(1));

    // Exits and governance while halted.
    let late = posted.wallet(5, 0);
    let open = posted.open_trader_ix(&late.owner());
    ok(posted.send(&[open], &[&late.kp]));
    let r = posted.request_withdraw_ix(&a, 0, 10);
    ok(posted.send(&[r], &[&a.kp]));
    let c = posted.cancel_request_ix(&a);
    ok(posted.send(&[c], &[&a.kp]));
    let r = posted.request_withdraw_ix(&a, 0, 10);
    ok(posted.send(&[r], &[&a.kp]));
    let w = posted.withdraw_ix(&a, true);
    ok(posted.send(&[w], &[&a.kp]));
    let close = posted.close_trader_ix(&late);
    ok(posted.send(&[close], &[&late.kp]));
    ok(propose(&mut posted, SET_TIMELOCK, &30u64.to_le_bytes()));
    let c = posted.cancel_change_ix(&posted.admin.pubkey());
    ok(posted.admin_send(c));
    ok(propose(&mut posted, SET_RELAY, &[4; 32]));
    posted.advance(20);
    ok(apply(&mut posted));
    let r = posted.remove_executor_ix(&posted.admin.pubkey(), &executor_id(&executor_key(1)));
    ok(posted.admin_send(r));
    let dest = posted.wallet(0, 0);
    let claim = posted.claim_fees_ix(&posted.admin.pubkey(), &dest.quote_ata, 0);
    ok(posted.admin_send(claim));
    assert!(posted.market_view().halted);

    // Every abort reason is allowed while halted.
    let mut f = revealed.fork();
    halt(&mut f);
    let admin = f.admin.insecure_clone();
    ok(f.abort(1, &admin, 1));
}

#[test]
fn reclaim_is_allowed_while_halted() {
    let mut env = Env::new(Cfg::default());
    for e in 1..=1025 {
        env.skip_epoch(e);
    }
    halt(&mut env);
    let r = env.reclaim_ix(1, &env.relay.pubkey());
    ok(env.crank(&[r]));
}

#[test]
fn fee_claims_conserve_the_vault() {
    let mut env = Env::new(Cfg::default());
    let a = env.trader(0, 1_000);
    let b = env.trader(100, 0);
    let s = Settlement::new(&[(a.owner(), 10, -110), (b.owner(), -10, 100)], 10);
    env.run_epoch(1, &s);
    let dest = env.wallet(0, 0);
    let vault = env.token_amount(&env.quote_vault);
    let stranger = env.funded();
    let c = env.claim_fees_ix(&stranger.pubkey(), &dest.quote_ata, 4);
    fails(env.send(&[c], &[&stranger]), E::Unauthorised);
    let mut wrong = env.claim_fees_ix(&env.admin.pubkey(), &dest.quote_ata, 4);
    wrong.accounts[2] = solana_instruction::AccountMeta::new(env.base_vault, false);
    fails(env.admin_send(wrong), E::InvalidAccount);
    let c = env.claim_fees_ix(&env.admin.pubkey(), &dest.quote_ata, 4);
    ok(env.admin_send(c));
    let c = env.claim_fees_ix(&env.admin.pubkey(), &dest.quote_ata, 7);
    fails(env.admin_send(c), E::Insolvent);
    let c = env.claim_fees_ix(&env.admin.pubkey(), &dest.quote_ata, 6);
    ok(env.admin_send(c));
    let m = env.market_view();
    assert_eq!((m.fees_accrued, m.fees_claimed), (10, 10));
    assert_eq!(env.token_amount(&env.quote_vault), vault - 10);
    assert_eq!(env.token_amount(&dest.quote_ata), 10);
    let quotes = env.trader_view(&a.owner()).quote + env.trader_view(&b.owner()).quote;
    assert_eq!(
        env.token_amount(&env.quote_vault),
        quotes + m.fees_accrued - m.fees_claimed
    );
}
