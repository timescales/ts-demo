//! Beacon v2, with the SlotHashes sysvar written directly: not ready,
//! skipped targets, the same beacon whoever reveals and whenever, the
//! deterministic expiry, anyone-abort after it, and the relay's abort
//! window closing at `commit_slot + d`.

mod common;

use common::*;
use solana_signer::Signer;
use timescales_core::{EpochId, Hash32};

const D: u64 = 4;
const REVEAL_WINDOW: u64 = 400;

fn committed() -> (Env, u64) {
    let mut env = Env::new(Cfg::default());
    ok(env.commit_for(1, &Settlement::default()));
    let c = env.batch_view(1).commit_slot;
    (env, c)
}

fn reveal_at(env: &mut Env, slot: u64, slots: &[u64]) -> TxResult {
    env.warp(slot);
    env.set_slot_hashes(slots);
    let r = env.reveal_ix(1);
    env.crank(&[r])
}

fn expected_beacon(env: &Env, a: u64, b: u64) -> [u8; 32] {
    let v = env.batch_view(1);
    timescales_auction::beacon_v2(
        &env.market.to_bytes(),
        EpochId(1),
        &Hash32(v.root),
        v.count,
        (a, Hash32(slot_hash(a))),
        (b, Hash32(slot_hash(b))),
    )
    .0
}

#[test]
fn not_ready_until_the_second_target_exists() {
    let (mut env, c) = committed();
    let upto = |s: u64| -> Vec<u64> { (c - 100..=s).collect() };
    fails(
        reveal_at(&mut env, c + 2 * D - 1, &upto(c + 2 * D - 1)),
        E::BeaconNotReady,
    );
    fails(reveal_at(&mut env, c + D, &upto(c + D)), E::BeaconNotReady);
    ok(reveal_at(&mut env, c + 2 * D, &upto(c + 2 * D)));
    let v = env.batch_view(1);
    assert_eq!(
        (v.status, v.beacon_slot_a, v.beacon_slot_b),
        (REVEALED, c + D, c + 2 * D)
    );
    assert_eq!(v.beacon, expected_beacon(&env, c + D, c + 2 * D));
    let r = env.reveal_ix(1);
    fails(env.crank(&[r]), E::WrongStatus);
}

#[test]
fn skipped_targets_move_to_the_next_produced_slot() {
    let (mut env, c) = committed();
    // Neither target slot was produced.
    let produced: Vec<u64> = (c..=c + 40)
        .filter(|s| *s != c + D && *s != c + 2 * D && *s != c + 2 * D + 1)
        .collect();
    ok(reveal_at(&mut env, c + 40, &produced));
    let v = env.batch_view(1);
    assert_eq!(
        (v.beacon_slot_a, v.beacon_slot_b),
        (c + D + 1, c + 2 * D + 2)
    );
    assert_eq!(v.beacon, expected_beacon(&env, c + D + 1, c + 2 * D + 2));
}

#[test]
fn the_beacon_does_not_depend_on_who_reveals_or_when() {
    let (env, c) = committed();
    let mut beacons = Vec::new();
    for (i, at) in [c + 2 * D + 1, c + 2 * D + 50, c + D + REVEAL_WINDOW]
        .into_iter()
        .enumerate()
    {
        let mut fork = env.fork();
        // What a cluster holds at `at`: the last 512 slots.
        let slots: Vec<u64> = (at.saturating_sub(511)..=at).collect();
        // A different revealer each time.
        let mut revealer = fork.funded();
        for _ in 0..i {
            revealer = fork.funded();
        }
        fork.warp(at);
        fork.set_slot_hashes(&slots);
        let r = {
            let mut ix = fork.reveal_ix(1);
            ix.accounts[0] = solana_instruction::AccountMeta::new_readonly(revealer.pubkey(), true);
            ix
        };
        ok(fork.send(&[r], &[&revealer]));
        let v = fork.batch_view(1);
        assert_eq!(v.reveal_slot, at);
        beacons.push((v.beacon_slot_a, v.beacon_slot_b, v.beacon));
    }
    assert!(beacons.windows(2).all(|w| w[0] == w[1]), "{beacons:?}");
}

#[test]
fn expiry_is_deterministic_and_then_anyone_aborts() {
    let (env, c) = committed();
    let deadline = c + D + REVEAL_WINDOW;
    let all = |at: u64| -> Vec<u64> { (at - 511..=at).collect() };

    let mut last = env.fork();
    ok(reveal_at(&mut last, deadline, &all(deadline)));

    let mut late = env.fork();
    fails(
        reveal_at(&mut late, deadline + 1, &all(deadline + 1)),
        E::BeaconExpired,
    );
    let anyone = late.funded();
    ok(late.abort(1, &anyone, 3));
    let v = late.batch_view(1);
    assert_eq!((v.status, v.abort_reason), (ABORTED, 3));
    assert_eq!(late.market_view().last_settled, 1);

    // Before the deadline the expiry abort is refused, so a reveal and an
    // expiry abort can never both be valid.
    let mut early = env.fork();
    early.warp(deadline);
    let anyone = early.funded();
    fails(early.abort(1, &anyone, 3), E::NotExpired);
}

#[test]
fn the_relay_may_abort_only_before_the_first_target() {
    let (env, c) = committed();
    let mut before = env.fork();
    before.warp(c + D - 1);
    let relay = before.relay.insecure_clone();
    ok(before.abort(1, &relay, 2));
    assert_eq!(before.batch_view(1).abort_reason, 2);

    let mut at = env.fork();
    at.warp(c + D);
    let relay = at.relay.insecure_clone();
    fails(at.abort(1, &relay, 2), E::Unauthorised);
}

#[test]
fn reveal_needs_the_slot_hashes_sysvar() {
    let (mut env, c) = committed();
    env.warp(c + 3 * D);
    env.fill_slot_hashes();
    let mut r = env.reveal_ix(1);
    r.accounts[3] = solana_instruction::AccountMeta::new_readonly(
        addr(solana_program::sysvar::clock::ID.to_bytes()),
        false,
    );
    fails(env.crank(&[r]), E::InvalidAccount);
}
