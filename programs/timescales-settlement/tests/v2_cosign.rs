//! Executor co-signatures: with quorum 2, nothing is verified or
//! finalized before a valid co-signature. Wrong digests, duplicates, unknown
//! and removed co-signers are rejected. A removed executor's signature stops
//! counting.

mod common;

use common::*;
use solana_signer::Signer;

fn posted(empty: bool) -> (Env, Settlement) {
    let mut env = Env::new(Cfg {
        executors: 3,
        quorum: 2,
        ..Cfg::default()
    });
    let s = if empty {
        Settlement::default()
    } else {
        let a = env.trader(100, 100);
        let b = env.trader(100, 100);
        Settlement::new(&[(a.owner(), 1, -1), (b.owner(), -1, 1)], 0)
    };
    ok(env.commit_for(1, &s));
    ok(env.reveal(1));
    let post = env.prepare(1, &s);
    ok(env.post(1, &post));
    (env, s)
}

#[test]
fn verify_and_finalize_wait_for_the_quorum() {
    let (mut env, s) = posted(false);
    fails(env.verify(1, &s, &[0]), E::QuorumNotMet);
    ok(env.cosign(1, 2));
    let b = env.batch_view(1);
    assert_eq!((b.cosign_count, b.cosign_bitmap), (2, 0b101));
    env.settle(1, &s);

    let (mut env, _) = posted(true);
    fails(env.finalize(1), E::QuorumNotMet);
    ok(env.cosign(1, 1));
    ok(env.finalize(1));
}

#[test]
fn bad_cosignatures_are_rejected() {
    let (env, _) = posted(true);

    let mut fork = env.fork();
    let key = executor_key(1);
    let wrong = [3u8; 32];
    let ixs = fork.cosign_ixs(1, &key, &wrong);
    fails(fork.crank(&ixs), E::BadSignature);

    let mut fork = env.fork();
    fails(fork.cosign(1, 0), E::AlreadyCosigned);
    ok(fork.cosign(1, 1));
    fails(fork.cosign(1, 1), E::AlreadyCosigned);

    let mut fork = env.fork();
    fails(fork.cosign(1, 6), E::UnknownExecutor);

    let mut fork = env.fork();
    let remove = fork.remove_executor_ix(&fork.admin.pubkey(), &executor_id(&executor_key(2)));
    ok(fork.admin_send(remove));
    fails(fork.cosign(1, 2), E::UnknownExecutor);

    // Without the precompile instruction.
    let mut fork = env.fork();
    let c = fork.cosign_ix(1);
    fails(fork.crank(&[c]), E::BadSignature);

    // Before a receipt exists.
    let mut fresh = Env::new(Cfg {
        executors: 2,
        quorum: 2,
        ..Cfg::default()
    });
    ok(fresh.commit_for(1, &Settlement::default()));
    ok(fresh.reveal(1));
    let digest = [0u8; 32];
    let ixs = fresh.cosign_ixs(1, &executor_key(1), &digest);
    fails(fresh.crank(&ixs), E::WrongStatus);
}

#[test]
fn a_removed_executor_stops_counting() {
    let (mut env, s) = posted(false);
    ok(env.cosign(1, 1));
    let remove = env.remove_executor_ix(&env.admin.pubkey(), &executor_id(&executor_key(1)));
    ok(env.admin_send(remove));
    fails(env.verify(1, &s, &[0]), E::QuorumNotMet);
    ok(env.cosign(1, 2));
    env.verify_all(1, &s);
    // Removing the poster after verification still blocks finalization.
    let remove = env.remove_executor_ix(&env.admin.pubkey(), &executor_id(&executor_key(0)));
    ok(env.admin_send(remove));
    fails(env.finalize(1), E::QuorumNotMet);
    let m = env.market_view();
    assert_eq!((m.executor_count, m.receipt_quorum), (1, 2));
    assert_eq!(m.executors[0], [0; 32]);
    assert_eq!(m.executors[1], [0; 32]);
    assert_eq!(m.executors[2], executor_id(&executor_key(2)));
}
