//! The abort matrix: every (reason x status x signer) cell, before and
//! after every deadline, against a model written from the design table.

mod common;

use common::*;
use solana_keypair::Keypair;
use solana_signer::Signer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Committed,
    Revealed,
    PostedBelowQuorum,
    PostedAtQuorum,
    Verified,
    VerifiedPartlyApplied,
    Settled,
    Aborted,
}

const STATES: [State; 8] = [
    State::Committed,
    State::Revealed,
    State::PostedBelowQuorum,
    State::PostedAtQuorum,
    State::Verified,
    State::VerifiedPartlyApplied,
    State::Settled,
    State::Aborted,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Who {
    Admin,
    Relay,
    Anyone,
}

fn cfg() -> Cfg {
    Cfg {
        executors: 2,
        quorum: 2,
        ..Cfg::default()
    }
}

fn setup(state: State) -> Env {
    let mut env = Env::new(cfg());
    let a = env.trader(100, 100);
    let b = env.trader(100, 100);
    let s = Settlement::new(&[(a.owner(), 1, -1), (b.owner(), -1, 1)], 0);
    ok(env.commit_for(1, &s));
    if state == State::Committed {
        return env;
    }
    if state == State::Aborted {
        let relay = env.relay.insecure_clone();
        ok(env.abort(1, &relay, 2));
        return env;
    }
    ok(env.reveal(1));
    if state == State::Revealed {
        return env;
    }
    env.advance(10);
    let post = env.prepare(1, &s);
    ok(env.post(1, &post));
    if state == State::PostedBelowQuorum {
        return env;
    }
    ok(env.cosign(1, 1));
    if state == State::PostedAtQuorum {
        return env;
    }
    env.verify_all(1, &s);
    ok(env.finalize(1));
    if state == State::Verified {
        return env;
    }
    ok(env.apply(1, &s, &[0]));
    if state == State::VerifiedPartlyApplied {
        return env;
    }
    ok(env.apply(1, &s, &[1]));
    ok(env.close_batch(1));
    env
}

/// The abort rules as written, in the program's check order.
fn expected(state: State, reason: u8, who: Who, late: bool, before_d: bool) -> Option<E> {
    use State::*;
    if matches!(state, Settled | Aborted) {
        return Some(E::OutOfOrder);
    }
    if state == VerifiedPartlyApplied {
        return Some(E::WrongStatus);
    }
    let not_expired = if late { None } else { Some(E::NotExpired) };
    match reason {
        1 => (who != Who::Admin).then_some(E::Unauthorised),
        2 => {
            if who != Who::Relay {
                Some(E::Unauthorised)
            } else if state != Committed {
                Some(E::WrongStatus)
            } else if !before_d {
                Some(E::Unauthorised)
            } else {
                None
            }
        }
        3 => {
            if state == Committed {
                not_expired
            } else {
                Some(E::WrongStatus)
            }
        }
        4 => {
            if state == Revealed {
                not_expired
            } else {
                Some(E::WrongStatus)
            }
        }
        5 => {
            if matches!(state, PostedBelowQuorum | PostedAtQuorum | Verified) {
                not_expired
            } else {
                Some(E::WrongStatus)
            }
        }
        6 => {
            if state == PostedBelowQuorum {
                not_expired
            } else {
                Some(E::WrongStatus)
            }
        }
        _ => Some(E::InvalidAbortReason),
    }
}

#[test]
fn every_cell() {
    let mut cells = 0;
    for state in STATES {
        let base = setup(state);
        let b = base.batch_view(1);
        let m = base.market_view();
        let d = u64::from(m.beacon_delay);
        // The latest deadline of this batch, plus one.
        let late_slot = [
            b.commit_slot + d + 400,
            b.reveal_slot + m.exec_timeout,
            b.receipt_slot + m.settle_timeout,
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
            + 1;
        for late in [false, true] {
            for reason in 0..=7u8 {
                for who in [Who::Admin, Who::Relay, Who::Anyone] {
                    let mut env = base.fork();
                    if late {
                        env.warp(late_slot);
                    }
                    let signer: Keypair = match who {
                        Who::Admin => env.admin.insecure_clone(),
                        Who::Relay => env.relay.insecure_clone(),
                        Who::Anyone => env.funded(),
                    };
                    let before_d = env.slot() < b.commit_slot + d;
                    let r = env.abort(1, &signer, reason);
                    let want = expected(state, reason, who, late, before_d);
                    let label = format!("{state:?} reason {reason} by {who:?} late={late}");
                    match (want, r) {
                        (None, Ok(_)) => {
                            let v = env.batch_view(1);
                            assert_eq!((v.status, v.abort_reason), (ABORTED, reason), "{label}");
                            let m = env.market_view();
                            assert_eq!(m.last_settled, 1, "{label}");
                            assert_eq!(m.last_progress_slot, env.slot(), "{label}");
                            assert_eq!(m.state_root, base.market_view().state_root, "{label}");
                            assert_eq!(m.prev_receipt, base.market_view().prev_receipt, "{label}");
                        }
                        (Some(e), Err(f)) => assert_eq!(
                            f.code,
                            Some(e.code()),
                            "{label}: want {e:?}, got {} {:?}",
                            f.err,
                            f.code.and_then(E::from_code)
                        ),
                        (want, got) => panic!("{label}: want {want:?}, got {got:?}"),
                    }
                    cells += 1;
                }
            }
        }
    }
    assert_eq!(cells, 8 * 2 * 8 * 3);
}

#[test]
fn settle_timeout_runs_from_the_receipt() {
    let mut env = Env::new(cfg());
    let s = Settlement::default();
    ok(env.commit_for(1, &s));
    ok(env.reveal(1));
    let reveal = env.batch_view(1).reveal_slot;
    // A slow but valid post: the settle timer has not started before it.
    env.warp(reveal + 140);
    let post = env.prepare(1, &s);
    ok(env.post(1, &post));
    ok(env.cosign(1, 1));
    let receipt = env.batch_view(1).receipt_slot;
    let anyone = env.funded();
    env.warp(receipt + env.cfg.settle_timeout);
    fails(env.abort(1, &anyone, 5), E::NotExpired);
    env.warp(receipt + env.cfg.settle_timeout + 1);
    ok(env.abort(1, &anyone, 5));
}

#[test]
fn quorum_timeout_only_below_quorum() {
    let mut env = Env::new(cfg());
    let s = Settlement::default();
    ok(env.commit_for(1, &s));
    ok(env.reveal(1));
    let post = env.prepare(1, &s);
    ok(env.post(1, &post));
    let receipt = env.batch_view(1).receipt_slot;
    let anyone = env.funded();
    let mut met = env.fork();
    env.warp(receipt + env.cfg.exec_timeout);
    fails(env.abort(1, &anyone, 6), E::NotExpired);
    env.warp(receipt + env.cfg.exec_timeout + 1);
    ok(env.abort(1, &anyone, 6));
    assert_eq!(env.batch_view(1).abort_reason, 6);

    ok(met.cosign(1, 1));
    met.warp(receipt + met.cfg.exec_timeout + 1);
    fails(met.abort(1, &anyone, 6), E::WrongStatus);
    // Removing a co-signer drops the batch below quorum again.
    let remove = met.remove_executor_ix(&met.admin.pubkey(), &executor_id(&executor_key(1)));
    ok(met.admin_send(remove));
    ok(met.abort(1, &anyone, 6));
}

#[test]
fn abort_needs_a_signature() {
    let mut env = Env::new(cfg());
    ok(env.commit_for(1, &Settlement::default()));
    let mut a = env.abort_ix(1, &env.admin.pubkey(), 1);
    a.accounts[0].is_signer = false;
    fails(env.crank(&[a]), E::Unauthorised);
}
