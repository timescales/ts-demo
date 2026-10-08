//! Property test: random interleavings of deposits, withdrawal
//! requests, cancels and withdrawals between the commit (snapshot), verify
//! and apply. Deltas are drawn against the available balances at the
//! commit. Verify always passes, apply never fails, the floor equals the
//! available balance at the commit, the vaults back every balance plus
//! unclaimed fees, `last_settled <= last_committed <= last_settled + 1`, and
//! no leaf is verified below quorum.

mod common;

use std::cell::RefCell;

use common::*;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

const TRADERS: usize = 3;
const WALLET: u64 = 1_000_000;

#[derive(Clone, Debug)]
enum Op {
    Deposit { t: usize, quote: bool, amount: u64 },
    Request { t: usize, base: u64, quote: u64 },
    Cancel { t: usize },
    Withdraw { t: usize, quote: bool },
}

fn op() -> impl Strategy<Value = Op> {
    let t = 0..TRADERS;
    prop_oneof![
        (t.clone(), any::<bool>(), 1u64..2_000).prop_map(|(t, quote, amount)| Op::Deposit {
            t,
            quote,
            amount
        }),
        (t.clone(), 0u64..3_000, 0u64..3_000).prop_map(|(t, base, quote)| Op::Request {
            t,
            base,
            quote
        }),
        t.clone().prop_map(|t| Op::Cancel { t }),
        (t, any::<bool>()).prop_map(|(t, quote)| Op::Withdraw { t, quote }),
    ]
}

#[derive(Clone, Debug)]
struct Trade {
    buyer: usize,
    seller: usize,
    qty: u64,
    price: u64,
    fee: u64,
}

#[derive(Clone, Debug)]
struct Case {
    initial: Vec<(u64, u64)>,
    old_requests: Vec<Option<(u64, u64)>>,
    trades: Vec<Trade>,
    before_verify: Vec<Op>,
    before_apply: Vec<Op>,
}

fn case() -> impl Strategy<Value = Case> {
    let trade = (0..TRADERS, 0..TRADERS, 0u64..500, 1u64..20, 0u64..30).prop_map(
        |(buyer, seller, qty, price, fee)| Trade {
            buyer,
            seller,
            qty,
            price,
            fee,
        },
    );
    (
        prop::collection::vec((0u64..3_000, 0u64..5_000), TRADERS),
        prop::collection::vec(prop::option::of((0u64..2_000, 0u64..3_000)), TRADERS),
        prop::collection::vec(trade, 0..6),
        prop::collection::vec(op(), 0..8),
        prop::collection::vec(op(), 0..8),
    )
        .prop_map(
            |(initial, old_requests, trades, before_verify, before_apply)| Case {
                initial,
                old_requests,
                trades,
                before_verify,
                before_apply,
            },
        )
}

struct Template {
    env: Env,
    traders: Vec<TraderAcc>,
}

fn template() -> Template {
    let mut env = Env::new(Cfg {
        executors: 2,
        quorum: 2,
        ..Cfg::default()
    });
    let traders = (0..TRADERS)
        .map(|_| {
            let t = env.wallet(WALLET, WALLET);
            let open = env.open_trader_ix(&t.owner());
            ok(env.send(&[open], &[&t.kp]));
            t
        })
        .collect();
    Template { env, traders }
}

thread_local! {
    static TEMPLATE: RefCell<Option<Template>> = const { RefCell::new(None) };
    /// Cases with at least one leaf, and with a floor captured in flight.
    static COVERAGE: RefCell<(u32, u32)> = const { RefCell::new((0, 0)) };
}

fn run_op(env: &mut Env, traders: &[TraderAcc], op: &Op) {
    let (t, ixn) = match *op {
        Op::Deposit { t, quote, amount } => (t, env.deposit_ix(&traders[t], quote, amount)),
        Op::Request { t, base, quote } => (t, env.request_withdraw_ix(&traders[t], base, quote)),
        Op::Cancel { t } => (t, env.cancel_request_ix(&traders[t])),
        Op::Withdraw { t, quote } => (t, env.withdraw_ix(&traders[t], quote)),
    };
    env.advance(1);
    if let Err(f) = env.send(&[ixn], &[&traders[t].kp]) {
        let allowed = [
            E::WithdrawPending,
            E::NothingToWithdraw,
            E::Insolvent,
            E::WithdrawLocked,
        ];
        assert!(
            f.code
                .is_some_and(|c| allowed.iter().any(|e| e.code() == c)),
            "{op:?} failed: {} {:?}",
            f.err,
            f.code.and_then(E::from_code)
        );
    }
}

fn check_invariants(env: &Env, traders: &[TraderAcc], snapshot: &[(u64, u64)], commit_slot: u64) {
    let m = env.market_view();
    assert!(m.last_settled <= m.last_committed && m.last_committed <= m.last_settled + 1);
    let (mut base, mut quote) = (0u64, 0u64);
    for (i, t) in traders.iter().enumerate() {
        let v = env.trader_view(&t.owner());
        base += v.base;
        quote += v.quote;
        if v.last_change_slot > commit_slot {
            assert_eq!(v.floor_epoch, 1, "trader {i} changed in flight");
        }
        if v.floor_epoch == 1 {
            assert_eq!(
                (v.floor_base, v.floor_quote),
                snapshot[i],
                "trader {i} floor"
            );
        } else {
            assert_eq!(v.floor_epoch, 0);
        }
    }
    assert_eq!(env.token_amount(&env.base_vault), base);
    assert_eq!(
        env.token_amount(&env.quote_vault),
        quote + m.fees_accrued - m.fees_claimed
    );
}

fn run(case: &Case) {
    TEMPLATE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let tpl = slot.get_or_insert_with(template);
        let mut env = tpl.env.fork();
        let traders = &tpl.traders;

        for (i, t) in traders.iter().enumerate() {
            let (b, q) = case.initial[i];
            for (quote, amount) in [(false, b), (true, q)] {
                if amount > 0 {
                    let d = env.deposit_ix(t, quote, amount);
                    ok(env.send(&[d], &[&t.kp]));
                }
            }
            if let Some((rb, rq)) = case.old_requests[i] {
                let r = env.request_withdraw_ix(t, rb.min(b), rq.min(q));
                let _ = env.send(&[r], &[&t.kp]);
            }
        }

        // The snapshot: available balances at the commit.
        let root = [0x11; 32];
        ok(env.commit(1, &root, 16));
        let commit_slot = env.batch_view(1).commit_slot;
        let snapshot: Vec<(u64, u64)> = traders
            .iter()
            .map(|t| env.trader_view(&t.owner()).available(1))
            .collect();

        // An honest executor's deltas: every trade fits the available
        // balances left after the trades before it.
        let mut avail: Vec<(i128, i128)> = snapshot
            .iter()
            .map(|(b, q)| (i128::from(*b), i128::from(*q)))
            .collect();
        let mut delta = [(0i64, 0i64); TRADERS];
        let mut touched = [false; TRADERS];
        let mut fees = 0u64;
        for tr in &case.trades {
            if tr.buyer == tr.seller {
                continue;
            }
            let budget = (avail[tr.buyer].1 - i128::from(tr.fee)).max(0);
            let qty = i128::from(tr.qty)
                .min(avail[tr.seller].0)
                .min(budget / i128::from(tr.price));
            if qty <= 0 {
                continue;
            }
            let cost = qty * i128::from(tr.price);
            avail[tr.buyer].0 += qty;
            avail[tr.buyer].1 -= cost + i128::from(tr.fee);
            avail[tr.seller].0 -= qty;
            avail[tr.seller].1 += cost;
            delta[tr.buyer].0 += qty as i64;
            delta[tr.buyer].1 -= (cost + i128::from(tr.fee)) as i64;
            delta[tr.seller].0 -= qty as i64;
            delta[tr.seller].1 += cost as i64;
            touched[tr.buyer] = true;
            touched[tr.seller] = true;
            fees += tr.fee;
        }
        let deltas: Vec<_> = (0..TRADERS)
            .filter(|i| touched[*i])
            .map(|i| (traders[i].owner(), delta[i].0, delta[i].1))
            .collect();
        let s = Settlement::new(&deltas, fees);

        for op in &case.before_verify {
            run_op(&mut env, traders, op);
            check_invariants(&env, traders, &snapshot, commit_slot);
        }

        ok(env.reveal(1));
        let post = env.prepare(1, &s);
        ok(env.post(1, &post));
        if !s.leaves.is_empty() {
            fails(env.verify(1, &s, &[0]), E::QuorumNotMet);
        }
        ok(env.cosign(1, 1));
        env.verify_all(1, &s);
        ok(env.finalize(1));
        check_invariants(&env, traders, &snapshot, commit_slot);

        for op in &case.before_apply {
            run_op(&mut env, traders, op);
            check_invariants(&env, traders, &snapshot, commit_slot);
        }

        env.advance(1);
        env.apply_all(1, &s);
        ok(env.close_batch(1));
        check_invariants(&env, traders, &snapshot, commit_slot);
        let m = env.market_view();
        assert_eq!(
            (m.last_committed, m.last_settled, m.fees_accrued),
            (1, 1, fees)
        );
        let mut floors = false;
        for (i, t) in traders.iter().enumerate() {
            let v = env.trader_view(&t.owner());
            if touched[i] {
                assert_eq!(v.last_leaf_epoch, 1);
            }
            floors |= v.floor_epoch == 1;
        }
        COVERAGE.with(|c| {
            let mut c = c.borrow_mut();
            c.0 += u32::from(!s.leaves.is_empty());
            c.1 += u32::from(floors);
        });
    });
}

#[test]
fn interleavings_never_break_a_batch() {
    let mut runner = TestRunner::new(Config {
        cases: 256,
        failure_persistence: None,
        ..Config::default()
    });
    runner
        .run(&case(), |c| {
            run(&c);
            Ok(())
        })
        .expect("property holds");
    // The generator must actually exercise settlement and the floor.
    let (with_leaves, with_floor) = COVERAGE.with(|c| *c.borrow());
    assert!(with_leaves >= 64, "only {with_leaves} cases had deltas");
    assert!(with_floor >= 64, "only {with_floor} cases captured a floor");
}
