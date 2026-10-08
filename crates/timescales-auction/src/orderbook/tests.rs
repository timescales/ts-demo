use super::*;
use crate::collateral::Balance;
use timescales_core::commitment::Salt;
use timescales_core::crypto::Signature;
use timescales_core::intent::Cancel;
use timescales_core::*;

fn params(flow: FlowMode) -> MarketParams {
    MarketParams {
        market: MarketId(1),
        base_lot_size: 10,
        tick_size: 1,
        band_half_width: 5,
        max_order_lots_log2: 16,
        max_orders_per_trader: 3,
        max_batch_envelopes: 1024,
        max_order_lifetime: 4,
        maker_fee: FeeBps(0),
        taker_fee: FeeBps(0),
        flow,
        rationing: Rationing::Lottery,
        commitment_scheme: CommitmentScheme::Sha256,
    }
}

fn trader(n: u8) -> TraderId {
    TraderId([n; 32])
}

fn order(t: u8, nonce: u64, side: Side, limit: u64, q: u64) -> Order {
    Order {
        market: MarketId(1),
        trader: trader(t),
        nonce,
        side,
        role: Role::Taker,
        kind: OrderKind::Limit,
        limit: Tick(limit),
        quantity: Lots(q),
        valid_from: EpochId(10),
        expires_at: EpochId(10),
    }
}

fn cand(c: u8, body: IntentBody) -> Candidate {
    Candidate {
        commitment: OrderCommitment([c; 32]),
        priority: Hash32([c; 32]),
        intent: Ok(PrivateIntent {
            body,
            salt: Salt([0; 32]),
            signature: Signature([0; 64]),
        }),
    }
}

fn rich(ts: &[u8]) -> BalanceSheet {
    ts.iter()
        .map(|t| {
            (
                trader(*t),
                Balance {
                    base: BaseAtoms(1 << 40),
                    quote: QuoteAtoms(1 << 40),
                },
            )
        })
        .collect()
}

fn run(
    flow: FlowMode,
    balances: &BalanceSheet,
    state: &OrderStateTable,
    cs: &[Candidate],
) -> ValidatedBatch {
    let p = params(flow);
    let band = p.band(Tick(100)).unwrap();
    validate(
        &ValidationContext {
            params: &p,
            band: &band,
            epoch: EpochId(10),
            state,
            balances,
        },
        cs,
    )
}

fn disp(v: &ValidatedBatch, c: u8) -> Disposition {
    v.dispositions
        .iter()
        .find(|(x, _)| *x == OrderCommitment([c; 32]))
        .map(|x| x.1)
        .unwrap()
}

#[test]
fn duplicate_commitment_keeps_first() {
    let b = IntentBody::Place(order(1, 0, Side::Buy, 100, 1));
    let v = run(
        FlowMode::SingleBook,
        &rich(&[1]),
        &OrderStateTable::default(),
        &[cand(1, b), cand(1, b)],
    );
    assert_eq!(v.dispositions[0].1, Disposition::Accepted);
    assert_eq!(
        v.dispositions[1].1,
        Disposition::Rejected(RejectReason::Duplicate)
    );
}

#[test]
fn only_owner_can_cancel() {
    let target = OrderCommitment([5; 32]);
    let mk = |t: u8, epoch: u64| {
        IntentBody::Cancel(Cancel {
            market: MarketId(1),
            trader: trader(t),
            nonce: 99,
            target,
            epoch: EpochId(epoch),
        })
    };
    let place = IntentBody::Place(order(1, 0, Side::Buy, 100, 1));
    let v = run(
        FlowMode::SingleBook,
        &rich(&[1, 2]),
        &OrderStateTable::default(),
        &[cand(2, mk(2, 10)), cand(5, place), cand(6, mk(1, 9))],
    );
    assert_eq!(disp(&v, 5), Disposition::Accepted);
    assert_eq!(disp(&v, 2), Disposition::CancelIgnored);
    assert_eq!(
        disp(&v, 6),
        Disposition::Rejected(RejectReason::StaleCancel)
    );

    let v = run(
        FlowMode::SingleBook,
        &rich(&[1]),
        &OrderStateTable::default(),
        &[cand(5, place), cand(7, mk(1, 10))],
    );
    assert_eq!(disp(&v, 5), Disposition::Rejected(RejectReason::Cancelled));
    assert_eq!(disp(&v, 7), Disposition::CancelApplied);
    assert_eq!(v.cancelled, vec![target]);
}

#[test]
fn nonce_reuse_and_order_limit() {
    let cs = [
        cand(1, IntentBody::Place(order(1, 0, Side::Buy, 100, 1))),
        cand(2, IntentBody::Place(order(1, 0, Side::Buy, 101, 1))),
        cand(3, IntentBody::Place(order(1, 1, Side::Buy, 100, 1))),
        cand(4, IntentBody::Place(order(1, 2, Side::Buy, 100, 1))),
        cand(5, IntentBody::Place(order(1, 3, Side::Buy, 100, 1))),
    ];
    let v = run(
        FlowMode::SingleBook,
        &rich(&[1]),
        &OrderStateTable::default(),
        &cs,
    );
    assert_eq!(
        disp(&v, 2),
        Disposition::Rejected(RejectReason::DuplicateNonce)
    );
    assert_eq!(
        disp(&v, 5),
        Disposition::Rejected(RejectReason::Risk(RiskViolation::TooManyOrders))
    );
    assert_eq!(v.accepted(), 3);
}

#[test]
fn prior_state_reduces_quantity_and_blocks_cancelled() {
    let state: OrderStateTable = [
        StateEntry {
            commitment: OrderCommitment([1; 32]),
            filled: Lots(4),
            cancelled: false,
            created: EpochId(9),
        },
        StateEntry {
            commitment: OrderCommitment([2; 32]),
            filled: Lots(0),
            cancelled: true,
            created: EpochId(9),
        },
        StateEntry {
            commitment: OrderCommitment([3; 32]),
            filled: Lots(5),
            cancelled: false,
            created: EpochId(9),
        },
    ]
    .into_iter()
    .collect();
    let cs = [
        cand(1, IntentBody::Place(order(1, 0, Side::Buy, 100, 5))),
        cand(2, IntentBody::Place(order(1, 1, Side::Buy, 100, 5))),
        cand(3, IntentBody::Place(order(1, 2, Side::Buy, 100, 5))),
    ];
    let v = run(FlowMode::SingleBook, &rich(&[1]), &state, &cs);
    let book = &v.books[&BookId::Single];
    assert_eq!(book[0].quantity, Lots(1));
    assert_eq!(disp(&v, 2), Disposition::Rejected(RejectReason::Spent));
    // Exhausted order is accepted with zero quantity, not rejected.
    assert_eq!(disp(&v, 3), Disposition::Accepted);
    assert_eq!(book[1].quantity, Lots(0));
}

#[test]
fn self_trade_cancels_both_sides_in_book_only() {
    let mut m = order(1, 0, Side::Sell, 100, 1);
    m.role = Role::Maker;
    let t = order(1, 1, Side::Buy, 100, 1); // same book as a maker sell under dual flow
    let mut other = order(1, 2, Side::Buy, 100, 1);
    other.role = Role::Maker; // book MakerBidTakerAsk
    let cs = [
        cand(1, IntentBody::Place(m)),
        cand(2, IntentBody::Place(t)),
        cand(3, IntentBody::Place(other)),
    ];
    let v = run(
        FlowMode::DualFlow,
        &rich(&[1]),
        &OrderStateTable::default(),
        &cs,
    );
    let stp = Disposition::Rejected(RejectReason::Risk(RiskViolation::SelfTrade));
    assert_eq!(disp(&v, 1), stp);
    assert_eq!(disp(&v, 2), stp);
    assert_eq!(disp(&v, 3), Disposition::Accepted);
}

#[test]
fn untradeable_orders_do_not_trigger_stp() {
    // Band is [95, 105]. A buy at 90 cannot trade.
    let cs = [
        cand(1, IntentBody::Place(order(1, 0, Side::Buy, 90, 1))),
        cand(2, IntentBody::Place(order(1, 1, Side::Sell, 100, 1))),
    ];
    let v = run(
        FlowMode::SingleBook,
        &rich(&[1]),
        &OrderStateTable::default(),
        &cs,
    );
    assert_eq!(disp(&v, 1), Disposition::Accepted);
    assert_eq!(disp(&v, 2), Disposition::Accepted);
    assert_eq!(v.books[&BookId::Single][0].slot, None);
}

#[test]
fn collateral_prefix() {
    let mut sheet = BalanceSheet::default();
    // Buy at slot for tick 100 costs 100 quote per lot (tick_size 1, no fee).
    sheet.set(
        trader(1),
        Balance {
            base: BaseAtoms(0),
            quote: QuoteAtoms(250),
        },
    );
    sheet.set(
        trader(2),
        Balance {
            base: BaseAtoms(10),
            quote: QuoteAtoms(0),
        },
    );
    let cs = [
        cand(1, IntentBody::Place(order(1, 0, Side::Buy, 100, 2))),
        cand(2, IntentBody::Place(order(1, 1, Side::Buy, 100, 1))),
        // Too large for the balance, and poisons the rest of the prefix.
        cand(3, IntentBody::Place(order(2, 0, Side::Sell, 100, 2))),
        cand(4, IntentBody::Place(order(2, 1, Side::Sell, 100, 1))),
    ];
    let v = run(
        FlowMode::SingleBook,
        &sheet,
        &OrderStateTable::default(),
        &cs,
    );
    assert_eq!(disp(&v, 1), Disposition::Accepted);
    assert_eq!(
        disp(&v, 2),
        Disposition::Rejected(RejectReason::InsufficientCollateral)
    );
    assert_eq!(
        disp(&v, 3),
        Disposition::Rejected(RejectReason::InsufficientCollateral)
    );
    assert_eq!(
        disp(&v, 4),
        Disposition::Rejected(RejectReason::InsufficientCollateral)
    );
}

#[test]
fn malformed_and_noop() {
    let bad = Candidate {
        commitment: OrderCommitment([9; 32]),
        priority: Hash32([9; 32]),
        intent: Err(RejectReason::Malformed),
    };
    let v = run(
        FlowMode::SingleBook,
        &rich(&[]),
        &OrderStateTable::default(),
        &[bad, cand(1, IntentBody::Noop)],
    );
    assert_eq!(disp(&v, 9), Disposition::Rejected(RejectReason::Malformed));
    assert_eq!(disp(&v, 1), Disposition::Noop);
    assert_eq!(v.accepted(), 0);
}

/// Every disposition, with each rejection reason and risk violation once.
fn all_dispositions() -> Vec<Disposition> {
    let risks = [
        RiskViolation::WrongMarket,
        RiskViolation::NotLive,
        RiskViolation::LifetimeTooLong,
        RiskViolation::QuantityTooLarge,
        RiskViolation::TooManyOrders,
        RiskViolation::SelfTrade,
    ];
    let mut reasons = vec![
        RejectReason::Malformed,
        RejectReason::CommitmentMismatch,
        RejectReason::BadSignature,
        RejectReason::UnsupportedVersion,
        RejectReason::Duplicate,
        RejectReason::DuplicateNonce,
        RejectReason::Spent,
        RejectReason::Cancelled,
        RejectReason::StaleCancel,
        RejectReason::InsufficientCollateral,
    ];
    reasons.extend(risks.map(RejectReason::Risk));
    let mut all = vec![
        Disposition::Noop,
        Disposition::CancelApplied,
        Disposition::CancelIgnored,
        Disposition::Accepted,
    ];
    all.extend(reasons.into_iter().map(Disposition::Rejected));
    all
}

#[test]
fn trace_label_is_the_debug_string() {
    let all = all_dispositions();
    assert_eq!(all.len(), 4 + 10 + 6);
    for d in &all {
        assert_eq!(d.trace_label(), format!("{d:?}"));
    }
    let labels: std::collections::BTreeSet<_> = all.iter().map(Disposition::trace_label).collect();
    assert_eq!(labels.len(), all.len());
    // Every variant is listed: these matches stop compiling when one is
    // added, and the list above must grow with them.
    for d in &all {
        match d {
            Disposition::Noop
            | Disposition::CancelApplied
            | Disposition::CancelIgnored
            | Disposition::Accepted => {}
            Disposition::Rejected(r) => match r {
                RejectReason::Malformed
                | RejectReason::CommitmentMismatch
                | RejectReason::BadSignature
                | RejectReason::UnsupportedVersion
                | RejectReason::Duplicate
                | RejectReason::DuplicateNonce
                | RejectReason::Spent
                | RejectReason::Cancelled
                | RejectReason::StaleCancel
                | RejectReason::InsufficientCollateral => {}
                RejectReason::Risk(v) => match v {
                    RiskViolation::WrongMarket
                    | RiskViolation::NotLive
                    | RiskViolation::LifetimeTooLong
                    | RiskViolation::QuantityTooLarge
                    | RiskViolation::TooManyOrders
                    | RiskViolation::SelfTrade => {}
                },
            },
        }
    }
}

#[test]
fn candidate_debug_hides_the_intent() {
    let c = cand(7, IntentBody::Place(order(3, 41, Side::Sell, 123, 77)));
    let shown = format!("{c:?}");
    assert!(shown.starts_with("Candidate { commitment: OrderCommitment("));
    assert!(shown.contains("intent: Ok(..)"));
    for secret in ["Place", "Sell", "123", "77", "41", "limit", "PrivateIntent"] {
        assert!(!shown.contains(secret), "{secret} leaked in {shown}");
    }
    let rejected = Candidate {
        intent: Err(RejectReason::BadSignature),
        ..c
    };
    assert!(format!("{rejected:?}").contains("intent: Err(BadSignature)"));
}
