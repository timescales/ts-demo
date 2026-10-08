//! Market risk constraints.
//!
//! These checks depend only on the order itself, the batch epoch and simple
//! per-trader counters. Collateral lives in the `collateral` module. All checks are
//! deterministic and evaluated in the batch's canonical order, so every
//! backend rejects the same orders.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use std::collections::BTreeMap;

use thiserror::Error;
use timescales_core::{BookId, EpochId, Lots, MarketParams, Order, Side, TraderId};

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskViolation {
    #[error("order is for a different market")]
    WrongMarket,
    #[error("batch epoch outside the order's validity window")]
    NotLive,
    #[error("validity window longer than the market allows")]
    LifetimeTooLong,
    #[error("quantity exceeds market maximum")]
    QuantityTooLarge,
    #[error("trader exceeded the per-batch order limit")]
    TooManyOrders,
    #[error("trader has orders on both sides of the same book")]
    SelfTrade,
}

/// Stateless checks on a single order.
///
/// A zero quantity is not a violation: such an order is accepted, reserves
/// nothing and never fills. Treating it as a rejection would force the MPC
/// backend to open a comparison on a secret quantity.
pub fn check_order(
    params: &MarketParams,
    epoch: EpochId,
    order: &Order,
) -> Result<(), RiskViolation> {
    if order.market != params.market {
        return Err(RiskViolation::WrongMarket);
    }
    if !order.is_live_at(epoch) {
        return Err(RiskViolation::NotLive);
    }
    if order.expires_at.0 - order.valid_from.0 > u64::from(params.max_order_lifetime) {
        return Err(RiskViolation::LifetimeTooLong);
    }
    if order.quantity.0 > params.max_order_lots() {
        return Err(RiskViolation::QuantityTooLarge);
    }
    Ok(())
}

/// Per-trader order count. Orders beyond the limit, in canonical order, are
/// rejected.
#[derive(Debug, Default)]
pub struct OrderCounter {
    counts: BTreeMap<TraderId, u32>,
}

impl OrderCounter {
    pub fn admit(&mut self, params: &MarketParams, trader: TraderId) -> Result<(), RiskViolation> {
        let c = self.counts.entry(trader).or_insert(0);
        if *c >= u32::from(params.max_orders_per_trader) {
            return Err(RiskViolation::TooManyOrders);
        }
        *c += 1;
        Ok(())
    }
}

/// Self-trade prevention, "cancel both" mode: a trader with live quantity on
/// both sides of the same book loses every order in that book.
///
/// Returns the `(trader, book)` pairs in conflict.
pub fn self_trade_conflicts<'a, I>(orders: I) -> BTreeMap<(TraderId, BookId), ()>
where
    I: IntoIterator<Item = (&'a TraderId, BookId, Side, Lots)>,
{
    let mut sides: BTreeMap<(TraderId, BookId), (bool, bool)> = BTreeMap::new();
    for (t, book, side, q) in orders {
        if q.is_zero() {
            continue;
        }
        let e = sides.entry((*t, book)).or_default();
        match side {
            Side::Buy => e.0 = true,
            Side::Sell => e.1 = true,
        }
    }
    sides
        .into_iter()
        .filter(|(_, (b, s))| *b && *s)
        .map(|(k, _)| (k, ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use timescales_core::*;

    fn params() -> MarketParams {
        MarketParams {
            market: MarketId(1),
            base_lot_size: 1,
            tick_size: 1,
            band_half_width: 4,
            max_order_lots_log2: 10,
            max_orders_per_trader: 2,
            max_batch_envelopes: 1024,
            max_order_lifetime: 3,
            maker_fee: FeeBps(0),
            taker_fee: FeeBps(0),
            flow: FlowMode::SingleBook,
            rationing: Rationing::Lottery,
            commitment_scheme: CommitmentScheme::Sha256,
        }
    }

    fn order() -> Order {
        Order {
            market: MarketId(1),
            trader: TraderId([1; 32]),
            nonce: 0,
            side: Side::Buy,
            role: Role::Taker,
            kind: OrderKind::Limit,
            limit: Tick(10),
            quantity: Lots(5),
            valid_from: EpochId(10),
            expires_at: EpochId(12),
        }
    }

    #[test]
    fn checks() {
        let p = params();
        assert!(check_order(&p, EpochId(11), &order()).is_ok());
        assert_eq!(
            check_order(&p, EpochId(13), &order()),
            Err(RiskViolation::NotLive)
        );
        assert_eq!(
            check_order(&p, EpochId(9), &order()),
            Err(RiskViolation::NotLive)
        );
        let mut o = order();
        o.expires_at = EpochId(14);
        assert_eq!(
            check_order(&p, EpochId(11), &o),
            Err(RiskViolation::LifetimeTooLong)
        );
        o = order();
        o.quantity = Lots(1024);
        assert_eq!(
            check_order(&p, EpochId(11), &o),
            Err(RiskViolation::QuantityTooLarge)
        );
        o.quantity = Lots(1023);
        assert!(check_order(&p, EpochId(11), &o).is_ok());
        o.market = MarketId(2);
        assert_eq!(
            check_order(&p, EpochId(11), &o),
            Err(RiskViolation::WrongMarket)
        );
    }

    #[test]
    fn counter_limits() {
        let p = params();
        let mut c = OrderCounter::default();
        let t = TraderId([1; 32]);
        assert!(c.admit(&p, t).is_ok());
        assert!(c.admit(&p, t).is_ok());
        assert_eq!(c.admit(&p, t), Err(RiskViolation::TooManyOrders));
        assert!(c.admit(&p, TraderId([2; 32])).is_ok());
    }

    #[test]
    fn stp_detects_two_sided_trader() {
        let a = TraderId([1; 32]);
        let b = TraderId([2; 32]);
        let v = [
            (&a, BookId::Single, Side::Buy, Lots(1)),
            (&a, BookId::Single, Side::Sell, Lots(1)),
            (&b, BookId::Single, Side::Buy, Lots(1)),
            (&b, BookId::Single, Side::Sell, Lots(0)),
        ];
        let c = self_trade_conflicts(v);
        assert!(c.contains_key(&(a, BookId::Single)));
        assert!(!c.contains_key(&(b, BookId::Single)));
    }
}
