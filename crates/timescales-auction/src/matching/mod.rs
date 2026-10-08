//! Deterministic allocation at the uniform clearing price.
//!
//! Given the clearing slot `p*` and volume `V` of a book, the short side is
//! filled completely and the long side is rationed:
//!
//! 1. **price priority** - on the long side, orders with a strictly better
//!    limit than the marginal level are filled in full.
//! 2. At the marginal level the residual `R` is rationed by the market's
//!    [`Rationing`] rule: **lottery** (canonical order, each order takes
//!    `min(quantity, residual)`) or **pro rata** (`floor(q * R / M)` where `M`
//!    is the level's total, leftover lots one each in canonical order).
//!
//! For buys the marginal level is the unique slot `m >= p*` with
//! `D(m+1) <= V < D(m)`. For sells the unique `m <= p*` with
//! `S(m-1) <= V < S(m)` (`D = S(-1) = 0`). If the long side's curve
//! equals `V` at `p*` nobody is rationed.
//!
//! Every fill executes at `tick(p*)`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use std::collections::BTreeMap;

use crate::clearing::{Clearing, ClearingError, Curves, clear};
use crate::orderbook::{BookOrder, ValidatedBatch};
use thiserror::Error;
use timescales_core::{BookId, ClearingPrice, Fill, Lots, PriceBand, Rationing, Side};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MatchError {
    #[error(transparent)]
    Clearing(#[from] ClearingError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookResult {
    pub clearing: Clearing,
    /// Fill per input order, aligned with the input slice.
    pub fills: Vec<Lots>,
}

pub fn match_book(
    band: &PriceBand,
    rationing: Rationing,
    orders: &[BookOrder],
) -> Result<BookResult, MatchError> {
    let k = band.ticks();
    let curves = Curves::build(k, orders.iter().map(|o| (o.side, o.slot, o.quantity.0)))?;
    let clearing = clear(&curves, band);
    let mut fills = vec![Lots::ZERO; orders.len()];
    if clearing.volume == 0 {
        return Ok(BookResult { clearing, fills });
    }
    allocate(Side::Buy, rationing, &curves, &clearing, orders, &mut fills);
    allocate(
        Side::Sell,
        rationing,
        &curves,
        &clearing,
        orders,
        &mut fills,
    );
    Ok(BookResult { clearing, fills })
}

/// Marginal slot and the residual to ration there, or `None` if every
/// eligible order on `side` fills completely.
fn marginal(side: Side, curves: &Curves, c: &Clearing) -> Option<(u32, u64)> {
    let v = c.volume;
    let k = curves.ticks();
    match side {
        Side::Buy => {
            let d = &curves.demand;
            if d[c.slot as usize] == v {
                return None;
            }
            // D is non-increasing and D(p*) > V: scan up for the last slot above V.
            let mut m = c.slot;
            while m + 1 < k && d[(m + 1) as usize] > v {
                m += 1;
            }
            let above = if m + 1 < k { d[(m + 1) as usize] } else { 0 };
            Some((m, v - above))
        }
        Side::Sell => {
            let s = &curves.supply;
            if s[c.slot as usize] == v {
                return None;
            }
            let mut m = c.slot;
            while m > 0 && s[(m - 1) as usize] > v {
                m -= 1;
            }
            let below = if m > 0 { s[(m - 1) as usize] } else { 0 };
            Some((m, v - below))
        }
    }
}

fn allocate(
    side: Side,
    rationing: Rationing,
    curves: &Curves,
    c: &Clearing,
    orders: &[BookOrder],
    fills: &mut [Lots],
) {
    let p = c.slot;
    let eligible = |slot: u32| match side {
        Side::Buy => slot >= p,
        Side::Sell => slot <= p,
    };
    match marginal(side, curves, c) {
        None => {
            for (o, f) in orders.iter().zip(fills.iter_mut()) {
                if o.side == side && o.slot.is_some_and(eligible) {
                    *f = o.quantity;
                }
            }
        }
        Some((m, residual)) => {
            let strictly_better = |slot: u32| match side {
                Side::Buy => slot > m,
                Side::Sell => slot < m,
            };
            let mut marginal = Vec::new();
            for (i, o) in orders.iter().enumerate() {
                if o.side != side {
                    continue;
                }
                match o.slot {
                    Some(s) if strictly_better(s) => fills[i] = o.quantity,
                    Some(s) if s == m => marginal.push(i),
                    _ => {}
                }
            }
            match rationing {
                Rationing::Lottery => ration_lottery(orders, &marginal, residual, fills),
                Rationing::ProRata => ration_pro_rata(orders, &marginal, residual, fills),
            }
        }
    }
}

fn ration_lottery(orders: &[BookOrder], marginal: &[usize], mut residual: u64, fills: &mut [Lots]) {
    for &i in marginal {
        let take = orders[i].quantity.0.min(residual);
        residual -= take;
        fills[i] = Lots(take);
    }
    debug_assert_eq!(residual, 0);
}

fn ration_pro_rata(orders: &[BookOrder], marginal: &[usize], residual: u64, fills: &mut [Lots]) {
    // Curve sums fit in 63 bits (MarketParams::validate), so `q * R` fits u128.
    let level: u128 = marginal
        .iter()
        .map(|&i| u128::from(orders[i].quantity.0))
        .sum();
    if level == 0 {
        return;
    }
    let r = u128::from(residual);
    let mut given = 0u128;
    for &i in marginal {
        let share = u128::from(orders[i].quantity.0) * r / level;
        // share <= q because r < level when rationing applies.
        fills[i] = Lots(u64::try_from(share).unwrap_or(u64::MAX));
        given += share;
    }
    // Fewer leftover lots than marginal orders with spare quantity, so one
    // pass in canonical order always places them all.
    let mut leftover = r - given;
    for &i in marginal {
        if leftover == 0 {
            break;
        }
        if fills[i] < orders[i].quantity {
            fills[i].0 += 1;
            leftover -= 1;
        }
    }
    debug_assert_eq!(leftover, 0);
}

/// Result of matching every book in a batch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MatchOutcome {
    pub clearing: Vec<ClearingPrice>,
    /// Non-zero fills, grouped by book in `BookId` order, canonical order
    /// within a book.
    pub fills: Vec<Fill>,
}

pub fn match_batch(
    band: &PriceBand,
    rationing: Rationing,
    batch: &ValidatedBatch,
) -> Result<MatchOutcome, MatchError> {
    let mut out = MatchOutcome::default();
    let books: &BTreeMap<BookId, Vec<BookOrder>> = &batch.books;
    for (book, orders) in books {
        let r = match_book(band, rationing, orders)?;
        let tick = band.tick_at(r.clearing.slot);
        out.clearing.push(ClearingPrice {
            book: *book,
            tick,
            volume: Lots(r.clearing.volume),
        });
        for (o, f) in orders.iter().zip(r.fills) {
            if !f.is_zero() {
                out.fills.push(Fill {
                    commitment: o.commitment,
                    trader: o.trader,
                    book: *book,
                    side: o.side,
                    role: o.role,
                    quantity: f,
                    tick,
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
