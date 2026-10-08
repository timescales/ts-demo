//! Bounded exhaustive checker for the clearing and allocation rules.
//!
//! For every book within the bounds (every combination of side, slot or
//! "cannot trade", and quantity for each order, and every reference
//! position) it:
//!
//! 1. Computes the clearing slot by brute force from the rule's definition,
//!    using curves summed directly from the orders.
//! 2. Enumerates *every* fill vector `f` with `0 <= f_i <= q_i` and keeps
//!    the ones satisfying the constraint form of the allocation rule
//!    (C1-C4 below).
//! 3. Requires exactly one survivor, equal to what `match_book` returns.
//!
//! The constraint form is deliberately not the constructive algorithm:
//!
//! * C1 eligibility: a buy fills only if `slot >= p*`, a sell only if
//!   `slot <= p*`.
//! * C2 balance: both sides sum to `V(p*)`.
//! * C3 price priority: any positive fill implies every strictly better order
//!   on that side is full.
//! * C4 lottery: at one slot and side, a positive fill for an order implies
//!   every earlier order there is full. Pro rata: each fill is the floor
//!   share or one more, extras go to the earliest orders with spare
//!   quantity.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Result, bail};
use clap::Parser;
use rayon::prelude::*;
use timescales_auction::matching::match_book;
use timescales_auction::orderbook::BookOrder;
use timescales_core::{Lots, OrderCommitment, PriceBand, Rationing, Role, Side, Tick, TraderId};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 3)]
    orders: usize,
    #[arg(long, default_value_t = 4)]
    ticks: u32,
    #[arg(long, default_value_t = 3)]
    max_qty: u64,
}

#[derive(Clone, Copy, Debug)]
struct O {
    side: Side,
    slot: Option<u32>,
    q: u64,
}

fn demand(os: &[O], p: u32) -> u64 {
    os.iter()
        .filter(|o| o.side == Side::Buy && o.slot.is_some_and(|s| s >= p))
        .map(|o| o.q)
        .sum()
}

fn supply(os: &[O], p: u32) -> u64 {
    os.iter()
        .filter(|o| o.side == Side::Sell && o.slot.is_some_and(|s| s <= p))
        .map(|o| o.q)
        .sum()
}

fn clearing(os: &[O], k: u32, r: u32) -> u32 {
    let key = |p: u32| {
        let (d, s) = (demand(os, p), supply(os, p));
        let v = d.min(s);
        let d_next = if p + 1 < k { demand(os, p + 1) } else { 0 };
        let s_prev = if p > 0 { supply(os, p - 1) } else { 0 };
        let strand = d_next > v || s_prev > v;
        (
            v,
            !strand,
            core::cmp::Reverse(d.abs_diff(s)),
            core::cmp::Reverse(p.abs_diff(r)),
            core::cmp::Reverse(p),
        )
    };
    (0..k).max_by_key(|&p| key(p)).unwrap_or(0)
}

fn satisfies(os: &[O], k: u32, p: u32, f: &[u64], rationing: Rationing) -> bool {
    let v = demand(os, p).min(supply(os, p));
    let better = |o: &O, than: u32| match o.side {
        Side::Buy => o.slot.is_some_and(|s| s > than),
        Side::Sell => o.slot.is_some_and(|s| s < than),
    };
    for (o, &x) in os.iter().zip(f) {
        let eligible = match o.side {
            Side::Buy => o.slot.is_some_and(|s| s >= p),
            Side::Sell => o.slot.is_some_and(|s| s <= p),
        };
        if x > o.q || (x > 0 && !eligible) {
            return false;
        }
    }
    for side in [Side::Buy, Side::Sell] {
        let sum: u64 = os
            .iter()
            .zip(f)
            .filter(|(o, _)| o.side == side)
            .map(|(_, x)| *x)
            .sum();
        if sum != v {
            return false;
        }
    }
    // C3 price priority.
    for (o, &x) in os.iter().zip(f) {
        if x == 0 {
            continue;
        }
        let s = o.slot.unwrap_or(0);
        if os
            .iter()
            .zip(f)
            .any(|(o2, &x2)| o2.side == o.side && better(o2, s) && x2 != o2.q)
        {
            return false;
        }
    }
    // C4 within a level.
    for side in [Side::Buy, Side::Sell] {
        for slot in 0..k {
            let level: Vec<usize> = (0..os.len())
                .filter(|&i| os[i].side == side && os[i].slot == Some(slot))
                .collect();
            let r: u64 = level.iter().map(|&i| f[i]).sum();
            let m: u64 = level.iter().map(|&i| os[i].q).sum();
            if r == m {
                continue;
            }
            match rationing {
                Rationing::Lottery => {
                    for (a, &i) in level.iter().enumerate() {
                        if f[i] > 0 && level[..a].iter().any(|&j| f[j] != os[j].q) {
                            return false;
                        }
                    }
                }
                Rationing::ProRata => {
                    let base: Vec<u64> = level.iter().map(|&i| os[i].q * r / m).collect();
                    let mut extras_done = false;
                    for (a, &i) in level.iter().enumerate() {
                        let extra = match f[i].checked_sub(base[a]) {
                            Some(e @ 0..=1) => e,
                            _ => return false,
                        };
                        let spare = base[a] < os[i].q;
                        if extra == 1 && extras_done {
                            return false;
                        }
                        if spare && extra == 0 {
                            extras_done = true;
                        }
                        if extra == 1 && !spare {
                            return false;
                        }
                    }
                }
            }
        }
    }
    true
}

fn decode(mut code: u64, n: usize, k: u32, max_q: u64) -> Vec<O> {
    let per_slot = u64::from(k) + 1;
    let per = 2 * per_slot * (max_q + 1);
    (0..n)
        .map(|_| {
            let c = code % per;
            code /= per;
            let side = if c.is_multiple_of(2) {
                Side::Buy
            } else {
                Side::Sell
            };
            let s = (c / 2) % per_slot;
            let q = c / (2 * per_slot);
            O {
                side,
                slot: (s < u64::from(k)).then_some(u32::try_from(s).unwrap_or(0)),
                q,
            }
        })
        .collect()
}

fn book_orders(os: &[O]) -> Vec<BookOrder> {
    os.iter()
        .enumerate()
        .map(|(i, o)| BookOrder {
            commitment: OrderCommitment([u8::try_from(i).unwrap_or(0); 32]),
            trader: TraderId([u8::try_from(i).unwrap_or(0); 32]),
            side: o.side,
            role: Role::Taker,
            slot: o.slot,
            quantity: Lots(o.q),
        })
        .collect()
}

fn check(os: &[O], k: u32, r: u32, rationing: Rationing) -> Result<(), String> {
    let band = PriceBand {
        lo: Tick(100),
        hi: Tick(100 + u64::from(k) - 1),
        reference: Tick(100 + u64::from(r)),
    };
    let got = match_book(&band, rationing, &book_orders(os)).map_err(|e| e.to_string())?;
    let p = clearing(os, k, r);
    if got.clearing.slot != p {
        return Err(format!("clearing slot {} != spec {p}", got.clearing.slot));
    }
    // Enumerate all fill vectors.
    let mut survivors = Vec::new();
    let mut f = vec![0u64; os.len()];
    loop {
        if satisfies(os, k, p, &f, rationing) {
            survivors.push(f.clone());
        }
        let mut i = 0;
        loop {
            if i == os.len() {
                break;
            }
            if f[i] < os[i].q {
                f[i] += 1;
                break;
            }
            f[i] = 0;
            i += 1;
        }
        if i == os.len() {
            break;
        }
    }
    if survivors.len() != 1 {
        return Err(format!("{} valid allocations", survivors.len()));
    }
    let ours: Vec<u64> = got.fills.iter().map(|x| x.0).collect();
    if ours != survivors[0] {
        return Err(format!("allocation {ours:?} != spec {:?}", survivors[0]));
    }
    Ok(())
}

fn main() -> Result<()> {
    let a = Args::parse();
    let per = 2 * (u64::from(a.ticks) + 1) * (a.max_qty + 1);
    let books = per
        .checked_pow(u32::try_from(a.orders)?)
        .ok_or_else(|| anyhow::anyhow!("bound too large"))?;
    let checked = AtomicU64::new(0);
    let failures: Vec<String> = (0..books)
        .into_par_iter()
        .flat_map_iter(|code| {
            let os = decode(code, a.orders, a.ticks, a.max_qty);
            let mut errs = Vec::new();
            for r in 0..a.ticks {
                for rule in [Rationing::Lottery, Rationing::ProRata] {
                    checked.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = check(&os, a.ticks, r, rule) {
                        errs.push(format!("{os:?} r={r} {rule:?}: {e}"));
                    }
                }
            }
            errs
        })
        .take_any(10)
        .collect();
    println!(
        "checked {} cases ({} books x {} references x 2 rationing rules), orders <= {}, ticks = {}, qty <= {}",
        checked.load(Ordering::Relaxed),
        books,
        a.ticks,
        a.orders,
        a.ticks,
        a.max_qty
    );
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL {f}");
        }
        bail!("{} failures", failures.len());
    }
    println!("all cases have exactly one valid result, equal to the implementation's");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn small_bound_holds() {
        for code in 0..(2 * 4 * 3u64).pow(2) {
            let os = super::decode(code, 2, 3, 2);
            for r in 0..3 {
                for rule in [
                    timescales_core::Rationing::Lottery,
                    timescales_core::Rationing::ProRata,
                ] {
                    super::check(&os, 3, r, rule).unwrap_or_else(|e| panic!("{os:?} r={r}: {e}"));
                }
            }
        }
    }
}
