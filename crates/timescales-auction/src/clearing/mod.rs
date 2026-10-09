//! Uniform-price clearing for a single call-auction book.
//!
//! Prices are band slots `0..K`. A buy at slot `b` is willing to trade at
//! every slot `p <= b`. A sell at slot `s` at every slot `p >= s`. Then
//!
//! ```text
//! D(p) = sum of buy quantity with slot >= p     (non-increasing in p)
//! S(p) = sum of sell quantity with slot <= p    (non-decreasing in p)
//! V(p) = min(D(p), S(p))                        executable volume
//! I(p) = |D(p) - S(p)|                          imbalance
//! ```
//!
//! A price `p` *strands* an order if some order with a strictly better limit
//! than `p` is left unfilled under price priority:
//!
//! ```text
//! strand(p) = D(p+1) > V(p)  or  S(p-1) > V(p)      (D = S(-1) = 0)
//! ```
//!
//! The clearing slot is the unique maximiser of the lexicographic key
//!
//! ```text
//! (V(p), not strand(p), -I(p), -|tick(p) - reference|, -p)
//! ```
//!
//! i.e. maximise volume. Among those, leave no order unfilled at a better
//! price (the DFBA condition, which picks the highest price under buy
//! surplus and the lowest under sell surplus, as Xetra does). Then minimise
//! imbalance (Nasdaq). Then stay closest to the reference price. Then prefer
//! the lower price. The last component makes the key injective in `p`, so
//! the maximiser is unique and every implementation that follows this
//! definition agrees bit for bit. A non-stranding volume maximiser always
//! exists, so the second component never has to
//! trade volume for fairness.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use thiserror::Error;
use timescales_core::{PriceBand, Side};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ClearingError {
    #[error("slot {slot} outside band of {ticks} ticks")]
    SlotOutOfBand { slot: u32, ticks: u32 },
    #[error("curve sum overflows u64")]
    Overflow,
}

/// Aggregate demand and supply at every band slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Curves {
    pub demand: Vec<u64>,
    pub supply: Vec<u64>,
}

impl Curves {
    /// Build from `(side, slot, quantity)` triples. Entries with no slot
    /// cannot trade and are skipped.
    pub fn build<I>(ticks: u32, entries: I) -> Result<Self, ClearingError>
    where
        I: IntoIterator<Item = (Side, Option<u32>, u64)>,
    {
        let k = ticks as usize;
        let mut buy_at = vec![0u64; k];
        let mut sell_at = vec![0u64; k];
        for (side, slot, q) in entries {
            let Some(s) = slot else { continue };
            if s >= ticks {
                return Err(ClearingError::SlotOutOfBand { slot: s, ticks });
            }
            let bucket = match side {
                Side::Buy => &mut buy_at[s as usize],
                Side::Sell => &mut sell_at[s as usize],
            };
            *bucket = bucket.checked_add(q).ok_or(ClearingError::Overflow)?;
        }
        let mut demand = vec![0u64; k];
        let mut acc = 0u64;
        for p in (0..k).rev() {
            acc = acc.checked_add(buy_at[p]).ok_or(ClearingError::Overflow)?;
            demand[p] = acc;
        }
        let mut supply = vec![0u64; k];
        acc = 0;
        for p in 0..k {
            acc = acc.checked_add(sell_at[p]).ok_or(ClearingError::Overflow)?;
            supply[p] = acc;
        }
        Ok(Self { demand, supply })
    }

    pub fn ticks(&self) -> u32 {
        u32::try_from(self.demand.len()).unwrap_or(u32::MAX)
    }

    pub fn volume(&self, p: u32) -> u64 {
        self.demand[p as usize].min(self.supply[p as usize])
    }

    pub fn imbalance(&self, p: u32) -> u64 {
        self.demand[p as usize].abs_diff(self.supply[p as usize])
    }

    /// Whether clearing at `p` leaves an order with a strictly better limit
    /// unfilled.
    pub fn strands(&self, p: u32) -> bool {
        let v = self.volume(p);
        let i = p as usize;
        let buy = i + 1 < self.demand.len() && self.demand[i + 1] > v;
        let sell = i > 0 && self.supply[i - 1] > v;
        buy || sell
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clearing {
    pub slot: u32,
    pub volume: u64,
    pub imbalance: u64,
}

/// Position of `slot` in the static tie-break order (0 is most preferred):
/// closest to the reference tick first, lower slot on equal distance.
///
/// The MPC and SNARK backends use this as a public constant per slot.
pub fn tie_break_rank(band: &PriceBand, slot: u32) -> u32 {
    let d = band.distance_to_reference(slot);
    let ticks = band.ticks();
    let better = (0..ticks)
        .filter(|&q| {
            let dq = band.distance_to_reference(q);
            dq < d || (dq == d && q < slot)
        })
        .count();
    u32::try_from(better).unwrap_or(u32::MAX)
}

/// [`tie_break_rank`] of every slot at once, indexed by slot. One sort
/// instead of a scan per slot, for the backends that rank the whole band.
pub fn tie_break_ranks(band: &PriceBand) -> Vec<u32> {
    let mut order: Vec<u32> = (0..band.ticks()).collect();
    order.sort_unstable_by_key(|&q| (band.distance_to_reference(q), q));
    let mut ranks = vec![0u32; order.len()];
    for (rank, &slot) in (0u32..).zip(&order) {
        ranks[slot as usize] = rank;
    }
    ranks
}

/// Apply the clearing rule. `curves` must have been built for `band`.
pub fn clear(curves: &Curves, band: &PriceBand) -> Clearing {
    let ticks = curves.ticks();
    debug_assert_eq!(ticks, band.ticks());
    let key = |p: u32| {
        (
            curves.volume(p),
            !curves.strands(p),
            core::cmp::Reverse(curves.imbalance(p)),
            core::cmp::Reverse(band.distance_to_reference(p)),
            core::cmp::Reverse(p),
        )
    };
    let best = (0..ticks).max_by_key(|&p| key(p)).unwrap_or(0);
    Clearing {
        slot: best,
        volume: curves.volume(best),
        imbalance: curves.imbalance(best),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use timescales_core::Tick;

    fn band(k: u32, reference_slot: u32) -> PriceBand {
        let lo = 1000u64;
        PriceBand {
            lo: Tick(lo),
            hi: Tick(lo + u64::from(k) - 1),
            reference: Tick(lo + u64::from(reference_slot)),
        }
    }

    fn entries() -> impl Strategy<Value = Vec<(Side, Option<u32>, u64)>> {
        prop::collection::vec(
            (
                prop_oneof![Just(Side::Buy), Just(Side::Sell)],
                prop::option::weighted(0.9, 0u32..9),
                0u64..50,
            ),
            0..40,
        )
    }

    #[test]
    fn crossing_book() {
        // Buys 10@slot4, 5@slot2. Sells 8@slot1, 4@slot3.
        let e = [
            (Side::Buy, Some(4), 10),
            (Side::Buy, Some(2), 5),
            (Side::Sell, Some(1), 8),
            (Side::Sell, Some(3), 4),
        ];
        let c = Curves::build(5, e).unwrap();
        assert_eq!(c.demand, vec![15, 15, 15, 10, 10]);
        assert_eq!(c.supply, vec![0, 8, 8, 12, 12]);
        let r = clear(&c, &band(5, 2));
        assert_eq!((r.slot, r.volume, r.imbalance), (3, 10, 2));
    }

    #[test]
    fn empty_book_clears_at_reference() {
        let c = Curves::build(7, []).unwrap();
        let r = clear(&c, &band(7, 3));
        assert_eq!((r.slot, r.volume), (3, 0));
    }

    #[test]
    fn every_clearing_error_is_produced() {
        // Exhaustive on purpose: a new variant must be produced here.
        fn variant(e: &ClearingError) -> usize {
            match e {
                ClearingError::SlotOutOfBand { .. } => 0,
                ClearingError::Overflow => 1,
            }
        }
        let errors = [
            Curves::build(5, [(Side::Buy, Some(5), 1)]).map(|_| ()),
            Curves::build(
                5,
                [(Side::Sell, Some(1), u64::MAX), (Side::Sell, Some(3), 1)],
            )
            .map(|_| ()),
        ];
        let seen: Vec<usize> = errors
            .iter()
            .map(|e| variant(e.as_ref().unwrap_err()))
            .collect();
        assert_eq!(seen, [0, 1]);
    }

    #[test]
    fn ranks_form_a_permutation() {
        let b = band(9, 2);
        let mut ranks: Vec<u32> = (0..9).map(|s| tie_break_rank(&b, s)).collect();
        assert_eq!(ranks[2], 0);
        assert_eq!(ranks[1], 1);
        assert_eq!(ranks[3], 2);
        ranks.sort_unstable();
        assert_eq!(ranks, (0..9).collect::<Vec<_>>());
    }

    #[test]
    fn ranks_table_matches_the_rank_function() {
        for (ticks, reference) in [(1, 0), (9, 2), (9, 8), (64, 31), (65, 32)] {
            let b = band(ticks, reference);
            let table = tie_break_ranks(&b);
            assert_eq!(table.len(), ticks as usize);
            for s in 0..ticks {
                assert_eq!(
                    table[s as usize],
                    tie_break_rank(&b, s),
                    "band {ticks} slot {s}"
                );
            }
        }
    }

    #[test]
    fn dfba_bid_auction_example() {
        // Jump's DFBA post, bid auction: maker buys 100@10.00, 1000@9.97.
        // Taker sells 100@10.01, 500@9.90. Expected clearing 9.97, volume 500.
        // Ticks of 0.01, band 9.80..10.20, reference deliberately far (9.80)
        // so the reference tie-break cannot be what selects 9.97.
        let b = PriceBand {
            lo: Tick(980),
            hi: Tick(1020),
            reference: Tick(980),
        };
        let slot = |t: u64| Some(u32::try_from(t - 980).unwrap());
        let e = [
            (Side::Buy, slot(1000), 100),
            (Side::Buy, slot(997), 1000),
            (Side::Sell, slot(1001), 100),
            (Side::Sell, slot(990), 500),
        ];
        let c = Curves::build(b.ticks(), e).unwrap();
        let r = clear(&c, &b);
        assert_eq!((b.tick_at(r.slot), r.volume), (Tick(997), 500));
    }

    #[test]
    fn dfba_ask_auction_example() {
        // Maker sells 100@10.01, 1000@10.03, 200@10.03. Taker buys 300@10.05,
        // 100@10.03. Expected 10.03, volume 400.
        let b = PriceBand {
            lo: Tick(980),
            hi: Tick(1020),
            reference: Tick(1020),
        };
        let slot = |t: u64| Some(u32::try_from(t - 980).unwrap());
        let e = [
            (Side::Sell, slot(1001), 100),
            (Side::Sell, slot(1003), 1000),
            (Side::Sell, slot(1003), 200),
            (Side::Buy, slot(1005), 300),
            (Side::Buy, slot(1003), 100),
        ];
        let c = Curves::build(b.ticks(), e).unwrap();
        let r = clear(&c, &b);
        assert_eq!((b.tick_at(r.slot), r.volume), (Tick(1003), 400));
    }

    proptest! {
        #[test]
        fn a_non_stranding_maximiser_exists(e in entries(), r in 0u32..9) {
            let b = band(9, r);
            let c = Curves::build(9, e).unwrap();
            let x = clear(&c, &b);
            prop_assert!(!c.strands(x.slot));
        }

        #[test]
        fn curves_match_definition(e in entries()) {
            let c = Curves::build(9, e.clone()).unwrap();
            for p in 0..9u32 {
                let d: u64 = e.iter().filter(|(s, sl, _)| *s == Side::Buy && sl.is_some_and(|x| x >= p)).map(|x| x.2).sum();
                let s: u64 = e.iter().filter(|(s, sl, _)| *s == Side::Sell && sl.is_some_and(|x| x <= p)).map(|x| x.2).sum();
                prop_assert_eq!(c.demand[p as usize], d);
                prop_assert_eq!(c.supply[p as usize], s);
            }
        }

        #[test]
        fn clearing_is_optimal_and_unique(e in entries(), r in 0u32..9) {
            let b = band(9, r);
            let c = Curves::build(9, e).unwrap();
            let x = clear(&c, &b);
            for p in 0..9u32 {
                if p == x.slot { continue; }
                let v = c.volume(p);
                prop_assert!(v <= x.volume);
                if v == x.volume {
                    prop_assert!(!c.strands(x.slot) || c.strands(p));
                    if c.strands(p) == c.strands(x.slot) {
                        let i = c.imbalance(p);
                        prop_assert!(i >= x.imbalance);
                        if i == x.imbalance {
                            prop_assert!(tie_break_rank(&b, p) > tie_break_rank(&b, x.slot));
                        }
                    }
                }
            }
        }
    }
}
