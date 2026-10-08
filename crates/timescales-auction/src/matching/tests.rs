use super::*;
use proptest::prelude::*;
use timescales_core::{OrderCommitment, Rationing, Role, Tick, TraderId};

fn band(k: u32, r: u32) -> PriceBand {
    PriceBand {
        lo: Tick(500),
        hi: Tick(500 + u64::from(k) - 1),
        reference: Tick(500 + u64::from(r)),
    }
}

fn bo(i: usize, side: Side, slot: Option<u32>, q: u64) -> BookOrder {
    let mut c = [0u8; 32];
    c[..8].copy_from_slice(&(i as u64).to_le_bytes());
    BookOrder {
        commitment: OrderCommitment(c),
        trader: TraderId([u8::try_from(i % 251).unwrap_or(0); 32]),
        side,
        role: Role::Taker,
        slot,
        quantity: Lots(q),
    }
}

/// Independent oracle: sort each side by price priority (stable, so
/// canonical order breaks ties) and hand out `V` greedily.
fn greedy(band: &PriceBand, orders: &[BookOrder]) -> (u32, u64, Vec<u64>) {
    let curves = Curves::build(
        band.ticks(),
        orders.iter().map(|o| (o.side, o.slot, o.quantity.0)),
    )
    .unwrap();
    let c = clear(&curves, band);
    let mut fills = vec![0u64; orders.len()];
    for side in [Side::Buy, Side::Sell] {
        let mut idx: Vec<usize> = (0..orders.len())
            .filter(|&i| {
                let o = &orders[i];
                o.side == side
                    && o.slot.is_some_and(|s| {
                        if side == Side::Buy {
                            s >= c.slot
                        } else {
                            s <= c.slot
                        }
                    })
            })
            .collect();
        idx.sort_by_key(|&i| {
            let s = orders[i].slot.unwrap_or(0);
            if side == Side::Buy {
                core::cmp::Reverse(s)
            } else {
                core::cmp::Reverse(u32::MAX - s)
            }
        });
        let mut rem = c.volume;
        for i in idx {
            let take = orders[i].quantity.0.min(rem);
            fills[i] = take;
            rem -= take;
        }
    }
    (c.slot, c.volume, fills)
}

fn book() -> impl Strategy<Value = (u32, u32, Vec<BookOrder>)> {
    (2u32..12).prop_flat_map(|k| {
        (
            Just(k),
            0..k,
            prop::collection::vec(
                (
                    prop_oneof![Just(Side::Buy), Just(Side::Sell)],
                    prop::option::weighted(0.9, 0..k),
                    0u64..20,
                ),
                0..60,
            )
            .prop_map(|v| {
                v.into_iter()
                    .enumerate()
                    .map(|(i, (s, sl, q))| bo(i, s, sl, q))
                    .collect()
            }),
        )
    })
}

#[test]
fn worked_example() {
    // Buys: 6@4, 5@3, 5@3. Sells: 4@1, 6@2. K = 5, reference slot 2.
    // D = [16,16,16,16,6], S = [0,4,10,10,10] -> V(2) = V(3) = 10.
    // Clearing at 2 would strand the buys at 3 (D(3) = 16 > 10), so p* = 3
    // even though 2 is closer to the reference.
    let orders = vec![
        bo(0, Side::Buy, Some(4), 6),
        bo(1, Side::Buy, Some(3), 5),
        bo(2, Side::Buy, Some(3), 5),
        bo(3, Side::Sell, Some(1), 4),
        bo(4, Side::Sell, Some(2), 6),
    ];
    let r = match_book(&band(5, 2), Rationing::Lottery, &orders).unwrap();
    assert_eq!((r.clearing.slot, r.clearing.volume), (3, 10));
    // Buy marginal level is slot 3 with residual 4: first in canonical order gets it.
    let f: Vec<u64> = r.fills.iter().map(|x| x.0).collect();
    assert_eq!(f, vec![6, 4, 0, 4, 6]);
}

#[test]
fn worked_example_pro_rata() {
    let orders = vec![
        bo(0, Side::Buy, Some(4), 6),
        bo(1, Side::Buy, Some(3), 5),
        bo(2, Side::Buy, Some(3), 5),
        bo(3, Side::Sell, Some(1), 4),
        bo(4, Side::Sell, Some(2), 6),
    ];
    // Same book. The marginal level (slot 3, M = 10) shares R = 4 pro rata.
    let r = match_book(&band(5, 2), Rationing::ProRata, &orders).unwrap();
    let f: Vec<u64> = r.fills.iter().map(|x| x.0).collect();
    assert_eq!(f.iter().take(3).sum::<u64>(), 10);
    assert_eq!(f, vec![6, 2, 2, 4, 6]);
}

/// The full DFBA example from Jump's post: both auctions, pro rata.
#[test]
fn dfba_worked_example() {
    let b = PriceBand {
        lo: Tick(980),
        hi: Tick(1020),
        reference: Tick(1000),
    };
    let s = |t: u64| Some(u32::try_from(t - 980).unwrap());
    // Bid auction: maker buys #1 100@10.00, #6 1000@9.97. Taker sells #5 100@10.01, #8 500@9.90.
    let bid = vec![
        bo(1, Side::Buy, s(1000), 100),
        bo(6, Side::Buy, s(997), 1000),
        bo(5, Side::Sell, s(1001), 100),
        bo(8, Side::Sell, s(990), 500),
    ];
    let r = match_book(&b, Rationing::ProRata, &bid).unwrap();
    assert_eq!(
        (b.tick_at(r.clearing.slot), r.clearing.volume),
        (Tick(997), 500)
    );
    assert_eq!(
        r.fills.iter().map(|x| x.0).collect::<Vec<_>>(),
        vec![100, 400, 0, 500]
    );
    // Ask auction: maker sells #2 100@10.01, #7 1000@10.03, #9 200@10.03.
    // Taker buys #3 300@10.05, #4 100@10.03.
    let ask = vec![
        bo(2, Side::Sell, s(1001), 100),
        bo(7, Side::Sell, s(1003), 1000),
        bo(9, Side::Sell, s(1003), 200),
        bo(3, Side::Buy, s(1005), 300),
        bo(4, Side::Buy, s(1003), 100),
    ];
    let r = match_book(&b, Rationing::ProRata, &ask).unwrap();
    assert_eq!(
        (b.tick_at(r.clearing.slot), r.clearing.volume),
        (Tick(1003), 400)
    );
    assert_eq!(
        r.fills.iter().map(|x| x.0).collect::<Vec<_>>(),
        vec![100, 250, 50, 300, 100]
    );
}

#[test]
fn no_cross_no_fills() {
    let orders = vec![bo(0, Side::Buy, Some(1), 5), bo(1, Side::Sell, Some(3), 5)];
    let r = match_book(&band(5, 2), Rationing::Lottery, &orders).unwrap();
    assert_eq!(r.clearing.volume, 0);
    assert!(r.fills.iter().all(|f| f.is_zero()));
}

#[test]
fn every_match_error_is_produced() {
    // Exhaustive on purpose: a new variant must be produced here.
    fn variant(e: &MatchError) -> usize {
        match e {
            MatchError::Clearing(_) => 0,
        }
    }
    let outside = [bo(0, Side::Buy, Some(5), 1)];
    let errors = [match_book(&band(5, 2), Rationing::Lottery, &outside).map(|_| ())];
    let seen: Vec<usize> = errors
        .iter()
        .map(|e| variant(e.as_ref().unwrap_err()))
        .collect();
    assert_eq!(seen, [0]);
    assert_eq!(
        errors[0],
        Err(MatchError::Clearing(ClearingError::SlotOutOfBand {
            slot: 5,
            ticks: 5
        }))
    );
}

proptest! {
    #[test]
    fn matches_greedy_oracle((k, r, orders) in book()) {
        let b = band(k, r);
        let res = match_book(&b, Rationing::Lottery, &orders).unwrap();
        let (slot, vol, fills) = greedy(&b, &orders);
        prop_assert_eq!(res.clearing.slot, slot);
        prop_assert_eq!(res.clearing.volume, vol);
        prop_assert_eq!(res.fills.iter().map(|f| f.0).collect::<Vec<_>>(), fills);
    }

    #[test]
    fn invariants((k, r, orders) in book(), pro_rata in any::<bool>()) {
        let b = band(k, r);
        let rule = if pro_rata { Rationing::ProRata } else { Rationing::Lottery };
        let res = match_book(&b, rule, &orders).unwrap();
        let p = res.clearing.slot;
        let mut buys = 0u64;
        let mut sells = 0u64;
        for (o, f) in orders.iter().zip(&res.fills) {
            prop_assert!(f.0 <= o.quantity.0, "overfill");
            if f.0 > 0 {
                let s = o.slot.expect("filled order must have a slot");
                match o.side {
                    Side::Buy => { prop_assert!(s >= p, "buy filled above its limit"); buys += f.0; }
                    Side::Sell => { prop_assert!(s <= p, "sell filled below its limit"); sells += f.0; }
                }
            }
        }
        prop_assert_eq!(buys, res.clearing.volume);
        prop_assert_eq!(sells, res.clearing.volume);
        // Price priority: any fill at a level implies every strictly better
        // level on the same side is full.
        for (o, f) in orders.iter().zip(&res.fills) {
            if f.0 == 0 { continue; }
            let s = o.slot.unwrap_or(0);
            for (o2, f2) in orders.iter().zip(&res.fills) {
                let better = match o.side {
                    Side::Buy => o2.slot.is_some_and(|s2| s2 > s),
                    Side::Sell => o2.slot.is_some_and(|s2| s2 < s),
                };
                if o2.side == o.side && better {
                    prop_assert_eq!(f2.0, o2.quantity.0);
                }
            }
        }
    }
}
