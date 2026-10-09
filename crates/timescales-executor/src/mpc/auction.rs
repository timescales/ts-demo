//! The batch auction over secret shares.
//!
//! Same semantics as the plaintext pipeline,
//! evaluated so that no party learns more than the public outputs:
//! fills, clearing prices and volumes, and the validity of each input.
//!
//! Phases and what they cost (n orders, K band ticks, B quantity bits,
//! T multi-order traders):
//!
//! | phase       | multiplications      | comparisons            |
//! |-------------|----------------------|------------------------|
//! | validity    | n (1 + B)            | -                      |
//! | self-trade  | ~ n * books          | 2 T * books            |
//! | collateral  | 4n                   | 2n                     |
//! | curves      | 4nK                  | -                      |
//! | clearing    | O per book        | ~ 6K per book          |
//! | allocation  | n * sides            | n * sides              |
//!
//! Everything else is linear in the shares and local.

// Slot, group and party indices are bounded by MAX_BAND_TICKS and the
// committee size, so the narrowing casts below cannot truncate.
#![allow(clippy::cast_possible_truncation, clippy::needless_range_loop)]

use std::collections::{BTreeMap, BTreeSet};

use timescales_auction::clearing::tie_break_ranks;
use timescales_auction::collateral::{BalanceSheet, buy_lock_per_lot};
use timescales_auction::orderbook::{OrderStateTable, fee_for};
use timescales_auction::{BatchHeader, canonical_order_by};
use timescales_core::intent::{MaskedBody, MaskedIntent};
use timescales_core::{
    BookId, ClearingPrice, Encode, Fill, Lots, OrderCommitment, PriceBand, Role, Side, TraderId,
};

use crate::mpc::encoding::{GROUPS, Layout};
use crate::mpc::engine::{Engine, Meter, MpcError};
use crate::mpc::field::Fp;
use crate::mpc::shares::Shared;

/// Public results of one MPC auction.
#[derive(Clone, Debug, Default)]
pub struct AuctionOutput {
    pub fills: Vec<Fill>,
    pub clearing: Vec<ClearingPrice>,
    pub cancelled: Vec<OrderCommitment>,
    /// Inputs rejected for public reasons or failed validity checks.
    pub rejected: usize,
    pub accepted: usize,
    /// Cumulative meter after each phase.
    pub phases: Vec<(&'static str, Meter)>,
}

struct Place {
    commitment: OrderCommitment,
    trader: TraderId,
    nonce: u64,
    valid_from: u64,
    expires_at: u64,
    x: Shared,
}

/// Bits needed for any curve value of this market.
pub fn quantity_width(header: &BatchHeader) -> u32 {
    let env_bits = 32
        - header
            .params
            .max_batch_envelopes
            .saturating_sub(1)
            .leading_zeros();
    u32::from(header.params.max_order_lots_log2) + env_bits + 1
}

/// Width for collateral comparisons: balances are `u64`.
pub const COLLATERAL_WIDTH: u32 = 64;

/// Run the auction. Any failure is followed by a MAC check, so an abort
/// caused by tampered openings is reported as such rather than as whatever
/// inconsistency the tampering produced first.
pub fn run(
    engine: &mut Engine,
    header: &BatchHeader,
    band: &PriceBand,
    intents: &[MaskedIntent],
    balances: &BalanceSheet,
    prior: &OrderStateTable,
) -> Result<AuctionOutput, MpcError> {
    match run_inner(engine, header, band, intents, balances, prior) {
        Ok(out) => Ok(out),
        Err(e @ MpcError::PartyUnavailable { .. }) => Err(e),
        Err(e) => {
            engine.mac_check()?;
            Err(e)
        }
    }
}

fn run_inner(
    engine: &mut Engine,
    header: &BatchHeader,
    band: &PriceBand,
    intents: &[MaskedIntent],
    balances: &BalanceSheet,
    prior: &OrderStateTable,
) -> Result<AuctionOutput, MpcError> {
    let params = &header.params;
    let layout = Layout::new(band, params.max_order_lots_log2);
    let l = layout.len();
    let k = band.ticks() as usize;
    let kq = quantity_width(header);
    let mut out = AuctionOutput::default();

    // ---- Public validation, canonical order. ----
    let order = canonical_order_by(&header.seed(), intents, |m| m.commitment, |m| m.to_bytes());
    let mut seen = BTreeSet::new();
    let mut cancels: BTreeMap<OrderCommitment, Vec<TraderId>> = BTreeMap::new();
    let mut raw: Vec<&MaskedIntent> = Vec::new();
    for (i, _) in &order {
        let m = &intents[*i];
        if m.market != header.market || m.epoch != header.epoch || m.verify_signature().is_err() {
            out.rejected += 1;
            continue;
        }
        match &m.body {
            MaskedBody::Noop => {}
            _ if !seen.insert(m.commitment) => out.rejected += 1,
            MaskedBody::Cancel(c) => {
                if c.market != params.market || c.epoch != header.epoch {
                    out.rejected += 1;
                } else {
                    cancels.entry(c.target).or_default().push(c.trader);
                }
            }
            MaskedBody::Place(_) => raw.push(m),
        }
    }

    // Inputs: take mask shares and add the published differences.
    let mut places = Vec::with_capacity(raw.len());
    for m in raw {
        let MaskedBody::Place(p) = &m.body else {
            continue;
        };
        let vals: Option<Vec<Fp>> = p
            .values
            .iter()
            .map(|v| Fp::from_bytes(v.0.to_le_bytes()))
            .collect();
        let (Some(vals), true) = (vals, p.values.len() == l) else {
            out.rejected += 1;
            continue;
        };
        let Some(mask) = engine.dealer().take_masks(&p.trader, p.mask_offset, l) else {
            out.rejected += 1;
            continue;
        };
        places.push(Place {
            commitment: m.commitment,
            trader: p.trader,
            nonce: p.nonce,
            valid_from: p.valid_from.0,
            expires_at: p.expires_at.0,
            x: engine.add_public(&mask, &vals),
        });
    }

    // Validity: one-hot via (sum rho u)^2 = sum rho^2 u, plus sum u = 1,
    // plus bit checks on the quantity. A single opened value per order.
    let valid = validity(engine, &layout, &places)?;
    // Validity bits decide who is rejected. Check them before acting.
    engine.mac_check()?;
    out.phases.push(("validity", engine.meter()));
    let mut nonces = BTreeSet::new();
    let mut counts: BTreeMap<TraderId, u32> = BTreeMap::new();
    let mut live: Vec<(Place, u64)> = Vec::new();
    for (p, ok) in places.into_iter().zip(valid) {
        let reject = !ok
            || p.valid_from > header.epoch.0
            || header.epoch.0 > p.expires_at
            || p.expires_at - p.valid_from > u64::from(params.max_order_lifetime)
            || !nonces.insert((p.trader, p.nonce));
        if reject {
            out.rejected += 1;
            continue;
        }
        if cancels
            .get(&p.commitment)
            .is_some_and(|ts| ts.contains(&p.trader))
        {
            out.cancelled.push(p.commitment);
            out.rejected += 1;
            continue;
        }
        let filled = match prior.get(&p.commitment) {
            Some(e) if e.cancelled => {
                out.rejected += 1;
                continue;
            }
            Some(e) => e.filled.0,
            None => 0,
        };
        let c = counts.entry(p.trader).or_insert(0);
        if *c >= u32::from(params.max_orders_per_trader) {
            out.rejected += 1;
            continue;
        }
        *c += 1;
        live.push((p, filled));
    }
    let n = live.len();
    out.accepted = n;

    let parties = engine.parties();
    let auth = engine.authenticated();
    let xs: Vec<&Shared> = live.iter().map(|(p, _)| &p.x).collect();
    let x = if xs.is_empty() {
        Shared::zeros(parties, 0, auth)
    } else {
        Shared::concat(&xs)
    };
    let at = |i: usize, pos: usize| i * l + pos;

    // Remaining quantity q' = sum 2^b bits - filled.
    let q_rows: Vec<Vec<(usize, Fp)>> = (0..n)
        .map(|i| {
            (0..layout.qty_bits)
                .map(|b| (at(i, layout.bit_pos(b)), Fp::pow2(b)))
                .collect()
        })
        .collect();
    let filled: Vec<Fp> = live.iter().map(|(_, f)| -Fp::from_u64(*f)).collect();
    let q = engine.add_public(&x.linear(&q_rows), &filled);

    let books: Vec<BookId> = BookId::books(params.flow).to_vec();
    let pairs: Vec<(BookId, Side)> = books
        .iter()
        .flat_map(|b| [(*b, Side::Buy), (*b, Side::Sell)])
        .collect();
    let pair_groups: Vec<Vec<usize>> = pairs
        .iter()
        .map(|(b, s)| Layout::groups_for(params.flow, *b, *s))
        .collect();

    // ---- Self-trade prevention. ----
    let keep = self_trade(
        engine,
        &layout,
        &x,
        &q,
        &live,
        &books,
        &pairs,
        &pair_groups,
        kq,
        n,
    )?;
    out.phases.push(("self-trade", engine.meter()));

    // ---- Collateral, prefix rule. ----
    let qk = engine.mul(&keep, &q)?;
    let mut lock_rows = Vec::with_capacity(n);
    let mut base_rows = Vec::with_capacity(n);
    for i in 0..n {
        let mut lr = Vec::new();
        let mut br = Vec::new();
        for (g, (role, side)) in GROUPS.iter().enumerate() {
            for j in 0..k {
                let p = at(i, layout.pos(g, Some(j as u32)));
                match side {
                    Side::Buy => {
                        let per_lot =
                            buy_lock_per_lot(params, band, j as u32, fee_for(params, *role));
                        lr.push((p, Fp::new(per_lot)));
                    }
                    Side::Sell => br.push((p, Fp::from_u64(params.base_lot_size))),
                }
            }
        }
        lock_rows.push(lr);
        base_rows.push(br);
    }
    let lock = x.linear(&lock_rows);
    let base = x.linear(&base_rows);
    let r = engine.mul_many(&[(&qk, &lock), (&qk, &base)])?;
    let (quote_req, base_req) = (&r[0], &r[1]);
    let mut prefix_rows = Vec::with_capacity(n);
    let mut by_trader: BTreeMap<TraderId, Vec<usize>> = BTreeMap::new();
    for (i, (p, _)) in live.iter().enumerate() {
        let v = by_trader.entry(p.trader).or_default();
        v.push(i);
        prefix_rows.push(v.iter().map(|&j| (j, Fp::ONE)).collect::<Vec<_>>());
    }
    let pq = quote_req.linear(&prefix_rows);
    let pb = base_req.linear(&prefix_rows);
    let bal_q: Vec<Fp> = live
        .iter()
        .map(|(p, _)| Fp::from_u64(balances.get(&p.trader).quote.0))
        .collect();
    let bal_b: Vec<Fp> = live
        .iter()
        .map(|(p, _)| Fp::from_u64(balances.get(&p.trader).base.0))
        .collect();
    let bals = engine.constant(&[bal_q, bal_b].concat());
    let ok = engine.ge(&bals, &Shared::concat(&[&pq, &pb]), COLLATERAL_WIDTH)?;
    let ok = ok.split(&[n, n]);
    let acc = engine.mul(&ok[0], &ok[1])?;
    let xq = engine.mul(&acc, &qk)?;
    out.phases.push(("collateral", engine.meter()));

    // ---- Curves. y[i,g,j] = xq_i * u[i,g,j] for in-band j. ----
    let in_band: Vec<usize> = (0..4)
        .flat_map(|g| (0..k).map(move |j| layout.pos(g, Some(j as u32))))
        .collect();
    let mut sel = Vec::with_capacity(n * in_band.len());
    let mut rep = Vec::with_capacity(n * in_band.len());
    for i in 0..n {
        for p in &in_band {
            sel.push(at(i, *p));
            rep.push(i);
        }
    }
    let y = engine.mul(&xq.gather(&rep), &x.gather(&sel))?;
    let yi = |i: usize, g: usize, j: usize| i * 4 * k + g * k + j;
    let level_rows = |gs: &[usize], j: usize| -> Vec<(usize, Fp)> {
        (0..n)
            .flat_map(|i| gs.iter().map(move |&g| (yi(i, g, j), Fp::ONE)))
            .collect()
    };
    // Per pair, per slot: total quantity at that level.
    let mut lv_rows = Vec::with_capacity(pairs.len() * k);
    for gs in &pair_groups {
        for j in 0..k {
            lv_rows.push(level_rows(gs, j));
        }
    }
    let levels = y.linear(&lv_rows);
    let lvl = |pi: usize, j: usize| pi * k + j;
    // D_B(p) = sum_{j >= p} buy level. S_B(p) = sum_{j <= p} sell level.
    let mut curve_rows = Vec::with_capacity(books.len() * 2 * k);
    for bi in 0..books.len() {
        let (pb, ps) = (2 * bi, 2 * bi + 1);
        for p in 0..k {
            curve_rows.push((p..k).map(|j| (lvl(pb, j), Fp::ONE)).collect::<Vec<_>>());
        }
        for p in 0..k {
            curve_rows.push((0..=p).map(|j| (lvl(ps, j), Fp::ONE)).collect::<Vec<_>>());
        }
    }
    let curves = levels.linear(&curve_rows);
    out.phases.push(("curves", engine.meter()));

    // ---- Clearing per book, all books together. ----
    let nb = books.len();
    let d_idx = |b: usize, p: usize| b * 2 * k + p;
    let s_idx = |b: usize, p: usize| b * 2 * k + k + p;
    let d = curves.gather(
        &(0..nb)
            .flat_map(|b| (0..k).map(move |p| d_idx(b, p)))
            .collect::<Vec<_>>(),
    );
    let s = curves.gather(
        &(0..nb)
            .flat_map(|b| (0..k).map(move |p| s_idx(b, p)))
            .collect::<Vec<_>>(),
    );
    let lt_ds = engine.lt(&d, &s, kq)?;
    let t = engine.mul(&lt_ds, &d.sub(&s))?;
    let vol = s.add(&t);
    let imb = d.sub(&s).sub(&t.scale(Fp::from_u64(2)));
    // strand(p): D(p+1) > V(p) or S(p-1) > V(p). Missing neighbours are 0
    // and can never exceed a volume.
    let zero = Shared::zeros(parties, 1, auth);
    let mut next_d = Vec::with_capacity(nb * k);
    let mut prev_s = Vec::with_capacity(nb * k);
    for b in 0..nb {
        for p in 0..k {
            next_d.push(if p + 1 < k {
                curves.gather(&[d_idx(b, p + 1)])
            } else {
                zero.clone()
            });
            prev_s.push(if p > 0 {
                curves.gather(&[s_idx(b, p - 1)])
            } else {
                zero.clone()
            });
        }
    }
    let next_d = Shared::concat(&next_d.iter().collect::<Vec<_>>());
    let prev_s = Shared::concat(&prev_s.iter().collect::<Vec<_>>());
    let st = engine.lt(
        &Shared::concat(&[&vol, &vol]),
        &Shared::concat(&[&next_d, &prev_s]),
        kq,
    )?;
    let st = st.split(&[nb * k, nb * k]);
    let both = engine.mul(&st[0], &st[1])?;
    let strand = st[0].add(&st[1]).sub(&both);
    let ns = engine.not(&strand);

    // Tournament over slots in tie-break order: left always ranks better,
    // so "left wins full ties" implements the final tie-break.
    let ranks = tie_break_ranks(band);
    let mut ranked: Vec<u32> = (0..k as u32).collect();
    ranked.sort_by_key(|&p| ranks[p as usize]);
    let per_book = |v: &Shared| -> Shared {
        v.gather(
            &(0..nb)
                .flat_map(|b| ranked.iter().map(move |&p| b * k + p as usize))
                .collect::<Vec<_>>(),
        )
    };
    let mut cand = Candidates {
        v: per_book(&vol),
        ns: per_book(&ns),
        i: per_book(&imb),
        idx: engine.constant(
            &(0..nb)
                .flat_map(|_| ranked.iter().map(|&p| Fp::from_u64(u64::from(p))))
                .collect::<Vec<_>>(),
        ),
        width: k,
    };
    while cand.width > 1 {
        cand = tournament_round(engine, cand, nb, kq)?;
    }
    let opened = engine.open(&Shared::concat(&[&cand.idx, &cand.v]))?;
    engine.mac_check()?;
    let mut winners = Vec::with_capacity(nb);
    for b in 0..nb {
        let slot =
            u32::try_from(opened[b].value()).map_err(|_| MpcError::Input("clearing slot"))?;
        let volume =
            u64::try_from(opened[nb + b].value()).map_err(|_| MpcError::Input("volume"))?;
        if slot as usize >= k {
            return Err(MpcError::Input("clearing slot out of band"));
        }
        winners.push((slot as usize, volume));
    }
    out.phases.push(("clearing", engine.meter()));

    // ---- Allocation: f_i = full_i + min(R, P_(i+1)) - min(R, P_i). ----
    let mut full_rows = Vec::new();
    let mut marg_rows = Vec::new();
    let mut residual = Vec::new();
    for (pi, (_, side)) in pairs.iter().enumerate() {
        let b = pi / 2;
        let (p, v) = winners[b];
        let gs = &pair_groups[pi];
        let better: Vec<usize> = match side {
            Side::Buy => (p + 1..k).collect(),
            Side::Sell => (0..p).collect(),
        };
        for i in 0..n {
            full_rows.push(
                gs.iter()
                    .flat_map(|&g| better.iter().map(move |&j| (yi(i, g, j), Fp::ONE)))
                    .collect::<Vec<_>>(),
            );
            marg_rows.push(
                gs.iter()
                    .map(|&g| (yi(i, g, p), Fp::ONE))
                    .collect::<Vec<_>>(),
            );
        }
        // R = V - D(p+1) for buys, V - S(p-1) for sells.
        let neighbour = match side {
            Side::Buy if p + 1 < k => curves.gather(&[d_idx(b, p + 1)]),
            Side::Sell if p > 0 => curves.gather(&[s_idx(b, p - 1)]),
            _ => zero.clone(),
        };
        residual.push(engine.add_const(&neighbour.scale(-Fp::ONE), Fp::from_u64(v)));
    }
    let full = y.linear(&full_rows);
    let marg = y.linear(&marg_rows);
    let np = pairs.len();
    let mut prefixes = Vec::with_capacity(np);
    let mut rs = Vec::with_capacity(np);
    for pi in 0..np {
        prefixes.push(marg.slice(pi * n, n).exclusive_prefix());
        rs.push(residual[pi].gather(&vec![0; n + 1]));
    }
    let g = engine.min(
        &Shared::concat(&rs.iter().collect::<Vec<_>>()),
        &Shared::concat(&prefixes.iter().collect::<Vec<_>>()),
        kq,
    )?;
    let mut fill_rows = Vec::with_capacity(np * n);
    for pi in 0..np {
        for i in 0..n {
            let base = pi * (n + 1);
            fill_rows.push(vec![(base + i + 1, Fp::ONE), (base + i, -Fp::ONE)]);
        }
    }
    let fills = full.add(&g.linear(&fill_rows));
    let fills = engine.open(&fills)?;
    out.phases.push(("allocation", engine.meter()));

    // Roles of filled orders, for fees. Derivable from book and side under
    // dual flow. Opened explicitly for single-book markets.
    let filled_any: Vec<bool> = (0..n)
        .map(|i| (0..np).any(|pi| !fills[pi * n + i].is_zero()))
        .collect();
    let roles: Vec<Option<Role>> = match params.flow {
        timescales_core::FlowMode::DualFlow => vec![None; n],
        timescales_core::FlowMode::SingleBook => {
            let who: Vec<usize> = (0..n).filter(|&i| filled_any[i]).collect();
            let rows: Vec<Vec<(usize, Fp)>> = who
                .iter()
                .map(|&i| {
                    (0..4)
                        .filter(|&g| GROUPS[g].0 == Role::Maker)
                        .flat_map(|g| (0..=k).map(move |j| (at(i, g * (k + 1) + j), Fp::ONE)))
                        .collect()
                })
                .collect();
            let opened = engine.open(&x.linear(&rows))?;
            let mut r = vec![None; n];
            for (w, v) in who.iter().zip(opened) {
                r[*w] = Some(if v == Fp::ONE {
                    Role::Maker
                } else {
                    Role::Taker
                });
            }
            r
        }
    };
    engine.mac_check()?;
    out.phases.push(("output", engine.meter()));

    for (bi, book) in books.iter().enumerate() {
        let (slot, volume) = winners[bi];
        let tick = band.tick_at(slot as u32);
        out.clearing.push(ClearingPrice {
            book: *book,
            tick,
            volume: Lots(volume),
        });
        for i in 0..n {
            for side in [Side::Buy, Side::Sell] {
                let pi = 2 * bi + usize::from(side == Side::Sell);
                let f = fills[pi * n + i];
                if f.is_zero() {
                    continue;
                }
                let qty = u64::try_from(f.value()).map_err(|_| MpcError::Input("fill"))?;
                let role = roles[i].unwrap_or_else(|| dual_role(*book, side));
                out.fills.push(Fill {
                    commitment: live[i].0.commitment,
                    trader: live[i].0.trader,
                    book: *book,
                    side,
                    role,
                    quantity: Lots(qty),
                    tick,
                });
            }
        }
    }
    Ok(out)
}

fn dual_role(book: BookId, side: Side) -> Role {
    match (book, side) {
        (BookId::MakerAskTakerBid, Side::Sell) | (BookId::MakerBidTakerAsk, Side::Buy) => {
            Role::Maker
        }
        _ => Role::Taker,
    }
}

fn validity(engine: &mut Engine, layout: &Layout, places: &[Place]) -> Result<Vec<bool>, MpcError> {
    let n = places.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let oh = layout.onehot_len();
    let bits = layout.qty_bits as usize;
    let rho = engine.dealer().coins(oh);
    let rho_bits = engine.dealer().coins(bits);
    let rho_sum = engine.dealer().coins(1)[0];
    let xs: Vec<&Shared> = places.iter().map(|p| &p.x).collect();
    let x = Shared::concat(&xs);
    let l = layout.len();
    let s = x.linear(
        &(0..n)
            .map(|i| (0..oh).map(|j| (i * l + j, rho[j])).collect())
            .collect::<Vec<_>>(),
    );
    let s2 = x.linear(
        &(0..n)
            .map(|i| (0..oh).map(|j| (i * l + j, rho[j] * rho[j])).collect())
            .collect::<Vec<_>>(),
    );
    let sum = x.linear(
        &(0..n)
            .map(|i| (0..oh).map(|j| (i * l + j, Fp::ONE)).collect())
            .collect::<Vec<_>>(),
    );
    let b = x.gather(
        &(0..n)
            .flat_map(|i| (0..bits).map(move |j| i * l + oh + j))
            .collect::<Vec<_>>(),
    );
    let sq = engine.mul_many(&[(&s, &s), (&b, &b)])?;
    // sum_l rho_l (b_l^2 - b_l)
    let bitterm = sq[1].sub(&b).linear(
        &(0..n)
            .map(|i| (0..bits).map(|j| (i * bits + j, rho_bits[j])).collect())
            .collect::<Vec<_>>(),
    );
    let sum_minus_one = engine.add_const(&sum, -Fp::ONE).scale(rho_sum);
    let v = sq[0].sub(&s2).add(&sum_minus_one).add(&bitterm);
    let opened = engine.open(&v)?;
    Ok(opened.iter().map(|z| z.is_zero()).collect())
}

#[allow(clippy::too_many_arguments)]
fn self_trade(
    engine: &mut Engine,
    layout: &Layout,
    x: &Shared,
    q: &Shared,
    live: &[(Place, u64)],
    books: &[BookId],
    pairs: &[(BookId, Side)],
    pair_groups: &[Vec<usize>],
    kq: u32,
    n: usize,
) -> Result<Shared, MpcError> {
    let l = layout.len();
    let k = layout.ticks as usize;
    // Only traders with two or more orders can be in conflict. That is
    // public, so everyone else skips the computation.
    let mut count: BTreeMap<TraderId, usize> = BTreeMap::new();
    for (p, _) in live {
        *count.entry(p.trader).or_default() += 1;
    }
    let multi: Vec<usize> = (0..n).filter(|&i| count[&live[i].0.trader] > 1).collect();
    let one = engine.constant(&vec![Fp::ONE; n]);
    if multi.is_empty() {
        return Ok(one);
    }
    // In-band presence per (order, pair), weighted by remaining quantity.
    let e_rows: Vec<Vec<(usize, Fp)>> = multi
        .iter()
        .flat_map(|&i| {
            pair_groups.iter().map(move |gs| {
                gs.iter()
                    .flat_map(|&g| {
                        (0..k).map(move |j| (i * l + layout.pos(g, Some(j as u32)), Fp::ONE))
                    })
                    .collect()
            })
        })
        .collect();
    let e = x.linear(&e_rows);
    let np = pairs.len();
    let qrep = q.gather(
        &multi
            .iter()
            .flat_map(|&i| std::iter::repeat_n(i, np))
            .collect::<Vec<_>>(),
    );
    let w = engine.mul(&qrep, &e)?;
    let traders: Vec<TraderId> = multi
        .iter()
        .map(|&i| live[i].0.trader)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let tpos: BTreeMap<TraderId, usize> =
        traders.iter().enumerate().map(|(i, t)| (*t, i)).collect();
    // W[t, pair] = sum of w over the trader's orders.
    let mut w_rows = vec![Vec::new(); traders.len() * np];
    for (mi, &i) in multi.iter().enumerate() {
        let t = tpos[&live[i].0.trader];
        for pi in 0..np {
            w_rows[t * np + pi].push((mi * np + pi, Fp::ONE));
        }
    }
    let wt = w.linear(&w_rows);
    let has = engine.ge(&wt, &engine.constant(&vec![Fp::ONE; wt.len()]), kq)?;
    let nb = books.len();
    let buys = has.gather(
        &(0..traders.len())
            .flat_map(|t| (0..nb).map(move |b| t * np + 2 * b))
            .collect::<Vec<_>>(),
    );
    let sells = has.gather(
        &(0..traders.len())
            .flat_map(|t| (0..nb).map(move |b| t * np + 2 * b + 1))
            .collect::<Vec<_>>(),
    );
    let conflict = engine.mul(&buys, &sells)?;
    // Membership of each order in each book (all positions of its groups).
    let book_groups: Vec<Vec<usize>> = (0..nb)
        .map(|b| [pair_groups[2 * b].clone(), pair_groups[2 * b + 1].clone()].concat())
        .collect();
    let in_rows: Vec<Vec<(usize, Fp)>> = multi
        .iter()
        .flat_map(|&i| {
            book_groups.iter().map(move |gs| {
                gs.iter()
                    .flat_map(|&g| (0..=k).map(move |j| (i * l + g * (k + 1) + j, Fp::ONE)))
                    .collect()
            })
        })
        .collect();
    let inbook = x.linear(&in_rows);
    let crep = conflict.gather(
        &multi
            .iter()
            .flat_map(|&i| {
                let t = tpos[&live[i].0.trader];
                (0..nb).map(move |b| t * nb + b)
            })
            .collect::<Vec<_>>(),
    );
    let hit = engine.mul(&inbook, &crep)?;
    let stp_multi = hit.linear(
        &(0..multi.len())
            .map(|mi| (0..nb).map(|b| (mi * nb + b, Fp::ONE)).collect())
            .collect::<Vec<_>>(),
    );
    // keep = 1 - stp, with stp = 0 for single-order traders.
    let mut rows = vec![Vec::new(); n];
    for (mi, &i) in multi.iter().enumerate() {
        rows[i].push((mi, Fp::ONE));
    }
    let stp = stp_multi.linear(&rows);
    Ok(one.sub(&stp))
}

struct Candidates {
    v: Shared,
    ns: Shared,
    i: Shared,
    idx: Shared,
    width: usize,
}

/// One tournament level over every book at once. Pairs adjacent
/// candidates. An odd one out advances unopposed.
fn tournament_round(
    engine: &mut Engine,
    c: Candidates,
    books: usize,
    kq: u32,
) -> Result<Candidates, MpcError> {
    let w = c.width;
    let half = w / 2;
    let left: Vec<usize> = (0..books)
        .flat_map(|b| (0..half).map(move |j| b * w + 2 * j))
        .collect();
    let right: Vec<usize> = left.iter().map(|x| x + 1).collect();
    let pick = |s: &Shared, idx: &[usize]| s.gather(idx);
    let (va, vb) = (pick(&c.v, &left), pick(&c.v, &right));
    let (na, nbb) = (pick(&c.ns, &left), pick(&c.ns, &right));
    let (ia, ib) = (pick(&c.i, &left), pick(&c.i, &right));
    let (xa, xb) = (pick(&c.idx, &left), pick(&c.idx, &right));
    let m = va.len();
    let cmp = engine.lt(
        &Shared::concat(&[&va, &vb, &ib]),
        &Shared::concat(&[&vb, &va, &ia]),
        kq,
    )?;
    let cmp = cmp.split(&[m, m, m]);
    let (b_more_v, a_more_v, b_less_i) = (&cmp[0], &cmp[1], &cmp[2]);
    let eq_v = engine.not(&b_more_v.add(a_more_v));
    let nab = engine.mul(&na, &nbb)?;
    let nsb_better = nbb.sub(&nab);
    // eq_ns = 1 - a - b + 2ab
    let eq_ns = engine.add_const(&nab.scale(Fp::from_u64(2)).sub(&na).sub(&nbb), Fp::ONE);
    let inner = nsb_better.add(&engine.mul(&eq_ns, b_less_i)?);
    let b_wins = b_more_v.add(&engine.mul(&eq_v, &inner)?);
    let diffs = engine.mul_many(&[
        (&b_wins, &vb.sub(&va)),
        (&b_wins, &nbb.sub(&na)),
        (&b_wins, &ib.sub(&ia)),
        (&b_wins, &xb.sub(&xa)),
    ])?;
    let wv = va.add(&diffs[0]);
    let wn = na.add(&diffs[1]);
    let wi = ia.add(&diffs[2]);
    let wx = xa.add(&diffs[3]);
    let new_w = half + w % 2;
    // Reassemble per book: winners, then the bye if any, preserving order.
    let mut order_v = Vec::new();
    let mut order_n = Vec::new();
    let mut order_i = Vec::new();
    let mut order_x = Vec::new();
    for b in 0..books {
        for j in 0..half {
            let at = b * half + j;
            order_v.push(wv.gather(&[at]));
            order_n.push(wn.gather(&[at]));
            order_i.push(wi.gather(&[at]));
            order_x.push(wx.gather(&[at]));
        }
        if w % 2 == 1 {
            let at = b * w + w - 1;
            order_v.push(c.v.gather(&[at]));
            order_n.push(c.ns.gather(&[at]));
            order_i.push(c.i.gather(&[at]));
            order_x.push(c.idx.gather(&[at]));
        }
    }
    let cat = |v: Vec<Shared>| Shared::concat(&v.iter().collect::<Vec<_>>());
    Ok(Candidates {
        v: cat(order_v),
        ns: cat(order_n),
        i: cat(order_i),
        idx: cat(order_x),
        width: new_w,
    })
}
