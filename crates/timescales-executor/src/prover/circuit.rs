//! R1CS for one batch: commitment openings, slot encoding, curves,
//! clearing optimality, allocation, and the public transcript.
//!
//! Every envelope of the batch occupies one entry, in canonical order.
//! Non-admitted entries carry a dummy witness and contribute nothing. The
//! circuit's shape depends only on `CircuitShape`, never on the data.
//!
//! Comparisons use a witness bit plus a range check on the signed gap, so
//! a comparison of `w`-bit values costs about `w + 2` constraints.

use crate::verifier::{CircuitShape, TranscriptEntry};
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use timescales_core::commitment::{Committable, Salt, poseidon};
use timescales_core::{BookId, Order, Side};
use zeroize::Zeroize;

use crate::prover::ProverError;

type R<T> = Result<T, SynthesisError>;

/// Bits for slot indices and tie-break ranks (`K <= 1025`).
const SLOT_BITS: u32 = 11;

/// Private data behind one admitted entry.
#[derive(Clone)]
pub struct OrderWitness {
    pub order: Order,
    pub salt: Salt,
    /// `(group, slot)` of the order in the band. `slot = None` if it cannot
    /// trade.
    pub group: usize,
    pub slot: Option<u32>,
}

/// The witness is a plaintext order. Nothing of it is printed.
impl core::fmt::Debug for OrderWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrderWitness(..)")
    }
}

impl OrderWitness {
    /// Overwrites the salt, the trader and every number of the order. Side,
    /// role and kind are enums, which `zeroize` cannot overwrite without
    /// unsafe code, so they stay.
    fn wipe(&mut self) {
        let Order {
            market,
            trader,
            nonce,
            side: _,
            role: _,
            kind: _,
            limit,
            quantity,
            valid_from,
            expires_at,
        } = &mut self.order;
        market.0.zeroize();
        trader.0.zeroize();
        nonce.zeroize();
        limit.0.zeroize();
        quantity.0.zeroize();
        valid_from.0.zeroize();
        expires_at.0.zeroize();
        self.salt.0.zeroize();
        self.group.zeroize();
        self.slot.zeroize();
    }
}

/// Every copy of a witness is wiped when dropped, including the ones a
/// proved circuit drops. The constraint system keeps its own assignment as
/// field elements, which arkworks does not wipe.
impl Drop for OrderWitness {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// `entry` is public transcript data. `order` prints redacted.
#[derive(Clone, Debug)]
pub struct EntryInput {
    pub entry: TranscriptEntry,
    pub order: Option<OrderWitness>,
}

impl EntryInput {
    pub fn padding() -> Self {
        Self {
            entry: TranscriptEntry::padding(),
            order: None,
        }
    }
}

/// Public inputs and witnesses for one batch. `Debug` prints the public
/// part. The witnesses print redacted (see [`OrderWitness`]).
#[derive(Clone, Debug)]
pub struct AuctionCircuit {
    pub shape: CircuitShape,
    pub lo: u64,
    pub entries: Vec<EntryInput>,
    /// `(clearing slot, volume)` per book.
    pub books: Vec<(u32, u64)>,
    pub transcript: Fr,
}

impl AuctionCircuit {
    /// A circuit with the right shape and no data, for key generation.
    pub fn blank(shape: CircuitShape) -> Result<Self, ProverError> {
        if shape.ticks == 0 {
            return Err(ProverError::Shape("a band has at least one tick"));
        }
        let w = (shape.ticks - 1) / 2;
        Ok(Self {
            shape,
            lo: 1,
            entries: vec![EntryInput::padding(); shape.capacity],
            books: shape.books().iter().map(|_| (w, 0)).collect(),
            transcript: Fr::from(0u64),
        })
    }
}

/// Position of a slot in the static tie-break order for a band whose
/// reference sits at slot `w` (always the band centre).
fn rank(p: u32, w: u32) -> u64 {
    let k = 2 * w + 1;
    let d = |q: u32| q.abs_diff(w);
    (0..k)
        .filter(|&q| d(q) < d(p) || (d(q) == d(p) && q < p))
        .count() as u64
}

fn pow2(k: u32) -> Fr {
    Fr::from(2u64).pow([u64::from(k)])
}

fn constant(x: u64) -> FpVar<Fr> {
    FpVar::constant(Fr::from(x))
}

/// Enforce `0 <= v < 2^bits`.
fn range(cs: &ConstraintSystemRef<Fr>, v: &FpVar<Fr>, bits: u32) -> R<()> {
    let mut b = Vec::with_capacity(bits as usize);
    for i in 0..bits as usize {
        b.push(Boolean::new_witness(cs.clone(), || {
            Ok(v.value()?.into_bigint().get_bit(i))
        })?);
    }
    Boolean::le_bits_to_fp(&b)?.enforce_equal(v)
}

/// `[a < b]` for `a, b` in `[0, 2^bits)`.
fn less_than(
    cs: &ConstraintSystemRef<Fr>,
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    bits: u32,
) -> R<Boolean<Fr>> {
    let lt = Boolean::new_witness(cs.clone(), || Ok(a.value()? < b.value()?))?;
    let d = b - a;
    let ltf: FpVar<Fr> = lt.clone().into();
    // lt: b - a - 1 >= 0. !lt: a - b >= 0
    let t = &ltf * (d.double()? - constant(1)) - &d;
    range(cs, &t, bits)?;
    Ok(lt)
}

fn mul_zero(a: &FpVar<Fr>, b: &FpVar<Fr>) -> R<()> {
    a.mul_equals(b, &FpVar::zero())
}

/// Groups `(role, side)` in index order 0..4: maker-buy, maker-sell,
/// taker-buy, taker-sell. Bit 0 is the side, bit 1 the role.
fn group_side(g: usize) -> Side {
    if g & 1 == 1 { Side::Sell } else { Side::Buy }
}

fn groups_for(shape: &CircuitShape, book: BookId, side: Side) -> Vec<usize> {
    use timescales_core::Role;
    (0..4)
        .filter(|&g| {
            let role = if g & 2 == 2 { Role::Taker } else { Role::Maker };
            group_side(g) == side && BookId::route(shape.flow, role, side) == book
        })
        .collect()
}

struct EntryVars {
    x: FpVar<Fr>,
    /// `y[g][j] = x * u[g][j]` for in-band `j`.
    y: Vec<Vec<FpVar<Fr>>>,
    /// In-band membership per group.
    member: Vec<FpVar<Fr>>,
    slot: FpVar<Fr>,
    group: FpVar<Fr>,
    fields: [FpVar<Fr>; 3],
}

impl ConstraintSynthesizer<Fr> for AuctionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        let shape = self.shape;
        // No circuit exists for an empty band, or for clearing results that
        // do not name one price per book. The arithmetic below assumes both.
        if shape.ticks == 0 || self.books.len() != shape.books().len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        let k = shape.ticks as usize;
        let w = (shape.ticks - 1) / 2;
        let kq = shape.curve_bits();
        let score_bits = 2 * kq + SLOT_BITS + 2;
        let big = constant(u64::MAX);

        // Public inputs, in the order of `PublicInputs::to_field_elements`.
        let transcript = FpVar::new_input(cs.clone(), || Ok(self.transcript))?;
        let lo = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.lo)))?;
        let hi = &lo + constant(shape.ticks as u64 - 1);
        let mut book_pub = Vec::new();
        for (s, v) in &self.books {
            let s = FpVar::new_input(cs.clone(), || Ok(Fr::from(u64::from(*s))))?;
            let v = FpVar::new_input(cs.clone(), || Ok(Fr::from(*v)))?;
            book_pub.push((s, v));
        }

        let mut entries = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            entries.push(entry(&cs, &shape, e, &lo, &hi, &big)?);
        }
        let n = entries.len();

        let books = shape.books();
        let pairs: Vec<(usize, Side)> = (0..books.len())
            .flat_map(|b| [(b, Side::Buy), (b, Side::Sell)])
            .collect();
        let pair_groups: Vec<Vec<usize>> = pairs
            .iter()
            .map(|(b, s)| groups_for(&shape, books[*b], *s))
            .collect();

        // Level totals per pair and slot, then curves per book.
        let level = |pi: usize, j: usize| -> FpVar<Fr> {
            let mut acc = FpVar::zero();
            for ev in &entries {
                for &g in &pair_groups[pi] {
                    acc += &ev.y[g][j];
                }
            }
            acc
        };
        let mut fills: Vec<FpVar<Fr>> = vec![FpVar::zero(); n];
        for (b, (pstar, vol)) in book_pub.iter().enumerate() {
            let buys: Vec<FpVar<Fr>> = (0..k).map(|j| level(2 * b, j)).collect();
            let sells: Vec<FpVar<Fr>> = (0..k).map(|j| level(2 * b + 1, j)).collect();
            let mut d = vec![FpVar::zero(); k + 1];
            for p in (0..k).rev() {
                d[p] = &d[p + 1] + &buys[p];
            }
            let mut s = Vec::with_capacity(k);
            let mut acc = FpVar::zero();
            for sp in &sells {
                acc += sp;
                s.push(acc.clone());
            }

            // Clearing key per slot.
            let mut vols = Vec::with_capacity(k);
            let mut scores = Vec::with_capacity(k);
            for p in 0..k {
                let lt: FpVar<Fr> = less_than(&cs, &d[p], &s[p], kq)?.into();
                let t = &lt * (&d[p] - &s[p]);
                let v = &s[p] + &t;
                let imb = &d[p] - &s[p] - t.double()?;
                let sb: FpVar<Fr> = if p + 1 < k {
                    less_than(&cs, &v, &d[p + 1], kq)?.into()
                } else {
                    FpVar::zero()
                };
                let ss: FpVar<Fr> = if p > 0 {
                    less_than(&cs, &v, &s[p - 1], kq)?.into()
                } else {
                    FpVar::zero()
                };
                let strand = &sb + &ss - &sb * &ss;
                let ns = constant(1) - strand;
                let score = &v * pow2(kq + 1 + SLOT_BITS)
                    + &ns * pow2(kq + SLOT_BITS)
                    + (FpVar::constant(pow2(kq) - Fr::from(1u64)) - &imb) * pow2(SLOT_BITS)
                    + FpVar::constant(
                        pow2(SLOT_BITS)
                            - Fr::from(1u64)
                            - Fr::from(rank(u32::try_from(p).unwrap_or(u32::MAX), w)),
                    );
                vols.push(v);
                scores.push(score);
            }

            // p* as a one-hot selector, tied to the public slot.
            let star = self.books[b].0 as usize;
            let sel: Vec<Boolean<Fr>> = (0..k)
                .map(|p| Boolean::new_witness(cs.clone(), || Ok(p == star)))
                .collect::<R<_>>()?;
            let selv: Vec<FpVar<Fr>> = sel.iter().map(|x| x.clone().into()).collect();
            selv.iter()
                .fold(FpVar::zero(), |a, b| a + b)
                .enforce_equal(&constant(1))?;
            selv.iter()
                .enumerate()
                .fold(FpVar::zero(), |a, (p, x)| a + x * Fr::from(p as u64))
                .enforce_equal(pstar)?;
            let dot = |v: &[FpVar<Fr>]| -> R<FpVar<Fr>> {
                let mut acc = FpVar::zero();
                for (x, y) in selv.iter().zip(v) {
                    acc += x * y;
                }
                Ok(acc)
            };
            let best = dot(&scores)?;
            dot(&vols)?.enforce_equal(vol)?;
            for p in 0..k {
                range(
                    &cs,
                    &(&best - &scores[p] - constant(1) + &selv[p]),
                    score_bits,
                )?;
            }
            let next_d: Vec<FpVar<Fr>> = (0..k).map(|p| d[p + 1].clone()).collect();
            let prev_s: Vec<FpVar<Fr>> = (0..k)
                .map(|p| {
                    if p > 0 {
                        s[p - 1].clone()
                    } else {
                        FpVar::zero()
                    }
                })
                .collect();
            let d_after = dot(&next_d)?;
            let s_before = dot(&prev_s)?;

            // Slot of each entry relative to p*.
            let mut gt = Vec::with_capacity(n);
            let mut lt = Vec::with_capacity(n);
            for ev in &entries {
                let a: FpVar<Fr> = less_than(&cs, pstar, &ev.slot, SLOT_BITS)?.into();
                let c: FpVar<Fr> = less_than(&cs, &ev.slot, pstar, SLOT_BITS)?.into();
                gt.push(a);
                lt.push(c);
            }
            for side in [Side::Buy, Side::Sell] {
                let pi = 2 * b + usize::from(side == Side::Sell);
                let residual = match side {
                    Side::Buy => vol - &d_after,
                    Side::Sell => vol - &s_before,
                };
                let mut prefix = FpVar::zero();
                let mut prev_min = FpVar::zero();
                for (i, ev) in entries.iter().enumerate() {
                    let mem = pair_groups[pi]
                        .iter()
                        .fold(FpVar::zero(), |acc, &g| acc + &ev.member[g]);
                    let xm = &ev.x * &mem;
                    let better = match side {
                        Side::Buy => &gt[i],
                        Side::Sell => &lt[i],
                    };
                    let eq = constant(1) - &gt[i] - &lt[i];
                    let full = &xm * better;
                    let marg = &xm * &eq;
                    prefix += &marg;
                    // min(R, P_(i+1)) - min(R, P_i). min(R, P_0) = 0.
                    let c: FpVar<Fr> = less_than(&cs, &prefix, &residual, kq)?.into();
                    let m = &residual + &c * (&prefix - &residual);
                    fills[i] += full + &m - &prev_min;
                    prev_min = m;
                }
            }
        }

        // Transcript over (commitment, filled, admitted, fill, tag).
        let mut absorbed = Vec::with_capacity(5 * n);
        for (ev, fill) in entries.iter().zip(&fills) {
            let nonzero: FpVar<Fr> = (!fill.is_zero()?).into();
            let tag = &nonzero * (&ev.group + constant(1));
            absorbed.extend([
                ev.fields[0].clone(),
                ev.fields[1].clone(),
                ev.fields[2].clone(),
                fill.clone(),
                tag,
            ]);
        }
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), poseidon::config());
        sponge.absorb(&absorbed)?;
        sponge.squeeze_field_elements(1)?[0].enforce_equal(&transcript)
    }
}

fn entry(
    cs: &ConstraintSystemRef<Fr>,
    shape: &CircuitShape,
    e: &EntryInput,
    lo: &FpVar<Fr>,
    hi: &FpVar<Fr>,
    big: &FpVar<Fr>,
) -> R<EntryVars> {
    let k = shape.ticks as usize;
    let stride = k + 1;
    let admitted = Boolean::new_witness(cs.clone(), || Ok(e.entry.admitted))?;
    let a: FpVar<Fr> = admitted.into();
    let c = FpVar::new_witness(cs.clone(), || Ok(e.entry.commitment))?;
    let filled = FpVar::new_witness(cs.clone(), || Ok(Fr::from(e.entry.filled)))?;

    // Plaintext, or a dummy that satisfies every constraint: a maker buy
    // that cannot trade (limit 0 < lo), quantity 0.
    let ow = e.order.as_ref();
    let pos = ow.map_or(k, |o| o.group * stride + o.slot.map_or(k, |s| s as usize));
    let limbs = ow.map(|o| o.order.poseidon_elements());
    let field = |i: usize| -> Fr {
        limbs
            .as_ref()
            .map_or(Fr::from(0u64), |l| poseidon::element(l[i]))
    };

    let u: Vec<Boolean<Fr>> = (0..4 * stride)
        .map(|j| Boolean::new_witness(cs.clone(), || Ok(j == pos)))
        .collect::<R<_>>()?;
    let uf: Vec<FpVar<Fr>> = u.iter().map(|b| b.clone().into()).collect();
    uf.iter()
        .fold(FpVar::zero(), |acc, x| acc + x)
        .enforce_equal(&constant(1))?;
    let sum_groups = |gs: &[usize]| -> FpVar<Fr> {
        let mut acc = FpVar::zero();
        for &g in gs {
            for j in 0..stride {
                acc += &uf[g * stride + j];
            }
        }
        acc
    };
    let side = sum_groups(&[1, 3]);
    let role = sum_groups(&[2, 3]);

    let kind = Boolean::new_witness(cs.clone(), || {
        Ok(ow.is_some_and(|o| o.order.kind == timescales_core::OrderKind::Market))
    })?;
    let kindf: FpVar<Fr> = kind.into();
    let limit = FpVar::new_witness(cs.clone(), || {
        Ok(Fr::from(ow.map_or(0, |o| o.order.limit.0)))
    })?;
    range(cs, &limit, 64)?;
    let qty = FpVar::new_witness(cs.clone(), || {
        Ok(Fr::from(ow.map_or(0, |o| o.order.quantity.0)))
    })?;
    range(cs, &qty, u32::from(shape.qty_bits))?;

    // e0 = KIND + 2^8 (side + 2 role + 4 kind) + 2^16 limit + 2^80 qty.
    let flags = &side + role.double()? + &kindf * Fr::from(4u64);
    let e0 = constant(u64::from(<Order as Committable>::KIND))
        + flags * pow2(8)
        + &limit * pow2(16)
        + &qty * pow2(80);
    let mut absorbed = vec![e0];
    for i in 1..5 {
        absorbed.push(FpVar::new_witness(cs.clone(), || Ok(field(i)))?);
    }
    absorbed.push(FpVar::new_witness(cs.clone(), || {
        Ok(ow.map_or(Fr::from(0u64), |o| poseidon::salt_element(&o.salt)))
    })?);
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), poseidon::config());
    sponge.absorb(&absorbed)?;
    let opened = sponge.squeeze_field_elements(1)?.remove(0);
    (&opened - &c).mul_equals(&a, &FpVar::zero())?;

    // Effective limit: market buys +inf (2^64 - 1), market sells 0.
    let leff = &limit + &kindf * (big * (constant(1) - &side) - &limit);

    // Slot rules: exact positions are equalities, clamped and
    // untradeable positions feed one non-negative slack.
    let mut slack = FpVar::zero();
    for g in 0..4 {
        let sell = group_side(g) == Side::Sell;
        for j in 0..k {
            let u = &uf[g * stride + j];
            let exact = if sell { j >= 1 } else { j + 1 < k };
            if exact {
                mul_zero(u, &(&leff - lo - constant(j as u64)))?;
            } else if sell {
                slack += u * (lo - &leff); // j = 0: L <= lo
            } else {
                slack += u * (&leff - hi); // j = K-1: L >= hi
            }
        }
        let none = &uf[g * stride + k];
        slack += if sell {
            none * (&leff - hi - constant(1))
        } else {
            none * (lo - constant(1) - &leff)
        };
    }
    range(cs, &slack, 64)?;

    let x = &a * (&qty - &filled);
    range(cs, &x, u32::from(shape.qty_bits))?;

    let mut y = Vec::with_capacity(4);
    let mut member = Vec::with_capacity(4);
    let mut slot = FpVar::zero();
    let mut group = FpVar::zero();
    for g in 0..4 {
        let mut row = Vec::with_capacity(k);
        let mut m = FpVar::zero();
        for j in 0..k {
            let u = &uf[g * stride + j];
            row.push(&x * u);
            m += u;
            slot += u * Fr::from(j as u64);
        }
        group += sum_groups(&[g]) * Fr::from(g as u64);
        y.push(row);
        member.push(m);
    }
    Ok(EntryVars {
        x,
        y,
        member,
        slot,
        group,
        fields: [c, filled, a],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{Keys, constraint_count, is_satisfied};
    use rand::SeedableRng;
    use timescales_core::FlowMode;

    fn shape(ticks: u32) -> CircuitShape {
        CircuitShape {
            capacity: 1,
            ticks,
            qty_bits: 4,
            flow: FlowMode::SingleBook,
        }
    }

    #[test]
    fn empty_bands_are_refused_without_panicking() {
        assert!(matches!(
            AuctionCircuit::blank(shape(0)),
            Err(ProverError::Shape(_))
        ));
        assert!(matches!(
            constraint_count(shape(0)),
            Err(ProverError::Shape(_))
        ));
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        assert!(matches!(
            Keys::setup(shape(0), &mut rng),
            Err(ProverError::Shape(_))
        ));
        // A hand-built circuit with no ticks fails synthesis instead.
        let mut c = AuctionCircuit::blank(shape(3)).unwrap();
        c.shape.ticks = 0;
        assert!(matches!(is_satisfied(c), Err(ProverError::Synthesis(_))));
    }

    #[test]
    fn clearing_must_name_one_price_per_book() {
        let mut c = AuctionCircuit::blank(shape(3)).unwrap();
        c.books.push((1, 0));
        assert!(matches!(is_satisfied(c), Err(ProverError::Synthesis(_))));
    }

    fn witness() -> OrderWitness {
        use timescales_core::commitment::Salt;
        use timescales_core::{EpochId, Lots, MarketId, OrderKind, Role, Tick, TraderId};
        OrderWitness {
            order: Order {
                market: MarketId(1),
                trader: TraderId([0xab; 32]),
                nonce: 4242,
                side: Side::Sell,
                role: Role::Maker,
                kind: OrderKind::Limit,
                limit: Tick(9876),
                quantity: Lots(5432),
                valid_from: EpochId(1),
                expires_at: EpochId(1),
            },
            salt: Salt([7; 32]),
            group: 1,
            slot: Some(2),
        }
    }

    #[test]
    fn witnesses_are_redacted_in_debug_output() {
        let mut c = AuctionCircuit::blank(shape(3)).unwrap();
        c.entries[0].order = Some(witness());
        let shown = format!("{c:?}");
        assert!(shown.contains("OrderWitness(..)"));
        for secret in ["9876", "5432", "4242", "abab", "Sell"] {
            assert!(!shown.contains(secret), "{secret} leaked");
        }
    }

    #[test]
    fn a_wiped_witness_keeps_no_number_trader_or_salt() {
        let mut w = witness();
        w.wipe();
        let o = &w.order;
        assert_eq!(
            [
                o.market.0,
                o.nonce,
                o.limit.0,
                o.quantity.0,
                o.valid_from.0,
                o.expires_at.0
            ],
            [0; 6]
        );
        assert_eq!(o.trader.0, [0; 32]);
        assert_eq!(w.salt.0, [0; 32]);
        assert_eq!((w.group, w.slot), (0, None));
    }

    #[test]
    fn smallest_band_synthesizes() {
        assert!(constraint_count(shape(1)).unwrap() > 0);
    }

    #[test]
    fn every_constructed_prover_error_is_produced() {
        // Exhaustive on purpose: a new variant must be listed here.
        fn variant(e: &ProverError) -> usize {
            match e {
                ProverError::Synthesis(_) => 0,
                ProverError::Serialization(_) => 1,
                ProverError::Shape(_) => 2,
            }
        }
        let mut c = AuctionCircuit::blank(shape(3)).unwrap();
        c.books.clear();
        let errors = [
            is_satisfied(c).map(|_| ()),
            Keys::from_bytes(shape(3), &[1, 2, 3]).map(|_| ()),
            AuctionCircuit::blank(shape(0)).map(|_| ()),
        ];
        let seen: Vec<usize> = errors
            .iter()
            .map(|e| variant(e.as_ref().unwrap_err()))
            .collect();
        assert_eq!(seen, [0, 1, 2]);
    }

    #[test]
    fn ranks_match_clearing_crate() {
        use timescales_core::{PriceBand, Tick};
        for w in 1..6u32 {
            let band = PriceBand {
                lo: Tick(100),
                hi: Tick(100 + 2 * u64::from(w)),
                reference: Tick(100 + u64::from(w)),
            };
            for p in 0..2 * w + 1 {
                assert_eq!(
                    rank(p, w),
                    u64::from(timescales_auction::clearing::tie_break_rank(&band, p))
                );
            }
        }
    }
}
