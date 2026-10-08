//! Collateral.
//!
//! Traders hold balances in an on-chain vault. A batch executes against a
//! snapshot of *available* balances (deposits minus pending withdrawals),
//! which is public.
//!
//! Each accepted order reserves the worst case it could cost:
//!
//! * A buy reserves `qty * (price(slot) + ceil(price(slot) * fee))` quote.
//! * A sell reserves `qty * base_lot_size` base.
//! * An order whose limit cannot trade inside the band reserves nothing.
//!
//! Admission uses the **prefix rule**: a trader's orders are visited in
//! canonical order and order `i` is accepted iff the sum of reservations of
//! orders `0..=i` fits the balance. Rejected orders still count towards the
//! prefix, so the accepted set is always a prefix of the trader's orders.
//! That makes the rule a parallel comparison per order rather than a
//! sequential scan, which matters for the MPC backend.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use std::collections::BTreeMap;

use timescales_core::crypto::{Hasher, domain};
use timescales_core::merkle::MerkleTree;
use timescales_core::{
    BaseAtoms, Decode, DecodeError, Encode, FeeBps, Hash32, MarketParams, PriceBand, QuoteAtoms,
    Reader, Side, TraderId,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Balance {
    pub base: BaseAtoms,
    pub quote: QuoteAtoms,
}

impl Encode for Balance {
    fn encode(&self, out: &mut Vec<u8>) {
        self.base.encode(out);
        self.quote.encode(out);
    }
}

impl Decode for Balance {
    const MIN_ENCODED_LEN: usize = 16;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Balance {
            base: BaseAtoms::decode(r)?,
            quote: QuoteAtoms::decode(r)?,
        })
    }
}

/// Snapshot of available balances the batch executes against.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BalanceSheet {
    entries: BTreeMap<TraderId, Balance>,
}

impl BalanceSheet {
    pub fn set(&mut self, trader: TraderId, b: Balance) {
        self.entries.insert(trader, b);
    }

    /// Unknown traders have zero balance.
    pub fn get(&self, trader: &TraderId) -> Balance {
        self.entries.get(trader).copied().unwrap_or_default()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&TraderId, &Balance)> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Merkle root over `(trader, balance)` in trader order. Binds a receipt
    /// to the exact snapshot it was computed against.
    pub fn root(&self) -> Hash32 {
        let leaves: Vec<Vec<u8>> = self
            .entries
            .iter()
            .map(|(t, b)| {
                let mut v = t.to_bytes();
                b.encode(&mut v);
                v
            })
            .collect();
        MerkleTree::from_data(&leaves).root()
    }

    pub fn digest(&self) -> Hash32 {
        Hasher::new(domain::SETTLEMENT)
            .chain(b"balances")
            .chain(self.root().as_bytes())
            .finalize()
    }
}

impl Encode for BalanceSheet {
    fn encode(&self, out: &mut Vec<u8>) {
        timescales_core::encoding::put_u32(
            out,
            u32::try_from(self.entries.len()).unwrap_or(u32::MAX),
        );
        for (t, b) in &self.entries {
            t.encode(out);
            b.encode(out);
        }
    }
}

impl Decode for BalanceSheet {
    const MIN_ENCODED_LEN: usize = 4;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let n = r.len_prefix(1 << 24)?;
        let mut entries = BTreeMap::new();
        let mut last: Option<TraderId> = None;
        for _ in 0..n {
            let t = TraderId::decode(r)?;
            // Strictly increasing keeps the encoding canonical.
            if last.is_some_and(|l| l >= t) {
                return Err(DecodeError::InvalidValue("BalanceSheet order"));
            }
            last = Some(t);
            entries.insert(t, Balance::decode(r)?);
        }
        Ok(Self { entries })
    }
}

impl FromIterator<(TraderId, Balance)> for BalanceSheet {
    fn from_iter<T: IntoIterator<Item = (TraderId, Balance)>>(iter: T) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }
}

/// Most that a trader's accepted orders may reserve of either asset in one
/// batch: settlement writes each trader's net change as an `i64`.
pub const MAX_REQUIREMENT: u128 = i64::MAX as u128;

/// Worst-case reservation for one order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Requirement {
    pub base: u128,
    pub quote: u128,
}

/// Quote atoms reserved per lot for a buy resting at `slot`, including the
/// fee upper bound for `fee`.
pub fn buy_lock_per_lot(params: &MarketParams, band: &PriceBand, slot: u32, fee: FeeBps) -> u128 {
    let price = band.tick_at(slot).0.saturating_mul(params.tick_size);
    u128::from(price) + u128::from(fee.fee_ceil_per_unit(price))
}

pub fn requirement(
    params: &MarketParams,
    band: &PriceBand,
    side: Side,
    slot: Option<u32>,
    quantity: u64,
    fee: FeeBps,
) -> Requirement {
    let Some(slot) = slot else {
        return Requirement::default();
    };
    match side {
        // Below 2^113 for valid params. Saturating keeps an out-of-range
        // order unaffordable instead of overflowing.
        Side::Buy => Requirement {
            base: 0,
            quote: u128::from(quantity).saturating_mul(buy_lock_per_lot(params, band, slot, fee)),
        },
        Side::Sell => Requirement {
            base: u128::from(quantity) * u128::from(params.base_lot_size),
            quote: 0,
        },
    }
}

/// Running prefix sums per trader implementing the prefix rule.
#[derive(Debug, Default)]
pub struct PrefixAdmission {
    used: BTreeMap<TraderId, Requirement>,
}

impl PrefixAdmission {
    /// Add `req` to the trader's prefix and report whether the prefix still
    /// fits the balance.
    ///
    /// A balance counts as at most [`MAX_REQUIREMENT`], so an admitted prefix
    /// never needs more than one settlement delta can carry, however large
    /// the balance. Valid market params already keep prefixes below that
    /// bound (`MarketParams::validate` and `band`). The cap holds regardless.
    pub fn admit(&mut self, sheet: &BalanceSheet, trader: TraderId, req: Requirement) -> bool {
        let u = self.used.entry(trader).or_default();
        u.base = u.base.saturating_add(req.base);
        u.quote = u.quote.saturating_add(req.quote);
        let bal = sheet.get(&trader);
        let available = |atoms: u64| u128::from(atoms).min(MAX_REQUIREMENT);
        u.base <= available(bal.base.0) && u.quote <= available(bal.quote.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use timescales_core::*;

    fn params() -> MarketParams {
        MarketParams {
            market: MarketId(1),
            base_lot_size: 100,
            tick_size: 10,
            band_half_width: 2,
            max_order_lots_log2: 20,
            max_orders_per_trader: 8,
            max_batch_envelopes: 1024,
            max_order_lifetime: 1,
            maker_fee: FeeBps(0),
            taker_fee: FeeBps(30),
            flow: FlowMode::SingleBook,
            rationing: Rationing::Lottery,
            commitment_scheme: CommitmentScheme::Sha256,
        }
    }

    #[test]
    fn prefix_rule_is_monotone() {
        let p = params();
        let band = p.band(Tick(50)).unwrap();
        let t = TraderId([1; 32]);
        let mut sheet = BalanceSheet::default();
        sheet.set(
            t,
            Balance {
                base: BaseAtoms(1_000),
                quote: QuoteAtoms(1_000),
            },
        );
        let mut adm = PrefixAdmission::default();
        // price at slot 2 = 50*10 = 500, fee ceil(500*30/1e4)=2 -> 502/lot
        let r1 = requirement(&p, &band, Side::Buy, Some(2), 1, FeeBps(30));
        assert_eq!(r1.quote, 502);
        assert!(adm.admit(&sheet, t, r1));
        assert!(!adm.admit(&sheet, t, r1)); // 1004 > 1000
        // A small order after a failure still fails: prefix includes rejects.
        assert!(!adm.admit(
            &sheet,
            t,
            requirement(&p, &band, Side::Buy, Some(0), 0, FeeBps(30))
        ));
        let s = requirement(&p, &band, Side::Sell, Some(0), 10, FeeBps(0));
        assert_eq!(s.base, 1_000);
    }

    #[test]
    fn requirements_are_capped_at_a_settlement_delta() {
        let t = TraderId([1; 32]);
        let mut sheet = BalanceSheet::default();
        sheet.set(
            t,
            Balance {
                base: BaseAtoms(u64::MAX),
                quote: QuoteAtoms(u64::MAX),
            },
        );
        let half = Requirement {
            base: MAX_REQUIREMENT / 2,
            quote: MAX_REQUIREMENT / 2,
        };
        let mut adm = PrefixAdmission::default();
        assert!(adm.admit(&sheet, t, half));
        assert!(adm.admit(&sheet, t, half));
        // The prefix is now i64::MAX - 1 of each asset. One more atom of
        // either fits, a second does not, although the balance covers both.
        let one = |base, quote| Requirement { base, quote };
        assert!(adm.admit(&sheet, t, one(1, 1)));
        assert!(!adm.admit(&sheet, t, one(1, 0)));
        let mut adm = PrefixAdmission::default();
        assert!(!adm.admit(&sheet, t, one(0, MAX_REQUIREMENT + 1)));

        // Balances below the cap are compared as they are.
        let poor = TraderId([2; 32]);
        sheet.set(
            poor,
            Balance {
                base: BaseAtoms(10),
                quote: QuoteAtoms(10),
            },
        );
        assert!(adm.admit(&sheet, poor, one(10, 10)));
        assert!(!adm.admit(&sheet, poor, one(0, 1)));
    }

    #[test]
    fn oversized_requirement_saturates() {
        // A band that `MarketParams::band` would refuse: one lot near the top
        // of the band costs about 2^64 quote atoms plus a 100% fee.
        let mut p = params();
        p.tick_size = 1;
        let band = PriceBand {
            lo: Tick(u64::MAX - 4),
            hi: Tick(u64::MAX),
            reference: Tick(u64::MAX - 2),
        };
        let r = requirement(&p, &band, Side::Buy, Some(4), u64::MAX, FeeBps(10_000));
        assert_eq!(r.quote, u128::MAX);
        let mut sheet = BalanceSheet::default();
        let t = TraderId([1; 32]);
        sheet.set(
            t,
            Balance {
                base: BaseAtoms(u64::MAX),
                quote: QuoteAtoms(u64::MAX),
            },
        );
        assert!(!PrefixAdmission::default().admit(&sheet, t, r));
        // Sells cannot overflow: u64 x u64 fits u128.
        p.base_lot_size = u64::MAX;
        let sell = requirement(&p, &band, Side::Sell, Some(0), u64::MAX, FeeBps(0));
        assert_eq!(sell.base, u128::from(u64::MAX) * u128::from(u64::MAX));
    }

    #[test]
    fn untradeable_orders_reserve_nothing() {
        let p = params();
        let band = p.band(Tick(50)).unwrap();
        assert_eq!(
            requirement(&p, &band, Side::Buy, None, 99, FeeBps(30)),
            Requirement::default()
        );
    }

    #[test]
    fn sheet_root_depends_on_contents() {
        let mut a = BalanceSheet::default();
        a.set(
            TraderId([1; 32]),
            Balance {
                base: BaseAtoms(1),
                quote: QuoteAtoms(2),
            },
        );
        let mut b = a.clone();
        assert_eq!(a.root(), b.root());
        b.set(
            TraderId([1; 32]),
            Balance {
                base: BaseAtoms(1),
                quote: QuoteAtoms(3),
            },
        );
        assert_ne!(a.root(), b.root());
    }
}
