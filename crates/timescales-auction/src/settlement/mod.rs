//! Settlement: from fills to per-account balance deltas.
//!
//! For a fill of `f` lots at tick `t` with role fee `r`:
//!
//! ```text
//! notional = f * t * tick_size            (quote atoms)
//! fee      = floor(notional * r / 10_000)
//! buyer: base += f * base_lot_size,  quote -= notional + fee
//! seller: base -= f * base_lot_size,  quote += notional - fee
//! fee vault:                             quote += fee
//! ```
//!
//! Deltas are netted per trader. The batch is valid only if it conserves
//! both assets:
//!
//! ```text
//! sum(base deltas)  == 0
//! sum(quote deltas) + fees == 0
//! ```
//!
//! which is the `sum(inputs) == sum(outputs) + fees` invariant. This is
//! checked here, again by the settlement program before any balance moves,
//! and by every verifier of a receipt.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use std::collections::BTreeMap;

use crate::collateral::{Balance, BalanceSheet};
use thiserror::Error;
use timescales_core::merkle::MerkleTree;
use timescales_core::{
    BaseAtoms, Decode, DecodeError, Encode, EpochId, Fill, Hash32, MarketId, MarketParams,
    QuoteAtoms, Reader, Role, Side, TraderId,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SettlementError {
    #[error("arithmetic overflow while settling")]
    Overflow,
    #[error("batch does not conserve {asset}: residual {residual}")]
    NotConserved { asset: &'static str, residual: i128 },
    #[error("trader {0} would go negative")]
    NegativeBalance(TraderId),
    #[error("settlement deltas are not canonical: {0}")]
    NotCanonical(&'static str),
}

/// Net change for one trader. Leaf of the settlement tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountDelta {
    pub trader: TraderId,
    pub base: i64,
    pub quote: i64,
}

impl AccountDelta {
    pub const ENCODED_LEN: usize = 32 + 8 + 8;
}

impl Encode for AccountDelta {
    fn encode(&self, out: &mut Vec<u8>) {
        self.trader.encode(out);
        timescales_core::encoding::put_i64(out, self.base);
        timescales_core::encoding::put_i64(out, self.quote);
    }
}

impl Decode for AccountDelta {
    const MIN_ENCODED_LEN: usize = AccountDelta::ENCODED_LEN;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(AccountDelta {
            trader: TraderId::decode(r)?,
            base: r.i64()?,
            quote: r.i64()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementBatch {
    pub market: MarketId,
    pub epoch: EpochId,
    /// Sorted by trader, zero deltas omitted.
    pub deltas: Vec<AccountDelta>,
    pub fees: QuoteAtoms,
}

impl SettlementBatch {
    pub fn tree(&self) -> MerkleTree {
        let leaves: Vec<Vec<u8>> = self.deltas.iter().map(Encode::to_bytes).collect();
        MerkleTree::from_data(&leaves)
    }

    pub fn root(&self) -> Hash32 {
        self.tree().root()
    }

    /// The form [`settle`] produces: traders strictly increasing (so each
    /// appears once) and no delta that is zero in both assets.
    pub fn check_canonical(&self) -> Result<(), SettlementError> {
        if self.deltas.windows(2).any(|w| w[0].trader >= w[1].trader) {
            return Err(SettlementError::NotCanonical(
                "traders not strictly increasing",
            ));
        }
        if self.deltas.iter().any(|d| d.base == 0 && d.quote == 0) {
            return Err(SettlementError::NotCanonical("zero delta"));
        }
        Ok(())
    }

    pub fn check_conservation(&self) -> Result<(), SettlementError> {
        let base: i128 = self.deltas.iter().map(|d| i128::from(d.base)).sum();
        let quote: i128 = self.deltas.iter().map(|d| i128::from(d.quote)).sum();
        if base != 0 {
            return Err(SettlementError::NotConserved {
                asset: "base",
                residual: base,
            });
        }
        let residual = quote + i128::from(self.fees.0);
        if residual != 0 {
            return Err(SettlementError::NotConserved {
                asset: "quote",
                residual,
            });
        }
        Ok(())
    }

    /// Balances after settlement. Fails if any account would go negative,
    /// which collateral admission is supposed to make impossible.
    pub fn apply(&self, sheet: &BalanceSheet) -> Result<BalanceSheet, SettlementError> {
        let mut out = sheet.clone();
        for d in &self.deltas {
            let b = sheet.get(&d.trader);
            let base = i128::from(b.base.0) + i128::from(d.base);
            let quote = i128::from(b.quote.0) + i128::from(d.quote);
            let to_u64 =
                |v: i128| u64::try_from(v).map_err(|_| SettlementError::NegativeBalance(d.trader));
            out.set(
                d.trader,
                Balance {
                    base: BaseAtoms(to_u64(base)?),
                    quote: QuoteAtoms(to_u64(quote)?),
                },
            );
        }
        Ok(out)
    }
}

pub fn settle(
    params: &MarketParams,
    epoch: EpochId,
    fills: &[Fill],
) -> Result<SettlementBatch, SettlementError> {
    let mut net: BTreeMap<TraderId, (i128, i128)> = BTreeMap::new();
    let mut fees: i128 = 0;
    for f in fills {
        let notional = u128::from(f.quantity.0)
            .checked_mul(u128::from(f.tick.0))
            .and_then(|x| x.checked_mul(u128::from(params.tick_size)))
            .ok_or(SettlementError::Overflow)?;
        let notional = u64::try_from(notional).map_err(|_| SettlementError::Overflow)?;
        let rate = match f.role {
            Role::Maker => params.maker_fee,
            Role::Taker => params.taker_fee,
        };
        let fee = i128::from(rate.fee_on(QuoteAtoms(notional)).0);
        let base = i128::from(f.quantity.0)
            .checked_mul(i128::from(params.base_lot_size))
            .ok_or(SettlementError::Overflow)?;
        // Both terms are below 2^64, so neither the sum nor the negation can
        // overflow. Only the running totals can.
        let notional = i128::from(notional);
        let (base, quote) = match f.side {
            Side::Buy => (base, -(notional + fee)),
            Side::Sell => (-base, notional - fee),
        };
        let e = net.entry(f.trader).or_default();
        e.0 = e.0.checked_add(base).ok_or(SettlementError::Overflow)?;
        e.1 = e.1.checked_add(quote).ok_or(SettlementError::Overflow)?;
        fees = fees.checked_add(fee).ok_or(SettlementError::Overflow)?;
    }
    let mut deltas = Vec::with_capacity(net.len());
    for (trader, (b, q)) in net {
        if b == 0 && q == 0 {
            continue;
        }
        let base = i64::try_from(b).map_err(|_| SettlementError::Overflow)?;
        let quote = i64::try_from(q).map_err(|_| SettlementError::Overflow)?;
        deltas.push(AccountDelta {
            trader,
            base,
            quote,
        });
    }
    let fees = QuoteAtoms(u64::try_from(fees).map_err(|_| SettlementError::Overflow)?);
    let batch = SettlementBatch {
        market: params.market,
        epoch,
        deltas,
        fees,
    };
    batch.check_conservation()?;
    Ok(batch)
}

impl Encode for SettlementBatch {
    fn encode(&self, out: &mut Vec<u8>) {
        self.market.encode(out);
        self.epoch.encode(out);
        timescales_core::encoding::put_seq(out, &self.deltas);
        self.fees.encode(out);
    }
}

impl Decode for SettlementBatch {
    const MIN_ENCODED_LEN: usize = 8 + 8 + 4 + 8;

    /// Only the canonical form decodes (see [`SettlementBatch::check_canonical`]),
    /// so the same balance changes cannot be published reordered, split
    /// across repeated traders or padded with zero deltas under another root.
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let batch = SettlementBatch {
            market: MarketId::decode(r)?,
            epoch: EpochId::decode(r)?,
            deltas: r.seq(timescales_core::MAX_BATCH_ENVELOPES as usize)?,
            fees: QuoteAtoms::decode(r)?,
        };
        batch
            .check_canonical()
            .map_err(|_| DecodeError::InvalidValue("SettlementBatch deltas"))?;
        Ok(batch)
    }
}

/// Record that a settlement was applied on chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementReceipt {
    pub market: MarketId,
    pub epoch: EpochId,
    pub execution_receipt: Hash32,
    pub settlement_root: Hash32,
    pub fees: QuoteAtoms,
    /// Chain-specific reference, e.g. the finalising transaction signature hash.
    pub chain_ref: Hash32,
}

impl Encode for SettlementReceipt {
    fn encode(&self, out: &mut Vec<u8>) {
        self.market.encode(out);
        self.epoch.encode(out);
        self.execution_receipt.encode(out);
        self.settlement_root.encode(out);
        self.fees.encode(out);
        self.chain_ref.encode(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use timescales_core::*;

    fn params(maker: u16, taker: u16) -> MarketParams {
        MarketParams {
            market: MarketId(1),
            base_lot_size: 1_000,
            tick_size: 7,
            band_half_width: 5,
            max_order_lots_log2: 20,
            max_orders_per_trader: 8,
            max_batch_envelopes: 1024,
            max_order_lifetime: 1,
            maker_fee: FeeBps(maker),
            taker_fee: FeeBps(taker),
            flow: FlowMode::DualFlow,
            rationing: Rationing::Lottery,
            commitment_scheme: CommitmentScheme::Sha256,
        }
    }

    fn fill(t: u8, side: Side, role: Role, q: u64, tick: u64) -> Fill {
        Fill {
            commitment: OrderCommitment([t; 32]),
            trader: TraderId([t; 32]),
            book: BookId::MakerAskTakerBid,
            side,
            role,
            quantity: Lots(q),
            tick: Tick(tick),
        }
    }

    #[test]
    fn simple_trade() {
        let p = params(0, 25);
        let fills = [
            fill(1, Side::Sell, Role::Maker, 3, 100),
            fill(2, Side::Buy, Role::Taker, 3, 100),
        ];
        let s = settle(&p, EpochId(1), &fills).unwrap();
        // notional = 3*100*7 = 2100, taker fee = floor(2100*25/1e4) = 5
        assert_eq!(s.fees, QuoteAtoms(5));
        assert_eq!(
            s.deltas[0],
            AccountDelta {
                trader: TraderId([1; 32]),
                base: -3000,
                quote: 2100
            }
        );
        assert_eq!(
            s.deltas[1],
            AccountDelta {
                trader: TraderId([2; 32]),
                base: 3000,
                quote: -2105
            }
        );
    }

    #[test]
    fn negative_balance_detected() {
        let p = params(0, 0);
        let fills = [
            fill(1, Side::Sell, Role::Maker, 1, 100),
            fill(2, Side::Buy, Role::Taker, 1, 100),
        ];
        let s = settle(&p, EpochId(1), &fills).unwrap();
        assert!(matches!(
            s.apply(&BalanceSheet::default()),
            Err(SettlementError::NegativeBalance(_))
        ));
    }

    #[test]
    fn tampered_batch_fails_conservation() {
        let p = params(10, 10);
        let fills = [
            fill(1, Side::Sell, Role::Maker, 5, 50),
            fill(2, Side::Buy, Role::Taker, 5, 50),
        ];
        let mut s = settle(&p, EpochId(1), &fills).unwrap();
        s.deltas[0].quote += 1;
        assert!(matches!(
            s.check_conservation(),
            Err(SettlementError::NotConserved { asset: "quote", .. })
        ));
    }

    #[test]
    fn oversized_fills_overflow_instead_of_panicking() {
        // One fill whose base amount exceeds i128.
        let mut p = params(0, 0);
        p.base_lot_size = u64::MAX;
        p.tick_size = 1;
        let fills = [fill(1, Side::Buy, Role::Taker, u64::MAX, 1)];
        assert_eq!(
            settle(&p, EpochId(1), &fills),
            Err(SettlementError::Overflow)
        );

        // Fills that fit one by one but not summed for one trader.
        p.base_lot_size = 1 << 62;
        let fills: Vec<Fill> = (0..8)
            .map(|_| fill(1, Side::Buy, Role::Taker, 1 << 63, 1))
            .collect();
        assert_eq!(
            settle(&p, EpochId(1), &fills),
            Err(SettlementError::Overflow)
        );

        // A sum that fits i128 but not an i64 delta.
        p.base_lot_size = 1 << 32;
        let fills = [fill(1, Side::Buy, Role::Taker, 1 << 32, 1)];
        assert_eq!(
            settle(&p, EpochId(1), &fills),
            Err(SettlementError::Overflow)
        );
    }

    fn batch(deltas: Vec<AccountDelta>) -> SettlementBatch {
        SettlementBatch {
            market: MarketId(1),
            epoch: EpochId(1),
            deltas,
            fees: QuoteAtoms(0),
        }
    }

    fn delta(t: u8, base: i64, quote: i64) -> AccountDelta {
        AccountDelta {
            trader: TraderId([t; 32]),
            base,
            quote,
        }
    }

    #[test]
    fn decode_accepts_only_canonical_deltas() {
        let ok = batch(vec![delta(1, -5, 7), delta(2, 5, 0), delta(3, 0, -7)]);
        assert_eq!(ok.check_canonical(), Ok(()));
        assert_eq!(SettlementBatch::decode_exact(&ok.to_bytes()), Ok(ok));

        let cases = [
            batch(vec![delta(2, 5, -7), delta(1, -5, 7)]),
            batch(vec![delta(1, 5, -7), delta(1, -5, 7)]),
            batch(vec![delta(1, -5, 7), delta(2, 0, 0), delta(3, 5, -7)]),
        ];
        for b in cases {
            assert!(matches!(
                b.check_canonical(),
                Err(SettlementError::NotCanonical(_))
            ));
            assert_eq!(
                SettlementBatch::decode_exact(&b.to_bytes()),
                Err(DecodeError::InvalidValue("SettlementBatch deltas"))
            );
        }
        // The empty batch is canonical, and the shortest encoding.
        let empty = batch(Vec::new());
        assert_eq!(empty.to_bytes().len(), SettlementBatch::MIN_ENCODED_LEN);
        assert_eq!(SettlementBatch::decode_exact(&empty.to_bytes()), Ok(empty));
        assert_eq!(
            delta(1, 1, 1).to_bytes().len(),
            AccountDelta::MIN_ENCODED_LEN
        );
    }

    #[test]
    fn every_settlement_error_is_produced() {
        // Exhaustive on purpose: a new variant must be produced here.
        fn variant(e: &SettlementError) -> usize {
            match e {
                SettlementError::Overflow => 0,
                SettlementError::NotConserved { .. } => 1,
                SettlementError::NegativeBalance(_) => 2,
                SettlementError::NotCanonical(_) => 3,
            }
        }
        let mut p = params(0, 0);
        p.base_lot_size = u64::MAX;
        let overflow = settle(
            &p,
            EpochId(1),
            &[fill(1, Side::Buy, Role::Taker, u64::MAX, 1)],
        );
        let unbalanced = batch(vec![delta(1, 1, 0)]).check_conservation();
        let p = params(0, 0);
        let trade = [
            fill(1, Side::Sell, Role::Maker, 1, 100),
            fill(2, Side::Buy, Role::Taker, 1, 100),
        ];
        let negative = settle(&p, EpochId(1), &trade)
            .unwrap()
            .apply(&BalanceSheet::default())
            .map(|_| ());
        let unsorted = batch(vec![delta(2, 1, 0), delta(1, -1, 0)]).check_canonical();
        let seen: Vec<usize> = [overflow.map(|_| ()), unbalanced, negative, unsorted]
            .iter()
            .map(|r| variant(r.as_ref().unwrap_err()))
            .collect();
        assert_eq!(seen, [0, 1, 2, 3]);
    }

    proptest! {
        /// `settle` only produces canonical batches, and they round-trip.
        #[test]
        fn settled_batches_are_canonical(trades in prop::collection::vec((1u8..20, 1u8..20, 1u64..1000, 1u64..10_000), 1..40)) {
            let p = params(3, 7);
            let mut fills = Vec::new();
            for (b, s, q, t) in trades {
                fills.push(fill(s, Side::Sell, Role::Maker, q, t));
                fills.push(fill(b, Side::Buy, Role::Taker, q, t));
            }
            let st = settle(&p, EpochId(1), &fills).unwrap();
            prop_assert!(st.check_canonical().is_ok());
            prop_assert_eq!(SettlementBatch::decode_exact(&st.to_bytes()).unwrap(), st);
        }

        /// Any balanced fill set conserves both assets after fees.
        #[test]
        fn conservation(trades in prop::collection::vec((1u8..20, 1u8..20, 1u64..1000, 1u64..10_000, any::<bool>()), 1..40),
                        maker in 0u16..100, taker in 0u16..100) {
            let p = params(maker, taker);
            let mut fills = Vec::new();
            for (b, s, q, t, maker_sells) in trades {
                let (sr, br) = if maker_sells { (Role::Maker, Role::Taker) } else { (Role::Taker, Role::Maker) };
                fills.push(fill(s, Side::Sell, sr, q, t));
                fills.push(fill(b, Side::Buy, br, q, t));
            }
            let st = settle(&p, EpochId(1), &fills).unwrap();
            prop_assert!(st.check_conservation().is_ok());
        }
    }
}
