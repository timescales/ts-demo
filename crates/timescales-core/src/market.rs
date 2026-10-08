//! Market configuration and the per-batch price band.

use thiserror::Error;

use crate::MAX_SETTLEMENT_DELTAS;
use crate::encoding::{Decode, DecodeError, Encode, Reader, put_u8, put_u16, put_u32};
use crate::order::Side;
use crate::units::{FeeBps, MarketId, Tick};

/// Upper bound on band width. Keeps every backend's per-order work bounded
/// (the MPC and ZK backends are linear in the band width).
pub const MAX_BAND_TICKS: u32 = 1025;

/// Hard cap on envelopes per batch, independent of market configuration.
pub const MAX_BATCH_ENVELOPES: u32 = 1 << 21;

/// Amounts that reach settlement must fit an `i64` delta.
const SETTLEMENT_LIMIT: u128 = i64::MAX as u128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FlowMode {
    SingleBook = 0,
    /// Maker and taker flow are cleared in two separate books per batch.
    DualFlow = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CommitmentScheme {
    /// SHA-256 based. Cheap natively and on Solana.
    Sha256 = 0,
    /// Poseidon over the BN254 scalar field. Required by markets that ask for
    /// SNARK proofs, since the circuit opens commitments.
    PoseidonBn254 = 1,
}

/// How the long side of a book is rationed at the clearing price, after
/// price priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Rationing {
    /// In canonical order (ascending priority key), each order takes
    /// `min(quantity, residual)`. At most one order is partially filled.
    Lottery = 0,
    /// Pro rata by size, as in the dual-flow batch auction: each order gets
    /// `floor(q * R / M)` and the leftover lots go one each to orders with
    /// spare quantity in canonical order.
    ProRata = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MarketParams {
    pub market: MarketId,
    /// Base atoms per lot.
    pub base_lot_size: u64,
    /// Quote atoms per lot per tick.
    pub tick_size: u64,
    /// Band is `[r - w, r + w]` around the batch reference tick `r`.
    pub band_half_width: u32,
    /// Orders must satisfy `quantity < 2^max_order_lots_log2`.
    pub max_order_lots_log2: u8,
    pub max_orders_per_trader: u16,
    pub max_batch_envelopes: u32,
    /// Upper bound on `expires_at - valid_from`. Lets per-order state be
    /// pruned a fixed number of epochs after it was created.
    pub max_order_lifetime: u32,
    pub maker_fee: FeeBps,
    pub taker_fee: FeeBps,
    pub flow: FlowMode,
    pub rationing: Rationing,
    pub commitment_scheme: CommitmentScheme,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MarketError {
    #[error("invalid market parameter: {0}")]
    InvalidParam(&'static str),
    #[error("reference tick {reference} too close to zero for half width {half_width}")]
    BandUnderflow { reference: u64, half_width: u32 },
    #[error("band upper tick overflows")]
    BandOverflow,
    #[error("worst-case notional at tick {tick} does not fit settlement range")]
    NotionalOverflow { tick: u64 },
    #[error("worst-case base exposure per trader does not fit settlement range")]
    BaseOverflow,
}

impl MarketParams {
    pub fn validate(&self) -> Result<(), MarketError> {
        let bad = |m| Err(MarketError::InvalidParam(m));
        if self.base_lot_size == 0 {
            return bad("base_lot_size must be positive");
        }
        if self.tick_size == 0 {
            return bad("tick_size must be positive");
        }
        if self.band_half_width == 0 || self.band_ticks() > MAX_BAND_TICKS {
            return bad("band_half_width out of range");
        }
        if !(1..=48).contains(&self.max_order_lots_log2) {
            return bad("max_order_lots_log2 must be in 1..=48");
        }
        if self.max_orders_per_trader == 0 {
            return bad("max_orders_per_trader must be positive");
        }
        if self.max_batch_envelopes == 0 || self.max_batch_envelopes > MAX_BATCH_ENVELOPES {
            return bad("max_batch_envelopes out of range");
        }
        // Per-book curve sums must fit in 63 bits so every backend can use the
        // same fixed-width arithmetic.
        let env_bits = 32 - (self.max_batch_envelopes - 1).leading_zeros();
        if u32::from(self.max_order_lots_log2) + env_bits > 63 {
            return bad("max_order_lots_log2 + log2(max_batch_envelopes) exceeds 63");
        }
        if self.maker_fee.0 > 10_000 || self.taker_fee.0 > 10_000 {
            return bad("fee above 100%");
        }
        // A trader's sells settle as one negative base delta, so the most
        // base one trader can deliver in a batch must fit an i64. `band`
        // bounds the quote side the same way.
        let base = u128::from(self.base_lot_size)
            .checked_mul(u128::from(self.max_order_lots()))
            .and_then(|b| b.checked_mul(u128::from(self.max_orders_per_trader)));
        if base.is_none_or(|b| b > SETTLEMENT_LIMIT) {
            return Err(MarketError::BaseOverflow);
        }
        Ok(())
    }

    /// [`Self::validate`] plus what the settlement program accepts: at most
    /// [`MAX_SETTLEMENT_DELTAS`] envelopes per batch, so a batch can never
    /// produce more settlement leaves than one receipt holds, and SHA-256
    /// commitments, the only scheme the program and the browser client
    /// support.
    pub fn validate_onchain(&self) -> Result<(), MarketError> {
        self.validate()?;
        if self.max_batch_envelopes > MAX_SETTLEMENT_DELTAS {
            return Err(MarketError::InvalidParam(
                "max_batch_envelopes exceeds the on-chain settlement limit",
            ));
        }
        if self.commitment_scheme != CommitmentScheme::Sha256 {
            return Err(MarketError::InvalidParam(
                "on-chain markets use SHA-256 commitments",
            ));
        }
        Ok(())
    }

    /// Decode params received from outside the process and require them to
    /// pass [`Self::validate`]. Plain [`Decode`] does not validate, and the
    /// arithmetic helpers on this type are only meaningful for valid params.
    pub fn decode_validated(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let params = Self::decode(r)?;
        params
            .validate()
            .map_err(|_| DecodeError::InvalidValue("MarketParams"))?;
        Ok(params)
    }

    /// Number of ticks in every band of this market.
    pub fn band_ticks(&self) -> u32 {
        self.band_half_width.saturating_mul(2).saturating_add(1)
    }

    /// `2^max_order_lots_log2 - 1`, saturating at `u64::MAX` for exponents
    /// that `validate` rejects.
    pub fn max_order_lots(&self) -> u64 {
        1u64.checked_shl(u32::from(self.max_order_lots_log2))
            .map_or(u64::MAX, |v| v - 1)
    }

    /// Quote atoms for one lot at `tick`.
    pub fn price_per_lot(&self, tick: Tick) -> Option<u64> {
        tick.0.checked_mul(self.tick_size)
    }

    pub fn max_fee(&self) -> FeeBps {
        self.maker_fee.max(self.taker_fee)
    }

    /// Build the band for a batch and check that no fill inside it can push a
    /// settlement amount out of range.
    pub fn band(&self, reference: Tick) -> Result<PriceBand, MarketError> {
        let w = u64::from(self.band_half_width);
        if reference.0 <= w {
            return Err(MarketError::BandUnderflow {
                reference: reference.0,
                half_width: self.band_half_width,
            });
        }
        let lo = Tick(reference.0 - w);
        let hi = Tick(
            reference
                .0
                .checked_add(w)
                .ok_or(MarketError::BandOverflow)?,
        );
        let price = self
            .price_per_lot(hi)
            .ok_or(MarketError::NotionalOverflow { tick: hi.0 })?;
        let per_lot = u128::from(price) + u128::from(self.max_fee().fee_ceil_per_unit(price));
        // Bound a single trader's aggregate delta, not just one order. The
        // first product is below 2^80. The second can exceed u128.
        let per_trader = u128::from(self.max_order_lots()) * u128::from(self.max_orders_per_trader);
        if per_trader
            .checked_mul(per_lot)
            .is_none_or(|n| n > SETTLEMENT_LIMIT)
        {
            return Err(MarketError::NotionalOverflow { tick: hi.0 });
        }
        Ok(PriceBand { lo, hi, reference })
    }
}

/// Contiguous tick range a batch may clear in, centred on the reference tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PriceBand {
    pub lo: Tick,
    pub hi: Tick,
    pub reference: Tick,
}

impl PriceBand {
    pub fn ticks(&self) -> u32 {
        // Construction bounds the width by MAX_BAND_TICKS.
        u32::try_from(self.hi.0 - self.lo.0 + 1).unwrap_or(u32::MAX)
    }

    pub fn tick_at(&self, slot: u32) -> Tick {
        Tick(self.lo.0 + u64::from(slot))
    }

    /// Map an effective limit to a band slot.
    ///
    /// A buy is eligible at every slot `<= slot`, a sell at every slot
    /// `>= slot`. Limits beyond the band on the passive side are clamped to
    /// the edge. Limits that cannot trade anywhere in the band yield `None`.
    pub fn slot(&self, side: Side, limit: Tick) -> Option<u32> {
        let k = self.ticks();
        match side {
            Side::Buy if limit < self.lo => None,
            Side::Buy if limit >= self.hi => Some(k - 1),
            Side::Sell if limit > self.hi => None,
            Side::Sell if limit <= self.lo => Some(0),
            _ => u32::try_from(limit.0 - self.lo.0).ok(),
        }
    }

    /// Distance of a slot from the reference tick. Used for tie-breaking.
    pub fn distance_to_reference(&self, slot: u32) -> u64 {
        self.tick_at(slot).0.abs_diff(self.reference.0)
    }
}

impl Encode for FlowMode {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for FlowMode {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(FlowMode::SingleBook),
            1 => Ok(FlowMode::DualFlow),
            tag => Err(DecodeError::InvalidTag {
                ty: "FlowMode",
                tag,
            }),
        }
    }
}

impl Encode for Rationing {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for Rationing {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(Rationing::Lottery),
            1 => Ok(Rationing::ProRata),
            tag => Err(DecodeError::InvalidTag {
                ty: "Rationing",
                tag,
            }),
        }
    }
}

impl Encode for CommitmentScheme {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for CommitmentScheme {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(CommitmentScheme::Sha256),
            1 => Ok(CommitmentScheme::PoseidonBn254),
            tag => Err(DecodeError::InvalidTag {
                ty: "CommitmentScheme",
                tag,
            }),
        }
    }
}

impl Encode for MarketParams {
    fn encode(&self, out: &mut Vec<u8>) {
        self.market.encode(out);
        self.base_lot_size.encode(out);
        self.tick_size.encode(out);
        put_u32(out, self.band_half_width);
        put_u8(out, self.max_order_lots_log2);
        put_u16(out, self.max_orders_per_trader);
        put_u32(out, self.max_batch_envelopes);
        put_u32(out, self.max_order_lifetime);
        put_u16(out, self.maker_fee.0);
        put_u16(out, self.taker_fee.0);
        self.flow.encode(out);
        self.rationing.encode(out);
        self.commitment_scheme.encode(out);
    }
}

impl MarketParams {
    pub const ENCODED_LEN: usize = 8 + 8 + 8 + 4 + 1 + 2 + 4 + 4 + 2 + 2 + 1 + 1 + 1;
}

impl Decode for MarketParams {
    const MIN_ENCODED_LEN: usize = MarketParams::ENCODED_LEN;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(MarketParams {
            market: MarketId::decode(r)?,
            base_lot_size: r.u64()?,
            tick_size: r.u64()?,
            band_half_width: r.u32()?,
            max_order_lots_log2: r.u8()?,
            max_orders_per_trader: r.u16()?,
            max_batch_envelopes: r.u32()?,
            max_order_lifetime: r.u32()?,
            maker_fee: FeeBps(r.u16()?),
            taker_fee: FeeBps(r.u16()?),
            flow: FlowMode::decode(r)?,
            rationing: Rationing::decode(r)?,
            commitment_scheme: CommitmentScheme::decode(r)?,
        })
    }
}

impl Encode for PriceBand {
    fn encode(&self, out: &mut Vec<u8>) {
        self.lo.encode(out);
        self.hi.encode(out);
        self.reference.encode(out);
    }
}

impl PriceBand {
    pub const ENCODED_LEN: usize = 3 * 8;
}

impl Decode for PriceBand {
    const MIN_ENCODED_LEN: usize = PriceBand::ENCODED_LEN;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let band = PriceBand {
            lo: Tick::decode(r)?,
            hi: Tick::decode(r)?,
            reference: Tick::decode(r)?,
        };
        if band.lo > band.hi
            || band.hi.0 - band.lo.0 >= u64::from(MAX_BAND_TICKS)
            || band.reference < band.lo
            || band.reference > band.hi
        {
            return Err(DecodeError::InvalidValue("PriceBand"));
        }
        Ok(band)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn params() -> MarketParams {
        MarketParams {
            market: MarketId(7),
            base_lot_size: 1_000,
            tick_size: 10,
            band_half_width: 4,
            max_order_lots_log2: 32,
            max_orders_per_trader: 16,
            max_batch_envelopes: 1 << 16,
            max_order_lifetime: 16,
            maker_fee: FeeBps(0),
            taker_fee: FeeBps(5),
            flow: FlowMode::DualFlow,
            rationing: Rationing::Lottery,
            commitment_scheme: CommitmentScheme::Sha256,
        }
    }

    #[test]
    fn slots_clamp_on_passive_side_only() {
        let band = params().band(Tick(100)).expect("band");
        assert_eq!((band.lo, band.hi, band.ticks()), (Tick(96), Tick(104), 9));
        assert_eq!(band.slot(Side::Buy, Tick(95)), None);
        assert_eq!(band.slot(Side::Buy, Tick(96)), Some(0));
        assert_eq!(band.slot(Side::Buy, Tick(1_000)), Some(8));
        assert_eq!(band.slot(Side::Sell, Tick(0)), Some(0));
        assert_eq!(band.slot(Side::Sell, Tick(104)), Some(8));
        assert_eq!(band.slot(Side::Sell, Tick(105)), None);
        assert_eq!(band.slot(Side::Sell, Tick(100)), Some(4));
    }

    #[test]
    fn band_rejects_overflowing_notional() {
        let mut p = params();
        p.max_order_lots_log2 = 48;
        p.tick_size = 1 << 20;
        assert!(matches!(
            p.band(Tick(1 << 20)),
            Err(MarketError::NotionalOverflow { .. })
        ));
    }

    #[test]
    fn params_roundtrip() {
        let p = params();
        assert_eq!(p.to_bytes().len(), MarketParams::ENCODED_LEN);
        let band = p.band(Tick(100)).expect("band");
        assert_eq!(band.to_bytes().len(), PriceBand::ENCODED_LEN);
        assert_eq!(PriceBand::decode_exact(&band.to_bytes()), Ok(band));
        assert_eq!(MarketParams::decode_exact(&p.to_bytes()), Ok(p));
        assert!(p.validate().is_ok());
    }

    #[test]
    fn max_order_lots_never_overflows_the_shift() {
        let lots = |b: u8| {
            let mut p = params();
            p.max_order_lots_log2 = b;
            p.max_order_lots()
        };
        assert_eq!(lots(0), 0);
        assert_eq!(lots(1), 1);
        assert_eq!(lots(48), (1 << 48) - 1);
        assert_eq!(lots(63), (1 << 63) - 1);
        assert_eq!(lots(64), u64::MAX);
        assert_eq!(lots(255), u64::MAX);
    }

    /// The audit's case: the u128 product `per_trader * per_lot` overflows,
    /// and wrapped it would have landed below `i64::MAX`.
    #[test]
    fn band_notional_check_does_not_wrap() {
        let mut p = params();
        p.max_order_lots_log2 = 48;
        p.max_orders_per_trader = 40_000;
        p.maker_fee = FeeBps(10_000);
        p.taker_fee = FeeBps(10_000);
        p.tick_size = 1;
        let hi = 15_111_572_745_182_918_371u64;
        let per_lot = 2 * u128::from(hi);
        let per_trader = u128::from(p.max_order_lots()) * 40_000;
        assert!(per_trader.checked_mul(per_lot).is_none());
        assert!(per_trader.wrapping_mul(per_lot) <= SETTLEMENT_LIMIT);
        let reference = Tick(hi - u64::from(p.band_half_width));
        assert_eq!(
            p.band(reference),
            Err(MarketError::NotionalOverflow { tick: hi })
        );
    }

    #[test]
    fn validate_bounds_base_exposure_per_trader() {
        let mut p = params();
        let per_trader = u128::from(p.max_order_lots()) * u128::from(p.max_orders_per_trader);
        let largest = u64::try_from(SETTLEMENT_LIMIT / per_trader).unwrap();
        p.base_lot_size = largest;
        assert_eq!(p.validate(), Ok(()));
        p.base_lot_size = largest + 1;
        assert_eq!(p.validate(), Err(MarketError::BaseOverflow));
        // The largest inputs `validate` lets through cannot overflow u128.
        p.base_lot_size = u64::MAX;
        p.max_order_lots_log2 = 48;
        p.max_orders_per_trader = u16::MAX;
        p.max_batch_envelopes = 1024;
        assert_eq!(p.validate(), Err(MarketError::BaseOverflow));
    }

    #[test]
    fn validate_onchain_adds_program_limits() {
        let mut p = params();
        p.max_batch_envelopes = crate::MAX_SETTLEMENT_DELTAS;
        assert_eq!(p.validate_onchain(), Ok(()));
        p.max_batch_envelopes += 1;
        assert!(p.validate().is_ok());
        assert!(matches!(
            p.validate_onchain(),
            Err(MarketError::InvalidParam(_))
        ));
        p.max_batch_envelopes = 16;
        p.commitment_scheme = CommitmentScheme::PoseidonBn254;
        assert!(p.validate().is_ok());
        assert!(matches!(
            p.validate_onchain(),
            Err(MarketError::InvalidParam(_))
        ));
        p.commitment_scheme = CommitmentScheme::Sha256;
        p.base_lot_size = u64::MAX;
        assert_eq!(p.validate_onchain(), Err(MarketError::BaseOverflow));
    }

    #[test]
    fn decode_validated_rejects_invalid_params() {
        let p = params();
        let good = p.to_bytes();
        let mut r = Reader::new(&good);
        assert_eq!(MarketParams::decode_validated(&mut r), Ok(p));
        assert_eq!(r.remaining(), 0);

        let mut bad = params();
        bad.tick_size = 0;
        let bytes = bad.to_bytes();
        assert_eq!(MarketParams::decode_exact(&bytes), Ok(bad));
        assert_eq!(
            MarketParams::decode_validated(&mut Reader::new(&bytes)),
            Err(DecodeError::InvalidValue("MarketParams"))
        );
        assert!(matches!(
            MarketParams::decode_validated(&mut Reader::new(&bytes[..45])),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn every_market_error_is_produced() {
        // Exhaustive on purpose: a new variant must be added here, with a
        // case that produces it.
        fn variant(e: &MarketError) -> usize {
            match e {
                MarketError::InvalidParam(_) => 0,
                MarketError::BandUnderflow { .. } => 1,
                MarketError::BandOverflow => 2,
                MarketError::NotionalOverflow { .. } => 3,
                MarketError::BaseOverflow => 4,
            }
        }
        let p = params();
        let errors = [
            MarketParams { tick_size: 0, ..p }.validate(),
            p.band(Tick(4)).map(|_| ()),
            p.band(Tick(u64::MAX - 1)).map(|_| ()),
            MarketParams {
                max_order_lots_log2: 48,
                tick_size: 1 << 20,
                ..p
            }
            .band(Tick(1 << 20))
            .map(|_| ()),
            MarketParams {
                base_lot_size: u64::MAX,
                ..p
            }
            .validate(),
        ];
        let seen: Vec<usize> = errors
            .iter()
            .map(|e| variant(e.as_ref().expect_err("every case fails")))
            .collect();
        assert_eq!(seen, [0, 1, 2, 3, 4]);
    }
}
