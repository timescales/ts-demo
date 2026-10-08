//! Integer newtypes for every financial quantity.
//!
//! Nothing here is floating point. Arithmetic is checked. The helpers return
//! `None` on overflow and callers turn that into a typed error.

use core::fmt;

use crate::encoding::{Decode, DecodeError, Encode, Reader, put_u64};

macro_rules! u64_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub u64);

        impl $name {
            pub const ZERO: Self = Self(0);
            pub const MAX: Self = Self(u64::MAX);

            #[inline]
            pub const fn get(self) -> u64 {
                self.0
            }

            #[inline]
            pub fn checked_add(self, rhs: Self) -> Option<Self> {
                self.0.checked_add(rhs.0).map(Self)
            }

            #[inline]
            pub fn checked_sub(self, rhs: Self) -> Option<Self> {
                self.0.checked_sub(rhs.0).map(Self)
            }

            #[inline]
            pub fn saturating_sub(self, rhs: Self) -> Self {
                Self(self.0.saturating_sub(rhs.0))
            }

            #[inline]
            pub const fn is_zero(self) -> bool {
                self.0 == 0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl Encode for $name {
            fn encode(&self, out: &mut Vec<u8>) {
                put_u64(out, self.0);
            }
        }

        impl Decode for $name {
            const MIN_ENCODED_LEN: usize = 8;

            fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                r.u64().map(Self)
            }
        }
    };
}

u64_newtype!(
    /// Quantity of the base asset, in market lots.
    Lots
);
u64_newtype!(
    /// Absolute price level. One lot at tick `t` costs `t * tick_size` quote atoms.
    Tick
);
u64_newtype!(
    /// Smallest indivisible unit of the base asset.
    BaseAtoms
);
u64_newtype!(
    /// Smallest indivisible unit of the quote asset.
    QuoteAtoms
);
u64_newtype!(
    /// Batch sequence number within a market. Strictly increasing.
    EpochId
);
u64_newtype!(
    /// Market identifier.
    MarketId
);

impl EpochId {
    #[inline]
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// Fee rate in basis points (1/10_000).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FeeBps(pub u16);

impl FeeBps {
    pub const DENOMINATOR: u64 = 10_000;

    /// `floor(notional * bps / 10_000)`. Cannot overflow: the product is
    /// computed in `u128` and the result is at most `notional`.
    pub fn fee_on(self, notional: QuoteAtoms) -> QuoteAtoms {
        let f = u128::from(notional.0) * u128::from(self.0) / u128::from(Self::DENOMINATOR);
        // f <= notional * 65535 / 10000 could exceed notional only if bps > 10_000,
        // which MarketParams::validate rejects. Saturate defensively anyway.
        QuoteAtoms(u64::try_from(f).unwrap_or(u64::MAX))
    }

    /// Per-lot fee upper bound used when locking collateral:
    /// `ceil(price * bps / 10_000)`. Locking `qty * (price + this)` always
    /// covers the fee actually charged on a fill of `qty` lots at `price`.
    pub fn fee_ceil_per_unit(self, price: u64) -> u64 {
        let num = u128::from(price) * u128::from(self.0);
        let d = u128::from(Self::DENOMINATOR);
        u64::try_from(num.div_ceil(d)).unwrap_or(u64::MAX)
    }
}

/// Signed balance change applied at settlement.
///
/// `i128` so that sums over a batch cannot overflow. Individual deltas are
/// range-checked into `i64` before they are written to the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SignedAmount(pub i128);

impl SignedAmount {
    pub const ZERO: Self = Self(0);

    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    pub fn to_i64(self) -> Option<i64> {
        i64::try_from(self.0).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_floor_and_ceil_bracket_true_fee() {
        let bps = FeeBps(7);
        for price in [1u64, 9, 10_000, 123_457, u32::MAX as u64] {
            for qty in [1u64, 3, 1000] {
                let notional = QuoteAtoms(price * qty);
                let charged = bps.fee_on(notional).0;
                assert!(charged <= qty * bps.fee_ceil_per_unit(price));
            }
        }
    }

    #[test]
    fn checked_arithmetic() {
        assert_eq!(Lots(u64::MAX).checked_add(Lots(1)), None);
        assert_eq!(Lots(1).checked_sub(Lots(2)), None);
        assert_eq!(Lots(5).saturating_sub(Lots(9)), Lots::ZERO);
    }
}
