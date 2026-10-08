//! The prime field `F_p`, `p = 2^127 - 1`.
//!
//! A Mersenne prime keeps reduction to shifts and adds. 127 bits leave room
//! for 64-bit (or 80-bit) integers plus a 40-bit statistical masking margin
//! in the comparison protocol, which is the same headroom argument Cerberus
//! makes for its 2^107 - 1 field.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use rand::Rng;

pub const MODULUS: u128 = (1u128 << 127) - 1;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Fp(u128);

impl fmt::Debug for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fp({})", self.0)
    }
}

#[inline]
fn reduce_once(x: u128) -> u128 {
    // x < 2^128: fold the top bit, then one conditional subtraction.
    let r = (x & MODULUS) + (x >> 127);
    if r >= MODULUS { r - MODULUS } else { r }
}

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

    /// Canonical constructor. Reduces arbitrary `u128`.
    pub fn new(x: u128) -> Self {
        Fp(reduce_once(x))
    }

    pub fn from_u64(x: u64) -> Self {
        Fp(u128::from(x))
    }

    /// Signed integers map to `x mod p`.
    pub fn from_i128(x: i128) -> Self {
        if x >= 0 {
            Fp::new(x.unsigned_abs())
        } else {
            -Fp::new(x.unsigned_abs())
        }
    }

    pub fn value(self) -> u128 {
        self.0
    }

    /// `2^k`, for `k < 127`.
    pub fn pow2(k: u32) -> Self {
        debug_assert!(k < 127);
        Fp(1u128 << k)
    }

    pub fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        loop {
            let x: u128 = rng.r#gen::<u128>() & MODULUS;
            if x != MODULUS {
                return Fp(x);
            }
        }
    }

    /// Uniform in `[0, 2^bits)`, `bits < 127`.
    pub fn random_bits<R: Rng + ?Sized>(rng: &mut R, bits: u32) -> Self {
        debug_assert!(bits < 127);
        Fp(rng.r#gen::<u128>() & ((1u128 << bits) - 1))
    }

    pub fn pow(self, mut e: u128) -> Self {
        let mut base = self;
        let mut acc = Fp::ONE;
        while e > 0 {
            if e & 1 == 1 {
                acc *= base;
            }
            base *= base;
            e >>= 1;
        }
        acc
    }

    /// Multiplicative inverse. `0` maps to `0`.
    pub fn inv(self) -> Self {
        self.pow(MODULUS - 2)
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Bit `i` of the canonical representative.
    pub fn bit(self, i: u32) -> bool {
        (self.0 >> i) & 1 == 1
    }

    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// Rejects non-canonical encodings.
    pub fn from_bytes(b: [u8; 16]) -> Option<Self> {
        let x = u128::from_le_bytes(b);
        (x < MODULUS).then_some(Fp(x))
    }
}

impl Add for Fp {
    type Output = Fp;
    #[inline]
    fn add(self, rhs: Fp) -> Fp {
        // Both < 2^127, so the sum fits in u128.
        Fp(reduce_once(self.0 + rhs.0))
    }
}

impl Sub for Fp {
    type Output = Fp;
    #[inline]
    fn sub(self, rhs: Fp) -> Fp {
        if self.0 >= rhs.0 {
            Fp(self.0 - rhs.0)
        } else {
            Fp(self.0 + MODULUS - rhs.0)
        }
    }
}

impl Neg for Fp {
    type Output = Fp;
    #[inline]
    fn neg(self) -> Fp {
        if self.0 == 0 {
            self
        } else {
            Fp(MODULUS - self.0)
        }
    }
}

impl Mul for Fp {
    type Output = Fp;
    #[inline]
    fn mul(self, rhs: Fp) -> Fp {
        let (a0, a1) = (self.0 & u128::from(u64::MAX), self.0 >> 64);
        let (b0, b1) = (rhs.0 & u128::from(u64::MAX), rhs.0 >> 64);
        // a1, b1 < 2^63, so every partial product and the middle sum fit u128.
        let ll = a0 * b0;
        let mid = a0 * b1 + a1 * b0;
        let hh = a1 * b1;
        let (lo, carry) = ll.overflowing_add(mid << 64);
        let hi = hh + (mid >> 64) + u128::from(carry);
        // x = hi*2^128 + lo and 2^128 = 2 (mod p). hi < 2^126 since x < 2^254.
        let lo = reduce_once(lo);
        Fp(reduce_once((hi << 1) + lo))
    }
}

impl AddAssign for Fp {
    fn add_assign(&mut self, rhs: Fp) {
        *self = *self + rhs;
    }
}

impl SubAssign for Fp {
    fn sub_assign(&mut self, rhs: Fp) {
        *self = *self - rhs;
    }
}

impl MulAssign for Fp {
    fn mul_assign(&mut self, rhs: Fp) {
        *self = *self * rhs;
    }
}

impl core::iter::Sum for Fp {
    fn sum<I: Iterator<Item = Fp>>(iter: I) -> Fp {
        iter.fold(Fp::ZERO, |a, b| a + b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn big_mul_mod(a: u128, b: u128) -> u128 {
        // Schoolbook double-and-add as an independent oracle.
        let mut acc = Fp::ZERO;
        let mut base = Fp(a);
        let mut e = b;
        while e > 0 {
            if e & 1 == 1 {
                acc += base;
            }
            base += base;
            e >>= 1;
        }
        acc.0
    }

    proptest! {
        #[test]
        fn mul_matches_double_and_add(a in 0..MODULUS, b in 0..MODULUS) {
            prop_assert_eq!((Fp(a) * Fp(b)).0, big_mul_mod(a, b));
        }

        #[test]
        fn inverse(a in 1..MODULUS) {
            prop_assert_eq!(Fp(a) * Fp(a).inv(), Fp::ONE);
        }

        #[test]
        fn add_sub_neg(a in 0..MODULUS, b in 0..MODULUS) {
            prop_assert_eq!(Fp(a) + Fp(b) - Fp(b), Fp(a));
            prop_assert_eq!(Fp(a) + (-Fp(a)), Fp::ZERO);
        }
    }

    #[test]
    fn edge_values() {
        let m = Fp(MODULUS - 1);
        assert_eq!(m * m, Fp::ONE);
        assert_eq!(m + Fp::ONE, Fp::ZERO);
        assert_eq!(Fp::from_i128(-1), m);
        assert_eq!(Fp::from_bytes(MODULUS.to_le_bytes()), None);
    }
}
