//! Shamir secret sharing of 32-byte secrets over GF(2^8).
//!
//! Byte-wise sharing with the AES field polynomial x^8 + x^4 + x^3 + x + 1.
//! Field multiplication is a fixed 8-iteration loop with no table lookups and
//! no secret-dependent branches.
//!
//! Used for the epoch decryption keys held by the key-release committee.
//! Reconstruction from fewer than `threshold` shares yields an unrelated value
//! rather than an error, so callers must check the result against a public
//! commitment (for us: the epoch public key).

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::CryptoError;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    /// Evaluation point, `1..=255`.
    pub index: u8,
    pub value: [u8; 32],
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Share(index={})", self.index)
    }
}

#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & (b & 1).wrapping_neg();
        let carry = (a >> 7).wrapping_neg();
        a = (a << 1) ^ (0x1b & carry);
        b >>= 1;
    }
    p
}

/// `a^254 = a^-1` for nonzero `a`.
fn gf_inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut e = 254u8;
    while e > 0 {
        if e & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    result
}

/// Split `secret` into `n` shares, any `threshold` of which reconstruct it.
pub fn split<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret: &[u8; 32],
    threshold: u8,
    n: u8,
) -> Result<Vec<Share>, CryptoError> {
    if threshold == 0 || threshold > n {
        return Err(CryptoError::InvalidThreshold { threshold, n });
    }
    // coeffs[d][byte]: degree-d coefficient for each byte position.
    let mut coeffs = vec![[0u8; 32]; usize::from(threshold)];
    coeffs[0] = *secret;
    for c in coeffs.iter_mut().skip(1) {
        rng.fill_bytes(c);
    }
    let shares = (1..=n)
        .map(|x| {
            let mut value = [0u8; 32];
            for (i, v) in value.iter_mut().enumerate() {
                // Horner evaluation, highest degree first.
                let mut acc = 0u8;
                for c in coeffs.iter().rev() {
                    acc = gf_mul(acc, x) ^ c[i];
                }
                *v = acc;
            }
            Share { index: x, value }
        })
        .collect();
    for c in &mut coeffs {
        c.zeroize();
    }
    Ok(shares)
}

/// Lagrange interpolation at zero. The secret is wiped when the returned
/// value is dropped.
pub fn combine(shares: &[Share]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if shares.is_empty() {
        return Err(CryptoError::NotEnoughShares);
    }
    for (i, s) in shares.iter().enumerate() {
        if s.index == 0 || shares[..i].iter().any(|t| t.index == s.index) {
            return Err(CryptoError::DuplicateShare(s.index));
        }
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (i, si) in shares.iter().enumerate() {
        // l_i(0) = prod_{j != i} x_j / (x_j - x_i). Subtraction is xor.
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, sj) in shares.iter().enumerate() {
            if i != j {
                num = gf_mul(num, sj.index);
                den = gf_mul(den, sj.index ^ si.index);
            }
        }
        let li = gf_mul(num, gf_inv(den));
        for (o, v) in out.iter_mut().zip(si.value.iter()) {
            *o ^= gf_mul(li, *v);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::SeedableRng;

    #[test]
    fn field_inverse() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "a={a}");
        }
    }

    #[test]
    fn rejects_bad_parameters() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0);
        assert!(split(&mut rng, &[1; 32], 0, 3).is_err());
        assert!(split(&mut rng, &[1; 32], 4, 3).is_err());
        assert!(combine(&[]).is_err());
    }

    proptest! {
        #[test]
        fn any_threshold_subset_reconstructs(secret in any::<[u8; 32]>(), t in 1u8..6, extra in 0u8..4, seed in any::<u64>()) {
            let n = t + extra;
            let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
            let shares = split(&mut rng, &secret, t, n).unwrap();
            // Take the last t shares to avoid always using the prefix.
            let subset: Vec<_> = shares[usize::from(n - t)..].to_vec();
            prop_assert_eq!(*combine(&subset).unwrap(), secret);
            if t > 1 {
                let fewer = &subset[1..];
                // Below threshold the result is unrelated to the secret with
                // overwhelming probability. Equality would be a 2^-256 event.
                prop_assert_ne!(*combine(fewer).unwrap(), secret);
            }
        }
    }
}
