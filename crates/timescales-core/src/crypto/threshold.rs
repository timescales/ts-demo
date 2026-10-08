//! Feldman verifiable secret sharing over Ed25519 scalars.
//!
//! The dealer draws `f(x) = s + a_1 x +... + a_{t-1} x^{t-1}` over the scalar
//! field, publishes `C_j = a_j*B` and hands member `i` the share `f(i)`. A
//! member checks its share against the commitments. The enclave checks every
//! released share the same way, combines `t` valid ones with Lagrange
//! interpolation at zero and requires `u(s*B)` to equal the announced key.
//!
//! The epoch public key `u(s*B)` is an ordinary X25519 public key, so traders
//! seal to it with standard X25519. Opening multiplies by `s` itself rather
//! than by a clamped key (see `EpochSecret::open_box`).

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::CryptoError;

/// Member `index`'s share `f(index)` of an epoch secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ScalarShare {
    pub index: u8,
    pub value: Scalar,
}

impl ScalarShare {
    /// The share `index || value` as a member releases it, with `bytes` the
    /// little-endian encoding of the scalar. `None` unless that encoding is
    /// canonical (below the group order).
    pub fn from_bytes(index: u8, bytes: &[u8; 32]) -> Option<Self> {
        Option::from(Scalar::from_canonical_bytes(*bytes)).map(|value| ScalarShare { index, value })
    }
}

impl core::fmt::Debug for ScalarShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ScalarShare")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// What [`FeldmanDealing::new`] returns: the secret `s`, the compressed
/// commitments `C_0..C_{t-1}` and the shares of members `1..=n`.
pub type Dealing = (Zeroizing<Scalar>, Vec<[u8; 32]>, Vec<ScalarShare>);

/// One Feldman dealing of a fresh epoch secret.
#[derive(Debug)]
pub struct FeldmanDealing;

impl FeldmanDealing {
    /// Returns the secret `s`, the compressed commitments `C_0..C_{t-1}` and
    /// the shares for members `1..=n`.
    ///
    /// # Panics
    ///
    /// If `t == 0` or `t > n`. Committee descriptions are validated before
    /// anyone deals for them. [`Self::try_new`] reports the error instead.
    #[allow(clippy::new_ret_no_self)]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, t: u8, n: u8) -> Dealing {
        match Self::try_new(rng, t, n) {
            Ok(dealing) => dealing,
            Err(e) => panic!("{e}"),
        }
    }

    /// [`Self::new`] for parameters that have not been validated yet.
    pub fn try_new<R: RngCore + CryptoRng>(
        rng: &mut R,
        t: u8,
        n: u8,
    ) -> Result<Dealing, CryptoError> {
        check_threshold(t, n)?;
        // A zero secret would make the epoch key the identity.
        let mut secret = Zeroizing::new(Scalar::random(rng));
        while *secret == Scalar::ZERO {
            *secret = Scalar::random(rng);
        }
        let (commitments, shares) = share_polynomial(rng, &secret, t, n);
        Ok((secret, commitments, shares))
    }

    /// Deals a given secret instead of a fresh one, for batches sealed to a
    /// key held outside the committee (the simulated dealer). Returns the
    /// compressed commitments `C_0..C_{t-1}` and the shares for members
    /// `1..=n`. A zero secret is refused: its epoch key would be the
    /// identity.
    pub fn deal_secret<R: RngCore + CryptoRng>(
        rng: &mut R,
        secret: &Scalar,
        t: u8,
        n: u8,
    ) -> Result<(Vec<[u8; 32]>, Vec<ScalarShare>), CryptoError> {
        check_threshold(t, n)?;
        if *secret == Scalar::ZERO {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(share_polynomial(rng, secret, t, n))
    }
}

fn check_threshold(t: u8, n: u8) -> Result<(), CryptoError> {
    if t == 0 || t > n {
        return Err(CryptoError::InvalidThreshold { threshold: t, n });
    }
    Ok(())
}

/// Draws `a_1..a_{t-1}` for `f(x) = secret + a_1 x +...`, and returns the
/// compressed commitments and the shares `f(1)..f(n)`.
fn share_polynomial<R: RngCore + CryptoRng>(
    rng: &mut R,
    secret: &Scalar,
    t: u8,
    n: u8,
) -> (Vec<[u8; 32]>, Vec<ScalarShare>) {
    // Allocated once at full size, so pushing never leaves an unzeroized
    // copy behind in a freed buffer.
    let mut coefficients = Zeroizing::new(Vec::with_capacity(usize::from(t)));
    coefficients.push(*secret);
    for _ in 1..t {
        coefficients.push(Scalar::random(rng));
    }
    let commitments = coefficients
        .iter()
        .map(|a| EdwardsPoint::mul_base(a).compress().to_bytes())
        .collect();
    let shares = (1..=n)
        .map(|index| {
            let x = Scalar::from(index);
            // Horner evaluation, highest degree first.
            let value = coefficients
                .iter()
                .rev()
                .fold(Scalar::ZERO, |acc, a| acc * x + a);
            ScalarShare { index, value }
        })
        .collect();
    (commitments, shares)
}

/// `value*B == sum_j C_j*index^j`.
///
/// False for index 0 (that would be the secret itself), for an empty
/// commitment list and for commitments with a torsion component: with every
/// `C_j` in the prime-order subgroup, a share verifies exactly when it equals
/// `f(index)` for the committed polynomial.
pub fn verify_share(share: &ScalarShare, commitments: &[EdwardsPoint]) -> bool {
    if share.index == 0
        || commitments.is_empty()
        || !commitments.iter().all(EdwardsPoint::is_torsion_free)
    {
        return false;
    }
    let x = Scalar::from(share.index);
    let powers: Vec<Scalar> = core::iter::successors(Some(Scalar::ONE), |p| Some(p * x))
        .take(commitments.len())
        .collect();
    // Commitments and indices are public, so variable time is fine here. The
    // share itself only goes through the constant-time base multiplication.
    let expected = EdwardsPoint::vartime_multiscalar_mul(&powers, commitments);
    EdwardsPoint::mul_base(&share.value) == expected
}

/// Lagrange interpolation at zero over the given shares.
///
/// Returns zero when `shares` is empty or its indices are not distinct and
/// non-zero. Zero is never a dealt secret, so the result then fails the
/// `x25519_public(s) == epoch_pk` check every caller makes before using it.
pub fn lagrange_combine(shares: &[ScalarShare]) -> Zeroizing<Scalar> {
    let distinct = shares
        .iter()
        .enumerate()
        .all(|(i, s)| s.index != 0 && shares[..i].iter().all(|o| o.index != s.index));
    let mut secret = Zeroizing::new(Scalar::ZERO);
    if shares.is_empty() || !distinct {
        return secret;
    }
    for (i, si) in shares.iter().enumerate() {
        let xi = Scalar::from(si.index);
        // l_i(0) = prod_{j!=i} x_j / (x_j - x_i)
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (j, sj) in shares.iter().enumerate() {
            if i != j {
                let xj = Scalar::from(sj.index);
                num *= xj;
                den *= xj - xi;
            }
        }
        *secret += si.value * num * den.invert();
    }
    secret
}

/// X25519 public key of a scalar secret: `(s*B).to_montgomery`.
pub fn x25519_public(s: &Scalar) -> [u8; 32] {
    EdwardsPoint::mul_base(s).to_montgomery().to_bytes()
}

/// Decompresses an Edwards point and returns its Montgomery `u`. `None` for
/// non-canonical encodings, the identity and points with a torsion component.
pub fn edwards_u(point: &[u8; 32]) -> Option<[u8; 32]> {
    let p = decompress_canonical(point)?;
    if p.is_identity() || !p.is_torsion_free() {
        return None;
    }
    Some(p.to_montgomery().to_bytes())
}

/// Decompresses `bytes` only if they are the canonical encoding of the point:
/// `CompressedEdwardsY::decompress` also accepts `y >= p` and a set sign bit
/// on `x = 0`, which would give one point several encodings.
pub fn decompress_canonical(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let p = CompressedEdwardsY(*bytes).decompress()?;
    (p.compress().to_bytes() == *bytes).then_some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::EIGHT_TORSION;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn points(commitments: &[[u8; 32]]) -> Vec<EdwardsPoint> {
        commitments
            .iter()
            .map(|c| decompress_canonical(c).expect("dealt commitments decompress"))
            .collect()
    }

    #[test]
    fn dealing_commits_to_the_secret_and_every_share_verifies() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for (t, n) in [(1, 1), (1, 3), (2, 3), (3, 5), (16, 16)] {
            let (s, commitments, shares) = FeldmanDealing::new(&mut rng, t, n);
            assert_eq!(commitments.len(), usize::from(t));
            assert_eq!(shares.len(), usize::from(n));
            assert_eq!(
                commitments[0],
                EdwardsPoint::mul_base(&s).compress().to_bytes()
            );
            assert_eq!(edwards_u(&commitments[0]), Some(x25519_public(&s)));
            let cs = points(&commitments);
            for (i, share) in shares.iter().enumerate() {
                assert_eq!(usize::from(share.index), i + 1);
                assert!(verify_share(share, &cs), "t={t} n={n} i={}", i + 1);
            }
        }
    }

    #[test]
    fn a_given_secret_is_dealt_and_reconstructs() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let secret = Scalar::random(&mut rng);
        for (t, n) in [(1, 1), (2, 3), (3, 5), (16, 16)] {
            let (commitments, shares) =
                FeldmanDealing::deal_secret(&mut rng, &secret, t, n).unwrap();
            assert_eq!(commitments.len(), usize::from(t));
            assert_eq!(
                commitments[0],
                EdwardsPoint::mul_base(&secret).compress().to_bytes()
            );
            let cs = points(&commitments);
            assert!(shares.iter().all(|share| verify_share(share, &cs)));
            assert_eq!(*lagrange_combine(&shares[..usize::from(t)]), secret);
        }
        assert_eq!(
            FeldmanDealing::deal_secret(&mut rng, &Scalar::ZERO, 2, 3).map(|_| ()),
            Err(CryptoError::InvalidPublicKey)
        );
        assert_eq!(
            FeldmanDealing::deal_secret(&mut rng, &secret, 4, 3).map(|_| ()),
            Err(CryptoError::InvalidThreshold { threshold: 4, n: 3 })
        );
    }

    #[test]
    fn released_shares_parse_only_canonical_encodings() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let (_, _, shares) = FeldmanDealing::new(&mut rng, 2, 3);
        for s in &shares {
            let parsed = ScalarShare::from_bytes(s.index, &s.value.to_bytes()).unwrap();
            assert_eq!(parsed.value, s.value);
            assert_eq!(parsed.index, s.index);
        }
        // The group order L itself and 2^256 - 1 are not canonical.
        let ell: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        assert!(ScalarShare::from_bytes(1, &ell).is_none());
        assert!(ScalarShare::from_bytes(1, &[0xff; 32]).is_none());
        let mut below = ell;
        below[0] -= 1;
        assert_eq!(
            ScalarShare::from_bytes(1, &below).map(|s| s.value),
            Some(-Scalar::ONE)
        );
        assert_eq!(
            ScalarShare::from_bytes(1, &[0; 32]).map(|s| s.value),
            Some(Scalar::ZERO)
        );
    }

    #[test]
    fn inconsistent_shares_do_not_verify() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (_, commitments, shares) = FeldmanDealing::new(&mut rng, 3, 5);
        let cs = points(&commitments);
        let mut wrong_value = shares[1].clone();
        wrong_value.value += Scalar::ONE;
        assert!(!verify_share(&wrong_value, &cs));
        let mut wrong_index = shares[1].clone();
        wrong_index.index = 3;
        assert!(!verify_share(&wrong_index, &cs));
        // f(0) is the secret, never a share.
        let mut zero = shares[0].clone();
        zero.index = 0;
        assert!(!verify_share(&zero, &cs));
        assert!(!verify_share(&shares[0], &[]));
        // Another dealing's commitments.
        let (_, other, _) = FeldmanDealing::new(&mut rng, 3, 5);
        assert!(!verify_share(&shares[0], &points(&other)));
        // Fewer commitments than the degree.
        assert!(!verify_share(&shares[0], &cs[..2]));
    }

    #[test]
    fn commitments_with_torsion_are_refused() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let (_, commitments, shares) = FeldmanDealing::new(&mut rng, 2, 3);
        let mut cs = points(&commitments);
        // An order-2 component on C_1 cancels for even indices: member 2's
        // share would still satisfy the equation.
        cs[1] += EIGHT_TORSION[4];
        assert!(EIGHT_TORSION[4].is_small_order() && !EIGHT_TORSION[4].is_identity());
        let lhs = EdwardsPoint::mul_base(&shares[1].value);
        let two = Scalar::from(2u8);
        assert_eq!(lhs, cs[0] + cs[1] * two);
        assert!(!verify_share(&shares[1], &cs));
    }

    #[test]
    fn any_threshold_subset_reconstructs_the_secret() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let (s, _, shares) = FeldmanDealing::new(&mut rng, 3, 5);
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let subset = [shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(*lagrange_combine(&subset), *s);
                    let reversed = [shares[c].clone(), shares[a].clone(), shares[b].clone()];
                    assert_eq!(*lagrange_combine(&reversed), *s);
                }
            }
        }
        // More than t shares interpolate the same polynomial.
        assert_eq!(*lagrange_combine(&shares), *s);
        // Fewer do not.
        assert_ne!(*lagrange_combine(&shares[..2]), *s);
    }

    #[test]
    fn invalid_index_sets_combine_to_zero() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let (_, _, shares) = FeldmanDealing::new(&mut rng, 2, 3);
        assert_eq!(*lagrange_combine(&[]), Scalar::ZERO);
        let dup = [shares[0].clone(), shares[0].clone()];
        assert_eq!(*lagrange_combine(&dup), Scalar::ZERO);
        let mut zero = shares[1].clone();
        zero.index = 0;
        assert_eq!(*lagrange_combine(&[shares[0].clone(), zero]), Scalar::ZERO);
        assert_eq!(x25519_public(&Scalar::ZERO), [0u8; 32]);
    }

    #[test]
    fn bad_thresholds_are_refused() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        for (t, n) in [(0, 3), (4, 3), (0, 0), (1, 0)] {
            assert_eq!(
                FeldmanDealing::try_new(&mut rng, t, n).map(|_| ()),
                Err(CryptoError::InvalidThreshold { threshold: t, n })
            );
        }
    }

    #[test]
    #[should_panic(expected = "invalid threshold 0 of 3")]
    fn new_panics_on_a_zero_threshold() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let _ = FeldmanDealing::new(&mut rng, 0, 3);
    }

    #[test]
    fn x25519_public_matches_clamped_x25519() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        for _ in 0..32 {
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut k);
            let standard = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(k));
            // B has order L, so the clamped integer acts on it like its
            // residue mod L.
            let s = Scalar::from_bytes_mod_order(curve25519_dalek::scalar::clamp_integer(k));
            assert_eq!(x25519_public(&s), standard.to_bytes());
        }
    }

    #[test]
    fn edwards_u_accepts_only_canonical_prime_order_points() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let s = Scalar::random(&mut rng);
        let p = EdwardsPoint::mul_base(&s);
        let enc = p.compress().to_bytes();
        assert_eq!(edwards_u(&enc), Some(x25519_public(&s)));

        // Identity and every torsion point.
        for t in EIGHT_TORSION {
            assert_eq!(edwards_u(&t.compress().to_bytes()), None);
            // A prime-order point plus a non-trivial torsion component.
            if !t.is_identity() {
                assert_eq!(edwards_u(&(p + t).compress().to_bytes()), None);
            }
        }

        // For y < 19 the encoding of y + p still fits below 2^255 and
        // decompresses to the same point as y. Only y itself is accepted.
        let mut on_curve = 0;
        for y in 0u8..19 {
            let mut canonical = [0u8; 32];
            canonical[0] = y;
            let mut shifted = PRIME;
            shifted[0] += y;
            if let Some(q) = CompressedEdwardsY(canonical).decompress() {
                assert_eq!(CompressedEdwardsY(shifted).decompress(), Some(q));
                assert_eq!(decompress_canonical(&shifted), None);
                assert_eq!(edwards_u(&shifted), None);
                assert_eq!(decompress_canonical(&canonical), Some(q));
                on_curve += 1;
            }
        }
        assert!(on_curve > 0, "some small y is on the curve");

        // The sign bit set on x = 0 (y = 1, the identity).
        let mut neg_zero = [0u8; 32];
        neg_zero[0] = 1;
        neg_zero[31] = 0x80;
        assert!(CompressedEdwardsY(neg_zero).decompress().is_some());
        assert_eq!(decompress_canonical(&neg_zero), None);

        // Not a point at all: find a y with no matching x.
        let off_curve = (2u8..)
            .map(|y| {
                let mut b = [0u8; 32];
                b[0] = y;
                b
            })
            .find(|b| CompressedEdwardsY(*b).decompress().is_none())
            .expect("half of all y are off the curve");
        assert_eq!(edwards_u(&off_curve), None);
    }

    /// p = 2^255 - 19, little-endian.
    const PRIME: [u8; 32] = {
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        p
    };
}
