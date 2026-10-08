//! Property tests of the Feldman threshold path ("Crypto"): shares
//! verify exactly when they are consistent with the commitments, any `t`
//! valid shares reconstruct the secret, and the threshold opening of a box
//! equals the standard X25519 opening for every honestly sealed box.

use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use proptest::collection::vec;
use proptest::prelude::*;
use rand::SeedableRng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;
use timescales_core::crypto::threshold::{
    FeldmanDealing, ScalarShare, decompress_canonical, edwards_u, lagrange_combine, verify_share,
    x25519_public,
};
use timescales_core::crypto::{CryptoError, EpochSecret, ScalarSealSecret, SealSecret, seal};

fn dealing(seed: [u8; 32], t: u8, n: u8) -> (Scalar, Vec<EdwardsPoint>, Vec<ScalarShare>) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (s, commitments, shares) = FeldmanDealing::new(&mut rng, t, n);
    let points = commitments
        .iter()
        .map(|c| decompress_canonical(c).expect("dealt commitments decompress"))
        .collect();
    (*s, points, shares)
}

/// `f(x)` from `t` points of a polynomial of degree `t - 1`, by the
/// Lagrange form evaluated at `x`.
fn evaluate(points: &[ScalarShare], x: u8) -> Scalar {
    let x = Scalar::from(x);
    points
        .iter()
        .map(|p| {
            let xi = Scalar::from(p.index);
            let l = points
                .iter()
                .filter(|o| o.index != p.index)
                .fold(Scalar::ONE, |l, o| {
                    let xj = Scalar::from(o.index);
                    l * (x - xj) * (xi - xj).invert()
                });
            p.value * l
        })
        .fold(Scalar::ZERO, |a, b| a + b)
}

/// `(t, n)` with `1 <= t <= n <= 16`.
fn threshold_and_size() -> impl Strategy<Value = (u8, u8)> {
    (1u8..=16).prop_flat_map(|n| (1..=n, Just(n)))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn threshold_shares_verify_iff_consistent(
        seed in any::<[u8; 32]>(),
        (t, n) in threshold_and_size(),
        index in 1u8..=16,
        forged in any::<[u8; 32]>(),
        honest in any::<bool>(),
    ) {
        let (_, commitments, shares) = dealing(seed, t, n);
        for share in &shares {
            prop_assert!(verify_share(share, &commitments));
        }
        // f(index) for any index, also beyond n, from t of the dealt shares.
        let expected = evaluate(&shares[..usize::from(t)], index);
        let value = if honest {
            expected
        } else {
            Scalar::from_bytes_mod_order(forged)
        };
        let candidate = ScalarShare { index, value };
        prop_assert_eq!(verify_share(&candidate, &commitments), value == expected);
    }

    #[test]
    fn threshold_any_t_shares_reconstruct_the_secret(
        seed in any::<[u8; 32]>(),
        (t, n) in threshold_and_size(),
        order in any::<u64>(),
        extra in any::<u8>(),
    ) {
        let (s, commitments, shares) = dealing(seed, t, n);
        let epoch_pk = edwards_u(&commitments[0].compress().to_bytes()).expect("C_0 is prime order");
        prop_assert_eq!(epoch_pk, x25519_public(&s));
        // A uniformly random subset of t to n shares, in random order.
        let mut subset = shares.clone();
        subset.shuffle(&mut ChaCha20Rng::seed_from_u64(order));
        subset.truncate(usize::from(t + extra % (n - t + 1)));
        let combined = lagrange_combine(&subset);
        prop_assert_eq!(*combined, s);
        prop_assert_eq!(x25519_public(&combined), epoch_pk);
        // t - 1 shares reveal nothing. They interpolate another value.
        if t > 1 {
            prop_assert_ne!(*lagrange_combine(&subset[..usize::from(t) - 1]), s);
        }
    }

    #[test]
    fn threshold_dealt_secret_opens_boxes_sealed_to_its_key(
        seed in any::<[u8; 32]>(),
        (t, n) in threshold_and_size(),
        plaintext in vec(any::<u8>(), 0..256),
    ) {
        let (s, _, shares) = dealing(seed, t, n);
        let key = EpochSecret::Threshold(ScalarSealSecret::from_scalar(
            *lagrange_combine(&shares[usize::from(n - t)..]),
        ));
        prop_assert_eq!(key.public(), x25519_public(&s));
        let mut rng = ChaCha20Rng::from_seed(seed);
        let b = seal(&mut rng, &key.public(), b"info", b"aad", &plaintext).expect("seal");
        let opened = key.open_box(&b.ephemeral, b"info", b"aad", &b.ciphertext).expect("opens");
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// For 10,000 random keys and honestly sealed boxes, opening through
    /// the threshold path (`u(s*E)` with the unclamped scalar) gives exactly
    /// what standard X25519 opening gives. `s = clamp(k) mod L` has the same
    /// public key as the X25519 secret `k`.
    #[test]
    fn threshold_open_box_equals_x25519_open(
        k in any::<[u8; 32]>(),
        seed in any::<[u8; 32]>(),
        plaintext in vec(any::<u8>(), 0..=256),
        info in vec(any::<u8>(), 0..48),
        aad in vec(any::<u8>(), 0..64),
    ) {
        let x25519 = SealSecret::from_bytes(k);
        let s = Scalar::from_bytes_mod_order(clamp_integer(k));
        prop_assert_eq!(*ScalarSealSecret::from_x25519(&x25519).scalar(), s);
        let threshold = EpochSecret::Threshold(ScalarSealSecret::from_scalar(s));
        let standard = EpochSecret::Dev(x25519);
        prop_assert_eq!(standard.public(), threshold.public());

        let mut rng = ChaCha20Rng::from_seed(seed);
        let b = seal(&mut rng, &standard.public(), &info, &aad, &plaintext).expect("seal");
        let a = standard
            .open_box(&b.ephemeral, &info, &aad, &b.ciphertext)
            .expect("standard opening");
        let t = threshold
            .open_box(&b.ephemeral, &info, &aad, &b.ciphertext)
            .expect("threshold opening");
        prop_assert_eq!(a.as_slice(), plaintext.as_slice());
        prop_assert_eq!(t.as_slice(), plaintext.as_slice());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Arbitrary ephemeral keys never panic the threshold opening, and keys
    /// are refused exactly when they leave the prime-order subgroup: every
    /// multiple of the base point passes the key check (and then fails only
    /// the AEAD on a random ciphertext), every such point plus a non-trivial
    /// torsion component is refused, and so is anything off the curve.
    #[test]
    fn threshold_open_box_refuses_exactly_the_bad_ephemeral_keys(
        k in any::<[u8; 32]>(),
        eph in any::<[u8; 32]>(),
        e in any::<[u8; 32]>(),
        torsion in 1usize..8,
        ciphertext in vec(any::<u8>(), 16..64),
    ) {
        let key = EpochSecret::Threshold(ScalarSealSecret::from_x25519(&SealSecret::from_bytes(k)));
        let any = key.open_box(&eph, b"i", b"a", &ciphertext);
        prop_assert!(matches!(
            any,
            Err(CryptoError::InvalidPublicKey) | Err(CryptoError::Aead)
        ));
        if MontgomeryPoint(eph).to_edwards(0).is_none() {
            prop_assert_eq!(any, Err(CryptoError::InvalidPublicKey));
        }

        let honest = EdwardsPoint::mul_base_clamped(e);
        let u = honest.to_montgomery().to_bytes();
        prop_assert_eq!(
            key.open_box(&u, b"i", b"a", &ciphertext),
            Err(CryptoError::Aead)
        );
        let mixed = (honest + EIGHT_TORSION[torsion]).to_montgomery().to_bytes();
        prop_assert_eq!(
            key.open_box(&mixed, b"i", b"a", &ciphertext),
            Err(CryptoError::InvalidPublicKey)
        );
    }
}
