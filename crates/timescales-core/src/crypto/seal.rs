//! Public-key sealed boxes.
//!
//! Ephemeral-static X25519, HKDF-SHA256, ChaCha20-Poly1305. Structurally this
//! is HPKE base mode (RFC 9180) with a fixed suite, but the wire format is our
//! own and it is not interoperable with HPKE implementations.
//!
//! Each box uses a fresh ephemeral key, so the derived AEAD key is single use
//! and a fixed nonce is safe.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::CryptoError;
use crate::crypto::hash::domain;
use crate::crypto::threshold::x25519_public;

/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// X25519 secret key for a recipient (an epoch key or an MPC node key).
pub struct SealSecret(StaticSecret);

impl core::fmt::Debug for SealSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SealSecret(pub={:02x?}..)", &self.public()[..4])
    }
}

impl Zeroize for SealSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl SealSecret {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(StaticSecret::random_from_rng(rng))
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(StaticSecret::from(b))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }
}

/// An epoch secret held as a raw Ed25519 scalar `s` (Feldman dealing).
/// Its public key is `u(s*B)`, and boxes are opened with the unclamped
/// Montgomery product `u(s*E)`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ScalarSealSecret(Scalar);

impl core::fmt::Debug for ScalarSealSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ScalarSealSecret(..)")
    }
}

impl ScalarSealSecret {
    pub fn from_scalar(s: Scalar) -> Self {
        Self(s)
    }

    pub fn scalar(&self) -> &Scalar {
        &self.0
    }

    /// The scalar form `clamp(k) mod L` of an X25519 secret `k`. It has the
    /// same public key and opens the same honestly sealed boxes, because the
    /// base point and every honest ephemeral point have order L. A locally
    /// held key can be dealt and opened through the threshold path.
    pub fn from_x25519(secret: &SealSecret) -> Self {
        let clamped = Zeroizing::new(clamp_integer(secret.to_bytes()));
        Self(Scalar::from_bytes_mod_order(*clamped))
    }

    /// `u(s*B)`: the X25519 public key traders seal to.
    pub fn public(&self) -> [u8; 32] {
        x25519_public(&self.0)
    }

    /// `u(s*E)` for the ephemeral key `E` of a box.
    ///
    /// `s` is a uniform scalar, not a clamped X25519 key, so the product is
    /// computed with `s` as it is and `E` must lie in the prime-order
    /// subgroup: a small-order component `T` would make the result depend on
    /// `s mod 8` and turn every decryption into an oracle for those bits,
    /// and a point on the twist leaks `s` modulo the twist's small factors.
    /// So the zero key, `u` values off the curve (on the twist),
    /// non-canonical encodings of `u` and points with a torsion component
    /// are refused. Honest ephemeral keys always pass: `clamp(e)*B` is a
    /// multiple of the base point.
    fn shared_secret(&self, ephemeral: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        if *ephemeral == [0u8; 32] {
            return Err(CryptoError::InvalidPublicKey);
        }
        let u = MontgomeryPoint(*ephemeral);
        // Either sign works: P and -P share u, are torsion-free together,
        // and u(s*P) = u(s*(-P)).
        let point = u.to_edwards(0).ok_or(CryptoError::InvalidPublicKey)?;
        if point.to_montgomery().to_bytes() != *ephemeral || !point.is_torsion_free() {
            return Err(CryptoError::InvalidPublicKey);
        }
        let mut product = u * self.0;
        let shared = Zeroizing::new(product.to_bytes());
        product.zeroize();
        // Only s = 0 gets here, which no dealing produces.
        if *shared == [0u8; 32] {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(shared)
    }
}

/// The key an epoch's envelopes are opened with: a locally derived X25519
/// key (simulation and v1 vectors) or a threshold-dealt scalar.
#[derive(Debug)]
pub enum EpochSecret {
    Dev(SealSecret),
    Threshold(ScalarSealSecret),
}

impl Zeroize for EpochSecret {
    fn zeroize(&mut self) {
        match self {
            EpochSecret::Dev(s) => s.zeroize(),
            EpochSecret::Threshold(s) => s.zeroize(),
        }
    }
}

impl EpochSecret {
    /// The X25519 public key boxes for this secret are sealed to.
    pub fn public(&self) -> [u8; 32] {
        match self {
            EpochSecret::Dev(s) => s.public(),
            EpochSecret::Threshold(s) => s.public(),
        }
    }

    /// Open a box sealed to this secret's public key. The threshold path
    /// rejects an ephemeral key that is zero, off the curve, not canonically
    /// encoded or has a torsion component before computing the shared
    /// secret, then derives the AEAD key exactly as [`open`].
    pub fn open_box(
        &self,
        ephemeral: &[u8; 32],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        match self {
            EpochSecret::Dev(s) => open(s, ephemeral, info, aad, ciphertext),
            EpochSecret::Threshold(s) => {
                let shared = s.shared_secret(ephemeral)?;
                decrypt(&shared, ephemeral, &s.public(), info, aad, ciphertext)
            }
        }
    }
}

/// Output of [`seal`]. `ciphertext.len == plaintext.len + TAG_LEN`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBox {
    pub ephemeral: [u8; 32],
    pub ciphertext: Vec<u8>,
}

fn derive_key(
    shared: &[u8; 32],
    eph: &[u8; 32],
    recipient: &[u8; 32],
    info: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph);
    salt[32..].copy_from_slice(recipient);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    let mut full_info = Vec::with_capacity(domain::SEAL_KDF.len() + info.len());
    full_info.extend_from_slice(domain::SEAL_KDF);
    full_info.extend_from_slice(info);
    // 32 bytes is always a valid HKDF-SHA256 output length.
    hk.expand(&full_info, okm.as_mut_slice())
        .unwrap_or_else(|_| unreachable!());
    okm
}

/// AEAD under the key derived from `shared`. The HKDF salt binds the
/// ephemeral and the recipient public keys.
fn decrypt(
    shared: &[u8; 32],
    ephemeral: &[u8; 32],
    recipient: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key = derive_key(shared, ephemeral, recipient, info);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
    cipher
        .decrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Aead)
}

/// Encrypt `plaintext` to `recipient`. `info` binds the key derivation to a
/// context (market, epoch, purpose). `aad` is authenticated but not encrypted.
pub fn seal<R: RngCore + CryptoRng>(
    rng: &mut R,
    recipient: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedBox, CryptoError> {
    let eph = StaticSecret::random_from_rng(rng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient));
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidPublicKey);
    }
    let key = derive_key(shared.as_bytes(), &eph_pub, recipient, info);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(SealedBox {
        ephemeral: eph_pub,
        ciphertext,
    })
}

/// Open a box sealed to `secret`'s public key. The plaintext is zeroized
/// when the returned buffer is dropped.
pub fn open(
    secret: &SealSecret,
    ephemeral: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let shared = secret.0.diffie_hellman(&PublicKey::from(*ephemeral));
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidPublicKey);
    }
    decrypt(
        shared.as_bytes(),
        ephemeral,
        &secret.public(),
        info,
        aad,
        ciphertext,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::threshold::FeldmanDealing;
    use curve25519_dalek::constants::EIGHT_TORSION;
    use curve25519_dalek::edwards::EdwardsPoint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn roundtrip_and_tamper() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let sk = SealSecret::generate(&mut rng);
        let b = seal(&mut rng, &sk.public(), b"ctx", b"hdr", b"hello").expect("seal");
        assert_eq!(b.ciphertext.len(), 5 + TAG_LEN);
        assert_eq!(
            open(&sk, &b.ephemeral, b"ctx", b"hdr", &b.ciphertext)
                .expect("open")
                .as_slice(),
            b"hello"
        );
        assert!(open(&sk, &b.ephemeral, b"ctx2", b"hdr", &b.ciphertext).is_err());
        assert!(open(&sk, &b.ephemeral, b"ctx", b"hdX", &b.ciphertext).is_err());
        let mut ct = b.ciphertext.clone();
        ct[0] ^= 1;
        assert!(open(&sk, &b.ephemeral, b"ctx", b"hdr", &ct).is_err());
    }

    #[test]
    fn low_order_ephemeral_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let sk = SealSecret::generate(&mut rng);
        // The all-zero point is small order. DH output is all zeros.
        assert_eq!(
            open(&sk, &[0u8; 32], b"", b"", &[0u8; 16]),
            Err(CryptoError::InvalidPublicKey)
        );
        assert_eq!(
            seal(&mut rng, &[0u8; 32], b"", b"", b"x"),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    fn threshold_secret(rng: &mut ChaCha20Rng) -> EpochSecret {
        let (s, _, _) = FeldmanDealing::new(rng, 2, 3);
        EpochSecret::Threshold(ScalarSealSecret::from_scalar(*s))
    }

    #[test]
    fn threshold_open_box_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(10);
        let key = threshold_secret(&mut rng);
        let b = seal(&mut rng, &key.public(), b"ctx", b"hdr", b"order").expect("seal");
        let pt = key
            .open_box(&b.ephemeral, b"ctx", b"hdr", &b.ciphertext)
            .expect("opens");
        assert_eq!(pt.as_slice(), b"order");
        assert_eq!(
            key.open_box(&b.ephemeral, b"ctx", b"hdX", &b.ciphertext),
            Err(CryptoError::Aead)
        );
        assert_eq!(
            key.open_box(&b.ephemeral, b"ct2", b"hdr", &b.ciphertext),
            Err(CryptoError::Aead)
        );
    }

    #[test]
    fn threshold_open_box_matches_dev_open_for_the_same_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        for _ in 0..16 {
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut k);
            let x25519 = SealSecret::from_bytes(k);
            let threshold = EpochSecret::Threshold(ScalarSealSecret::from_x25519(&x25519));
            let dev = EpochSecret::Dev(x25519);
            assert_eq!(dev.public(), threshold.public());
            let b = seal(&mut rng, &dev.public(), b"i", b"a", b"same bytes").expect("seal");
            let a = dev.open_box(&b.ephemeral, b"i", b"a", &b.ciphertext);
            let t = threshold.open_box(&b.ephemeral, b"i", b"a", &b.ciphertext);
            assert_eq!(a, t);
            assert_eq!(t.expect("opens").as_slice(), b"same bytes");
        }
    }

    /// A `u` on the twist: `to_edwards` finds no curve point for it.
    fn twist_u() -> [u8; 32] {
        (2u8..)
            .map(|u| {
                let mut b = [0u8; 32];
                b[0] = u;
                b
            })
            .find(|b| MontgomeryPoint(*b).to_edwards(0).is_none())
            .expect("about half of all u lie on the twist")
    }

    #[test]
    fn threshold_open_box_rejects_bad_ephemeral_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let key = threshold_secret(&mut rng);
        let ct = [0u8; 32];
        let refused = |eph: &[u8; 32]| key.open_box(eph, b"", b"", &ct);

        assert_eq!(refused(&[0u8; 32]), Err(CryptoError::InvalidPublicKey));
        assert_eq!(refused(&twist_u()), Err(CryptoError::InvalidPublicKey));
        // u = p - 1 (that is, -1) is on the twist and is special-cased.
        let mut minus_one = [0xffu8; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0x7f;
        assert_eq!(refused(&minus_one), Err(CryptoError::InvalidPublicKey));

        let honest = EdwardsPoint::mul_base(&Scalar::random(&mut rng));
        for t in EIGHT_TORSION.iter().skip(1) {
            // Pure small-order points and prime-order points with a torsion
            // component.
            let small = t.to_montgomery().to_bytes();
            assert_eq!(refused(&small), Err(CryptoError::InvalidPublicKey));
            let mixed = (honest + t).to_montgomery().to_bytes();
            assert_eq!(refused(&mixed), Err(CryptoError::InvalidPublicKey));
        }

        // The same honest point under a non-canonical encoding of u: bit 255
        // set (ignored by the field decoding) is refused, the canonical
        // encoding is not (it fails only the AEAD).
        let canonical = honest.to_montgomery().to_bytes();
        assert_eq!(refused(&canonical), Err(CryptoError::Aead));
        let mut high_bit = canonical;
        high_bit[31] |= 0x80;
        assert_eq!(refused(&high_bit), Err(CryptoError::InvalidPublicKey));
    }

    #[test]
    fn threshold_zero_scalar_never_opens() {
        let key = EpochSecret::Threshold(ScalarSealSecret::from_scalar(Scalar::ZERO));
        assert_eq!(key.public(), [0u8; 32]);
        let honest = EdwardsPoint::mul_base(&Scalar::from(7u8))
            .to_montgomery()
            .to_bytes();
        assert_eq!(
            key.open_box(&honest, b"", b"", &[0u8; 16]),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn epoch_secret_zeroizes() {
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let mut dev = EpochSecret::Dev(SealSecret::generate(&mut rng));
        dev.zeroize();
        assert_eq!(
            dev.public(),
            SealSecret::from_bytes([0u8; 32]).public(),
            "a zeroized dev key is the all-zero secret"
        );
        let mut threshold = threshold_secret(&mut rng);
        threshold.zeroize();
        assert_eq!(threshold.public(), [0u8; 32]);
        // Debug output never shows key material.
        assert_eq!(format!("{threshold:?}"), "Threshold(ScalarSealSecret(..))");
    }
}
