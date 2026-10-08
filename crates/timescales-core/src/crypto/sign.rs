//! Ed25519 signatures over 32-byte domain-separated digests.
//!
//! Signing a digest rather than the full message keeps on-chain verification
//! cheap: the Solana Ed25519 precompile only ever sees 32 bytes.

use core::fmt;

use crate::{Decode, DecodeError, Encode, Hash32, Reader};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::CryptoError;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(pub [u8; 64]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

impl Encode for Signature {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Signature {
    const MIN_ENCODED_LEN: usize = 64;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.array().map(Signature)
    }
}

/// Long-term Ed25519 key. Zeroized on drop by `ed25519-dalek`.
pub struct Keypair(SigningKey);

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keypair(pub={})", Hash32(self.public()))
    }
}

impl Keypair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(SigningKey::generate(rng))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// The secret seed. Zeroized when the returned value is dropped.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign_digest(&self, digest: &Hash32) -> Signature {
        Signature(self.0.sign(digest.as_bytes()).to_bytes())
    }

    /// Signs `message` as given: for texts a wallet shows the user.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message).to_bytes())
    }
}

/// Strict verification of a signature over `message` as given.
pub fn verify_message(
    public: &[u8; 32],
    message: &[u8],
    sig: &Signature,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
    vk.verify_strict(message, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

/// Strict verification: rejects non-canonical encodings and small-order keys.
pub fn verify_digest(
    public: &[u8; 32],
    digest: &Hash32,
    sig: &Signature,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
    vk.verify_strict(digest.as_bytes(), &sig)
        .map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn sign_verify() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let kp = Keypair::generate(&mut rng);
        let d = Hash32([3; 32]);
        let s = kp.sign_digest(&d);
        assert!(verify_digest(&kp.public(), &d, &s).is_ok());
        assert_eq!(
            verify_digest(&kp.public(), &Hash32([4; 32]), &s),
            Err(CryptoError::BadSignature)
        );
        let mut bad = s;
        bad.0[0] ^= 1;
        assert!(verify_digest(&kp.public(), &d, &bad).is_err());
    }

    #[test]
    fn seed_round_trips() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(2);
        let kp = Keypair::generate(&mut rng);
        let seed = kp.seed();
        assert_eq!(Keypair::from_seed(*seed).public(), kp.public());
        assert_eq!(
            format!("{kp:?}"),
            format!("Keypair(pub={})", Hash32(kp.public()))
        );
    }
}
