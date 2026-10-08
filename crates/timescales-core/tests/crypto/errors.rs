//! Every `CryptoError` variant is reachable through the public API.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_core::Hash32;
use timescales_core::crypto::shamir::{self, Share};
use timescales_core::crypto::threshold::FeldmanDealing;
use timescales_core::crypto::{CryptoError, Keypair, SealSecret, open, seal, verify_digest};

#[test]
fn every_crypto_error_is_produced() {
    // Exhaustive on purpose: a new variant must be produced here.
    fn variant(e: &CryptoError) -> usize {
        match e {
            CryptoError::InvalidPublicKey => 0,
            CryptoError::BadSignature => 1,
            CryptoError::Aead => 2,
            CryptoError::InvalidThreshold { .. } => 3,
            CryptoError::NotEnoughShares => 4,
            CryptoError::DuplicateShare(_) => 5,
        }
    }
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let key = SealSecret::generate(&mut rng);
    let sealed = seal(&mut rng, &key.public(), b"info", b"aad", b"plaintext").expect("seal");
    let signer = Keypair::generate(&mut rng);
    let other = Keypair::generate(&mut rng);
    let digest = Hash32([7; 32]);
    let share = |index: u8| Share {
        index,
        value: [index; 32],
    };
    let errors = [
        seal(&mut rng, &[0u8; 32], b"info", b"aad", b"x").map(|_| ()),
        verify_digest(&other.public(), &digest, &signer.sign_digest(&digest)),
        open(&key, &sealed.ephemeral, b"info", b"aaX", &sealed.ciphertext).map(|_| ()),
        FeldmanDealing::try_new(&mut rng, 3, 2).map(|_| ()),
        shamir::combine(&[]).map(|_| ()),
        shamir::combine(&[share(1), share(1)]).map(|_| ()),
    ];
    let seen: Vec<usize> = errors
        .iter()
        .map(|e| variant(e.as_ref().expect_err("every case fails")))
        .collect();
    assert_eq!(seen, [0, 1, 2, 3, 4, 5]);
    assert_eq!(
        errors[3],
        Err(CryptoError::InvalidThreshold { threshold: 3, n: 2 })
    );
    assert_eq!(errors[5], Err(CryptoError::DuplicateShare(1)));
}
