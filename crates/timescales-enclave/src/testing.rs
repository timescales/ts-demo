//! Test support (feature `test-util`, and the crate's own tests): signing a message the way a wallet
//! signs a SIWS grant. Never part of a service build.

use timescales_core::crypto::threshold::{ScalarShare, decompress_canonical};

use crate::ed25519::{BASEPOINT, Sha512, reduce_le};

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// The RFC 8032 Ed25519 signature of `message` under the key with secret
/// seed `seed` (the seed `timescales_core::crypto::Keypair::from_seed` takes).
pub fn sign_message(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let expanded = sha512(&[seed]);
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&expanded[..32]);
    a_bytes[0] &= 248;
    a_bytes[31] &= 127;
    a_bytes[31] |= 64;
    let zero = ScalarShare::from_bytes(1, &[0; 32])
        .map(|s| s.value)
        .unwrap_or_else(|| unreachable!("zero is a canonical scalar"));
    let b = decompress_canonical(&BASEPOINT)
        .unwrap_or_else(|| unreachable!("the base point decompresses"));
    let a = reduce_le(&zero, &a_bytes);
    let public = (b * a).compress().to_bytes();
    let r = reduce_le(&zero, &sha512(&[&expanded[32..], message]));
    let big_r = (b * r).compress().to_bytes();
    let k = reduce_le(&zero, &sha512(&[&big_r, &public, message]));
    let s = r + k * a;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
}

#[cfg(test)]
mod tests {
    use timescales_core::crypto::{Keypair, hash};

    use super::*;

    #[test]
    fn signatures_match_the_digest_signer_and_verify() {
        for i in 0u8..4 {
            let seed = [i; 32];
            let digest = hash(b"timescales/test/sign", &[i]);
            assert_eq!(
                sign_message(&seed, digest.as_bytes()),
                Keypair::from_seed(seed).sign_digest(&digest).0
            );
            let text = b"localhost:4173 wants you to sign in with your Solana account:";
            let sig = sign_message(&seed, text);
            assert!(crate::ed25519::verify_strict(
                &Keypair::from_seed(seed).public(),
                text,
                &sig
            ));
        }
    }
}
