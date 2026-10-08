//! Private intents and their sealed, fixed-size transport form.
//!
//! Lifecycle on the trader side:
//!
//! 1. Build an [`IntentBody`] (place, cancel, or cover traffic).
//! 2. Draw a salt, compute the commitment, sign the commitment.
//! 3. Seal the [`PrivateIntent`] to the batch key for the target epoch.
//!
//! The executor reverses the steps with [`SealedEnvelope::open`] (or
//! [`SealedEnvelope::open_with`] for an epoch secret), which only succeeds
//! if decryption, parsing, the commitment opening and the signature all
//! check out.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod envelope;
#[allow(clippy::module_inception)]
pub mod intent;
pub mod masked;

pub use envelope::{CIPHERTEXT_LEN, ENVELOPE_LEN, PLAINTEXT_LEN, SealedEnvelope};
pub use intent::{
    Cancel, IntentBody, PrivateIntent, commit_body, signature_digest, signed_message,
};
pub use masked::{FieldBytes, MaskedBody, MaskedIntent, MaskedPlace};

use crate::DecodeError;
use crate::commitment::CommitmentError;
use crate::crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IntentError {
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("decryption failed: {0}")]
    Crypto(CryptoError),
    #[error("malformed plaintext: {0}")]
    Malformed(DecodeError),
    #[error("commitment: {0}")]
    Commitment(CommitmentError),
    #[error("commitment does not match envelope header")]
    CommitmentMismatch,
    #[error("intent signature invalid")]
    BadSignature,
    #[error("signing key does not match the trader named in the intent")]
    WrongSigner,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SealSecret;
    use crate::identity::TraderKey;
    use crate::*;
    use rand::SeedableRng;

    fn setup() -> (rand_chacha::ChaCha20Rng, TraderKey, SealSecret, Order) {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(11);
        let key = TraderKey::generate(&mut rng);
        let epoch_key = SealSecret::generate(&mut rng);
        let order = Order {
            market: MarketId(1),
            trader: key.id(),
            nonce: 7,
            side: Side::Buy,
            role: Role::Taker,
            kind: OrderKind::Limit,
            limit: Tick(101),
            quantity: Lots(3),
            valid_from: EpochId(5),
            expires_at: EpochId(5),
        };
        (rng, key, epoch_key, order)
    }

    fn seal(
        rng: &mut rand_chacha::ChaCha20Rng,
        ek: &SealSecret,
        c: OrderCommitment,
        i: &PrivateIntent,
    ) -> SealedEnvelope {
        SealedEnvelope::seal(rng, MarketId(1), EpochId(5), &ek.public(), c, i).unwrap()
    }

    #[test]
    fn place_roundtrip() {
        let (mut rng, key, ek, order) = setup();
        let (intent, c) =
            PrivateIntent::place(&mut rng, &key, CommitmentScheme::Sha256, order).unwrap();
        let env = seal(&mut rng, &ek, c, &intent);
        assert_eq!(env.to_bytes().len(), ENVELOPE_LEN);
        assert_eq!(SealedEnvelope::decode_exact(&env.to_bytes()).unwrap(), env);
        let opened = env.open(&ek, CommitmentScheme::Sha256).unwrap();
        assert_eq!(opened, intent);
    }

    #[test]
    fn all_intent_kinds_have_identical_envelope_size() {
        let (mut rng, key, ek, order) = setup();
        let (p, pc) =
            PrivateIntent::place(&mut rng, &key, CommitmentScheme::Sha256, order).unwrap();
        let cancel = Cancel {
            market: MarketId(1),
            trader: key.id(),
            nonce: 8,
            target: pc,
            epoch: EpochId(5),
        };
        let (c, cc) =
            PrivateIntent::cancel(&mut rng, &key, CommitmentScheme::Sha256, cancel).unwrap();
        let (n, nc) = PrivateIntent::noop(&mut rng, CommitmentScheme::Sha256).unwrap();
        let sizes: Vec<usize> = [(p, pc), (c, cc), (n, nc)]
            .iter()
            .map(|(i, c)| seal(&mut rng, &ek, *c, i).to_bytes().len())
            .collect();
        assert!(sizes.iter().all(|s| *s == ENVELOPE_LEN));
    }

    #[test]
    fn header_swap_breaks_decryption() {
        let (mut rng, key, ek, order) = setup();
        let (intent, c) =
            PrivateIntent::place(&mut rng, &key, CommitmentScheme::Sha256, order).unwrap();
        let mut env = seal(&mut rng, &ek, c, &intent);
        env.epoch = EpochId(6);
        assert!(matches!(
            env.open(&ek, CommitmentScheme::Sha256),
            Err(IntentError::Crypto(_))
        ));
    }

    #[test]
    fn forged_signature_rejected() {
        let (mut rng, key, ek, order) = setup();
        let (mut intent, c) =
            PrivateIntent::place(&mut rng, &key, CommitmentScheme::Sha256, order).unwrap();
        intent.signature.0[10] ^= 0x40;
        let env = seal(&mut rng, &ek, c, &intent);
        assert_eq!(
            env.open(&ek, CommitmentScheme::Sha256),
            Err(IntentError::BadSignature)
        );
    }

    #[test]
    fn wrong_commitment_rejected() {
        let (mut rng, key, ek, order) = setup();
        let (intent, _) =
            PrivateIntent::place(&mut rng, &key, CommitmentScheme::Sha256, order).unwrap();
        let env = seal(&mut rng, &ek, OrderCommitment([1; 32]), &intent);
        assert_eq!(
            env.open(&ek, CommitmentScheme::Sha256),
            Err(IntentError::CommitmentMismatch)
        );
    }

    #[test]
    fn debug_output_redacts_the_intent() {
        let (mut rng, key, ek, order) = setup();
        let (intent, c) =
            PrivateIntent::place(&mut rng, &key, CommitmentScheme::Sha256, order).unwrap();
        assert_eq!(format!("{intent:?}"), "PrivateIntent(..)");
        assert_eq!(format!("{intent:#?}"), "PrivateIntent(..)");
        let (noop, _) = PrivateIntent::noop(&mut rng, CommitmentScheme::Sha256).unwrap();
        assert_eq!(format!("{noop:?}"), format!("{intent:?}"));
        // The envelope shows only its public header.
        let env = seal(&mut rng, &ek, c, &intent);
        let shown = format!("{env:?}");
        assert!(shown.contains("commitment") && !shown.contains("ciphertext"));
    }

    #[test]
    fn cannot_sign_for_someone_else() {
        let (mut rng, _key, _ek, order) = setup();
        let other = TraderKey::generate(&mut rng);
        assert_eq!(
            PrivateIntent::place(&mut rng, &other, CommitmentScheme::Sha256, order).unwrap_err(),
            IntentError::WrongSigner
        );
    }
}
