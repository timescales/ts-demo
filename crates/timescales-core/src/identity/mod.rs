//! Identities of protocol participants.
//!
//! Traders and executors are identified by Ed25519 public keys. This crate
//! wraps the signing keys with role-specific types so a trader key cannot be
//! passed where an executor key is expected, and provides a small registry
//! used by relays (who may submit) and settlement (which executors are
//! recognised).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use std::collections::BTreeMap;

use crate::crypto::{Keypair, Signature, Zeroizing, verify_digest, verify_message};
use crate::{ExecutorId, Hash32, TraderId};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityError {
    #[error("bad signature")]
    BadSignature,
    #[error("unknown identity")]
    Unknown,
    #[error("identity revoked")]
    Revoked,
}

#[derive(Debug)]
pub struct TraderKey(Keypair);

impl TraderKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(Keypair::generate(rng))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(Keypair::from_seed(seed))
    }

    pub fn id(&self) -> TraderId {
        TraderId(self.0.public())
    }

    pub fn sign(&self, digest: &Hash32) -> Signature {
        self.0.sign_digest(digest)
    }

    /// Signs a text the trader's wallet shows, as a wallet's `signMessage` does.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.0.sign_message(message)
    }

    /// The secret seed. Zeroized when the returned value is dropped.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        self.0.seed()
    }
}

#[derive(Debug)]
pub struct ExecutorKey(Keypair);

impl ExecutorKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(Keypair::generate(rng))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(Keypair::from_seed(seed))
    }

    pub fn id(&self) -> ExecutorId {
        ExecutorId(self.0.public())
    }

    pub fn sign(&self, digest: &Hash32) -> Signature {
        self.0.sign_digest(digest)
    }
}

pub fn verify_trader(id: &TraderId, digest: &Hash32, sig: &Signature) -> Result<(), IdentityError> {
    verify_digest(&id.0, digest, sig).map_err(|_| IdentityError::BadSignature)
}

/// A trader's signature over a text its wallet showed (`signMessage`).
pub fn verify_trader_message(
    id: &TraderId,
    message: &[u8],
    sig: &Signature,
) -> Result<(), IdentityError> {
    verify_message(&id.0, message, sig).map_err(|_| IdentityError::BadSignature)
}

pub fn verify_executor(
    id: &ExecutorId,
    digest: &Hash32,
    sig: &Signature,
) -> Result<(), IdentityError> {
    verify_digest(&id.0, digest, sig).map_err(|_| IdentityError::BadSignature)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Active,
    Revoked,
}

/// Allowlist keyed by identity with per-entry metadata.
#[derive(Clone, Debug)]
pub struct Registry<K: Ord, M> {
    entries: BTreeMap<K, (Status, M)>,
}

impl<K: Ord, M> Default for Registry<K, M> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<K: Ord + Copy, M> Registry<K, M> {
    pub fn insert(&mut self, id: K, meta: M) {
        self.entries.insert(id, (Status::Active, meta));
    }

    pub fn revoke(&mut self, id: &K) -> bool {
        match self.entries.get_mut(id) {
            Some(e) => {
                e.0 = Status::Revoked;
                true
            }
            None => false,
        }
    }

    pub fn require_active(&self, id: &K) -> Result<&M, IdentityError> {
        match self.entries.get(id) {
            Some((Status::Active, m)) => Ok(m),
            Some((Status::Revoked, _)) => Err(IdentityError::Revoked),
            None => Err(IdentityError::Unknown),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn roles_sign_and_verify() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(3);
        let t = TraderKey::generate(&mut rng);
        let d = Hash32([1; 32]);
        assert!(verify_trader(&t.id(), &d, &t.sign(&d)).is_ok());
        let e = ExecutorKey::generate(&mut rng);
        assert!(verify_executor(&e.id(), &d, &t.sign(&d)).is_err());
    }

    #[test]
    fn trader_seed_restores_the_key() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(4);
        let t = TraderKey::generate(&mut rng);
        assert_eq!(TraderKey::from_seed(*t.seed()).id(), t.id());
    }

    #[test]
    fn registry_revocation() {
        let mut r: Registry<TraderId, ()> = Registry::default();
        let id = TraderId([1; 32]);
        assert_eq!(r.require_active(&id), Err(IdentityError::Unknown));
        r.insert(id, ());
        assert!(r.require_active(&id).is_ok());
        assert!(r.revoke(&id));
        assert_eq!(r.require_active(&id), Err(IdentityError::Revoked));
    }

    #[test]
    fn every_identity_error_is_produced() {
        // Exhaustive on purpose: a new variant must be produced here.
        fn variant(e: &IdentityError) -> usize {
            match e {
                IdentityError::BadSignature => 0,
                IdentityError::Unknown => 1,
                IdentityError::Revoked => 2,
            }
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(5);
        let t = TraderKey::generate(&mut rng);
        let d = Hash32([9; 32]);
        let mut sig = t.sign(&d);
        sig.0[0] ^= 1;
        let mut r: Registry<TraderId, ()> = Registry::default();
        let unknown = r.require_active(&t.id()).map(|_| ());
        r.insert(t.id(), ());
        r.revoke(&t.id());
        let errors = [
            verify_trader(&t.id(), &d, &sig),
            unknown,
            r.require_active(&t.id()).map(|_| ()),
        ];
        let seen: Vec<usize> = errors
            .iter()
            .map(|e| variant(e.as_ref().unwrap_err()))
            .collect();
        assert_eq!(seen, [0, 1, 2]);
    }
}
