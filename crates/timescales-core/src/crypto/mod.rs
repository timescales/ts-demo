//! Cryptographic building blocks.
//!
//! Thin, opinionated wrappers over audited crates (`sha2`, `ed25519-dalek`,
//! `x25519-dalek`, `curve25519-dalek`, `chacha20poly1305`, `hkdf`). Two
//! schemes are assembled here from those crates' group and field operations,
//! both small enough to review in full: byte-wise Shamir sharing over
//! GF(2^8) ([`shamir`]) and Feldman verifiable secret sharing over Ed25519
//! scalars ([`threshold`]), whose secrets open sealed boxes through
//! [`EpochSecret`].
//!
//! Functions that hand out secret bytes return them in [`Zeroizing`], which
//! wipes them when dropped.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod codec;
pub mod hash;
pub mod seal;
pub mod shamir;
pub mod sign;
pub mod threshold;

pub use hash::{Hasher, domain, hash, hash_parts};
pub use seal::{EpochSecret, ScalarSealSecret, SealSecret, SealedBox, TAG_LEN, open, seal};
pub use sign::{Keypair, Signature, verify_digest, verify_message};
pub use zeroize::Zeroizing;

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("authenticated decryption failed")]
    Aead,
    #[error("invalid threshold {threshold} of {n}")]
    InvalidThreshold { threshold: u8, n: u8 },
    #[error("not enough shares")]
    NotEnoughShares,
    #[error("duplicate or zero share index {0}")]
    DuplicateShare(u8),
}
