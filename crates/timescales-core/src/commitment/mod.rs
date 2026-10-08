//! Commitments to private intents.
//!
//! A commitment is published when an intent is submitted and opened only
//! inside an executor. It must be
//!
//! * **hiding** - the 256-bit salt is drawn uniformly by the trader, so the
//!   commitment reveals nothing about the intent under the random-oracle
//!   model for the hash.
//! * **binding** - opening to two different intents requires a hash
//!   collision.
//!
//! The scheme is fixed per market (`MarketParams::commitment_scheme`).
//! SHA-256 is the default. Markets that require SNARK proofs use Poseidon so
//! the circuit can open commitments cheaply. That variant is behind the
//! `poseidon` feature because it pulls in arkworks.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use crate::crypto::{Hasher, domain};
use crate::{CommitmentScheme, Encode, Order, OrderCommitment};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[cfg(feature = "poseidon")]
pub mod poseidon;

/// Salt drawn by the trader for each intent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Salt(pub [u8; 32]);

impl core::fmt::Debug for Salt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Salt(..)")
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommitmentError {
    #[error("commitment scheme {0:?} not compiled in")]
    UnsupportedScheme(CommitmentScheme),
    #[error("commitment does not open to the given intent")]
    Mismatch,
}

/// Something a trader can commit to.
pub trait Committable {
    /// Distinguishes intent kinds so a cancel can never open a placement.
    const KIND: u8;

    /// Canonical byte encoding (SHA-256 scheme).
    fn commitment_bytes(&self, out: &mut Vec<u8>);

    /// Field-friendly encoding as 64-bit limbs (Poseidon scheme). Each limb
    /// is lifted into the field without reduction.
    fn commitment_limbs(&self) -> Vec<u64>;

    /// Field elements for the Poseidon scheme, each given as a little-endian
    /// integer below 2^248. The default packs [`Self::commitment_limbs`]
    /// three per element after a kind element. Orders override it with a
    /// layout the auction circuit can open cheaply.
    fn poseidon_elements(&self) -> Vec<[u64; 4]> {
        let mut out = vec![[u64::from(Self::KIND), 0, 0, 0]];
        for chunk in self.commitment_limbs().chunks(3) {
            let mut e = [0u64; 4];
            e[..chunk.len()].copy_from_slice(chunk);
            out.push(e);
        }
        out
    }
}

impl Committable for Order {
    const KIND: u8 = 1;

    fn commitment_bytes(&self, out: &mut Vec<u8>) {
        self.encode(out);
    }

    fn commitment_limbs(&self) -> Vec<u64> {
        let t = self.trader.0;
        let limb = |i: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&t[i * 8..i * 8 + 8]);
            u64::from_le_bytes(b)
        };
        vec![
            self.market.0,
            limb(0),
            limb(1),
            limb(2),
            limb(3),
            self.nonce,
            u64::from(self.side as u8)
                | u64::from(self.role as u8) << 1
                | u64::from(self.kind as u8) << 2,
            self.limit.0,
            self.quantity.0,
            self.valid_from.0,
            self.expires_at.0,
        ]
    }

    /// ```text
    /// e0 = KIND + 2^8 (side | role<<1 | kind<<2) + 2^16 limit + 2^80 quantity
    /// e1 = market + 2^64 nonce + 2^128 valid_from
    /// e2 = expires_at
    /// e3 = trader[0..16],  e4 = trader[16..32]
    /// ```
    /// The fields the auction needs sit together in `e0` so the circuit
    /// decomposes one element. The rest are absorbed opaquely.
    fn poseidon_elements(&self) -> Vec<[u64; 4]> {
        let flags = u64::from(self.side as u8)
            | u64::from(self.role as u8) << 1
            | u64::from(self.kind as u8) << 2;
        let l = self.limit.0;
        let q = self.quantity.0;
        // e0 bits: [0,8) kind, [8,16) flags, [16,80) limit, [80,144) quantity.
        let e0 = [
            u64::from(Self::KIND) | flags << 8 | l << 16,
            l >> 48 | q << 16,
            q >> 48,
            0,
        ];
        let e1 = [self.market.0, self.nonce, self.valid_from.0, 0];
        let e2 = [self.expires_at.0, 0, 0, 0];
        let t = |i: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&self.trader.0[i * 8..i * 8 + 8]);
            u64::from_le_bytes(b)
        };
        vec![e0, e1, e2, [t(0), t(1), 0, 0], [t(2), t(3), 0, 0]]
    }
}

pub fn commit<T: Committable>(
    scheme: CommitmentScheme,
    item: &T,
    salt: &Salt,
) -> Result<OrderCommitment, CommitmentError> {
    match scheme {
        CommitmentScheme::Sha256 => Ok(commit_sha256(item, salt)),
        #[cfg(feature = "poseidon")]
        CommitmentScheme::PoseidonBn254 => Ok(poseidon::commit(item, salt)),
        #[cfg(not(feature = "poseidon"))]
        CommitmentScheme::PoseidonBn254 => Err(CommitmentError::UnsupportedScheme(scheme)),
    }
}

pub fn commit_sha256<T: Committable>(item: &T, salt: &Salt) -> OrderCommitment {
    let mut body = Vec::with_capacity(128);
    body.push(T::KIND);
    item.commitment_bytes(&mut body);
    let h = Hasher::new(domain::ORDER_COMMITMENT)
        .chain(&body)
        .chain(&salt.0)
        .finalize();
    OrderCommitment(h.0)
}

/// Check an opening. The comparison is constant time. The commitment is
/// public but the recomputed value is derived from secrets.
pub fn verify<T: Committable>(
    scheme: CommitmentScheme,
    commitment: &OrderCommitment,
    item: &T,
    salt: &Salt,
) -> Result<(), CommitmentError> {
    let c = commit(scheme, item, salt)?;
    if bool::from(c.0.ct_eq(&commitment.0)) {
        Ok(())
    } else {
        Err(CommitmentError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EpochId, Lots, MarketId, OrderKind, Role, Side, Tick, TraderId};

    fn order() -> Order {
        Order {
            market: MarketId(1),
            trader: TraderId([5; 32]),
            nonce: 1,
            side: Side::Sell,
            role: Role::Maker,
            kind: OrderKind::Limit,
            limit: Tick(99),
            quantity: Lots(10),
            valid_from: EpochId(1),
            expires_at: EpochId(1),
        }
    }

    #[test]
    fn opens_and_binds() {
        let s = Salt([1; 32]);
        let c = commit_sha256(&order(), &s);
        assert!(verify(CommitmentScheme::Sha256, &c, &order(), &s).is_ok());
        let mut o2 = order();
        o2.quantity = Lots(11);
        assert_eq!(
            verify(CommitmentScheme::Sha256, &c, &o2, &s),
            Err(CommitmentError::Mismatch)
        );
        assert!(verify(CommitmentScheme::Sha256, &c, &order(), &Salt([2; 32])).is_err());
    }

    #[test]
    fn every_commitment_error_is_produced() {
        // Exhaustive on purpose: a new variant must be produced here.
        fn variant(e: &CommitmentError) -> usize {
            match e {
                CommitmentError::UnsupportedScheme(_) => 0,
                CommitmentError::Mismatch => 1,
            }
        }
        let s = Salt([1; 32]);
        let c = commit_sha256(&order(), &s);
        let mut errors = vec![verify(
            CommitmentScheme::Sha256,
            &c,
            &order(),
            &Salt([2; 32]),
        )];
        // Without the `poseidon` feature the scheme is reported as
        // unsupported. With it (feature unification in workspace runs) that
        // variant cannot occur.
        let poseidon = commit(CommitmentScheme::PoseidonBn254, &order(), &s);
        let expected: &[usize] = if cfg!(feature = "poseidon") {
            assert!(poseidon.is_ok());
            &[1]
        } else {
            errors.push(poseidon.map(|_| ()));
            &[1, 0]
        };
        let seen: Vec<usize> = errors
            .iter()
            .map(|e| variant(e.as_ref().unwrap_err()))
            .collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn salt_hides_identical_orders() {
        assert_ne!(
            commit_sha256(&order(), &Salt([1; 32])),
            commit_sha256(&order(), &Salt([2; 32]))
        );
    }

    #[test]
    fn limbs_are_injective_on_flags() {
        let mut seen = std::collections::HashSet::new();
        for side in [Side::Buy, Side::Sell] {
            for role in [Role::Maker, Role::Taker] {
                for kind in [OrderKind::Limit, OrderKind::Market] {
                    let mut o = order();
                    o.side = side;
                    o.role = role;
                    o.kind = kind;
                    assert!(seen.insert(o.commitment_limbs()[6]));
                }
            }
        }
    }
}
