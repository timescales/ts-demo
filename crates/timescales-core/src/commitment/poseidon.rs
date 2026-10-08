//! Poseidon commitments over the BN254 scalar field.
//!
//! Sponge of width 3 (rate 2, capacity 1), `x^5` S-box, 8 full and 57
//! partial rounds, round constants and MDS matrix from the Grain LFSR as
//! implemented in `ark-crypto-primitives`. The round counts are the ones
//! the Poseidon paper gives for `t = 3` at 128-bit security over a ~254-bit
//! prime. The constants are arkworks', not circomlib's, so these digests are
//! not interchangeable with Circom Poseidon (or Solana's `sol_poseidon`).
//!
//! `C = Poseidon(e_0,..., e_m, salt)` where `e_i` are the item's
//! [`Committable::poseidon_elements`] and `salt` is the first 31 bytes of
//! the trader's salt (248 bits of hiding).

use std::sync::OnceLock;

use crate::OrderCommitment;
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{
    PoseidonConfig, PoseidonSponge, find_poseidon_ark_and_mds,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, BigInteger256, PrimeField};

use crate::commitment::{Committable, Salt};

pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 57;
pub const ALPHA: u64 = 5;
pub const RATE: usize = 2;

pub fn config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            u64::from(Fr::MODULUS_BIT_SIZE),
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0,
        );
        PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, 1)
    })
}

pub fn element(limbs: [u64; 4]) -> Fr {
    Fr::from_bigint(BigInteger256::new(limbs))
        .unwrap_or_else(|| unreachable!("elements are below 2^248"))
}

pub fn salt_element(salt: &Salt) -> Fr {
    Fr::from_le_bytes_mod_order(&salt.0[..31])
}

pub fn to_commitment(x: &Fr) -> OrderCommitment {
    let b = x.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[..32]);
    OrderCommitment(out)
}

pub fn from_commitment(c: &OrderCommitment) -> Option<Fr> {
    let x = Fr::from_le_bytes_mod_order(&c.0);
    (to_commitment(&x) == *c).then_some(x)
}

pub fn hash(elements: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(config());
    sponge.absorb(&elements.to_vec());
    sponge.squeeze_native_field_elements(1)[0]
}

pub fn commit_field<T: Committable>(item: &T, salt: &Salt) -> Fr {
    let mut e: Vec<Fr> = item.poseidon_elements().into_iter().map(element).collect();
    e.push(salt_element(salt));
    hash(&e)
}

pub fn commit<T: Committable>(item: &T, salt: &Salt) -> OrderCommitment {
    to_commitment(&commit_field(item, salt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{Salt, verify};
    use crate::*;

    fn order() -> Order {
        Order {
            market: MarketId(3),
            trader: TraderId([0xab; 32]),
            nonce: u64::MAX,
            side: Side::Sell,
            role: Role::Taker,
            kind: OrderKind::Limit,
            limit: Tick(u64::MAX - 1),
            quantity: Lots(u64::MAX),
            valid_from: EpochId(5),
            expires_at: EpochId(9),
        }
    }

    #[test]
    fn opens_and_binds() {
        let s = Salt([7; 32]);
        let c = commit(&order(), &s);
        assert!(verify(CommitmentScheme::PoseidonBn254, &c, &order(), &s).is_ok());
        let mut o = order();
        o.limit = Tick(1);
        assert!(verify(CommitmentScheme::PoseidonBn254, &c, &o, &s).is_err());
        assert!(from_commitment(&c).is_some());
    }

    #[test]
    fn order_packing_is_injective_on_auction_fields() {
        // Extreme values must not bleed across bit ranges.
        let e = order().poseidon_elements();
        let x = element(e[0]).into_bigint();
        let bits = x.to_bits_le();
        let read = |from: usize, len: usize| -> u64 {
            (0..len).fold(0u64, |acc, i| acc | (u64::from(bits[from + i]) << i))
        };
        assert_eq!(read(0, 8), 1);
        assert_eq!(read(8, 8), 0b011);
        assert_eq!(read(16, 64), u64::MAX - 1);
        assert_eq!(read(80, 64), u64::MAX);
        assert!(bits[144..].iter().all(|b| !b));
    }
}
