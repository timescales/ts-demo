//! Program-derived addresses and the derived market id.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};
use timescales_core::crypto::{domain, hash_parts};

use crate::program::{ASSOCIATED_TOKEN_PROGRAM, ClientError, Key, TOKEN_PROGRAM};

const MAX_SEEDS: usize = 16;
const MAX_SEED_LEN: usize = 32;

fn on_curve(k: &Key) -> bool {
    CompressedEdwardsY(*k).decompress().is_some()
}

/// `Pubkey::find_program_address`: the first bump from 255 down to 1 whose
/// address is off the Ed25519 curve. Like Solana, bump 0 is never tried.
pub fn find_pda(seeds: &[&[u8]], program: &Key) -> Result<(Key, u8), ClientError> {
    first_bump(seeds, program, |k| !on_curve(k))
}

/// The first bump from 255 down to 1 whose candidate address `valid`
/// accepts. Only a test can make every candidate invalid.
pub(crate) fn first_bump(
    seeds: &[&[u8]],
    program: &Key,
    valid: impl Fn(&Key) -> bool,
) -> Result<(Key, u8), ClientError> {
    if seeds.len() >= MAX_SEEDS {
        return Err(ClientError::InvalidArgument("too many seeds"));
    }
    if seeds.iter().any(|s| s.len() > MAX_SEED_LEN) {
        return Err(ClientError::InvalidArgument("seed longer than 32 bytes"));
    }
    for bump in (1..=u8::MAX).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program);
        h.update(b"ProgramDerivedAddress");
        let k: Key = h.finalize().into();
        if valid(&k) {
            return Ok((k, bump));
        }
    }
    Err(ClientError::NoPda)
}

/// `LE64(H(MARKET_ID, program || creator || salt)[0..8])`. The program
/// accepts only this id for `InitMarket` by `creator` with `salt`.
pub fn derive_market_id(program: &Key, creator: &Key, salt: &[u8; 32]) -> u64 {
    let h = hash_parts(domain::MARKET_ID, &[program, creator, salt]);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.0[..8]);
    u64::from_le_bytes(b)
}

/// `["market", market_id u64 LE]`.
pub fn market_pda(program: &Key, market_id: u64) -> Result<(Key, u8), ClientError> {
    find_pda(&[b"market", &market_id.to_le_bytes()], program)
}

/// `["trader", market, owner]`.
pub fn trader_pda(program: &Key, market: &Key, owner: &Key) -> Result<(Key, u8), ClientError> {
    find_pda(&[b"trader", market, owner], program)
}

/// `["batch", market, epoch u64 LE]`.
pub fn batch_pda(program: &Key, market: &Key, epoch: u64) -> Result<(Key, u8), ClientError> {
    find_pda(&[b"batch", market, &epoch.to_le_bytes()], program)
}

/// The associated token account of `owner` for `mint` under the classic
/// Token program: `[owner, Token, mint]` derived by the associated token
/// account program. The owner may itself be a PDA (vaults owned by the
/// market).
pub fn associated_token_address(owner: &Key, mint: &Key) -> Key {
    // Every one of 255 candidates would have to be a curve point. Solana's
    // `find_program_address` panics in that case as well.
    find_pda(&[owner, &TOKEN_PROGRAM, mint], &ASSOCIATED_TOKEN_PROGRAM)
        .expect("an associated token address exists for every owner and mint")
        .0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdas_are_off_curve_with_the_highest_valid_bump() {
        let program = [7u8; 32];
        for id in 0..64u64 {
            let (k, bump) = market_pda(&program, id).unwrap();
            assert!(!on_curve(&k));
            // Every higher bump gives a curve point.
            for higher in u16::from(bump) + 1..=255 {
                let mut h = Sha256::new();
                h.update(b"market");
                h.update(id.to_le_bytes());
                h.update([u8::try_from(higher).unwrap()]);
                h.update(program);
                h.update(b"ProgramDerivedAddress");
                let candidate: Key = h.finalize().into();
                assert!(on_curve(&candidate), "id {id} bump {higher}");
            }
        }
    }

    #[test]
    fn no_pda_once_every_bump_is_tried() {
        let tried = std::cell::Cell::new(0);
        let none = first_bump(&[b"market"], &[7u8; 32], |_| {
            tried.set(tried.get() + 1);
            false
        });
        assert_eq!(none, Err(ClientError::NoPda));
        // Bumps 255 down to 1: bump 0 is never tried.
        assert_eq!(tried.get(), 255);
    }

    #[test]
    fn seed_limits() {
        let program = [1u8; 32];
        assert_eq!(
            find_pda(&[&[0u8; 33]], &program),
            Err(ClientError::InvalidArgument("seed longer than 32 bytes"))
        );
        let seeds: Vec<&[u8]> = vec![b"x"; 16];
        assert_eq!(
            find_pda(&seeds, &program),
            Err(ClientError::InvalidArgument("too many seeds"))
        );
        let seeds: Vec<&[u8]> = vec![b"x"; 15];
        assert!(find_pda(&seeds, &program).is_ok());
    }

    #[test]
    fn market_id_is_the_first_eight_digest_bytes() {
        let (program, creator, salt) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let h = hash_parts(domain::MARKET_ID, &[&program, &creator, &salt]);
        let id = derive_market_id(&program, &creator, &salt);
        assert_eq!(id.to_le_bytes(), h.0[..8]);
        assert_ne!(id, derive_market_id(&creator, &program, &salt));
        assert_ne!(id, derive_market_id(&program, &creator, &[4u8; 32]));
    }
}
