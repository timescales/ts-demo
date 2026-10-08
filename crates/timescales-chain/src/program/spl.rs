//! Classic SPL Token and associated-token-account helpers: the instructions
//! a local bootstrap needs to create mints, vaults and funded trader
//! accounts, and the mint decoder clients use to show mint and freeze
//! authorities. Token-2022 is out of scope.

use crate::program::pda::associated_token_address;
use crate::program::{
    ASSOCIATED_TOKEN_PROGRAM, ClientError, Ix, Key, Meta, SYSTEM_PROGRAM, TOKEN_PROGRAM,
};

/// Size of a classic mint account.
pub const MINT_LEN: usize = 82;
/// Size of a classic token account.
pub const TOKEN_ACCOUNT_LEN: usize = 165;

/// Associated token program `CreateIdempotent`: creates the associated
/// token account of `owner` for `mint` unless it already exists. `owner`
/// may be a PDA, so this also creates vaults owned by a market.
pub fn create_ata_idempotent(payer: &Key, owner: &Key, mint: &Key) -> Ix {
    Ix {
        program: ASSOCIATED_TOKEN_PROGRAM,
        accounts: vec![
            Meta::w(*payer, true),
            Meta::w(associated_token_address(owner, mint), false),
            Meta::r(*owner, false),
            Meta::r(*mint, false),
            Meta::r(SYSTEM_PROGRAM, false),
            Meta::r(TOKEN_PROGRAM, false),
        ],
        data: vec![1],
    }
}

fn token_ix(accounts: Vec<Meta>, data: Vec<u8>) -> Ix {
    Ix {
        program: TOKEN_PROGRAM,
        accounts,
        data,
    }
}

/// `InitializeMint2`: `20 || decimals || mint_authority32 || COption<freeze>`
/// on an allocated, Token-owned 82-byte account.
pub fn initialize_mint2(
    mint: &Key,
    mint_authority: &Key,
    freeze_authority: Option<&Key>,
    decimals: u8,
) -> Ix {
    let mut data = vec![20, decimals];
    data.extend_from_slice(mint_authority);
    match freeze_authority {
        Some(k) => {
            data.push(1);
            data.extend_from_slice(k);
        }
        None => data.push(0),
    }
    token_ix(vec![Meta::w(*mint, false)], data)
}

/// `InitializeAccount3`: `18 || owner32` on an allocated, Token-owned
/// 165-byte account.
pub fn initialize_account3(account: &Key, mint: &Key, owner: &Key) -> Ix {
    let mut data = vec![18];
    data.extend_from_slice(owner);
    token_ix(vec![Meta::w(*account, false), Meta::r(*mint, false)], data)
}

/// `MintTo`: `7 || amount u64`, signed by the mint authority.
pub fn mint_to(mint: &Key, dest: &Key, authority: &Key, amount: u64) -> Ix {
    let mut data = vec![7];
    data.extend_from_slice(&amount.to_le_bytes());
    token_ix(
        vec![
            Meta::w(*mint, false),
            Meta::w(*dest, false),
            Meta::r(*authority, true),
        ],
        data,
    )
}

/// The fields of an initialized classic mint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mint {
    pub mint_authority: Option<Key>,
    pub supply: u64,
    pub decimals: u8,
    /// Whoever holds it can freeze any token account of this mint,
    /// including a market's vault.
    pub freeze_authority: Option<Key>,
}

/// Decodes an initialized classic mint as the Token program unpacks it:
/// exactly 82 bytes, `COption` tags 0 or 1, the initialized flag set.
pub fn decode_mint(d: &[u8]) -> Result<Mint, ClientError> {
    let d: &[u8; MINT_LEN] = d.try_into().map_err(|_| ClientError::Malformed)?;
    let (authority, rest) = d.split_at(36);
    let (supply, rest) = rest.split_at(8);
    let (flags, freeze) = rest.split_at(2);
    if flags[1] != 1 {
        return Err(ClientError::Malformed);
    }
    Ok(Mint {
        mint_authority: coption_key(authority)?,
        supply: u64::from_le_bytes(supply.try_into().map_err(|_| ClientError::Malformed)?),
        decimals: flags[0],
        freeze_authority: coption_key(freeze)?,
    })
}

/// `COption<Pubkey>`: a u32 tag (0 none, 1 some) and 32 key bytes, which
/// are ignored when the tag is 0.
fn coption_key(b: &[u8]) -> Result<Option<Key>, ClientError> {
    let (tag, key) = b.split_at_checked(4).ok_or(ClientError::Malformed)?;
    match tag {
        [0, 0, 0, 0] => Ok(None),
        [1, 0, 0, 0] => Ok(Some(key.try_into().map_err(|_| ClientError::Malformed)?)),
        _ => Err(ClientError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Token program's layout. The key bytes of a `None` are left
    /// non-zero, as after an authority is removed.
    fn mint_bytes(
        authority: Option<Key>,
        supply: u64,
        decimals: u8,
        freeze: Option<Key>,
    ) -> Vec<u8> {
        let mut d = Vec::with_capacity(MINT_LEN);
        d.extend_from_slice(&u32::from(authority.is_some()).to_le_bytes());
        d.extend_from_slice(&authority.unwrap_or([0xee; 32]));
        d.extend_from_slice(&supply.to_le_bytes());
        d.push(decimals);
        d.push(1);
        d.extend_from_slice(&u32::from(freeze.is_some()).to_le_bytes());
        d.extend_from_slice(&freeze.unwrap_or([0xdd; 32]));
        d
    }

    #[test]
    fn mints_decode_with_and_without_authorities() {
        let m = decode_mint(&mint_bytes(Some([1; 32]), 77, 6, Some([2; 32]))).unwrap();
        assert_eq!(
            m,
            Mint {
                mint_authority: Some([1; 32]),
                supply: 77,
                decimals: 6,
                freeze_authority: Some([2; 32]),
            }
        );
        let m = decode_mint(&mint_bytes(None, 0, 9, None)).unwrap();
        assert_eq!((m.mint_authority, m.freeze_authority), (None, None));
    }

    #[test]
    fn malformed_mints_are_refused() {
        let good = mint_bytes(None, 1, 0, Some([2; 32]));
        assert!(decode_mint(&good[..81]).is_err());
        let mut long = good.clone();
        long.push(0);
        assert!(decode_mint(&long).is_err());
        let mut uninitialized = good.clone();
        uninitialized[45] = 0;
        assert!(decode_mint(&uninitialized).is_err());
        let mut bad_tag = good.clone();
        bad_tag[46] = 2;
        assert!(decode_mint(&bad_tag).is_err());
        let mut bad_high_tag = good;
        bad_high_tag[3] = 1;
        assert!(decode_mint(&bad_high_tag).is_err());
    }
}
