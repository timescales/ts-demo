//! Client of the settlement program v2 (`programs/timescales-settlement`,
//! the design): builders for all 24 instructions, account decoders,
//! the error table and transaction size planning.
//!
//! No Solana SDK dependency: an instruction is a plain `(program, accounts,
//! data)` triple with 32-byte keys, which callers convert to whatever SDK
//! version they use. Byte layouts mirror the program's `instruction.rs` and
//! `state.rs`. `programs/timescales-settlement/tests/v13_conformance.rs` runs
//! every builder and decoder against the program in LiteSVM.
//!
//! Timescales trader identities are Ed25519 public keys, so a trader's
//! Timescales id is also its Solana address.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

mod accounts;
pub mod compute_budget;
pub mod errors;
mod governance;
mod instructions;
pub mod loader;
mod merkle;
mod pda;
pub mod spl;
pub mod system;
mod tx;

use thiserror::Error;
use timescales_core::Hash32;

pub use accounts::{
    BATCH_LEN, BATCH_TAG, BatchAccount, BatchStatus, LAYOUT_VERSION, MARKET_LEN, MARKET_TAG,
    MarketAccount, TRADER_LEN, TRADER_TAG, TraderAccount, available, decode_batch, decode_market,
    decode_trader,
};
pub use errors::TimescalesProgramError;
pub use governance::{GovernanceChange, PendingChange};
pub use instructions::{
    AbortReason, InitMarketArgs, Leaf, Side, abort_batch, accept_admin, apply_change, apply_deltas,
    apply_deltas_with, cancel_change, cancel_withdraw_request, claim_fees, close_batch,
    close_trader, commit_batch, cosign_receipt, deposit, ed25519_verify, finalize, init_market,
    leaves, open_trader, post_receipt, propose_change, reclaim_batch, remove_executor,
    request_withdraw, reveal_beacon, set_halted, verify_deltas, verify_deltas_with, withdraw,
};
pub use pda::{
    associated_token_address, batch_pda, derive_market_id, find_pda, market_pda, trader_pda,
};
pub use tx::{MAX_TX_SIZE, legacy_tx_size, plan_delta_chunks};

/// The pre-move path of this API. The v2 client was built in a `v2` module
/// next to the v1 client and now lives at the crate root. This keeps
/// `crate::program::v2::...` imports compiling until their crates move.
#[doc(hidden)]
pub mod v2 {
    pub use crate::program::*;
}

pub type Key = [u8; 32];

pub const SYSTEM_PROGRAM: Key = [0; 32];
pub const TOKEN_PROGRAM: Key = base58_key("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const ASSOCIATED_TOKEN_PROGRAM: Key =
    base58_key("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const COMPUTE_BUDGET_PROGRAM: Key = base58_key("ComputeBudget111111111111111111111111111111");
pub const ED25519_PROGRAM: Key = base58_key("Ed25519SigVerify111111111111111111111111111");
pub const BPF_LOADER_UPGRADEABLE: Key = base58_key("BPFLoaderUpgradeab1e11111111111111111111111");
pub const INSTRUCTIONS_SYSVAR: Key = base58_key("Sysvar1nstructions1111111111111111111111111");
pub const SLOT_HASHES_SYSVAR: Key = base58_key("SysvarS1otHashes111111111111111111111111111");

/// Executor slots of a market.
pub const MAX_EXECUTORS: usize = 8;
/// Settlement leaves one batch can have. Equals the program's `MAX_DELTAS`
/// and `timescales_core::MAX_SETTLEMENT_DELTAS`.
pub const MAX_DELTAS: usize = 1024;

/// `H_merkle-node("")`: the state root of a market before its first batch.
pub const EMPTY_STATE_ROOT: Hash32 = Hash32([
    0x70, 0xce, 0x57, 0x60, 0x30, 0x71, 0x45, 0x2b, 0x06, 0xad, 0xa7, 0x13, 0xd6, 0x0a, 0xf7, 0x3a,
    0xe1, 0x64, 0x13, 0x8e, 0x22, 0x90, 0xa7, 0x94, 0x27, 0x41, 0xa3, 0xf5, 0x19, 0x17, 0x44, 0x66,
]);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ClientError {
    #[error("no valid program address for these seeds")]
    NoPda,
    #[error("account data malformed")]
    Malformed,
    #[error("too many leaves for one instruction")]
    TooManyLeaves,
    #[error("too many executors")]
    TooManyExecutors,
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    pub key: Key,
    pub signer: bool,
    pub writable: bool,
}

impl Meta {
    pub fn w(key: Key, signer: bool) -> Self {
        Self {
            key,
            signer,
            writable: true,
        }
    }

    pub fn r(key: Key, signer: bool) -> Self {
        Self {
            key,
            signer,
            writable: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ix {
    pub program: Key,
    pub accounts: Vec<Meta>,
    pub data: Vec<u8>,
}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decodes a 32-byte base58 address. Only the canonical encoding is
/// accepted: one leading `1` per leading zero byte, nothing longer.
pub fn decode_base58(s: &str) -> Option<Key> {
    let mut bytes: Vec<u8> = Vec::with_capacity(32);
    for c in s.bytes() {
        let digit = BASE58_ALPHABET.iter().position(|a| *a == c)?;
        let mut carry = u32::try_from(digit).ok()?;
        for b in bytes.iter_mut().rev() {
            carry += u32::from(*b) * 58;
            *b = carry.to_le_bytes()[0];
            carry >>= 8;
        }
        while carry > 0 {
            if bytes.len() > 32 {
                return None;
            }
            bytes.insert(0, carry.to_le_bytes()[0]);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|c| *c == b'1').count();
    let mut out = vec![0u8; zeros];
    out.extend(bytes);
    out.try_into().ok()
}

/// [`decode_base58`] for the well-known addresses above, at compile time.
const fn base58_key(s: &str) -> Key {
    let s = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < s.len() {
        let mut digit: u32 = 0;
        while digit < 58 && BASE58_ALPHABET[digit as usize] != s[i] {
            digit += 1;
        }
        assert!(digit < 58, "not a base58 digit");
        let mut carry = digit;
        let mut j = out.len();
        while j > 0 {
            j -= 1;
            carry += out[j] as u32 * 58;
            out[j] = carry.to_le_bytes()[0];
            carry >>= 8;
        }
        assert!(carry == 0, "base58 value longer than 32 bytes");
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_time_addresses_decode_like_the_runtime_decoder() {
        for (s, k) in [
            ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", TOKEN_PROGRAM),
            (
                "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
                ASSOCIATED_TOKEN_PROGRAM,
            ),
            (
                "ComputeBudget111111111111111111111111111111",
                COMPUTE_BUDGET_PROGRAM,
            ),
            (
                "Ed25519SigVerify111111111111111111111111111",
                ED25519_PROGRAM,
            ),
            (
                "BPFLoaderUpgradeab1e11111111111111111111111",
                BPF_LOADER_UPGRADEABLE,
            ),
            (
                "Sysvar1nstructions1111111111111111111111111",
                INSTRUCTIONS_SYSVAR,
            ),
            (
                "SysvarS1otHashes111111111111111111111111111",
                SLOT_HASHES_SYSVAR,
            ),
            ("11111111111111111111111111111111", SYSTEM_PROGRAM),
        ] {
            assert_eq!(decode_base58(s), Some(k), "{s}");
        }
        // Bytes from an independent base58 decoder.
        let hex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        assert_eq!(
            TOKEN_PROGRAM.to_vec(),
            hex("06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9")
        );
        assert_eq!(
            ASSOCIATED_TOKEN_PROGRAM.to_vec(),
            hex("8c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f859")
        );
        assert_eq!(
            COMPUTE_BUDGET_PROGRAM.to_vec(),
            hex("0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000")
        );
    }

    #[test]
    fn base58_rejects_non_canonical_and_wrong_lengths() {
        assert_eq!(decode_base58(""), None);
        assert_eq!(decode_base58("1111111111111111111111111111111"), None);
        assert_eq!(decode_base58("111111111111111111111111111111111"), None);
        assert_eq!(decode_base58("0OIl"), None);
        assert_eq!(
            decode_base58("1TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            None
        );
        assert_eq!(decode_base58(&"z".repeat(60)), None);
    }

    #[test]
    fn empty_state_root_is_the_empty_merkle_root() {
        assert_eq!(EMPTY_STATE_ROOT, timescales_core::merkle::empty_root());
    }

    #[test]
    fn delta_bound_matches_the_protocol_constant() {
        assert_eq!(MAX_DELTAS, timescales_core::MAX_SETTLEMENT_DELTAS as usize);
    }

    /// Every `ClientError` variant comes out of some input. The match
    /// is exhaustive, so a new variant does not compile until it is listed
    /// here with an input that produces it.
    #[test]
    fn every_client_error_variant_is_produced() {
        let program = [7u8; 32];
        let leaf = Leaf {
            index: 0,
            delta: timescales_auction::settlement::AccountDelta {
                trader: timescales_core::TraderId([1; 32]),
                base: 0,
                quote: 0,
            },
            path: vec![],
        };
        let nine_executors = GovernanceChange::SetExecutors {
            keys: vec![[1; 32]; 9],
            quorum: 1,
        };
        let produced = [
            pda::first_bump(&[b"x"], &program, |_| false).unwrap_err(),
            decode_trader(&[]).unwrap_err(),
            verify_deltas(&program, &[2; 32], &[3; 32], 1, &vec![leaf; 256]).unwrap_err(),
            nine_executors.payload().unwrap_err(),
            find_pda(&[&[0u8; 33]], &program).unwrap_err(),
        ];
        let mut seen = [false; 5];
        for e in &produced {
            let i = match e {
                ClientError::NoPda => 0,
                ClientError::Malformed => 1,
                ClientError::TooManyLeaves => 2,
                ClientError::TooManyExecutors => 3,
                ClientError::InvalidArgument(_) => 4,
            };
            seen[i] = true;
        }
        assert_eq!(seen, [true; 5], "{produced:?}");
    }
}
