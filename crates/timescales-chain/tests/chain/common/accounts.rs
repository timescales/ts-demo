//! The program-owned accounts preloaded into the validator the RPC fixtures
//! were recorded from, rebuilt here so tests can compare them byte for byte.

use serde_json::{Value, json};
use solana_keypair::Keypair;
use solana_signer::Signer;
use timescales_chain::program::{TRADER_LEN, TRADER_TAG, market_pda, trader_pda};

/// The dev program id.
pub const PROGRAM: &str = "FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL";

pub fn program() -> [u8; 32] {
    timescales_chain::program::decode_base58(PROGRAM).unwrap()
}

pub fn market() -> [u8; 32] {
    market_pda(&program(), 42).unwrap().0
}

pub fn other_market() -> [u8; 32] {
    market_pda(&program(), 43).unwrap().0
}

pub fn owner(seed: u8) -> [u8; 32] {
    Keypair::new_from_array([seed; 32]).pubkey().to_bytes()
}

/// A preloaded Trader account.
#[derive(Clone, Debug)]
pub struct Fixture {
    pub address: [u8; 32],
    pub owner: [u8; 32],
    pub market: [u8; 32],
    pub data: Vec<u8>,
    pub lamports: u64,
}

/// Trader bytes: tag, bump, layout version 2, reserved, market,
/// owner, then the ten u64 fields from `base` to `floor_quote`.
pub fn trader_bytes(market: &[u8; 32], owner: &[u8; 32], bump: u8, fields: [u64; 10]) -> Vec<u8> {
    let mut d = vec![TRADER_TAG, bump, 2, 0];
    d.extend_from_slice(market);
    d.extend_from_slice(owner);
    for f in fields {
        d.extend_from_slice(&f.to_le_bytes());
    }
    assert_eq!(d.len(), TRADER_LEN);
    d
}

/// Two traders of [`market`] and one of [`other_market`].
pub fn traders() -> Vec<Fixture> {
    [
        (market(), 0xa1, [1_000, 50_000, 0, 0, 0, 0, 120, 0, 0, 0]),
        (market(), 0xb2, [7, 9, 3, 4, 5, 2, 130, 5, 4, 5]),
        (other_market(), 0xc3, [1, 1, 0, 0, 0, 0, 1, 0, 0, 0]),
    ]
    .into_iter()
    .map(|(market, seed, fields)| {
        let owner = owner(seed);
        let (address, bump) = trader_pda(&program(), &market, &owner).unwrap();
        Fixture {
            address,
            owner,
            market,
            data: trader_bytes(&market, &owner, bump, fields),
            lamports: 1_920_960,
        }
    })
    .collect()
}

pub fn b58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

/// The `--account <address> <file>` JSON of `solana-test-validator`.
pub fn account_file(f: &Fixture) -> Value {
    use base64::Engine;
    json!({
        "pubkey": b58(&f.address),
        "account": {
            "lamports": f.lamports,
            "data": [base64::engine::general_purpose::STANDARD.encode(&f.data), "base64"],
            "owner": PROGRAM,
            "executable": false,
            "rentEpoch": 0,
            "space": f.data.len(),
        }
    })
}
