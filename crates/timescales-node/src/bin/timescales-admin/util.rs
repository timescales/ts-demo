//! Parsing and printing of keys, digests and amounts on the command line.

use anyhow::{Context, Result, bail};
use timescales_core::Hash32;

pub(crate) type Key = [u8; 32];

pub(crate) fn b58(key: &Key) -> String {
    bs58::encode(key).into_string()
}

pub(crate) fn b58_sig(sig: &[u8; 64]) -> String {
    bs58::encode(sig).into_string()
}

/// A 32-byte key given as base58 (Solana style) or as 64 hex digits.
pub(crate) fn parse_key(s: &str) -> Result<Key> {
    let s = s.trim();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return parse_hex32(s);
    }
    timescales_chain::program::decode_base58(s)
        .with_context(|| format!("`{s}` is not a base58 key"))
}

pub(crate) fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut out)
        .with_context(|| format!("`{s}` is not 64 hex digits"))?;
    Ok(out)
}

pub(crate) fn parse_hash(s: &str) -> Result<Hash32> {
    parse_hex32(s).map(Hash32)
}

/// A 64-byte signature as base58 or 128 hex digits.
pub(crate) fn parse_sig(s: &str) -> Result<[u8; 64]> {
    let s = s.trim();
    let bytes = if s.len() == 128 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(s)?
    } else {
        bs58::decode(s)
            .into_vec()
            .with_context(|| format!("`{s}` is not a base58 signature"))?
    };
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("a signature is 64 bytes"))
}

/// Unix milliseconds now.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Prints a JSON value on stdout, pretty.
pub(crate) fn print_json(v: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

pub(crate) fn nonzero(key: &Key, what: &str) -> Result<()> {
    if *key == [0; 32] {
        bail!("{what} must not be zero");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn keys_parse_from_base58_and_hex() {
        let key = [7u8; 32];
        assert_eq!(parse_key(&b58(&key)).unwrap(), key);
        assert_eq!(parse_key(&hex::encode(key)).unwrap(), key);
        assert!(parse_key("not a key").is_err());
        assert!(parse_key(&hex::encode([1u8; 31])).is_err());
    }

    #[test]
    fn signatures_parse_from_base58_and_hex() {
        let sig = [9u8; 64];
        assert_eq!(parse_sig(&b58_sig(&sig)).unwrap(), sig);
        assert_eq!(parse_sig(&hex::encode(sig)).unwrap(), sig);
        assert!(parse_sig(&b58(&[1; 32])).is_err());
    }
}
