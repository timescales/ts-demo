//! JSON encodings of protocol values.
//!
//! Each type serializes to a string and refuses on input anything but the
//! one canonical form: decimal integers without sign or leading zeros (and
//! range checked after the pattern), lowercase hex of the exact length,
//! base58 of the exact byte length, and standard base64 with canonical
//! padding. A JSON number is never accepted where a string is expected.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use timescales_core::{ExecutorId, Hash32, OrderCommitment, TraderId};

/// Pattern of [`U64`]. The value is range checked after it matches.
pub const U64_PATTERN: &str = "^(0|[1-9][0-9]{0,19})$";
/// Pattern of [`I64`]. The value is range checked after it matches.
pub const I64_PATTERN: &str = "^(0|-?[1-9][0-9]{0,18})$";

const BASE58_ALPHABET: &str = "[1-9A-HJ-NP-Za-km-z]";

/// Why a string is not the canonical encoding of a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodingError {
    #[error("not a decimal u64 without sign or leading zeros")]
    NotDecimal,
    #[error("decimal value above u64::MAX")]
    U64Range,
    #[error("not a decimal i64 without leading zeros or '-0'")]
    NotSignedDecimal,
    #[error("decimal value outside the i64 range")]
    I64Range,
    #[error("not lowercase hex of whole bytes")]
    NotLowerHex,
    #[error("not base58")]
    NotBase58,
    #[error("not standard base64 with canonical padding")]
    NotBase64,
    #[error("expected {expected} bytes, found {found}")]
    Length { expected: usize, found: usize },
}

/// A protocol u64 as a decimal string `^(0|[1-9][0-9]{0,19})$`, range
/// checked after the regex.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U64(pub u64);

/// A signed 64-bit value as a decimal string with an optional leading `-`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct I64(pub i64);

/// 32 bytes as 64 lowercase hex characters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hex32(pub [u8; 32]);

/// 64 bytes as 128 lowercase hex characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hex64(pub [u8; 64]);

/// Bytes of any length as lowercase hex.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Hex(pub Vec<u8>);

/// A Solana account address in base58.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct B58(pub [u8; 32]);

/// A transaction signature in base58.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct B58Sig(pub [u8; 64]);

/// Canonical bytes in standard base64 with padding.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct B64(pub Vec<u8>);

fn parse_u64(s: &str) -> Result<u64, EncodingError> {
    let canonical = match s.as_bytes() {
        [b'0'] => true,
        [b'1'..=b'9', rest @ ..] => rest.len() <= 19 && rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    if !canonical {
        return Err(EncodingError::NotDecimal);
    }
    // Only twenty-digit values above u64::MAX get here and fail.
    s.parse().map_err(|_| EncodingError::U64Range)
}

fn parse_i64(s: &str) -> Result<i64, EncodingError> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    let canonical = match digits.as_bytes() {
        [b'0'] => digits.len() == s.len(),
        [b'1'..=b'9', rest @ ..] => rest.len() <= 18 && rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    if !canonical {
        return Err(EncodingError::NotSignedDecimal);
    }
    s.parse().map_err(|_| EncodingError::I64Range)
}

fn parse_hex(s: &str) -> Result<Vec<u8>, EncodingError> {
    let lower =
        s.len().is_multiple_of(2) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !lower {
        return Err(EncodingError::NotLowerHex);
    }
    hex::decode(s).map_err(|_| EncodingError::NotLowerHex)
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], EncodingError> {
    bytes.try_into().map_err(|_| EncodingError::Length {
        expected: N,
        found: bytes.len(),
    })
}

/// Base58 decoding is a bijection between strings and byte strings (each
/// leading `1` is one leading zero byte), so the exact length is the only
/// canonicality check needed.
fn parse_base58<const N: usize>(s: &str) -> Result<[u8; N], EncodingError> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|_| EncodingError::NotBase58)?;
    fixed(&bytes)
}

impl U64 {
    pub fn parse(s: &str) -> Result<Self, EncodingError> {
        parse_u64(s).map(Self)
    }
}

impl I64 {
    pub fn parse(s: &str) -> Result<Self, EncodingError> {
        parse_i64(s).map(Self)
    }
}

impl Hex32 {
    pub fn parse(s: &str) -> Result<Self, EncodingError> {
        fixed(&parse_hex(s)?).map(Self)
    }
}

impl Hex64 {
    pub fn parse(s: &str) -> Result<Self, EncodingError> {
        fixed(&parse_hex(s)?).map(Self)
    }
}

impl Hex {
    pub fn parse(s: &str) -> Result<Self, EncodingError> {
        parse_hex(s).map(Self)
    }
}

impl B58 {
    pub fn parse(s: &str) -> Result<Self, EncodingError> {
        parse_base58(s).map(Self)
    }
}

impl B58Sig {
    pub fn parse(s: &str) -> Result<Self, EncodingError> {
        parse_base58(s).map(Self)
    }
}

impl B64 {
    /// Standard alphabet, canonical padding and no non-zero trailing bits,
    /// so every byte string has exactly one accepted encoding.
    pub fn parse(s: &str) -> Result<Self, EncodingError> {
        STANDARD
            .decode(s)
            .map(Self)
            .map_err(|_| EncodingError::NotBase64)
    }
}

impl fmt::Display for U64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Display for I64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Display for Hex32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Display for Hex64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Display for B58 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}

impl fmt::Display for B58Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}

impl fmt::Display for B64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(&self.0))
    }
}

macro_rules! string_encoding {
    ($($ty:ident: $what:literal),* $(,)?) => {$(
        impl FromStr for $ty {
            type Err = EncodingError;

            fn from_str(s: &str) -> Result<Self, EncodingError> {
                Self::parse(s)
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = Cow::<'de, str>::deserialize(d)?;
                Self::parse(&s).map_err(|e| {
                    de::Error::custom(format_args!(concat!("invalid ", $what, " {:?}: {}"), s, e))
                })
            }
        }
    )*};
}

string_encoding!(
    U64: "U64",
    I64: "I64",
    Hex32: "Hex32",
    Hex64: "Hex64",
    Hex: "Hex",
    B58: "B58",
    B58Sig: "B58 signature",
    B64: "B64",
);

macro_rules! string_schema {
    ($($ty:ident => $schema:tt),* $(,)?) => {$(
        impl JsonSchema for $ty {
            fn schema_name() -> Cow<'static, str> {
                stringify!($ty).into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!($schema)
            }
        }
    )*};
}

string_schema!(
    U64 => {
        "description": "Protocol u64 (epochs, ticks, lots, atoms, slots, ids) as a decimal string; the value is at most 18446744073709551615.",
        "type": "string",
        "pattern": U64_PATTERN,
    },
    I64 => {
        "description": "Signed 64-bit value as a decimal string.",
        "type": "string",
        "pattern": I64_PATTERN,
    },
    Hex32 => {
        "description": "32 bytes as lowercase hex without 0x.",
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
    },
    Hex64 => {
        "description": "64 bytes as lowercase hex without 0x.",
        "type": "string",
        "pattern": "^[0-9a-f]{128}$",
    },
    Hex => {
        "description": "Bytes as lowercase hex without 0x.",
        "type": "string",
        "pattern": "^([0-9a-f]{2})*$",
    },
    B58 => {
        "description": "A Solana account (32 bytes) in base58.",
        "type": "string",
        "pattern": format!("^{BASE58_ALPHABET}{{32,44}}$"),
    },
    B58Sig => {
        "description": "A transaction signature (64 bytes) in base58.",
        "type": "string",
        "pattern": format!("^{BASE58_ALPHABET}{{64,88}}$"),
    },
    B64 => {
        "description": "Canonical binary encoding in RFC 4648 standard base64 with padding.",
        "type": "string",
        "contentEncoding": "base64",
        "pattern": "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    },
);

impl From<u64> for U64 {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<U64> for u64 {
    fn from(v: U64) -> Self {
        v.0
    }
}

impl From<i64> for I64 {
    fn from(v: i64) -> Self {
        Self(v)
    }
}

impl From<I64> for i64 {
    fn from(v: I64) -> Self {
        v.0
    }
}

impl From<[u8; 32]> for Hex32 {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<Hash32> for Hex32 {
    fn from(h: Hash32) -> Self {
        Self(h.0)
    }
}

impl From<OrderCommitment> for Hex32 {
    fn from(c: OrderCommitment) -> Self {
        Self(c.0)
    }
}

impl From<Hex32> for Hash32 {
    fn from(h: Hex32) -> Self {
        Self(h.0)
    }
}

impl From<[u8; 64]> for Hex64 {
    fn from(b: [u8; 64]) -> Self {
        Self(b)
    }
}

impl From<Vec<u8>> for Hex {
    fn from(b: Vec<u8>) -> Self {
        Self(b)
    }
}

impl From<[u8; 32]> for B58 {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<ExecutorId> for B58 {
    fn from(id: ExecutorId) -> Self {
        Self(id.0)
    }
}

impl From<TraderId> for B58 {
    fn from(id: TraderId) -> Self {
        Self(id.0)
    }
}

impl From<[u8; 64]> for B58Sig {
    fn from(b: [u8; 64]) -> Self {
        Self(b)
    }
}

impl From<Vec<u8>> for B64 {
    fn from(b: Vec<u8>) -> Self {
        Self(b)
    }
}

impl From<&[u8]> for B64 {
    fn from(b: &[u8]) -> Self {
        Self(b.to_vec())
    }
}
