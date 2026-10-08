//! Fixed-size identifiers and digests.

use core::fmt;

use crate::encoding::{Decode, DecodeError, Encode, Reader};

macro_rules! bytes32_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub const ZERO: Self = Self([0u8; 32]);

            #[inline]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn to_hex(&self) -> String {
                let mut s = String::with_capacity(64);
                for b in self.0 {
                    s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
                    s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
                }
                s
            }

            pub fn from_hex(s: &str) -> Option<Self> {
                let s = s.strip_prefix("0x").unwrap_or(s);
                if s.len() != 64 {
                    return None;
                }
                let mut out = [0u8; 32];
                for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
                    let hi = char::from(chunk[0]).to_digit(16)?;
                    let lo = char::from(chunk[1]).to_digit(16)?;
                    out[i] = u8::try_from(hi << 4 | lo).ok()?;
                }
                Some(Self(out))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let h = self.to_hex();
                write!(f, concat!(stringify!($name), "({}..)"), &h[..12])
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(b: [u8; 32]) -> Self {
                Self(b)
            }
        }

        impl Encode for $name {
            fn encode(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.0);
            }
        }

        impl Decode for $name {
            const MIN_ENCODED_LEN: usize = 32;

            fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                r.array().map(Self)
            }
        }
    };
}

bytes32_newtype!(
    /// Generic 32-byte digest.
    Hash32
);
bytes32_newtype!(
    /// A trader's long-term account key (Ed25519 public key bytes).
    TraderId
);
bytes32_newtype!(
    /// An executor's signing key (Ed25519 public key bytes).
    ExecutorId
);
bytes32_newtype!(
    /// Hiding, binding commitment to a private intent. Public once submitted.
    OrderCommitment
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = u8::try_from(i * 7).unwrap_or(0);
        }
        let h = Hash32(b);
        assert_eq!(Hash32::from_hex(&h.to_hex()), Some(h));
        assert_eq!(Hash32::from_hex("zz"), None);
    }
}
