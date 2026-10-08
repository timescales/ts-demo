//! Raw key material only. Solana types live in `timescales-chain`.
//!
//! Every loader refuses a file that group or others can access (any of
//! the mode bits `0o077`), that is not a regular file, or that is larger
//! than its format allows. Secrets are read into zeroizing buffers and no
//! loader logs or formats key bytes.
//!
//! Formats: Solana keypairs are the CLI's JSON array of 64 integers
//! (secret seed then public key). Every other key is 64 hex digits,
//! optionally surrounded by whitespace.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use thiserror::Error;
use timescales_core::crypto::{Keypair, SealSecret};
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is accessible by group or others (mode {mode:o})")]
    Permissions { path: PathBuf, mode: u32 },
    #[error("{path}: {reason}")]
    Format { path: PathBuf, reason: &'static str },
}

/// A 32-byte key-encryption key.
pub struct Kek(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for Kek {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Kek(..)")
    }
}

impl Kek {
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Longest file any loader reads: a Solana keypair with generous spacing.
const MAX_KEY_FILE: u64 = 4096;

/// 64-byte JSON array. Refuses group/world-readable files.
///
/// The second half must be the public key of the first, so a truncated or
/// mixed-up file is refused instead of yielding a different key.
pub fn solana_keypair_bytes(path: &Path) -> Result<Zeroizing<[u8; 64]>, KeyError> {
    let text = read_private(path)?;
    let bytes = parse_json_bytes(&text)
        .ok_or_else(|| bad_format(path, "expected a JSON array of 64 bytes"))?;
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes[..32]);
    if Keypair::from_seed(*seed).public() != bytes[32..] {
        return Err(bad_format(
            path,
            "the public half does not match the secret half",
        ));
    }
    Ok(bytes)
}

/// 32-byte hex seed.
pub fn ed25519_seed(path: &Path) -> Result<Keypair, KeyError> {
    let seed = hex32(path)?;
    Ok(Keypair::from_seed(*seed))
}

pub fn x25519_secret(path: &Path) -> Result<SealSecret, KeyError> {
    let secret = hex32(path)?;
    Ok(SealSecret::from_bytes(*secret))
}

/// 32 bytes.
pub fn kek(path: &Path) -> Result<Kek, KeyError> {
    hex32(path).map(Kek::from_bytes)
}

fn bad_format(path: &Path, reason: &'static str) -> KeyError {
    KeyError::Format {
        path: path.to_path_buf(),
        reason,
    }
}

/// 64 hex digits, optionally surrounded by whitespace.
fn hex32(path: &Path) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let text = read_private(path)?;
    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(text.trim_ascii(), key.as_mut_slice())
        .map_err(|_| bad_format(path, "expected 64 hex digits"))?;
    Ok(key)
}

/// Reads a secret file after checking that it is a regular file only its
/// owner can access. The checks use the opened file, not the path, so the
/// file cannot be swapped between the check and the read.
pub(crate) fn read_private(path: &Path) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let io = |source| KeyError::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = File::open(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() {
        return Err(bad_format(path, "not a regular file"));
    }
    check_private_mode(path, &meta)?;
    if meta.len() > MAX_KEY_FILE {
        return Err(bad_format(path, "file too large for a key"));
    }
    // Sized up front so the buffer never reallocates and leaves no copy.
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(MAX_KEY_FILE + 1).unwrap_or(4097),
    ));
    file.take(MAX_KEY_FILE)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    Ok(bytes)
}

#[cfg(unix)]
fn check_private_mode(path: &Path, meta: &std::fs::Metadata) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyError::Permissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_mode(_path: &Path, _meta: &std::fs::Metadata) -> Result<(), KeyError> {
    Ok(())
}

/// `[n0, n1,..., n63]` with optional whitespace, each `n` a decimal
/// `0..=255`, written straight into a zeroizing buffer.
fn parse_json_bytes(text: &[u8]) -> Option<Zeroizing<[u8; 64]>> {
    let mut out = Zeroizing::new([0u8; 64]);
    let mut rest = text.trim_ascii().strip_prefix(b"[")?.strip_suffix(b"]")?;
    for (i, slot) in out.iter_mut().enumerate() {
        if i > 0 {
            rest = rest.trim_ascii_start().strip_prefix(b",")?;
        }
        rest = rest.trim_ascii_start();
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 || digits > 3 {
            return None;
        }
        let mut value = 0u16;
        for d in &rest[..digits] {
            value = value * 10 + u16::from(d - b'0');
        }
        *slot = u8::try_from(value).ok()?;
        rest = &rest[digits..];
    }
    rest.trim_ascii().is_empty().then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_arrays_of_exactly_64_bytes() {
        let ok: String = format!(
            "[{}]",
            (0..64)
                .map(|i| (i * 4).to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let parsed = parse_json_bytes(ok.as_bytes()).unwrap();
        assert_eq!(parsed[63], 252);
        let spaced = format!(
            " [ {} ]\n",
            (0..64).map(|_| "7").collect::<Vec<_>>().join(" ,\n ")
        );
        assert_eq!(*parse_json_bytes(spaced.as_bytes()).unwrap(), [7u8; 64]);

        for bad in [
            "[]".to_owned(),
            format!("[{}]", vec!["1"; 63].join(",")),
            format!("[{}]", vec!["1"; 65].join(",")),
            format!("[{},256]", vec!["1"; 63].join(",")),
            format!("[{},-1]", vec!["1"; 63].join(",")),
            format!("[{},1.0]", vec!["1"; 63].join(",")),
            format!("[{},0001]", vec!["1"; 63].join(",")),
            format!("[{},]", vec!["1"; 64].join(",")),
            vec!["1"; 64].join(","),
            format!("[{}] x", vec!["1"; 64].join(",")),
        ] {
            assert!(parse_json_bytes(bad.as_bytes()).is_none(), "{bad}");
        }
    }
}
