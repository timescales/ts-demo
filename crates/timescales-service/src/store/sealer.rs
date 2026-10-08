//! At-rest sealing of secret columns.
//!
//! ```text
//! sealed = generation u32 || nonce12 || ChaCha20-Poly1305(key_g, nonce, plaintext, aad || generation u32)
//! ```
//!
//! The generation names the key. It is also authenticated, so a blob cannot
//! be moved to another generation.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::store::StoreError;
use crate::store::store::{durable_rename, io_error, with_suffix};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4 + NONCE_LEN;

/// HKDF info of the at-rest key ratchet: `KEK_{g+1} = HKDF(KEK_g, this)`.
const RATCHET_INFO: &[u8] = b"timescales/v1/kek-ratchet";

/// First line of a ratchet key file. One `<generation> <hex32>` line per
/// live generation follows, oldest first.
const KEY_FILE_HEADER: &str = "timescales/v1/kek-ratchet";
const MAX_KEY_FILE_LEN: u64 = 64 * 1024;

/// ChaCha20-Poly1305, random 96-bit nonce, AAD-bound. The output carries
/// the key generation.
pub trait SecretSealer: Send + Sync {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, StoreError>;
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError>;
}

/// The key generation a sealed value names, if it is long enough to be one.
pub(crate) fn sealed_generation(sealed: &[u8]) -> Option<u32> {
    if sealed.len() < HEADER_LEN + TAG_LEN {
        return None;
    }
    let generation: [u8; 4] = sealed.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(generation))
}

fn bound_aad(aad: &[u8], generation: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(aad.len() + 4);
    out.extend_from_slice(aad);
    out.extend_from_slice(&generation.to_le_bytes());
    out
}

fn seal_with(
    key: &[u8; 32],
    generation: u32,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &bound_aad(aad, generation),
            },
        )
        .map_err(|_| StoreError::Conflict("value too large to seal"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open_with(
    key: &[u8; 32],
    generation: u32,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let (header, ciphertext) = sealed
        .split_at_checked(HEADER_LEN)
        .ok_or(StoreError::Corrupt("sealed value is truncated"))?;
    let nonce = &header[4..];
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &bound_aad(aad, generation),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| StoreError::Corrupt("sealed value failed authentication"))
}

/// Single key (node KEK).
pub struct KekSealer {
    key: Zeroizing<[u8; 32]>,
}

impl KekSealer {
    /// Generation of every value a `KekSealer` seals.
    pub const GENERATION: u32 = 0;

    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key }
    }
}

impl core::fmt::Debug for KekSealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KekSealer(..)")
    }
}

impl SecretSealer for KekSealer {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        seal_with(&self.key, Self::GENERATION, aad, plaintext)
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        match sealed_generation(sealed) {
            Some(Self::GENERATION) => open_with(&self.key, Self::GENERATION, aad, sealed),
            Some(_) => Err(StoreError::Corrupt("sealed under another key")),
            None => Err(StoreError::Corrupt("sealed value is truncated")),
        }
    }
}

/// Generations g, g+1, ... with `KEK_{g+1} = HKDF(KEK_g, "timescales/v1/kek-ratchet")`.
/// `erase(g)` deletes a generation from the key file.
///
/// Values are sealed under the newest (current) generation. The key file
/// holds every generation that has not been erased. It is rewritten
/// atomically and fsynced on every change, and must not be accessible by
/// group or others. Once a generation is erased, nothing sealed under it
/// can be opened again, including from an older copy of the database.
pub struct RatchetSealer {
    path: PathBuf,
    keys: Mutex<BTreeMap<u32, Zeroizing<[u8; 32]>>>,
}

impl core::fmt::Debug for RatchetSealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let keys = self.keys.lock();
        f.debug_struct("RatchetSealer")
            .field("path", &self.path)
            .field("generations", &keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl RatchetSealer {
    /// Writes a new key file holding `key` as generation `generation`
    /// (mode 0600). Refuses to overwrite an existing file.
    pub fn create(
        key_file: &Path,
        generation: u32,
        key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, StoreError> {
        if key_file.exists() {
            return Err(StoreError::Conflict("at-rest key file already exists"));
        }
        let keys = BTreeMap::from([(generation, key)]);
        write_key_file(key_file, &keys)?;
        Ok(Self {
            path: key_file.to_path_buf(),
            keys: Mutex::new(keys),
        })
    }

    /// Loads the key file, which is rewritten atomically on every change.
    pub fn load(key_file: &Path) -> Result<Self, StoreError> {
        let text = read_key_file(key_file)?;
        let keys = parse_key_file(&text)?;
        Ok(Self {
            path: key_file.to_path_buf(),
            keys: Mutex::new(keys),
        })
    }

    pub fn current_generation(&self) -> u32 {
        self.keys.lock().keys().next_back().copied().unwrap_or(0)
    }

    /// Derives the next generation and makes it current.
    pub fn advance(&self) -> Result<u32, StoreError> {
        let mut keys = self.keys.lock();
        let (generation, key) = current(&keys)?;
        let next = generation
            .checked_add(1)
            .ok_or(StoreError::Conflict("key generations exhausted"))?;
        let mut derived = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, key.as_slice())
            .expand(RATCHET_INFO, derived.as_mut_slice())
            .map_err(|_| StoreError::Corrupt("key derivation failed"))?;
        let mut updated = keys.clone();
        updated.insert(next, derived);
        write_key_file(&self.path, &updated)?;
        *keys = updated;
        Ok(next)
    }

    /// Erases one generation. Erasing one that is already gone does nothing.
    /// The current generation cannot be erased.
    pub fn erase(&self, generation: u32) -> Result<(), StoreError> {
        let mut keys = self.keys.lock();
        if generation == current(&keys)?.0 {
            return Err(StoreError::Conflict(
                "the current key generation cannot be erased",
            ));
        }
        if !keys.contains_key(&generation) {
            return Ok(());
        }
        let mut updated = keys.clone();
        updated.remove(&generation);
        write_key_file(&self.path, &updated)?;
        *keys = updated;
        Ok(())
    }

    /// Erases every generation older than `generation` (never the current
    /// one), with one rewrite of the key file. Returns the erased ones.
    pub(crate) fn erase_below(&self, generation: u32) -> Result<Vec<u32>, StoreError> {
        let mut keys = self.keys.lock();
        let limit = generation.min(current(&keys)?.0);
        let erased: Vec<u32> = keys.range(..limit).map(|(g, _)| *g).collect();
        if erased.is_empty() {
            return Ok(erased);
        }
        let updated = keys.split_off(&limit);
        if let Err(e) = write_key_file(&self.path, &updated) {
            // Nothing changed on disk: keep the keys in memory too.
            let mut restored = std::mem::take(&mut *keys);
            restored.extend(updated);
            *keys = restored;
            return Err(e);
        }
        *keys = updated;
        Ok(erased)
    }

    pub(crate) fn has_generation(&self, generation: u32) -> bool {
        self.keys.lock().contains_key(&generation)
    }
}

impl SecretSealer for RatchetSealer {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        let keys = self.keys.lock();
        let (generation, key) = current(&keys)?;
        seal_with(key, generation, aad, plaintext)
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let generation =
            sealed_generation(sealed).ok_or(StoreError::Corrupt("sealed value is truncated"))?;
        let keys = self.keys.lock();
        let key = keys
            .get(&generation)
            .ok_or(StoreError::Corrupt("sealed under an erased key generation"))?;
        open_with(key, generation, aad, sealed)
    }
}

/// The newest generation. Every constructor leaves at least one, and erasing
/// never removes the newest.
fn current(keys: &BTreeMap<u32, Zeroizing<[u8; 32]>>) -> Result<(u32, &[u8; 32]), StoreError> {
    keys.iter()
        .next_back()
        .map(|(g, k)| (*g, &**k))
        .ok_or(StoreError::Corrupt("no at-rest key generation"))
}

fn read_key_file(path: &Path) -> Result<Zeroizing<String>, StoreError> {
    let mut file = File::open(path).map_err(|e| io_error("opening", path, &e))?;
    let meta = file.metadata().map_err(|e| io_error("reading", path, &e))?;
    if !meta.is_file() {
        return Err(StoreError::Conflict(
            "at-rest key file is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            tracing::error!(
                path = %path.display(),
                mode = format_args!("{:o}", meta.permissions().mode() & 0o777),
                "at-rest key file is accessible by group or others"
            );
            return Err(StoreError::Conflict(
                "at-rest key file is accessible by group or others",
            ));
        }
    }
    if meta.len() > MAX_KEY_FILE_LEN {
        return Err(StoreError::Corrupt("at-rest key file is too large"));
    }
    let len = usize::try_from(meta.len()).unwrap_or(0);
    let mut bytes = Zeroizing::new(Vec::with_capacity(len + 1));
    Read::by_ref(&mut file)
        .take(MAX_KEY_FILE_LEN + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("reading", path, &e))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| StoreError::Corrupt("at-rest key file is malformed"))?;
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    out.push_str(text);
    Ok(out)
}

fn parse_key_file(text: &str) -> Result<BTreeMap<u32, Zeroizing<[u8; 32]>>, StoreError> {
    const MALFORMED: StoreError = StoreError::Corrupt("at-rest key file is malformed");
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some(KEY_FILE_HEADER) {
        return Err(MALFORMED);
    }
    let mut keys = BTreeMap::new();
    let mut last: Option<u32> = None;
    for line in lines.map(str::trim).filter(|l| !l.is_empty()) {
        let (generation, hex) = line.split_once(' ').ok_or(MALFORMED)?;
        let generation: u32 = generation.parse().map_err(|_| MALFORMED)?;
        if last.is_some_and(|l| generation <= l) {
            return Err(MALFORMED);
        }
        let key = decode_key(hex.trim()).ok_or(MALFORMED)?;
        keys.insert(generation, key);
        last = Some(generation);
    }
    if keys.is_empty() {
        return Err(MALFORMED);
    }
    Ok(keys)
}

fn write_key_file(
    path: &Path,
    keys: &BTreeMap<u32, Zeroizing<[u8; 32]>>,
) -> Result<(), StoreError> {
    // Sized up front, so the buffer holding the keys never reallocates and
    // leaves no copy behind.
    let mut text = Zeroizing::new(String::with_capacity(
        KEY_FILE_HEADER.len() + 1 + keys.len() * (10 + 1 + 64 + 1),
    ));
    text.push_str(KEY_FILE_HEADER);
    text.push('\n');
    for (generation, key) in keys {
        text.push_str(&generation.to_string());
        text.push(' ');
        encode_key(key, &mut text);
        text.push('\n');
    }
    let tmp = with_suffix(path, ".tmp");
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error("removing", &tmp, &e)),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| io_error("creating", &tmp, &e))?;
    file.write_all(text.as_bytes())
        .map_err(|e| io_error("writing", &tmp, &e))?;
    drop(file);
    durable_rename(&tmp, path)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn encode_key(key: &[u8; 32], out: &mut String) {
    for b in key {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
}

fn decode_key(hex: &str) -> Option<Zeroizing<[u8; 32]>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    let (pairs, _) = bytes.as_chunks::<2>();
    for (out, [hi, lo]) in key.iter_mut().zip(pairs) {
        *out = nibble(*hi)? << 4 | nibble(*lo)?;
    }
    Some(key)
}
