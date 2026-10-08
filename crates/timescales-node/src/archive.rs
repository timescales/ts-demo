//! Immutable public artifacts per terminal epoch, under
//! `data_dir/archive/<market>/<epoch>.bin`.
//!
//! The archive outlives the store's retention: `recover-state` replays the
//! fills and cancels of archived epochs to rebuild the carried order state,
//! and the fetch path reads it before asking enclaves. Only data that
//! is public once the quorum is on chain is written here.
//!
//! ```text
//! record = ver u8 (1) || epoch u64 || status u8 (1 settled, 2 aborted) || terminal_slot u64
//!          || u8 has_header || [header 283] || bytes receipt || bytes artifacts
//!          || u8 has_attestation || [bytes attestation] || seq<(executor32 || sig64)>
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;
use timescales_core::encoding::{put_bool, put_bytes, put_u8, put_u32};
use timescales_core::{Decode, DecodeError, Encode, Reader};

use crate::Address;

const VERSION: u8 = 1;
/// Largest record read back (receipt, artifacts and attestation together).
const MAX_RECORD: u64 = 16 * 1024 * 1024;
const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("archive I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("archive record of epoch {0} does not decode: {1}")]
    Decode(u64, DecodeError),
    #[error("a different record is archived for epoch {0}")]
    Conflict(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    Settled,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub epoch: u64,
    pub terminal: Terminal,
    pub terminal_slot: u64,
    pub header: Option<Vec<u8>>,
    /// `ExecutionReceipt` bytes.
    pub receipt: Vec<u8>,
    /// `ExecutionArtifacts` bytes.
    pub artifacts: Vec<u8>,
    pub attestation: Option<Vec<u8>>,
    pub cosigs: Vec<(Address, [u8; 64])>,
}

impl Encode for Record {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, VERSION);
        self.epoch.encode(out);
        put_u8(
            out,
            match self.terminal {
                Terminal::Settled => 1,
                Terminal::Aborted => 2,
            },
        );
        self.terminal_slot.encode(out);
        put_bool(out, self.header.is_some());
        if let Some(h) = &self.header {
            out.extend_from_slice(h);
        }
        put_bytes(out, &self.receipt);
        put_bytes(out, &self.artifacts);
        put_bool(out, self.attestation.is_some());
        if let Some(a) = &self.attestation {
            put_bytes(out, a);
        }
        put_u32(out, u32::try_from(self.cosigs.len()).unwrap_or(u32::MAX));
        for (executor, sig) in &self.cosigs {
            out.extend_from_slice(executor);
            out.extend_from_slice(sig);
        }
    }
}

impl Decode for Record {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let version = r.u8()?;
        if version != VERSION {
            return Err(DecodeError::InvalidValue("archive record version"));
        }
        let epoch = r.u64()?;
        let terminal = match r.u8()? {
            1 => Terminal::Settled,
            2 => Terminal::Aborted,
            tag => {
                return Err(DecodeError::InvalidTag {
                    ty: "archive terminal status",
                    tag,
                });
            }
        };
        let terminal_slot = r.u64()?;
        let header = if r.bool()? {
            Some(r.array::<283>()?.to_vec())
        } else {
            None
        };
        let receipt = r.bytes(MAX_BYTES)?;
        let artifacts = r.bytes(MAX_BYTES)?;
        let attestation = if r.bool()? {
            Some(r.bytes(MAX_BYTES)?)
        } else {
            None
        };
        let n = r.u32()?;
        if n > 8 {
            return Err(DecodeError::LengthExceeded {
                len: usize::try_from(n).unwrap_or(usize::MAX),
                max: 8,
            });
        }
        let mut cosigs = Vec::new();
        for _ in 0..n {
            cosigs.push((r.array::<32>()?, r.array::<64>()?));
        }
        Ok(Record {
            epoch,
            terminal,
            terminal_slot,
            header,
            receipt,
            artifacts,
            attestation,
            cosigs,
        })
    }
}

/// The archive of one node: `root/<market b58>/<epoch>.bin`.
#[derive(Clone, Debug)]
pub struct Archive {
    root: PathBuf,
}

impl Archive {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("archive"),
        }
    }

    fn path(&self, market: &Address, epoch: u64) -> PathBuf {
        self.root
            .join(bs58::encode(market).into_string())
            .join(format!("{epoch:020}.bin"))
    }

    /// Writes `record` once. The same record again is a no-op. A
    /// different one for the epoch is refused, because archived data is
    /// immutable.
    pub fn write(&self, market: &Address, record: &Record) -> Result<(), ArchiveError> {
        let path = self.path(market, record.epoch);
        let bytes = record.to_bytes();
        if let Some(existing) = self.read_bytes(&path)? {
            return if existing == bytes {
                Ok(())
            } else {
                Err(ArchiveError::Conflict(record.epoch))
            };
        }
        let io = |source| ArchiveError::Io {
            path: path.clone(),
            source,
        };
        let dir = path.parent().unwrap_or(&self.root);
        std::fs::create_dir_all(dir).map_err(io)?;
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp).map_err(io)?;
        f.write_all(&bytes).map_err(io)?;
        f.sync_all().map_err(io)?;
        std::fs::rename(&tmp, &path).map_err(io)?;
        // The rename is durable only once the directory is.
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    pub fn read(&self, market: &Address, epoch: u64) -> Result<Option<Record>, ArchiveError> {
        let path = self.path(market, epoch);
        match self.read_bytes(&path)? {
            Some(bytes) => Record::decode_exact(&bytes)
                .map(Some)
                .map_err(|e| ArchiveError::Decode(epoch, e)),
            None => Ok(None),
        }
    }

    /// Archived epochs of `market` in `from..=to`, ascending.
    pub fn records(
        &self,
        market: &Address,
        from: u64,
        to: u64,
    ) -> Result<Vec<Record>, ArchiveError> {
        let mut out = Vec::new();
        for epoch in from..=to {
            if let Some(r) = self.read(market, epoch)? {
                out.push(r);
            }
        }
        Ok(out)
    }

    fn read_bytes(&self, path: &Path) -> Result<Option<Vec<u8>>, ArchiveError> {
        use std::io::Read;
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ArchiveError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let mut bytes = Vec::new();
        file.take(MAX_RECORD)
            .read_to_end(&mut bytes)
            .map_err(|source| ArchiveError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(epoch: u64) -> Record {
        Record {
            epoch,
            terminal: Terminal::Settled,
            terminal_slot: 99,
            header: Some(vec![2; 283]),
            receipt: vec![1, 2, 3],
            artifacts: vec![4, 5],
            attestation: None,
            cosigs: vec![([7; 32], [8; 64])],
        }
    }

    #[test]
    fn records_are_written_once_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let a = Archive::new(dir.path());
        let m = [3u8; 32];
        assert!(a.read(&m, 4).unwrap().is_none());
        a.write(&m, &record(4)).unwrap();
        a.write(&m, &record(4)).unwrap();
        assert_eq!(a.read(&m, 4).unwrap(), Some(record(4)));
        let mut other = record(4);
        other.receipt = vec![9];
        assert!(matches!(
            a.write(&m, &other),
            Err(ArchiveError::Conflict(4))
        ));
        a.write(&m, &record(6)).unwrap();
        let all = a.records(&m, 1, 10).unwrap();
        assert_eq!(all.iter().map(|r| r.epoch).collect::<Vec<_>>(), vec![4, 6]);
    }
}
