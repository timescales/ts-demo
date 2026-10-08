//! Quotes from an Intel TDX guest through the kernel's configfs-tsm report
//! interface (feature `tdx-tsm`).
//!
//! **Untested on hardware.** The I/O sequence below is tested against a
//! fake configfs tree only. Quotes are never trusted because of where they
//! came from: members verify every quote with dcap-qvl, and
//! `timescales-admin` does before an executor is registered.
//!
//! ```text
//! mkdir  <root>/timescales-<random>    the kernel creates the attributes
//! read   provider                      must be "tdx_guest"
//! read   generation                   g
//! write  inblob                        64 bytes of report data
//! read   outblob, generation           g + 1: our write was the only one,
//!                                      so the quote is over our report
//!                                      data, otherwise write again
//! rmdir  <root>/timescales-<random>
//! ```
//!
//! The kernel bumps `generation` on every write, which is how its ABI
//! (`Documentation/ABI/testing/configfs-tsm`) has readers detect a
//! concurrent writer to the same entry.
//!
//! The measurement and the debug flag of [`Quoter::quote`] are not inputs
//! here: the TDX module reports the TD's own MRTD, RTMRs and attributes.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::attestation::{Evidence, Measurement, Platform};
use rand::RngCore;
use thiserror::Error;

use crate::tee::enclave::{QuoteError, Quoter};

/// Trust label of quotes produced here (K, `/v1/info.trust.quote_generation`).
pub const QUOTE_GENERATION_LABEL: &str = "configfs_tsm_untested_on_hardware";

/// Where the kernel mounts the report interface.
pub const DEFAULT_ROOT: &str = "/sys/kernel/config/tsm/report";

/// Why a quote could not be read.
#[derive(Debug, Error)]
pub enum TsmError {
    #[error("{op} {}: {source}", path.display())]
    Io {
        op: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("report provider is {0:?}, not tdx_guest")]
    Provider(String),
    #[error("generation attribute is not a number")]
    Generation,
    #[error("the report entry changed under every one of {0} attempts")]
    Contended(u32),
    #[error("the provider returned an empty quote")]
    EmptyQuote,
}

/// The filesystem operations a quote needs. Configfs in production.
pub(crate) trait ConfigFs: Send + Sync {
    fn create_dir(&self, path: &Path) -> io::Result<()>;
    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()>;
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn remove_dir(&self, path: &Path) -> io::Result<()>;
}

struct StdFs;

impl ConfigFs for StdFs {
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir(path)
    }

    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        std::fs::write(path, data)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_dir(path)
    }
}

/// A [`Quoter`] over configfs-tsm.
pub struct TsmQuoter {
    root: PathBuf,
    fs: Arc<dyn ConfigFs>,
    attempts: u32,
}

impl core::fmt::Debug for TsmQuoter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TsmQuoter")
            .field("root", &self.root)
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

impl TsmQuoter {
    /// Quotes through the report interface mounted at `root` (normally
    /// [`DEFAULT_ROOT`]).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_fs(root, Arc::new(StdFs))
    }

    pub(crate) fn with_fs(root: impl Into<PathBuf>, fs: Arc<dyn ConfigFs>) -> Self {
        Self {
            root: root.into(),
            fs,
            attempts: 3,
        }
    }

    /// A TD quote over `report_data`. The report entry is removed again
    /// whatever happens. If that fails the entry is left behind and the
    /// quote, if one was read, is still returned.
    pub fn quote_report(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, TsmError> {
        let entry = self.root.join(entry_name());
        self.fs.create_dir(&entry).map_err(|source| TsmError::Io {
            op: "mkdir",
            path: entry.clone(),
            source,
        })?;
        let quote = self.read_quote(&entry, report_data);
        let _ = self.fs.remove_dir(&entry);
        quote
    }

    fn read_quote(&self, entry: &Path, report_data: &[u8; 64]) -> Result<Vec<u8>, TsmError> {
        let provider = self.read_text(&entry.join("provider"))?;
        if provider != "tdx_guest" {
            return Err(TsmError::Provider(provider));
        }
        let inblob = entry.join("inblob");
        let outblob = entry.join("outblob");
        for _ in 0..self.attempts {
            let before = self.generation(entry)?;
            self.fs
                .write(&inblob, report_data)
                .map_err(|source| TsmError::Io {
                    op: "write",
                    path: inblob.clone(),
                    source,
                })?;
            let quote = self.fs.read(&outblob).map_err(|source| TsmError::Io {
                op: "read",
                path: outblob.clone(),
                source,
            })?;
            // Any count other than our one write means another writer got in
            // somewhere between the two reads, and the quote may be over its
            // report data.
            if before.checked_add(1) != Some(self.generation(entry)?) {
                continue;
            }
            if quote.is_empty() {
                return Err(TsmError::EmptyQuote);
            }
            return Ok(quote);
        }
        Err(TsmError::Contended(self.attempts))
    }

    fn read_text(&self, path: &Path) -> Result<String, TsmError> {
        let bytes = self.fs.read(path).map_err(|source| TsmError::Io {
            op: "read",
            path: path.to_path_buf(),
            source,
        })?;
        Ok(String::from_utf8_lossy(&bytes).trim_end().to_owned())
    }

    fn generation(&self, entry: &Path) -> Result<u64, TsmError> {
        self.read_text(&entry.join("generation"))?
            .parse()
            .map_err(|_| TsmError::Generation)
    }
}

/// A fresh entry name, so concurrent quotes never share an entry.
fn entry_name() -> String {
    let mut r = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut r);
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    format!("timescales-{hex}")
}

impl Quoter for TsmQuoter {
    /// Evidence with an empty quote when none could be read. Members
    /// refuse it. The enclave quotes through [`Quoter::try_quote`].
    fn quote(&self, measurement: Measurement, debug: bool, report_data: [u8; 64]) -> Evidence {
        self.try_quote(measurement, debug, report_data)
            .unwrap_or(Evidence {
                platform: Platform::IntelTdx,
                quote: Vec::new(),
            })
    }

    fn try_quote(
        &self,
        _measurement: Measurement,
        _debug: bool,
        report_data: [u8; 64],
    ) -> Result<Evidence, QuoteError> {
        self.quote_report(&report_data)
            .map(|quote| Evidence {
                platform: Platform::IntelTdx,
                quote,
            })
            .map_err(|e| QuoteError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use timescales_core::Hash32;

    use super::*;

    /// A configfs report tree in a temporary directory. Like the kernel, it
    /// creates the attributes on mkdir, bumps the entry's `generation` on
    /// every `inblob` write, derives `outblob` from `inblob` and removes the
    /// attributes on rmdir.
    ///
    /// Two kinds of interference, each for as many of our operations as
    /// its count says: `after_write` lets another writer replace the report
    /// data right after ours, so `outblob` is over theirs.
    /// `after_read` lets another writer in right after an `outblob` read.
    struct FakeTsm {
        provider: &'static str,
        after_write: Mutex<u32>,
        after_read: Mutex<u32>,
        created: Mutex<Vec<PathBuf>>,
    }

    impl FakeTsm {
        fn new(provider: &'static str) -> Self {
            Self {
                provider,
                after_write: Mutex::new(0),
                after_read: Mutex::new(0),
                created: Mutex::default(),
            }
        }

        fn interfering(self, after_write: u32, after_read: u32) -> Self {
            *self.after_write.lock().unwrap() = after_write;
            *self.after_read.lock().unwrap() = after_read;
            self
        }

        fn take(count: &Mutex<u32>) -> bool {
            let mut left = count.lock().unwrap();
            let some = *left > 0;
            *left = left.saturating_sub(1);
            some
        }

        /// What the kernel does on an `inblob` write.
        fn store(entry: &Path, data: &[u8]) -> io::Result<()> {
            std::fs::write(entry.join("inblob"), data)?;
            let mut quote = b"TDQUOTE:".to_vec();
            quote.extend_from_slice(data);
            std::fs::write(entry.join("outblob"), quote)?;
            let g: u64 = std::fs::read_to_string(entry.join("generation"))?
                .trim_end()
                .parse()
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            std::fs::write(entry.join("generation"), format!("{}\n", g + 1))
        }
    }

    const FOREIGN: [u8; 64] = [0xf0; 64];

    impl ConfigFs for FakeTsm {
        fn create_dir(&self, path: &Path) -> io::Result<()> {
            std::fs::create_dir(path)?;
            std::fs::write(path.join("provider"), format!("{}\n", self.provider))?;
            std::fs::write(path.join("generation"), "0\n")?;
            std::fs::write(path.join("outblob"), b"")?;
            self.created.lock().unwrap().push(path.to_path_buf());
            Ok(())
        }

        fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
            let entry = path.parent().unwrap();
            Self::store(entry, data)?;
            if Self::take(&self.after_write) {
                Self::store(entry, &FOREIGN)?;
            }
            Ok(())
        }

        fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
            let data = std::fs::read(path)?;
            if path.file_name().is_some_and(|n| n == "outblob") && Self::take(&self.after_read) {
                Self::store(path.parent().unwrap(), &FOREIGN)?;
            }
            Ok(data)
        }

        fn remove_dir(&self, path: &Path) -> io::Result<()> {
            for attr in ["provider", "generation", "outblob", "inblob"] {
                let _ = std::fs::remove_file(path.join(attr));
            }
            std::fs::remove_dir(path)
        }
    }

    /// A fresh directory standing in for the report root, removed on drop.
    struct Root(PathBuf);

    impl Root {
        fn new() -> Self {
            let mut r = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut r);
            let name: String = r.iter().map(|b| format!("{b:02x}")).collect();
            let path = std::env::temp_dir().join(format!("timescales-tsm-{name}"));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn entries(&self) -> usize {
            std::fs::read_dir(&self.0).unwrap().count()
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn report_data() -> [u8; 64] {
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(Hash32([7; 32]).as_bytes());
        rd
    }

    fn expected_quote() -> Vec<u8> {
        let mut q = b"TDQUOTE:".to_vec();
        q.extend_from_slice(&report_data());
        q
    }

    #[test]
    fn quote_over_the_report_data_and_entry_removed() {
        let root = Root::new();
        let fake = Arc::new(FakeTsm::new("tdx_guest"));
        let q = TsmQuoter::with_fs(&root.0, fake.clone());
        assert_eq!(q.quote_report(&report_data()).unwrap(), expected_quote());
        assert_eq!(root.entries(), 0);
        let ev = q
            .try_quote(Measurement(Hash32::ZERO), false, report_data())
            .unwrap();
        assert_eq!(ev.platform, Platform::IntelTdx);
        assert_eq!(ev.quote, expected_quote());
        // Every quote gets its own entry.
        let created = fake.created.lock().unwrap();
        assert_eq!(created.len(), 2);
        assert_ne!(created[0], created[1]);
        assert!(created.iter().all(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("timescales-")
        }));
    }

    #[test]
    fn another_provider_is_refused() {
        let root = Root::new();
        let q = TsmQuoter::with_fs(&root.0, Arc::new(FakeTsm::new("sev_guest")));
        assert!(matches!(
            q.quote_report(&report_data()),
            Err(TsmError::Provider(p)) if p == "sev_guest"
        ));
        assert_eq!(root.entries(), 0);
    }

    #[test]
    fn a_racing_writer_forces_a_retry_and_persistent_races_give_up() {
        let root = Root::new();
        // Both kinds can hit the same attempt: (1, 2) fails twice.
        for (after_write, after_read) in [(2, 0), (0, 2), (1, 2)] {
            let fake = FakeTsm::new("tdx_guest").interfering(after_write, after_read);
            let q = TsmQuoter::with_fs(&root.0, Arc::new(fake));
            assert_eq!(q.quote_report(&report_data()).unwrap(), expected_quote());
        }
        for (after_write, after_read) in [(3, 0), (0, 3), (2, 3)] {
            let fake = FakeTsm::new("tdx_guest").interfering(after_write, after_read);
            let q = TsmQuoter::with_fs(&root.0, Arc::new(fake));
            assert!(matches!(
                q.quote_report(&report_data()),
                Err(TsmError::Contended(3))
            ));
        }
        assert_eq!(root.entries(), 0);
    }

    #[test]
    fn a_quote_over_another_writers_report_data_is_never_returned() {
        // Another writer replaces the report data right after ours, before
        // we read anything: generation and outblob are consistent with each
        // other, but outblob is over its data. Only counting writes from
        // before ours catches that.
        let root = Root::new();
        let fake = FakeTsm::new("tdx_guest").interfering(1, 0);
        let q = TsmQuoter::with_fs(&root.0, Arc::new(fake));
        let quote = q.quote_report(&report_data()).unwrap();
        assert_eq!(quote, expected_quote());
        assert!(!quote.ends_with(&FOREIGN));
    }

    #[test]
    fn a_missing_interface_is_an_io_error() {
        let root = Root::new();
        let q = TsmQuoter::new(root.0.join("not-mounted"));
        let err = q.quote_report(&report_data()).unwrap_err();
        assert!(matches!(err, TsmError::Io { op: "mkdir", .. }), "{err}");
        // As a quoter: an error from try_quote, empty evidence from quote.
        assert!(
            q.try_quote(Measurement(Hash32::ZERO), false, report_data())
                .is_err()
        );
        let ev = q.quote(Measurement(Hash32::ZERO), false, report_data());
        assert_eq!((ev.platform, ev.quote.len()), (Platform::IntelTdx, 0));
    }

    #[test]
    fn std_filesystem_without_a_kernel_finds_no_attributes() {
        // On an ordinary filesystem mkdir creates no attributes, so the
        // provider cannot be read.
        let root = Root::new();
        let q = TsmQuoter::new(&root.0);
        let err = q.quote_report(&report_data()).unwrap_err();
        assert!(matches!(err, TsmError::Io { op: "read", .. }), "{err}");
    }

    #[test]
    fn a_garbled_generation_is_an_error() {
        struct Garbled(FakeTsm);
        impl ConfigFs for Garbled {
            fn create_dir(&self, path: &Path) -> io::Result<()> {
                self.0.create_dir(path)
            }
            fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
                self.0.write(path, data)?;
                std::fs::write(path.parent().unwrap().join("generation"), "seven\n")
            }
            fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
                self.0.read(path)
            }
            fn remove_dir(&self, path: &Path) -> io::Result<()> {
                self.0.remove_dir(path)
            }
        }
        let root = Root::new();
        let q = TsmQuoter::with_fs(&root.0, Arc::new(Garbled(FakeTsm::new("tdx_guest"))));
        assert!(matches!(
            q.quote_report(&report_data()),
            Err(TsmError::Generation)
        ));
        assert_eq!(QUOTE_GENERATION_LABEL, "configfs_tsm_untested_on_hardware");
    }

    #[test]
    fn an_empty_quote_is_an_error() {
        struct Silent(FakeTsm);
        impl ConfigFs for Silent {
            fn create_dir(&self, path: &Path) -> io::Result<()> {
                self.0.create_dir(path)
            }
            fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
                self.0.write(path, data)?;
                std::fs::write(path.parent().unwrap().join("outblob"), b"")
            }
            fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
                self.0.read(path)
            }
            fn remove_dir(&self, path: &Path) -> io::Result<()> {
                self.0.remove_dir(path)
            }
        }
        let root = Root::new();
        let q = TsmQuoter::with_fs(&root.0, Arc::new(Silent(FakeTsm::new("tdx_guest"))));
        assert!(matches!(
            q.quote_report(&report_data()),
            Err(TsmError::EmptyQuote)
        ));
        assert_eq!(root.entries(), 0);
    }
}
