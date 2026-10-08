//! Booting the enclave on its platform ("Boot").
//!
//! * **Simulated** (feature `sim-platform`, **no security**, refused under
//!   the production profile): an ordinary process. Quotes are signed by a
//!   simulated platform whose key and vendor certificate come from the
//!   key file `timescales-enclave keygen --simulated` writes. The vendor is
//!   the dev CA derived from `simulated_vendor_seed`. Whoever holds either
//!   can forge evidence, and the host operator can read every order the
//!   enclave executes.
//! * **Intel TDX** (feature `tdx-tsm`): quotes through configfs-tsm
//!   (`TsmQuoter`). **Untested on hardware.**
//!
//! A simulated enclave keeps its seal and executor keys in the key file, so
//! the executor registered for the market survives restarts. A TDX enclave
//! draws fresh keys at every boot and is registered again after each one.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

#[cfg(any(feature = "sim-platform", feature = "tdx-tsm"))]
use timescales_core::Hash32;
use timescales_executor::attestation::{Measurement, Platform};
use timescales_executor::tee::{Enclave, Quoter};
use timescales_service::{ConfigError, ConfigIssue};

use crate::{EnclaveError, PlatformMode};

/// Simulated key file, the layout `timescales-admin keygen` writes:
/// `"TSCLSIMK" || version u8 || seal_seed32 || executor_seed32 ||
/// platform_seed32 || has_certificate u8 || PlatformCertificate (98 B)`.
/// A file without the certificate cannot boot.
#[cfg(feature = "sim-platform")]
const KEY_FILE_MAGIC: &[u8; 8] = b"TSCLSIMK";
#[cfg(feature = "sim-platform")]
const KEY_FILE_VERSION: u8 = 1;
const KEY_FILE_LEN: usize = 8 + 1 + 96 + 1 + 98;

/// An enclave booted on its platform.
pub(crate) struct Booted {
    pub enclave: Arc<Enclave>,
    pub quoter: Arc<dyn Quoter>,
    pub platform: Platform,
    /// What the identity endpoint reports: the program measurement in
    /// simulated mode (a crate-name/version hash, not an image
    /// measurement). Zero on TDX, whose measurement is in the quote.
    pub measurement: Measurement,
    pub quote_generation: &'static str,
    /// Whether a quote over test report data was produced (and, simulated,
    /// verified against the vendor) at boot.
    pub self_test: bool,
}

fn refused(field: &str, message: impl Into<String>) -> EnclaveError {
    EnclaveError::Config(ConfigError::Invalid(vec![ConfigIssue::new(field, message)]))
}

/// Report data of the boot self-test.
#[cfg(any(feature = "sim-platform", feature = "tdx-tsm"))]
fn self_test_data() -> [u8; 64] {
    let mut rd = [0u8; 64];
    rd[..32].copy_from_slice(
        timescales_core::crypto::hash(b"timescales/enclave/self-test", &[]).as_bytes(),
    );
    rd
}

pub(crate) fn boot(mode: &PlatformMode) -> Result<Booted, EnclaveError> {
    match mode {
        PlatformMode::Simulated {
            key_file,
            vendor_seed_file,
        } => boot_simulated(key_file, vendor_seed_file),
        PlatformMode::IntelTdx { configfs_root } => boot_tdx(configfs_root),
    }
}

#[cfg(feature = "sim-platform")]
mod simulated {
    use timescales_core::crypto::Zeroizing;
    use timescales_executor::attestation::simulated::{
        PlatformCertificate, SimulatedPlatform, SimulatedQuoteVerifier, SimulatedVendor,
    };
    use timescales_executor::attestation::{Evidence, QuoteVerifier};

    use super::*;

    /// The simulated vendor's current security version. Members configure
    /// its root with the same version.
    pub(super) const VENDOR_SVN: u16 = 0;

    /// [`Quoter`] over a simulated platform (the executor-tee impl exists
    /// only with its `simulation` feature, which services never enable).
    pub(super) struct SimQuoter(pub(super) SimulatedPlatform);

    impl Quoter for SimQuoter {
        fn quote(&self, measurement: Measurement, debug: bool, report_data: [u8; 64]) -> Evidence {
            self.0.quote(measurement, debug, report_data)
        }
    }

    pub(super) fn vendor(path: &Path) -> Result<SimulatedVendor, EnclaveError> {
        let seed = timescales_service::keys::ed25519_seed(path)
            .map_err(|e| EnclaveError::Config(e.into()))?
            .seed();
        Ok(SimulatedVendor::from_seed(*seed, VENDOR_SVN))
    }

    /// The keys a simulated enclave boots with.
    pub(super) struct KeyFile {
        pub(super) seal: Zeroizing<[u8; 32]>,
        pub(super) executor: Zeroizing<[u8; 32]>,
        pub(super) platform: SimulatedPlatform,
    }

    pub(super) fn encode(
        seal: &[u8; 32],
        executor: &[u8; 32],
        platform: &SimulatedPlatform,
    ) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(KEY_FILE_LEN));
        out.extend_from_slice(KEY_FILE_MAGIC);
        out.push(KEY_FILE_VERSION);
        out.extend_from_slice(seal);
        out.extend_from_slice(executor);
        out.extend_from_slice(platform.key_seed().as_slice());
        out.push(1);
        out.extend_from_slice(&platform.certificate().to_bytes());
        out
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<KeyFile, String> {
        if bytes.len() < 8 + 1 + 96 + 1
            || &bytes[..8] != KEY_FILE_MAGIC
            || bytes[8] != KEY_FILE_VERSION
        {
            return Err("not a simulated enclave key file (version 1)".to_owned());
        }
        if bytes[105] != 1 || bytes.len() != KEY_FILE_LEN {
            return Err(
                "the key file has no platform certificate; generate it with a sim-platform build"
                    .to_owned(),
            );
        }
        let seed = |at: usize| {
            let mut s = Zeroizing::new([0u8; 32]);
            s.copy_from_slice(&bytes[at..at + 32]);
            s
        };
        let (seal, executor, platform_seed) = (seed(9), seed(41), seed(73));
        let cert = PlatformCertificate::from_bytes(&bytes[106..]).map_err(|e| e.to_string())?;
        let platform =
            SimulatedPlatform::from_parts(*platform_seed, cert).map_err(|e| e.to_string())?;
        Ok(KeyFile {
            seal,
            executor,
            platform,
        })
    }

    pub(super) fn self_test(quoter: &SimQuoter, vendor: &SimulatedVendor) -> bool {
        let rd = self_test_data();
        let evidence = quoter.quote(timescales_executor::tee::program_measurement(), false, rd);
        SimulatedQuoteVerifier::from_root(vendor.root_key(), VENDOR_SVN)
            .verify(&evidence)
            .is_ok_and(|r| r.report_data == rd && !r.debug)
    }
}

#[cfg(feature = "sim-platform")]
fn boot_simulated(key_file: &Path, vendor_seed_file: &Path) -> Result<Booted, EnclaveError> {
    let vendor = simulated::vendor(vendor_seed_file)?;
    let bytes = read_private(key_file).map_err(|e| refused("enclave.simulated_key_file", e))?;
    let keys = simulated::decode(&bytes).map_err(|e| refused("enclave.simulated_key_file", e))?;
    let platform = keys.platform;
    if platform.certificate().verify(&vendor.root_key()).is_err() {
        return Err(refused(
            "enclave.simulated_key_file",
            "the platform certificate was not issued by the configured vendor seed",
        ));
    }
    let quoter = Arc::new(simulated::SimQuoter(platform));
    let self_test = simulated::self_test(&quoter, &vendor);
    let measurement = timescales_executor::tee::program_measurement();
    let enclave = Arc::new(Enclave::boot_with_keys(
        Arc::clone(&quoter) as Arc<dyn Quoter>,
        measurement,
        false,
        timescales_core::crypto::SealSecret::from_bytes(*keys.seal),
        timescales_core::identity::ExecutorKey::from_seed(*keys.executor),
    ));
    Ok(Booted {
        enclave,
        quoter,
        platform: Platform::Simulated,
        measurement,
        quote_generation: "simulated",
        self_test,
    })
}

#[cfg(not(feature = "sim-platform"))]
fn boot_simulated(_key_file: &Path, _vendor_seed_file: &Path) -> Result<Booted, EnclaveError> {
    Err(refused(
        "enclave.platform",
        "\"simulated\" needs a build with the sim-platform feature",
    ))
}

#[cfg(feature = "tdx-tsm")]
fn boot_tdx(configfs_root: &Path) -> Result<Booted, EnclaveError> {
    use timescales_executor::tee::TsmQuoter;
    let quoter: Arc<dyn Quoter> = Arc::new(TsmQuoter::new(configfs_root));
    let self_test = quoter
        .try_quote(Measurement(Hash32::ZERO), false, self_test_data())
        .is_ok_and(|e| !e.quote.is_empty());
    let enclave = Arc::new(Enclave::boot(
        Arc::clone(&quoter),
        Measurement(Hash32::ZERO),
        false,
    ));
    Ok(Booted {
        enclave,
        quoter,
        platform: Platform::IntelTdx,
        measurement: Measurement(Hash32::ZERO),
        quote_generation: timescales_executor::tee::tsm::QUOTE_GENERATION_LABEL,
        self_test,
    })
}

#[cfg(not(feature = "tdx-tsm"))]
fn boot_tdx(_configfs_root: &Path) -> Result<Booted, EnclaveError> {
    Err(refused(
        "enclave.platform",
        "\"intel_tdx\" needs a build with the tdx-tsm feature",
    ))
}

/// Reads a secret file only its owner can access.
#[cfg_attr(not(feature = "sim-platform"), allow(dead_code))]
fn read_private(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is accessible by group or others (mode {mode:o})",
                path.display()
            ));
        }
    }
    let mut bytes = Vec::with_capacity(KEY_FILE_LEN);
    file.take(4096)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(bytes)
}

/// Writes `bytes` to a new file at `path`, readable by its owner only.
#[cfg_attr(not(feature = "sim-platform"), allow(dead_code))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// `keygen --simulated`: a new simulated platform certified by the vendor
/// derived from `vendor_seed_file`, written to `out` (which must not
/// exist). Returns the platform id. No security.
#[cfg(feature = "sim-platform")]
pub fn keygen_simulated(vendor_seed_file: &Path, out: &Path) -> Result<Hash32, EnclaveError> {
    let vendor = simulated::vendor(vendor_seed_file)?;
    let platform = vendor.platform(&mut rand_core::OsRng, simulated::VENDOR_SVN);
    let mut seal = timescales_core::crypto::Zeroizing::new([0u8; 32]);
    let mut executor = timescales_core::crypto::Zeroizing::new([0u8; 32]);
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, seal.as_mut_slice());
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, executor.as_mut_slice());
    let bytes = simulated::encode(&seal, &executor, &platform);
    write_private(out, &bytes)
        .map_err(|e| refused("--out", format!("writing {}: {e}", out.display())))?;
    Ok(platform.id())
}

#[cfg(all(test, feature = "sim-platform"))]
mod tests {
    use super::*;

    fn seed_file(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("vendor.hex");
        write_private(&path, hex::encode([5u8; 32]).as_bytes()).unwrap();
        path
    }

    #[test]
    fn a_generated_key_file_boots_and_passes_the_self_test() {
        let dir = tempfile::tempdir().unwrap();
        let vendor = seed_file(dir.path());
        let keys = dir.path().join("keys.bin");
        let id = keygen_simulated(&vendor, &keys).unwrap();
        // Never overwritten.
        assert!(keygen_simulated(&vendor, &keys).is_err());
        let booted = boot_simulated(&keys, &vendor).unwrap();
        assert!(booted.self_test);
        assert_eq!(booted.platform, Platform::Simulated);
        let file = simulated::decode(&std::fs::read(&keys).unwrap()).unwrap();
        assert_eq!(file.platform.id(), id);
        // The executor registered for a market survives a restart.
        let again = boot_simulated(&keys, &vendor).unwrap();
        assert_eq!(again.enclave.executor_id(), booted.enclave.executor_id());
        assert_eq!(
            booted.enclave.executor_id(),
            timescales_core::identity::ExecutorKey::from_seed(*file.executor).id()
        );
    }

    #[test]
    fn another_vendor_or_an_open_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let vendor = seed_file(dir.path());
        let keys = dir.path().join("keys.bin");
        keygen_simulated(&vendor, &keys).unwrap();
        let other = dir.path().join("other.hex");
        write_private(&other, hex::encode([6u8; 32]).as_bytes()).unwrap();
        assert!(boot_simulated(&keys, &other).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o644)).unwrap();
            let err = boot_simulated(&keys, &vendor).err().unwrap().to_string();
            assert!(err.contains("group or others"), "{err}");
        }
    }
}
