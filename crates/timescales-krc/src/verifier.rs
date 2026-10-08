//! The quote verifiers a member's policy names ("Attestation
//! verification"): Intel TDX through dcap-qvl with collateral reloaded on
//! change, and the simulated vendor in `sim-platform` builds only (**no
//! security**: whoever holds the vendor seed forges evidence).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use timescales_executor::attestation::tdx::TdxDcapVerifier;
use timescales_executor::attestation::{
    AttestationError, Evidence, Platform, QuoteVerifier, VerifiedReport,
};

use crate::config::PolicyConfig;

/// Largest collateral file read.
const MAX_COLLATERAL_BYTES: u64 = 4 * 1024 * 1024;

/// Dispatches evidence to the verifier of its platform. A platform without
/// one is refused as unsupported.
pub struct PlatformVerifiers {
    tdx: Option<Arc<TdxDcapVerifier>>,
    simulated: Option<Arc<dyn QuoteVerifier>>,
}

impl core::fmt::Debug for PlatformVerifiers {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlatformVerifiers")
            .field("tdx", &self.tdx.is_some())
            .field("simulated", &self.simulated.is_some())
            .finish()
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn read_collateral(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_COLLATERAL_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_COLLATERAL_BYTES {
        return Err(format!("{} is too large", path.display()));
    }
    Ok(bytes)
}

impl PlatformVerifiers {
    /// The verifiers `cfg` asks for. The TDX collateral file must exist and
    /// parse. It may be expired (every verification then fails until a
    /// newer one is installed by [`CollateralWatch`]).
    pub fn from_config(cfg: &PolicyConfig) -> Result<Self, String> {
        let tdx = if cfg.intel_tdx() {
            let path = cfg
                .tdx_collateral_file
                .as_ref()
                .ok_or("tdx_collateral_file is required for intel_tdx")?;
            let json = read_collateral(path)?;
            let v = TdxDcapVerifier::from_collateral_json(&json, unix_secs)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            Some(Arc::new(v))
        } else {
            None
        };
        let simulated = if cfg.simulated() {
            Some(simulated_verifier(cfg)?)
        } else {
            None
        };
        Ok(Self { tdx, simulated })
    }

    /// The TDX verifier, to refresh its collateral.
    pub fn tdx(&self) -> Option<&Arc<TdxDcapVerifier>> {
        self.tdx.as_ref()
    }
}

#[cfg(feature = "sim-platform")]
fn simulated_verifier(cfg: &PolicyConfig) -> Result<Arc<dyn QuoteVerifier>, String> {
    use timescales_executor::attestation::simulated::SimulatedQuoteVerifier;
    let root = cfg
        .simulated_vendor_root
        .as_deref()
        .and_then(crate::config::parse_hex::<32>)
        .ok_or("simulated_vendor_root must be 64 hex digits")?;
    tracing::warn!("accepting SIMULATED attestation evidence: no security");
    // Every simulated platform certificate counts as current.
    Ok(Arc::new(SimulatedQuoteVerifier::from_root(root, 0)))
}

#[cfg(not(feature = "sim-platform"))]
fn simulated_verifier(_: &PolicyConfig) -> Result<Arc<dyn QuoteVerifier>, String> {
    Err("the simulated platform needs a build with the sim-platform feature".to_owned())
}

impl QuoteVerifier for PlatformVerifiers {
    fn verify(&self, evidence: &Evidence) -> Result<VerifiedReport, AttestationError> {
        match evidence.platform {
            Platform::IntelTdx => match &self.tdx {
                Some(v) => v.verify(evidence),
                None => Err(AttestationError::UnsupportedPlatform(evidence.platform)),
            },
            Platform::Simulated => match &self.simulated {
                Some(v) => v.verify(evidence),
                None => Err(AttestationError::UnsupportedPlatform(evidence.platform)),
            },
            other => Err(AttestationError::UnsupportedPlatform(other)),
        }
    }
}

/// Re-reads the TDX collateral file when it changes and installs it when
/// it is newer and not expired (`tdx_collateral_file`).
#[derive(Debug)]
pub struct CollateralWatch {
    path: PathBuf,
    verifier: Arc<TdxDcapVerifier>,
    seen: Option<SystemTime>,
}

impl CollateralWatch {
    pub fn new(path: PathBuf, verifier: Arc<TdxDcapVerifier>) -> Self {
        let seen = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        Self {
            path,
            verifier,
            seen,
        }
    }

    /// Installs the file if it changed since the last poll. Returns the
    /// collateral expiry in Unix seconds.
    pub fn poll(&mut self) -> u64 {
        let modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        if modified.is_some() && modified != self.seen {
            self.seen = modified;
            match read_collateral(&self.path) {
                Ok(json) => match self.verifier.refresh(&json) {
                    Ok(()) => {
                        tracing::info!(path = %self.path.display(), "TDX collateral reloaded")
                    }
                    Err(e) => {
                        tracing::error!(path = %self.path.display(), error = %e, "TDX collateral refused")
                    }
                },
                Err(e) => tracing::error!(error = %e, "TDX collateral not read"),
            }
        }
        self.verifier.expires_at()
    }
}
