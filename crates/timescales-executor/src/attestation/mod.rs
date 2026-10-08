//! Remote attestation abstraction.
//!
//! The pipeline is the RATS one (RFC 9334): an attester produces
//! **evidence** (a quote) over a **measurement** of the code it runs and 64
//! bytes of caller-chosen **report data**. A verifier checks the evidence
//! against the vendor's endorsements and produces a [`VerifiedReport`].
//! Policy (the `policy` module) then decides whether to trust it, and only then is
//! key material released.
//!
//! Verification is behind [`QuoteVerifier`] so the rest of Timescales never
//! depends on a particular vendor. Two implementations exist:
//!
//! * `simulated` (feature `sim-platform`) - an Ed25519 "vendor" that
//!   certifies "platform" keys, which sign reports. It reproduces the
//!   *structure* of TDX/SNP evidence (vendor root, per-platform key, TCB
//!   level, debug flag, report data) so the key-release and policy logic can
//!   be exercised end to end, and it gives no security whatsoever.
//! * `tdx` (feature `tdx-dcap`) - Intel TDX quotes verified with
//!   `dcap-qvl` against Intel collateral, which can be refreshed while the
//!   verifier is in use.
//!
//! What attestation does **not** give: correctness of the measured code,
//! freshness of its state, availability, or protection against side
//! channels or physical attacks. A quote produced with an extracted
//! attestation key verifies like a genuine one.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod codec;
#[cfg(feature = "sim-platform")]
pub mod simulated;
#[cfg(feature = "tdx-dcap")]
pub mod tdx;

/// Whether this build includes simulation-only components.
pub const SIMULATION_BUILD: bool = cfg!(feature = "simulation");

/// Whether this build produces and accepts evidence from the simulated
/// platform. Services refuse to start with it under the production
/// profile.
pub const SIM_PLATFORM_BUILD: bool = cfg!(feature = "sim-platform");

#[cfg(feature = "simulation")]
#[used]
static SIMULATION_MARKER: [u8; 29] = *b"timescales:SIMULATION_BUILD=1";

use std::collections::BTreeSet;

use thiserror::Error;
use timescales_core::crypto::{Hasher, domain};
use timescales_core::{
    Decode, DecodeError, Encode, ExecutorId, Hash32, Reader,
    encoding::{put_bytes, put_u8},
};

/// Upper bound on encoded evidence. TDX v4 quotes with certification data
/// are a few KiB.
pub const MAX_EVIDENCE_LEN: usize = 16 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AttestationError {
    #[error("evidence is malformed: {0}")]
    Malformed(&'static str),
    #[error("evidence platform {0:?} not supported by this verifier")]
    UnsupportedPlatform(Platform),
    #[error("endorsement chain invalid")]
    BadEndorsement,
    #[error("evidence signature invalid")]
    BadSignature,
    #[error("platform key revoked")]
    Revoked,
    #[error("verification backend error: {0}")]
    Backend(String),
    /// The verifier's collateral (TCB info or QE identity) is past its
    /// `nextUpdate`, in Unix seconds.
    #[error("collateral expired at {expires_at} (now {now})")]
    CollateralExpired { expires_at: u64, now: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Platform {
    Simulated = 0,
    IntelTdx = 1,
    AmdSevSnp = 2,
    AwsNitro = 3,
}

impl Platform {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Simulated),
            1 => Some(Self::IntelTdx),
            2 => Some(Self::AmdSevSnp),
            3 => Some(Self::AwsNitro),
            _ => None,
        }
    }
}

/// Digest identifying the measured code. For TDX this is derived from MRTD
/// and RTMR0..3. For the simulator it is a hash of the program identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Measurement(pub Hash32);

impl Measurement {
    pub fn of_program(name: &str, version: &str, build: &[u8]) -> Self {
        Measurement(
            Hasher::new(domain::MEASUREMENT)
                .chain(name.as_bytes())
                .chain(&[0])
                .chain(version.as_bytes())
                .chain(&[0])
                .chain(build)
                .finalize(),
        )
    }
}

/// `H(RELEASE_POLICY, "measurements" || u32 count || each measurement in
/// ascending order)`: lets a member's signed release policy commit to its
/// measurement allowlist without publishing it.
pub fn measurement_set_digest(measurements: &BTreeSet<Measurement>) -> Hash32 {
    let count = u32::try_from(measurements.len()).unwrap_or(u32::MAX);
    let mut h = Hasher::new(domain::RELEASE_POLICY)
        .chain(b"measurements")
        .chain(&count.to_le_bytes());
    for m in measurements {
        h.update(m.0.as_bytes());
    }
    h.finalize()
}

/// Vendor's judgement of the platform's patch level, as in Intel's TCB
/// status values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TcbStatus {
    UpToDate,
    SwHardeningNeeded,
    ConfigurationNeeded,
    OutOfDate,
    Revoked,
}

/// Raw evidence as produced by the attester.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub platform: Platform,
    pub quote: Vec<u8>,
}

/// The fields of an Intel TDX TD report that the measurement does not
/// cover, so that policy can appraise them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TdFields {
    /// Software-defined configuration measured when the TD was built. The
    /// enclave image puts its program id, the cluster's genesis hash and its
    /// market list here.
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    /// Extended CPU features enabled for the TD.
    pub xfam: [u8; 8],
    /// Measurement of the TDX module.
    pub mr_seam: [u8; 48],
    /// TD attributes, little-endian. Bit 0 is DEBUG.
    pub td_attributes: [u8; 8],
}

/// What a verifier extracted from evidence it accepted cryptographically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReport {
    pub platform: Platform,
    pub measurement: Measurement,
    pub tcb: TcbStatus,
    pub debug: bool,
    pub report_data: [u8; 64],
    /// Stable identifier of the physical platform (for diversity policies).
    pub platform_id: Hash32,
    /// TD report fields. `Some` exactly for Intel TDX evidence.
    pub td: Option<TdFields>,
}

pub trait QuoteVerifier: Send + Sync {
    fn verify(&self, evidence: &Evidence) -> Result<VerifiedReport, AttestationError>;
}

/// Report data binding for executor attestations: the enclave's sealing key
/// (shares are encrypted to it), its receipt-signing key, the batch it asks
/// to execute and the verifiers' freshness nonces.
pub fn report_data(
    seal_key: &[u8; 32],
    executor: &ExecutorId,
    header_digest: &Hash32,
    nonces_digest: &Hash32,
) -> [u8; 64] {
    let h = Hasher::new(domain::REPORT_DATA)
        .chain(seal_key)
        .chain(executor.as_bytes())
        .chain(header_digest.as_bytes())
        .chain(nonces_digest.as_bytes())
        .finalize();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(h.as_bytes());
    out
}

pub fn nonces_digest(nonces: &[Hash32]) -> Hash32 {
    let mut h = Hasher::new(domain::REPORT_DATA).chain(b"nonces");
    for n in nonces {
        h.update(n.as_bytes());
    }
    h.finalize()
}

/// Report data for key-release attestations:
/// `H(REPORT_DATA_V2, seal_key || executor || header digest || nonces digest ||
/// committee digest) || 0^32`. Binding the committee digest stops a host from
/// using the real members' shares under a committee it forged.
pub fn report_data_v2(
    seal_key: &[u8; 32],
    executor: &ExecutorId,
    header_digest: &Hash32,
    nonces_digest: &Hash32,
    committee_digest: &Hash32,
) -> [u8; 64] {
    let h = Hasher::new(domain::REPORT_DATA_V2)
        .chain(seal_key)
        .chain(executor.as_bytes())
        .chain(header_digest.as_bytes())
        .chain(nonces_digest.as_bytes())
        .chain(committee_digest.as_bytes())
        .finalize();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(h.as_bytes());
    out
}

/// Report data of the evidence an enclave publishes for registration:
/// `H(EXECUTOR_REGISTRATION, seal_key || executor || program || market || nonce) || 0^32`.
pub fn registration_report_data(
    seal_key: &[u8; 32],
    executor: &ExecutorId,
    program: &[u8; 32],
    market: &[u8; 32],
    nonce: &[u8; 32],
) -> [u8; 64] {
    let h = Hasher::new(domain::EXECUTOR_REGISTRATION)
        .chain(seal_key)
        .chain(executor.as_bytes())
        .chain(program)
        .chain(market)
        .chain(nonce)
        .finalize();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(h.as_bytes());
    out
}

/// An executor's claim to be allowed to run a specific batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorAttestation {
    pub executor: ExecutorId,
    pub seal_key: [u8; 32],
    pub header_digest: Hash32,
    /// One nonce per key-release member, in member order.
    pub nonces: Vec<Hash32>,
    pub evidence: Evidence,
}

impl ExecutorAttestation {
    pub fn expected_report_data(&self) -> [u8; 64] {
        report_data(
            &self.seal_key,
            &self.executor,
            &self.header_digest,
            &nonces_digest(&self.nonces),
        )
    }

    pub fn digest(&self) -> Hash32 {
        Hasher::new(domain::ATTESTATION_REPORT)
            .chain(&self.to_bytes())
            .finalize()
    }
}

/// Key-release attestation: as [`ExecutorAttestation`], plus the
/// digest of the committee the enclave was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorAttestationV2 {
    pub executor: ExecutorId,
    pub seal_key: [u8; 32],
    pub header_digest: Hash32,
    /// One nonce per key-release member, in member order.
    pub nonces: Vec<Hash32>,
    pub committee_digest: Hash32,
    pub evidence: Evidence,
}

impl ExecutorAttestationV2 {
    pub fn expected_report_data(&self) -> [u8; 64] {
        report_data_v2(
            &self.seal_key,
            &self.executor,
            &self.header_digest,
            &nonces_digest(&self.nonces),
            &self.committee_digest,
        )
    }

    pub fn digest(&self) -> Hash32 {
        Hasher::new(domain::ATTESTATION_REPORT)
            .chain(&self.to_bytes())
            .finalize()
    }
}

impl Encode for Evidence {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.platform as u8);
        put_bytes(out, &self.quote);
    }
}

impl Decode for Evidence {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let tag = r.u8()?;
        let platform = Platform::from_u8(tag).ok_or(DecodeError::InvalidTag {
            ty: "Platform",
            tag,
        })?;
        Ok(Evidence {
            platform,
            quote: r.bytes(MAX_EVIDENCE_LEN)?,
        })
    }
}

impl Encode for ExecutorAttestation {
    fn encode(&self, out: &mut Vec<u8>) {
        self.executor.encode(out);
        out.extend_from_slice(&self.seal_key);
        self.header_digest.encode(out);
        timescales_core::encoding::put_seq(out, &self.nonces);
        self.evidence.encode(out);
    }
}

impl Decode for ExecutorAttestation {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ExecutorAttestation {
            executor: ExecutorId::decode(r)?,
            seal_key: r.array()?,
            header_digest: Hash32::decode(r)?,
            nonces: r.seq(256)?,
            evidence: Evidence::decode(r)?,
        })
    }
}
