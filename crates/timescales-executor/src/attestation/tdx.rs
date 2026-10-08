//! Intel TDX evidence verified with `dcap-qvl`.
//!
//! The quote is checked against Intel's production root, the PCK chain and
//! CRLs, TCB info and QE identity supplied as collateral. Debug TDs are
//! rejected by `dcap-qvl` unless explicitly allowed, which we never do.
//!
//! Collateral and time are inputs, not fetched here: production deployments
//! refresh collateral from Intel PCS or a PCCS they trust ([`TdxDcapVerifier::refresh`]),
//! and must treat that service as an availability dependency. The
//! collateral sits behind an [`ArcSwap`], so a refresh never blocks a
//! verification in progress.

use std::sync::Arc;

use arc_swap::ArcSwap;
use dcap_qvl::verify::QuoteVerifier as DcapVerifier;
use dcap_qvl::{QeIdentity, QuoteCollateralV3, TcbInfo};
use thiserror::Error;
use timescales_core::Hash32;
use timescales_core::crypto::{Hasher, domain};

use crate::attestation::{
    AttestationError, Evidence, Measurement, Platform, QuoteVerifier, TcbStatus, TdFields,
    VerifiedReport,
};

/// Measurement for a TD: MRTD and RTMR0..3 together.
pub fn td_measurement(mr_td: &[u8; 48], rtmrs: [&[u8; 48]; 4]) -> Measurement {
    let mut h = Hasher::new(domain::MEASUREMENT)
        .chain(b"intel-tdx")
        .chain(mr_td);
    for r in rtmrs {
        h.update(r);
    }
    Measurement(h.finalize())
}

fn tcb_status(s: &str) -> TcbStatus {
    match s {
        "UpToDate" => TcbStatus::UpToDate,
        "SWHardeningNeeded" => TcbStatus::SwHardeningNeeded,
        "ConfigurationNeeded" | "ConfigurationAndSWHardeningNeeded" => {
            TcbStatus::ConfigurationNeeded
        }
        "Revoked" => TcbStatus::Revoked,
        // OutOfDate, OutOfDateConfigurationNeeded and anything unknown.
        _ => TcbStatus::OutOfDate,
    }
}

/// Why collateral was not installed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CollateralError {
    #[error("collateral is malformed: {0}")]
    Malformed(&'static str),
    /// The TCB info or QE identity is past its `nextUpdate`.
    #[error("collateral expired at {expires_at} (now {now})")]
    CollateralExpired { expires_at: u64, now: u64 },
}

/// Collateral as installed, with the earliest `nextUpdate` of its TCB info
/// and QE identity.
struct Collateral {
    inner: QuoteCollateralV3,
    expires_at: u64,
}

impl Collateral {
    /// Parses Intel's JSON. The error names the part that is malformed.
    fn parse(json: &[u8]) -> Result<Self, &'static str> {
        let inner: QuoteCollateralV3 =
            serde_json::from_slice(json).map_err(|_| "collateral json")?;
        let tcb: TcbInfo = serde_json::from_str(&inner.tcb_info).map_err(|_| "tcb info json")?;
        let qe: QeIdentity =
            serde_json::from_str(&inner.qe_identity).map_err(|_| "qe identity json")?;
        let tcb_next = rfc3339_utc_secs(&tcb.next_update).ok_or("tcb info nextUpdate")?;
        let qe_next = rfc3339_utc_secs(&qe.next_update).ok_or("qe identity nextUpdate")?;
        Ok(Self {
            inner,
            expires_at: tcb_next.min(qe_next),
        })
    }
}

/// Seconds since the Unix epoch of a UTC RFC 3339 timestamp as Intel PCS
/// writes them (`2025-07-19T10:16:03Z`, optionally with fractional
/// seconds, which are dropped). Other offsets are refused.
fn rfc3339_utc_secs(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let time = time.split_once('.').map_or(time, |(whole, frac)| {
        if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
            ""
        } else {
            whole
        }
    });
    let num = |part: &str, len: usize| -> Option<u64> {
        (part.len() == len && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse().ok())
            .flatten()
    };
    let mut d = date.split('-');
    let (year, month, day) = (num(d.next()?, 4)?, num(d.next()?, 2)?, num(d.next()?, 2)?);
    let mut t = time.split(':');
    let (hour, minute, second) = (num(t.next()?, 2)?, num(t.next()?, 2)?, num(t.next()?, 2)?);
    if d.next().is_some() || t.next().is_some() {
        return None;
    }
    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[usize::try_from(month - 1).ok()?] {
        return None;
    }
    let days_before_year: u64 = (1970..year)
        .map(|y| {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                366
            } else {
                365
            }
        })
        .sum();
    let days_before_month: u64 = month_days[..usize::try_from(month - 1).ok()?].iter().sum();
    let days = days_before_year + days_before_month + day - 1;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

pub struct TdxDcapVerifier {
    collateral: ArcSwap<Collateral>,
    now_secs: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl core::fmt::Debug for TdxDcapVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TdxDcapVerifier")
            .field("collateral_expires_at", &self.expires_at())
            .finish_non_exhaustive()
    }
}

impl TdxDcapVerifier {
    /// A verifier over collateral parsed from Intel's JSON. Collateral that
    /// has already expired is accepted here (every verification then fails
    /// until [`Self::refresh`] installs a current one), so a member can
    /// start before its PCCS is reachable.
    pub fn from_collateral_json(
        json: &[u8],
        now_secs: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Result<Self, AttestationError> {
        let collateral = Collateral::parse(json).map_err(AttestationError::Malformed)?;
        Ok(Self {
            collateral: ArcSwap::from_pointee(collateral),
            now_secs: Box::new(now_secs),
        })
    }

    /// Install newer collateral. Collateral that is malformed or already
    /// expired is refused and the installed one stays.
    pub fn refresh(&self, json: &[u8]) -> Result<(), CollateralError> {
        let next = Collateral::parse(json).map_err(CollateralError::Malformed)?;
        let now = (self.now_secs)();
        if now > next.expires_at {
            return Err(CollateralError::CollateralExpired {
                expires_at: next.expires_at,
                now,
            });
        }
        self.collateral.store(Arc::new(next));
        Ok(())
    }

    /// Earliest `nextUpdate` of the installed TCB info and QE identity, in
    /// Unix seconds.
    pub fn expires_at(&self) -> u64 {
        self.collateral.load().expires_at
    }
}

impl QuoteVerifier for TdxDcapVerifier {
    fn verify(&self, evidence: &Evidence) -> Result<VerifiedReport, AttestationError> {
        if evidence.platform != Platform::IntelTdx {
            return Err(AttestationError::UnsupportedPlatform(evidence.platform));
        }
        let collateral = self.collateral.load();
        let now = (self.now_secs)();
        if now > collateral.expires_at {
            return Err(AttestationError::CollateralExpired {
                expires_at: collateral.expires_at,
                now,
            });
        }
        let report = DcapVerifier::new_prod()
            .verify(&evidence.quote, &collateral.inner, now)
            .map_err(|e| AttestationError::Backend(e.to_string()))?;
        let td = report
            .report
            .as_td10()
            .ok_or(AttestationError::Malformed("not a TD report"))?;
        let measurement =
            td_measurement(&td.mr_td, [&td.rt_mr0, &td.rt_mr1, &td.rt_mr2, &td.rt_mr3]);
        let platform_id = Hasher::new(domain::MEASUREMENT)
            .chain(b"ppid")
            .chain(&report.ppid)
            .finalize();
        Ok(VerifiedReport {
            platform: Platform::IntelTdx,
            measurement,
            tcb: tcb_status(&report.status),
            // TUD.DEBUG is bit 0 of TDATTRIBUTES.
            debug: td.td_attributes[0] & 1 == 1,
            report_data: td.report_data,
            platform_id: Hash32(platform_id.0),
            td: Some(TdFields {
                mr_config_id: td.mr_config_id,
                mr_owner: td.mr_owner,
                mr_owner_config: td.mr_owner_config,
                xfam: td.xfam,
                mr_seam: td.mr_seam,
                td_attributes: td.td_attributes,
            }),
        })
    }
}
