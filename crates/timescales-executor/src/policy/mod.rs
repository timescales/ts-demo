//! Policy.
//!
//! * [`AttestationPolicy`] decides whether verified attestation evidence is
//!   good enough to receive key material. Verification (the `attestation` module)
//!   answers "is this evidence genuine". Appraisal answers "do we trust what
//!   it says". Keeping them separate means the same verifier output can be
//!   judged by different committees with different risk tolerance.
//! * [`ExecutionPolicy`] decides which backends may execute a market's
//!   batches, in which order, with what proof requirement, and how failures
//!   are retried.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use std::collections::BTreeSet;
use std::time::Duration;

use crate::attestation::{
    Measurement, Platform, TcbStatus, TdFields, VerifiedReport, measurement_set_digest,
};
use thiserror::Error;
use timescales_auction::receipts::BackendKind;
use timescales_core::Hash32;

/// Why an appraisal refused a report.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyViolation {
    #[error("platform {0:?} not allowed")]
    Platform(Platform),
    #[error("measurement not in allowlist")]
    Measurement,
    #[error("TCB status {0:?} not accepted")]
    Tcb(TcbStatus),
    #[error("debug enclaves are not accepted")]
    Debug,
    #[error("report data does not bind the expected keys, batch and nonces")]
    ReportData,
    #[error("platform is blocked by policy")]
    BlockedPlatform,
    #[error("MRCONFIGID does not match the pinned configuration")]
    MrConfigId,
    #[error("XFAM does not match the pin")]
    Xfam,
    #[error("TD attributes break the attributes rule")]
    TdAttributes,
    #[error("an Intel TDX report without TD fields")]
    MissingTdFields,
}

/// The deployment profile a policy is checked against. The services map
/// their own `profile` onto it (`timescales-service` depends on this crate,
/// so it cannot be shared).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    Local,
    Devnet,
    Production,
}

/// A rule over the TD attributes: `td_attributes & mask == value`, both as
/// little-endian 64-bit values. It applies on top of
/// [`AttestationPolicy::allow_debug`]: a debug TD is refused as
/// [`PolicyViolation::Debug`] unless debug is allowed, and, when the mask
/// covers the debug bit (bit 0), also as [`PolicyViolation::TdAttributes`]
/// if the rule's value for that bit is 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TdAttributesRule {
    pub mask: [u8; 8],
    pub value: [u8; 8],
}

impl TdAttributesRule {
    /// Every bit of `bits` must be set (for example `SEPT_VE_DISABLE`).
    pub fn require(bits: [u8; 8]) -> Self {
        Self {
            mask: bits,
            value: bits,
        }
    }

    pub fn matches(&self, td_attributes: &[u8; 8]) -> bool {
        let attrs = u64::from_le_bytes(*td_attributes);
        attrs & u64::from_le_bytes(self.mask) == u64::from_le_bytes(self.value)
    }
}

/// What the TD fields of an Intel TDX report must show. An unset pin
/// accepts any value. [`AttestationPolicy::check_profile`] requires all of
/// them in production.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TdPolicy {
    /// The measured enclave configuration (program id, genesis hash and
    /// markets).
    pub mr_config_id: Option<[u8; 48]>,
    pub attributes: Option<TdAttributesRule>,
    pub xfam: Option<[u8; 8]>,
}

impl TdPolicy {
    /// Checks the pins in a fixed order: MRCONFIGID, XFAM, TD attributes.
    fn appraise(&self, td: &TdFields) -> Result<(), PolicyViolation> {
        if self.mr_config_id.is_some_and(|pin| pin != td.mr_config_id) {
            return Err(PolicyViolation::MrConfigId);
        }
        if self.xfam.is_some_and(|pin| pin != td.xfam) {
            return Err(PolicyViolation::Xfam);
        }
        if self
            .attributes
            .is_some_and(|rule| !rule.matches(&td.td_attributes))
        {
            return Err(PolicyViolation::TdAttributes);
        }
        Ok(())
    }
}

/// A rule [`AttestationPolicy::check_profile`] found broken.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProfileIssue {
    #[error("the simulated platform is not accepted under the production profile")]
    SimulatedPlatform,
    #[error("debug enclaves are not accepted under the production profile")]
    DebugAllowed,
    #[error("minimum TCB {0:?} is below sw_hardening_needed")]
    TcbTooLow(TcbStatus),
    #[error("no TD attributes rule (tdx_td_attributes_mask)")]
    NoTdAttributes,
    #[error("no XFAM pin (tdx_xfam)")]
    NoXfam,
    #[error("no MRCONFIGID pin (tdx_mr_config_id)")]
    NoMrConfigId,
}

/// The policy part of a member's signed `ReleasePolicyStatement`.
/// The member adds its identity, committee and epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleasePolicyFields {
    /// Bit 0: the simulated platform. Bit 1: Intel TDX.
    pub platforms: u8,
    /// `crate::attestation::measurement_set_digest` of the allowlist.
    pub measurement_set_digest: Hash32,
    pub allow_debug: bool,
    /// 0 up to date, 1 SW hardening needed, 2 configuration needed, 3 out
    /// of date (the `TcbStatus` numbering of the release refusal codec).
    pub min_tcb: u8,
    /// The MRCONFIGID pin, zero when there is none.
    pub mr_config_id: [u8; 48],
}

/// Statement bit of the simulated platform.
pub const PLATFORM_BIT_SIMULATED: u8 = 1 << 0;
/// Statement bit of Intel TDX.
pub const PLATFORM_BIT_INTEL_TDX: u8 = 1 << 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationPolicy {
    pub platforms: BTreeSet<Platform>,
    pub measurements: BTreeSet<Measurement>,
    /// The worst TCB status accepted. `Revoked` is never accepted.
    pub min_tcb: TcbStatus,
    pub allow_debug: bool,
    pub blocked_platforms: BTreeSet<Hash32>,
    pub td: TdPolicy,
}

impl AttestationPolicy {
    /// Strict default: only `UpToDate`, no debug, explicit allowlists, no
    /// TD pins (add them for TDX).
    pub fn strict(
        platforms: impl IntoIterator<Item = Platform>,
        measurements: impl IntoIterator<Item = Measurement>,
    ) -> Self {
        Self {
            platforms: platforms.into_iter().collect(),
            measurements: measurements.into_iter().collect(),
            min_tcb: TcbStatus::UpToDate,
            allow_debug: false,
            blocked_platforms: BTreeSet::new(),
            td: TdPolicy::default(),
        }
    }

    /// Appraise a verified report. Checks run in a fixed order so the
    /// reported violation is deterministic: platform, blocklist, debug, TCB,
    /// measurement, TD fields, report data.
    pub fn appraise(
        &self,
        report: &VerifiedReport,
        expected_report_data: &[u8; 64],
    ) -> Result<(), PolicyViolation> {
        if !self.platforms.contains(&report.platform) {
            return Err(PolicyViolation::Platform(report.platform));
        }
        if self.blocked_platforms.contains(&report.platform_id) {
            return Err(PolicyViolation::BlockedPlatform);
        }
        if report.debug && !self.allow_debug {
            return Err(PolicyViolation::Debug);
        }
        if report.tcb == TcbStatus::Revoked || report.tcb > self.min_tcb {
            return Err(PolicyViolation::Tcb(report.tcb));
        }
        if !self.measurements.contains(&report.measurement) {
            return Err(PolicyViolation::Measurement);
        }
        if report.platform == Platform::IntelTdx {
            // A TDX report without TD fields cannot show the pinned
            // configuration.
            let td = report.td.as_ref().ok_or(PolicyViolation::MissingTdFields)?;
            self.td.appraise(td)?;
        }
        if &report.report_data != expected_report_data {
            return Err(PolicyViolation::ReportData);
        }
        Ok(())
    }

    /// Every rule `profile` imposes that this policy breaks. Only the
    /// production profile has rules: no simulated platform, no debug
    /// enclaves, a minimum TCB of `UpToDate` or `SwHardeningNeeded`, and
    /// the TD attributes, XFAM and MRCONFIGID pins.
    pub fn check_profile(&self, profile: Profile) -> Result<(), Vec<ProfileIssue>> {
        if profile != Profile::Production {
            return Ok(());
        }
        let mut issues = Vec::new();
        if self.platforms.contains(&Platform::Simulated) {
            issues.push(ProfileIssue::SimulatedPlatform);
        }
        if self.allow_debug {
            issues.push(ProfileIssue::DebugAllowed);
        }
        if self.min_tcb > TcbStatus::SwHardeningNeeded {
            issues.push(ProfileIssue::TcbTooLow(self.min_tcb));
        }
        if self.td.attributes.is_none() {
            issues.push(ProfileIssue::NoTdAttributes);
        }
        if self.td.xfam.is_none() {
            issues.push(ProfileIssue::NoXfam);
        }
        if self.td.mr_config_id.is_none() {
            issues.push(ProfileIssue::NoMrConfigId);
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    /// The policy fields of this member's `ReleasePolicyStatement`.
    /// Platforms without a statement bit (SEV-SNP, Nitro) are not listed.
    pub fn statement(&self) -> ReleasePolicyFields {
        let mut platforms = 0;
        if self.platforms.contains(&Platform::Simulated) {
            platforms |= PLATFORM_BIT_SIMULATED;
        }
        if self.platforms.contains(&Platform::IntelTdx) {
            platforms |= PLATFORM_BIT_INTEL_TDX;
        }
        ReleasePolicyFields {
            platforms,
            measurement_set_digest: measurement_set_digest(&self.measurements),
            allow_debug: self.allow_debug,
            min_tcb: match self.min_tcb {
                TcbStatus::UpToDate => 0,
                TcbStatus::SwHardeningNeeded => 1,
                TcbStatus::ConfigurationNeeded => 2,
                TcbStatus::OutOfDate => 3,
                TcbStatus::Revoked => 4,
            },
            mr_config_id: self.td.mr_config_id.unwrap_or([0; 48]),
        }
    }
}

/// When a proof must accompany a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofMode {
    /// Receipts are trusted on executor attestation alone.
    None,
    /// Settlement waits for a verified proof.
    Synchronous,
    /// Settle on the receipt. A proof must be posted within this many epochs
    /// or the executor is penalised and the market halts.
    Deferred { window_epochs: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionPolicy {
    /// Allowed backends in order of preference.
    pub backends: Vec<BackendKind>,
    pub proof: ProofMode,
    /// Attempts per backend before moving to the next one.
    pub attempts_per_backend: u8,
    pub attempt_timeout: Duration,
    /// Batches larger than this skip the MPC backend (its latency grows with
    /// batch size and would miss the epoch).
    pub mpc_max_batch: usize,
}

impl ExecutionPolicy {
    /// Backends to try for a batch of `n` envelopes, given which are
    /// currently healthy. Order is preference order, filtered.
    pub fn plan(&self, n: usize, healthy: &BTreeSet<BackendKind>) -> Vec<BackendKind> {
        self.backends
            .iter()
            .copied()
            .filter(|b| healthy.contains(b))
            .filter(|b| *b != BackendKind::Mpc || n <= self.mpc_max_batch)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEPT_VE_DISABLE_BIT: u64 = 1 << 28;
    const SEPT_VE_DISABLE: [u8; 8] = SEPT_VE_DISABLE_BIT.to_le_bytes();
    const XFAM: [u8; 8] = [0xe7, 0x02, 0x06, 0, 0, 0, 0, 0];

    fn report() -> VerifiedReport {
        VerifiedReport {
            platform: Platform::Simulated,
            measurement: Measurement(Hash32([1; 32])),
            tcb: TcbStatus::UpToDate,
            debug: false,
            report_data: [9; 64],
            platform_id: Hash32([2; 32]),
            td: None,
        }
    }

    fn policy() -> AttestationPolicy {
        AttestationPolicy::strict([Platform::Simulated], [Measurement(Hash32([1; 32]))])
    }

    fn td_fields() -> TdFields {
        TdFields {
            mr_config_id: [7; 48],
            mr_owner: [0; 48],
            mr_owner_config: [0; 48],
            xfam: XFAM,
            mr_seam: [3; 48],
            td_attributes: SEPT_VE_DISABLE,
        }
    }

    fn tdx_report() -> VerifiedReport {
        VerifiedReport {
            platform: Platform::IntelTdx,
            td: Some(td_fields()),
            ..report()
        }
    }

    fn production() -> AttestationPolicy {
        let mut p = AttestationPolicy::strict([Platform::IntelTdx], [Measurement(Hash32([1; 32]))]);
        p.td = TdPolicy {
            mr_config_id: Some([7; 48]),
            attributes: Some(TdAttributesRule::require(SEPT_VE_DISABLE)),
            xfam: Some(XFAM),
        };
        p
    }

    #[test]
    fn appraisal_order_and_outcomes() {
        let p = policy();
        assert!(p.appraise(&report(), &[9; 64]).is_ok());
        assert_eq!(
            p.appraise(&report(), &[8; 64]),
            Err(PolicyViolation::ReportData)
        );
        let mut r = report();
        r.measurement = Measurement(Hash32([3; 32]));
        assert_eq!(p.appraise(&r, &[9; 64]), Err(PolicyViolation::Measurement));
        r = report();
        r.tcb = TcbStatus::OutOfDate;
        assert_eq!(
            p.appraise(&r, &[9; 64]),
            Err(PolicyViolation::Tcb(TcbStatus::OutOfDate))
        );
        r.debug = true;
        assert_eq!(p.appraise(&r, &[9; 64]), Err(PolicyViolation::Debug));
        r.platform = Platform::AwsNitro;
        assert_eq!(
            p.appraise(&r, &[9; 64]),
            Err(PolicyViolation::Platform(Platform::AwsNitro))
        );
        let mut p2 = policy();
        p2.blocked_platforms.insert(Hash32([2; 32]));
        assert_eq!(
            p2.appraise(&report(), &[9; 64]),
            Err(PolicyViolation::BlockedPlatform)
        );
    }

    #[test]
    fn minimum_tcb_accepts_better_statuses_and_never_revoked() {
        let mut p = policy();
        p.min_tcb = TcbStatus::SwHardeningNeeded;
        for (tcb, ok) in [
            (TcbStatus::UpToDate, true),
            (TcbStatus::SwHardeningNeeded, true),
            (TcbStatus::ConfigurationNeeded, false),
            (TcbStatus::OutOfDate, false),
            (TcbStatus::Revoked, false),
        ] {
            let r = VerifiedReport { tcb, ..report() };
            assert_eq!(p.appraise(&r, &[9; 64]).is_ok(), ok, "{tcb:?}");
        }
        p.min_tcb = TcbStatus::Revoked;
        let r = VerifiedReport {
            tcb: TcbStatus::Revoked,
            ..report()
        };
        assert_eq!(
            p.appraise(&r, &[9; 64]),
            Err(PolicyViolation::Tcb(TcbStatus::Revoked))
        );
    }

    #[test]
    fn td_fields_are_appraised_for_tdx_reports() {
        let p = production();
        assert!(p.appraise(&tdx_report(), &[9; 64]).is_ok());

        let missing = VerifiedReport {
            td: None,
            ..tdx_report()
        };
        assert_eq!(
            p.appraise(&missing, &[9; 64]),
            Err(PolicyViolation::MissingTdFields)
        );
        type Edit = fn(&mut TdFields);
        let edits: [(Edit, PolicyViolation); 4] = [
            (|td| td.mr_config_id[0] ^= 1, PolicyViolation::MrConfigId),
            (|td| td.xfam[0] ^= 1, PolicyViolation::Xfam),
            (
                |td| td.td_attributes = [0; 8],
                PolicyViolation::TdAttributes,
            ),
            // Another attribute set instead of the required one.
            (
                |td| td.td_attributes = (1u64 << 30).to_le_bytes(),
                PolicyViolation::TdAttributes,
            ),
        ];
        for (edit, violation) in edits {
            let mut r = tdx_report();
            let mut td = td_fields();
            edit(&mut td);
            r.td = Some(td);
            assert_eq!(p.appraise(&r, &[9; 64]), Err(violation));
        }
        // The pins are checked in a fixed order.
        let mut r = tdx_report();
        r.td = Some(TdFields {
            mr_config_id: [0; 48],
            xfam: [0; 8],
            td_attributes: [0; 8],
            ..td_fields()
        });
        assert_eq!(p.appraise(&r, &[9; 64]), Err(PolicyViolation::MrConfigId));
        r.td = Some(TdFields {
            xfam: [0; 8],
            td_attributes: [0; 8],
            ..td_fields()
        });
        assert_eq!(p.appraise(&r, &[9; 64]), Err(PolicyViolation::Xfam));
        // TD checks run before the report data check.
        let mut r = tdx_report();
        r.td = Some(TdFields {
            xfam: [0; 8],
            ..td_fields()
        });
        assert_eq!(p.appraise(&r, &[0; 64]), Err(PolicyViolation::Xfam));
        // Bits outside the rule's mask are free. Owner fields are not pinned.
        let mut r = tdx_report();
        r.td = Some(TdFields {
            td_attributes: ((1u64 << 28) | (1u64 << 30)).to_le_bytes(),
            mr_owner: [5; 48],
            ..td_fields()
        });
        assert!(p.appraise(&r, &[9; 64]).is_ok());
    }

    #[test]
    fn unpinned_td_fields_accept_any_value() {
        let mut p = production();
        p.td = TdPolicy::default();
        let mut r = tdx_report();
        r.td = Some(TdFields {
            mr_config_id: [0; 48],
            xfam: [0; 8],
            td_attributes: [0; 8],
            ..td_fields()
        });
        assert!(p.appraise(&r, &[9; 64]).is_ok());
    }

    #[test]
    fn attributes_rule_is_mask_and_value() {
        let rule = TdAttributesRule {
            mask: 0b1011u64.to_le_bytes(),
            value: 0b0010u64.to_le_bytes(),
        };
        assert!(rule.matches(&0b0010u64.to_le_bytes()));
        assert!(rule.matches(&0b0110u64.to_le_bytes()));
        assert!(!rule.matches(&0b0011u64.to_le_bytes()));
        assert!(!rule.matches(&0b1010u64.to_le_bytes()));
        let require = TdAttributesRule::require(SEPT_VE_DISABLE);
        assert!(require.matches(&((1u64 << 28) | 1).to_le_bytes()));
        assert!(!require.matches(&[0; 8]));
    }

    #[test]
    fn debug_needs_allow_debug_and_a_rule_that_admits_the_debug_bit() {
        let debug_attrs = (SEPT_VE_DISABLE_BIT | 1).to_le_bytes();
        let debug_td = VerifiedReport {
            debug: true,
            td: Some(TdFields {
                td_attributes: debug_attrs,
                ..td_fields()
            }),
            ..tdx_report()
        };
        let mut p = production();
        assert_eq!(p.appraise(&debug_td, &[9; 64]), Err(PolicyViolation::Debug));
        p.allow_debug = true;
        // The production rule leaves bit 0 out of its mask.
        assert!(p.appraise(&debug_td, &[9; 64]).is_ok());
        // A rule that covers bit 0 with value 0 refuses debug TDs too.
        p.td.attributes = Some(TdAttributesRule {
            mask: (SEPT_VE_DISABLE_BIT | 1).to_le_bytes(),
            value: SEPT_VE_DISABLE,
        });
        assert_eq!(
            p.appraise(&debug_td, &[9; 64]),
            Err(PolicyViolation::TdAttributes)
        );
        assert!(p.appraise(&tdx_report(), &[9; 64]).is_ok());
    }

    #[test]
    fn production_profile_rules() {
        assert_eq!(production().check_profile(Profile::Production), Ok(()));
        let mut p = production();
        p.min_tcb = TcbStatus::SwHardeningNeeded;
        assert_eq!(p.check_profile(Profile::Production), Ok(()));

        let mut bad = production();
        bad.platforms.insert(Platform::Simulated);
        bad.allow_debug = true;
        bad.min_tcb = TcbStatus::ConfigurationNeeded;
        bad.td = TdPolicy::default();
        assert_eq!(
            bad.check_profile(Profile::Production),
            Err(vec![
                ProfileIssue::SimulatedPlatform,
                ProfileIssue::DebugAllowed,
                ProfileIssue::TcbTooLow(TcbStatus::ConfigurationNeeded),
                ProfileIssue::NoTdAttributes,
                ProfileIssue::NoXfam,
                ProfileIssue::NoMrConfigId,
            ])
        );
        for profile in [Profile::Local, Profile::Devnet] {
            assert_eq!(bad.check_profile(profile), Ok(()));
        }
        for (edit, issue) in [
            (
                (|p: &mut AttestationPolicy| p.min_tcb = TcbStatus::OutOfDate)
                    as fn(&mut AttestationPolicy),
                ProfileIssue::TcbTooLow(TcbStatus::OutOfDate),
            ),
            (|p| p.td.attributes = None, ProfileIssue::NoTdAttributes),
            (|p| p.td.xfam = None, ProfileIssue::NoXfam),
            (|p| p.td.mr_config_id = None, ProfileIssue::NoMrConfigId),
        ] {
            let mut p = production();
            edit(&mut p);
            assert_eq!(p.check_profile(Profile::Production), Err(vec![issue]));
        }
    }

    #[test]
    fn statement_fields() {
        let s = production().statement();
        assert_eq!(s.platforms, PLATFORM_BIT_INTEL_TDX);
        assert!(!s.allow_debug);
        assert_eq!(s.min_tcb, 0);
        assert_eq!(s.mr_config_id, [7; 48]);

        let mut p = policy();
        p.platforms.insert(Platform::IntelTdx);
        p.platforms.insert(Platform::AmdSevSnp);
        p.allow_debug = true;
        p.min_tcb = TcbStatus::OutOfDate;
        let s = p.statement();
        assert_eq!(s.platforms, PLATFORM_BIT_SIMULATED | PLATFORM_BIT_INTEL_TDX);
        assert!(s.allow_debug);
        assert_eq!(s.min_tcb, 3);
        assert_eq!(s.mr_config_id, [0; 48]);

        // The measurement digest depends on the set, not on insertion order.
        let a = Measurement(Hash32([1; 32]));
        let b = Measurement(Hash32([2; 32]));
        let one = AttestationPolicy::strict([Platform::IntelTdx], [a, b]).statement();
        let two = AttestationPolicy::strict([Platform::IntelTdx], [b, a, b]).statement();
        let only_a = AttestationPolicy::strict([Platform::IntelTdx], [a]).statement();
        assert_eq!(one.measurement_set_digest, two.measurement_set_digest);
        assert_ne!(one.measurement_set_digest, only_a.measurement_set_digest);
    }

    #[test]
    fn plan_filters_unhealthy_and_oversized() {
        let e = ExecutionPolicy {
            backends: vec![BackendKind::Tee, BackendKind::Mpc],
            proof: ProofMode::None,
            attempts_per_backend: 2,
            attempt_timeout: Duration::from_secs(1),
            mpc_max_batch: 100,
        };
        let all: BTreeSet<_> = [BackendKind::Tee, BackendKind::Mpc].into_iter().collect();
        assert_eq!(e.plan(10, &all), vec![BackendKind::Tee, BackendKind::Mpc]);
        assert_eq!(e.plan(1000, &all), vec![BackendKind::Tee]);
        let mpc_only: BTreeSet<_> = [BackendKind::Mpc].into_iter().collect();
        assert_eq!(e.plan(10, &mpc_only), vec![BackendKind::Mpc]);
    }
}
