//! Member and dealer configuration files, parsed with
//! `deny_unknown_fields`.
//!
//! A file holds one table, `[member]` or `[dealer]` ([`MemberFile`],
//! [`DealerFile`]). [`Validate`] reports every rule a file breaks at once.
//! Some rules apply under `profile = "production"`
//! only. Relative paths in a file are relative to the file's directory
//! ([`MemberConfig::resolve_paths`], [`DealerConfig::resolve_paths`]).

use std::collections::BTreeSet;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use timescales_chain::{Address, Level};
use timescales_core::{Decode, Hash32};
use timescales_executor::attestation::{Measurement, Platform, TcbStatus};
use timescales_executor::policy::{AttestationPolicy, TdAttributesRule, TdPolicy};
use timescales_executor::tee::MAX_RELEASES_PER_EPOCH;
use timescales_service::wire::CommitteeDescription;
use timescales_service::{
    ConfigIssue, MAINNET_BETA_GENESIS_HASH, Profile, TelemetryConfig, TlsConfig, Validate, rules,
};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketEntry {
    /// Market address (base58).
    pub address: String,
    pub committee_file: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    pub cluster: String,
    pub genesis_hash: String,
    pub program_id: String,
    pub rpc_urls: Vec<String>,
    /// Providers that must agree on release-critical reads.
    #[serde(default = "one")]
    pub rpc_agree: usize,
    #[serde(default)]
    pub release_commitment: Option<String>,
    #[serde(default)]
    pub confirmed_cache_ms: Option<u64>,
    pub rpc_timeout_ms: u64,
}

fn one() -> usize {
    1
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// `"simulated"` (sim-platform builds) and/or `"intel_tdx"`.
    pub platforms: Vec<String>,
    /// Hex measurements.
    pub measurements: Vec<String>,
    pub allow_debug: bool,
    pub min_tcb: String,
    #[serde(default)]
    pub simulated_vendor_root: Option<String>,
    #[serde(default)]
    pub tdx_collateral_file: Option<PathBuf>,
    #[serde(default)]
    pub tdx_mr_config_id: String,
    #[serde(default)]
    pub tdx_td_attributes_mask: String,
    #[serde(default)]
    pub tdx_xfam: String,
}

/// `[member]`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberConfig {
    pub profile: Profile,
    /// Position in the committee description, 1..=n.
    pub index: u8,
    pub listen: String,
    pub ops_listen: String,
    pub data_dir: PathBuf,
    pub identity_key: PathBuf,
    pub transport_key: PathBuf,
    pub kek_file: PathBuf,
    pub kek_ratchet_epochs: u64,
    /// Never backed up or replicated.
    pub shares_dir: PathBuf,
    pub dealer_keys: Vec<String>,
    pub skew_ms: u64,
    pub nonce_ttl_ms: u64,
    pub max_nonces_per_epoch_executor: u32,
    pub max_outstanding_nonces: u32,
    pub max_releases_per_epoch: u32,
    pub per_caller_rps: u32,
    pub per_caller_burst: u32,
    pub prune_interval_ms: u64,
    pub audit_retention_days: u32,
    #[serde(rename = "market")]
    pub markets: Vec<MarketEntry>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    pub chain: ChainConfig,
    pub policy: PolicyConfig,
    pub telemetry: TelemetryConfig,
}

/// `[dealer]`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DealerConfig {
    pub profile: Profile,
    pub data_dir: PathBuf,
    pub identity_key: PathBuf,
    /// At least the node's `max_park_ahead_epochs + 2`.
    pub lookahead_epochs: u64,
    pub interval_ms: u64,
    pub ack_timeout_ms: u64,
    pub node_url: String,
    pub node_identity: String,
    pub ops_listen: String,
    /// In member index order.
    pub member_urls: Vec<String>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(rename = "market")]
    pub markets: Vec<MarketEntry>,
    pub chain: ChainConfig,
    pub telemetry: TelemetryConfig,
}

/// A member configuration file.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberFile {
    pub member: MemberConfig,
}

/// A dealer configuration file.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DealerFile {
    pub dealer: DealerConfig,
}

impl Validate for MemberFile {
    fn validate(&self, profile: Profile) -> Result<(), Vec<ConfigIssue>> {
        into_result(self.member.issues(profile))
    }
}

impl Validate for DealerFile {
    fn validate(&self, profile: Profile) -> Result<(), Vec<ConfigIssue>> {
        into_result(self.dealer.issues(profile))
    }
}

fn into_result(issues: Vec<ConfigIssue>) -> Result<(), Vec<ConfigIssue>> {
    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

/// Largest committee file read (#5 is at most 1,078 bytes).
const MAX_COMMITTEE_FILE: u64 = 4096;
/// Most epochs a dealer deals ahead.
const MAX_LOOKAHEAD: u64 = 1024;

pub fn parse_b58_32(s: &str) -> Option<[u8; 32]> {
    bs58::decode(s).into_vec().ok()?.try_into().ok()
}

pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

fn resolve(base: &Path, path: &mut PathBuf) {
    if path.is_relative() && !path.as_os_str().is_empty() {
        *path = base.join(&*path);
    }
}

fn resolve_tls(base: &Path, tls: &mut Option<TlsConfig>) {
    if let Some(t) = tls.as_mut().filter(|t| t.is_configured()) {
        resolve(base, &mut t.cert_file);
        resolve(base, &mut t.key_file);
    }
}

/// Reads and checks the committee description of `address`: it decodes
/// exactly, is valid and names that market.
pub fn load_committee(path: &Path, address: &Address) -> Result<CommitteeDescription, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_COMMITTEE_FILE + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_COMMITTEE_FILE {
        return Err(format!("{} is larger than a committee", path.display()));
    }
    let committee = CommitteeDescription::decode_exact(&bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    committee
        .validate()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if committee.market != *address {
        return Err(format!("{} describes another market", path.display()));
    }
    Ok(committee)
}

impl ChainConfig {
    pub fn genesis(&self) -> Option<[u8; 32]> {
        parse_b58_32(&self.genesis_hash)
    }

    pub fn program(&self) -> Option<Address> {
        parse_b58_32(&self.program_id)
    }

    /// The commitment level of release-critical reads.
    pub fn release_level(&self) -> Level {
        match self.release_commitment.as_deref() {
            Some("confirmed") => Level::Confirmed,
            _ => Level::Finalized,
        }
    }

    fn issues(&self, field: &str, member: bool, profile: Profile, issues: &mut Vec<ConfigIssue>) {
        if !["localnet", "devnet", "testnet", "mainnet-beta"].contains(&self.cluster.as_str()) {
            issues.push(ConfigIssue::new(
                format!("{field}.cluster"),
                "expected localnet, devnet, testnet or mainnet-beta",
            ));
        }
        match self.genesis() {
            None => issues.push(ConfigIssue::new(
                format!("{field}.genesis_hash"),
                "expected a base58 32-byte hash",
            )),
            Some(g) if g == MAINNET_BETA_GENESIS_HASH && profile != Profile::Production => {
                issues.push(ConfigIssue::new(
                    format!("{field}.genesis_hash"),
                    format!("mainnet-beta refuses the {profile} profile"),
                ));
            }
            Some(_) => {}
        }
        if self.program().is_none() {
            issues.push(ConfigIssue::new(
                format!("{field}.program_id"),
                "expected a base58 32-byte address",
            ));
        }
        if self.rpc_urls.is_empty() {
            issues.push(ConfigIssue::new(
                format!("{field}.rpc_urls"),
                "at least one RPC URL is needed",
            ));
        }
        for (i, u) in self.rpc_urls.iter().enumerate() {
            rules::url(&format!("{field}.rpc_urls[{i}]"), u, profile, issues);
        }
        let distinct: BTreeSet<&String> = self.rpc_urls.iter().collect();
        if distinct.len() != self.rpc_urls.len() {
            issues.push(ConfigIssue::new(
                format!("{field}.rpc_urls"),
                "the same URL is listed twice",
            ));
        }
        if self.rpc_timeout_ms == 0 {
            issues.push(ConfigIssue::new(
                format!("{field}.rpc_timeout_ms"),
                "must be positive",
            ));
        }
        if !member {
            if self.release_commitment.is_some() || self.confirmed_cache_ms.is_some() {
                issues.push(ConfigIssue::new(
                    field,
                    "release_commitment and confirmed_cache_ms are member settings",
                ));
            }
            if self.rpc_agree != 1 {
                issues.push(ConfigIssue::new(
                    format!("{field}.rpc_agree"),
                    "the dealer reads from one provider at a time",
                ));
            }
            return;
        }
        if self.rpc_agree == 0 || self.rpc_agree > self.rpc_urls.len() {
            issues.push(ConfigIssue::new(
                format!("{field}.rpc_agree"),
                "must be between 1 and the number of rpc_urls",
            ));
        }
        match self.release_commitment.as_deref() {
            None | Some("finalized") => {}
            Some("confirmed") if profile == Profile::Local => {}
            Some("confirmed") => issues.push(ConfigIssue::new(
                format!("{field}.release_commitment"),
                "\"confirmed\" is allowed in profile local only",
            )),
            Some(other) => issues.push(ConfigIssue::new(
                format!("{field}.release_commitment"),
                format!("expected \"finalized\" or \"confirmed\", got {other:?}"),
            )),
        }
        if self.confirmed_cache_ms.is_some_and(|ms| ms > 2_000) {
            issues.push(ConfigIssue::new(
                format!("{field}.confirmed_cache_ms"),
                "at most 2000 (caches registrations for at most 2 s)",
            ));
        }
        if profile == Profile::Production {
            if self.rpc_urls.len() < 2 {
                issues.push(ConfigIssue::new(
                    format!("{field}.rpc_urls"),
                    "production needs at least 2 independent providers",
                ));
            }
            if self.rpc_agree < 2 {
                issues.push(ConfigIssue::new(
                    format!("{field}.rpc_agree"),
                    "production needs at least 2 agreeing providers",
                ));
            }
        }
    }
}

fn markets_issues(field: &str, markets: &[MarketEntry], issues: &mut Vec<ConfigIssue>) {
    if markets.is_empty() {
        issues.push(ConfigIssue::new(field, "at least one market is needed"));
    }
    let mut seen = BTreeSet::new();
    for (i, m) in markets.iter().enumerate() {
        match parse_b58_32(&m.address) {
            None => issues.push(ConfigIssue::new(
                format!("{field}[{i}].address"),
                "expected a base58 32-byte address",
            )),
            Some(a) if !seen.insert(a) => issues.push(ConfigIssue::new(
                format!("{field}[{i}].address"),
                "market listed twice",
            )),
            Some(_) => {}
        }
        if m.committee_file.as_os_str().is_empty() {
            issues.push(ConfigIssue::new(
                format!("{field}[{i}].committee_file"),
                "missing",
            ));
        }
    }
}

fn listen_issue(field: &str, addr: &str, issues: &mut Vec<ConfigIssue>) {
    if addr.parse::<SocketAddr>().is_err() {
        issues.push(ConfigIssue::new(field, format!("{addr:?} is not ip:port")));
    }
}

fn positive(field: &str, value: u64, issues: &mut Vec<ConfigIssue>) {
    if value == 0 {
        issues.push(ConfigIssue::new(field, "must be positive"));
    }
}

/// Market addresses of a validated configuration, in file order.
fn addresses(markets: &[MarketEntry]) -> Vec<Address> {
    markets
        .iter()
        .filter_map(|m| parse_b58_32(&m.address))
        .collect()
}

impl PolicyConfig {
    /// The appraisal policy this configuration describes.
    pub fn attestation_policy(&self) -> Result<AttestationPolicy, Vec<ConfigIssue>> {
        let mut issues = Vec::new();
        let policy = self.build(&mut issues);
        if issues.is_empty() {
            Ok(policy)
        } else {
            Err(issues)
        }
    }

    pub fn simulated(&self) -> bool {
        self.platforms.iter().any(|p| p == "simulated")
    }

    pub fn intel_tdx(&self) -> bool {
        self.platforms.iter().any(|p| p == "intel_tdx")
    }

    fn build(&self, issues: &mut Vec<ConfigIssue>) -> AttestationPolicy {
        const F: &str = "member.policy";
        let mut platforms = BTreeSet::new();
        if self.platforms.is_empty() {
            issues.push(ConfigIssue::new(
                format!("{F}.platforms"),
                "at least one platform is needed",
            ));
        }
        for p in &self.platforms {
            match p.as_str() {
                "simulated" => {
                    platforms.insert(Platform::Simulated);
                }
                "intel_tdx" => {
                    platforms.insert(Platform::IntelTdx);
                }
                other => issues.push(ConfigIssue::new(
                    format!("{F}.platforms"),
                    format!("unknown platform {other:?}"),
                )),
            }
        }
        let mut measurements = BTreeSet::new();
        if self.measurements.is_empty() {
            issues.push(ConfigIssue::new(
                format!("{F}.measurements"),
                "at least one measurement is needed",
            ));
        }
        for (i, m) in self.measurements.iter().enumerate() {
            match parse_hex::<32>(m) {
                Some(b) => {
                    measurements.insert(Measurement(Hash32(b)));
                }
                None => issues.push(ConfigIssue::new(
                    format!("{F}.measurements[{i}]"),
                    "expected 64 hex digits",
                )),
            }
        }
        let min_tcb = match self.min_tcb.as_str() {
            "up_to_date" => TcbStatus::UpToDate,
            "sw_hardening_needed" => TcbStatus::SwHardeningNeeded,
            "configuration_needed" => TcbStatus::ConfigurationNeeded,
            "out_of_date" => TcbStatus::OutOfDate,
            other => {
                issues.push(ConfigIssue::new(
                    format!("{F}.min_tcb"),
                    format!("unknown TCB status {other:?}"),
                ));
                TcbStatus::UpToDate
            }
        };
        let mut td = TdPolicy::default();
        if !self.tdx_mr_config_id.is_empty() {
            match parse_hex::<48>(&self.tdx_mr_config_id) {
                Some(b) => td.mr_config_id = Some(b),
                None => issues.push(ConfigIssue::new(
                    format!("{F}.tdx_mr_config_id"),
                    "expected 96 hex digits",
                )),
            }
        }
        if !self.tdx_td_attributes_mask.is_empty() {
            match parse_hex::<8>(&self.tdx_td_attributes_mask) {
                Some(b) => td.attributes = Some(TdAttributesRule::require(b)),
                None => issues.push(ConfigIssue::new(
                    format!("{F}.tdx_td_attributes_mask"),
                    "expected 16 hex digits",
                )),
            }
        }
        if !self.tdx_xfam.is_empty() {
            match parse_hex::<8>(&self.tdx_xfam) {
                Some(b) => td.xfam = Some(b),
                None => issues.push(ConfigIssue::new(
                    format!("{F}.tdx_xfam"),
                    "expected 16 hex digits",
                )),
            }
        }
        match (&self.simulated_vendor_root, self.simulated()) {
            (Some(root), true) if parse_hex::<32>(root).is_none() => {
                issues.push(ConfigIssue::new(
                    format!("{F}.simulated_vendor_root"),
                    "expected 64 hex digits",
                ));
            }
            (None, true) => issues.push(ConfigIssue::new(
                format!("{F}.simulated_vendor_root"),
                "required when \"simulated\" is a platform",
            )),
            (Some(_), false) => issues.push(ConfigIssue::new(
                format!("{F}.simulated_vendor_root"),
                "set although \"simulated\" is not a platform",
            )),
            _ => {}
        }
        if self.simulated() && !timescales_executor::attestation::SIM_PLATFORM_BUILD {
            issues.push(ConfigIssue::new(
                format!("{F}.platforms"),
                "\"simulated\" needs a build with the sim-platform feature",
            ));
        }
        if self.intel_tdx()
            && self
                .tdx_collateral_file
                .as_ref()
                .is_none_or(|p| p.as_os_str().is_empty())
        {
            issues.push(ConfigIssue::new(
                format!("{F}.tdx_collateral_file"),
                "required when \"intel_tdx\" is a platform",
            ));
        }
        AttestationPolicy {
            platforms,
            measurements,
            min_tcb,
            allow_debug: self.allow_debug,
            blocked_platforms: BTreeSet::new(),
            td,
        }
    }
}

impl MemberConfig {
    /// Every rule this configuration breaks under `profile`.
    pub fn issues(&self, profile: Profile) -> Vec<ConfigIssue> {
        const F: &str = "member";
        let mut issues = Vec::new();
        if !(1..=timescales_executor::tee::MAX_COMMITTEE).contains(&self.index) {
            issues.push(ConfigIssue::new(format!("{F}.index"), "must be 1..=16"));
        }
        listen_issue(&format!("{F}.listen"), &self.listen, &mut issues);
        listen_issue(&format!("{F}.ops_listen"), &self.ops_listen, &mut issues);
        for (field, path) in [
            ("data_dir", &self.data_dir),
            ("identity_key", &self.identity_key),
            ("transport_key", &self.transport_key),
            ("kek_file", &self.kek_file),
            ("shares_dir", &self.shares_dir),
        ] {
            if path.as_os_str().is_empty() {
                issues.push(ConfigIssue::new(format!("{F}.{field}"), "missing"));
            }
        }
        if self.shares_dir == self.data_dir
            || (profile == Profile::Production && self.shares_dir.starts_with(&self.data_dir))
        {
            issues.push(ConfigIssue::new(
                format!("{F}.shares_dir"),
                "shares.sqlite must live outside data_dir (it is never backed up)",
            ));
        }
        positive(
            &format!("{F}.kek_ratchet_epochs"),
            self.kek_ratchet_epochs,
            &mut issues,
        );
        if self.dealer_keys.is_empty() {
            issues.push(ConfigIssue::new(
                format!("{F}.dealer_keys"),
                "at least one dealer key is needed",
            ));
        }
        for (i, k) in self.dealer_keys.iter().enumerate() {
            if parse_hex::<32>(k).is_none() {
                issues.push(ConfigIssue::new(
                    format!("{F}.dealer_keys[{i}]"),
                    "expected 64 hex digits",
                ));
            }
        }
        if self.skew_ms == 0 || self.skew_ms > 30_000 {
            issues.push(ConfigIssue::new(
                format!("{F}.skew_ms"),
                "must be 1..=30000",
            ));
        }
        positive(&format!("{F}.nonce_ttl_ms"), self.nonce_ttl_ms, &mut issues);
        positive(
            &format!("{F}.max_nonces_per_epoch_executor"),
            self.max_nonces_per_epoch_executor.into(),
            &mut issues,
        );
        positive(
            &format!("{F}.max_outstanding_nonces"),
            self.max_outstanding_nonces.into(),
            &mut issues,
        );
        if !(1..=MAX_RELEASES_PER_EPOCH).contains(&self.max_releases_per_epoch) {
            issues.push(ConfigIssue::new(
                format!("{F}.max_releases_per_epoch"),
                format!("must be 1..={MAX_RELEASES_PER_EPOCH}"),
            ));
        }
        positive(
            &format!("{F}.per_caller_rps"),
            self.per_caller_rps.into(),
            &mut issues,
        );
        positive(
            &format!("{F}.per_caller_burst"),
            self.per_caller_burst.into(),
            &mut issues,
        );
        positive(
            &format!("{F}.prune_interval_ms"),
            self.prune_interval_ms,
            &mut issues,
        );
        positive(
            &format!("{F}.audit_retention_days"),
            self.audit_retention_days.into(),
            &mut issues,
        );
        markets_issues(&format!("{F}.market"), &self.markets, &mut issues);
        rules::tls(&format!("{F}.tls"), self.tls.as_ref(), profile, &mut issues);
        self.chain
            .issues(&format!("{F}.chain"), true, profile, &mut issues);
        let policy = self.policy.build(&mut issues);
        if let Err(broken) = policy.check_profile(policy_profile(profile)) {
            for b in broken {
                issues.push(ConfigIssue::new(format!("{F}.policy"), b.to_string()));
            }
        }
        rules::telemetry(
            &format!("{F}.telemetry"),
            &self.telemetry,
            profile,
            &mut issues,
        );
        issues
    }

    /// Makes every relative path absolute against `base`, the directory of
    /// the configuration file.
    pub fn resolve_paths(&mut self, base: &Path) {
        for p in [
            &mut self.data_dir,
            &mut self.identity_key,
            &mut self.transport_key,
            &mut self.kek_file,
            &mut self.shares_dir,
        ] {
            resolve(base, p);
        }
        for m in &mut self.markets {
            resolve(base, &mut m.committee_file);
        }
        if let Some(p) = self.policy.tdx_collateral_file.as_mut() {
            resolve(base, p);
        }
        resolve_tls(base, &mut self.tls);
    }

    pub fn market_addresses(&self) -> Vec<Address> {
        addresses(&self.markets)
    }

    pub fn dealer_key_set(&self) -> BTreeSet<[u8; 32]> {
        self.dealer_keys
            .iter()
            .filter_map(|k| parse_hex::<32>(k))
            .collect()
    }
}

impl DealerConfig {
    /// Every rule this configuration breaks under `profile`.
    pub fn issues(&self, profile: Profile) -> Vec<ConfigIssue> {
        const F: &str = "dealer";
        let mut issues = Vec::new();
        for (field, path) in [
            ("data_dir", &self.data_dir),
            ("identity_key", &self.identity_key),
        ] {
            if path.as_os_str().is_empty() {
                issues.push(ConfigIssue::new(format!("{F}.{field}"), "missing"));
            }
        }
        if !(2..=MAX_LOOKAHEAD).contains(&self.lookahead_epochs) {
            issues.push(ConfigIssue::new(
                format!("{F}.lookahead_epochs"),
                format!(
                    "must be 2..={MAX_LOOKAHEAD} (at least the node's max_park_ahead_epochs + 2)"
                ),
            ));
        }
        positive(&format!("{F}.interval_ms"), self.interval_ms, &mut issues);
        positive(
            &format!("{F}.ack_timeout_ms"),
            self.ack_timeout_ms,
            &mut issues,
        );
        rules::url(
            &format!("{F}.node_url"),
            &self.node_url,
            profile,
            &mut issues,
        );
        if parse_hex::<32>(&self.node_identity).is_none() {
            issues.push(ConfigIssue::new(
                format!("{F}.node_identity"),
                "expected 64 hex digits",
            ));
        }
        listen_issue(&format!("{F}.ops_listen"), &self.ops_listen, &mut issues);
        if self.member_urls.is_empty() {
            issues.push(ConfigIssue::new(
                format!("{F}.member_urls"),
                "at least one member URL is needed",
            ));
        }
        for (i, u) in self.member_urls.iter().enumerate() {
            rules::url(&format!("{F}.member_urls[{i}]"), u, profile, &mut issues);
        }
        rules::tls(&format!("{F}.tls"), self.tls.as_ref(), profile, &mut issues);
        markets_issues(&format!("{F}.market"), &self.markets, &mut issues);
        self.chain
            .issues(&format!("{F}.chain"), false, profile, &mut issues);
        rules::telemetry(
            &format!("{F}.telemetry"),
            &self.telemetry,
            profile,
            &mut issues,
        );
        issues
    }

    /// Makes every relative path absolute against `base`, the directory of
    /// the configuration file.
    pub fn resolve_paths(&mut self, base: &Path) {
        resolve(base, &mut self.data_dir);
        resolve(base, &mut self.identity_key);
        for m in &mut self.markets {
            resolve(base, &mut m.committee_file);
        }
        resolve_tls(base, &mut self.tls);
    }

    pub fn market_addresses(&self) -> Vec<Address> {
        addresses(&self.markets)
    }

    pub fn node_key(&self) -> Option<[u8; 32]> {
        parse_hex::<32>(&self.node_identity)
    }
}

pub(crate) fn policy_profile(profile: Profile) -> timescales_executor::policy::Profile {
    match profile {
        Profile::Local => timescales_executor::policy::Profile::Local,
        Profile::Devnet => timescales_executor::policy::Profile::Devnet,
        Profile::Production => timescales_executor::policy::Profile::Production,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_base58_parse_exact_lengths() {
        assert_eq!(parse_hex::<2>("0aff"), Some([0x0a, 0xff]));
        assert_eq!(parse_hex::<2>("0aff00"), None);
        assert_eq!(parse_hex::<2>("zz00"), None);
        let key = [7u8; 32];
        assert_eq!(parse_b58_32(&bs58::encode(key).into_string()), Some(key));
        assert_eq!(parse_b58_32(&bs58::encode([7u8; 31]).into_string()), None);
    }

    #[test]
    fn relative_paths_resolve_against_the_file() {
        let mut p = PathBuf::from("committee.bin");
        resolve(Path::new("/etc/timescales"), &mut p);
        assert_eq!(p, PathBuf::from("/etc/timescales/committee.bin"));
        let mut abs = PathBuf::from("/var/lib/x");
        resolve(Path::new("/etc"), &mut abs);
        assert_eq!(abs, PathBuf::from("/var/lib/x"));
        let mut empty = PathBuf::new();
        resolve(Path::new("/etc"), &mut empty);
        assert!(empty.as_os_str().is_empty());
    }
}
