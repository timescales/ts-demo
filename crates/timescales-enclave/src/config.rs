//! `timescales-enclave` configuration, parsed with
//! `deny_unknown_fields`.
//!
//! A file holds one `[enclave]` table ([`EnclaveFile`]). [`Validate`]
//! reports every rule the file breaks at once. Some rules apply under
//! `profile = "production"` only. Relative paths are
//! relative to the file's directory ([`EnclaveConfig::resolve_paths`]).

use std::collections::BTreeSet;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use timescales_chain::{Address, FeeMode, FeePolicy};
use timescales_core::Decode;
use timescales_service::wire::{ChainId, CommitteeDescription};
use timescales_service::{
    ConfigIssue, MAINNET_BETA_GENESIS_HASH, Profile, TelemetryConfig, TlsConfig, Validate, rules,
};

use crate::PlatformMode;

/// Where the kernel mounts configfs-tsm when `tdx_configfs_root` is not set.
pub const DEFAULT_TDX_CONFIGFS_ROOT: &str = "/sys/kernel/config/tsm/report";

/// Compute-unit margin over the simulated consumption of every transaction.
const CU_MARGIN_PCT: u8 = 20;
/// Largest committee file read (#5 is at most 1,078 bytes).
const MAX_COMMITTEE_FILE: u64 = 4096;
/// Smallest `max_body_bytes` that still holds an `ExecuteRequest` with one
/// envelope and its provenance.
const MIN_BODY_BYTES: u64 = 64 * 1024;
/// Largest `max_body_bytes` (#15: 16 MiB plus the envelope).
const MAX_BODY_BYTES: u64 = 17 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    Simulated,
    IntelTdx,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveMarket {
    pub address: String,
    pub committee_file: PathBuf,
    /// Grant domains accepted by the provenance check.
    pub session_domains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityFee {
    pub mode: String,
    pub fixed_micro_lamports: String,
    pub percentile: u8,
    pub max_micro_lamports: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveChain {
    pub cluster: String,
    pub genesis_hash: String,
    pub program_id: String,
    pub rpc_urls: Vec<String>,
    pub rpc_agree: usize,
    pub rpc_timeout_ms: u64,
    pub poll_interval_ms: u64,
    pub priority_fee: PriorityFee,
}

/// `[enclave]`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveConfig {
    pub profile: Profile,
    pub listen: String,
    pub ops_listen: String,
    pub platform: PlatformKind,
    /// Simulated only.
    #[serde(default)]
    pub simulated_key_file: Option<PathBuf>,
    /// Simulated only: dev CA. No security.
    #[serde(default)]
    pub simulated_vendor_seed: Option<PathBuf>,
    /// Intel TDX only. Untested on hardware.
    #[serde(default)]
    pub tdx_configfs_root: Option<PathBuf>,
    pub fee_payer_keypair: PathBuf,
    pub node_keys: Vec<String>,
    pub member_urls: Vec<String>,
    pub member_timeout_ms: u64,
    pub post_deadline_ms: u64,
    pub settle_backstop_after_ms: u64,
    pub reveal_backstop_slots: u64,
    pub allow_sign_message_grants: bool,
    pub max_concurrent_executions: u32,
    pub max_body_bytes: u64,
    pub result_cache_entries: u32,
    #[serde(rename = "market")]
    pub markets: Vec<EnclaveMarket>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    pub chain: EnclaveChain,
    pub telemetry: TelemetryConfig,
}

/// An enclave configuration file.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveFile {
    pub enclave: EnclaveConfig,
}

impl Validate for EnclaveFile {
    fn validate(&self, profile: Profile) -> Result<(), Vec<ConfigIssue>> {
        let issues = self.enclave.issues(profile);
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }
}

pub fn parse_b58_32(s: &str) -> Option<[u8; 32]> {
    bs58::decode(s).into_vec().ok()?.try_into().ok()
}

pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

fn resolve(base: &Path, path: &mut PathBuf) {
    if path.is_relative() && !path.as_os_str().is_empty() {
        *path = base.join(&*path);
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

fn positive(field: &str, value: u64, issues: &mut Vec<ConfigIssue>) {
    if value == 0 {
        issues.push(ConfigIssue::new(field, "must be positive"));
    }
}

fn listen_issue(field: &str, addr: &str, issues: &mut Vec<ConfigIssue>) {
    if addr.parse::<SocketAddr>().is_err() {
        issues.push(ConfigIssue::new(field, format!("{addr:?} is not ip:port")));
    }
}

fn missing_path(path: Option<&PathBuf>) -> bool {
    path.is_none_or(|p| p.as_os_str().is_empty())
}

impl EnclaveChain {
    pub fn genesis(&self) -> Option<[u8; 32]> {
        parse_b58_32(&self.genesis_hash)
    }

    pub fn program(&self) -> Option<Address> {
        parse_b58_32(&self.program_id)
    }

    /// The SIWS chain id grants for this cluster name (`testnet` has none).
    pub fn chain_id(&self) -> Option<ChainId> {
        match self.cluster.as_str() {
            "localnet" => Some(ChainId::Localnet),
            "devnet" => Some(ChainId::Devnet),
            "mainnet-beta" => Some(ChainId::Mainnet),
            _ => None,
        }
    }

    /// The fee policy of every transaction the enclave pays for.
    pub fn fee_policy(&self) -> Option<FeePolicy> {
        let fixed = self.priority_fee.fixed_micro_lamports.parse::<u64>().ok()?;
        let max = self.priority_fee.max_micro_lamports.parse::<u64>().ok()?;
        let mode = match self.priority_fee.mode.as_str() {
            "fixed" => FeeMode::Fixed(fixed),
            "recent" => FeeMode::Recent,
            _ => return None,
        };
        Some(FeePolicy {
            mode,
            percentile: self.priority_fee.percentile,
            max_micro_lamports: max,
            cu_margin_pct: CU_MARGIN_PCT,
        })
    }

    fn issues(&self, profile: Profile, issues: &mut Vec<ConfigIssue>) {
        const F: &str = "enclave.chain";
        if self.chain_id().is_none() {
            issues.push(ConfigIssue::new(
                format!("{F}.cluster"),
                "expected localnet, devnet or mainnet-beta (session grants name no other chain)",
            ));
        }
        match self.genesis() {
            None => issues.push(ConfigIssue::new(
                format!("{F}.genesis_hash"),
                "expected a base58 32-byte hash",
            )),
            Some(g) if g == MAINNET_BETA_GENESIS_HASH && profile != Profile::Production => {
                issues.push(ConfigIssue::new(
                    format!("{F}.genesis_hash"),
                    format!("mainnet-beta refuses the {profile} profile"),
                ));
            }
            Some(_) => {}
        }
        if self.program().is_none() {
            issues.push(ConfigIssue::new(
                format!("{F}.program_id"),
                "expected a base58 32-byte address",
            ));
        }
        if self.rpc_urls.is_empty() {
            issues.push(ConfigIssue::new(
                format!("{F}.rpc_urls"),
                "at least one RPC URL is needed",
            ));
        }
        for (i, u) in self.rpc_urls.iter().enumerate() {
            rules::url(&format!("{F}.rpc_urls[{i}]"), u, profile, issues);
        }
        let distinct: BTreeSet<&String> = self.rpc_urls.iter().collect();
        if distinct.len() != self.rpc_urls.len() {
            issues.push(ConfigIssue::new(
                format!("{F}.rpc_urls"),
                "the same URL is listed twice",
            ));
        }
        if self.rpc_agree == 0 || self.rpc_agree > self.rpc_urls.len() {
            issues.push(ConfigIssue::new(
                format!("{F}.rpc_agree"),
                "must be between 1 and the number of rpc_urls",
            ));
        }
        positive(&format!("{F}.rpc_timeout_ms"), self.rpc_timeout_ms, issues);
        positive(
            &format!("{F}.poll_interval_ms"),
            self.poll_interval_ms,
            issues,
        );
        let fee = &self.priority_fee;
        if !["fixed", "recent"].contains(&fee.mode.as_str()) {
            issues.push(ConfigIssue::new(
                format!("{F}.priority_fee.mode"),
                "expected \"fixed\" or \"recent\"",
            ));
        }
        for (field, value) in [
            ("fixed_micro_lamports", &fee.fixed_micro_lamports),
            ("max_micro_lamports", &fee.max_micro_lamports),
        ] {
            if value.parse::<u64>().is_err() {
                issues.push(ConfigIssue::new(
                    format!("{F}.priority_fee.{field}"),
                    "expected a decimal u64 string",
                ));
            }
        }
        if fee.percentile > 100 {
            issues.push(ConfigIssue::new(
                format!("{F}.priority_fee.percentile"),
                "must be 0..=100",
            ));
        }
        if profile == Profile::Production {
            if self.rpc_urls.len() < 2 {
                issues.push(ConfigIssue::new(
                    format!("{F}.rpc_urls"),
                    "production needs at least 2 independent providers",
                ));
            }
            if self.rpc_agree < 2 {
                issues.push(ConfigIssue::new(
                    format!("{F}.rpc_agree"),
                    "production needs at least 2 agreeing providers",
                ));
            }
        }
    }
}

impl EnclaveConfig {
    /// Every rule this configuration breaks under `profile`.
    pub fn issues(&self, profile: Profile) -> Vec<ConfigIssue> {
        const F: &str = "enclave";
        let mut issues = Vec::new();
        listen_issue(&format!("{F}.listen"), &self.listen, &mut issues);
        listen_issue(&format!("{F}.ops_listen"), &self.ops_listen, &mut issues);
        match self.platform {
            PlatformKind::Simulated => {
                if profile == Profile::Production {
                    issues.push(ConfigIssue::new(
                        format!("{F}.platform"),
                        "the simulated platform has no security and is refused in production",
                    ));
                }
                for (field, path) in [
                    ("simulated_key_file", self.simulated_key_file.as_ref()),
                    ("simulated_vendor_seed", self.simulated_vendor_seed.as_ref()),
                ] {
                    if missing_path(path) {
                        issues.push(ConfigIssue::new(
                            format!("{F}.{field}"),
                            "required with platform \"simulated\"",
                        ));
                    }
                }
                if self.tdx_configfs_root.is_some() {
                    issues.push(ConfigIssue::new(
                        format!("{F}.tdx_configfs_root"),
                        "set although the platform is \"simulated\"",
                    ));
                }
            }
            PlatformKind::IntelTdx => {
                for (field, set) in [
                    ("simulated_key_file", self.simulated_key_file.is_some()),
                    (
                        "simulated_vendor_seed",
                        self.simulated_vendor_seed.is_some(),
                    ),
                ] {
                    if set {
                        issues.push(ConfigIssue::new(
                            format!("{F}.{field}"),
                            "set although the platform is \"intel_tdx\"",
                        ));
                    }
                }
                if self
                    .tdx_configfs_root
                    .as_ref()
                    .is_some_and(|p| p.as_os_str().is_empty())
                {
                    issues.push(ConfigIssue::new(
                        format!("{F}.tdx_configfs_root"),
                        "empty; leave it out for the kernel's default",
                    ));
                }
            }
        }
        if self.fee_payer_keypair.as_os_str().is_empty() {
            issues.push(ConfigIssue::new(
                format!("{F}.fee_payer_keypair"),
                "missing",
            ));
        }
        if self.node_keys.is_empty() {
            issues.push(ConfigIssue::new(
                format!("{F}.node_keys"),
                "at least one node key is needed",
            ));
        }
        for (i, k) in self.node_keys.iter().enumerate() {
            if parse_hex32(k).is_none() {
                issues.push(ConfigIssue::new(
                    format!("{F}.node_keys[{i}]"),
                    "expected 64 hex digits",
                ));
            }
        }
        if self.member_urls.is_empty() {
            issues.push(ConfigIssue::new(
                format!("{F}.member_urls"),
                "at least one member URL is needed",
            ));
        }
        for (i, u) in self.member_urls.iter().enumerate() {
            rules::url(&format!("{F}.member_urls[{i}]"), u, profile, &mut issues);
        }
        positive(
            &format!("{F}.member_timeout_ms"),
            self.member_timeout_ms,
            &mut issues,
        );
        positive(
            &format!("{F}.post_deadline_ms"),
            self.post_deadline_ms,
            &mut issues,
        );
        positive(
            &format!("{F}.settle_backstop_after_ms"),
            self.settle_backstop_after_ms,
            &mut issues,
        );
        positive(
            &format!("{F}.reveal_backstop_slots"),
            self.reveal_backstop_slots,
            &mut issues,
        );
        if profile == Profile::Production && self.allow_sign_message_grants {
            issues.push(ConfigIssue::new(
                format!("{F}.allow_sign_message_grants"),
                "production accepts solana:signIn grants only",
            ));
        }
        positive(
            &format!("{F}.max_concurrent_executions"),
            self.max_concurrent_executions.into(),
            &mut issues,
        );
        if !(MIN_BODY_BYTES..=MAX_BODY_BYTES).contains(&self.max_body_bytes) {
            issues.push(ConfigIssue::new(
                format!("{F}.max_body_bytes"),
                format!("must be {MIN_BODY_BYTES}..={MAX_BODY_BYTES}"),
            ));
        }
        positive(
            &format!("{F}.result_cache_entries"),
            self.result_cache_entries.into(),
            &mut issues,
        );
        self.markets_issues(&mut issues);
        rules::tls(&format!("{F}.tls"), self.tls.as_ref(), profile, &mut issues);
        self.chain.issues(profile, &mut issues);
        rules::telemetry(
            &format!("{F}.telemetry"),
            &self.telemetry,
            profile,
            &mut issues,
        );
        issues
    }

    fn markets_issues(&self, issues: &mut Vec<ConfigIssue>) {
        const F: &str = "enclave.market";
        if self.markets.is_empty() {
            issues.push(ConfigIssue::new(F, "at least one market is needed"));
        }
        let mut seen = BTreeSet::new();
        for (i, m) in self.markets.iter().enumerate() {
            match parse_b58_32(&m.address) {
                None => issues.push(ConfigIssue::new(
                    format!("{F}[{i}].address"),
                    "expected a base58 32-byte address",
                )),
                Some(a) if !seen.insert(a) => issues.push(ConfigIssue::new(
                    format!("{F}[{i}].address"),
                    "market listed twice",
                )),
                Some(_) => {}
            }
            if m.committee_file.as_os_str().is_empty() {
                issues.push(ConfigIssue::new(
                    format!("{F}[{i}].committee_file"),
                    "missing",
                ));
            }
            if m.session_domains.is_empty() {
                issues.push(ConfigIssue::new(
                    format!("{F}[{i}].session_domains"),
                    "at least one domain is needed, or no grant passes the provenance check",
                ));
            }
            if m.session_domains.iter().any(|d| d.trim().is_empty()) {
                issues.push(ConfigIssue::new(
                    format!("{F}[{i}].session_domains"),
                    "empty domain",
                ));
            }
        }
    }

    /// The checks of the files this configuration names that need no
    /// secret and no network: every committee description decodes, is
    /// valid, names its market and has one member URL per member.
    pub fn file_issues(&self) -> Vec<ConfigIssue> {
        let mut issues = Vec::new();
        for (i, (entry, address)) in self.markets.iter().zip(self.market_addresses()).enumerate() {
            let field = format!("enclave.market[{i}].committee_file");
            match load_committee(&entry.committee_file, &address) {
                Ok(c) if c.members.len() != self.member_urls.len() => {
                    issues.push(ConfigIssue::new(
                        "enclave.member_urls",
                        format!(
                            "{} URLs for a committee of {} (one per member, in index order)",
                            self.member_urls.len(),
                            c.members.len()
                        ),
                    ));
                }
                Ok(_) => {}
                Err(e) => issues.push(ConfigIssue::new(field, e)),
            }
        }
        issues
    }

    /// Makes every relative path absolute against `base`, the directory of
    /// the configuration file.
    pub fn resolve_paths(&mut self, base: &Path) {
        resolve(base, &mut self.fee_payer_keypair);
        for p in [
            self.simulated_key_file.as_mut(),
            self.simulated_vendor_seed.as_mut(),
            self.tdx_configfs_root.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            resolve(base, p);
        }
        for m in &mut self.markets {
            resolve(base, &mut m.committee_file);
        }
        if let Some(t) = self.tls.as_mut().filter(|t| t.is_configured()) {
            resolve(base, &mut t.cert_file);
            resolve(base, &mut t.key_file);
        }
    }

    /// Market addresses, in file order. Entries that do not parse are left
    /// out (validation reports them).
    pub fn market_addresses(&self) -> Vec<Address> {
        self.markets
            .iter()
            .filter_map(|m| parse_b58_32(&m.address))
            .collect()
    }

    pub fn node_key_set(&self) -> BTreeSet<[u8; 32]> {
        self.node_keys
            .iter()
            .filter_map(|k| parse_hex32(k))
            .collect()
    }

    /// The platform this configuration boots.
    pub fn platform_mode(&self) -> PlatformMode {
        match self.platform {
            PlatformKind::Simulated => PlatformMode::Simulated {
                key_file: self.simulated_key_file.clone().unwrap_or_default(),
                vendor_seed_file: self.simulated_vendor_seed.clone().unwrap_or_default(),
            },
            PlatformKind::IntelTdx => PlatformMode::IntelTdx {
                configfs_root: self
                    .tdx_configfs_root
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_TDX_CONFIGFS_ROOT)),
            },
        }
    }

    pub fn member_timeout(&self) -> Duration {
        Duration::from_millis(self.member_timeout_ms)
    }

    pub fn post_deadline(&self) -> Duration {
        Duration::from_millis(self.post_deadline_ms)
    }

    pub fn settle_backstop_after(&self) -> Duration {
        Duration::from_millis(self.settle_backstop_after_ms)
    }

    pub fn tls_config(&self) -> Option<TlsConfig> {
        self.tls.clone().filter(TlsConfig::is_configured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_base58_parse_exact_lengths() {
        let key = [7u8; 32];
        assert_eq!(parse_b58_32(&bs58::encode(key).into_string()), Some(key));
        assert_eq!(parse_b58_32(&bs58::encode([7u8; 31]).into_string()), None);
        assert_eq!(parse_hex32(&hex::encode(key)), Some(key));
        assert_eq!(parse_hex32("0aff"), None);
    }

    #[test]
    fn relative_paths_resolve_against_the_file() {
        let mut p = PathBuf::from("committee.bin");
        resolve(Path::new("/etc/timescales"), &mut p);
        assert_eq!(p, PathBuf::from("/etc/timescales/committee.bin"));
        let mut abs = PathBuf::from("/var/lib/x");
        resolve(Path::new("/etc"), &mut abs);
        assert_eq!(abs, PathBuf::from("/var/lib/x"));
    }
}
