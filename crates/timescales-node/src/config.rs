//! `timescales-node.toml`: one struct per TOML table, parsed with
//! `deny_unknown_fields`.
//!
//! [`Validate`] checks every rule that needs no network: field ranges, the
//! production-only rules, the market parameter and committee
//! files. The chain bindings (genesis hash, Market account, relay key,
//! executors, balances) are checked by [`check_chain_bindings`] at start and
//! by `config-check` without `--offline`.
//!
//! The field documentation below is also what `print-config-docs` prints:
//! [`config_docs`] reads it from this file's source, so the reference cannot
//! drift from the structs.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer};
use timescales_core::{
    CommitmentScheme, Decode, FeeBps, FlowMode, MarketId, MarketParams, Rationing,
};
use timescales_service::wire::CommitteeDescription;
use timescales_service::{
    ConfigError, ConfigIssue, Profile, TelemetryConfig, TlsConfig, Validate, check_cluster_profile,
    rules,
};

/// A u64 written as a decimal string, so TOML and JSON tooling never round it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecimalU64(pub u64);

impl<'de> Deserialize<'de> for DecimalU64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<u64>()
            .map(DecimalU64)
            .map_err(|_| serde::de::Error::custom(format!("expected a decimal u64, got {s:?}")))
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub node: NodeSection,
    pub api: ApiConfig,
    pub sessions: SessionsConfig,
    pub admin: AdminConfig,
    pub metrics: MetricsConfig,
    pub telemetry: TelemetryConfig,
    pub solana: SolanaConfig,
    pub keys: KeysConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    pub store: StoreConfig,
    pub execution: ExecutionConfig,
    #[serde(rename = "market")]
    pub markets: Vec<MarketConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// `[a-z0-9-]{1,32}`. Log and metric label.
    pub id: String,
    /// "local" | "devnet" | "production".
    pub profile: Profile,
    /// node.sqlite, LOCK, archive/ and backups/ live here. Mode 0700.
    pub data_dir: PathBuf,
    /// How long shutdown waits for jobs to reach a durable checkpoint.
    pub shutdown_grace_ms: u64,
    /// One-shot recovery override. Also a CLI flag.
    #[serde(default)]
    pub accept_chain_ahead: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// GCRA rate per client IP (IPv6 keyed by /64).
    pub per_ip_rps: u32,
    pub per_ip_burst: u32,
    /// GCRA rate per session key.
    pub per_session_rps: u32,
    pub per_session_burst: u32,
    /// GCRA rate of submissions per wallet.
    pub per_wallet_submit_rps: u32,
    pub per_wallet_submit_burst: u32,
}

/// `[api]`: the public listener.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Public REST + WS address, behind the TLS proxy.
    pub listen: String,
    /// SIWS `URI:` must equal this.
    pub public_base_url: String,
    /// SIWS first-line domains (exact host[:port]). Also given to enclaves.
    pub session_domains: Vec<String>,
    /// Exact origins. Https only, no "*".
    pub cors_allowed_origins: Vec<String>,
    /// X-Forwarded-For is honoured only from these networks.
    pub trusted_proxy_cidrs: Vec<String>,
    /// Largest JSON body.
    pub max_body_bytes: u32,
    /// Largest submission body.
    pub submit_max_body_bytes: u32,
    /// Concurrent requests before load shedding.
    pub max_concurrency: u32,
    pub request_timeout_ms: u64,
    pub ws_max_connections: u32,
    /// Per IP (/64 for IPv6).
    pub ws_max_connections_per_ip: u32,
    pub ws_max_subscriptions: u32,
    /// Messages queued per connection before it is closed (4008).
    pub ws_send_queue: u32,
    pub ws_heartbeat_ms: u64,
    pub ws_inbound_max_bytes: u32,
    /// `since_seq` resume window.
    pub event_log_hours: u32,
    pub rate_limit: RateLimitConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionsConfig {
    /// Longest session lifetime. At most 86400.
    pub max_ttl_s: u64,
    /// Lifetime of a session nonce.
    pub nonce_ttl_s: u64,
    /// Creating one more session evicts the wallet's oldest.
    pub max_per_wallet: u32,
    /// Allowed clock skew of `TimescalesSession` request auth.
    pub skew_ms: u64,
    /// Accept grants signed with solana:signMessage (no wallet domain
    /// check). Production logs a warning when true.
    pub allow_sign_message_grants: bool,
}

/// `[admin]`: admin and internal routes on a private interface.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Admin and internal routes. A private interface.
    pub listen: String,
    /// At least 32 random bytes, base64. Mode 0400.
    pub token_file: PathBuf,
    /// Hex keys allowed to send `KeyBundlePut`.
    pub dealer_keys: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Prometheus `/metrics`, `/livez` and `/readyz`.
    pub listen: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum Cluster {
    #[serde(rename = "localnet")]
    Localnet,
    #[serde(rename = "devnet")]
    Devnet,
    #[serde(rename = "mainnet-beta")]
    MainnetBeta,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Commitment {
    Processed,
    Confirmed,
    Finalized,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeeModeConfig {
    Fixed,
    Recent,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityFeeConfig {
    /// "fixed" | "recent".
    pub mode: FeeModeConfig,
    /// Compute-unit price in mode "fixed".
    pub fixed_micro_lamports: DecimalU64,
    /// Percentile of recent fees in mode "recent".
    pub percentile: u8,
    /// Cap in either mode.
    pub max_micro_lamports: DecimalU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolanaConfig {
    /// "localnet" | "devnet" | "mainnet-beta". Not localnet.
    pub cluster: Cluster,
    /// Base58. Pinned and checked at start.
    pub genesis_hash: String,
    /// The settlement program (base58).
    pub program_id: String,
    /// Failover order. Https.
    pub rpc_urls: Vec<String>,
    pub rpc_timeout_ms: u64,
    /// Level of ordinary reads. "confirmed" or "finalized".
    pub read_commitment: Commitment,
    /// Beacon finality before assembly. "confirmed" only in local.
    pub release_commitment: Commitment,
    pub poll_interval_ms: u64,
    pub confirm_timeout_ms: u64,
    /// Loop iterations of one idempotent chain operation.
    pub tx_max_attempts: u32,
    /// Settlement transactions in flight at once.
    pub max_parallel_txs: u32,
    /// Margin over the simulated compute units.
    pub cu_margin_pct: u8,
    /// Alert below this. Intake pauses below a quarter of it.
    pub min_relay_balance_lamports: DecimalU64,
    /// Alert below this.
    pub min_cranker_balance_lamports: DecimalU64,
    /// Close terminal batch accounts after the retention period.
    pub reclaim_batches: bool,
    pub priority_fee: PriorityFeeConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysConfig {
    /// Solana JSON keypair. Pubkey == Market.relay. Pays batch rent. 0400.
    pub relay_keypair: PathBuf,
    /// Pays reveal, settle, abort, apply-change, co-sign and reclaim fees.
    pub cranker_keypair: PathBuf,
    /// Ed25519 seed (hex). Signs SignedEnvelopes to enclaves.
    pub service_key: PathBuf,
    /// 32 bytes (hex). Seals carried cover.
    pub kek_file: PathBuf,
    /// 32 bytes (hex). MACs session nonces.
    pub nonce_key_file: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Synchronous {
    Full,
    Normal,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    /// "full".
    pub synchronous: Synchronous,
    /// Group commit window.
    pub group_commit_ms: u64,
    /// Writes per group commit.
    pub group_commit_max: usize,
    /// Read-only connections.
    pub readers: usize,
    /// Queued writes before callers see OVERLOADED.
    pub queue: usize,
    pub busy_timeout_ms: u64,
    /// Private rows are deleted this many epochs after terminal.
    pub private_keep_epochs: u64,
    /// Wallet columns are nulled this many hours after terminal.
    pub wallet_link_hours: u64,
    /// 0 disables the node's own backups (use Litestream or a nightly one).
    pub backup_every_epochs: u64,
    pub backup_dir: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedPlatform {
    Simulated,
    IntelTdx,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveEndpoint {
    /// https.
    pub url: String,
    /// Pinned SignedEnvelope key of the enclave host (hex).
    pub identity: String,
    /// Pinned receipt key (hex). Must be in `Market.executors`.
    pub executor: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConfig {
    /// Enclaves dispatched beyond receipt_quorum.
    pub spare_executions: u32,
    /// Attempts per enclave and epoch. Also capped by reveal_slot +
    /// exec_timeout_slots.
    pub attempts_per_enclave: u32,
    pub attempt_timeout_ms: u64,
    pub retry_backoff_ms: u64,
    /// Consecutive failures that open an enclave's circuit.
    pub circuit_open_after: u32,
    /// Time before an open circuit lets one probe through.
    pub circuit_half_open_after_ms: u64,
    /// "simulated" | "intel_tdx". intel_tdx.
    pub expected_platform: ExpectedPlatform,
    /// Start although an enclave's /enclave/v1/identity could not be read
    /// to check expected_platform (logged warning). Start is otherwise
    /// refused.
    #[serde(default)]
    pub allow_unverified_platform: bool,
    #[serde(rename = "enclave")]
    pub enclaves: Vec<EnclaveEndpoint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PaddingConfig {
    PowerOfTwo { min: u32 },
    Fixed { n: u32 },
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdlePolicyConfig {
    Commit,
    Extend,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaConfig {
    /// Hard cap per wallet and epoch, parked envelopes included.
    pub max_envelopes_per_wallet_per_epoch: u32,
    pub max_parked_per_wallet: u32,
    /// true.
    pub require_trader_account: bool,
    /// Eligibility: quote + base valued at the band's low tick, in quote
    /// atoms. Must be > 0.
    pub min_available_value_quote: DecimalU64,
    /// Per-wallet per-epoch quota = min(cap, floor(available_value / this)).
    pub min_value_per_envelope_quote: DecimalU64,
    /// Epochs a wallet stays banned after unauthenticated envelopes.
    pub ban_epochs: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceSource {
    Fixed,
    LastClearing,
    Operator,
    /// Profile local only. Labelled "modelled" everywhere it is shown.
    ModelledTlsnotary,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceConfig {
    /// "fixed" | "last_clearing" | "operator" | "modelled_tlsnotary" (local only).
    pub source: ReferenceSource,
    /// Reference tick before any clearing or operator value.
    pub initial_tick: DecimalU64,
    /// Modelled notary sources (modelled_tlsnotary only).
    #[serde(default)]
    pub modelled_sources: Option<u32>,
    /// Modelled sources that must agree (modelled_tlsnotary only).
    #[serde(default)]
    pub modelled_min_sources: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketConfig {
    /// Market PDA `["market", market_id]` (base58).
    pub address: String,
    pub name: String,
    /// Display hint only, never trusted by clients.
    pub base_symbol: String,
    /// Display hint only, never trusted by clients.
    pub quote_symbol: String,
    /// Market parameters (JSON). Must equal Market.params.
    pub params_file: PathBuf,
    /// CommitteeDescription. Its digest must equal Market.committee_digest.
    pub committee_file: PathBuf,
    /// 1000..=600000.
    pub epoch_interval_ms: u64,
    /// power_of_two {min} | fixed {n} | none. Not none.
    pub padding: PaddingConfig,
    /// `CarryingCover`. 0.0..=0.9.
    pub cover_carry_probability: f64,
    /// At most params.max_batch_envelopes.
    pub max_real_per_epoch: u32,
    /// At most params.max_order_lifetime and the dealer's lookahead.
    pub max_park_ahead_epochs: u32,
    /// "commit" (cover-only batches hide idle epochs) | "extend".
    pub idle_policy: IdlePolicyConfig,
    /// Intervals an idle epoch stays open (idle_policy = "extend" only).
    pub max_idle_extend: u32,
    pub quota: QuotaConfig,
    pub reference: ReferenceConfig,
}

/// The program's largest batch (`MAX_DELTAS`).
pub const MAX_BATCH_ENVELOPES: u32 = 1024;
/// Shortest and longest epoch interval.
pub const EPOCH_INTERVAL_MS: core::ops::RangeInclusive<u64> = 1_000..=600_000;
/// Longest session lifetime.
pub const MAX_SESSION_TTL_S: u64 = 86_400;

impl NodeConfig {
    /// Reads `path` and settles its profile, resolves the relative paths
    /// it names against the file's directory, then validates it (the
    /// market files are only found once resolved).
    pub fn load(path: &Path, profile: Option<Profile>) -> Result<Self, ConfigError> {
        let Unvalidated(mut cfg) = timescales_service::load_config(path, profile)?;
        cfg.resolve_paths(path.parent().unwrap_or(Path::new(".")));
        cfg.validate(cfg.node.profile)
            .map_err(ConfigError::Invalid)?;
        Ok(cfg)
    }

    /// Relative paths are taken relative to `base` (the configuration
    /// file's directory).
    pub fn resolve_paths(&mut self, base: &Path) {
        let fix = |p: &mut PathBuf| {
            if !p.as_os_str().is_empty() && p.is_relative() {
                *p = base.join(&*p);
            }
        };
        fix(&mut self.node.data_dir);
        fix(&mut self.admin.token_file);
        fix(&mut self.keys.relay_keypair);
        fix(&mut self.keys.cranker_keypair);
        fix(&mut self.keys.service_key);
        fix(&mut self.keys.kek_file);
        fix(&mut self.keys.nonce_key_file);
        fix(&mut self.store.backup_dir);
        if let Some(tls) = &mut self.tls {
            fix(&mut tls.cert_file);
            fix(&mut tls.key_file);
        }
        for m in &mut self.markets {
            fix(&mut m.params_file);
            fix(&mut m.committee_file);
        }
    }

    /// Settings that pass validation but that an operator must have meant:
    /// `config-check` prints them, `run` logs them once telemetry is up.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.node.profile != Profile::Production {
            return out;
        }
        if self.sessions.allow_sign_message_grants {
            out.push(
                "sessions.allow_sign_message_grants = true in production: grants signed with \
                 signMessage carry no wallet domain check"
                    .into(),
            );
        }
        if self.execution.allow_unverified_platform {
            out.push(
                "execution.allow_unverified_platform = true in production: the node starts even \
                 when an enclave's platform cannot be checked against expected_platform"
                    .into(),
            );
        }
        out
    }

    pub fn program_id(&self) -> Option<[u8; 32]> {
        base58_32(&self.solana.program_id)
    }

    pub fn genesis_hash(&self) -> Option<[u8; 32]> {
        base58_32(&self.solana.genesis_hash)
    }

    /// The `[api]` and `[admin]` rate and size settings as the API layer
    /// reads them.
    pub fn api(&self) -> &ApiConfig {
        &self.api
    }
}

/// A configuration as parsed, before its paths are resolved. Validated by
/// [`NodeConfig::load`] afterwards.
#[derive(Deserialize)]
#[serde(transparent)]
struct Unvalidated(NodeConfig);

impl Validate for Unvalidated {
    fn validate(&self, _: Profile) -> Result<(), Vec<ConfigIssue>> {
        Ok(())
    }
}

/// The files a `[[market]]` names, decoded and checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketFiles {
    pub address: [u8; 32],
    pub params: MarketParams,
    pub committee: CommitteeDescription,
}

impl MarketConfig {
    /// Reads and checks the parameter and committee files against this
    /// market's address and `program`.
    pub fn files(&self, program: &[u8; 32]) -> Result<MarketFiles, Vec<ConfigIssue>> {
        let mut issues = Vec::new();
        let address = base58_32(&self.address);
        if address.is_none() {
            issues.push(ConfigIssue::new("market.address", "not a base58 address"));
        }
        let params = match std::fs::read_to_string(&self.params_file) {
            Ok(text) => match parse_params_json(&text) {
                Ok(p) => Some(p),
                Err(e) => {
                    issues.push(ConfigIssue::new("market.params_file", e));
                    None
                }
            },
            Err(e) => {
                issues.push(ConfigIssue::new(
                    "market.params_file",
                    format!("{}: {e}", self.params_file.display()),
                ));
                None
            }
        };
        let committee = match std::fs::read(&self.committee_file) {
            Ok(bytes) => match CommitteeDescription::decode_exact(&bytes) {
                Ok(c) => match c.validate() {
                    Ok(()) => Some(c),
                    Err(e) => {
                        issues.push(ConfigIssue::new("market.committee_file", e.to_string()));
                        None
                    }
                },
                Err(e) => {
                    issues.push(ConfigIssue::new(
                        "market.committee_file",
                        format!("not a CommitteeDescription: {e}"),
                    ));
                    None
                }
            },
            Err(e) => {
                issues.push(ConfigIssue::new(
                    "market.committee_file",
                    format!("{}: {e}", self.committee_file.display()),
                ));
                None
            }
        };
        if let (Some(address), Some(params)) = (address, params) {
            match timescales_chain::program::market_pda(program, params.market.0) {
                Ok((pda, _)) if pda == address => {}
                _ => issues.push(ConfigIssue::new(
                    "market.address",
                    format!(
                        "is not the market PDA of market id {} under the configured program",
                        params.market.0
                    ),
                )),
            }
            if self.max_real_per_epoch > params.max_batch_envelopes {
                issues.push(ConfigIssue::new(
                    "market.max_real_per_epoch",
                    "exceeds params.max_batch_envelopes",
                ));
            }
            if self.max_park_ahead_epochs > params.max_order_lifetime {
                issues.push(ConfigIssue::new(
                    "market.max_park_ahead_epochs",
                    "exceeds params.max_order_lifetime",
                ));
            }
            if params
                .band(timescales_core::Tick(self.reference.initial_tick.0))
                .is_err()
            {
                issues.push(ConfigIssue::new(
                    "market.reference.initial_tick",
                    "gives no valid price band under the market parameters",
                ));
            }
        }
        if let (Some(address), Some(c)) = (address, &committee)
            && c.market != address
        {
            issues.push(ConfigIssue::new(
                "market.committee_file",
                "describes the committee of another market",
            ));
        }
        match (address, params, committee) {
            (Some(address), Some(params), Some(committee)) if issues.is_empty() => {
                Ok(MarketFiles {
                    address,
                    params,
                    committee,
                })
            }
            _ => Err(issues),
        }
    }
}

/// Market parameters in the JSON format of `config/market-*.json`. They
/// must pass the program's checks (`validate_onchain`: at most 1024
/// envelopes per batch, SHA-256 commitments).
pub fn parse_params_json(text: &str) -> Result<MarketParams, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let u = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("missing integer `{k}`"))
    };
    let s = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("missing string `{k}`"))
    };
    let narrow = |k: &str| format!("`{k}` out of range");
    let params = MarketParams {
        market: MarketId(u("market")?),
        base_lot_size: u("base_lot_size")?,
        tick_size: u("tick_size")?,
        band_half_width: u32::try_from(u("band_half_width")?)
            .map_err(|_| narrow("band_half_width"))?,
        max_order_lots_log2: u8::try_from(u("max_order_lots_log2")?)
            .map_err(|_| narrow("max_order_lots_log2"))?,
        max_orders_per_trader: u16::try_from(u("max_orders_per_trader")?)
            .map_err(|_| narrow("max_orders_per_trader"))?,
        max_batch_envelopes: u32::try_from(u("max_batch_envelopes")?)
            .map_err(|_| narrow("max_batch_envelopes"))?,
        max_order_lifetime: u32::try_from(u("max_order_lifetime")?)
            .map_err(|_| narrow("max_order_lifetime"))?,
        maker_fee: FeeBps(u16::try_from(u("maker_fee_bps")?).map_err(|_| narrow("maker_fee_bps"))?),
        taker_fee: FeeBps(u16::try_from(u("taker_fee_bps")?).map_err(|_| narrow("taker_fee_bps"))?),
        flow: match s("flow")? {
            "single" => FlowMode::SingleBook,
            "dual" => FlowMode::DualFlow,
            other => return Err(format!("unknown flow `{other}`")),
        },
        rationing: match s("rationing")? {
            "lottery" => Rationing::Lottery,
            "pro-rata" => Rationing::ProRata,
            other => return Err(format!("unknown rationing `{other}`")),
        },
        commitment_scheme: match s("commitment_scheme")? {
            "sha256" => CommitmentScheme::Sha256,
            "poseidon-bn254" => CommitmentScheme::PoseidonBn254,
            other => return Err(format!("unknown commitment scheme `{other}`")),
        },
    };
    params.validate().map_err(|e| e.to_string())?;
    params
        .validate_onchain()
        .map_err(|e| format!("refused by the program: {e}"))?;
    Ok(params)
}

pub(crate) fn base58_32(s: &str) -> Option<[u8; 32]> {
    let bytes = bs58::decode(s).into_vec().ok()?;
    let key: [u8; 32] = bytes.try_into().ok()?;
    // Only the canonical spelling: a different string for the same bytes
    // would make two configurations of one market look different.
    (bs58::encode(key).into_string() == s).then_some(key)
}

pub(crate) fn hex_32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if s.len() != 64 || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

fn socket(field: &str, value: &str, issues: &mut Vec<ConfigIssue>) -> Option<SocketAddr> {
    match value.parse::<SocketAddr>() {
        Ok(a) => Some(a),
        Err(_) => {
            issues.push(ConfigIssue::new(field, format!("{value:?} is not ip:port")));
            None
        }
    }
}

/// Loopback, RFC 1918, link-local or IPv6 unique-local.
fn private_interface(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || v6.is_unicast_link_local()
        }
    }
}

fn positive(field: &str, v: u64, issues: &mut Vec<ConfigIssue>) {
    if v == 0 {
        issues.push(ConfigIssue::new(field, "must be greater than 0"));
    }
}

impl Validate for NodeConfig {
    fn validate(&self, profile: Profile) -> Result<(), Vec<ConfigIssue>> {
        let mut issues = Vec::new();
        let prod = profile == Profile::Production;

        // [node]
        let id_ok = (1..=32).contains(&self.node.id.len())
            && self
                .node
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !id_ok {
            issues.push(ConfigIssue::new("node.id", "must match [a-z0-9-]{1,32}"));
        }
        if self.node.profile != profile {
            issues.push(ConfigIssue::new(
                "node.profile",
                format!("is {}, validated as {profile}", self.node.profile),
            ));
        }
        if self.node.data_dir.as_os_str().is_empty() {
            issues.push(ConfigIssue::new("node.data_dir", "missing"));
        }
        positive(
            "node.shutdown_grace_ms",
            self.node.shutdown_grace_ms,
            &mut issues,
        );

        self.validate_api(prod, &mut issues);
        self.validate_sessions(&mut issues);

        // [admin], [metrics], [telemetry]
        if let Some(a) = socket("admin.listen", &self.admin.listen, &mut issues)
            && prod
            && !private_interface(a.ip())
        {
            issues.push(ConfigIssue::new(
                "admin.listen",
                "must be a private interface in production",
            ));
        }
        if self.admin.token_file.as_os_str().is_empty() {
            issues.push(ConfigIssue::new("admin.token_file", "missing"));
        }
        for (i, k) in self.admin.dealer_keys.iter().enumerate() {
            if hex_32(k).is_none() {
                issues.push(ConfigIssue::new(
                    format!("admin.dealer_keys[{i}]"),
                    "expected 64 lowercase hex digits",
                ));
            }
        }
        socket("metrics.listen", &self.metrics.listen, &mut issues);
        rules::telemetry("telemetry", &self.telemetry, profile, &mut issues);

        self.validate_solana(profile, &mut issues);

        // [keys], [tls], [store]
        for (field, path) in [
            ("keys.relay_keypair", &self.keys.relay_keypair),
            ("keys.cranker_keypair", &self.keys.cranker_keypair),
            ("keys.service_key", &self.keys.service_key),
            ("keys.kek_file", &self.keys.kek_file),
            ("keys.nonce_key_file", &self.keys.nonce_key_file),
        ] {
            if path.as_os_str().is_empty() {
                issues.push(ConfigIssue::new(field, "missing"));
            }
        }
        rules::tls("tls", self.tls.as_ref(), profile, &mut issues);
        let s = &self.store;
        if prod && s.synchronous != Synchronous::Full {
            issues.push(ConfigIssue::new(
                "store.synchronous",
                "must be \"full\" in production",
            ));
        }
        for (field, v) in [
            ("store.group_commit_max", s.group_commit_max),
            ("store.readers", s.readers),
            ("store.queue", s.queue),
        ] {
            positive(field, u64::try_from(v).unwrap_or(u64::MAX), &mut issues);
        }
        if s.backup_every_epochs > 0 && s.backup_dir.as_os_str().is_empty() {
            issues.push(ConfigIssue::new("store.backup_dir", "missing"));
        }

        self.validate_execution(prod, profile, &mut issues);
        self.validate_markets(profile, &mut issues);

        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }
}

impl NodeConfig {
    fn validate_api(&self, prod: bool, issues: &mut Vec<ConfigIssue>) {
        let a = &self.api;
        socket("api.listen", &a.listen, issues);
        rules::url(
            "api.public_base_url",
            &a.public_base_url,
            if prod {
                Profile::Production
            } else {
                Profile::Local
            },
            issues,
        );
        if a.session_domains.is_empty() {
            issues.push(ConfigIssue::new(
                "api.session_domains",
                "at least one domain",
            ));
        }
        for (i, d) in a.session_domains.iter().enumerate() {
            let valid = !d.is_empty()
                && !d.contains("://")
                && !d.contains('/')
                && d.bytes().all(|b| b.is_ascii_graphic());
            if !valid {
                issues.push(ConfigIssue::new(
                    format!("api.session_domains[{i}]"),
                    "expected an exact host[:port]",
                ));
            }
        }
        for (i, o) in a.cors_allowed_origins.iter().enumerate() {
            let field = format!("api.cors_allowed_origins[{i}]");
            if o == "*" {
                issues.push(ConfigIssue::new(field, "wildcard origins are not allowed"));
                continue;
            }
            let scheme_ok = o.starts_with("https://") || (!prod && o.starts_with("http://"));
            let host = o.split_once("://").map_or("", |(_, h)| h);
            if !scheme_ok || host.is_empty() || host.contains('/') {
                issues.push(ConfigIssue::new(
                    field,
                    if prod {
                        "expected an https origin without a path"
                    } else {
                        "expected an http(s) origin without a path"
                    },
                ));
            }
        }
        for (i, c) in a.trusted_proxy_cidrs.iter().enumerate() {
            if c.parse::<ipnet::IpNet>().is_err() {
                issues.push(ConfigIssue::new(
                    format!("api.trusted_proxy_cidrs[{i}]"),
                    format!("{c:?} is not a CIDR"),
                ));
            }
        }
        for (field, v) in [
            ("api.max_body_bytes", u64::from(a.max_body_bytes)),
            (
                "api.submit_max_body_bytes",
                u64::from(a.submit_max_body_bytes),
            ),
            ("api.max_concurrency", u64::from(a.max_concurrency)),
            ("api.request_timeout_ms", a.request_timeout_ms),
            ("api.ws_max_connections", u64::from(a.ws_max_connections)),
            (
                "api.ws_max_connections_per_ip",
                u64::from(a.ws_max_connections_per_ip),
            ),
            (
                "api.ws_max_subscriptions",
                u64::from(a.ws_max_subscriptions),
            ),
            ("api.ws_send_queue", u64::from(a.ws_send_queue)),
            ("api.ws_heartbeat_ms", a.ws_heartbeat_ms),
            (
                "api.ws_inbound_max_bytes",
                u64::from(a.ws_inbound_max_bytes),
            ),
            ("api.event_log_hours", u64::from(a.event_log_hours)),
            (
                "api.rate_limit.per_ip_rps",
                u64::from(a.rate_limit.per_ip_rps),
            ),
            (
                "api.rate_limit.per_ip_burst",
                u64::from(a.rate_limit.per_ip_burst),
            ),
            (
                "api.rate_limit.per_session_rps",
                u64::from(a.rate_limit.per_session_rps),
            ),
            (
                "api.rate_limit.per_session_burst",
                u64::from(a.rate_limit.per_session_burst),
            ),
            (
                "api.rate_limit.per_wallet_submit_rps",
                u64::from(a.rate_limit.per_wallet_submit_rps),
            ),
            (
                "api.rate_limit.per_wallet_submit_burst",
                u64::from(a.rate_limit.per_wallet_submit_burst),
            ),
        ] {
            positive(field, v, issues);
        }
        if a.submit_max_body_bytes < 1024 {
            issues.push(ConfigIssue::new(
                "api.submit_max_body_bytes",
                "too small for one submission",
            ));
        }
    }

    fn validate_sessions(&self, issues: &mut Vec<ConfigIssue>) {
        let s = &self.sessions;
        if s.max_ttl_s == 0 || s.max_ttl_s > MAX_SESSION_TTL_S {
            issues.push(ConfigIssue::new(
                "sessions.max_ttl_s",
                format!("must be 1..={MAX_SESSION_TTL_S}"),
            ));
        }
        positive("sessions.nonce_ttl_s", s.nonce_ttl_s, issues);
        positive(
            "sessions.max_per_wallet",
            u64::from(s.max_per_wallet),
            issues,
        );
        positive("sessions.skew_ms", s.skew_ms, issues);
    }

    fn validate_solana(&self, profile: Profile, issues: &mut Vec<ConfigIssue>) {
        let s = &self.solana;
        let prod = profile == Profile::Production;
        if prod && s.cluster == Cluster::Localnet {
            issues.push(ConfigIssue::new(
                "solana.cluster",
                "localnet is refused in production",
            ));
        }
        match base58_32(&s.genesis_hash) {
            Some(g) => {
                if let Err(e) = check_cluster_profile(profile, &g) {
                    issues.push(ConfigIssue::new("solana.genesis_hash", e.to_string()));
                }
                let mainnet = g == timescales_service::MAINNET_BETA_GENESIS_HASH;
                if mainnet != (s.cluster == Cluster::MainnetBeta) {
                    issues.push(ConfigIssue::new(
                        "solana.genesis_hash",
                        "does not match solana.cluster",
                    ));
                }
            }
            None => issues.push(ConfigIssue::new("solana.genesis_hash", "not a base58 hash")),
        }
        if base58_32(&s.program_id).is_none() {
            issues.push(ConfigIssue::new(
                "solana.program_id",
                "not a base58 address",
            ));
        }
        if s.rpc_urls.is_empty() {
            issues.push(ConfigIssue::new("solana.rpc_urls", "at least one URL"));
        }
        for (i, u) in s.rpc_urls.iter().enumerate() {
            rules::url(&format!("solana.rpc_urls[{i}]"), u, profile, issues);
        }
        if s.read_commitment == Commitment::Processed {
            issues.push(ConfigIssue::new(
                "solana.read_commitment",
                "must be confirmed or finalized",
            ));
        }
        if profile != Profile::Local && s.release_commitment != Commitment::Finalized {
            issues.push(ConfigIssue::new(
                "solana.release_commitment",
                "must be finalized outside profile local",
            ));
        }
        if s.release_commitment == Commitment::Processed {
            issues.push(ConfigIssue::new(
                "solana.release_commitment",
                "must be confirmed or finalized",
            ));
        }
        positive("solana.rpc_timeout_ms", s.rpc_timeout_ms, issues);
        positive("solana.poll_interval_ms", s.poll_interval_ms, issues);
        positive("solana.confirm_timeout_ms", s.confirm_timeout_ms, issues);
        positive(
            "solana.tx_max_attempts",
            u64::from(s.tx_max_attempts),
            issues,
        );
        positive(
            "solana.max_parallel_txs",
            u64::from(s.max_parallel_txs),
            issues,
        );
        if s.cu_margin_pct > 100 {
            issues.push(ConfigIssue::new("solana.cu_margin_pct", "at most 100"));
        }
        if s.priority_fee.percentile > 100 {
            issues.push(ConfigIssue::new(
                "solana.priority_fee.percentile",
                "at most 100",
            ));
        }
        if s.priority_fee.fixed_micro_lamports > s.priority_fee.max_micro_lamports {
            issues.push(ConfigIssue::new(
                "solana.priority_fee.fixed_micro_lamports",
                "exceeds max_micro_lamports",
            ));
        }
    }

    fn validate_execution(&self, prod: bool, profile: Profile, issues: &mut Vec<ConfigIssue>) {
        let e = &self.execution;
        if e.enclaves.is_empty() {
            issues.push(ConfigIssue::new(
                "execution.enclave",
                "at least one enclave",
            ));
        }
        if prod && e.expected_platform != ExpectedPlatform::IntelTdx {
            issues.push(ConfigIssue::new(
                "execution.expected_platform",
                "the simulated platform is refused in production",
            ));
        }
        positive(
            "execution.attempts_per_enclave",
            u64::from(e.attempts_per_enclave),
            issues,
        );
        positive("execution.attempt_timeout_ms", e.attempt_timeout_ms, issues);
        positive(
            "execution.circuit_open_after",
            u64::from(e.circuit_open_after),
            issues,
        );
        let mut identities = BTreeSet::new();
        let mut executors = BTreeSet::new();
        for (i, en) in e.enclaves.iter().enumerate() {
            rules::url(
                &format!("execution.enclave[{i}].url"),
                &en.url,
                profile,
                issues,
            );
            match hex_32(&en.identity) {
                Some(k) if identities.insert(k) => {}
                Some(_) => issues.push(ConfigIssue::new(
                    format!("execution.enclave[{i}].identity"),
                    "listed twice",
                )),
                None => issues.push(ConfigIssue::new(
                    format!("execution.enclave[{i}].identity"),
                    "expected 64 lowercase hex digits",
                )),
            }
            match hex_32(&en.executor) {
                Some(k) if executors.insert(k) => {}
                Some(_) => issues.push(ConfigIssue::new(
                    format!("execution.enclave[{i}].executor"),
                    "listed twice",
                )),
                None => issues.push(ConfigIssue::new(
                    format!("execution.enclave[{i}].executor"),
                    "expected 64 lowercase hex digits",
                )),
            }
        }
    }

    fn validate_markets(&self, profile: Profile, issues: &mut Vec<ConfigIssue>) {
        let prod = profile == Profile::Production;
        if self.markets.is_empty() {
            issues.push(ConfigIssue::new("market", "at least one [[market]]"));
        }
        let program = self.program_id();
        let mut seen = BTreeSet::new();
        for (i, m) in self.markets.iter().enumerate() {
            let at = |f: &str| format!("market[{i}].{f}");
            if !seen.insert(m.address.clone()) {
                issues.push(ConfigIssue::new(at("address"), "listed twice"));
            }
            if m.name.trim().is_empty() {
                issues.push(ConfigIssue::new(at("name"), "missing"));
            }
            if !EPOCH_INTERVAL_MS.contains(&m.epoch_interval_ms) {
                issues.push(ConfigIssue::new(
                    at("epoch_interval_ms"),
                    "must be 1000..=600000",
                ));
            }
            match m.padding {
                PaddingConfig::None if prod => issues.push(ConfigIssue::new(
                    at("padding"),
                    "padding \"none\" is refused in production",
                )),
                PaddingConfig::PowerOfTwo { min: 0 } | PaddingConfig::Fixed { n: 0 } => {
                    issues.push(ConfigIssue::new(at("padding"), "must be at least 1"));
                }
                PaddingConfig::Fixed { n } if n > MAX_BATCH_ENVELOPES => issues.push(
                    ConfigIssue::new(at("padding"), "exceeds the program's 1024 envelopes"),
                ),
                _ => {}
            }
            if !(0.0..=0.9).contains(&m.cover_carry_probability) {
                issues.push(ConfigIssue::new(
                    at("cover_carry_probability"),
                    "must be 0.0..=0.9",
                ));
            }
            if m.max_real_per_epoch == 0 || m.max_real_per_epoch > MAX_BATCH_ENVELOPES {
                issues.push(ConfigIssue::new(
                    at("max_real_per_epoch"),
                    "must be 1..=1024",
                ));
            }
            if m.idle_policy == IdlePolicyConfig::Extend && m.max_idle_extend == 0 {
                issues.push(ConfigIssue::new(
                    at("max_idle_extend"),
                    "must be at least 1 with idle_policy = \"extend\"",
                ));
            }
            let q = &m.quota;
            positive(
                &at("quota.max_envelopes_per_wallet_per_epoch"),
                u64::from(q.max_envelopes_per_wallet_per_epoch),
                issues,
            );
            positive(
                &at("quota.min_available_value_quote"),
                q.min_available_value_quote.0,
                issues,
            );
            positive(
                &at("quota.min_value_per_envelope_quote"),
                q.min_value_per_envelope_quote.0,
                issues,
            );
            if prod && !q.require_trader_account {
                issues.push(ConfigIssue::new(
                    at("quota.require_trader_account"),
                    "must be true in production",
                ));
            }
            let r = &m.reference;
            positive(&at("reference.initial_tick"), r.initial_tick.0, issues);
            match r.source {
                ReferenceSource::ModelledTlsnotary => {
                    if profile != Profile::Local {
                        issues.push(ConfigIssue::new(
                            at("reference.source"),
                            "modelled_tlsnotary is allowed in profile local only",
                        ));
                    }
                    match (r.modelled_sources, r.modelled_min_sources) {
                        (Some(n), Some(k)) if n >= 1 && (1..=n).contains(&k) => {}
                        _ => issues.push(ConfigIssue::new(
                            at("reference.modelled_sources"),
                            "modelled_tlsnotary needs 1 <= modelled_min_sources <= modelled_sources",
                        )),
                    }
                }
                _ => {
                    if r.modelled_sources.is_some() || r.modelled_min_sources.is_some() {
                        issues.push(ConfigIssue::new(
                            at("reference.modelled_sources"),
                            "only for source = \"modelled_tlsnotary\"",
                        ));
                    }
                }
            }
            if let Some(program) = program
                && let Err(file_issues) = m.files(&program)
            {
                issues.extend(file_issues.into_iter().map(|mut issue| {
                    issue.field = issue.field.replacen("market.", &format!("market[{i}]."), 1);
                    issue
                }));
            }
        }
    }
}

/// One TOML table of the reference: its heading and the struct that
/// describes it in this file.
const TABLES: &[(&str, &str)] = &[
    ("node", "NodeSection"),
    ("api", "ApiConfig"),
    ("api.rate_limit", "RateLimitConfig"),
    ("sessions", "SessionsConfig"),
    ("admin", "AdminConfig"),
    ("metrics", "MetricsConfig"),
    ("solana", "SolanaConfig"),
    ("solana.priority_fee", "PriorityFeeConfig"),
    ("keys", "KeysConfig"),
    ("store", "StoreConfig"),
    ("execution", "ExecutionConfig"),
    ("[execution.enclave]", "EnclaveEndpoint"),
    ("[market]", "MarketConfig"),
    ("market.quota", "QuotaConfig"),
    ("market.reference", "ReferenceConfig"),
];

/// The tables whose structs live in `timescales-service`.
const SHARED_TABLES: &[(&str, &[(&str, &str)])] = &[
    (
        "telemetry",
        &[
            ("log_format", "\"json\" | \"pretty\"; (P) json."),
            ("log_filter", "tracing filter, e.g. \"info\"."),
            (
                "otlp_endpoint",
                "OTLP/HTTP traces URL; empty disables export (feature otlp).",
            ),
            (
                "service_name",
                "Service name in traces; defaults to timescales-node.",
            ),
        ],
    ),
    (
        "tls",
        &[
            (
                "cert_file",
                "PEM certificate for mutual TLS 1.3; (P) required.",
            ),
            ("key_file", "PEM private key of cert_file."),
            (
                "peer_spki_sha256",
                "SHA-256 of each pinned peer's SubjectPublicKeyInfo (hex).",
            ),
        ],
    ),
];

/// One field of a struct in this file, with its doc comment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FieldDoc {
    pub(crate) name: String,
    pub(crate) ty: String,
    pub(crate) doc: String,
}

/// Every `pub` field of `pub struct name` in `source`, with the `///`
/// lines above it. Serde renames are applied.
pub(crate) fn struct_fields(source: &str, name: &str) -> Option<Vec<FieldDoc>> {
    let start = source.find(&format!("pub struct {name} {{"))?;
    let body = &source[start..];
    let end = body.find("\n}")?;
    let mut fields = Vec::new();
    let mut doc: Vec<&str> = Vec::new();
    let mut rename: Option<String> = None;
    for line in body[..end].lines().skip(1) {
        let line = line.trim();
        if let Some(d) = line.strip_prefix("///") {
            doc.push(d.trim());
        } else if let Some(r) = line.strip_prefix("#[serde(rename = \"") {
            rename = r.split('"').next().map(str::to_owned);
        } else if let Some(f) = line.strip_prefix("pub ") {
            let (field, ty) = f.split_once(':')?;
            fields.push(FieldDoc {
                name: rename.take().unwrap_or_else(|| field.trim().to_owned()),
                ty: ty.trim().trim_end_matches(',').to_owned(),
                doc: doc.join(" "),
            });
            doc.clear();
        }
    }
    Some(fields)
}

/// The configuration reference (`print-config-docs`), rendered from the
/// doc comments of the structs in this file.
pub fn config_docs() -> String {
    let source = include_str!("config.rs");
    let mut out = String::from(
        "# timescales-node configuration reference\n\n\
         Unknown fields are refused. u64 amounts are decimal strings. Relative paths are \
         resolved against the configuration file's directory. (P) marks rules enforced \
         when profile = \"production\".\n",
    );
    for (table, ty) in TABLES {
        // `[[market]]` and `[[execution.enclave]]` are arrays of tables.
        out.push_str(&format!("\n[{table}]\n"));
        for f in struct_fields(source, ty).unwrap_or_default() {
            // Nested tables are listed under their own heading.
            if TABLES
                .iter()
                .any(|(t, s)| *s == f.ty && t.ends_with(&f.name))
            {
                continue;
            }
            if f.name == "enclave" || f.name == "telemetry" || f.name == "tls" {
                continue;
            }
            out.push_str(&format!("{:<34} # {}", f.name, f.ty));
            if !f.doc.is_empty() {
                out.push_str(&format!(": {}", f.doc));
            }
            out.push('\n');
        }
    }
    for (table, fields) in SHARED_TABLES {
        out.push_str(&format!("\n[{table}]\n"));
        for (name, doc) in *fields {
            out.push_str(&format!("{name:<34} # {doc}\n"));
        }
    }
    out
}

/// What the chain must show for this configuration to run (startup,
///): checked by `run` and by `config-check` without `--offline`.
#[derive(Debug)]
pub struct ChainFacts {
    pub genesis_hash: [u8; 32],
    pub markets: Vec<(MarketFiles, timescales_chain::program::MarketAccount)>,
    pub relay: [u8; 32],
    pub relay_balance: u64,
    pub cranker_balance: u64,
    /// Pinned executor keys of the configured enclaves.
    pub pinned_executors: Vec<[u8; 32]>,
    /// Lamports per batch account (rent of `BATCH_LEN`).
    pub batch_rent: u64,
}

/// Slots in one day at 400 ms (the commit fees of the funding rule).
const MIN_TIMELOCK_PRODUCTION: u64 = 216_000;
/// Batch accounts kept funded (`BATCH_RETENTION`).
const BATCH_RETENTION: u64 = 1024;

/// The online rules, as issues (refusals) and warnings.
pub fn check_chain_bindings(
    cfg: &NodeConfig,
    facts: &ChainFacts,
) -> (Vec<ConfigIssue>, Vec<String>) {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let profile = cfg.node.profile;
    if Some(facts.genesis_hash) != cfg.genesis_hash() {
        issues.push(ConfigIssue::new(
            "solana.genesis_hash",
            "differs from the cluster's genesis hash",
        ));
    }
    if let Err(e) = check_cluster_profile(profile, &facts.genesis_hash) {
        issues.push(ConfigIssue::new("node.profile", e.to_string()));
    }
    for (files, market) in &facts.markets {
        let at = bs58::encode(files.address).into_string();
        if market.params != files.params {
            issues.push(ConfigIssue::new(
                format!("market {at}"),
                "params_file differs from Market.params",
            ));
        }
        let digest = files.committee.digest();
        let previous = market.prev_committee_digest != timescales_core::Hash32::ZERO
            && market.prev_committee_digest == digest;
        if market.committee_digest != digest && !previous {
            issues.push(ConfigIssue::new(
                format!("market {at}"),
                "committee_file digest is neither Market.committee_digest nor the previous one",
            ));
        }
        if market.relay != facts.relay {
            issues.push(ConfigIssue::new(
                format!("market {at}"),
                "the relay key is not Market.relay",
            ));
        }
        for e in &facts.pinned_executors {
            if market.executor_slot(e).is_none() {
                issues.push(ConfigIssue::new(
                    format!("market {at}"),
                    format!(
                        "pinned executor {} is not in Market.executors",
                        hex::encode(e)
                    ),
                ));
            }
        }
        if profile == Profile::Production && market.timelock_slots < MIN_TIMELOCK_PRODUCTION {
            issues.push(ConfigIssue::new(
                format!("market {at}"),
                "timelock_slots is below MIN_TIMELOCK",
            ));
        }
    }
    let funding = (BATCH_RETENTION + 2).saturating_mul(facts.batch_rent);
    if profile == Profile::Production && cfg.solana.min_relay_balance_lamports.0 < funding {
        warnings.push(format!(
            "solana.min_relay_balance_lamports is below the funding rule \
             (BATCH_RETENTION + 2) x rent = {funding} lamports"
        ));
    }
    if facts.relay_balance < cfg.solana.min_relay_balance_lamports.0 {
        warnings.push(format!(
            "relay balance {} lamports is below min_relay_balance_lamports",
            facts.relay_balance
        ));
    }
    if facts.cranker_balance < cfg.solana.min_cranker_balance_lamports.0 {
        warnings.push(format!(
            "cranker balance {} lamports is below min_cranker_balance_lamports",
            facts.cranker_balance
        ));
    }
    (issues, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_lists_every_field_of_every_table() {
        let source = include_str!("config.rs");
        let docs = config_docs();
        for (table, ty) in TABLES {
            let fields = struct_fields(source, ty).unwrap_or_else(|| panic!("{ty} not found"));
            assert!(!fields.is_empty(), "{table}");
            for f in fields {
                assert!(docs.contains(&f.name), "{table}.{} missing", f.name);
            }
        }
        assert!(docs.contains("[api.rate_limit]"));
        assert!(docs.contains("[[market]]"));
        assert!(docs.contains("[[execution.enclave]]"));
        assert!(docs.contains("Eligibility: quote + base valued"));
    }

    fn fixture() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/node/data/node.production.toml")
    }

    #[test]
    fn the_production_fixture_passes_offline() {
        let cfg = NodeConfig::load(&fixture(), None).unwrap();
        assert_eq!(cfg.node.profile, Profile::Production);
        assert!(cfg.markets[0].params_file.is_absolute());
    }

    #[test]
    fn production_rules_refuse_what_they_must() {
        let text = std::fs::read_to_string(fixture()).unwrap();
        let bad = text
            .replace("https://rpc-a.example.org", "http://rpc-a.example.org")
            .replace(
                "expected_platform = \"intel_tdx\"",
                "expected_platform = \"simulated\"",
            )
            .replace(
                "padding = { kind = \"power_of_two\", min = 64 }",
                "padding = { kind = \"none\" }",
            )
            .replace(
                "release_commitment = \"finalized\"",
                "release_commitment = \"confirmed\"",
            )
            .replace("synchronous = \"full\"", "synchronous = \"normal\"")
            .replace(
                "require_trader_account = true",
                "require_trader_account = false",
            )
            .replace("listen = \"10.0.0.5:8081\"", "listen = \"0.0.0.0:8081\"");
        let dir = tempfile::tempdir().unwrap();
        for f in ["market.production.json", "committee.production.bin"] {
            std::fs::copy(fixture().with_file_name(f), dir.path().join(f)).unwrap();
        }
        let path = dir.path().join("node.toml");
        std::fs::write(&path, bad).unwrap();
        let Err(ConfigError::Invalid(issues)) = NodeConfig::load(&path, None) else {
            panic!("accepted");
        };
        let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
        for f in [
            "solana.rpc_urls[0]",
            "execution.expected_platform",
            "market[0].padding",
            "solana.release_commitment",
            "store.synchronous",
            "market[0].quota.require_trader_account",
            "admin.listen",
        ] {
            assert!(fields.contains(&f), "{f} not refused: {fields:?}");
        }
        // The same file is fine in profile local, minus the local-only rules.
        let local = NodeConfig::load(&path, Some(Profile::Local));
        assert!(
            local.is_err(),
            "mainnet-beta refuses non-production profiles"
        );
    }

    #[test]
    fn production_overrides_are_reported_as_warnings() {
        let cfg = NodeConfig::load(&fixture(), None).unwrap();
        assert!(cfg.warnings().is_empty());
        let text = std::fs::read_to_string(fixture())
            .unwrap()
            .replace(
                "allow_sign_message_grants = false",
                "allow_sign_message_grants = true",
            )
            .replace(
                "expected_platform = \"intel_tdx\"",
                "expected_platform = \"intel_tdx\"\nallow_unverified_platform = true",
            );
        let dir = tempfile::tempdir().unwrap();
        for f in ["market.production.json", "committee.production.bin"] {
            std::fs::copy(fixture().with_file_name(f), dir.path().join(f)).unwrap();
        }
        let path = dir.path().join("node.toml");
        std::fs::write(&path, text).unwrap();
        let warnings = NodeConfig::load(&path, None).unwrap().warnings();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].starts_with("sessions.allow_sign_message_grants"));
        assert!(warnings[1].starts_with("execution.allow_unverified_platform"));
    }

    #[test]
    fn params_json_matches_the_cli_format() {
        let p = parse_params_json(
            r#"{"band_half_width": 16, "base_lot_size": 1, "commitment_scheme": "sha256",
                "flow": "dual", "maker_fee_bps": 0, "market": 7, "max_batch_envelopes": 1024,
                "max_order_lifetime": 16, "max_order_lots_log2": 40, "max_orders_per_trader": 8,
                "rationing": "pro-rata", "taker_fee_bps": 10, "tick_size": 1}"#,
        )
        .unwrap();
        assert_eq!(p.market, MarketId(7));
        assert_eq!(p.flow, FlowMode::DualFlow);
        let too_big = r#"{"band_half_width": 16, "base_lot_size": 1, "commitment_scheme": "sha256",
                "flow": "dual", "maker_fee_bps": 0, "market": 7, "max_batch_envelopes": 2048,
                "max_order_lifetime": 16, "max_order_lots_log2": 40, "max_orders_per_trader": 8,
                "rationing": "pro-rata", "taker_fee_bps": 10, "tick_size": 1}"#;
        assert!(parse_params_json(too_big).unwrap_err().contains("program"));
        assert!(parse_params_json("{}").unwrap_err().contains("missing"));
    }

    #[test]
    fn base58_and_hex_accept_only_canonical_spellings() {
        let key = [7u8; 32];
        let s = bs58::encode(key).into_string();
        assert_eq!(base58_32(&s), Some(key));
        assert_eq!(base58_32("1"), None);
        assert_eq!(hex_32(&hex::encode(key)), Some(key));
        let lettered = [0xab_u8; 32];
        assert_eq!(hex_32(&hex::encode(lettered)), Some(lettered));
        assert_eq!(hex_32(&hex::encode(lettered).to_uppercase()), None);
        assert_eq!(hex_32("00"), None);
    }

    #[test]
    fn private_interfaces() {
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "::1", "fd00::1"] {
            assert!(private_interface(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["0.0.0.0", "8.8.8.8", "2001:db8::1"] {
            assert!(!private_interface(ip.parse().unwrap()), "{ip}");
        }
    }
}
