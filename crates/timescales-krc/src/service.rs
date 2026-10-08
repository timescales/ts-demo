//! Process wiring for the `timescales-krc` binary: configuration loading
//! and checks, keys, stores, RPC, and the member and dealer services with
//! their ops listeners.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, bail};
use rand_core::{OsRng, RngCore};
use timescales_chain::{HttpRpc, Level, QuorumRpc, SolanaRpc};
use timescales_service::store::dealer::DealerRepo;
use timescales_service::store::member::MemberRepo;
use timescales_service::store::{RatchetSealer, Schema, Store, StoreOptions};
use timescales_service::wire::MessageKind;
use timescales_service::{
    BuildInfo, ConfigError, ConfigIssue, HttpLimits, Metrics, Profile, Readiness, ReadinessProbe,
    keys, load_config, ops_router, refuse_simulation,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::config::{ChainConfig, DealerFile, MemberFile, load_committee};
use crate::dealer::Dealer;
use crate::member::{Member, MemberKeys};
use crate::verifier::{CollateralWatch, PlatformVerifiers};
use crate::{BoxFuture, DealerConfig, KrcChain, MemberConfig, RpcKrcChain, b58, now_ms};

/// Exit code after a store write error (fail-stop).
pub const EXIT_STORE_FAILED: i32 = 70;
/// Readiness wants a chain read within this long.
const FRESH_CHAIN_MS: u64 = 30_000;
/// Default `confirmed_cache_ms`.
const CONFIRMED_CACHE_MS: u64 = 2_000;
/// How often the TDX collateral file is looked at.
const COLLATERAL_POLL: Duration = Duration::from_secs(60);

pub fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
        git_sha: option_env!("TIMESCALES_GIT_SHA").unwrap_or("unknown"),
        simulation: false,
        sim_platform: timescales_executor::attestation::SIM_PLATFORM_BUILD,
    }
}

/// A configuration file of either service.
#[derive(Debug)]
pub enum AnyConfig {
    Member(Box<MemberConfig>),
    Dealer(Box<DealerConfig>),
}

fn config_dir(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new("."))
}

pub fn load_member(path: &Path, profile: Option<Profile>) -> Result<MemberConfig, ConfigError> {
    let mut cfg = load_config::<MemberFile>(path, profile)?.member;
    cfg.resolve_paths(config_dir(path));
    Ok(cfg)
}

pub fn load_dealer(path: &Path, profile: Option<Profile>) -> Result<DealerConfig, ConfigError> {
    let mut cfg = load_config::<DealerFile>(path, profile)?.dealer;
    cfg.resolve_paths(config_dir(path));
    Ok(cfg)
}

/// Loads a member or a dealer file, told apart by its table.
pub fn load_any(path: &Path, profile: Option<Profile>) -> Result<AnyConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let table: toml::Table = toml::from_str(&text).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    if table.contains_key("member") {
        Ok(AnyConfig::Member(Box::new(load_member(path, profile)?)))
    } else if table.contains_key("dealer") {
        Ok(AnyConfig::Dealer(Box::new(load_dealer(path, profile)?)))
    } else {
        Err(ConfigError::Invalid(vec![ConfigIssue::new(
            "",
            "expected a [member] or a [dealer] table",
        )]))
    }
}

/// The checks of the files a configuration names that need no secret and
/// no network: every committee description decodes, is valid and names
/// its market. The member's index is in it. The dealer has one URL per
/// member.
pub fn file_issues(cfg: &AnyConfig) -> Vec<ConfigIssue> {
    let mut issues = Vec::new();
    match cfg {
        AnyConfig::Member(m) => {
            for (i, (entry, address)) in m.markets.iter().zip(m.market_addresses()).enumerate() {
                let field = format!("member.market[{i}].committee_file");
                match load_committee(&entry.committee_file, &address) {
                    Ok(c) if c.member(m.index).is_none() => issues.push(ConfigIssue::new(
                        field,
                        format!("member {} is not in this committee", m.index),
                    )),
                    Ok(_) => {}
                    Err(e) => issues.push(ConfigIssue::new(field, e)),
                }
            }
        }
        AnyConfig::Dealer(d) => {
            for (i, (entry, address)) in d.markets.iter().zip(d.market_addresses()).enumerate() {
                let field = format!("dealer.market[{i}].committee_file");
                match load_committee(&entry.committee_file, &address) {
                    Ok(c) if c.members.len() != d.member_urls.len() => {
                        issues.push(ConfigIssue::new(
                            "dealer.member_urls",
                            format!(
                                "{} URLs for a committee of {}",
                                d.member_urls.len(),
                                c.members.len()
                            ),
                        ));
                    }
                    Ok(_) => {}
                    Err(e) => issues.push(ConfigIssue::new(field, e)),
                }
            }
        }
    }
    issues
}

/// RPC providers of a chain section: `rpc_agree` of them must agree on
/// every read.
pub fn quorum_rpc(chain: &ChainConfig) -> anyhow::Result<Arc<dyn SolanaRpc>> {
    let timeout = Duration::from_millis(chain.rpc_timeout_ms);
    let providers = chain
        .rpc_urls
        .iter()
        .map(|u| {
            HttpRpc::new(vec![u.clone()], timeout)
                .map(|r| Arc::new(r) as Arc<dyn SolanaRpc>)
                .with_context(|| format!("RPC client for {u}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Arc::new(QuorumRpc::new(providers, chain.rpc_agree)?))
}

/// The chain bindings `config-check` checks without `--offline`: the
/// genesis hash, the program and every market, whose committee digest must
/// be the configured committee's (the current one, or for a member also
/// the previous one).
pub async fn chain_issues(cfg: &AnyConfig) -> anyhow::Result<Vec<ConfigIssue>> {
    let (chain, markets, field, member) = match cfg {
        AnyConfig::Member(m) => (&m.chain, &m.markets, "member", true),
        AnyConfig::Dealer(d) => (&d.chain, &d.markets, "dealer", false),
    };
    let mut issues = Vec::new();
    let rpc = quorum_rpc(chain)?;
    let genesis = rpc
        .genesis_hash()
        .await
        .context("reading the genesis hash")?;
    if Some(genesis) != chain.genesis() {
        issues.push(ConfigIssue::new(
            format!("{field}.chain.genesis_hash"),
            format!("the cluster's genesis hash is {}", b58(&genesis)),
        ));
    }
    let program = chain.program().unwrap_or_default();
    if rpc
        .get_account(program, Level::Confirmed, None)
        .await?
        .is_none()
    {
        issues.push(ConfigIssue::new(
            format!("{field}.chain.program_id"),
            "no such account on the cluster",
        ));
    }
    for (i, entry) in markets.iter().enumerate() {
        let Some(address) = crate::config::parse_b58_32(&entry.address) else {
            continue;
        };
        let f = format!("{field}.market[{i}]");
        let Some(account) = rpc.get_account(address, Level::Confirmed, None).await? else {
            issues.push(ConfigIssue::new(f, "no market account on the cluster"));
            continue;
        };
        let market = match timescales_chain::program::decode_market(&account.data) {
            Ok(m) if account.owner == program => m,
            _ => {
                issues.push(ConfigIssue::new(
                    f,
                    "not a market of the configured program",
                ));
                continue;
            }
        };
        let Ok(committee) = load_committee(&entry.committee_file, &address) else {
            continue;
        };
        let digest = committee.digest();
        let known =
            digest == market.committee_digest || (member && digest == market.prev_committee_digest);
        if !known {
            issues.push(ConfigIssue::new(
                format!("{f}.committee_file"),
                format!(
                    "committee digest {digest} is not the market's ({})",
                    market.committee_digest
                ),
            ));
        }
    }
    Ok(issues)
}

fn open_store(path: &Path, schema: Schema) -> anyhow::Result<Store> {
    let opts = StoreOptions {
        secure_delete: schema == Schema::MemberShares,
        ..StoreOptions::default()
    };
    Store::open(path, schema, opts).with_context(|| format!("opening {}", path.display()))
}

fn create_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))
}

/// The at-rest key file, created with a fresh random generation 0 on the
/// first start.
fn at_rest_key(path: &Path) -> anyhow::Result<RatchetSealer> {
    if path.exists() {
        return RatchetSealer::load(path).with_context(|| format!("loading {}", path.display()));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut_slice());
    tracing::info!(path = %path.display(), "creating the at-rest key file");
    RatchetSealer::create(path, 0, key).with_context(|| format!("creating {}", path.display()))
}

fn open_member_repo(
    cfg: &MemberConfig,
    at_rest: &Arc<RatchetSealer>,
) -> anyhow::Result<MemberRepo> {
    create_dir(&cfg.data_dir)?;
    create_dir(&cfg.shares_dir)?;
    let member = open_store(&cfg.data_dir.join("member.sqlite"), Schema::Member)?;
    let shares = open_store(&cfg.shares_dir.join("shares.sqlite"), Schema::MemberShares)?;
    Ok(MemberRepo::new(member, shares, Arc::clone(at_rest)))
}

async fn check_genesis(rpc: &Arc<dyn SolanaRpc>, chain: &ChainConfig) -> anyhow::Result<()> {
    let genesis = rpc
        .genesis_hash()
        .await
        .context("reading the genesis hash")?;
    if Some(genesis) != chain.genesis() {
        bail!(
            "the RPC providers serve genesis {}, not the configured {}",
            b58(&genesis),
            chain.genesis_hash
        );
    }
    Ok(())
}

fn refuse_plaintext_with_tls(tls: Option<&timescales_service::TlsConfig>) -> anyhow::Result<()> {
    if tls.is_some_and(|t| t.is_configured()) {
        // timescales-service has the server configuration
        // (`tls::server_config`) but no listener that terminates TLS, and
        // this crate has no TLS dependency of its own. Serving plaintext
        // when the operator asked for mutual TLS is not an option.
        bail!(
            "[tls] is configured, but this build cannot serve mutual TLS \
             refusing to listen in plaintext"
        );
    }
    Ok(())
}

struct MemberReady {
    member: Arc<Member>,
    chain: Arc<RpcKrcChain>,
}

impl ReadinessProbe for MemberReady {
    fn ready(&self) -> BoxFuture<'_, Readiness> {
        Box::pin(async move {
            let store = self.member.store_ok().await;
            let chain = now_ms().saturating_sub(self.chain.last_success_ms()) < FRESH_CHAIN_MS;
            Readiness {
                ready: store && chain,
                checks: vec![("store".to_owned(), store), ("chain".to_owned(), chain)],
            }
        })
    }
}

async fn serve(
    addr: String,
    router: axum::Router,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("listen address {addr}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(%addr, "listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("serving")
}

/// `member run`. Returns the process exit code.
pub async fn run_member(cfg: MemberConfig, shutdown: CancellationToken) -> anyhow::Result<i32> {
    let build = build_info();
    refuse_simulation(cfg.profile, &build)?;
    refuse_plaintext_with_tls(cfg.tls.as_ref())?;
    timescales_service::tls::install_default_provider();

    let identity = keys::ed25519_seed(&cfg.identity_key)?;
    let transport = keys::x25519_secret(&cfg.transport_key)?;
    let at_rest = Arc::new(at_rest_key(&cfg.kek_file)?);
    let repo = open_member_repo(&cfg, &at_rest)?;

    let rpc = quorum_rpc(&cfg.chain)?;
    check_genesis(&rpc, &cfg.chain).await?;
    let program = cfg.chain.program().context("chain.program_id")?;
    let chain = Arc::new(RpcKrcChain::new(
        rpc,
        program,
        cfg.chain.release_level(),
        Duration::from_millis(cfg.chain.confirmed_cache_ms.unwrap_or(CONFIRMED_CACHE_MS)),
    ));
    let verifiers =
        Arc::new(PlatformVerifiers::from_config(&cfg.policy).map_err(anyhow::Error::msg)?);
    let policy = cfg
        .policy
        .attestation_policy()
        .map_err(ConfigError::Invalid)?;
    let tee_platform = if cfg.policy.intel_tdx() {
        "intel_tdx"
    } else {
        "simulated"
    };
    let limits = HttpLimits {
        max_body_bytes: MessageKind::ReleaseRequest.max_envelope_len(),
        request_timeout: Duration::from_secs(10),
        max_concurrency: 64,
        per_caller_rps: cfg.per_caller_rps,
        per_caller_burst: cfg.per_caller_burst,
    };
    let listen = cfg.listen.clone();
    let ops_listen = cfg.ops_listen.clone();
    let prune_every = Duration::from_millis(cfg.prune_interval_ms);
    let collateral = cfg.policy.tdx_collateral_file.clone();
    let member = Arc::new(Member::new(
        cfg,
        MemberKeys {
            identity,
            transport,
            at_rest,
        },
        repo,
        Arc::clone(&chain) as Arc<dyn KrcChain>,
        Arc::clone(&verifiers) as Arc<dyn timescales_executor::attestation::QuoteVerifier>,
        policy,
    )?);

    let mut metrics = Metrics::new(&build, tee_platform);
    member.metrics().register(&mut metrics.registry);
    chain.register_metrics(&mut metrics.registry);
    let ops = ops_router(
        Arc::new(metrics),
        Arc::new(MemberReady {
            member: Arc::clone(&member),
            chain: Arc::clone(&chain),
        }),
    );

    let exit = Arc::new(AtomicU64::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    {
        let (member, shutdown, exit) = (Arc::clone(&member), shutdown.clone(), Arc::clone(&exit));
        tasks.spawn(async move {
            let mut tick = tokio::time::interval(prune_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = tick.tick() => {}
                }
                if let Err(e) = member.prune().await {
                    tracing::warn!(error = %e, "prune failed");
                }
                if !member.store_ok().await {
                    tracing::error!("store closed after a write error; exiting");
                    exit.store(
                        u64::try_from(EXIT_STORE_FAILED).unwrap_or(1),
                        Ordering::SeqCst,
                    );
                    shutdown.cancel();
                    break;
                }
            }
        });
    }
    if let (Some(path), Some(tdx)) = (collateral, verifiers.tdx()) {
        let (member, shutdown) = (Arc::clone(&member), shutdown.clone());
        let mut watch = CollateralWatch::new(path, Arc::clone(tdx));
        tasks.spawn(async move {
            let mut tick = tokio::time::interval(COLLATERAL_POLL);
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = tick.tick() => {}
                }
                let expires = watch.poll();
                member
                    .metrics()
                    .collateral_expiry
                    .set(i64::try_from(expires).unwrap_or(i64::MAX));
            }
        });
    }
    let api = crate::member::router(Arc::clone(&member), limits);
    let served = tokio::try_join!(
        serve(listen, api, shutdown.clone()),
        serve(ops_listen, ops, shutdown.clone())
    );
    shutdown.cancel();
    while tasks.join_next().await.is_some() {}
    served?;
    Ok(i32::try_from(exit.load(Ordering::SeqCst)).unwrap_or(1))
}

/// `member rekey`: advances the at-rest key one generation and erases
/// every older generation no stored share is sealed under. Run it while
/// the member is stopped: a running member keeps its own copy of the key
/// file in memory.
pub async fn rekey(cfg: &MemberConfig) -> anyhow::Result<u32> {
    let at_rest = Arc::new(
        RatchetSealer::load(&cfg.kek_file)
            .with_context(|| format!("loading {}", cfg.kek_file.display()))?,
    );
    let repo = open_member_repo(cfg, &at_rest)?;
    let generation = at_rest.advance()?;
    repo.ratchet(generation).await?;
    Ok(generation)
}

struct DealerReady {
    last_round_ms: Arc<AtomicU64>,
    interval_ms: u64,
}

impl ReadinessProbe for DealerReady {
    fn ready(&self) -> BoxFuture<'_, Readiness> {
        Box::pin(async move {
            let last = self.last_round_ms.load(Ordering::Relaxed);
            let fresh = now_ms().saturating_sub(last) < FRESH_CHAIN_MS.max(3 * self.interval_ms);
            Readiness {
                ready: fresh,
                checks: vec![("rounds".to_owned(), fresh)],
            }
        })
    }
}

fn dealer_parts(
    cfg: &DealerConfig,
) -> anyhow::Result<(
    timescales_core::crypto::Keypair,
    DealerRepo,
    Arc<dyn SolanaRpc>,
)> {
    let identity = keys::ed25519_seed(&cfg.identity_key)?;
    create_dir(&cfg.data_dir)?;
    let repo = DealerRepo::new(open_store(
        &cfg.data_dir.join("dealer.sqlite"),
        Schema::Dealer,
    )?);
    let rpc: Arc<dyn SolanaRpc> = Arc::new(HttpRpc::new(
        cfg.chain.rpc_urls.clone(),
        Duration::from_millis(cfg.chain.rpc_timeout_ms),
    )?);
    Ok((identity, repo, rpc))
}

/// `dealer`. Returns the process exit code.
pub async fn run_dealer(cfg: DealerConfig, shutdown: CancellationToken) -> anyhow::Result<i32> {
    let build = build_info();
    refuse_simulation(cfg.profile, &build)?;
    timescales_service::tls::install_default_provider();
    let (identity, repo, rpc) = dealer_parts(&cfg)?;
    check_genesis(&rpc, &cfg.chain).await?;
    let ops_listen = cfg.ops_listen.clone();
    let interval_ms = cfg.interval_ms;
    let dealer = Dealer::new(cfg, identity, repo, rpc)?;
    let mut metrics = Metrics::new(&build, "none");
    dealer.metrics().register(&mut metrics.registry);
    let last_round_ms = dealer.last_round();
    let ops = ops_router(
        Arc::new(metrics),
        Arc::new(DealerReady {
            last_round_ms,
            interval_ms,
        }),
    );
    let ops_task = tokio::spawn(serve(ops_listen, ops, shutdown.clone()));
    let result = dealer.run(shutdown.clone()).await;
    shutdown.cancel();
    ops_task.await.context("ops listener")??;
    match result {
        Ok(()) => Ok(0),
        Err(crate::dealer::DealError::Krc(crate::KrcError::Store(e))) => {
            tracing::error!(error = %e, "store failed; exiting");
            Ok(EXIT_STORE_FAILED)
        }
        Err(e) => Err(e.into()),
    }
}

/// `dealer supersede`: drops the dealings of the previous committee from
/// `from_epoch` on (emergency rotation).
pub async fn supersede(
    cfg: DealerConfig,
    market: [u8; 32],
    from_epoch: u64,
) -> anyhow::Result<u64> {
    timescales_service::tls::install_default_provider();
    let (identity, repo, rpc) = dealer_parts(&cfg)?;
    check_genesis(&rpc, &cfg.chain).await?;
    let dealer = Dealer::new(cfg, identity, repo, rpc)?;
    Ok(dealer
        .supersede(market, timescales_core::EpochId(from_epoch))
        .await?)
}
