//! Process wiring for the `timescales-enclave` binary: configuration
//! loading and checks, RPC and market chains, the fee payer, the API and
//! ops listeners, and the background tasks.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use timescales_chain::{
    Address, FileSigner, Level, MarketChain, MarketChainConfig, MinimalRpc, QuorumRpc,
    SolanaMarketChain, SolanaRpc, TxSender, TxSigner,
};
use timescales_service::{
    ConfigError, ConfigIssue, HttpLimits, Metrics, Profile, Readiness, ReadinessProbe, keys,
    load_config, ops_router,
};

use crate::config::{EnclaveConfig, EnclaveFile, load_committee, parse_b58_32};
use crate::{EnclaveService, TxLog, router};

/// How long a sent transaction is polled before its outcome counts as
/// unknown (the market chain then observes again).
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(60);
/// How often the fee payer's balance is read.
const FEE_PAYER_POLL: Duration = Duration::from_secs(30);

fn config_dir(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new("."))
}

/// Loads and validates an enclave file. Relative paths resolve against
/// its directory.
pub fn load(path: &Path, profile: Option<Profile>) -> Result<EnclaveConfig, ConfigError> {
    let mut cfg = load_config::<EnclaveFile>(path, profile)?.enclave;
    cfg.resolve_paths(config_dir(path));
    Ok(cfg)
}

/// RPC providers of the chain section: `rpc_agree` of them must agree on
/// every read. Installs the ring provider reqwest needs first.
pub fn quorum_rpc(cfg: &EnclaveConfig) -> anyhow::Result<Arc<dyn SolanaRpc>> {
    timescales_service::tls::install_default_provider();
    let timeout = Duration::from_millis(cfg.chain.rpc_timeout_ms);
    let providers = cfg
        .chain
        .rpc_urls
        .iter()
        .map(|u| {
            MinimalRpc::new(vec![u.clone()], timeout)
                .map(|r| Arc::new(r) as Arc<dyn SolanaRpc>)
                .with_context(|| format!("RPC client for {u}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Arc::new(QuorumRpc::new(providers, cfg.chain.rpc_agree)?))
}

/// The chain bindings `config-check` checks without `--offline`: the
/// genesis hash, the program and every market, whose committee digest must
/// be the configured committee's (current or previous).
pub async fn chain_issues(cfg: &EnclaveConfig) -> anyhow::Result<Vec<ConfigIssue>> {
    let mut issues = Vec::new();
    let rpc = quorum_rpc(cfg)?;
    let genesis = rpc
        .genesis_hash()
        .await
        .context("reading the genesis hash")?;
    if Some(genesis) != cfg.chain.genesis() {
        issues.push(ConfigIssue::new(
            "enclave.chain.genesis_hash",
            format!(
                "the cluster's genesis hash is {}",
                bs58::encode(genesis).into_string()
            ),
        ));
    }
    let program = cfg.chain.program().unwrap_or_default();
    if rpc
        .get_account(program, Level::Confirmed, None)
        .await?
        .is_none()
    {
        issues.push(ConfigIssue::new(
            "enclave.chain.program_id",
            "no such account on the cluster",
        ));
    }
    for (i, entry) in cfg.markets.iter().enumerate() {
        let Some(address) = parse_b58_32(&entry.address) else {
            continue;
        };
        let f = format!("enclave.market[{i}]");
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
        if digest != market.committee_digest && digest != market.prev_committee_digest {
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

/// The fee payer from its Solana key file (it only pays fees).
pub fn fee_payer(cfg: &EnclaveConfig) -> anyhow::Result<Arc<dyn TxSigner>> {
    let bytes = keys::solana_keypair_bytes(&cfg.fee_payer_keypair)?;
    Ok(Arc::new(FileSigner::from_bytes(bytes).map_err(|e| {
        anyhow::anyhow!("{}: {e}", cfg.fee_payer_keypair.display())
    })?))
}

/// One `SolanaMarketChain` per configured market over `rpc`, sharing one
/// sender whose journal is `log`.
pub fn market_chains(
    cfg: &EnclaveConfig,
    rpc: &Arc<dyn SolanaRpc>,
    log: &Arc<TxLog>,
) -> anyhow::Result<BTreeMap<Address, Arc<dyn MarketChain>>> {
    let program = cfg.chain.program().context("enclave.chain.program_id")?;
    let fees = cfg
        .chain
        .fee_policy()
        .context("enclave.chain.priority_fee")?;
    let poll = Duration::from_millis(cfg.chain.poll_interval_ms);
    let sender = Arc::new(TxSender::new(
        Arc::clone(rpc),
        fees,
        Arc::clone(log) as Arc<dyn timescales_chain::TxJournal>,
        poll,
        CONFIRM_TIMEOUT,
    ));
    let chain_cfg = MarketChainConfig {
        poll_interval: poll,
        ..MarketChainConfig::default()
    };
    Ok(cfg
        .market_addresses()
        .into_iter()
        .map(|m| {
            let chain: Arc<dyn MarketChain> = Arc::new(SolanaMarketChain::new(
                Arc::clone(rpc),
                Arc::clone(&sender),
                program,
                m,
                chain_cfg,
            ));
            (m, chain)
        })
        .collect())
}

/// The listener limits of the enclave API.
pub fn http_limits(cfg: &EnclaveConfig) -> HttpLimits {
    HttpLimits {
        max_body_bytes: usize::try_from(cfg.max_body_bytes).unwrap_or(usize::MAX),
        request_timeout: Duration::from_secs(10),
        max_concurrency: 64,
        per_caller_rps: 5,
        per_caller_burst: 10,
    }
}

struct Ready(Arc<EnclaveService>);

impl ReadinessProbe for Ready {
    fn ready(&self) -> timescales_service::BoxFuture<'_, Readiness> {
        Box::pin(async move { self.0.readiness() })
    }
}

async fn serve(
    addr: String,
    router: axum::Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("listen address {addr}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(%addr, "listening");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .context("serving")
}

/// `run`: boots the enclave and serves until `shutdown` resolves.
pub async fn run(
    cfg: EnclaveConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    if cfg.tls_config().is_some() {
        // timescales-service has the server configuration but no listener
        // that terminates TLS, and this crate has no TLS dependency of its
        // own. Serving plaintext when the operator asked for mutual TLS is
        // not an option.
        bail!(
            "[enclave.tls] is configured, but this build cannot serve mutual TLS \
             refusing to listen in plaintext"
        );
    }
    let rpc = quorum_rpc(&cfg)?;
    let genesis = rpc
        .genesis_hash()
        .await
        .context("reading the genesis hash")?;
    if Some(genesis) != cfg.chain.genesis() {
        bail!(
            "the RPC providers serve genesis {}, not the configured {}",
            bs58::encode(genesis).into_string(),
            cfg.chain.genesis_hash
        );
    }
    let log = Arc::new(TxLog::new());
    let chains = market_chains(&cfg, &rpc, &log)?;
    let payer = fee_payer(&cfg)?;
    let payer_address = payer.address();
    let limits = http_limits(&cfg);
    let (listen, ops_listen) = (cfg.listen.clone(), cfg.ops_listen.clone());
    let svc = Arc::new(EnclaveService::boot(cfg, chains, payer)?.with_tx_log(log));

    let mut metrics = Metrics::new(&crate::build_info(), svc.platform_name());
    svc.metrics().register(&mut metrics.registry);
    let ops = ops_router(Arc::new(metrics), Arc::new(Ready(Arc::clone(&svc))));

    let backstops = svc.spawn_backstops();
    let balance = {
        let (rpc, gauge) = (Arc::clone(&rpc), svc.metrics().fee_payer_balance.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FEE_PAYER_POLL);
            loop {
                tick.tick().await;
                match rpc.get_account(payer_address, Level::Confirmed, None).await {
                    Ok(a) => {
                        let lamports = a.map_or(0, |a| a.lamports);
                        gauge.set(i64::try_from(lamports).unwrap_or(i64::MAX));
                    }
                    Err(e) => tracing::debug!(error = %e, "reading the fee payer's balance"),
                }
            }
        })
    };
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|s| *s).await;
    };
    let signal = tokio::spawn(async move {
        shutdown.await;
        let _ = stop_tx.send(true);
    });
    let api = router(Arc::clone(&svc), limits);
    let served = tokio::try_join!(
        serve(listen, api, stopped(stop_rx.clone())),
        serve(ops_listen, ops, stopped(stop_rx))
    );
    backstops.abort();
    balance.abort();
    signal.abort();
    served.map(|_| ())
}
