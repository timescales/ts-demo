//! Wiring of the binary (start-up order): configuration, the
//! data-directory lock, store, keys, RPC, chain adapters, enclave clients,
//! the engine, and the listeners. Also the offline commands of the CLI.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use axum::serve::ListenerExt;
use timescales_chain::{FileSigner, HttpRpc, Level, MarketChain, SolanaRpc, TxSigner};
use timescales_core::crypto::Keypair;
use timescales_core::{Decode, Encode, EpochId};
use timescales_service::store::node::NodeRepo;
use timescales_service::store::{KekSealer, Schema, Store, StoreOptions};
use timescales_service::{
    BuildInfo, Metrics, Profile, Readiness, ReadinessProbe, SignedClient, refuse_simulation,
};
use zeroize::Zeroizing;

use crate::archive::Archive;
use crate::config::{ChainFacts, ExpectedPlatform, NodeConfig, Synchronous, check_chain_bindings};
use crate::exec::{EnclaveInfo, HttpExecClient};
use crate::handle::{NodeHandle, start_with_metrics};
use crate::telemetry::NodeMetrics;
use crate::{Address, BoxFuture, ExecClient, NodeApi, NodeKeys, SystemClock};

/// Exit code when another process holds the data directory.
pub const EXIT_LOCKED: i32 = 75;
/// Exit code after a store write error (fail-stop).
pub const EXIT_STORE: i32 = 70;

/// What this binary was built with.
pub fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
        git_sha: option_env!("TIMESCALES_GIT_SHA").unwrap_or("unknown"),
        simulation: timescales_service::relay::SIMULATION_BUILD
            || timescales_executor::SIMULATION_BUILD
            || timescales_auction::SIMULATION_BUILD
            || timescales_core::oracle::SIMULATION_BUILD,
        // The node does not link the attestation crate's simulated
        // platform directly. A simulation build of its dependencies sets
        // the flags above.
        sim_platform: false,
    }
}

/// An exclusive lock on `data_dir/LOCK`, held for the life of the process.
#[derive(Debug)]
pub struct DataDirLock {
    _file: File,
}

/// `Err(None)` when another process holds the lock.
pub fn lock_data_dir(dir: &Path) -> Result<DataDirLock, Option<std::io::Error>> {
    std::fs::create_dir_all(dir).map_err(Some)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("LOCK"))
        .map_err(Some)?;
    match file.try_lock() {
        Ok(()) => Ok(DataDirLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(None),
        Err(std::fs::TryLockError::Error(e)) => Err(Some(e)),
    }
}

pub fn store_options(cfg: &NodeConfig) -> StoreOptions {
    StoreOptions {
        synchronous_full: cfg.store.synchronous == Synchronous::Full,
        group_commit_ms: cfg.store.group_commit_ms,
        group_commit_max: cfg.store.group_commit_max,
        readers: cfg.store.readers,
        busy_timeout_ms: cfg.store.busy_timeout_ms,
        queue: cfg.store.queue,
        secure_delete: false,
    }
}

pub fn open_store(cfg: &NodeConfig) -> anyhow::Result<NodeRepo> {
    let path = cfg.node.data_dir.join("node.sqlite");
    let store = Store::open(&path, Schema::Node, store_options(cfg))
        .with_context(|| format!("opening {}", path.display()))?;
    Ok(NodeRepo::new(store))
}

fn solana_signer(path: &Path) -> anyhow::Result<(Arc<dyn TxSigner>, Keypair)> {
    let bytes = timescales_service::keys::solana_keypair_bytes(path)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[..32]);
    let keypair = Keypair::from_seed(seed);
    seed.fill(0);
    let signer = FileSigner::from_bytes(bytes).map_err(|e| anyhow!("{}: {e}", path.display()))?;
    Ok((Arc::new(signer), keypair))
}

/// Loads every key of `[keys]`: permission checks, zeroizing
/// buffers, nothing logged.
pub fn load_keys(cfg: &NodeConfig) -> anyhow::Result<NodeKeys> {
    let (relay, relay_signing) = solana_signer(&cfg.keys.relay_keypair)?;
    let (cranker, _) = solana_signer(&cfg.keys.cranker_keypair)?;
    let service = timescales_service::keys::ed25519_seed(&cfg.keys.service_key)?;
    let kek = timescales_service::keys::kek(&cfg.keys.kek_file)?;
    let nonce = timescales_service::keys::kek(&cfg.keys.nonce_key_file)?;
    Ok(NodeKeys {
        relay,
        relay_signing: Arc::new(relay_signing),
        cranker,
        service: Arc::new(service),
        kek: Arc::new(KekSealer::new(Zeroizing::new(*kek.as_bytes()))),
        nonce_key: Zeroizing::new(*nonce.as_bytes()),
    })
}

pub fn rpc(cfg: &NodeConfig) -> anyhow::Result<Arc<dyn SolanaRpc>> {
    let rpc = HttpRpc::new(
        cfg.solana.rpc_urls.clone(),
        Duration::from_millis(cfg.solana.rpc_timeout_ms),
    )?;
    Ok(Arc::new(rpc))
}

fn market_addresses(cfg: &NodeConfig) -> Vec<Address> {
    cfg.markets
        .iter()
        .filter_map(|m| crate::config::base58_32(&m.address))
        .collect()
}

/// Reads what the online rules compare against.
pub async fn chain_facts(
    cfg: &NodeConfig,
    rpc: &Arc<dyn SolanaRpc>,
    relay: Address,
    cranker: Address,
) -> anyhow::Result<ChainFacts> {
    let program = cfg.program_id().ok_or_else(|| anyhow!("bad program id"))?;
    let genesis_hash = rpc.genesis_hash().await?;
    let mut markets = Vec::new();
    for m in &cfg.markets {
        let files = m.files(&program).map_err(|issues| {
            anyhow!(
                "{}",
                issues
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })?;
        let account = rpc
            .get_account(files.address, Level::Confirmed, None)
            .await?
            .ok_or_else(|| anyhow!("market account {} not found", m.address))?;
        if account.owner != program {
            bail!("market account {} is not owned by the program", m.address);
        }
        let market = timescales_chain::program::decode_market(&account.data)
            .map_err(|e| anyhow!("market account {}: {e}", m.address))?;
        markets.push((files, market));
    }
    let (_, balances) = rpc
        .get_multiple_accounts(vec![relay, cranker], Level::Confirmed, None)
        .await?;
    let lamports = |i: usize| {
        balances
            .get(i)
            .and_then(|a| a.as_ref())
            .map_or(0, |a| a.lamports)
    };
    Ok(ChainFacts {
        genesis_hash,
        markets,
        relay,
        relay_balance: lamports(0),
        cranker_balance: lamports(1),
        pinned_executors: cfg
            .execution
            .enclaves
            .iter()
            .filter_map(EnclaveInfo::from_config)
            .map(|e| e.executor)
            .collect(),
        batch_rent: rpc
            .minimum_balance_for_rent_exemption(timescales_chain::program::BATCH_LEN)
            .await?,
    })
}

/// The platform check: what every configured enclave's identity says
/// against `expected_platform`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PlatformCheck {
    /// Enclaves that report another platform.
    pub mismatched: Vec<String>,
    /// Enclaves whose identity could not be read, with the reason.
    pub unverified: Vec<String>,
}

pub async fn platform_check(cfg: &NodeConfig, exec: &dyn ExecClient) -> PlatformCheck {
    // The wire encoding of `timescales_executor::attestation::Platform`.
    let (expected, name) = match cfg.execution.expected_platform {
        ExpectedPlatform::Simulated => (0u8, "simulated"),
        ExpectedPlatform::IntelTdx => (1u8, "intel_tdx"),
    };
    let mut out = PlatformCheck::default();
    for (i, e) in cfg.execution.enclaves.iter().enumerate() {
        match exec.identity(i).await {
            Ok(id) if id.platform as u8 == expected => {}
            Ok(id) => out.mismatched.push(format!(
                "enclave {} reports platform {:?}, expected_platform is {name}",
                e.url, id.platform
            )),
            Err(err) => out.unverified.push(format!("enclave {}: {err}", e.url)),
        }
    }
    out
}

/// Whether `run` may start after `check`: a mismatch never may. An
/// unverified enclave may outside production, or with
/// `execution.allow_unverified_platform`. Returns the warnings to log.
pub fn platform_verdict(cfg: &NodeConfig, check: &PlatformCheck) -> anyhow::Result<Vec<String>> {
    if !check.mismatched.is_empty() {
        bail!(
            "enclave platform check failed: {}",
            check.mismatched.join("; ")
        );
    }
    if check.unverified.is_empty() {
        return Ok(Vec::new());
    }
    let detail = check.unverified.join("; ");
    if cfg.node.profile == Profile::Production && !cfg.execution.allow_unverified_platform {
        bail!(
            "the enclave platform check (expected_platform against /enclave/v1/identity) could \
             not be performed ({detail}); set execution.allow_unverified_platform = true to \
             start anyway"
        );
    }
    Ok(vec![format!(
        "the enclave platform check (expected_platform against /enclave/v1/identity) was not \
         performed: {detail}; trust.enclave in /v1/info is the configured value, not a checked one"
    )])
}

/// The start-up warnings section K requires for what is simulated or
/// untested in this deployment.
pub fn trust_warnings(cfg: &NodeConfig) -> Vec<&'static str> {
    match cfg.execution.expected_platform {
        ExpectedPlatform::Simulated => vec![
            "Enclave: SIMULATED. The enclaves run as ordinary processes; their host operators \
             can read every order they execute",
        ],
        ExpectedPlatform::IntelTdx => {
            vec!["TDX quote generation uses configfs-tsm, which is untested on hardware"]
        }
    }
}

/// `config-check`: offline rules, and unless `offline` the chain bindings.
pub async fn config_check(
    path: &Path,
    profile: Option<Profile>,
    offline: bool,
) -> anyhow::Result<()> {
    let cfg = NodeConfig::load(path, profile)?;
    refuse_simulation(cfg.node.profile, &build_info())?;
    println!(
        "{}: offline rules pass (profile {})",
        path.display(),
        cfg.node.profile
    );
    for w in cfg.warnings() {
        println!("warning: {w}");
    }
    for w in trust_warnings(&cfg) {
        println!("warning: {w}");
    }
    if offline {
        return Ok(());
    }
    let keys = load_keys(&cfg)?;
    let rpc = rpc(&cfg)?;
    let facts = chain_facts(&cfg, &rpc, keys.relay.address(), keys.cranker.address()).await?;
    let (issues, warnings) = check_chain_bindings(&cfg, &facts);
    for w in &warnings {
        println!("warning: {w}");
    }
    let exec = exec_client(&cfg, keys.service.clone())?;
    let platforms = platform_check(&cfg, &*exec).await;
    match platform_verdict(&cfg, &platforms) {
        Ok(warnings) => {
            for w in warnings {
                println!("warning: {w}");
            }
        }
        Err(e) => {
            println!("error: {e}");
            bail!("enclave platform check");
        }
    }
    if !issues.is_empty() {
        for i in &issues {
            println!("error: {i}");
        }
        bail!("{} chain binding issue(s)", issues.len());
    }
    println!("chain bindings pass");
    Ok(())
}

struct Ready(Arc<NodeHandle>);

impl ReadinessProbe for Ready {
    fn ready(&self) -> BoxFuture<'_, Readiness> {
        Box::pin(async move {
            let store = !self.0.store().store().is_closed();
            let markets = self.0.ready();
            Readiness {
                ready: store && markets,
                checks: vec![("store".into(), store), ("markets".into(), markets)],
            }
        })
    }
}

/// `run`: the start-up order, then the listeners until SIGTERM.
pub async fn run(
    path: &Path,
    profile: Option<Profile>,
    accept_chain_ahead: bool,
) -> anyhow::Result<i32> {
    let mut cfg = NodeConfig::load(path, profile)?;
    cfg.node.accept_chain_ahead |= accept_chain_ahead;
    refuse_simulation(cfg.node.profile, &build_info())?;
    let _telemetry = timescales_service::init_telemetry(&cfg.telemetry, "timescales-node")?;
    for w in cfg.warnings() {
        tracing::warn!("{w}");
    }
    for w in trust_warnings(&cfg) {
        tracing::warn!("{w}");
    }
    let _lock = match lock_data_dir(&cfg.node.data_dir) {
        Ok(l) => l,
        Err(None) => {
            tracing::error!("another process holds {}/LOCK", cfg.node.data_dir.display());
            return Ok(EXIT_LOCKED);
        }
        Err(Some(e)) => return Err(e.into()),
    };
    let repo = Arc::new(open_store(&cfg)?);
    let keys = load_keys(&cfg)?;
    // The internal key route signs its answers with the service key.
    let service = keys.service.clone();
    let rpc = rpc(&cfg)?;
    let program = cfg.program_id().ok_or_else(|| anyhow!("bad program id"))?;
    let sender = crate::chain::sender(rpc.clone(), repo.clone(), &cfg.solana);
    let resolved = sender.resolve_pending().await?;
    tracing::info!(
        resolved = resolved.len(),
        "journalled transactions resolved"
    );
    let last_landed = timescales_chain::TxJournal::last_landed_slot(&*repo).await?;
    let addresses = market_addresses(&cfg);
    let chains = crate::chain::markets(
        rpc.clone(),
        sender,
        program,
        &addresses,
        crate::chain::chain_config(&cfg.solana, &cfg.execution),
        last_landed,
    );
    let facts = chain_facts(&cfg, &rpc, keys.relay.address(), keys.cranker.address()).await?;
    let (issues, warnings) = check_chain_bindings(&cfg, &facts);
    for w in warnings {
        tracing::warn!("{w}");
    }
    if !issues.is_empty() {
        for i in &issues {
            tracing::error!("{i}");
        }
        bail!("{} chain binding issue(s)", issues.len());
    }
    let exec = exec_client(&cfg, keys.service.clone())?;
    for w in platform_verdict(&cfg, &platform_check(&cfg, &*exec).await)? {
        tracing::warn!("{w}");
    }
    let platform = match cfg.execution.expected_platform {
        crate::config::ExpectedPlatform::Simulated => "simulated",
        crate::config::ExpectedPlatform::IntelTdx => "intel_tdx",
    };
    let mut metrics = Metrics::new(&build_info(), platform);
    let node_metrics = Arc::new(NodeMetrics::register(&mut metrics.registry));
    let metrics = Arc::new(metrics);
    let genesis = facts.genesis_hash;
    let store_for_watch = repo.clone();
    let handle = Arc::new(
        start_with_metrics(
            cfg.clone(),
            chains,
            rpc,
            repo,
            exec,
            Arc::new(SystemClock),
            keys,
            node_metrics,
            program,
            genesis,
        )
        .await?,
    );
    let api: Arc<dyn NodeApi> = handle.clone();
    let public = crate::api::router(api.clone(), cfg.api.clone());
    let admin = crate::api::admin_router_with(
        api,
        cfg.admin.clone(),
        crate::api::AdminOptions {
            service: Some(service),
            ..crate::api::AdminOptions::default()
        },
    );
    let ops = timescales_service::ops_router(metrics, Arc::new(Ready(handle.clone())));
    let serve = |addr: &str, router: axum::Router| {
        let addr = addr.to_owned();
        async move {
            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .with_context(|| format!("binding {addr}"))?
                // Stream frames and small replies leave as they are written.
                .tap_io(|tcp| {
                    let _ = tcp.set_nodelay(true);
                });
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(timescales_service::shutdown_signal())
            .await?;
            anyhow::Ok(())
        }
    };
    let store_down = async move {
        loop {
            if store_for_watch.store().is_closed() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    let code = tokio::select! {
        r = serve(&cfg.api.listen, public) => { r?; 0 }
        r = serve(&cfg.admin.listen, admin) => { r?; 0 }
        r = serve(&cfg.metrics.listen, ops) => { r?; 0 }
        () = store_down => {
            tracing::error!("store closed after a write error; exiting");
            EXIT_STORE
        }
    };
    if let Ok(h) = Arc::try_unwrap(handle) {
        h.shutdown().await?;
    }
    Ok(code)
}

/// One `SignedClient` per configured enclave, pinned to its identity.
pub fn exec_client(
    cfg: &NodeConfig,
    signer: Arc<dyn timescales_service::wire::EnvelopeSigner>,
) -> anyhow::Result<Arc<HttpExecClient>> {
    let tls = cfg
        .tls
        .clone()
        .filter(timescales_service::TlsConfig::is_configured);
    let timeout = Duration::from_millis(cfg.execution.attempt_timeout_ms);
    let mut clients = Vec::new();
    for e in &cfg.execution.enclaves {
        let info = EnclaveInfo::from_config(e).ok_or_else(|| anyhow!("bad enclave entry"))?;
        let client = SignedClient::new(signer.clone(), info.identity, tls.clone(), timeout)?;
        clients.push((info.url, client));
    }
    Ok(Arc::new(HttpExecClient::new(clients)))
}

/// `migrate`: open the store, which applies pending migrations after a
/// pre-migration copy. With `check`, a temporary copy is migrated instead
/// and the database is left as it is.
pub fn migrate(path: &Path, profile: Option<Profile>, check: bool) -> anyhow::Result<()> {
    let cfg = NodeConfig::load(path, profile)?;
    let db = cfg.node.data_dir.join("node.sqlite");
    if check {
        let dir =
            std::env::temp_dir().join(format!("timescales-node-migrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let copy = dir.join("node.sqlite");
        if db.is_file() {
            std::fs::copy(&db, &copy)?;
        }
        let store = Store::open(&copy, Schema::Node, store_options(&cfg))?;
        println!(
            "migrations apply cleanly; schema version {}",
            store.schema_version()
        );
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
        return Ok(());
    }
    let store = Store::open(&db, Schema::Node, store_options(&cfg))?;
    println!("schema version {}", store.schema_version());
    Ok(())
}

/// `backup --to`: an online copy with the private tables stripped.
pub async fn backup(path: &Path, profile: Option<Profile>, to: PathBuf) -> anyhow::Result<()> {
    let cfg = NodeConfig::load(path, profile)?;
    let repo = open_store(&cfg)?;
    let report = repo.backup(to).await?;
    println!(
        "{} bytes to {} (stripped: {}; integrity {})",
        report.bytes,
        report.path.display(),
        report.stripped.join(", "),
        if report.integrity_ok { "ok" } else { "FAILED" }
    );
    if !report.integrity_ok {
        bail!("the backup failed its integrity check");
    }
    Ok(())
}

/// `recover-state --market`: rebuild the carried order state of the last
/// settled epoch from the archived fills and cancels of the epochs that
/// can still hold live orders, check it against `Market.state_root`, and
/// store it ("carried state").
pub async fn recover_state(
    path: &Path,
    profile: Option<Profile>,
    market: &str,
) -> anyhow::Result<()> {
    let cfg = NodeConfig::load(path, profile)?;
    let program = cfg.program_id().ok_or_else(|| anyhow!("bad program id"))?;
    let mcfg = cfg
        .markets
        .iter()
        .find(|m| m.address == market)
        .ok_or_else(|| anyhow!("market {market} is not configured"))?;
    let files = mcfg
        .files(&program)
        .map_err(|_| anyhow!("market files of {market} do not load"))?;
    let rpc = rpc(&cfg)?;
    let account = rpc
        .get_account(files.address, Level::Confirmed, None)
        .await?
        .ok_or_else(|| anyhow!("market account not found"))?;
    let m = timescales_chain::program::decode_market(&account.data).map_err(|e| anyhow!("{e}"))?;
    let repo = open_store(&cfg)?;
    let archive = Archive::new(&cfg.node.data_dir);
    match rebuild_carried_state(&repo, &archive, files.address, &files.params, &m).await? {
        Some((epoch, replayed)) => println!(
            "carried state of epoch {epoch} rebuilt from {replayed} archived epochs; root matches the chain"
        ),
        None => println!("nothing settled yet; the carried state is empty"),
    }
    Ok(())
}

/// Rebuilds the carried order state of `m.last_settled` from the archive
/// and stores it with that epoch's archived result. Returns the epoch and
/// how many archived epochs were replayed. The replay starts two order
/// lifetimes back: an order's state entry is pruned by its creation epoch,
/// and an order changed inside the window may have been created up to one
/// lifetime before it.
pub async fn rebuild_carried_state(
    repo: &NodeRepo,
    archive: &Archive,
    market: Address,
    params: &timescales_core::MarketParams,
    m: &timescales_chain::program::MarketAccount,
) -> anyhow::Result<Option<(u64, u64)>> {
    let last = m.last_settled;
    if last == 0 {
        return Ok(None);
    }
    let lifetime = u64::from(params.max_order_lifetime);
    let from = last.saturating_sub(2 * lifetime + 1).max(1);
    let mut table = timescales_auction::orderbook::OrderStateTable::default();
    let mut last_record = None;
    let mut replayed = 0;
    for r in archive.records(&market, from, last)? {
        if r.terminal != crate::archive::Terminal::Settled {
            continue;
        }
        let artifacts =
            timescales_auction::receipts::ExecutionArtifacts::decode_exact(&r.artifacts)
                .map_err(|e| anyhow!("archived artifacts of epoch {}: {e}", r.epoch))?;
        table = crate::exec::replay(table, r.epoch, params.max_order_lifetime, &artifacts);
        replayed += 1;
        last_record = Some(r);
    }
    let Some(record) = last_record.filter(|r| r.epoch == last) else {
        bail!("the archive does not hold the last settled epoch {last}");
    };
    if table.root() != m.state_root {
        bail!("the replayed state root differs from Market.state_root");
    }
    let receipt = timescales_auction::receipts::ExecutionReceipt::decode_exact(&record.receipt)
        .map_err(|e| anyhow!("archived receipt: {e}"))?;
    let artifacts =
        timescales_auction::receipts::ExecutionArtifacts::decode_exact(&record.artifacts)
            .map_err(|e| anyhow!("archived artifacts: {e}"))?;
    repo.put_result(timescales_service::store::node::PostedResult {
        market,
        epoch: last,
        receipt: receipt.to_bytes(),
        artifacts: artifacts.to_bytes(),
        attestation: record.attestation.clone(),
        cosigs: record.cosigs.clone(),
        fills: Vec::new(),
        deltas: Vec::new(),
        cancelled: Vec::new(),
        order_state: table.to_bytes(),
        order_state_root: table.root(),
    })
    .await?;
    repo.confirm_order_state(market, last).await?;
    Ok(Some((EpochId(last).0, replayed)))
}

/// `healthcheck --url`: exit 0 when the URL answers 200 (plain HTTP, the
/// ops listener is private).
pub fn healthcheck(url: &str) -> anyhow::Result<bool> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("only http:// URLs are probed"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/readyz"),
    };
    let mut stream = std::net::TcpStream::connect(host)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )?;
    let mut head = [0u8; 16];
    let n = stream.read(&mut head)?;
    let line = String::from_utf8_lossy(&head[..n]);
    Ok(line.starts_with("HTTP/1.1 200") || line.starts_with("HTTP/1.0 200"))
}

/// Every chain adapter keyed by market, for tools.
pub type Chains = BTreeMap<Address, Arc<dyn MarketChain>>;
