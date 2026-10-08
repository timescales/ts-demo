//! The test world: LiteSVM with the program, a market with three
//! simulated enclaves and a receipt quorum of two, a test dealer, the node
//! under test on its own `FaultyRpc`, and a `ManualClock` that the harness
//! keeps at tokio's (paused) time.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tempfile::TempDir;
use timescales_chain::program::{BatchAccount, InitMarketArgs, MarketAccount, Side};
use timescales_chain::{
    FaultyRpc, FeeMode, FeePolicy, Level, LiteSvmRpc, MarketChain, MarketChainConfig,
    SolanaMarketChain, SolanaRpc, TxSender, TxSigner,
};
use timescales_core::crypto::Keypair;
use timescales_core::{
    CommitmentScheme, Encode, FeeBps, FlowMode, MarketId, MarketParams, Rationing,
};
use timescales_node::config::NodeConfig;
use timescales_node::handle::start_with_metrics;
use timescales_node::market::MarketView;
use timescales_node::telemetry::NodeMetrics;
use timescales_node::{ExecClient, ManualClock, NodeApi, NodeHandle, NodeKeys};
use timescales_service::relay::{Padding, RelayConfig};
use timescales_service::store::node::{EpochRow, NodeRepo, Phase};
use timescales_service::store::{KekSealer, Schema, Store, StoreOptions};
use zeroize::Zeroizing;

use super::dealer::Dealer;
use super::enclave::FakeEnclaves;
use super::svm::{self, MemJournal, airdrop, key, seed};
use super::trader::Trader;

/// Unix time the manual clock starts at.
pub const BASE_MS: u64 = 1_800_000_000_000;

#[derive(Clone, Debug)]
pub struct Options {
    pub enclaves: usize,
    pub quorum: u8,
    pub interval_ms: u64,
    pub park_ahead: u32,
    pub idle: &'static str,
    pub reference_tick: u64,
    pub exec_timeout: u64,
    pub timelock: u64,
    pub min_value_per_envelope: u64,
    pub max_real: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            enclaves: 3,
            quorum: 2,
            interval_ms: 600_000,
            park_ahead: 4,
            idle: "commit",
            reference_tick: 100,
            exec_timeout: 1_000,
            timelock: 20,
            min_value_per_envelope: 1_000,
            max_real: 1024,
        }
    }
}

pub struct World {
    pub opts: Options,
    pub svm: Arc<LiteSvmRpc>,
    /// The harness's and the enclaves' provider.
    pub rpc: Arc<FaultyRpc<LiteSvmRpc>>,
    /// The node's provider: faults here hit only the node.
    pub node_rpc: Arc<FaultyRpc<LiteSvmRpc>>,
    pub sender: Arc<TxSender>,
    pub chain: Arc<dyn MarketChain>,
    pub program: [u8; 32],
    pub market: [u8; 32],
    pub market_id: u64,
    pub params: MarketParams,
    pub relay_cfg: RelayConfig,
    pub admin: Arc<dyn TxSigner>,
    pub creator: Arc<dyn TxSigner>,
    pub relay_seed: [u8; 32],
    pub cranker_seed: [u8; 32],
    pub enclaves: Arc<FakeEnclaves>,
    pub dealer: Dealer,
    pub clock: Arc<ManualClock>,
    pub dir: TempDir,
    pub cfg: NodeConfig,
    pub node: Option<NodeHandle>,
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    pub base_vault: [u8; 32],
    pub quote_vault: [u8; 32],
    pub metrics: Option<Arc<NodeMetrics>>,
    /// The running node's repository, to see when every task let go of it.
    repo: Option<std::sync::Weak<NodeRepo>>,
    seq: AtomicU64,
}

fn chain_cfg() -> MarketChainConfig {
    MarketChainConfig {
        max_attempts: 12,
        ..MarketChainConfig::default()
    }
}

fn fees() -> FeePolicy {
    FeePolicy {
        mode: FeeMode::Fixed(1_000),
        percentile: 75,
        max_micro_lamports: 200_000,
        cu_margin_pct: 20,
    }
}

impl World {
    pub async fn new(opts: Options) -> World {
        let clock = Arc::new(ManualClock::new(BASE_MS));
        {
            let clock = clock.clone();
            let start = tokio::time::Instant::now();
            tokio::spawn(async move {
                loop {
                    let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap();
                    clock.set(BASE_MS + elapsed);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
        }
        let svm = svm::new_svm();
        let rpc = Arc::new(FaultyRpc::new(svm.clone()));
        let node_rpc = Arc::new(FaultyRpc::new(svm.clone()));
        let dyn_rpc: Arc<dyn SolanaRpc> = rpc.clone();
        let journal = Arc::new(MemJournal::default());
        let sender = Arc::new(TxSender::new(
            dyn_rpc.clone(),
            fees(),
            journal,
            svm::SLOT_TIME,
            Duration::from_secs(30),
        ));
        let program = svm::program();
        let funded = |label: &str, n: u64| {
            let (s, _) = key(seed(label, n));
            airdrop(&svm, s.address(), 100_000_000_000);
            s
        };
        let creator = funded("creator", 0);
        let admin = funded("admin", 0);
        let relay_seed = seed("relay", 0);
        let cranker_seed = seed("cranker", 0);
        let (relay, _) = key(relay_seed);
        let (cranker, _) = key(cranker_seed);
        airdrop(&svm, relay.address(), 100_000_000_000);
        airdrop(&svm, cranker.address(), 100_000_000_000);
        let fee_payers: Vec<Arc<dyn TxSigner>> = (0..opts.enclaves)
            .map(|i| funded("enclave-fee", i as u64))
            .collect();
        tokio::time::sleep(svm::SLOT_TIME * 2).await;

        let salt = [0x5a; 32];
        let market_id =
            timescales_chain::program::derive_market_id(&program, &creator.address(), &salt);
        let market = timescales_chain::program::market_pda(&program, market_id)
            .unwrap()
            .0;
        let mut enclaves = FakeEnclaves::new(
            opts.enclaves,
            3,
            2,
            market,
            program,
            vec!["localhost:4173".into()],
            fee_payers,
        );
        let dealer = Dealer::new(market, MarketId(market_id), enclaves.members.clone(), 2);

        let (base_mint_key, _) = key(seed("base-mint", 0));
        let (quote_mint_key, _) = key(seed("quote-mint", 0));
        let (base_vault_key, _) = key(seed("base-vault", 0));
        let (quote_vault_key, _) = key(seed("quote-vault", 0));
        let (base_mint, quote_mint) = (base_mint_key.address(), quote_mint_key.address());
        let (base_vault, quote_vault) = (base_vault_key.address(), quote_vault_key.address());
        svm::mint(&dyn_rpc, &sender, &creator, base_mint_key).await;
        svm::mint(&dyn_rpc, &sender, &creator, quote_mint_key).await;
        svm::token_account(
            &dyn_rpc,
            &sender,
            &creator,
            base_mint,
            market,
            base_vault_key,
            0,
        )
        .await;
        svm::token_account(
            &dyn_rpc,
            &sender,
            &creator,
            quote_mint,
            market,
            quote_vault_key,
            0,
        )
        .await;

        let params = MarketParams {
            market: MarketId(market_id),
            base_lot_size: 1,
            tick_size: 1,
            band_half_width: 16,
            max_order_lots_log2: 20,
            max_orders_per_trader: 8,
            max_batch_envelopes: 1024,
            max_order_lifetime: 8,
            maker_fee: FeeBps(0),
            taker_fee: FeeBps(10),
            flow: FlowMode::DualFlow,
            rationing: Rationing::ProRata,
            commitment_scheme: CommitmentScheme::Sha256,
        };
        let args = InitMarketArgs {
            salt,
            admin: admin.address(),
            relay: relay.address(),
            params,
            committee_digest: dealer.committee_digest(),
            beacon_delay_slots: 4,
            timelock_slots: opts.timelock,
            exec_timeout_slots: opts.exec_timeout,
            settle_timeout_slots: (2 * opts.exec_timeout).max(1_500),
            receipt_quorum: opts.quorum,
            executors: enclaves.list.iter().map(|e| e.executor()).collect(),
        };
        let init = timescales_chain::program::init_market(
            &program,
            &creator.address(),
            &base_mint,
            &quote_mint,
            &base_vault,
            &quote_vault,
            &args,
        )
        .unwrap();
        svm::send(&sender, vec![init], &creator, vec![]).await;

        let chain: Arc<dyn MarketChain> = Arc::new(SolanaMarketChain::new(
            dyn_rpc,
            sender.clone(),
            program,
            market,
            chain_cfg(),
        ));
        enclaves.connect(chain.clone(), dealer.committee_digest(), 2);

        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(
            dir.path(),
            &opts,
            program,
            market,
            &params,
            &dealer,
            &enclaves,
        );
        let relay_cfg = RelayConfig {
            params,
            market_address: market,
            padding: Padding::PowerOfTwo { min: 4 },
            allow_masked: false,
            max_real: 1024,
            carry_p: 0.5,
        };
        World {
            opts,
            svm,
            rpc,
            node_rpc,
            sender,
            chain,
            program,
            market,
            market_id,
            params,
            relay_cfg,
            admin,
            creator,
            relay_seed,
            cranker_seed,
            enclaves: Arc::new(enclaves),
            dealer,
            clock,
            dir,
            cfg,
            node: None,
            base_mint,
            quote_mint,
            base_vault,
            quote_vault,
            metrics: None,
            repo: None,
            seq: AtomicU64::new(0),
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.dir.path().join("data").join("node.sqlite")
    }

    fn keys(&self) -> NodeKeys {
        let (relay, relay_kp) = key(self.relay_seed);
        let (cranker, _) = key(self.cranker_seed);
        NodeKeys {
            relay,
            relay_signing: Arc::new(relay_kp),
            cranker,
            service: Arc::new(Keypair::from_seed([0x51; 32])),
            kek: Arc::new(KekSealer::new(Zeroizing::new([0x4b; 32]))),
            nonce_key: Zeroizing::new([0x4e; 32]),
        }
    }

    /// Starts the node over the world's database (start-up order).
    pub async fn start_node(&mut self) -> Result<(), timescales_node::NodeError> {
        self.start_node_with(self.cfg.clone()).await
    }

    pub async fn start_node_with(
        &mut self,
        cfg: NodeConfig,
    ) -> Result<(), timescales_node::NodeError> {
        assert!(self.node.is_none(), "node already running");
        std::fs::create_dir_all(self.db_path().parent().unwrap()).unwrap();
        let store = Store::open(
            &self.db_path(),
            Schema::Node,
            StoreOptions {
                synchronous_full: false,
                group_commit_ms: 1,
                ..StoreOptions::default()
            },
        )
        .unwrap();
        let repo = Arc::new(NodeRepo::new(store));
        self.repo = Some(Arc::downgrade(&repo));
        let rpc: Arc<dyn SolanaRpc> = self.node_rpc.clone();
        let sender = timescales_node::chain::sender(rpc.clone(), repo.clone(), &cfg.solana);
        sender
            .resolve_pending()
            .await
            .map_err(|e| timescales_node::NodeError::Chain(e.into()))?;
        let last = timescales_chain::TxJournal::last_landed_slot(&*repo)
            .await
            .unwrap_or(0);
        let chains = timescales_node::chain::markets(
            rpc.clone(),
            sender,
            self.program,
            &[self.market],
            timescales_node::chain::chain_config(&cfg.solana, &cfg.execution),
            last,
        );
        let metrics = Arc::new(NodeMetrics::unregistered());
        self.metrics = Some(metrics.clone());
        let exec: Arc<dyn ExecClient> = self.enclaves.clone();
        let genesis = cfg.genesis_hash().unwrap();
        let handle = start_with_metrics(
            cfg,
            chains,
            rpc,
            repo,
            exec,
            self.clock.clone(),
            self.keys(),
            metrics,
            self.program,
            genesis,
        )
        .await?;
        self.node = Some(handle);
        Ok(())
    }

    /// Stops the node abruptly (jobs get 1 ms to reach a checkpoint).
    pub async fn crash(&mut self) {
        if let Some(n) = self.node.take() {
            n.shutdown().await.unwrap();
        }
        // Wait until every task (blocking ones included, which run in real
        // time) dropped the repository: replacing the database under an
        // open connection fails the next open with a disk I/O error.
        let started = std::time::Instant::now();
        while self.repo.as_ref().is_some_and(|r| r.strong_count() > 0) {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "the node's store is still held after shutdown"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
            std::thread::sleep(Duration::from_millis(1));
        }
        // The count reaches zero before the store's drop, which joins its
        // threads and closes the connections, has finished on the thread
        // that dropped it last.
        std::thread::sleep(Duration::from_millis(20));
        self.repo = None;
    }

    pub fn node(&self) -> &NodeHandle {
        self.node.as_ref().expect("node running")
    }

    pub fn view(&self) -> MarketView {
        self.node().view(self.market).unwrap()
    }

    /// A consistent copy of the node's database, taken online.
    pub async fn copy_db(&self, name: &str) -> PathBuf {
        let dest = self.dir.path().join(format!("{name}.sqlite"));
        let r = self
            .node()
            .store()
            .store()
            .backup_to(dest.clone(), &[])
            .await
            .unwrap();
        assert!(r.integrity_ok);
        dest
    }

    /// Replaces the (stopped) node's database with `copy`.
    pub fn restore_db(&self, copy: &Path) {
        assert!(self.node.is_none());
        let db = self.db_path();
        for ext in ["sqlite-wal", "sqlite-shm"] {
            let _ = std::fs::remove_file(db.with_extension(ext));
        }
        std::fs::copy(copy, &db).unwrap();
    }

    /// Deals and delivers the bundles of `epochs`.
    pub async fn deal(&self, epochs: std::ops::RangeInclusive<u64>) {
        for e in epochs {
            self.node()
                .put_key_bundle(self.market, self.dealer.bundle(e))
                .await
                .unwrap();
        }
    }

    pub fn epoch_pk(&self, epoch: u64) -> [u8; 32] {
        self.dealer.bundle(epoch).announcement.epoch_pk
    }

    /// A funded wallet without a Trader account, not logged in.
    pub fn new_trader(&self) -> Trader {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let wallet_seed = seed("trader", n);
        let (wallet, _) = key(wallet_seed);
        airdrop(&self.svm, wallet.address(), 10_000_000_000);
        Trader::new(wallet, wallet_seed, seed("session", n), n)
    }

    /// Opens `t`'s Trader account and deposits `base` and `quote`.
    pub async fn fund(&self, t: &Trader, base: u64, quote: u64) {
        let n = t.index;
        let rpc: Arc<dyn SolanaRpc> = self.rpc.clone();
        let owner = t.id();
        let (base_ata, _) = key(seed("trader-base", n));
        let (quote_ata, _) = key(seed("trader-quote", n));
        let (b, q) = (base_ata.address(), quote_ata.address());
        svm::token_account(
            &rpc,
            &self.sender,
            &self.creator,
            self.base_mint,
            owner,
            base_ata,
            base,
        )
        .await;
        svm::token_account(
            &rpc,
            &self.sender,
            &self.creator,
            self.quote_mint,
            owner,
            quote_ata,
            quote,
        )
        .await;
        let mut ixs = vec![
            timescales_chain::program::open_trader(&self.program, &owner, &self.market).unwrap(),
        ];
        for (side, amount, source, vault) in [
            (Side::Base, base, b, self.base_vault),
            (Side::Quote, quote, q, self.quote_vault),
        ] {
            if amount > 0 {
                ixs.push(
                    timescales_chain::program::deposit(
                        &self.program,
                        &owner,
                        &self.market,
                        &source,
                        &vault,
                        side,
                        amount,
                    )
                    .unwrap(),
                );
            }
        }
        svm::send(&self.sender, ixs, &t.wallet, vec![]).await;
        tokio::time::sleep(svm::SLOT_TIME * 2).await;
    }

    /// A wallet with a Trader account holding `base` and `quote`, logged in.
    pub async fn trader(&self, base: u64, quote: u64) -> Trader {
        let mut t = self.new_trader();
        self.fund(&t, base, quote).await;
        if self.node.is_some() {
            t.login(self.node(), self.clock_now(), self.market, self.program)
                .await;
        }
        t
    }

    pub fn clock_now(&self) -> u64 {
        timescales_node::Clock::now_ms(&*self.clock)
    }

    pub async fn market_account(&self) -> MarketAccount {
        self.chain.market(Level::Confirmed).await.unwrap()
    }

    pub async fn batch(&self, e: u64) -> Option<BatchAccount> {
        self.chain.batch(e, Level::Confirmed).await.unwrap()
    }

    pub async fn row(&self, e: u64) -> Option<EpochRow> {
        self.node().store().epoch(self.market, e).await.unwrap()
    }

    pub async fn trader_account(
        &self,
        owner: [u8; 32],
    ) -> timescales_chain::program::TraderAccount {
        let pda = timescales_chain::program::trader_pda(&self.program, &self.market, &owner)
            .unwrap()
            .0;
        let a = self
            .rpc
            .get_account(pda, Level::Confirmed, None)
            .await
            .unwrap()
            .unwrap();
        timescales_chain::program::decode_trader(&a.data).unwrap()
    }

    pub async fn set_halted(&self, halted: bool) {
        let ix = timescales_chain::program::set_halted(
            &self.program,
            &self.admin.address(),
            &self.market,
            halted,
        );
        svm::send(&self.sender, vec![ix], &self.admin, vec![]).await;
        tokio::time::sleep(svm::SLOT_TIME * 2).await;
    }

    /// Waits (tokio time) until `check` returns `Some`. Panics with `what`
    /// after `limit`.
    pub async fn wait<T>(
        &self,
        what: &str,
        limit: Duration,
        mut check: impl AsyncFnMut(&World) -> Option<T>,
    ) -> T {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if let Some(t) = check(self).await {
                return t;
            }
            if tokio::time::Instant::now() > deadline {
                let view = self.node.as_ref().and_then(|n| n.view(self.market));
                panic!("timed out waiting for {what}; view: {view:#?}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The open epoch, once one is open.
    pub async fn open_epoch(&self) -> u64 {
        self.wait(
            "an open epoch",
            Duration::from_secs(120),
            async |w: &World| w.view().open.map(|o| o.epoch),
        )
        .await
    }

    /// An open epoch with at least half its interval left, so a test can
    /// submit into it before the cutoff.
    pub async fn fresh_epoch(&self) -> u64 {
        let half = self.opts.interval_ms / 2;
        self.wait(
            "a fresh open epoch",
            Duration::from_secs(120),
            async |w: &World| {
                let now = w.clock_now();
                w.view()
                    .open
                    .filter(|o| o.cutoff_ms > now + half)
                    .map(|o| o.epoch)
            },
        )
        .await
    }

    /// Moves tokio time (and so the node's clock and the slots) to just
    /// past the open epoch's cutoff.
    pub async fn to_cutoff(&self) {
        let Some(open) = self.view().open else {
            return;
        };
        let now = self.clock_now();
        if open.cutoff_ms > now {
            tokio::time::advance(Duration::from_millis(open.cutoff_ms - now + 1)).await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    /// Waits for epoch `e`'s row to reach a phase in `phases`.
    pub async fn phase(&self, e: u64, phases: &[Phase]) -> EpochRow {
        let what = format!("epoch {e} in {phases:?}");
        self.wait(&what, Duration::from_secs(600), async |w: &World| {
            w.row(e).await.filter(|r| phases.contains(&r.phase))
        })
        .await
    }

    pub async fn status(&self, e: u64, pred: impl Fn(&BatchAccount) -> bool) -> BatchAccount {
        let what = format!("batch {e} status");
        self.wait(&what, Duration::from_secs(600), async |w: &World| {
            w.batch(e).await.filter(|b| pred(b))
        })
        .await
    }
}

#[allow(clippy::too_many_arguments)]
fn write_config(
    dir: &Path,
    opts: &Options,
    program: [u8; 32],
    market: [u8; 32],
    params: &MarketParams,
    dealer: &Dealer,
    enclaves: &FakeEnclaves,
) -> NodeConfig {
    let params_json = serde_json::json!({
        "market": params.market.0,
        "base_lot_size": params.base_lot_size,
        "tick_size": params.tick_size,
        "band_half_width": params.band_half_width,
        "max_order_lots_log2": params.max_order_lots_log2,
        "max_orders_per_trader": params.max_orders_per_trader,
        "max_batch_envelopes": params.max_batch_envelopes,
        "max_order_lifetime": params.max_order_lifetime,
        "maker_fee_bps": params.maker_fee.0,
        "taker_fee_bps": params.taker_fee.0,
        "flow": "dual",
        "rationing": "pro-rata",
        "commitment_scheme": "sha256",
    });
    std::fs::write(dir.join("market.json"), params_json.to_string()).unwrap();
    std::fs::write(dir.join("committee.bin"), dealer.committee.to_bytes()).unwrap();
    let genesis = bs58::encode(svm::cluster().genesis_hash).into_string();
    let enclave_tables: String = enclaves
        .list
        .iter()
        .enumerate()
        .map(|(i, e)| {
            format!(
                "[[execution.enclave]]\nurl = \"http://127.0.0.1:{}\"\nidentity = \"{}\"\nexecutor = \"{}\"\n\n",
                18090 + i,
                hex::encode(e.enclave.executor_id().0),
                hex::encode(e.executor()),
            )
        })
        .collect();
    let text = format!(
        r#"
[node]
id = "node-test"
profile = "local"
data_dir = "data"
shutdown_grace_ms = 1

[api]
listen = "127.0.0.1:0"
public_base_url = "http://localhost:4173"
session_domains = ["localhost:4173"]
cors_allowed_origins = ["http://localhost:4173"]
trusted_proxy_cidrs = ["127.0.0.1/32"]
max_body_bytes = 4096
submit_max_body_bytes = 2048
max_concurrency = 512
request_timeout_ms = 30000
ws_max_connections = 5000
ws_max_connections_per_ip = 20
ws_max_subscriptions = 16
ws_send_queue = 256
ws_heartbeat_ms = 15000
ws_inbound_max_bytes = 4096
event_log_hours = 24

[api.rate_limit]
per_ip_rps = 20
per_ip_burst = 40
per_session_rps = 5
per_session_burst = 20
per_wallet_submit_rps = 5
per_wallet_submit_burst = 20

[sessions]
max_ttl_s = 86400
nonce_ttl_s = 300
max_per_wallet = 2
skew_ms = 30000
allow_sign_message_grants = false

[admin]
listen = "127.0.0.1:0"
token_file = "admin-token"
dealer_keys = []

[metrics]
listen = "127.0.0.1:0"

[telemetry]
log_format = "pretty"
log_filter = "info"

[solana]
cluster = "localnet"
genesis_hash = "{genesis}"
program_id = "{program}"
rpc_urls = ["http://127.0.0.1:8899"]
rpc_timeout_ms = 5000
read_commitment = "confirmed"
release_commitment = "finalized"
poll_interval_ms = 400
confirm_timeout_ms = 30000
tx_max_attempts = 12
max_parallel_txs = 16
cu_margin_pct = 20
min_relay_balance_lamports = "1000000"
min_cranker_balance_lamports = "1000000"
reclaim_batches = false

[solana.priority_fee]
mode = "fixed"
fixed_micro_lamports = "1000"
percentile = 75
max_micro_lamports = "200000"

[keys]
relay_keypair = "relay.json"
cranker_keypair = "cranker.json"
service_key = "service.hex"
kek_file = "kek.hex"
nonce_key_file = "nonce.hex"

[store]
synchronous = "normal"
group_commit_ms = 1
group_commit_max = 256
readers = 4
queue = 8192
busy_timeout_ms = 5000
private_keep_epochs = 64
wallet_link_hours = 24
backup_every_epochs = 0
backup_dir = "backups"

[execution]
spare_executions = 1
attempts_per_enclave = 4
attempt_timeout_ms = 60000
retry_backoff_ms = 500
circuit_open_after = 3
circuit_half_open_after_ms = 2000
expected_platform = "simulated"

{enclave_tables}
[[market]]
address = "{market}"
name = "TEST/USD"
base_symbol = "TEST"
quote_symbol = "USD"
params_file = "market.json"
committee_file = "committee.bin"
epoch_interval_ms = {interval}
padding = {{ kind = "power_of_two", min = 4 }}
cover_carry_probability = 0.5
max_real_per_epoch = {max_real}
max_park_ahead_epochs = {park}
idle_policy = "{idle}"
max_idle_extend = 2

[market.quota]
max_envelopes_per_wallet_per_epoch = 16
max_parked_per_wallet = 64
require_trader_account = true
min_available_value_quote = "1000"
min_value_per_envelope_quote = "{per_env}"
ban_epochs = 64

[market.reference]
source = "last_clearing"
initial_tick = "{tick}"
"#,
        program = bs58::encode(program).into_string(),
        market = bs58::encode(market).into_string(),
        interval = opts.interval_ms,
        park = opts.park_ahead,
        idle = opts.idle,
        per_env = opts.min_value_per_envelope,
        tick = opts.reference_tick,
        max_real = opts.max_real,
    );
    let path = dir.join("node.toml");
    std::fs::write(&path, text).unwrap();
    NodeConfig::load(&path, None).unwrap()
}

/// The epoch an event names, if any.
pub fn epoch_of(e: &timescales_service::api::Event) -> Option<u64> {
    use timescales_service::api::Event as E;
    match e {
        E::KeyPublished { epoch, .. }
        | E::EpochOpened { epoch, .. }
        | E::EpochClosed { epoch, .. }
        | E::EpochCommitted { epoch, .. }
        | E::EpochRevealed { epoch, .. }
        | E::EpochExecuting { epoch, .. }
        | E::EpochPosted { epoch, .. }
        | E::EpochCosigned { epoch, .. }
        | E::EpochSettlement { epoch, .. }
        | E::EpochSettled { epoch, .. }
        | E::EpochAborting { epoch, .. }
        | E::EpochAborted { epoch, .. }
        | E::EpochQuorum { epoch, .. } => Some(epoch.0),
        _ => None,
    }
}
