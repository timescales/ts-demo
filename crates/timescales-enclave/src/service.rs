//! [`EnclaveService`]: execute, publish, identity and the backstops.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use parking_lot::Mutex;
use timescales_auction::receipts::{ExecutionArtifacts, ExecutionReceipt, cosign_digest};
use timescales_auction::{epoch_binding, terms_digest};
use timescales_chain::program::{BatchAccount, BatchStatus, MarketAccount};
use timescales_chain::{
    Address, BatchPredicate, ChainError, CosignOutcome, Level, MarketChain, PostOutcome,
    RevealOutcome, TxOp, TxSigner,
};
use timescales_core::crypto::verify_digest;
use timescales_core::{
    Encode, EpochId, ExecutorId, HEADER_VERSION_ENVELOPE_BOUND, Hash32, MarketId,
};
use timescales_executor::attestation::registration_report_data;
use timescales_executor::tee::{EpochInputs, EpochKey, KeyReleaseService, TeeExecutor};
use timescales_executor::{ExecutionBatch, ExecutorError, KeyProvider};
use timescales_service::wire::{
    ChainId, EnclaveIdentity, EnclaveRefusal, EnvelopeSigner, ExecutePosted, ExecuteReady,
    ExecuteRequest, PostedTx, PublishRequest,
};
use timescales_service::{ConfigError, ConfigIssue, Profile, Readiness, TlsConfig};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::balance;
use crate::config::{EnclaveConfig, load_committee};
use crate::journal::TxLog;
use crate::metrics::EnclaveMetrics;
use crate::platform::{self, Booted};
use crate::provenance::{self, GrantRules};
use crate::remote::RemoteMember;
use crate::{EnclaveEnvelopeSigner, EnclaveError, now_ms};

/// Registration quotes are cached this long per (market, nonce).
const IDENTITY_TTL: Duration = Duration::from_secs(60);
/// Cached registration quotes at most.
const MAX_IDENTITIES: usize = 4096;
/// Readiness wants a successful chain read within this long.
const FRESH_CHAIN_MS: u64 = 30_000;
/// Results are checked for terminal batches every this many backstop
/// passes.
const PRUNE_EVERY: u32 = 10;

/// A refusal shared by every caller that joined one execution.
#[derive(Clone, Debug)]
struct Refused {
    code: EnclaveRefusal,
    detail: String,
    traders: u32,
}

impl Refused {
    fn new(code: EnclaveRefusal, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            traders: 0,
        }
    }

    fn bad(detail: impl Into<String>) -> Self {
        Self::new(EnclaveRefusal::BadRequest, detail)
    }

    fn binding(detail: impl Into<String>) -> Self {
        Self::new(EnclaveRefusal::BindingMismatch, detail)
    }

    fn busy(detail: impl Into<String>) -> Self {
        Self::new(EnclaveRefusal::Busy, detail)
    }
}

impl From<Refused> for EnclaveError {
    fn from(r: Refused) -> Self {
        match r.code {
            EnclaveRefusal::BindingMismatch => EnclaveError::BindingMismatch,
            EnclaveRefusal::BalanceMismatch => EnclaveError::BalanceMismatch { traders: r.traders },
            EnclaveRefusal::KeyUnavailable => EnclaveError::KeyUnavailable(r.detail),
            EnclaveRefusal::Busy => EnclaveError::Busy,
            _ => EnclaveError::BadRequest(r.detail),
        }
    }
}

/// A completed execution, kept until its batch is terminal.
struct Executed {
    market: Address,
    epoch: u64,
    header: [u8; 283],
    receipt: ExecutionReceipt,
    artifacts: ExecutionArtifacts,
    attestation: Vec<u8>,
    ready: ExecuteReady,
    /// This enclave's post, once it has one.
    posted: Mutex<Option<ExecutePosted>>,
    /// One publish at a time per execution.
    publishing: tokio::sync::Mutex<()>,
}

/// Names the execution only: its artifacts hold fills that stay inside
/// until they are published.
impl core::fmt::Debug for Executed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Executed")
            .field("epoch", &self.epoch)
            .field("header_digest", &self.ready.header_digest)
            .finish_non_exhaustive()
    }
}

impl Executed {
    fn outcome_digest(&self) -> Hash32 {
        self.ready.outcome_digest
    }

    fn receipt_digest(&self) -> Hash32 {
        self.receipt.digest()
    }

    fn posted(&self, posted: PostedTx, cosigned: Vec<PostedTx>) -> ExecutePosted {
        ExecutePosted {
            receipt: self.receipt.clone(),
            artifacts: self.artifacts.clone(),
            attestation: self.attestation.clone(),
            posted,
            cosigned,
        }
    }
}

/// The remote members of one committee, in index order.
type Members = Vec<Arc<dyn KeyReleaseService>>;
/// A registration quote and when it was made.
type CachedIdentity = (Instant, EnclaveIdentity);

type Job = Shared<BoxFuture<'static, Result<Arc<Executed>, Refused>>>;

enum Slot {
    Running(Job),
    Done(Arc<Executed>),
}

/// A posted batch this enclave watches until it is terminal: if neither
/// co-signatures nor verification nor application move for
/// `settle_backstop_after`, it re-sends the co-signatures it was given and
/// cranks settlement itself ("Backstops").
struct SettleWatch {
    executed: Arc<Executed>,
    cosigs: Vec<(Address, [u8; 64])>,
    progress: Option<(BatchStatus, u32, u32, u8)>,
    since: Instant,
    cranking: Arc<std::sync::atomic::AtomicBool>,
}

struct Market {
    chain: Arc<dyn MarketChain>,
    session_domains: Vec<String>,
}

/// The parts of the configuration the service keeps.
struct Settings {
    profile: Profile,
    program: Address,
    chain_id: ChainId,
    member_urls: Vec<String>,
    member_timeout: Duration,
    tls: Option<TlsConfig>,
    post_deadline: Duration,
    settle_backstop_after: Duration,
    reveal_backstop_slots: u64,
    poll_interval: Duration,
    allow_sign_message: bool,
    cache_capacity: usize,
    node_keys: BTreeSet<[u8; 32]>,
}

struct Inner {
    settings: Settings,
    markets: BTreeMap<Address, Market>,
    fee_payer: Arc<dyn TxSigner>,
    booted: Booted,
    signer: Arc<dyn EnvelopeSigner>,
    executions: Arc<Semaphore>,
    results: Mutex<HashMap<Hash32, Slot>>,
    members: Mutex<HashMap<(Address, Hash32), Members>>,
    identities: Mutex<HashMap<(Address, [u8; 32]), CachedIdentity>>,
    settling: Mutex<HashMap<Hash32, SettleWatch>>,
    metrics: EnclaveMetrics,
    log: OnceLock<Arc<TxLog>>,
    last_chain_ok_ms: AtomicU64,
    passes: AtomicU64,
}

/// The enclave host service.
pub struct EnclaveService {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for EnclaveService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EnclaveService")
            .field("executor", &self.inner.booted.enclave.executor_id())
            .field("platform", &self.inner.booted.platform)
            .field("markets", &self.inner.markets.len())
            .finish_non_exhaustive()
    }
}

/// Epoch keys come with each request (the bundle), never from a provider.
struct NoKeys;

impl KeyProvider for NoKeys {
    fn epoch_public(&self, _: MarketId, _: EpochId) -> Result<[u8; 32], ExecutorError> {
        Err(ExecutorError::Unavailable(
            "epoch keys come with the execute request".into(),
        ))
    }

    fn epoch_secret(
        &self,
        _: MarketId,
        _: EpochId,
    ) -> Result<timescales_core::crypto::SealSecret, ExecutorError> {
        Err(ExecutorError::Unavailable(
            "the enclave reconstructs epoch secrets from released shares".into(),
        ))
    }
}

fn invalid(field: &str, message: impl Into<String>) -> EnclaveError {
    EnclaveError::Config(ConfigError::Invalid(vec![ConfigIssue::new(field, message)]))
}

fn platform_name(p: timescales_executor::attestation::Platform) -> &'static str {
    match p {
        timescales_executor::attestation::Platform::IntelTdx => "intel_tdx",
        _ => "simulated",
    }
}

impl EnclaveService {
    /// Boots the platform and the enclave ("Boot") over `chains`, one
    /// per configured market, paying fees with `fee_payer`. Refuses a
    /// production profile with a simulation build, a non-production profile
    /// on mainnet-beta, a platform this build lacks and committee files that
    /// do not match the member URLs.
    pub fn boot(
        cfg: EnclaveConfig,
        chains: BTreeMap<Address, Arc<dyn MarketChain>>,
        fee_payer: Arc<dyn TxSigner>,
    ) -> Result<Self, EnclaveError> {
        let issues = cfg.issues(cfg.profile);
        if !issues.is_empty() {
            return Err(EnclaveError::Config(ConfigError::Invalid(issues)));
        }
        timescales_service::refuse_simulation(cfg.profile, &crate::build_info())?;
        let genesis = cfg
            .chain
            .genesis()
            .ok_or_else(|| invalid("enclave.chain.genesis_hash", "not a base58 hash"))?;
        timescales_service::check_cluster_profile(cfg.profile, &genesis)?;
        let program = cfg
            .chain
            .program()
            .ok_or_else(|| invalid("enclave.chain.program_id", "not a base58 address"))?;
        let chain_id = cfg
            .chain
            .chain_id()
            .ok_or_else(|| invalid("enclave.chain.cluster", "no SIWS chain id"))?;

        let mut markets = BTreeMap::new();
        for (entry, address) in cfg.markets.iter().zip(cfg.market_addresses()) {
            let committee = load_committee(&entry.committee_file, &address)
                .map_err(|e| invalid("enclave.market.committee_file", e))?;
            if committee.members.len() != cfg.member_urls.len() {
                return Err(invalid(
                    "enclave.member_urls",
                    "one URL per committee member, in index order",
                ));
            }
            let chain = chains.get(&address).cloned().ok_or_else(|| {
                invalid(
                    "enclave.market",
                    format!(
                        "no chain for market {}",
                        bs58::encode(address).into_string()
                    ),
                )
            })?;
            markets.insert(
                address,
                Market {
                    chain,
                    session_domains: entry.session_domains.clone(),
                },
            );
        }

        let booted = platform::boot(&cfg.platform_mode())?;
        if !booted.self_test {
            tracing::warn!("platform self-test failed: no verifiable quote at boot");
        }
        let metrics = EnclaveMetrics::default();
        metrics.set_platform(platform_name(booted.platform), booted.quote_generation);
        tracing::info!(
            executor = %bs58::encode(booted.enclave.executor_id().0).into_string(),
            platform = ?booted.platform,
            quote_generation = booted.quote_generation,
            "enclave booted"
        );
        let signer: Arc<dyn EnvelopeSigner> =
            Arc::new(EnclaveEnvelopeSigner(Arc::clone(&booted.enclave)));
        let settings = Settings {
            profile: cfg.profile,
            program,
            chain_id,
            node_keys: cfg.node_key_set(),
            member_urls: cfg.member_urls.clone(),
            member_timeout: cfg.member_timeout(),
            tls: cfg.tls_config(),
            post_deadline: cfg.post_deadline(),
            settle_backstop_after: cfg.settle_backstop_after(),
            reveal_backstop_slots: cfg.reveal_backstop_slots,
            poll_interval: Duration::from_millis(cfg.chain.poll_interval_ms),
            allow_sign_message: cfg.allow_sign_message_grants,
            cache_capacity: usize::try_from(cfg.result_cache_entries).unwrap_or(usize::MAX),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                settings,
                markets,
                fee_payer,
                booted,
                signer,
                executions: Arc::new(Semaphore::new(
                    usize::try_from(cfg.max_concurrent_executions).unwrap_or(1),
                )),
                results: Mutex::new(HashMap::new()),
                members: Mutex::new(HashMap::new()),
                identities: Mutex::new(HashMap::new()),
                settling: Mutex::new(HashMap::new()),
                metrics,
                log: OnceLock::new(),
                last_chain_ok_ms: AtomicU64::new(0),
                passes: AtomicU64::new(0),
            }),
        })
    }

    /// The journal of the `TxSender` behind the market chains, so posted
    /// results name the signatures of their transactions. Without it they
    /// carry zero signatures and the slots read from the batch.
    #[must_use]
    pub fn with_tx_log(self, log: Arc<TxLog>) -> Self {
        let _ = self.inner.log.set(log);
        self
    }

    pub fn executor(&self) -> ExecutorId {
        self.inner.booted.enclave.executor_id()
    }

    pub fn seal_key(&self) -> [u8; 32] {
        self.inner.booted.enclave.seal_key()
    }

    pub fn fee_payer(&self) -> Address {
        self.inner.fee_payer.address()
    }

    /// `"simulated"` or `"intel_tdx"`.
    pub fn platform_name(&self) -> &'static str {
        platform_name(self.inner.booted.platform)
    }

    pub fn profile(&self) -> Profile {
        self.inner.settings.profile
    }

    pub fn metrics(&self) -> &EnclaveMetrics {
        &self.inner.metrics
    }

    /// The enclave's typed envelope signer (its executor key, through
    /// `Enclave::sign_rpc_envelope`).
    pub fn envelope_signer(&self) -> Arc<dyn EnvelopeSigner> {
        Arc::clone(&self.inner.signer)
    }

    pub(crate) fn is_node(&self, key: &[u8; 32]) -> bool {
        self.inner.settings.node_keys.contains(key)
    }

    /// Platform self-test passed at boot and a chain read succeeded in the
    /// last 30 s.
    pub fn readiness(&self) -> Readiness {
        let platform = self.inner.booted.self_test;
        let chain = now_ms().saturating_sub(self.inner.last_chain_ok_ms.load(Ordering::Relaxed))
            < FRESH_CHAIN_MS;
        Readiness {
            ready: platform && chain,
            checks: vec![
                ("platform".to_owned(), platform),
                ("chain".to_owned(), chain),
            ],
        }
    }

    /// Cached per (market, nonce), rate-limited.
    pub async fn identity(
        &self,
        market: Address,
        nonce: [u8; 32],
    ) -> Result<EnclaveIdentity, EnclaveError> {
        let inner = &self.inner;
        if !inner.markets.contains_key(&market) {
            return Err(EnclaveError::BadRequest("market not served".into()));
        }
        {
            let mut cache = inner.identities.lock();
            if let Some((at, id)) = cache.get(&(market, nonce))
                && at.elapsed() < IDENTITY_TTL
            {
                return Ok(id.clone());
            }
            if cache.len() >= MAX_IDENTITIES {
                cache.retain(|_, (at, _)| at.elapsed() < IDENTITY_TTL);
                if cache.len() >= MAX_IDENTITIES {
                    return Err(EnclaveError::Busy);
                }
            }
        }
        let enclave = &inner.booted.enclave;
        let executor = enclave.executor_id();
        let seal_key = enclave.seal_key();
        let rd = registration_report_data(
            &seal_key,
            &executor,
            &inner.settings.program,
            &market,
            &nonce,
        );
        let quoter = Arc::clone(&inner.booted.quoter);
        let measurement = inner.booted.measurement;
        let evidence =
            tokio::task::spawn_blocking(move || quoter.try_quote(measurement, false, rd))
                .await
                .map_err(|_| EnclaveError::Quote("quote task failed".into()))?
                .map_err(|e| EnclaveError::Quote(e.to_string()))?;
        let id = EnclaveIdentity {
            executor,
            seal_key,
            platform: inner.booted.platform,
            measurement: measurement.0,
            evidence,
            fee_payer: inner.fee_payer.address(),
        };
        inner
            .identities
            .lock()
            .insert((market, nonce), (Instant::now(), id.clone()));
        Ok(id)
    }

    /// Idempotent per header digest.
    pub async fn execute(&self, req: Arc<ExecuteRequest>) -> Result<ExecuteReady, EnclaveError> {
        let header = &req.batch.header;
        if header.version != HEADER_VERSION_ENVELOPE_BOUND {
            return Err(EnclaveError::BadRequest(
                "only header version 2 is executed".into(),
            ));
        }
        if !self.inner.markets.contains_key(&req.market) {
            return Err(EnclaveError::BadRequest("market not served".into()));
        }
        let digest = header.digest();
        let job = {
            let mut results = self.inner.results.lock();
            match results.get(&digest) {
                Some(Slot::Done(e)) => return Ok(e.ready.clone()),
                Some(Slot::Running(job)) => job.clone(),
                None => {
                    if results.len() >= self.inner.settings.cache_capacity {
                        return Err(EnclaveError::Busy);
                    }
                    let permit = Arc::clone(&self.inner.executions)
                        .try_acquire_owned()
                        .map_err(|_| EnclaveError::Busy)?;
                    let inner = Arc::clone(&self.inner);
                    // The execution runs to the end on its own task, so a
                    // caller that gives up does not waste the KRC round.
                    let task = tokio::spawn(async move {
                        let started = Instant::now();
                        let result = Inner::run(&inner, req, permit).await;
                        inner
                            .metrics
                            .execute_seconds
                            .observe(started.elapsed().as_secs_f64());
                        inner.finish(digest, &result);
                        result
                    });
                    let job: Job = async move {
                        task.await
                            .unwrap_or_else(|_| Err(Refused::busy("execution task failed")))
                    }
                    .boxed()
                    .shared();
                    results.insert(digest, Slot::Running(job.clone()));
                    job
                }
            }
        };
        job.await.map(|e| e.ready.clone()).map_err(Into::into)
    }

    /// Poster path.
    pub async fn publish(&self, req: PublishRequest) -> Result<ExecutePosted, EnclaveError> {
        let executed = match self.inner.results.lock().get(&req.header_digest) {
            Some(Slot::Done(e)) => Arc::clone(e),
            _ => return Err(EnclaveError::NotExecuted),
        };
        if executed.market != req.market || executed.epoch != req.epoch.0 {
            return Err(EnclaveError::NotExecuted);
        }
        let _one = executed.publishing.lock().await;
        let cached = executed.posted.lock().clone();
        let result = match cached {
            Some(posted) => Ok(posted),
            None => self.inner.publish(&executed, &req).await,
        };
        let label = match &result {
            Ok(_) => "posted",
            Err(EnclaveError::QuorumPending) => "quorum_pending",
            Err(EnclaveError::OutcomeMismatch { .. }) => "outcome_mismatch",
            Err(EnclaveError::QuorumInvalid) => "quorum_invalid",
            Err(_) => "failed",
        };
        self.inner.metrics.post(label);
        if let Ok(posted) = &result {
            *executed.posted.lock() = Some(posted.clone());
        }
        result
    }

    /// One pass of the backstops: reveal every market's batch that
    /// is still Committed `reveal_backstop_slots` after its beacon became
    /// computable, crank stalled settlements this enclave posted, and drop
    /// results of terminal batches.
    pub async fn backstop_pass(&self) {
        let inner = &self.inner;
        for (address, market) in &inner.markets {
            if let Err(e) = inner.reveal_backstop(address, market).await {
                tracing::debug!(error = %e, "reveal backstop: chain read failed");
            }
        }
        inner.settle_backstop().await;
        let passes = inner.passes.fetch_add(1, Ordering::Relaxed);
        if passes.is_multiple_of(u64::from(PRUNE_EVERY)) {
            inner.prune().await;
        }
    }

    /// Runs [`Self::backstop_pass`] every chain poll interval until the
    /// task is aborted. Every step observes chain state before it acts, so
    /// aborting at any point is safe.
    pub fn spawn_backstops(&self) -> tokio::task::JoinHandle<()> {
        let svc = Self {
            inner: Arc::clone(&self.inner),
        };
        let every = self
            .inner
            .settings
            .poll_interval
            .max(Duration::from_millis(100));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                svc.backstop_pass().await;
            }
        })
    }
}

impl Inner {
    fn market(&self, address: &Address) -> Result<&Market, Refused> {
        self.markets
            .get(address)
            .ok_or_else(|| Refused::bad("market not served"))
    }

    fn chain_ok(&self) {
        self.last_chain_ok_ms.store(now_ms(), Ordering::Relaxed);
    }

    /// Records the outcome of an execution: a result is kept until its
    /// batch is terminal, a refusal is forgotten so a retry runs again.
    fn finish(&self, digest: Hash32, result: &Result<Arc<Executed>, Refused>) {
        let mut results = self.results.lock();
        match result {
            Ok(e) => {
                results.insert(digest, Slot::Done(Arc::clone(e)));
            }
            Err(r) => {
                tracing::info!(code = ?r.code, detail = %r.detail, "execution refused");
                results.remove(&digest);
            }
        }
    }

    /// The remote members of `committee`, in index order, built once per
    /// (market, committee).
    fn members(
        &self,
        market: Address,
        committee: &timescales_service::wire::CommitteeDescription,
    ) -> Result<Vec<Arc<dyn KeyReleaseService>>, Refused> {
        let digest = committee.digest();
        if let Some(m) = self.members.lock().get(&(market, digest)) {
            return Ok(m.clone());
        }
        if committee.members.len() != self.settings.member_urls.len() {
            return Err(Refused::new(
                EnclaveRefusal::KeyUnavailable,
                "committee size differs from member_urls",
            ));
        }
        let members = committee
            .members
            .iter()
            .zip(&self.settings.member_urls)
            .map(|(m, url)| {
                RemoteMember::new(
                    m.index,
                    url,
                    m.identity,
                    market,
                    Arc::clone(&self.signer),
                    self.settings.tls.clone(),
                    self.settings.member_timeout,
                )
                .map(|r| Arc::new(r) as Arc<dyn KeyReleaseService>)
                .map_err(|e| {
                    Refused::new(
                        EnclaveRefusal::KeyUnavailable,
                        format!("member client: {e}"),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut cache = self.members.lock();
        // Committees change rarely. A small cache is enough.
        if cache.len() >= 16 {
            cache.clear();
        }
        cache.insert((market, digest), members.clone());
        Ok(members)
    }

    /// The execute request, start to finish.
    async fn run(
        inner: &Arc<Self>,
        req: Arc<ExecuteRequest>,
        _permit: OwnedSemaphorePermit,
    ) -> Result<Arc<Executed>, Refused> {
        let header = req.batch.header;
        let epoch = header.epoch.0;
        let market = inner.market(&req.market)?;
        let chain = &market.chain;

        // 1. Inputs against chain state read by the enclave.
        let chain_busy = |e: ChainError| Refused::busy(format!("chain: {e}"));
        let m = chain.market(Level::Confirmed).await.map_err(chain_busy)?;
        let b = chain
            .batch(epoch, Level::Confirmed)
            .await
            .map_err(chain_busy)?
            .ok_or_else(|| Refused::bad("no batch on chain for this epoch"))?;
        inner.chain_ok();
        if header.market.0 != m.market_id || header.params != m.params {
            return Err(Refused::bad("header names another market or parameters"));
        }
        if b.status == BatchStatus::Committed || b.status.is_terminal() {
            return Err(Refused::bad(format!("batch is {:?}", b.status)));
        }
        if (header.batch_root, header.envelope_count, header.beacon) != (b.root, b.count, b.beacon)
        {
            return Err(Refused::bad("header does not match the committed batch"));
        }
        let committee = &req.committee;
        committee
            .validate()
            .map_err(|e| Refused::bad(format!("committee: {e}")))?;
        if committee.market != req.market {
            return Err(Refused::bad("committee describes another market"));
        }
        let mut allowed = vec![m.committee_digest];
        if m.prev_committee_digest != Hash32::ZERO {
            allowed.push(m.prev_committee_digest);
        }
        let ann = &req.bundle.announcement;
        req.bundle
            .verify(committee, &allowed, false)
            .map_err(|e| Refused::binding(format!("bundle: {e}")))?;
        if ann.market != req.market || ann.epoch != header.epoch {
            return Err(Refused::binding("bundle is for another market or epoch"));
        }
        let committee_digest = committee.digest();
        let binding = epoch_binding(&req.price_commitment, &ann.digest(), &committee_digest);
        if header.price_commitment != binding {
            return Err(Refused::binding("header binding"));
        }
        if b.terms_digest != terms_digest(&header.band, &header.price_commitment) {
            return Err(Refused::binding("committed terms"));
        }

        // 2. Provenance.
        let rules = GrantRules {
            domains: &market.session_domains,
            program: inner.settings.program,
            chain_id: inner.settings.chain_id,
            market: req.market,
            allow_sign_message: inner.settings.allow_sign_message,
        };
        let admitted = provenance::admit(&req.batch.envelopes, &req.provenance, &rules);
        if admitted.rejected > 0 {
            inner
                .metrics
                .provenance_rejects
                .inc_by(u64::from(admitted.rejected));
            tracing::info!(
                epoch,
                rejected = admitted.rejected,
                "envelopes failed the provenance check"
            );
        }

        // 3. Balance sheet, before any key is requested.
        let snapshot = chain
            .trader_snapshot(b.commit_slot)
            .await
            .map_err(chain_busy)?;
        let traders = balance::mismatches(&req.batch.balances, &snapshot, epoch, b.commit_slot);
        if traders > 0 {
            inner.metrics.balance_check_failures.inc();
            tracing::warn!(
                epoch,
                traders,
                "TimescalesBalanceSheetMismatch: the balance sheet disagrees with chain state"
            );
            return Err(Refused {
                traders,
                ..Refused::new(
                    EnclaveRefusal::BalanceMismatch,
                    format!("{traders} trader(s)"),
                )
            });
        }

        // 5. Run: challenge, attest, release, reconstruct, execute.
        let members = inner.members(req.market, committee)?;
        let executor = TeeExecutor::new(
            Arc::clone(&inner.booted.enclave),
            members,
            committee.threshold,
            Arc::new(NoKeys),
            inner.settings.member_timeout,
        )
        .map_err(|e| Refused::new(EnclaveRefusal::KeyUnavailable, e.to_string()))?
        .with_committee_digest(committee_digest);
        let inputs = EpochInputs {
            market_address: req.market,
            price_commitment: req.price_commitment,
            key: EpochKey {
                epoch_pk: ann.epoch_pk,
                commitments: ann.commitments.clone(),
            },
            announcement_digest: ann.digest(),
            admission: Some(admitted.admission),
        };
        let batch: Arc<ExecutionBatch> = Arc::new(req.batch.clone());
        let run = executor.execute_epoch(batch, inputs).await;
        let rejected_shares = |members: &[timescales_executor::MemberFailure]| {
            u64::try_from(members.iter().filter(|m| m.refusal.is_none()).count()).unwrap_or(0)
        };
        let run = match run {
            Ok(run) => run,
            Err(ExecutorError::KeyUnavailable(f)) => {
                inner
                    .metrics
                    .share_rejects
                    .inc_by(rejected_shares(&f.members));
                return Err(Refused::new(EnclaveRefusal::KeyUnavailable, f.reason));
            }
            Err(ExecutorError::BadHeader("epoch binding")) => {
                return Err(Refused::binding("header binding"));
            }
            Err(ExecutorError::BadHeader(why)) => return Err(Refused::bad(why)),
            Err(ExecutorError::Attestation(why)) => {
                return Err(Refused::new(
                    EnclaveRefusal::KeyUnavailable,
                    format!("attestation: {why}"),
                ));
            }
            Err(ExecutorError::Unavailable(why)) => return Err(Refused::busy(why)),
            Err(e) => return Err(Refused::bad(e.to_string())),
        };
        let shares = rejected_shares(&run.member_failures);
        if shares > 0 {
            inner.metrics.share_rejects.inc_by(shares);
        }

        // 6. Digests and a co-signature only.
        let result = run.result;
        let header_digest = header.digest();
        let outcome_digest = result.receipt.outcome.digest();
        let cosign = inner.booted.enclave.sign_cosign(
            &req.market,
            header.epoch,
            &header_digest,
            &outcome_digest,
        );
        let ready = ExecuteReady {
            executor: inner.booted.enclave.executor_id(),
            header_digest,
            outcome_digest,
            cosign,
            unauthenticated: result.metrics.unauthenticated.clone(),
        };
        let header_bytes: [u8; 283] = header
            .to_bytes()
            .try_into()
            .map_err(|_| Refused::bad("header encoding"))?;
        Ok(Arc::new(Executed {
            market: req.market,
            epoch,
            header: header_bytes,
            receipt: result.receipt,
            artifacts: result.artifacts,
            attestation: result.attestation.unwrap_or_default(),
            ready,
            posted: Mutex::new(None),
            publishing: tokio::sync::Mutex::new(()),
        }))
    }

    fn landed(&self, market: &Address, epoch: u64, op: TxOp) -> Vec<([u8; 64], u64)> {
        self.log
            .get()
            .map(|log| log.landed(market, epoch, op))
            .unwrap_or_default()
    }

    /// The posting transaction of this enclave's receipt: from the
    /// journal when this process sent it, otherwise the batch's receipt
    /// slot with a zero signature.
    fn posted_tx(&self, e: &Executed, receipt_slot: u64) -> PostedTx {
        match self.landed(&e.market, e.epoch, TxOp::Post).last() {
            Some((signature, slot)) => PostedTx {
                signature: *signature,
                slot: *slot,
            },
            None => PostedTx {
                signature: [0; 64],
                slot: receipt_slot,
            },
        }
    }

    fn cosigned_txs(&self, e: &Executed) -> Vec<PostedTx> {
        self.landed(&e.market, e.epoch, TxOp::Cosign)
            .into_iter()
            .map(|(signature, slot)| PostedTx { signature, slot })
            .take(timescales_service::wire::MAX_COSIGS)
            .collect()
    }

    /// The publish request, start to finish.
    async fn publish(
        &self,
        e: &Arc<Executed>,
        req: &PublishRequest,
    ) -> Result<ExecutePosted, EnclaveError> {
        let market = self
            .markets
            .get(&e.market)
            .ok_or(EnclaveError::NotExecuted)?;
        let chain = &market.chain;
        let failed = |err: ChainError| EnclaveError::PostFailed(format!("chain: {err}"));
        let m = chain.market(Level::Confirmed).await.map_err(failed)?;
        let b = chain
            .batch(e.epoch, Level::Confirmed)
            .await
            .map_err(failed)?
            .ok_or_else(|| EnclaveError::PostFailed("no batch on chain".into()))?;
        self.chain_ok();
        match b.status {
            BatchStatus::Committed => {
                return Err(EnclaveError::PostFailed("beacon not revealed".into()));
            }
            BatchStatus::Aborted => return Err(EnclaveError::PostFailed("batch aborted".into())),
            BatchStatus::BeaconRevealed => {}
            BatchStatus::ReceiptPosted | BatchStatus::Verified | BatchStatus::Settled => {
                return self.posted_by_someone(chain.as_ref(), e, &m, &b).await;
            }
        }

        // 1. Co-signatures of quorum - 1 distinct registered executors
        // other than this one, over this outcome.
        let own = self.booted.enclave.executor_id();
        let need = usize::from(m.receipt_quorum.saturating_sub(1));
        let digest = cosign_digest(
            &e.market,
            EpochId(e.epoch),
            &e.ready.header_digest,
            &e.outcome_digest(),
        );
        let mut seen = BTreeSet::new();
        let valid = req.cosigs.iter().all(|(executor, sig)| {
            executor.0 != own.0
                && seen.insert(executor.0)
                && m.executor_slot(&executor.0).is_some()
                && verify_digest(&executor.0, &digest, sig).is_ok()
        });
        if !valid || req.cosigs.len() < need {
            return Err(EnclaveError::QuorumInvalid);
        }
        let cosigs: Vec<(Address, [u8; 64])> = req
            .cosigs
            .iter()
            .map(|(executor, sig)| (executor.0, sig.0))
            .collect();

        // 2. Post, co-sign, and see the receipt confirmed, within the
        // deadline.
        let deadline = tokio::time::Instant::now() + self.settings.post_deadline;
        let attempt = tokio::time::timeout_at(
            deadline,
            self.post_and_cosign(chain.as_ref(), e, &cosigs, deadline),
        )
        .await;
        let failure = match attempt {
            Ok(Ok(PostStep::Posted { receipt_slot })) => {
                self.watch_settlement(e, cosigs);
                return Ok(e.posted(self.posted_tx(e, receipt_slot), self.cosigned_txs(e)));
            }
            Ok(Ok(PostStep::Diverted)) => None,
            Ok(Err(why)) => Some(why),
            Err(_) => Some("post deadline expired".to_owned()),
        };

        // 3. Re-observe: never discard a result whose receipt may have
        // landed.
        let m = chain.market(Level::Confirmed).await.map_err(failed)?;
        let b = chain
            .batch(e.epoch, Level::Confirmed)
            .await
            .map_err(failed)?
            .ok_or_else(|| EnclaveError::PostFailed("no batch on chain".into()))?;
        if b.receipt == e.receipt_digest() {
            self.watch_settlement(e, cosigs);
            return Ok(e.posted(self.posted_tx(e, b.receipt_slot), self.cosigned_txs(e)));
        }
        if b.status >= BatchStatus::ReceiptPosted && b.status != BatchStatus::Aborted {
            return self.posted_by_someone(chain.as_ref(), e, &m, &b).await;
        }
        Err(EnclaveError::PostFailed(
            failure.unwrap_or_else(|| "receipt not on chain".to_owned()),
        ))
    }

    async fn post_and_cosign(
        &self,
        chain: &dyn MarketChain,
        e: &Executed,
        cosigs: &[(Address, [u8; 64])],
        deadline: tokio::time::Instant,
    ) -> Result<PostStep, String> {
        let posted = chain
            .ensure_posted(
                e.epoch,
                e.header,
                e.receipt.to_bytes(),
                Arc::clone(&self.fee_payer),
            )
            .await
            .map_err(|err| format!("post: {err}"))?;
        match posted {
            PostOutcome::Posted { .. } | PostOutcome::AlreadyPosted { same_receipt: true } => {}
            PostOutcome::AlreadyPosted {
                same_receipt: false,
            } => return Ok(PostStep::Diverted),
            PostOutcome::WrongStatus(s) => return Err(format!("batch is {s:?}")),
            PostOutcome::Rejected(err) => return Err(format!("program refused the post: {err}")),
        }
        if !cosigs.is_empty() {
            // The node re-sends any co-signature missing on chain, so a
            // failure here does not fail the post.
            match chain
                .ensure_cosigned(e.epoch, cosigs.to_vec(), Arc::clone(&self.fee_payer))
                .await
            {
                Ok(outcomes) => {
                    for o in outcomes {
                        if !matches!(
                            o,
                            CosignOutcome::Cosigned { .. } | CosignOutcome::AlreadyCosigned
                        ) {
                            tracing::warn!(epoch = e.epoch, outcome = ?o, "co-signature not applied");
                        }
                    }
                }
                Err(err) => tracing::warn!(epoch = e.epoch, error = %err, "co-signing failed"),
            }
        }
        // Through the market's QuorumRpc: `rpc_agree` providers (two in
        // production) must report the receipt confirmed.
        let b = chain
            .wait_batch(
                e.epoch,
                BatchPredicate::AtLeast(BatchStatus::ReceiptPosted),
                Level::Confirmed,
                deadline,
            )
            .await
            .map_err(|err| format!("waiting for the receipt: {err}"))?;
        if b.receipt != e.receipt_digest() {
            return Ok(PostStep::Diverted);
        }
        Ok(PostStep::Posted {
            receipt_slot: b.receipt_slot,
        })
    }

    /// The batch carries a receipt. This enclave's own (a
    /// post that landed earlier), another with the same outcome (co-sign,
    /// then answer once the quorum is on chain), or another outcome.
    async fn posted_by_someone(
        &self,
        chain: &dyn MarketChain,
        e: &Arc<Executed>,
        m: &MarketAccount,
        b: &BatchAccount,
    ) -> Result<ExecutePosted, EnclaveError> {
        if b.receipt == e.receipt_digest() {
            return Ok(e.posted(self.posted_tx(e, b.receipt_slot), self.cosigned_txs(e)));
        }
        if b.outcome_digest != e.outcome_digest() || b.header_digest != e.ready.header_digest {
            return Err(EnclaveError::OutcomeMismatch {
                receipt: e.receipt.to_bytes(),
            });
        }
        let own = self.booted.enclave.executor_id();
        let Some(slot) = m.executor_slot(&own.0) else {
            return Err(EnclaveError::PostFailed(
                "this executor is not registered".into(),
            ));
        };
        let (mut m, mut b) = (m.clone(), b.clone());
        if b.cosign_bitmap & (1u8 << slot) == 0 && b.status == BatchStatus::ReceiptPosted {
            let outcome = chain
                .ensure_cosigned(
                    e.epoch,
                    vec![(own.0, e.ready.cosign.0)],
                    Arc::clone(&self.fee_payer),
                )
                .await
                .map_err(|err| EnclaveError::PostFailed(format!("co-signing: {err}")))?;
            if outcome
                .iter()
                .any(|o| matches!(o, CosignOutcome::OutcomeMismatch))
            {
                return Err(EnclaveError::OutcomeMismatch {
                    receipt: e.receipt.to_bytes(),
                });
            }
            let failed = |err: ChainError| EnclaveError::PostFailed(format!("chain: {err}"));
            m = chain.market(Level::Confirmed).await.map_err(failed)?;
            b = chain
                .batch(e.epoch, Level::Confirmed)
                .await
                .map_err(failed)?
                .ok_or_else(|| EnclaveError::PostFailed("no batch on chain".into()))?;
        }
        if b.status == BatchStatus::Settled || m.quorum_met(b.cosign_bitmap) {
            return Ok(e.posted(
                PostedTx {
                    signature: [0; 64],
                    slot: b.receipt_slot,
                },
                self.cosigned_txs(e),
            ));
        }
        Err(EnclaveError::QuorumPending)
    }

    fn watch_settlement(&self, e: &Arc<Executed>, cosigs: Vec<(Address, [u8; 64])>) {
        self.settling
            .lock()
            .entry(e.ready.header_digest)
            .or_insert_with(|| SettleWatch {
                executed: Arc::clone(e),
                cosigs,
                progress: None,
                since: Instant::now(),
                cranking: Arc::default(),
            });
    }

    async fn reveal_backstop(&self, address: &Address, market: &Market) -> Result<(), ChainError> {
        let chain = &market.chain;
        let m = chain.market(Level::Confirmed).await?;
        self.chain_ok();
        if m.last_committed <= m.last_settled {
            return Ok(());
        }
        let epoch = m.last_committed;
        let Some(b) = chain.batch(epoch, Level::Confirmed).await? else {
            return Ok(());
        };
        if b.status != BatchStatus::Committed {
            return Ok(());
        }
        let d = u64::from(m.beacon_delay_slots);
        let due = b
            .commit_slot
            .saturating_add(2 * d)
            .saturating_add(self.settings.reveal_backstop_slots);
        if chain.slot(Level::Confirmed).await? < due {
            return Ok(());
        }
        match chain
            .ensure_revealed(epoch, Arc::clone(&self.fee_payer))
            .await?
        {
            RevealOutcome::Revealed { .. } => {
                let by_us = self
                    .log
                    .get()
                    .is_none_or(|_| !self.landed(address, epoch, TxOp::Reveal).is_empty());
                if by_us {
                    self.metrics.reveal_backstop.inc();
                    tracing::warn!(epoch, "revealed the beacon as a backstop");
                }
            }
            other => tracing::debug!(epoch, outcome = ?other, "reveal backstop"),
        }
        Ok(())
    }

    async fn settle_backstop(&self) {
        let watches: Vec<(Hash32, Arc<Executed>)> = self
            .settling
            .lock()
            .iter()
            .map(|(k, w)| (*k, Arc::clone(&w.executed)))
            .collect();
        for (key, e) in watches {
            let Some(market) = self.markets.get(&e.market) else {
                continue;
            };
            let chain = Arc::clone(&market.chain);
            let (Ok(m), Ok(b)) = (
                chain.market(Level::Confirmed).await,
                chain.batch(e.epoch, Level::Confirmed).await,
            ) else {
                continue;
            };
            let Some(b) = b.filter(|b| !b.status.is_terminal() && b.receipt == e.receipt_digest())
            else {
                self.settling.lock().remove(&key);
                continue;
            };
            let progress = (b.status, b.verified_count, b.applied_count, b.cosign_bitmap);
            let crank = {
                let mut settling = self.settling.lock();
                let Some(w) = settling.get_mut(&key) else {
                    continue;
                };
                if w.progress != Some(progress) {
                    w.progress = Some(progress);
                    w.since = Instant::now();
                    None
                } else if w.since.elapsed() >= self.settings.settle_backstop_after
                    && !w.cranking.swap(true, Ordering::AcqRel)
                {
                    w.since = Instant::now();
                    let missing: Vec<(Address, [u8; 64])> = w
                        .cosigs
                        .iter()
                        .filter(|(k, _)| {
                            m.executor_slot(k)
                                .is_some_and(|s| b.cosign_bitmap & (1u8 << s) == 0)
                        })
                        .copied()
                        .collect();
                    Some((missing, Arc::clone(&w.cranking)))
                } else {
                    None
                }
            };
            let Some((missing, cranking)) = crank else {
                continue;
            };
            let payer = Arc::clone(&self.fee_payer);
            let settlement = Arc::new(e.artifacts.settlement.clone());
            let epoch = e.epoch;
            tokio::spawn(async move {
                tracing::warn!(epoch, "settlement stalled; cranking it as a backstop");
                if !missing.is_empty()
                    && let Err(err) = chain
                        .ensure_cosigned(epoch, missing, Arc::clone(&payer))
                        .await
                {
                    tracing::warn!(epoch, error = %err, "re-sending co-signatures failed");
                }
                let (tx, _rx) = tokio::sync::mpsc::channel(16);
                match chain.ensure_settled(epoch, settlement, payer, tx).await {
                    Ok(slot) => tracing::info!(epoch, slot, "settled by the backstop"),
                    Err(err) => tracing::warn!(epoch, error = %err, "settlement backstop failed"),
                }
                cranking.store(false, Ordering::Release);
            });
        }
    }

    /// Drops results whose batch is terminal or gone, and expired
    /// registration quotes.
    async fn prune(&self) {
        self.identities
            .lock()
            .retain(|_, (at, _)| at.elapsed() < IDENTITY_TTL);
        let done: Vec<(Hash32, Address, u64)> = self
            .results
            .lock()
            .iter()
            .filter_map(|(k, s)| match s {
                Slot::Done(e) => Some((*k, e.market, e.epoch)),
                Slot::Running(_) => None,
            })
            .collect();
        for (key, address, epoch) in done {
            let Some(market) = self.markets.get(&address) else {
                continue;
            };
            let terminal = match market.chain.batch(epoch, Level::Confirmed).await {
                Ok(None) => true,
                Ok(Some(b)) => b.status.is_terminal(),
                Err(_) => false,
            };
            if terminal {
                self.results.lock().remove(&key);
                self.settling.lock().remove(&key);
            }
        }
    }
}

/// How the post step ended.
enum PostStep {
    Posted {
        receipt_slot: u64,
    },
    /// Another receipt is on chain.
    Diverted,
}
