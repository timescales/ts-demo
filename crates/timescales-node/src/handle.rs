//! [`NodeHandle`]: the [`NodeApi`] implementation, the only
//! interface between the engine and the HTTP layer, and [`start`].
//!
//! Reads that the API serves often (`current`, `status`, `markets`) come
//! from each market's watch channel, without an actor round trip.
//! Submissions and admin commands go through the actor's mailbox.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use timescales_chain::{Level, MarketChain, SolanaRpc};
use timescales_core::{
    CommitmentScheme, Encode, FlowMode, MarketParams, OrderCommitment, Rationing,
};
use timescales_service::Profile;
use timescales_service::api::{
    API_VERSION, B58, B64, Band, BookLabel, Clearing, CommitteeMemberView, CommitteeView,
    ComponentStatus, CreateSessionRequest, CurrentEpoch, EnclavePlatform, EpochKey, EpochPhaseRef,
    ErrorCode, Event, Hex32, IdlePolicy, Info, InfoLimits, Intake as IntakeState, KeyGeneration,
    MarketChainState, MarketDetail, MarketParamsJson, MarketState, MarketStatus, MarketSummary,
    MintAuthorities, MintAuthority, MpcStatus, Notice, NoticeLevel, Observation, OpenEpoch,
    OverallStatus, PaddingView, ParkedItem, PendingChangeView, PriceCommitmentView, ProfileJson,
    ProgramView, QuoteGeneration, QuoteVerification, RealSlotsLeft, ReferencePrice,
    RelayPolicyView, RetractResult, Session, SessionNonce, Status, StatusComponent, SubmitResult,
    TimingView, Trust, U64,
};
use timescales_service::relay::{CarryingCover, Padding, Relay, RelayConfig};
use timescales_service::store::node::{NodeRepo, Retention};
use timescales_service::wire::EpochKeyBundle;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::archive::Archive;
use crate::clock::Clock;
use crate::config::{
    Cluster, ExpectedPlatform, IdlePolicyConfig, MarketConfig, MarketFiles, NodeConfig,
    PaddingConfig, ReferenceSource,
};
use crate::events::{EventBus, LiveEvent};
use crate::exec::{EnclaveInfo, Enclaves};
use crate::intake::{Eligibility, Intake};
use crate::keys::KeyDirectory;
use crate::market::governance::Watch;
use crate::market::jobs::JobCtx;
use crate::market::recover::{RecoverError, RecoverInput};
use crate::market::runtime::{self, MarketHandle, Timing};
use crate::market::{
    BundleFacts, Cmd, MarketActor, MarketSettings, MarketView, Mode, Reply, SlotsLeft, public_phase,
};
use crate::sessions::{MarketQuotas, Sessions, SessionsInit};
use crate::telemetry::NodeMetrics;
use crate::{
    Address, AdminCmd, AdminReply, AdminStatus, BoxFuture, EventsSince, NodeApi, NodeDeps,
    NodeError, SessionError, SessionRef, SubmitError, VerifiedSubmission,
};

/// Mint facts shown in `MarketDetail` (display only, V-1 re-reads them).
#[derive(Clone, Copy, Debug, Default)]
struct MintFacts {
    decimals: u8,
    mint_authority: Option<Address>,
    freeze_authority: Option<Address>,
}

struct MarketEntry {
    cfg: MarketConfig,
    files: MarketFiles,
    handle: MarketHandle,
    keys: Arc<KeyDirectory>,
    reference: ReferenceSource,
    base_mint: MintFacts,
    quote_mint: MintFacts,
}

struct Inner {
    cfg: NodeConfig,
    program: Address,
    genesis: Address,
    repo: Arc<NodeRepo>,
    events: Arc<EventBus>,
    sessions: Arc<Sessions>,
    intake: Intake,
    clock: Arc<dyn Clock>,
    metrics: Arc<NodeMetrics>,
    markets: BTreeMap<Address, MarketEntry>,
    started_ms: u64,
}

/// A running node: the [`NodeApi`] implementation plus shutdown.
pub struct NodeHandle {
    inner: Arc<Inner>,
    shutdown: CancellationToken,
    tasks: parking_lot::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl core::fmt::Debug for NodeHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeHandle")
            .field("markets", &self.inner.markets.len())
            .finish_non_exhaustive()
    }
}

fn padding(p: PaddingConfig) -> Padding {
    match p {
        PaddingConfig::PowerOfTwo { min } => Padding::PowerOfTwo { min },
        PaddingConfig::Fixed { n } => Padding::Fixed(n),
        PaddingConfig::None => Padding::None,
    }
}

async fn mint_facts(rpc: &Arc<dyn SolanaRpc>, mint: Address) -> MintFacts {
    match rpc.get_account(mint, Level::Confirmed, None).await {
        Ok(Some(a)) => match timescales_chain::program::spl::decode_mint(&a.data) {
            Ok(m) => MintFacts {
                decimals: m.decimals,
                mint_authority: m.mint_authority,
                freeze_authority: m.freeze_authority,
            },
            Err(_) => MintFacts::default(),
        },
        _ => MintFacts::default(),
    }
}

/// Starts the node over `deps` (see [`crate::start`]).
pub async fn start(cfg: NodeConfig, deps: NodeDeps) -> Result<NodeHandle, NodeError> {
    let NodeDeps {
        chains,
        rpc,
        store,
        exec,
        clock,
        keys,
    } = deps;
    let program = cfg.program_id().ok_or_else(|| NodeError::Api {
        code: ErrorCode::Internal,
        detail: "solana.program_id is not a base58 address".into(),
    })?;
    let genesis = cfg.genesis_hash().unwrap_or_default();
    let repo = Arc::new(store);
    let metrics = Arc::new(NodeMetrics::unregistered());
    start_with_metrics(
        cfg, chains, rpc, repo, exec, clock, keys, metrics, program, genesis,
    )
    .await
}

/// [`start`] with the metric families the binary registered.
#[allow(clippy::too_many_arguments)]
pub async fn start_with_metrics(
    cfg: NodeConfig,
    chains: BTreeMap<Address, Arc<dyn MarketChain>>,
    rpc: Arc<dyn SolanaRpc>,
    repo: Arc<NodeRepo>,
    exec: Arc<dyn crate::ExecClient>,
    clock: Arc<dyn Clock>,
    keys: crate::NodeKeys,
    metrics: Arc<NodeMetrics>,
    program: Address,
    genesis: Address,
) -> Result<NodeHandle, NodeError> {
    let mut stream_id = [0u8; 16];
    OsRng.fill_bytes(&mut stream_id);
    repo.set_meta("stream_id", stream_id.to_vec()).await?;
    {
        let m = metrics.clone();
        repo.store().set_commit_observer(move |took, _| {
            m.store_commit_seconds.observe(took.as_secs_f64());
        });
    }
    let events = Arc::new(EventBus::new(repo.clone(), cfg.markets.len(), stream_id).await?);
    let eligibility = Arc::new(Eligibility::new(program, rpc.clone(), clock.clone()));
    let mut quotas = BTreeMap::new();
    let mut files = Vec::new();
    for m in &cfg.markets {
        let f = m.files(&program).map_err(|issues| {
            NodeError::Config(timescales_service::ConfigError::Invalid(issues))
        })?;
        quotas.insert(f.address, MarketQuotas::from(m));
        files.push((m.clone(), f));
    }
    let sessions = Arc::new(Sessions::new(SessionsInit {
        cfg: cfg.sessions.clone(),
        api: cfg.api.clone(),
        cluster: cfg.solana.cluster,
        program,
        nonce_key: keys.nonce_key.clone(),
        repo: repo.clone(),
        clock: clock.clone(),
        eligibility: eligibility.clone(),
        quotas,
    }));
    let enclaves = Arc::new(Enclaves::new(
        cfg.execution
            .enclaves
            .iter()
            .filter_map(EnclaveInfo::from_config)
            .collect(),
        &cfg.execution,
    ));
    let shutdown = CancellationToken::new();
    let grace = Duration::from_millis(cfg.node.shutdown_grace_ms);
    let release_level = crate::chain::level(cfg.solana.release_commitment);
    let archive = Archive::new(&cfg.node.data_dir);
    let retention = Retention {
        private_keep_epochs: cfg.store.private_keep_epochs,
        wallet_link_hours: cfg.store.wallet_link_hours,
        event_log_hours: u64::from(cfg.api.event_log_hours),
    };

    let mut markets = BTreeMap::new();
    let mut tasks = Vec::new();
    let mut intake_markets = BTreeMap::new();
    for (mcfg, f) in files {
        let address = f.address;
        let chain = chains
            .get(&address)
            .cloned()
            .ok_or(NodeError::MarketUnknown(address))?;
        let dir = Arc::new(KeyDirectory::new(
            address,
            f.params.market,
            f.committee.clone(),
        ));
        let relay_cfg = RelayConfig {
            params: f.params,
            market_address: address,
            padding: padding(mcfg.padding),
            allow_masked: false,
            max_real: mcfg.max_real_per_epoch,
            carry_p: mcfg.cover_carry_probability,
        };
        let cover = {
            let dir = dir.clone();
            let params = f.params;
            move || -> Box<dyn timescales_service::relay::CoverSource> {
                Box::new(CarryingCover::new(dir.clone(), params, false))
            }
        };
        let restored = crate::market::recover::recover(RecoverInput {
            market: address,
            chain: chain.clone(),
            repo: repo.clone(),
            keys: dir.clone(),
            relay_cfg: relay_cfg.clone(),
            relay_key: keys.relay_signing.clone(),
            cover: Box::new(cover.clone()),
            accept_chain_ahead: cfg.node.accept_chain_ahead,
            now_ms: clock.now_ms(),
        })
        .await
        .map_err(|e| match e {
            RecoverError::Store(s) => NodeError::Store(s),
            RecoverError::Chain(c) => NodeError::Chain(c),
            other => NodeError::Api {
                code: ErrorCode::MarketUnavailable,
                detail: other.to_string(),
            },
        })?;
        if let Some(open) = restored
            .epochs
            .iter()
            .find(|r| r.phase == timescales_service::store::node::Phase::Open)
            && clock.now_ms() >= open.cutoff_ms.unwrap_or(0)
        {
            metrics
                .epoch_late_cutoff
                .get_or_create(&metrics.market(&address))
                .inc();
        }
        let settings = Arc::new(MarketSettings {
            address,
            params: f.params,
            interval_ms: mcfg.epoch_interval_ms,
            padding: padding(mcfg.padding),
            carry_p: mcfg.cover_carry_probability,
            max_real: mcfg.max_real_per_epoch,
            park_ahead: mcfg.max_park_ahead_epochs,
            idle: mcfg.idle_policy,
            max_idle_extend: mcfg.max_idle_extend,
            quota: mcfg.quota.clone(),
            relay_key: keys.relay_signing.clone(),
            min_relay_lamports: cfg.solana.min_relay_balance_lamports.0,
            reclaim_batches: cfg.solana.reclaim_batches,
            backup_every_epochs: cfg.store.backup_every_epochs,
            private_keep_epochs: cfg.store.private_keep_epochs,
        });
        let relay_factory: crate::market::RelayFactory = {
            let relay_cfg = relay_cfg.clone();
            let key = keys.relay_signing.clone();
            let cover = cover.clone();
            Arc::new(move || Relay::new(relay_cfg.clone(), key.clone(), cover()))
        };
        let reference = crate::reference::source(f.params.market, &mcfg.reference);
        let reference_kind = mcfg.reference.source;
        let actor = MarketActor::new(settings.clone(), restored, reference, relay_factory);
        let ctx = Arc::new(JobCtx {
            market: address,
            settings,
            chain: chain.clone(),
            rpc: rpc.clone(),
            repo: repo.clone(),
            exec: exec.clone(),
            enclaves: enclaves.clone(),
            exec_cfg: cfg.execution.clone(),
            keys: dir.clone(),
            committee: f.committee.clone(),
            relay_signer: keys.relay.clone(),
            cranker: keys.cranker.clone(),
            clock: clock.clone(),
            events: events.clone(),
            metrics: metrics.clone(),
            archive: archive.clone(),
            eligibility: eligibility.clone(),
            release_level,
            slot_ms: 400,
            retention,
            backup_dir: cfg.store.backup_dir.clone(),
            wait: Duration::from_millis(cfg.solana.confirm_timeout_ms),
        });
        let watch = Watch {
            market: address,
            program,
            chain: chain.clone(),
            rpc: rpc.clone(),
            relay: keys.relay.address(),
            cranker: keys.cranker.address(),
            keys: dir.clone(),
            repo: repo.clone(),
            metrics: metrics.clone(),
        };
        let timing = Timing {
            tick: Duration::from_millis(50),
            poll: Duration::from_millis(cfg.solana.poll_interval_ms),
            program_every: 25,
        };
        let (handle, task) = runtime::spawn(actor, ctx, watch, timing, shutdown.clone(), grace);
        tasks.push(task);
        eligibility.register(address, f.params, mcfg.quota.clone(), handle.view.clone());
        intake_markets.insert(address, (handle.clone(), relay_cfg.clone()));
        let (base_mint, quote_mint) = match chain.market(Level::Confirmed).await {
            Ok(m) => (
                mint_facts(&rpc, m.base_mint).await,
                mint_facts(&rpc, m.quote_mint).await,
            ),
            Err(_) => (MintFacts::default(), MintFacts::default()),
        };
        markets.insert(
            address,
            MarketEntry {
                cfg: mcfg,
                files: f,
                handle,
                keys: dir,
                reference: reference_kind,
                base_mint,
                quote_mint,
            },
        );
    }
    let intake = Intake::new(
        intake_markets,
        crate::intake::Verifier::new(crate::MAX_BLOCKING_THREADS / 2),
        sessions.clone(),
        eligibility,
        repo.clone(),
        clock.clone(),
        Duration::from_millis(cfg.api.request_timeout_ms),
    );
    let started_ms = clock.now_ms();
    tracing::info!(markets = markets.len(), "node started");
    Ok(NodeHandle {
        inner: Arc::new(Inner {
            cfg,
            program,
            genesis,
            repo,
            events,
            sessions,
            intake,
            clock,
            metrics,
            markets,
            started_ms,
        }),
        shutdown,
        tasks: parking_lot::Mutex::new(tasks),
    })
}

fn market_state(v: &MarketView) -> MarketState {
    match v.mode {
        Mode::Fenced(_) => MarketState::Fenced,
        Mode::Recovering => MarketState::Recovering,
        Mode::Draining => MarketState::Draining,
        Mode::Running if v.operator_paused => MarketState::Paused,
        Mode::Running => MarketState::Running,
    }
}

fn clearing(prices: &[timescales_core::ClearingPrice]) -> Vec<Clearing> {
    prices
        .iter()
        .map(|p| Clearing {
            book: crate::exec::book(p.book),
            tick: U64(p.tick.0),
            volume: U64(p.volume.0),
        })
        .collect()
}

fn params_json(p: &MarketParams) -> MarketParamsJson {
    MarketParamsJson {
        market: U64(p.market.0),
        base_lot_size: U64(p.base_lot_size),
        tick_size: U64(p.tick_size),
        band_half_width: p.band_half_width,
        max_order_lots_log2: u32::from(p.max_order_lots_log2),
        max_orders_per_trader: u32::from(p.max_orders_per_trader),
        max_batch_envelopes: p.max_batch_envelopes,
        max_order_lifetime: p.max_order_lifetime,
        maker_fee_bps: u32::from(p.maker_fee.0),
        taker_fee_bps: u32::from(p.taker_fee.0),
        flow: match p.flow {
            FlowMode::SingleBook => timescales_service::api::FlowJson::SingleBook,
            FlowMode::DualFlow => timescales_service::api::FlowJson::DualFlow,
        },
        rationing: match p.rationing {
            Rationing::Lottery => timescales_service::api::RationingJson::Lottery,
            Rationing::ProRata => timescales_service::api::RationingJson::ProRata,
        },
        commitment_scheme: match p.commitment_scheme {
            // Configuration refuses every other scheme (validate_onchain).
            CommitmentScheme::Sha256 | CommitmentScheme::PoseidonBn254 => {
                timescales_service::api::CommitmentSchemeJson::Sha256
            }
        },
    }
}

fn reference_price(r: ReferenceSource) -> ReferencePrice {
    match r {
        ReferenceSource::Fixed => ReferencePrice::Fixed,
        ReferenceSource::LastClearing => ReferencePrice::LastClearing,
        ReferenceSource::Operator => ReferencePrice::Operator,
        ReferenceSource::ModelledTlsnotary => ReferencePrice::ModelledTlsnotary,
    }
}

fn epoch_key(bundle: &crate::keys::VerifiedBundle) -> EpochKey {
    EpochKey {
        epoch: U64(bundle.epoch),
        epoch_pk: Hex32(bundle.epoch_pk),
        committee_digest: Hex32(bundle.committee_digest.0),
        bundle_b64: B64(bundle.bytes.clone()),
    }
}

impl NodeHandle {
    /// Stops intake, waits for in-flight writes and jobs (bounded by
    /// `shutdown_grace_ms`) and returns.
    pub async fn shutdown(self) -> Result<(), NodeError> {
        self.shutdown.cancel();
        let tasks = std::mem::take(&mut *self.tasks.lock());
        let grace = Duration::from_millis(self.inner.cfg.node.shutdown_grace_ms);
        for t in tasks {
            let _ = tokio::time::timeout(grace + Duration::from_secs(1), t).await;
        }
        self.inner
            .repo
            .store()
            .barrier()
            .await
            .or_else(|e| match e {
                timescales_service::store::StoreError::Closed => Ok(()),
                other => Err(other),
            })?;
        Ok(())
    }

    /// `Authorization: TimescalesSession` for session-scoped routes.
    pub async fn authenticate(
        &self,
        header: &str,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<SessionRef, SessionError> {
        self.inner
            .sessions
            .authenticate(header, method, path_and_query, body)
            .await
    }

    /// `POST /v1/sessions` with whether the session was created (201) or
    /// an identical grant returned the existing one (200).
    pub async fn create_session_status(
        &self,
        req: CreateSessionRequest,
        min_context_slot: Option<u64>,
    ) -> Result<(Session, bool), SessionError> {
        self.inner.sessions.create(req, min_context_slot).await
    }

    /// Decodes `raw` exactly and verifies the submission for market `m` on
    /// the verification pool (OVERLOADED after two seconds without a
    /// slot). The API layer builds the items of [`NodeApi::submit`] with it.
    /// Intake verifies them again regardless.
    pub async fn verify_submission(
        &self,
        m: Address,
        raw: Vec<u8>,
    ) -> Result<VerifiedSubmission, SubmitError> {
        self.inner.intake.verify(m, raw).await
    }

    /// The node's metric families.
    pub fn metrics(&self) -> &Arc<NodeMetrics> {
        &self.inner.metrics
    }

    /// The live view of a market (tests and the admin status).
    pub fn view(&self, m: Address) -> Option<MarketView> {
        self.inner
            .markets
            .get(&m)
            .map(|e| e.handle.view.borrow().clone())
    }

    /// Readiness: store open, reconciliation done, every market's chain
    /// view fresh.
    pub fn ready(&self) -> bool {
        !self.inner.repo.store().is_closed()
            && self.inner.markets.values().all(|e| {
                let v = e.handle.view.borrow();
                v.context_slot > 0 && v.mode != Mode::Recovering
            })
    }

    fn entry(&self, m: Address) -> Result<&MarketEntry, NodeError> {
        self.inner
            .markets
            .get(&m)
            .ok_or(NodeError::MarketUnknown(m))
    }

    async fn ask(&self, m: Address, cmd: AdminCmd) -> Result<AdminReply, NodeError> {
        let e = self.entry(m)?;
        let (request, rx) = e.handle.replies.register();
        e.handle
            .internal
            .send(Cmd::Admin { request, cmd })
            .map_err(|_| NodeError::ShuttingDown)?;
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(Reply::Admin { reply, .. })) => Ok(reply),
            _ => {
                e.handle.replies.cancel(request);
                Err(NodeError::ShuttingDown)
            }
        }
    }

    fn market_status(&self, e: &MarketEntry) -> MarketStatus {
        let v = e.handle.view.borrow();
        MarketStatus {
            market: B58(e.files.address),
            state: market_state(&v),
            intake: if v.pause.is_none() {
                IntakeState::Open
            } else {
                IntakeState::Paused
            },
            pause_reason: v.pause,
            current_epoch: v.open.as_ref().map(|o| U64(o.epoch)),
            last_committed: U64(v.last_committed),
            last_settled: U64(v.last_settled),
            settlement_lag: u32::try_from(v.next_epoch.saturating_sub(v.last_settled + 1))
                .unwrap_or(u32::MAX),
            keys_ready_ahead: v.keys_ready_ahead,
        }
    }
}

impl NodeApi for NodeHandle {
    fn info(&self) -> Info {
        let i = &self.inner;
        let simulated = i.cfg.execution.expected_platform == ExpectedPlatform::Simulated;
        let first = i.markets.values().next();
        let account = first.and_then(|e| e.handle.view.borrow().chain_market.clone());
        let reference = first.map_or(ReferencePrice::Fixed, |e| reference_price(e.reference));
        let mut notes = Vec::new();
        if simulated {
            notes.push(
                "Enclave: SIMULATED. Execution runs on ordinary hardware; its host operator can \
                 read every order it executes."
                    .to_owned(),
            );
        } else {
            notes.push(
                "Enclave: Intel TDX. Quote generation through configfs-tsm is untested on \
                 hardware."
                    .to_owned(),
            );
        }
        notes.push(
            "Epoch keys come from a trusted dealer (Feldman VSS) that sees every key it deals; \
             no DKG."
                .to_owned(),
        );
        if reference == ReferencePrice::ModelledTlsnotary {
            notes
                .push("Reference price: MODELLED TLSNotary observations (no notarisation).".into());
        } else {
            notes.push("Reference price: operator-provided.".into());
        }
        Info {
            api_version: API_VERSION.to_owned(),
            protocol_version: 1,
            header_version: 2,
            node_version: env!("CARGO_PKG_VERSION").to_owned(),
            git_sha: option_env!("TIMESCALES_GIT_SHA")
                .unwrap_or("unknown")
                .to_owned(),
            profile: match i.cfg.node.profile {
                Profile::Local => ProfileJson::Local,
                Profile::Devnet => ProfileJson::Devnet,
                Profile::Production => ProfileJson::Production,
            },
            cluster: match i.cfg.solana.cluster {
                Cluster::Localnet => timescales_service::api::Cluster::Localnet,
                Cluster::Devnet => timescales_service::api::Cluster::Devnet,
                Cluster::MainnetBeta => timescales_service::api::Cluster::MainnetBeta,
            },
            genesis_hash: B58(i.genesis),
            program_id: B58(i.program),
            server_time_ms: i.clock.now_ms(),
            markets: i.markets.keys().copied().map(B58).collect(),
            trust: Trust {
                enclave: if simulated {
                    EnclavePlatform::Simulated
                } else {
                    EnclavePlatform::IntelTdx
                },
                quote_generation: if simulated {
                    QuoteGeneration::Simulated
                } else {
                    QuoteGeneration::ConfigfsTsmUntestedOnHardware
                },
                quote_verification: if simulated {
                    QuoteVerification::SimulatedVendor
                } else {
                    QuoteVerification::IntelDcap
                },
                key_generation: KeyGeneration::TrustedDealerFeldman,
                dkg: false,
                mpc: MpcStatus::Disabled,
                reference_price: reference,
                receipt_quorum: account.as_ref().map_or(0, |a| u32::from(a.receipt_quorum)),
                registered_executors: account.as_ref().map_or(0, |a| a.live_slots().count_ones()),
                notes,
            },
            limits: InfoLimits {
                submit_max_body_bytes: i.cfg.api.submit_max_body_bytes,
                session_max_ttl_s: u32::try_from(i.cfg.sessions.max_ttl_s).unwrap_or(u32::MAX),
            },
        }
    }

    fn status(&self) -> Status {
        let i = &self.inner;
        let now = i.clock.now_ms();
        let mut components = vec![StatusComponent {
            name: "store".into(),
            status: if i.repo.store().is_closed() {
                ComponentStatus::Down
            } else {
                ComponentStatus::Ok
            },
            detail: None,
            since_ms: i.started_ms,
        }];
        let mut markets = Vec::new();
        let mut recovering = false;
        let mut degraded = false;
        for e in i.markets.values() {
            let status = self.market_status(e);
            let v = e.handle.view.borrow();
            recovering |= v.mode == Mode::Recovering;
            let pipeline = match &v.mode {
                Mode::Fenced(_) => ComponentStatus::Down,
                _ if v.pause.is_some() => ComponentStatus::Degraded,
                _ => ComponentStatus::Ok,
            };
            degraded |= pipeline != ComponentStatus::Ok;
            let addr = bs58::encode(e.files.address).into_string();
            components.push(StatusComponent {
                name: format!("pipeline:{addr}"),
                status: pipeline,
                detail: v.pause.map(|p| format!("{p:?}").to_lowercase()),
                since_ms: i.started_ms,
            });
            components.push(StatusComponent {
                name: format!("epoch_keys:{addr}"),
                status: if v.keys_ready_ahead > 0 || v.open.is_some() {
                    ComponentStatus::Ok
                } else {
                    ComponentStatus::Degraded
                },
                detail: None,
                since_ms: i.started_ms,
            });
            markets.push(status);
        }
        let store_down = i.repo.store().is_closed();
        Status {
            status: if store_down {
                OverallStatus::Down
            } else if recovering {
                OverallStatus::Recovering
            } else if degraded {
                OverallStatus::Degraded
            } else {
                OverallStatus::Ok
            },
            server_time_ms: now,
            components,
            markets,
            notice: store_down.then(|| Notice {
                level: NoticeLevel::Critical,
                message: "The node's store is closed; it is restarting.".into(),
                since_ms: now,
            }),
        }
    }

    fn markets(&self) -> Vec<MarketSummary> {
        self.inner
            .markets
            .values()
            .map(|e| {
                let v = e.handle.view.borrow();
                MarketSummary {
                    market: B58(e.files.address),
                    name: e.cfg.name.clone(),
                    base_symbol: e.cfg.base_symbol.clone(),
                    quote_symbol: e.cfg.quote_symbol.clone(),
                    state: market_state(&v),
                    halted: v.halted,
                    last_clearing: (!v.last_clearing.is_empty())
                        .then(|| clearing(&v.last_clearing)),
                }
            })
            .collect()
    }

    fn market(&self, m: Address) -> Option<MarketDetail> {
        let e = self.inner.markets.get(&m)?;
        let v = e.handle.view.borrow().clone();
        let a = v.chain_market.clone()?;
        let summary = self.markets().into_iter().find(|s| s.market.0 == m)?;
        let c = &e.files.committee;
        let books = match a.params.flow {
            FlowMode::SingleBook => vec![BookLabel {
                book: timescales_service::api::Book::Single,
                label: "All buys against all sells".into(),
            }],
            FlowMode::DualFlow => vec![
                BookLabel {
                    book: timescales_service::api::Book::MakerAskTakerBid,
                    label: "Maker asks, taker bids".into(),
                },
                BookLabel {
                    book: timescales_service::api::Book::MakerBidTakerAsk,
                    label: "Maker bids, taker asks".into(),
                },
            ],
        };
        Some(MarketDetail {
            summary,
            market_id: U64(a.market_id),
            creator: B58(a.creator),
            admin: B58(a.admin),
            params: params_json(&a.params),
            params_b64: B64(a.params.to_bytes()),
            params_digest: Hex32(a.params_digest.0),
            base_mint: B58(a.base_mint),
            quote_mint: B58(a.quote_mint),
            base_vault: B58(a.base_vault),
            quote_vault: B58(a.quote_vault),
            base_decimals: u32::from(e.base_mint.decimals),
            quote_decimals: u32::from(e.quote_mint.decimals),
            relay: B58(a.relay),
            executors: a
                .executors
                .iter()
                .filter(|k| **k != [0; 32])
                .copied()
                .map(B58)
                .collect(),
            receipt_quorum: u32::from(a.receipt_quorum),
            committee: CommitteeView {
                digest: Hex32(c.digest().0),
                description_b64: B64(c.to_bytes()),
                threshold: u32::from(c.threshold),
                members: c
                    .members
                    .iter()
                    .map(|mm| CommitteeMemberView {
                        index: u32::from(mm.index),
                        identity: Hex32(mm.identity),
                        transport: Hex32(mm.transport),
                    })
                    .collect(),
                prev_digest: (a.prev_committee_digest != timescales_core::Hash32::ZERO)
                    .then_some(Hex32(a.prev_committee_digest.0)),
                prev_description_b64: None,
                policies_b64: Vec::new(),
            },
            timing: TimingView {
                epoch_interval_ms: u32::try_from(e.cfg.epoch_interval_ms).unwrap_or(u32::MAX),
                beacon_delay_slots: u32::from(a.beacon_delay_slots),
                exec_timeout_slots: U64(a.exec_timeout_slots),
                settle_timeout_slots: U64(a.settle_timeout_slots),
                timelock_slots: U64(a.timelock_slots),
                max_park_ahead_epochs: e.cfg.max_park_ahead_epochs,
            },
            relay_policy: RelayPolicyView {
                padding: match e.cfg.padding {
                    PaddingConfig::PowerOfTwo { min } => PaddingView::PowerOfTwo { min },
                    PaddingConfig::Fixed { n } => PaddingView::Fixed { n },
                    // An unpadded relay (local only) publishes real counts.
                    // Shown as a fixed size of 0.
                    PaddingConfig::None => PaddingView::Fixed { n: 0 },
                },
                ack: timescales_service::api::AckView::Immediate,
                max_envelopes_per_wallet_per_epoch: e.cfg.quota.max_envelopes_per_wallet_per_epoch,
                max_parked_per_wallet: e.cfg.quota.max_parked_per_wallet,
                min_available_value_quote: U64(e.cfg.quota.min_available_value_quote.0),
                min_value_per_envelope_quote: U64(e.cfg.quota.min_value_per_envelope_quote.0),
                require_trader_account: e.cfg.quota.require_trader_account,
                idle_policy: match e.cfg.idle_policy {
                    IdlePolicyConfig::Commit => IdlePolicy::Commit,
                    IdlePolicyConfig::Extend => IdlePolicy::Extend,
                },
            },
            market_id_salt: Hex32(a.salt),
            session_domains: self.inner.cfg.api.session_domains.clone(),
            mint_authorities: MintAuthorities {
                base: MintAuthority {
                    mint: e.base_mint.mint_authority.map(B58),
                    freeze: e.base_mint.freeze_authority.map(B58),
                },
                quote: MintAuthority {
                    mint: e.quote_mint.mint_authority.map(B58),
                    freeze: e.quote_mint.freeze_authority.map(B58),
                },
            },
            books,
            pending_change: a.pending.as_ref().map(|p| PendingChangeView {
                kind: match p.change.kind() {
                    1 => timescales_service::api::ChangeKind::SetRelay,
                    2 => timescales_service::api::ChangeKind::SetExecutors,
                    3 => timescales_service::api::ChangeKind::SetCommitteeDigest,
                    4 => timescales_service::api::ChangeKind::SetAdmin,
                    5 => timescales_service::api::ChangeKind::SetTimings,
                    _ => timescales_service::api::ChangeKind::SetTimelock,
                },
                eta_slot: U64(p.eta_slot),
                payload_b64: B64(p.change.payload().unwrap_or_default()),
                due: v.context_slot >= p.eta_slot,
            }),
            program: ProgramView {
                upgrade_authority: v.program.and_then(|p| p.upgrade_authority).map(B58),
                last_deploy_slot: U64(v.program.map_or(0, |p| p.last_deploy_slot)),
            },
            chain: MarketChainState {
                last_committed: U64(a.last_committed),
                last_settled: U64(a.last_settled),
                state_root: Hex32(a.state_root.0),
                prev_receipt: Hex32(a.prev_receipt.0),
                context_slot: U64(v.context_slot),
            },
        })
    }

    fn current(&self, m: Address) -> Option<CurrentEpoch> {
        let e = self.inner.markets.get(&m)?;
        let v = e.handle.view.borrow().clone();
        let source = reference_price(e.reference);
        let open = v.open.as_ref().and_then(|o| {
            let bundle = e.keys.get(o.epoch)?;
            let pc = o.price_commitment.as_ref();
            Some(OpenEpoch {
                epoch: U64(o.epoch),
                opens_at_ms: o.opens_at_ms,
                cutoff_ms: o.cutoff_ms,
                band: Band {
                    lo: U64(o.band.lo.0),
                    hi: U64(o.band.hi.0),
                    reference: U64(o.band.reference.0),
                },
                binding: Hex32(o.binding.0),
                terms_digest: Hex32(o.terms_digest.0),
                price_commitment: PriceCommitmentView {
                    digest: Hex32(pc.map_or([0; 32], |p| p.digest().0)),
                    reference: U64(o.band.reference.0),
                    source,
                    observations: pc
                        .map(|p| {
                            p.observations
                                .iter()
                                .map(|ob| Observation {
                                    source: ob.source,
                                    tick: U64(ob.tick.0),
                                    time: U64(ob.time),
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    commitment_b64: B64(pc.map(Encode::to_bytes).unwrap_or_default()),
                },
                announcement_b64: B64(o.announcement.clone()),
                key: epoch_key(&bundle),
                real_slots_left: match o.slots_left {
                    SlotsLeft::Available => RealSlotsLeft::Available,
                    SlotsLeft::Low => RealSlotsLeft::Low,
                    SlotsLeft::Full => RealSlotsLeft::Full,
                },
            })
        });
        Some(CurrentEpoch {
            market: B58(m),
            server_time_ms: self.inner.clock.now_ms(),
            intake: if v.pause.is_none() {
                IntakeState::Open
            } else {
                IntakeState::Paused
            },
            pause_reason: v.pause,
            open,
            park_window: v
                .park_window
                .iter()
                .filter_map(|ep| e.keys.get(*ep))
                .map(|b| epoch_key(&b))
                .collect(),
            previous: v.previous.map(|(ep, p)| EpochPhaseRef {
                epoch: U64(ep),
                phase: public_phase(p),
            }),
            inflight: v.inflight.map(|(ep, p)| EpochPhaseRef {
                epoch: U64(ep),
                phase: public_phase(p),
            }),
            context_slot: U64(v.context_slot),
        })
    }

    fn submit(
        &self,
        m: Address,
        items: Vec<VerifiedSubmission>,
        session: SessionRef,
    ) -> BoxFuture<'_, Vec<Result<SubmitResult, SubmitError>>> {
        Box::pin(async move { self.inner.intake.submit(m, items, session).await })
    }

    fn parked(
        &self,
        m: Address,
        session: SessionRef,
    ) -> BoxFuture<'_, Result<Vec<ParkedItem>, NodeError>> {
        Box::pin(async move {
            self.entry(m)?;
            Ok(self
                .inner
                .repo
                .parked_by_wallet(m, session.wallet)
                .await?
                .into_iter()
                .map(|(epoch, c)| ParkedItem {
                    epoch: U64(epoch),
                    commitment: Hex32(c.0),
                })
                .collect())
        })
    }

    fn retract_parked(
        &self,
        m: Address,
        session: SessionRef,
        c: OrderCommitment,
    ) -> BoxFuture<'_, Result<RetractResult, NodeError>> {
        Box::pin(async move {
            let e = self.entry(m)?;
            let (request, rx) = e.handle.replies.register();
            e.handle
                .tx
                .try_send(Cmd::Retract {
                    request,
                    wallet: session.wallet,
                    commitment: c,
                })
                .map_err(|_| {
                    e.handle.replies.cancel(request);
                    NodeError::Api {
                        code: ErrorCode::Overloaded,
                        detail: "market mailbox full".into(),
                    }
                })?;
            match tokio::time::timeout(Duration::from_secs(10), rx).await {
                Ok(Ok(Reply::Retract {
                    removed, kept_open, ..
                })) => Ok(RetractResult {
                    removed_epochs: removed.into_iter().map(U64).collect(),
                    kept_open_epoch: kept_open.map(U64),
                }),
                _ => {
                    e.handle.replies.cancel(request);
                    Err(NodeError::ShuttingDown)
                }
            }
        })
    }

    fn session_nonce(&self) -> BoxFuture<'_, Result<SessionNonce, NodeError>> {
        Box::pin(async move { Ok(self.inner.sessions.nonce()) })
    }

    fn create_session(
        &self,
        req: CreateSessionRequest,
        min_context_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Session, SessionError>> {
        Box::pin(async move {
            self.inner
                .sessions
                .create(req, min_context_slot)
                .await
                .map(|(s, _)| s)
        })
    }

    fn session(&self, key: [u8; 32]) -> BoxFuture<'_, Result<Option<Session>, NodeError>> {
        Box::pin(async move {
            let Some(row) = self.inner.repo.session(key).await? else {
                return Ok(None);
            };
            let market = row
                .market
                .or_else(|| self.inner.markets.keys().next().copied());
            let usage = match market.and_then(|m| self.inner.markets.get(&m).map(|e| (m, e))) {
                Some((m, e)) => {
                    let epoch = e.handle.view.borrow().next_epoch;
                    let (used, parked) = self.inner.repo.wallet_usage(m, epoch, row.wallet).await?;
                    Some(crate::sessions::usage(epoch, used, parked))
                }
                None => None,
            };
            Ok(Some(self.inner.sessions.dto(&row, None, usage)))
        })
    }

    fn revoke_session(&self, key: [u8; 32]) -> BoxFuture<'_, Result<(), NodeError>> {
        Box::pin(async move { self.inner.sessions.revoke(key).await })
    }

    fn events(&self) -> broadcast::Receiver<Arc<LiveEvent>> {
        self.inner.events.subscribe()
    }

    fn head_seq(&self) -> u64 {
        self.inner.events.head_seq()
    }

    fn events_since(
        &self,
        seq: u64,
        topics: Vec<String>,
    ) -> BoxFuture<'_, Result<EventsSince, NodeError>> {
        Box::pin(async move { Ok(self.inner.events.since(seq, topics).await?) })
    }

    fn stream_id(&self) -> [u8; 16] {
        self.inner.events.stream_id()
    }

    fn store(&self) -> &NodeRepo {
        &self.inner.repo
    }

    fn put_key_bundle(
        &self,
        m: Address,
        b: EpochKeyBundle,
    ) -> BoxFuture<'_, Result<(), NodeError>> {
        Box::pin(async move {
            let e = self.entry(m)?;
            let epoch = b.announcement.epoch.0;
            let v = e
                .keys
                .verify_bundle(epoch, b)
                .map_err(|err| NodeError::Api {
                    code: ErrorCode::BadRequest,
                    detail: err.to_string(),
                })?;
            let now = self.inner.clock.now_ms();
            let outcome = self
                .inner
                .repo
                .put_key_bundle(m, epoch, v.bytes.clone(), now)
                .await?;
            match outcome {
                timescales_service::store::node::PutOutcome::Conflict => {
                    return Err(NodeError::Api {
                        code: ErrorCode::BadRequest,
                        detail: format!(
                            "a different bundle is held for epoch {epoch} and may not be replaced"
                        ),
                    });
                }
                timescales_service::store::node::PutOutcome::Identical => {
                    let _ = e.keys.insert(v.clone());
                }
                timescales_service::store::node::PutOutcome::Inserted => {
                    e.keys.replace(v.clone());
                    if let Err(err) = self
                        .inner
                        .events
                        .publish(
                            vec![(
                                Some(m),
                                Event::KeyPublished {
                                    market: B58(m),
                                    epoch: U64(epoch),
                                },
                            )],
                            now,
                        )
                        .await
                    {
                        tracing::warn!(error = %err, "key.published not published");
                    }
                }
            }
            e.handle
                .internal
                .send(Cmd::KeyBundle {
                    epoch,
                    facts: BundleFacts {
                        key_digest: v.key_digest,
                        committee_digest: v.committee_digest,
                        epoch_pk: v.epoch_pk,
                        bytes: v.bytes,
                    },
                })
                .map_err(|_| NodeError::ShuttingDown)?;
            Ok(())
        })
    }

    fn admin(&self, cmd: AdminCmd) -> BoxFuture<'_, Result<AdminReply, NodeError>> {
        Box::pin(async move {
            match cmd {
                AdminCmd::Status => {
                    let mut markets = Vec::new();
                    for m in self.inner.markets.keys().copied().collect::<Vec<_>>() {
                        if let AdminReply::Status(s) = self.ask(m, AdminCmd::Status).await? {
                            markets.extend(s.markets);
                        }
                    }
                    Ok(AdminReply::Status(AdminStatus { markets }))
                }
                AdminCmd::Backup => {
                    let dir = &self.inner.cfg.store.backup_dir;
                    std::fs::create_dir_all(dir).map_err(|e| NodeError::Api {
                        code: ErrorCode::Internal,
                        detail: format!("backup dir: {e}"),
                    })?;
                    let dest =
                        dir.join(format!("node-manual-{}.sqlite", self.inner.clock.now_ms()));
                    let report = self.inner.repo.backup(dest).await?;
                    Ok(AdminReply::Backup(report))
                }
                AdminCmd::Pause(m)
                | AdminCmd::Resume(m)
                | AdminCmd::Drain(m)
                | AdminCmd::SetReference(m, _)
                | AdminCmd::Abort(m, _) => self.ask(m, cmd).await,
            }
        })
    }
}

impl Drop for NodeHandle {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}
