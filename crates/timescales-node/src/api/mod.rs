//! HTTP layer over [`NodeApi`]: public REST and WebSocket routes, and the
//! admin and internal routes on the private listener.
//!
//! The public router applies, outermost first: request ids, the version
//! header and problem bodies ([`limits::frame`]). CORS. Draining, load
//! shedding and the request timeout ([`limits::shed`]). And the per-IP rate
//! limit ([`limits::per_ip`]). Session and wallet limits, body limits and
//! authentication are applied by the handlers that need them. The listener
//! must be served with `into_make_service_with_connect_info::<SocketAddr>`,
//! or every client shares one per-IP bucket.

mod admin;
mod errors;
mod internal;
mod limits;
mod reads;
mod sessions;
mod submit;
mod ws;

use std::sync::Arc;

use axum::Router;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ipnet::IpNet;
use timescales_chain::Address;
use timescales_service::api::{ErrorCode, ExecutorRegistration, RateLimitScope};
use timescales_service::wire::EnvelopeSigner;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub use admin::{AbortWindow, RUNBOOK_STUCK_BATCH, abort_window};

use self::errors::ApiError;
use self::limits::{Gcra, IpKey, NodeClock};
use crate::config::{AdminConfig, ApiConfig};
use crate::{BoxFuture, Clock, NodeApi, NodeError, SystemClock};

/// The tolerated clock difference of `TimescalesSession` requests.
pub const DEFAULT_SESSION_SKEW_MS: u64 = 30_000;

/// Executor registrations for `GET /v1/executors` (the evidence each
/// enclave presented when it was registered). [`NodeApi`] does not carry
/// them, so the node passes a directory in [`ApiOptions`].
pub trait ExecutorDirectory: Send + Sync {
    fn executors(
        &self,
        market: Address,
    ) -> BoxFuture<'_, Result<Vec<ExecutorRegistration>, NodeError>>;
}

/// What the public router needs besides [`NodeApi`] and `[api]`.
#[derive(Clone)]
pub struct ApiOptions {
    pub clock: Arc<dyn Clock>,
    /// `[sessions] skew_ms`.
    pub session_skew_ms: u64,
    /// Cancelled when the node starts draining: new requests get
    /// `DRAINING` and streams close with 4503.
    pub shutdown: CancellationToken,
    pub executors: Option<Arc<dyn ExecutorDirectory>>,
}

impl Default for ApiOptions {
    fn default() -> Self {
        ApiOptions {
            clock: Arc::new(SystemClock),
            session_skew_ms: DEFAULT_SESSION_SKEW_MS,
            shutdown: CancellationToken::new(),
            executors: None,
        }
    }
}

impl core::fmt::Debug for ApiOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApiOptions")
            .field("session_skew_ms", &self.session_skew_ms)
            .field("draining", &self.shutdown.is_cancelled())
            .field("executors", &self.executors.is_some())
            .finish_non_exhaustive()
    }
}

/// State shared by the public handlers.
pub(crate) struct Shared {
    pub(crate) node: Arc<dyn NodeApi>,
    pub(crate) cfg: ApiConfig,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) trusted: Vec<IpNet>,
    pub(crate) per_ip: Gcra<IpKey>,
    pub(crate) per_session: Gcra<[u8; 32]>,
    pub(crate) per_wallet: Gcra<[u8; 32]>,
    pub(crate) concurrency: Arc<Semaphore>,
    pub(crate) shutdown: CancellationToken,
    pub(crate) session_skew_ms: u64,
    pub(crate) replay: sessions::ReplayCache,
    pub(crate) streams: ws::Connections,
    pub(crate) executors: Option<Arc<dyn ExecutorDirectory>>,
}

pub(crate) type Ctx = Arc<Shared>;

impl Shared {
    pub(crate) fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }
}

fn trusted_proxies(cidrs: &[String]) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|c| match c.parse::<IpNet>() {
            Ok(n) => Some(n),
            Err(_) => {
                tracing::error!(cidr = %c, "ignoring an invalid trusted proxy CIDR");
                None
            }
        })
        .collect()
}

/// Public REST + WS.
pub fn router(node: Arc<dyn NodeApi>, cfg: ApiConfig) -> Router {
    router_with(node, cfg, ApiOptions::default())
}

/// [`router`] with the node's clock, session skew, shutdown signal and
/// executor directory.
pub fn router_with(node: Arc<dyn NodeApi>, cfg: ApiConfig, opts: ApiOptions) -> Router {
    let clock = NodeClock(opts.clock.clone());
    let rl = &cfg.rate_limit;
    let ctx: Ctx = Arc::new(Shared {
        node,
        trusted: trusted_proxies(&cfg.trusted_proxy_cidrs),
        per_ip: Gcra::new(
            RateLimitScope::Ip,
            rl.per_ip_rps,
            rl.per_ip_burst,
            clock.clone(),
        ),
        per_session: Gcra::new(
            RateLimitScope::Session,
            rl.per_session_rps,
            rl.per_session_burst,
            clock.clone(),
        ),
        per_wallet: Gcra::new(
            RateLimitScope::Wallet,
            rl.per_wallet_submit_rps,
            rl.per_wallet_submit_burst,
            clock,
        ),
        concurrency: Arc::new(Semaphore::new(
            usize::try_from(cfg.max_concurrency.max(1)).unwrap_or(usize::MAX),
        )),
        clock: opts.clock,
        shutdown: opts.shutdown,
        session_skew_ms: opts.session_skew_ms,
        replay: sessions::ReplayCache::default(),
        streams: ws::Connections::default(),
        executors: opts.executors,
        cfg,
    });
    let cors = limits::cors(&ctx.cfg.cors_allowed_origins);
    Router::new()
        .route("/livez", get(reads::livez))
        .route("/readyz", get(reads::readyz))
        .route("/v1/info", get(reads::info))
        .route("/v1/status", get(reads::status))
        .route("/v1/time", get(reads::time))
        .route("/v1/markets", get(reads::markets))
        .route("/v1/markets/{market}", get(reads::market))
        .route("/v1/markets/{market}/epochs/current", get(reads::current))
        .route("/v1/markets/{market}/epochs", get(reads::epochs))
        .route("/v1/markets/{market}/epochs/{epoch}", get(reads::epoch))
        .route("/v1/markets/{market}/epochs/{epoch}/key", get(reads::key))
        .route(
            "/v1/markets/{market}/epochs/{epoch}/leaves",
            get(reads::leaves),
        )
        .route(
            "/v1/markets/{market}/epochs/{epoch}/leaves.bin",
            get(reads::leaves_bin),
        )
        .route(
            "/v1/markets/{market}/epochs/{epoch}/artifacts",
            get(reads::artifacts),
        )
        .route(
            "/v1/markets/{market}/epochs/{epoch}/balances",
            get(reads::balances),
        )
        .route(
            "/v1/markets/{market}/committee/policies",
            get(reads::policies),
        )
        .route("/v1/markets/{market}/clearing", get(reads::clearing))
        .route("/v1/executors", get(reads::executors))
        .route("/v1/sessions/nonce", get(sessions::nonce))
        .route("/v1/sessions", post(sessions::create))
        .route(
            "/v1/sessions/current",
            get(sessions::current).delete(sessions::revoke),
        )
        .route("/v1/markets/{market}/submissions", post(submit::one))
        .route(
            "/v1/markets/{market}/submissions/batch",
            post(submit::batch),
        )
        .route("/v1/markets/{market}/parked", get(sessions::parked))
        .route(
            "/v1/markets/{market}/parked/retract",
            post(sessions::retract),
        )
        .route("/v1/stream", get(ws::upgrade))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(from_fn_with_state(ctx.clone(), limits::per_ip))
        .layer(from_fn_with_state(ctx.clone(), limits::shed))
        .layer(cors)
        .layer(from_fn(limits::frame))
        .with_state(ctx)
}

async fn not_found() -> Response {
    ApiError::new(ErrorCode::NotFound, "no such resource").into_response()
}

async fn method_not_allowed() -> Response {
    ApiError::bad_request("method", "method not allowed on this resource").into_response()
}

/// What the admin router needs besides [`NodeApi`] and `[admin]`.
#[derive(Clone)]
pub struct AdminOptions {
    pub clock: Arc<dyn Clock>,
    /// The bearer token. Read from `token_file` when `None`.
    pub token: Option<Zeroizing<String>>,
    /// The node's service key: it addresses and signs the answers of the
    /// internal routes. Without it those routes answer 503.
    pub service: Option<Arc<dyn EnvelopeSigner>>,
    /// Tolerated clock difference of internal envelopes.
    pub envelope_skew_ms: u64,
}

impl Default for AdminOptions {
    fn default() -> Self {
        AdminOptions {
            clock: Arc::new(SystemClock),
            token: None,
            service: None,
            envelope_skew_ms: DEFAULT_SESSION_SKEW_MS,
        }
    }
}

impl core::fmt::Debug for AdminOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdminOptions")
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("service", &self.service.as_ref().map(|s| s.public()))
            .field("envelope_skew_ms", &self.envelope_skew_ms)
            .finish_non_exhaustive()
    }
}

/// Admin + internal routes.
pub fn admin_router(node: Arc<dyn NodeApi>, cfg: AdminConfig) -> Router {
    admin_router_with(node, cfg, AdminOptions::default())
}

/// [`admin_router`] with the node's clock, an explicit token and the
/// service key that signs internal answers.
pub fn admin_router_with(node: Arc<dyn NodeApi>, cfg: AdminConfig, opts: AdminOptions) -> Router {
    admin::router(node, cfg, opts)
}
