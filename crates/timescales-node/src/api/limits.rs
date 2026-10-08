//! Limits and the controls that apply to every public request:
//! request ids and the version header, load shedding, the per-IP rate limit
//! (IPv6 clients keyed by their /64), body limits and CORS.

use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::clock::Clock as GovernorClock;
use governor::middleware::StateInformationMiddleware;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use ipnet::IpNet;
use timescales_service::api::{API_VERSION, ErrorCode, RateLimitScope};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::Instrument;

use super::Ctx;
use super::errors::{ApiError, PROBLEM_CONTENT_TYPE, PendingProblem};
use crate::Clock;

pub(crate) const API_VERSION_HEADER: &str = "timescales-api-version";
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";
pub(crate) const RATE_LIMIT_POLICY_HEADER: &str = "ratelimit-policy";
pub(crate) const RATE_LIMIT_HEADER: &str = "ratelimit";

/// Routes that answer health probes. They are never rate limited or shed.
fn is_probe(path: &str) -> bool {
    matches!(path, "/livez" | "/readyz")
}

// ---- Client identity ----

/// What per-IP limits are keyed on: an IPv4 address, or the /64 of an IPv6
/// address (one subscriber usually holds a whole /64).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum IpKey {
    V4([u8; 4]),
    V6Net([u8; 8]),
    /// The listener was not given peer addresses. Every such client shares
    /// one bucket.
    Unknown,
}

impl IpKey {
    pub(crate) fn of(ip: Option<IpAddr>) -> IpKey {
        match ip {
            Some(IpAddr::V4(a)) => IpKey::V4(a.octets()),
            Some(IpAddr::V6(a)) => match a.to_ipv4_mapped() {
                Some(v4) => IpKey::V4(v4.octets()),
                None => {
                    let mut net = [0; 8];
                    net.copy_from_slice(&a.octets()[..8]);
                    IpKey::V6Net(net)
                }
            },
            None => IpKey::Unknown,
        }
    }
}

/// The client's address: the peer, or, when the peer is a trusted proxy,
/// the right-most `X-Forwarded-For` hop that is not one.
pub(crate) fn client_ip(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted: &[IpNet],
) -> Option<IpAddr> {
    let peer = peer?;
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(&peer) {
        return Some(peer);
    }
    let mut hops = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let Ok(value) = value.to_str() else {
            return Some(peer);
        };
        for hop in value.split(',') {
            match hop.trim().parse::<IpAddr>() {
                Ok(ip) => hops.push(ip),
                // A hop we cannot read ends what we can trust.
                Err(_) => return Some(peer),
            }
        }
    }
    let mut client = peer;
    for ip in hops.into_iter().rev() {
        client = ip;
        if !is_trusted(&ip) {
            break;
        }
    }
    Some(client)
}

/// The client key of a request.
pub(crate) fn request_ip_key(
    ctx: &Ctx,
    req_headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> IpKey {
    IpKey::of(client_ip(peer.map(|p| p.ip()), req_headers, &ctx.trusted))
}

pub(crate) fn peer_of(req: &Request) -> Option<SocketAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
}

// ---- GCRA rate limits ----

/// governor over the node's [`Clock`], so tests move time by hand.
#[derive(Clone)]
pub(crate) struct NodeClock(pub(crate) Arc<dyn Clock>);

impl GovernorClock for NodeClock {
    type Instant = Duration;

    fn now(&self) -> Duration {
        Duration::from_millis(self.0.now_ms())
    }
}

type Keyed<K> = RateLimiter<K, DashMapStateStore<K>, NodeClock, StateInformationMiddleware>;

/// How often the limiter forgets keys whose buckets are full again.
const RETAIN_EVERY: u64 = 4096;

/// One GCRA limit (`rps` sustained, `burst` at once) per key.
pub(crate) struct Gcra<K: Hash + Eq + Clone> {
    scope: RateLimitScope,
    limiter: Keyed<K>,
    clock: NodeClock,
    rps: u32,
    burst: u32,
    checks: AtomicU64,
}

/// The bucket after a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RateState {
    pub(crate) remaining: u32,
    /// Zero when the request was allowed.
    pub(crate) retry_after_ms: u64,
}

impl<K: Hash + Eq + Clone> Gcra<K> {
    pub(crate) fn new(scope: RateLimitScope, rps: u32, burst: u32, clock: NodeClock) -> Self {
        let rps = rps.max(1);
        let burst = burst.max(1);
        let quota = Quota::per_second(NonZeroU32::new(rps).unwrap_or(NonZeroU32::MIN))
            .allow_burst(NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN));
        let limiter = Keyed::<K>::new(quota, DashMapStateStore::default(), clock.clone());
        Gcra {
            scope,
            limiter,
            clock,
            rps,
            burst,
            checks: AtomicU64::new(0),
        }
    }

    /// Takes one token for `key`.
    pub(crate) fn check(&self, key: &K) -> Result<RateState, RateState> {
        if self.checks.fetch_add(1, Ordering::Relaxed) % RETAIN_EVERY == RETAIN_EVERY - 1 {
            self.limiter.retain_recent();
        }
        match self.limiter.check_key(key) {
            Ok(snapshot) => Ok(RateState {
                remaining: snapshot.remaining_burst_capacity(),
                retry_after_ms: 0,
            }),
            Err(not_until) => {
                let wait = not_until.wait_time_from(self.clock.now());
                Err(RateState {
                    remaining: 0,
                    retry_after_ms: u64::try_from(wait.as_millis()).unwrap_or(u64::MAX).max(1),
                })
            }
        }
    }

    fn scope_name(&self) -> &'static str {
        match self.scope {
            RateLimitScope::Ip => "ip",
            RateLimitScope::Session => "session",
            RateLimitScope::Wallet => "wallet",
        }
    }

    /// `RateLimit-Policy` and `RateLimit` (draft-ietf-httpapi-ratelimit-headers):
    /// the quota is `burst` requests per the window that refills it, and `t`
    /// is the seconds until the bucket is full again.
    pub(crate) fn headers(&self, state: RateState) -> [(&'static str, String); 2] {
        let window = u64::from(self.burst).div_ceil(u64::from(self.rps)).max(1);
        let used = u64::from(self.burst.saturating_sub(state.remaining));
        let refill = used.div_ceil(u64::from(self.rps));
        let name = self.scope_name();
        [
            (
                RATE_LIMIT_POLICY_HEADER,
                format!("\"{name}\";q={};w={window}", self.burst),
            ),
            (
                RATE_LIMIT_HEADER,
                format!("\"{name}\";r={};t={refill}", state.remaining),
            ),
        ]
    }

    /// Takes a token, or the `RATE_LIMITED` problem with its headers.
    pub(crate) fn take(&self, key: &K) -> Result<[(&'static str, String); 2], ApiError> {
        match self.check(key) {
            Ok(state) => Ok(self.headers(state)),
            Err(state) => {
                let [policy, rate] = self.headers(state);
                Err(ApiError::rate_limited(self.scope, state.retry_after_ms)
                    .with_header(policy.0, policy.1)
                    .with_header(rate.0, rate.1))
            }
        }
    }
}

fn set_headers(response: &mut Response, headers: &[(&'static str, String)]) {
    for (name, value) in headers {
        if let Ok(v) = HeaderValue::from_str(value) {
            response.headers_mut().insert(*name, v);
        }
    }
}

// ---- Middleware ----

/// The request's id: a client-supplied UUID is echoed, anything else is
/// replaced by a new UUIDv7.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestId(pub(crate) String);

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() == 36)
        .and_then(|v| uuid::Uuid::parse_str(v).ok())
        .unwrap_or_else(uuid::Uuid::now_v7)
        .hyphenated()
        .to_string()
}

/// Outermost layer: request id, `Timescales-Api-Version`, `no-store`
/// unless a handler chose a cache policy, and the body of every problem.
pub(crate) async fn frame(mut req: Request, next: Next) -> Response {
    let id = request_id(req.headers());
    req.extensions_mut().insert(RequestId(id.clone()));
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let span = tracing::info_span!("http.request", route = %route, request_id = %id);
    let mut response = next.run(req).instrument(span).await;
    finish(&mut response, &id);
    response
}

/// Writes a pending problem's body and the headers every response carries.
pub(crate) fn finish(response: &mut Response, id: &str) {
    if let Some(PendingProblem(mut problem)) = response.extensions_mut().remove::<PendingProblem>()
    {
        problem.request_id = id.to_owned();
        match serde_json::to_vec(&problem) {
            Ok(body) => {
                *response.body_mut() = Body::from(body);
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
                );
            }
            Err(e) => tracing::error!(error = %e, "problem did not serialize"),
        }
    }
    let headers = response.headers_mut();
    headers.insert(API_VERSION_HEADER, HeaderValue::from_static(API_VERSION));
    if let Ok(v) = HeaderValue::from_str(id) {
        headers.insert(REQUEST_ID_HEADER, v);
    }
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

/// Refuses work while draining (`DRAINING`), sheds load above
/// `max_concurrency` (`OVERLOADED`) and bounds each request by
/// `request_timeout_ms`.
pub(crate) async fn shed(State(ctx): State<Ctx>, req: Request, next: Next) -> Response {
    if is_probe(req.uri().path()) {
        return next.run(req).await;
    }
    if ctx.shutdown.is_cancelled() {
        return ApiError::new(
            ErrorCode::Draining,
            "the node is shutting down; retry shortly",
        )
        .into_response();
    }
    let Ok(_permit) = ctx.concurrency.clone().try_acquire_owned() else {
        return ApiError::new(ErrorCode::Overloaded, "too many concurrent requests")
            .with_retry_after_ms(1000)
            .into_response();
    };
    let timeout = Duration::from_millis(ctx.cfg.request_timeout_ms.max(1));
    match tokio::time::timeout(timeout, next.run(req)).await {
        Ok(response) => response,
        Err(_) => ApiError::new(ErrorCode::Overloaded, "request timed out")
            .with_retry_after_ms(1000)
            .into_response(),
    }
}

/// The per-IP GCRA limit, with its state in `RateLimit` headers.
pub(crate) async fn per_ip(State(ctx): State<Ctx>, req: Request, next: Next) -> Response {
    if is_probe(req.uri().path()) || req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    let key = request_ip_key(&ctx, req.headers(), peer_of(&req));
    match ctx.per_ip.take(&key) {
        Ok(headers) => {
            let mut response = next.run(req).await;
            // A narrower limit a handler applied (session, wallet) wins.
            if !response.headers().contains_key(RATE_LIMIT_HEADER) {
                set_headers(&mut response, &headers);
            }
            response
        }
        Err(e) => e.into_response(),
    }
}

/// Exact origins only, no credentials, the methods and headers the API
/// uses, and the response headers clients read.
pub(crate) fn cors(origins: &[String]) -> CorsLayer {
    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| match HeaderValue::from_str(o) {
            // Exact origins only: a wildcard is never honoured.
            Ok(v) if v != "*" => Some(v),
            _ => {
                tracing::error!(origin = %o, "ignoring a CORS origin that is not an exact origin");
                None
            }
        })
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .expose_headers([
            HeaderName::from_static(REQUEST_ID_HEADER),
            HeaderName::from_static(API_VERSION_HEADER),
            HeaderName::from_static(RATE_LIMIT_POLICY_HEADER),
            HeaderName::from_static(RATE_LIMIT_HEADER),
            header::RETRY_AFTER,
            header::ETAG,
        ])
        .max_age(Duration::from_secs(600))
}

/// Whether a request's `Origin` may open the stream: absent (not a
/// browser) or exactly one of the configured origins.
pub(crate) fn origin_allowed(headers: &HeaderMap, origins: &[String]) -> bool {
    match headers.get(header::ORIGIN) {
        None => true,
        Some(origin) => origins.iter().any(|o| o.as_bytes() == origin.as_bytes()),
    }
}

// ---- Bodies ----

/// Reads a body of at most `limit` bytes. `json` also requires
/// `Content-Type: application/json`.
pub(crate) async fn read_body(req: Request, limit: usize, json: bool) -> Result<Bytes, ApiError> {
    if json {
        let ok = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
        if !ok {
            return Err(ApiError::new(
                ErrorCode::UnsupportedMediaType,
                "expected application/json",
            ));
        }
    }
    let too_large = || {
        ApiError::new(
            ErrorCode::BodyTooLarge,
            format!("request bodies here are limited to {limit} bytes"),
        )
    };
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > limit as u64) {
        return Err(too_large());
    }
    axum::body::to_bytes(req.into_body(), limit)
        .await
        .map_err(|_| too_large())
}

/// Parses a JSON body. A refusal names the field serde complained about.
pub(crate) fn parse_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| {
        let message = e.to_string();
        let field = message
            .split('`')
            .nth(1)
            .filter(|f| !f.is_empty() && f.len() <= 64)
            .unwrap_or("body")
            .to_owned();
        ApiError::bad_request(&field, format!("invalid JSON body: {message}"))
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn ipv6_clients_share_their_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(IpKey::of(Some(a)), IpKey::of(Some(b)));
        assert_ne!(IpKey::of(Some(a)), IpKey::of(Some(c)));
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert_eq!(IpKey::of(Some(mapped)), IpKey::V4([10, 0, 0, 1]));
        assert_eq!(
            IpKey::of(Some(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            IpKey::V6Net([0; 8])
        );
    }

    #[test]
    fn forwarded_for_is_honoured_only_from_trusted_proxies() {
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 2.2.2.2, 10.1.1.1"),
        );
        let proxy: IpAddr = "10.0.0.5".parse().unwrap();
        let stranger: IpAddr = "3.3.3.3".parse().unwrap();
        assert_eq!(
            client_ip(Some(proxy), &headers, &trusted),
            Some("2.2.2.2".parse().unwrap())
        );
        assert_eq!(
            client_ip(Some(stranger), &headers, &trusted),
            Some(stranger)
        );
        headers.insert("x-forwarded-for", HeaderValue::from_static("nonsense"));
        assert_eq!(client_ip(Some(proxy), &headers, &trusted), Some(proxy));
        assert_eq!(client_ip(None, &headers, &trusted), None);
    }
}
