//! `/enclave/v1/*`.
//!
//! `execute` and `publish` take a [`SignedEnvelope`] from one of the
//! configured node keys, checked prefix first ([`VerifiedEnvelope`]), and
//! answer in an envelope signed by the executor key through the typed
//! signer: the result, or an `ErrorResponse` under an error status.
//! `identity` is plain JSON for anyone, limited per client address.
//!
//! [`SignedEnvelope`]: timescales_service::wire::SignedEnvelope

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRef, Query, State};
use axum::http::{Extensions, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use timescales_auction::receipts::ExecutionReceipt;
use timescales_core::{Decode, Encode};
use timescales_executor::attestation::Platform;
use timescales_service::wire::{
    EnclaveRefusal, ErrorResponse, ExecuteRequest, MessageKind, PublishRequest, ReplayGuard,
};
use timescales_service::{
    EnvelopeAuth, HttpLimits, VerifiedEnvelope, sealed_response, sealed_response_with_status,
};
use tokio::sync::Semaphore;

use crate::config::{parse_b58_32, parse_hex32};
use crate::{EnclaveError, EnclaveService, now_ms};

/// Envelopes remembered against replay (100k entries).
const REPLAY_CAPACITY: usize = 100_000;
/// Accepted clock skew of request envelopes (+/-30 s).
const SKEW_MS: u64 = 30_000;
/// Client addresses tracked by the identity limiter at most.
const MAX_TRACKED_CLIENTS: usize = 4096;

/// Per-address GCRA with a bounded table: addresses whose bucket is full
/// again are dropped when the table fills up. If it is still full, an
/// unknown address is refused until room frees up.
#[derive(Debug)]
pub(crate) struct IpLimiter {
    emission: Duration,
    tolerance: Duration,
    tat: Mutex<HashMap<IpAddr, Instant>>,
}

impl IpLimiter {
    pub(crate) fn new(rps: u32, burst: u32) -> Self {
        let emission = Duration::from_secs(1) / rps.max(1);
        Self {
            emission,
            tolerance: emission * burst.max(1).saturating_sub(1),
            tat: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut tat = self.tat.lock();
        if !tat.contains_key(&ip) && tat.len() >= MAX_TRACKED_CLIENTS {
            tat.retain(|_, t| *t > now);
            if tat.len() >= MAX_TRACKED_CLIENTS {
                return false;
            }
        }
        let current = tat.get(&ip).copied().unwrap_or(now).max(now);
        if current.duration_since(now) > self.tolerance {
            return false;
        }
        tat.insert(ip, current + self.emission);
        true
    }
}

#[derive(Clone)]
struct AppState {
    svc: Arc<EnclaveService>,
    auth: EnvelopeAuth,
    limiter: Arc<IpLimiter>,
    permits: Arc<Semaphore>,
    limits: HttpLimits,
}

impl FromRef<AppState> for EnvelopeAuth {
    fn from_ref(s: &AppState) -> Self {
        s.auth.clone()
    }
}

/// `/enclave/v1/*`. Serve it with
/// `into_make_service_with_connect_info::<SocketAddr>` so the identity
/// route can limit per client address. Without it every client shares one
/// bucket.
pub fn router(svc: Arc<EnclaveService>, limits: HttpLimits) -> Router {
    let nodes = Arc::clone(&svc);
    let allowed = move |sender: &[u8; 32], kind: MessageKind| {
        matches!(
            kind,
            MessageKind::ExecuteRequest | MessageKind::PublishRequest
        ) && nodes.is_node(sender)
    };
    let auth = EnvelopeAuth {
        me: svc.executor().0,
        allowed: Arc::new(allowed),
        replay: Arc::new(ReplayGuard::new(REPLAY_CAPACITY, 2 * SKEW_MS)),
        skew_ms: SKEW_MS,
        now_ms: Arc::new(now_ms),
    };
    let state = AppState {
        svc,
        auth,
        limiter: Arc::new(IpLimiter::new(
            limits.per_caller_rps,
            limits.per_caller_burst,
        )),
        permits: Arc::new(Semaphore::new(limits.max_concurrency.max(1))),
        limits,
    };
    Router::new()
        .route("/enclave/v1/execute", post(execute))
        .route("/enclave/v1/publish", post(publish))
        .route("/enclave/v1/identity", get(identity))
        .layer(DefaultBodyLimit::max(limits.max_body_bytes))
        .with_state(state)
}

fn busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "1")],
        "busy",
    )
        .into_response()
}

/// The HTTP status and `ErrorResponse` of a refusal.
fn refusal(e: &EnclaveError) -> (StatusCode, ErrorResponse) {
    use EnclaveRefusal as R;
    let (status, code, detail) = match e {
        EnclaveError::BindingMismatch => (StatusCode::CONFLICT, R::BindingMismatch, e.to_string()),
        EnclaveError::BalanceMismatch { traders } => (
            StatusCode::CONFLICT,
            R::BalanceMismatch,
            format!("{traders} trader(s)"),
        ),
        EnclaveError::KeyUnavailable(d) => (
            StatusCode::SERVICE_UNAVAILABLE,
            R::KeyUnavailable,
            d.clone(),
        ),
        EnclaveError::BadRequest(d) => (StatusCode::BAD_REQUEST, R::BadRequest, d.clone()),
        EnclaveError::PostFailed(d) => (StatusCode::SERVICE_UNAVAILABLE, R::PostFailed, d.clone()),
        EnclaveError::OutcomeMismatch { receipt } => {
            return match ExecutionReceipt::decode_exact(receipt) {
                Ok(r) => (
                    StatusCode::CONFLICT,
                    ErrorResponse::outcome_mismatch(r, "another outcome was posted"),
                ),
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::refused(R::PostFailed, "receipt does not encode"),
                ),
            };
        }
        EnclaveError::QuorumInvalid => (
            StatusCode::UNPROCESSABLE_ENTITY,
            R::QuorumInvalid,
            e.to_string(),
        ),
        EnclaveError::QuorumPending => (StatusCode::CONFLICT, R::QuorumPending, e.to_string()),
        EnclaveError::NotExecuted => (StatusCode::NOT_FOUND, R::NotExecuted, e.to_string()),
        EnclaveError::Busy
        | EnclaveError::Chain(_)
        | EnclaveError::Config(_)
        | EnclaveError::Quote(_) => (StatusCode::SERVICE_UNAVAILABLE, R::Busy, e.to_string()),
    };
    (status, ErrorResponse::refused(code, &detail))
}

fn sealed(s: &AppState, kind: MessageKind, to: [u8; 32], body: Vec<u8>) -> Response {
    sealed_response(kind, &*s.svc.envelope_signer(), to, now_ms(), body)
}

fn refused(s: &AppState, to: [u8; 32], e: &EnclaveError) -> Response {
    let (status, body) = refusal(e);
    sealed_response_with_status(
        status,
        MessageKind::ErrorResponse,
        &*s.svc.envelope_signer(),
        to,
        now_ms(),
        body.to_bytes(),
    )
}

async fn execute(State(s): State<AppState>, env: VerifiedEnvelope) -> Response {
    if env.kind != MessageKind::ExecuteRequest {
        return (
            StatusCode::BAD_REQUEST,
            "expected an ExecuteRequest envelope",
        )
            .into_response();
    }
    let Ok(_permit) = s.permits.try_acquire() else {
        return busy();
    };
    let req = match ExecuteRequest::decode_exact(&env.body) {
        Ok(r) => r,
        Err(e) => {
            return refused(
                &s,
                env.sender,
                &EnclaveError::BadRequest(format!("decode: {e}")),
            );
        }
    };
    match s.svc.execute(Arc::new(req)).await {
        Ok(ready) => sealed(&s, MessageKind::ExecuteReady, env.sender, ready.to_bytes()),
        Err(e) => {
            tracing::info!(error = %e, "execute refused");
            refused(&s, env.sender, &e)
        }
    }
}

async fn publish(State(s): State<AppState>, env: VerifiedEnvelope) -> Response {
    if env.kind != MessageKind::PublishRequest {
        return (
            StatusCode::BAD_REQUEST,
            "expected a PublishRequest envelope",
        )
            .into_response();
    }
    let Ok(_permit) = s.permits.try_acquire() else {
        return busy();
    };
    let req = match PublishRequest::decode_exact(&env.body) {
        Ok(r) => r,
        Err(e) => {
            return refused(
                &s,
                env.sender,
                &EnclaveError::BadRequest(format!("decode: {e}")),
            );
        }
    };
    match s.svc.publish(req).await {
        Ok(posted) => sealed(
            &s,
            MessageKind::ExecutePosted,
            env.sender,
            posted.to_bytes(),
        ),
        Err(e) => {
            tracing::info!(error = %e, "publish refused");
            refused(&s, env.sender, &e)
        }
    }
}

#[derive(Debug, Deserialize)]
struct IdentityQuery {
    market: String,
    nonce: String,
}

/// The registration identity (the `ExecutorRegistration` encodings).
#[derive(Debug, Serialize)]
struct IdentityJson {
    market: String,
    nonce: String,
    executor: String,
    seal_key: String,
    platform: &'static str,
    measurement: String,
    fee_payer: String,
    evidence_b64: String,
}

fn platform_name(p: Platform) -> &'static str {
    match p {
        Platform::IntelTdx => "intel_tdx",
        Platform::Simulated => "simulated",
        Platform::AmdSevSnp => "amd_sev_snp",
        Platform::AwsNitro => "aws_nitro",
    }
}

async fn identity(
    State(s): State<AppState>,
    extensions: Extensions,
    Query(q): Query<IdentityQuery>,
) -> Response {
    let ip = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::from([0, 0, 0, 0]), |c| c.0.ip());
    if !s.limiter.check_at(ip, Instant::now()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1")],
            "rate limited",
        )
            .into_response();
    }
    let (Some(market), Some(nonce)) = (parse_b58_32(&q.market), parse_hex32(&q.nonce)) else {
        return (
            StatusCode::BAD_REQUEST,
            "market must be base58 and nonce 64 hex digits",
        )
            .into_response();
    };
    let Ok(_permit) = s.permits.try_acquire() else {
        return busy();
    };
    match tokio::time::timeout(s.limits.request_timeout, s.svc.identity(market, nonce)).await {
        Err(_) => busy(),
        Ok(Ok(id)) => axum::Json(IdentityJson {
            market: q.market,
            nonce: hex::encode(nonce),
            executor: bs58::encode(id.executor.0).into_string(),
            seal_key: hex::encode(id.seal_key),
            platform: platform_name(id.platform),
            measurement: id.measurement.to_hex(),
            fee_payer: bs58::encode(id.fee_payer).into_string(),
            evidence_b64: base64::engine::general_purpose::STANDARD.encode(id.evidence.to_bytes()),
        })
        .into_response(),
        Ok(Err(EnclaveError::BadRequest(d))) => (StatusCode::NOT_FOUND, d).into_response(),
        Ok(Err(EnclaveError::Busy)) => busy(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "identity quote failed");
            (StatusCode::SERVICE_UNAVAILABLE, "no quote").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_limiter_is_per_address_and_bounded() {
        let l = IpLimiter::new(10, 2);
        let t0 = Instant::now();
        let a = IpAddr::from([10, 0, 0, 1]);
        assert!(l.check_at(a, t0));
        assert!(l.check_at(a, t0));
        assert!(!l.check_at(a, t0));
        assert!(l.check_at(IpAddr::from([10, 0, 0, 2]), t0));
        assert!(l.check_at(a, t0 + Duration::from_millis(101)));
        for i in 0..MAX_TRACKED_CLIENTS {
            let ip = IpAddr::from(u32::try_from(i).unwrap().to_be_bytes());
            let _ = l.check_at(ip, t0);
        }
        assert!(l.tat.lock().len() <= MAX_TRACKED_CLIENTS);
    }

    #[test]
    fn every_refusal_has_its_code() {
        let receipt_free = [
            (
                EnclaveError::BindingMismatch,
                EnclaveRefusal::BindingMismatch,
            ),
            (
                EnclaveError::BalanceMismatch { traders: 2 },
                EnclaveRefusal::BalanceMismatch,
            ),
            (
                EnclaveError::KeyUnavailable("x".into()),
                EnclaveRefusal::KeyUnavailable,
            ),
            (
                EnclaveError::BadRequest("x".into()),
                EnclaveRefusal::BadRequest,
            ),
            (EnclaveError::Busy, EnclaveRefusal::Busy),
            (
                EnclaveError::PostFailed("x".into()),
                EnclaveRefusal::PostFailed,
            ),
            (EnclaveError::QuorumInvalid, EnclaveRefusal::QuorumInvalid),
            (EnclaveError::QuorumPending, EnclaveRefusal::QuorumPending),
            (EnclaveError::NotExecuted, EnclaveRefusal::NotExecuted),
        ];
        for (e, code) in receipt_free {
            let (status, body) = refusal(&e);
            assert!(!status.is_success());
            assert_eq!(body.code, code);
            assert!(body.receipt.is_none());
            // Decodes as the node reads it.
            assert_eq!(ErrorResponse::decode_exact(&body.to_bytes()).unwrap(), body);
        }
        let (_, body) = refusal(&EnclaveError::BalanceMismatch { traders: 3 });
        assert_eq!(body.detail, "3 trader(s)");
    }
}
