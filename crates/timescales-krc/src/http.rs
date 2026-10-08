//! The member's HTTP API, `/krc/v1/*`.
//!
//! Every POST carries a [`SignedEnvelope`](timescales_service::wire::SignedEnvelope)
//! whose 94-byte prefix (version, kind, audience, length and sender) is
//! checked before the body is read ([`VerifiedEnvelope`]): only configured
//! dealers may send share deliveries and announcement queries. Challenges
//! and releases may come from any key, because executors are authorized by
//! their on-chain registration (d), after the per-caller rate limit.
//! Answers are envelopes signed by the member's identity. Release refusals
//! are `200` with tag 1, so they are signed too. A refused challenge
//! carries the same refusal body under an error status.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, FromRef, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use timescales_core::{Decode, Encode, ExecutorId};
use timescales_executor::attestation::Platform;
use timescales_executor::tee::KeyReleaseRequest;
use timescales_service::wire::{
    AnnouncementQuery, AnnouncementReply, ChallengeRequest, MessageKind, ReleaseRefusal,
    ReleaseResponse, ReplayGuard, ShareDelivery,
};
use timescales_service::{
    EnvelopeAuth, HttpLimits, VerifiedEnvelope, sealed_response, sealed_response_with_status,
};
use tokio::sync::Semaphore;

use crate::KrcError;
use crate::config::parse_b58_32;
use crate::member::{Member, ShareRefusal};
use crate::{b58, now_ms};

/// Envelopes remembered against replay (100k entries).
const REPLAY_CAPACITY: usize = 100_000;

#[derive(Clone)]
struct AppState {
    member: Arc<Member>,
    auth: EnvelopeAuth,
    limits: HttpLimits,
    permits: Arc<Semaphore>,
}

impl FromRef<AppState> for EnvelopeAuth {
    fn from_ref(s: &AppState) -> Self {
        s.auth.clone()
    }
}

pub(crate) fn router(member: Arc<Member>, limits: HttpLimits) -> Router {
    let dealers = Arc::clone(&member);
    let allowed = move |sender: &[u8; 32], kind: MessageKind| match kind {
        MessageKind::ShareDelivery | MessageKind::AnnouncementQuery => dealers.is_dealer(sender),
        MessageKind::ChallengeRequest | MessageKind::ReleaseRequest => true,
        _ => false,
    };
    let auth = EnvelopeAuth {
        me: member.identity().public(),
        allowed: Arc::new(allowed),
        replay: Arc::new(ReplayGuard::new(REPLAY_CAPACITY, 2 * member.skew_ms())),
        skew_ms: member.skew_ms(),
        now_ms: Arc::new(now_ms),
    };
    let state = AppState {
        member,
        auth,
        limits,
        permits: Arc::new(Semaphore::new(limits.max_concurrency.max(1))),
    };
    Router::new()
        .route("/krc/v1/shares", post(shares))
        .route("/krc/v1/announcements", post(announcements))
        .route("/krc/v1/policy", get(policy))
        .route("/krc/v1/challenge", post(challenge))
        .route("/krc/v1/release", post(release))
        .route("/krc/v1/identity", get(identity))
        .layer(DefaultBodyLimit::max(limits.max_body_bytes))
        .with_state(state)
}

fn status(code: StatusCode, message: &'static str) -> Response {
    (code, message).into_response()
}

/// Runs `f` within the concurrency and time limits. `None` when either
/// was hit.
async fn bounded<T>(s: &AppState, f: impl Future<Output = T>) -> Option<T> {
    let _permit = s.permits.try_acquire().ok()?;
    tokio::time::timeout(s.limits.request_timeout, f).await.ok()
}

fn busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "1")],
        "busy",
    )
        .into_response()
}

fn sealed(s: &AppState, kind: MessageKind, to: [u8; 32], body: Vec<u8>) -> Response {
    sealed_response(kind, s.member.identity(), to, now_ms(), body)
}

async fn shares(State(s): State<AppState>, env: VerifiedEnvelope) -> Response {
    if env.kind != MessageKind::ShareDelivery {
        return status(StatusCode::BAD_REQUEST, "expected a ShareDelivery envelope");
    }
    let Ok(d) = ShareDelivery::decode_exact(&env.body) else {
        return status(StatusCode::BAD_REQUEST, "malformed share delivery");
    };
    let (m, e) = (d.announcement.market, d.announcement.epoch);
    let Some(result) = bounded(&s, s.member.accept_share(env.sender, d)).await else {
        return busy();
    };
    match result {
        Ok(ack) => sealed(&s, MessageKind::EpochKeyAck, env.sender, ack.to_bytes()),
        Err(ShareRefusal::SecondAnnouncement { stored }) => {
            // The stored announcement with this member's ack: the digest,
            // and evidence of what the member vouched for.
            match s.member.announcement(m, e).await {
                Ok(Some(held)) if held.0.digest() == stored => sealed_response_with_status(
                    StatusCode::CONFLICT,
                    MessageKind::AnnouncementReply,
                    s.member.identity(),
                    env.sender,
                    now_ms(),
                    AnnouncementReply(Some(held)).to_bytes(),
                ),
                _ => (StatusCode::CONFLICT, stored.to_hex()).into_response(),
            }
        }
        Err(ShareRefusal::Unauthenticated) => status(StatusCode::FORBIDDEN, "not a dealer"),
        Err(ShareRefusal::UnknownMarket) => status(StatusCode::NOT_FOUND, "market not served"),
        Err(ShareRefusal::CommitteeMismatch) => status(
            StatusCode::PRECONDITION_FAILED,
            "committee digest does not match chain state",
        ),
        Err(ShareRefusal::TooLate) => status(StatusCode::GONE, "epoch already committed"),
        Err(ShareRefusal::BadShare) => status(
            StatusCode::UNPROCESSABLE_ENTITY,
            "share does not verify against the announcement",
        ),
        Err(ShareRefusal::Internal(e)) => {
            tracing::warn!(error = %e, "share delivery not processed");
            busy()
        }
    }
}

async fn announcements(State(s): State<AppState>, env: VerifiedEnvelope) -> Response {
    if env.kind != MessageKind::AnnouncementQuery {
        return status(
            StatusCode::BAD_REQUEST,
            "expected an AnnouncementQuery envelope",
        );
    }
    let Ok(q) = AnnouncementQuery::decode_exact(&env.body) else {
        return status(StatusCode::BAD_REQUEST, "malformed announcement query");
    };
    match s.member.announcement(q.market, q.epoch).await {
        Ok(held) => sealed(
            &s,
            MessageKind::AnnouncementReply,
            env.sender,
            AnnouncementReply(held).to_bytes(),
        ),
        Err(KrcError::UnknownMarket(_)) => status(StatusCode::NOT_FOUND, "market not served"),
        Err(e) => {
            tracing::warn!(error = %e, "announcement query not answered");
            busy()
        }
    }
}

#[derive(Debug, Deserialize)]
struct PolicyQuery {
    market: Option<String>,
}

/// The signed statement for `?market=<b58>`, or for the first configured
/// market without the parameter.
async fn policy(State(s): State<AppState>, Query(q): Query<PolicyQuery>) -> Response {
    let statement = match q.market.as_deref() {
        None => Some(s.member.policy()),
        Some(m) => parse_b58_32(m).and_then(|m| s.member.policy_for(&m)),
    };
    match statement {
        Some(st) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            st.to_bytes(),
        )
            .into_response(),
        None => status(StatusCode::NOT_FOUND, "market not served"),
    }
}

/// HTTP status of a refused challenge.
fn refusal_status(code: ReleaseRefusal) -> StatusCode {
    match code {
        ReleaseRefusal::Unauthenticated | ReleaseRefusal::NotRegistered => StatusCode::FORBIDDEN,
        ReleaseRefusal::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ReleaseRefusal::BadRequest => StatusCode::BAD_REQUEST,
        ReleaseRefusal::NoShare => StatusCode::NOT_FOUND,
        ReleaseRefusal::Unavailable | ReleaseRefusal::NotFinal => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::CONFLICT,
    }
}

fn refused(code: ReleaseRefusal) -> Vec<u8> {
    ReleaseResponse::refused(code, &format!("{code:?}")).to_bytes()
}

async fn challenge(State(s): State<AppState>, env: VerifiedEnvelope) -> Response {
    if env.kind != MessageKind::ChallengeRequest {
        return status(
            StatusCode::BAD_REQUEST,
            "expected a ChallengeRequest envelope",
        );
    }
    let result = match ChallengeRequest::decode_exact(&env.body) {
        Ok(r) => {
            let Some(result) = bounded(&s, s.member.challenge(ExecutorId(env.sender), r)).await
            else {
                return busy();
            };
            result
        }
        Err(_) => Err(ReleaseRefusal::BadRequest),
    };
    match result {
        Ok(c) => sealed(&s, MessageKind::ChallengeResponse, env.sender, c.to_bytes()),
        Err(code) => sealed_response_with_status(
            refusal_status(code),
            MessageKind::ReleaseResponse,
            s.member.identity(),
            env.sender,
            now_ms(),
            refused(code),
        ),
    }
}

async fn release(State(s): State<AppState>, env: VerifiedEnvelope) -> Response {
    if env.kind != MessageKind::ReleaseRequest {
        return status(
            StatusCode::BAD_REQUEST,
            "expected a ReleaseRequest envelope",
        );
    }
    let response = match KeyReleaseRequest::decode_exact(&env.body) {
        Ok(r) => {
            let Some(result) = bounded(&s, s.member.release(ExecutorId(env.sender), r)).await
            else {
                return busy();
            };
            match result {
                Ok(share) => ReleaseResponse::Share(share).to_bytes(),
                Err(code) => refused(code),
            }
        }
        Err(_) => refused(ReleaseRefusal::BadRequest),
    };
    sealed(&s, MessageKind::ReleaseResponse, env.sender, response)
}

#[derive(Debug, Serialize)]
struct Identity {
    index: u8,
    identity: String,
    transport: String,
    platforms: Vec<&'static str>,
    measurements: Vec<String>,
    committee_digests: BTreeMap<String, String>,
    version: &'static str,
}

async fn identity(State(s): State<AppState>) -> Response {
    let m = &s.member;
    let policy = m.attestation_policy();
    let body = Identity {
        index: m.index(),
        identity: hex::encode(m.identity().public()),
        transport: hex::encode(m.transport_public()),
        platforms: policy
            .platforms
            .iter()
            .filter_map(|p| match p {
                Platform::Simulated => Some("simulated"),
                Platform::IntelTdx => Some("intel_tdx"),
                _ => None,
            })
            .collect(),
        measurements: policy.measurements.iter().map(|x| x.0.to_hex()).collect(),
        committee_digests: m
            .committee_digests()
            .map(|(market, digest)| (b58(market), digest.to_hex()))
            .collect(),
        version: env!("CARGO_PKG_VERSION"),
    };
    axum::Json(body).into_response()
}
