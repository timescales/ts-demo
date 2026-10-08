//! Sessions and the session-scoped parked routes (20,
//! 21), authenticated by `Authorization: TimescalesSession
//! <pk>.<ts>.<sig>`: the session key's signature over the
//! method, path, timestamp and body, within the skew, with the timestamp
//! strictly increasing per session.

use std::collections::HashMap;

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;
use timescales_core::OrderCommitment;
use timescales_service::api::{CreateSessionRequest, ErrorCode, Items, RetractRequest, Session};
use timescales_service::wire::{
    MAX_SESSION_TEXT_BYTES, SessionAuthorization, WireError, parse_session_message,
};

use super::Ctx;
use super::errors::ApiError;
use super::limits::{self, read_body};
use super::reads::{json, market_detail, parse_market};
use crate::SessionRef;

/// Sessions whose last request timestamp is remembered at once. Entries
/// older than the skew are dropped first. If the cache is still full new
/// sessions are refused (fail closed) until entries age out.
const REPLAY_CAPACITY: usize = 100_000;

/// The last accepted `ts` per session key.
#[derive(Debug, Default)]
pub(crate) struct ReplayCache(Mutex<HashMap<[u8; 32], u64>>);

impl ReplayCache {
    /// Records `ts` for `key` if it is newer than the last one.
    fn advance(&self, key: [u8; 32], ts: u64, now_ms: u64, skew_ms: u64) -> Result<(), ApiError> {
        let mut map = self.0.lock();
        if let Some(last) = map.get(&key) {
            if ts <= *last {
                return Err(ApiError::new(
                    ErrorCode::Skew,
                    "request timestamp is not after the session's previous request",
                ));
            }
        } else if map.len() >= REPLAY_CAPACITY {
            // Entries outside the skew window can no longer be replayed.
            map.retain(|_, last| now_ms.saturating_sub(*last) <= skew_ms);
            if map.len() >= REPLAY_CAPACITY {
                return Err(ApiError::new(
                    ErrorCode::Overloaded,
                    "too many active sessions; retry shortly",
                ));
            }
        }
        map.insert(key, ts);
        Ok(())
    }
}

/// The session behind an authenticated request.
pub(crate) struct Authed {
    pub(crate) session: Session,
    pub(crate) sref: SessionRef,
}

/// Looks a session key up and checks that it is live.
pub(crate) async fn live_session(ctx: &Ctx, key: [u8; 32]) -> Result<Authed, ApiError> {
    let session =
        ctx.node.session(key).await?.ok_or_else(|| {
            ApiError::new(ErrorCode::SessionUnknown, "no such session; create one")
        })?;
    if session.expires_at_ms <= ctx.now_ms() {
        return Err(ApiError::new(
            ErrorCode::SessionExpired,
            "the session expired; create a new one",
        ));
    }
    let sref = SessionRef {
        session_key: key,
        wallet: session.wallet.0,
        market: session.market.map(|m| m.0),
    };
    Ok(Authed { session, sref })
}

/// Verifies a session-scoped request: header, signature over the exact
/// request, skew, replay, the per-session rate limit and the session.
async fn authenticate(
    ctx: &Ctx,
    method: &Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(Authed, [(&'static str, String); 2]), ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::SessionUnknown,
                "a TimescalesSession authorization is required",
            )
        })?
        .to_str()
        .map_err(|_| ApiError::bad_request("authorization", "authorization is not ASCII"))?;
    let auth = SessionAuthorization::parse(value).map_err(|_| {
        ApiError::bad_request("authorization", "not a TimescalesSession authorization")
    })?;
    let now = ctx.now_ms();
    auth.verify(
        method.as_str(),
        path_and_query,
        body,
        now,
        ctx.session_skew_ms,
    )
    .map_err(|e| match e {
        WireError::Skew { .. } => ApiError::new(
            ErrorCode::Skew,
            "request timestamp outside the allowed skew; resynchronise the clock",
        ),
        _ => ApiError::new(
            ErrorCode::BadSignature,
            "the session signature does not verify",
        ),
    })?;
    ctx.replay
        .advance(auth.session_key, auth.ts_ms, now, ctx.session_skew_ms)?;
    let rate = ctx.per_session.take(&auth.session_key)?;
    Ok((live_session(ctx, auth.session_key).await?, rate))
}

fn with_rate(mut response: Response, rate: &[(&'static str, String); 2]) -> Response {
    for (name, value) in rate {
        if let Ok(v) = axum::http::HeaderValue::from_str(value) {
            response.headers_mut().insert(*name, v);
        }
    }
    response
}

/// Reads the body and authenticates the request it belongs to.
async fn authed_request(
    ctx: &Ctx,
    req: Request,
    json_body: bool,
) -> Result<(Authed, [(&'static str, String); 2], axum::body::Bytes), ApiError> {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or_else(|| req.uri().path().to_owned(), |p| p.as_str().to_owned());
    let headers = req.headers().clone();
    let limit = usize::try_from(ctx.cfg.max_body_bytes).unwrap_or(usize::MAX);
    let body = read_body(req, limit, json_body).await?;
    let (authed, rate) = authenticate(ctx, &method, &path_and_query, &headers, &body).await?;
    Ok((authed, rate, body))
}

/// A session bound to one market works only there.
fn check_market(authed: &Authed, m: [u8; 32]) -> Result<(), ApiError> {
    match authed.sref.market {
        Some(bound) if bound != m => Err(ApiError::new(
            ErrorCode::SessionUnknown,
            "the session is bound to another market",
        )
        .with_market(m)),
        _ => Ok(()),
    }
}

// ---- Routes ----

pub(crate) async fn nonce(State(ctx): State<Ctx>) -> Result<Response, ApiError> {
    Ok(json(StatusCode::OK, &ctx.node.session_nonce().await?))
}

/// `201` with a new session, `200` with the existing one for a grant the
/// node already accepted.
pub(crate) async fn create(State(ctx): State<Ctx>, req: Request) -> Result<Response, ApiError> {
    let limit = usize::try_from(ctx.cfg.max_body_bytes).unwrap_or(usize::MAX);
    let body = read_body(req, limit, true).await?;
    let request: CreateSessionRequest = limits::parse_json(&body)?;
    if request.message.len() > MAX_SESSION_TEXT_BYTES {
        return Err(ApiError::new(
            ErrorCode::SessionTemplateInvalid,
            format!("the grant text exceeds {MAX_SESSION_TEXT_BYTES} bytes"),
        ));
    }
    if request.signature_b64.0.len() != 64 {
        return Err(ApiError::bad_request(
            "signature_b64",
            "a signature is 64 bytes",
        ));
    }
    // Which key the grant authorises, to tell a repeated grant from a new
    // one. The node does every check of the grant itself.
    let existing = match parse_session_message(&request.message) {
        Ok(grant) if grant.wallet == request.wallet.0 => ctx
            .node
            .session(grant.session_key)
            .await?
            .filter(|s| s.wallet == request.wallet),
        _ => None,
    };
    let min_context_slot = request.min_context_slot.map(|s| s.0);
    let session = ctx.node.create_session(request, min_context_slot).await?;
    let status = if existing.is_some_and(|e| e.session_key == session.session_key) {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok(json(status, &session))
}

pub(crate) async fn current(State(ctx): State<Ctx>, req: Request) -> Result<Response, ApiError> {
    let (authed, rate, _) = authed_request(&ctx, req, false).await?;
    Ok(with_rate(json(StatusCode::OK, &authed.session), &rate))
}

pub(crate) async fn revoke(State(ctx): State<Ctx>, req: Request) -> Result<Response, ApiError> {
    let (authed, rate, _) = authed_request(&ctx, req, false).await?;
    ctx.node.revoke_session(authed.sref.session_key).await?;
    Ok(with_rate(StatusCode::NO_CONTENT.into_response(), &rate))
}

/// This session's wallet's parked envelopes, and nobody else's.
pub(crate) async fn parked(
    State(ctx): State<Ctx>,
    Path(market): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let (authed, rate, _) = authed_request(&ctx, req, false).await?;
    market_detail(&ctx, m)?;
    check_market(&authed, m)?;
    let items = ctx.node.parked(m, authed.sref).await?;
    Ok(with_rate(json(StatusCode::OK, &Items { items }), &rate))
}

/// Operator-trusted removal of queued envelopes after the open epoch.
pub(crate) async fn retract(
    State(ctx): State<Ctx>,
    Path(market): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let (authed, rate, body) = authed_request(&ctx, req, true).await?;
    market_detail(&ctx, m)?;
    check_market(&authed, m)?;
    let request: RetractRequest = limits::parse_json(&body)?;
    let result = ctx
        .node
        .retract_parked(m, authed.sref, OrderCommitment(request.commitment.0))
        .await?;
    Ok(with_rate(json(StatusCode::OK, &result), &rate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_must_increase_per_session() {
        let cache = ReplayCache::default();
        cache.advance([1; 32], 10, 10, 30_000).unwrap();
        assert_eq!(
            cache.advance([1; 32], 10, 10, 30_000).unwrap_err().code,
            ErrorCode::Skew
        );
        cache.advance([1; 32], 11, 11, 30_000).unwrap();
        cache.advance([2; 32], 5, 11, 30_000).unwrap();
    }
}
