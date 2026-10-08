//! Submissions. The HTTP layer decodes each
//! `Submission` exactly, refuses masked encodings, other versions and other
//! markets, finds the live session whose key signed it, applies the
//! per-wallet rate limit and verifies the signature. The node does the rest
//! (epoch, eligibility, quotas, capacity, dedup and the promise).

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Map, Value};
use timescales_auction::AuctionError;
use timescales_core::{Decode, MarketParams, PROTOCOL_VERSION};
use timescales_service::api::{
    B64, ErrorCode, Items, ProblemDetails, SubmitBatchRequest, SubmitItemError, SubmitItemResult,
    SubmitRequest,
};
use timescales_service::relay::{Padding, RelayConfig, RelayError, Submission};

use super::Ctx;
use super::errors::ApiError;
use super::limits::{self, RequestId, read_body};
use super::reads::{json, market_detail, market_params, parse_market};
use super::sessions::live_session;
use crate::{SessionRef, SubmitError, VerifiedSubmission};

/// `SealedEnvelope`: 289 bytes.
const ENVELOPE_LEN: usize = 289;

fn decode_failed(e: &timescales_core::DecodeError) -> ApiError {
    ApiError::from_details(ProblemDetails::from(e), format!("submission: {e}"))
}

/// Decodes one submission and checks what needs no key: no masked
/// encoding, envelope version 1, this market.
fn decode(bytes: &[u8], market_id: u64) -> Result<Submission, ApiError> {
    if bytes.get(ENVELOPE_LEN) == Some(&1) {
        return Err(ApiError::new(
            ErrorCode::MaskedNotSupported,
            "this node has no MPC path; submit without a masked encoding",
        ));
    }
    let s = Submission::decode_exact(bytes).map_err(|e| decode_failed(&e))?;
    if s.masked.is_some() {
        return Err(ApiError::new(
            ErrorCode::MaskedNotSupported,
            "masked encodings are refused",
        ));
    }
    if s.envelope.version != PROTOCOL_VERSION {
        return Err(ApiError::new(
            ErrorCode::VersionUnsupported,
            format!("envelope version {} is not supported", s.envelope.version),
        ));
    }
    if s.envelope.market.0 != market_id {
        return Err(ApiError::new(
            ErrorCode::WrongMarket,
            "the envelope is for another market",
        ));
    }
    Ok(s)
}

fn relay_config(params: MarketParams, market: [u8; 32]) -> RelayConfig {
    RelayConfig {
        params,
        market_address: market,
        // Only the stateless checks of `verify_submission` read this config.
        padding: Padding::None,
        allow_masked: false,
        max_real: 0,
        carry_p: 0.0,
    }
}

/// The session key's signature (strictly) and the stateless relay checks.
fn verify(cfg: &RelayConfig, raw: Vec<u8>, s: &Submission) -> Result<VerifiedSubmission, ApiError> {
    let inner = timescales_service::relay::verify_submission(cfg, s).map_err(|e| match e {
        RelayError::BadSignature => ApiError::new(
            ErrorCode::BadSignature,
            "the submission signature does not verify",
        ),
        RelayError::MaskedNotAllowed => ApiError::new(
            ErrorCode::MaskedNotSupported,
            "masked encodings are refused",
        ),
        RelayError::UnsupportedVersion(v) => ApiError::new(
            ErrorCode::VersionUnsupported,
            format!("envelope version {v} is not supported"),
        ),
        RelayError::Auction(AuctionError::WrongMarket { .. }) => {
            ApiError::new(ErrorCode::WrongMarket, "the envelope is for another market")
        }
        other => ApiError::new(ErrorCode::BadRequest, other.to_string()),
    })?;
    Ok(VerifiedSubmission { raw, inner })
}

/// The problem of a submission the node refused. The relay-signed refusal
/// travels in `details.refusal_b64`.
fn refused(e: &SubmitError, market: [u8; 32], epoch: u64) -> ApiError {
    let mut details = match &e.details {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    };
    if let Some(refusal) = &e.refusal
        && e.code.refusal_code().is_some()
        && !details.contains_key("refusal_b64")
    {
        details.insert(
            "refusal_b64".to_owned(),
            Value::String(B64(refusal.clone()).to_string()),
        );
    }
    let mut err = ApiError::new(e.code, e.code.title().to_owned())
        .with_market(market)
        .with_epoch(epoch);
    if !details.is_empty() {
        err.details = Some(Value::Object(details));
    }
    err.retry_after_ms = e.retry_after_ms;
    err
}

fn with_rate(mut response: Response, rate: &[(&'static str, String); 2]) -> Response {
    for (name, value) in rate {
        if let Ok(v) = axum::http::HeaderValue::from_str(value) {
            response.headers_mut().insert(*name, v);
        }
    }
    response
}

/// `202` with the promise, or the problem.
pub(crate) async fn one(
    State(ctx): State<Ctx>,
    Path(market): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let detail = market_detail(&ctx, m)?;
    let params = market_params(&detail)?;
    let limit = usize::try_from(ctx.cfg.submit_max_body_bytes).unwrap_or(usize::MAX);
    let body = read_body(req, limit, true).await?;
    let request: SubmitRequest = limits::parse_json(&body)?;
    let raw = request.submission_b64.0;
    let s = decode(&raw, params.market.0).map_err(|e| e.with_market(m))?;
    let epoch = s.envelope.epoch.0;
    let authed = live_session(&ctx, s.trader.0)
        .await
        .map_err(|e| e.with_market(m).with_epoch(epoch))?;
    if authed.sref.market.is_some_and(|b| b != m) {
        return Err(ApiError::new(
            ErrorCode::SessionUnknown,
            "the session is bound to another market",
        )
        .with_market(m));
    }
    let rate = ctx.per_wallet.take(&authed.sref.wallet)?;
    let vs = verify(&relay_config(params, m), raw, &s)
        .map_err(|e| e.with_market(m).with_epoch(epoch))?;
    let mut results = ctx.node.submit(m, vec![vs], authed.sref).await;
    match results.pop() {
        Some(Ok(result)) => Ok(with_rate(json(StatusCode::ACCEPTED, &result), &rate)),
        Some(Err(e)) => Err(refused(&e, m, epoch)),
        None => Err(ApiError::internal(
            "the node answered no result for a submission",
        )),
    }
}

/// One item of a batch, until the node has answered it.
enum Item {
    Failed(ApiError),
    Pending { s: Box<Submission>, raw: Vec<u8> },
}

/// `207` with one result per submission, in request order.
pub(crate) async fn batch(
    State(ctx): State<Ctx>,
    Path(market): Path<String>,
    req: Request,
) -> Result<Response, ApiError> {
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();
    let m = parse_market(&market)?;
    let detail = market_detail(&ctx, m)?;
    let params = market_params(&detail)?;
    let max_items = usize::try_from(detail.timing.max_park_ahead_epochs)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    let limit = usize::try_from(ctx.cfg.submit_max_body_bytes)
        .unwrap_or(usize::MAX)
        .saturating_mul(max_items);
    let body = read_body(req, limit, true).await?;
    let request: SubmitBatchRequest = limits::parse_json(&body)?;
    if request.submissions_b64.is_empty() || request.submissions_b64.len() > max_items {
        return Err(ApiError::bad_request(
            "submissions_b64",
            format!("a batch holds 1 to {max_items} submissions, one per epoch of one order"),
        ));
    }

    let mut items: Vec<Item> = request
        .submissions_b64
        .into_iter()
        .map(|b| match decode(&b.0, params.market.0) {
            Ok(s) => Item::Pending {
                s: Box::new(s),
                raw: b.0,
            },
            Err(e) => Item::Failed(e.with_market(m)),
        })
        .collect();

    // Every submission of the batch must come from one session.
    let trader = items.iter().find_map(|i| match i {
        Item::Pending { s, .. } => Some(s.trader.0),
        Item::Failed(_) => None,
    });
    let mut session: Option<SessionRef> = None;
    let mut rate = None;
    if let Some(trader) = trader {
        let found = match live_session(&ctx, trader).await {
            Ok(a) if a.sref.market.is_some_and(|b| b != m) => Err(ApiError::new(
                ErrorCode::SessionUnknown,
                "the session is bound to another market",
            )),
            other => other.map(|a| a.sref),
        };
        match found {
            Ok(sref) => {
                // One rate-limit token for the whole batch.
                rate = Some(ctx.per_wallet.take(&sref.wallet)?);
                session = Some(sref);
            }
            Err(e) => {
                for item in &mut items {
                    if let Item::Pending { s, .. } = item {
                        let epoch = s.envelope.epoch.0;
                        *item = Item::Failed(e.clone().with_market(m).with_epoch(epoch));
                    }
                }
            }
        }
    }

    let cfg = relay_config(params, m);
    let mut verified = Vec::new();
    let mut slots: Vec<Option<(usize, u64)>> = Vec::with_capacity(items.len());
    for item in &mut items {
        let Item::Pending { s, raw } = item else {
            slots.push(None);
            continue;
        };
        let epoch = s.envelope.epoch.0;
        let outcome = if Some(s.trader.0) != trader {
            Err(ApiError::bad_request(
                "submissions_b64",
                "all submissions of a batch come from one session",
            ))
        } else {
            verify(&cfg, std::mem::take(raw), s)
        };
        match outcome {
            Ok(vs) => {
                slots.push(Some((verified.len(), epoch)));
                verified.push(vs);
            }
            Err(e) => {
                *item = Item::Failed(e.with_market(m).with_epoch(epoch));
                slots.push(None);
            }
        }
    }

    let mut answers: Vec<Option<Result<timescales_service::api::SubmitResult, SubmitError>>> =
        match (session, verified.is_empty()) {
            (Some(sref), false) => ctx
                .node
                .submit(m, verified, sref)
                .await
                .into_iter()
                .map(Some)
                .collect(),
            _ => Vec::new(),
        };
    let mut out = Vec::with_capacity(items.len());
    for (item, slot) in items.into_iter().zip(slots) {
        let result = match (item, slot) {
            (Item::Failed(e), _) => Err(e),
            (Item::Pending { .. }, Some((i, epoch))) => {
                match answers.get_mut(i).and_then(Option::take) {
                    Some(Ok(r)) => Ok(r),
                    Some(Err(e)) => {
                        let problem = refused(&e, m, epoch).to_problem(&request_id);
                        out.push(SubmitItemResult::Error(SubmitItemError {
                            problem,
                            refusal_b64: e.refusal.map(B64),
                        }));
                        continue;
                    }
                    None => Err(ApiError::internal(
                        "the node answered fewer results than submissions",
                    )),
                }
            }
            (Item::Pending { .. }, None) => Err(ApiError::internal("unverified batch item")),
        };
        out.push(match result {
            Ok(r) => SubmitItemResult::Ok(r),
            Err(e) => SubmitItemResult::Error(SubmitItemError::from(e.to_problem(&request_id))),
        });
    }
    let response = json(StatusCode::MULTI_STATUS, &Items { items: out });
    Ok(match rate {
        Some(rate) => with_rate(response, &rate),
        None => response,
    })
}
