//! Admin routes (bearer token, private listener) and the internal
//! `KeyBundlePut` route.
//!
//! The abort route offers what the program allows the node: a relay abort while
//! the batch is committed and `slot < commit_slot + d`, before either
//! beacon input exists, or a timeout abort that is already due. Anything
//! else is refused with 409 and the stuck-batch runbook, which explains the
//! admin (multisig) abort.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use timescales_service::api::{AbortReason, B58, TimingView, U64};
use timescales_service::store::node::{EpochRow, Phase};
use zeroize::Zeroizing;

use super::AdminOptions;
use super::internal;
use super::reads::{parse_epoch, parse_market};
use crate::config::AdminConfig;
use crate::{AdminCmd, AdminReply, AdminStatus, Clock, NodeApi, NodeError};

/// The runbook a refused abort points to.
pub const RUNBOOK_STUCK_BATCH: &str = "stuck-batch";

/// Slots after `commit_slot + d` during which the beacon can be revealed
/// (`REVEAL_WINDOW`).
const REVEAL_WINDOW: u64 = 400;

/// Shortest admin token, in decoded bytes.
const MIN_TOKEN_BYTES: usize = 32;

/// Which abort, if any, the node may send for an epoch at `slot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortWindow {
    /// Reason 2: committed and `slot < commit_slot + d`.
    Relay,
    /// A permissionless timeout abort that is due.
    Timeout(AbortReason),
    /// The node is already aborting the epoch.
    InProgress,
    /// No abort the node may send. The reason says why.
    Refused(&'static str),
}

/// The abort window over the node's view of an epoch. The chain decides in the
/// end. This keeps the route from offering what the program would refuse.
pub fn abort_window(row: &EpochRow, timing: &TimingView, slot: u64) -> AbortWindow {
    let d = u64::from(timing.beacon_delay_slots);
    let exec = timing.exec_timeout_slots.0;
    let settle = timing.settle_timeout_slots.0;
    match row.phase {
        Phase::Settled | Phase::Aborted => return AbortWindow::Refused("the epoch is terminal"),
        Phase::Aborting => return AbortWindow::InProgress,
        Phase::Scheduled | Phase::Open | Phase::Closed | Phase::Committing => {
            return AbortWindow::Refused("no batch of this epoch is committed");
        }
        _ => {}
    }
    let Some(commit) = row.commit_slot else {
        return AbortWindow::Refused("no batch of this epoch is committed");
    };
    let receipt_slot = row.receipt_slot;
    if let Some(r) = receipt_slot {
        if row.phase == Phase::Posted {
            // The quorum is on chain. Only a stalled settlement times out.
            return if slot > r.saturating_add(settle) {
                AbortWindow::Timeout(AbortReason::SettleTimeout)
            } else {
                AbortWindow::Refused(
                    "settlement has not timed out; the relay has no abort after the beacon",
                )
            };
        }
        return if slot > r.saturating_add(exec) {
            AbortWindow::Timeout(AbortReason::QuorumTimeout)
        } else {
            AbortWindow::Refused(
                "the posted receipt has not timed out; the relay has no abort after the beacon",
            )
        };
    }
    if let Some(reveal) = row.reveal_slot {
        return if slot > reveal.saturating_add(exec) {
            AbortWindow::Timeout(AbortReason::ExecTimeout)
        } else {
            AbortWindow::Refused(
                "execution has not timed out; the relay has no abort after the beacon",
            )
        };
    }
    if slot < commit.saturating_add(d) {
        AbortWindow::Relay
    } else if slot > commit.saturating_add(d).saturating_add(REVEAL_WINDOW) {
        AbortWindow::Timeout(AbortReason::BeaconExpired)
    } else {
        AbortWindow::Refused("the relay may abort only while slot < commit_slot + d")
    }
}

// ---- State and auth ----

#[derive(Clone)]
struct Admin {
    node: Arc<dyn NodeApi>,
    /// `None` when the token file is missing or too short: every admin
    /// request is refused (fail closed).
    token: Option<Arc<Zeroizing<String>>>,
}

/// The token file holds at least 32 random bytes in base64.
fn load_token(cfg: &AdminConfig, opts: &AdminOptions) -> Option<Zeroizing<String>> {
    let token = match &opts.token {
        Some(t) => t.clone(),
        None => match std::fs::read_to_string(&cfg.token_file) {
            Ok(text) => Zeroizing::new(text.trim().to_owned()),
            Err(e) => {
                tracing::error!(path = %cfg.token_file.display(), error = %e, "admin token unreadable; admin routes refuse every request");
                return None;
            }
        },
    };
    let long_enough = base64::engine::general_purpose::STANDARD
        .decode(token.as_bytes())
        .is_ok_and(|b| b.len() >= MIN_TOKEN_BYTES);
    if !long_enough {
        tracing::error!(
            "admin token is not base64 of at least 32 bytes; admin routes refuse every request"
        );
        return None;
    }
    Some(token)
}

/// Equal length and content, without an early exit on the first
/// difference.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Serialize)]
struct AdminProblem<'a> {
    error: &'a str,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    runbook: Option<&'a str>,
}

fn refuse(
    status: StatusCode,
    error: &str,
    detail: impl Into<String>,
    runbook: Option<&str>,
) -> Response {
    (
        status,
        axum::Json(AdminProblem {
            error,
            detail: detail.into(),
            runbook,
        }),
    )
        .into_response()
}

/// `Some` refusal unless the request carries the admin token.
fn check_bearer(admin: &Admin, headers: &HeaderMap) -> Option<Response> {
    let Some(token) = &admin.token else {
        return Some(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "token_unavailable",
            "the admin token is not configured",
            None,
        ));
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if constant_time_eq(presented.as_bytes(), token.as_bytes()) {
        None
    } else {
        Some(refuse(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid bearer token is required",
            None,
        ))
    }
}

fn node_error(e: NodeError) -> Response {
    match e {
        NodeError::MarketUnknown(_) => {
            refuse(StatusCode::NOT_FOUND, "market_unknown", e.to_string(), None)
        }
        NodeError::Api { code, detail } => refuse(
            StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            code.as_str(),
            detail,
            None,
        ),
        NodeError::ShuttingDown => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "draining",
            e.to_string(),
            None,
        ),
        other => {
            tracing::error!(error = %other, "admin request failed");
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "internal error",
                None,
            )
        }
    }
}

fn reply(r: Result<AdminReply, NodeError>) -> Response {
    match r {
        Ok(AdminReply::Ok) => StatusCode::NO_CONTENT.into_response(),
        Ok(AdminReply::Refused { reason, runbook }) => {
            refuse(StatusCode::CONFLICT, "refused", reason, Some(runbook))
        }
        Ok(AdminReply::Status(s)) => (StatusCode::OK, axum::Json(status_view(&s))).into_response(),
        Ok(AdminReply::Backup(b)) => (
            StatusCode::OK,
            axum::Json(BackupView {
                path: b.path.display().to_string(),
                bytes: U64(b.bytes),
                stripped: b.stripped,
                integrity_ok: b.integrity_ok,
            }),
        )
            .into_response(),
        Err(e) => node_error(e),
    }
}

// ---- Views ----

fn phase_name(p: Phase) -> &'static str {
    match p {
        Phase::Scheduled => "scheduled",
        Phase::Open => "open",
        Phase::Closed => "closed",
        Phase::Committing => "committing",
        Phase::Committed => "committed",
        Phase::Snapshotted => "snapshotted",
        Phase::Revealed => "revealed",
        Phase::Sealed => "sealed",
        Phase::Executing => "executing",
        Phase::Posted => "posted",
        Phase::Settled => "settled",
        Phase::Aborting => "aborting",
        Phase::Aborted => "aborted",
    }
}

#[derive(Serialize)]
struct EpochPhaseView {
    epoch: U64,
    phase: &'static str,
}

#[derive(Serialize)]
struct MarketStatusView {
    market: B58,
    state: String,
    epochs: Vec<EpochPhaseView>,
    settlement_lag: U64,
    keys_ready_ahead: u32,
    relay_balance_lamports: U64,
    cranker_balance_lamports: U64,
    pending_change: Option<u8>,
    last_errors: Vec<String>,
}

#[derive(Serialize)]
struct StatusView {
    markets: Vec<MarketStatusView>,
}

fn status_view(s: &AdminStatus) -> StatusView {
    StatusView {
        markets: s
            .markets
            .iter()
            .map(|m| MarketStatusView {
                market: B58(m.market),
                state: m.state.clone(),
                epochs: m
                    .epochs
                    .iter()
                    .map(|(e, p)| EpochPhaseView {
                        epoch: U64(*e),
                        phase: phase_name(*p),
                    })
                    .collect(),
                settlement_lag: U64(m.settlement_lag),
                keys_ready_ahead: m.keys_ready_ahead,
                relay_balance_lamports: U64(m.relay_balance_lamports),
                cranker_balance_lamports: U64(m.cranker_balance_lamports),
                pending_change: m.pending_change,
                last_errors: m.last_errors.clone(),
            })
            .collect(),
    }
}

#[derive(Serialize)]
struct BackupView {
    path: String,
    bytes: U64,
    stripped: Vec<&'static str>,
    integrity_ok: bool,
}

// ---- Routes ----

async fn status(State(admin): State<Admin>, headers: HeaderMap) -> Response {
    if let Some(r) = check_bearer(&admin, &headers) {
        return r;
    }
    reply(admin.node.admin(AdminCmd::Status).await)
}

async fn market_cmd(
    admin: &Admin,
    headers: &HeaderMap,
    market: &str,
    cmd: fn([u8; 32]) -> AdminCmd,
) -> Response {
    if let Some(r) = check_bearer(admin, headers) {
        return r;
    }
    let m = match parse_market(market) {
        Ok(m) => m,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "bad_request",
                e.detail.clone(),
                None,
            );
        }
    };
    reply(admin.node.admin(cmd(m)).await)
}

async fn pause(State(admin): State<Admin>, Path(m): Path<String>, headers: HeaderMap) -> Response {
    market_cmd(&admin, &headers, &m, AdminCmd::Pause).await
}

async fn resume(State(admin): State<Admin>, Path(m): Path<String>, headers: HeaderMap) -> Response {
    market_cmd(&admin, &headers, &m, AdminCmd::Resume).await
}

async fn drain(State(admin): State<Admin>, Path(m): Path<String>, headers: HeaderMap) -> Response {
    market_cmd(&admin, &headers, &m, AdminCmd::Drain).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceRequest {
    tick: U64,
}

/// Body limit of admin requests.
const ADMIN_BODY_LIMIT: usize = 1024;

async fn reference(
    State(admin): State<Admin>,
    Path(market): Path<String>,
    req: Request,
) -> Response {
    if let Some(r) = check_bearer(&admin, req.headers()) {
        return r;
    }
    let m = match parse_market(&market) {
        Ok(m) => m,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "bad_request",
                e.detail.clone(),
                None,
            );
        }
    };
    let body = match axum::body::to_bytes(req.into_body(), ADMIN_BODY_LIMIT).await {
        Ok(b) => b,
        Err(_) => {
            return refuse(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "body too large",
                None,
            );
        }
    };
    let request: ReferenceRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, "bad_request", e.to_string(), None),
    };
    reply(
        admin
            .node
            .admin(AdminCmd::SetReference(m, request.tick.0))
            .await,
    )
}

async fn abort(
    State(admin): State<Admin>,
    Path((market, epoch)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Some(r) = check_bearer(&admin, &headers) {
        return r;
    }
    let (m, e) = match (parse_market(&market), parse_epoch(&epoch)) {
        (Ok(m), Ok(e)) => (m, e),
        (Err(err), _) | (_, Err(err)) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "bad_request",
                err.detail.clone(),
                None,
            );
        }
    };
    let (Some(detail), Some(current)) = (admin.node.market(m), admin.node.current(m)) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "market_unknown",
            "no such market",
            None,
        );
    };
    let row = match admin.node.store().epoch(m, e).await {
        Ok(Some(row)) => row,
        Ok(None) => return refuse(StatusCode::NOT_FOUND, "not_found", "no such epoch", None),
        Err(err) => return node_error(err.into()),
    };
    if let AbortWindow::Refused(reason) = abort_window(&row, &detail.timing, current.context_slot.0)
    {
        return refuse(
            StatusCode::CONFLICT,
            "abort_refused",
            reason,
            Some(RUNBOOK_STUCK_BATCH),
        );
    }
    reply(admin.node.admin(AdminCmd::Abort(m, e)).await)
}

async fn backup(State(admin): State<Admin>, headers: HeaderMap) -> Response {
    if let Some(r) = check_bearer(&admin, &headers) {
        return r;
    }
    reply(admin.node.admin(AdminCmd::Backup).await)
}

async fn not_found() -> Response {
    refuse(StatusCode::NOT_FOUND, "not_found", "no such route", None)
}

pub(super) fn router(node: Arc<dyn NodeApi>, cfg: AdminConfig, opts: AdminOptions) -> Router {
    let token = load_token(&cfg, &opts).map(Arc::new);
    let admin = Admin {
        node: node.clone(),
        token,
    };
    let clock: Arc<dyn Clock> = opts.clock.clone();
    let admin_routes = Router::new()
        .route("/admin/v1/status", get(status))
        .route("/admin/v1/markets/{market}/pause", post(pause))
        .route("/admin/v1/markets/{market}/resume", post(resume))
        .route("/admin/v1/markets/{market}/drain", post(drain))
        .route("/admin/v1/markets/{market}/reference", post(reference))
        .route(
            "/admin/v1/markets/{market}/epochs/{epoch}/abort",
            post(abort),
        )
        .route("/admin/v1/backup", post(backup))
        .with_state(admin);
    admin_routes
        .merge(internal::router(
            node,
            &cfg,
            opts.service,
            clock,
            opts.envelope_skew_ms,
        ))
        .fallback(not_found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_compare_whole() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
