//! Public reads: node, markets, epochs and their public
//! artifacts. Nothing here takes a wallet, trader or commitment as a key.
//! Clients download per-epoch public data and filter locally.
//!
//! Epoch resources are built from the store's epoch rows. Fields the node
//! does not persist (the chain's beacon slots, verification progress) are
//! left `null` rather than guessed. Clients re-read the chain for every
//! check that matters.

use axum::Json;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use timescales_auction::BatchHeader;
use timescales_auction::receipts::{BackendKind, ExecutionReceipt};
use timescales_core::{BookId, ClearingPrice, Decode, MarketParams, PROTOCOL_VERSION, Reader};
use timescales_service::api::{
    AbortReason, AbortView, Artifacts, B58, B58Sig, B64, Band, BatchView, Book, Clearing,
    CosignatureView, CurrentEpoch, EnclavePlatform, EpochDetail, EpochKey, EpochSummary, ErrorCode,
    Hex32, Hex64, Items, Leaves, MarketDetail, NotYetAvailableDetails, OutcomeView, Page,
    PolicyStatementView, ProblemDetails, PublicPhase, Quorum, ReceiptBackend, ReceiptView,
    SettlementStatus, SettlementView, TapeRow, Time, TxKind, TxView, U64,
};
use timescales_service::store::node::{EpochRow, Phase};
use timescales_service::wire::{EpochKeyBundle, ReleasePolicyStatement};

use super::Ctx;
use super::errors::ApiError;

// ---- Parameters ----

pub(crate) fn parse_market(s: &str) -> Result<[u8; 32], ApiError> {
    B58::parse(s).map(|m| m.0).map_err(|e| {
        ApiError::bad_request("market", format!("market is not an account address: {e}"))
    })
}

pub(crate) fn parse_epoch(s: &str) -> Result<u64, ApiError> {
    U64::parse(s)
        .map(|e| e.0)
        .map_err(|e| ApiError::bad_request("epoch", format!("epoch is not a U64: {e}")))
}

/// The market's detail, or `MARKET_UNKNOWN`.
pub(crate) fn market_detail(ctx: &Ctx, m: [u8; 32]) -> Result<MarketDetail, ApiError> {
    ctx.node
        .market(m)
        .ok_or_else(|| ApiError::market_unknown(m))
}

/// The market's canonical parameters, from the bytes the node serves.
pub(crate) fn market_params(detail: &MarketDetail) -> Result<MarketParams, ApiError> {
    MarketParams::decode_exact(&detail.params_b64.0).map_err(ApiError::internal)
}

fn current_of(ctx: &Ctx, m: [u8; 32]) -> Result<CurrentEpoch, ApiError> {
    ctx.node
        .current(m)
        .ok_or_else(|| ApiError::market_unknown(m))
}

/// `?before=<U64>&limit=<1..=200>`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PageQuery {
    before: Option<String>,
    limit: Option<String>,
}

const DEFAULT_LIMIT: u32 = 50;

fn page_args(
    q: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<(Option<u64>, u32), ApiError> {
    let Query(q) = q.map_err(|e| ApiError::bad_request("query", e.body_text()))?;
    let before = q
        .before
        .map(|b| U64::parse(&b).map(|v| v.0))
        .transpose()
        .map_err(|e| ApiError::bad_request("before", format!("before is not a U64: {e}")))?;
    let limit = match q.limit {
        None => DEFAULT_LIMIT,
        Some(l) => l
            .parse::<u32>()
            .ok()
            .filter(|l| (1..=timescales_service::store::node::MAX_PAGE).contains(l))
            .ok_or_else(|| ApiError::bad_request("limit", "limit must be 1 to 200"))?,
    };
    Ok((before, limit))
}

// ---- Responses ----

pub(crate) fn json<T: Serialize>(status: StatusCode, body: &T) -> Response {
    (status, Json(body)).into_response()
}

fn not_yet(after: PublicPhase, detail: &str) -> ApiError {
    ApiError::from_details(
        ProblemDetails::NotYetAvailable(NotYetAvailableDetails {
            available_after: after,
        }),
        detail,
    )
}

/// `public, max-age=31536000, immutable` with a strong `ETag`, or `304`
/// when the client already holds it (terminal public data only).
fn immutable(headers: &HeaderMap, body: Vec<u8>, content_type: &'static str) -> Response {
    let digest = timescales_core::crypto::hash(b"timescales/api/etag", &body);
    let etag = format!("\"{}\"", hex::encode(&digest.0[..16]));
    let matches = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag || t.trim() == "*"));
    let mut response = if matches {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response()
    };
    let h = response.headers_mut();
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    response
}

fn json_maybe_immutable<T: Serialize>(headers: &HeaderMap, terminal: bool, body: &T) -> Response {
    if !terminal {
        return json(StatusCode::OK, body);
    }
    match serde_json::to_vec(body) {
        Ok(bytes) => immutable(headers, bytes, "application/json"),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

// ---- Node ----

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

pub(crate) async fn livez() -> Response {
    json(StatusCode::OK, &Health { status: "ok" })
}

/// Ready while the store accepts writes and the node is neither down nor
/// still reconciling with the chain (the node folds its chain lag into
/// `Status`).
pub(crate) async fn readyz(State(ctx): State<Ctx>) -> Response {
    let store_ok = !ctx.node.store().store().is_closed();
    let status = ctx.node.status().status;
    let ready = store_ok
        && matches!(
            status,
            timescales_service::api::OverallStatus::Ok
                | timescales_service::api::OverallStatus::Degraded
        )
        && !ctx.shutdown.is_cancelled();
    if ready {
        json(StatusCode::OK, &Health { status: "ready" })
    } else {
        json(
            StatusCode::SERVICE_UNAVAILABLE,
            &Health {
                status: "not_ready",
            },
        )
    }
}

pub(crate) async fn info(State(ctx): State<Ctx>) -> Response {
    json(StatusCode::OK, &ctx.node.info())
}

pub(crate) async fn status(State(ctx): State<Ctx>) -> Response {
    json(StatusCode::OK, &ctx.node.status())
}

/// Server time and the newest chain slot any market's view is based on.
pub(crate) async fn time(State(ctx): State<Ctx>) -> Result<Response, ApiError> {
    let slot = ctx
        .node
        .info()
        .markets
        .iter()
        .filter_map(|m| ctx.node.current(m.0))
        .map(|c| c.context_slot.0)
        .max()
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::MarketUnavailable,
                "no market has a chain view yet",
            )
        })?;
    Ok(json(
        StatusCode::OK,
        &Time {
            server_time_ms: ctx.now_ms(),
            slot: U64(slot),
        },
    ))
}

// ---- Markets ----

pub(crate) async fn markets(State(ctx): State<Ctx>) -> Response {
    json(
        StatusCode::OK,
        &Items {
            items: ctx.node.markets(),
        },
    )
}

pub(crate) async fn market(
    State(ctx): State<Ctx>,
    Path(market): Path<String>,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    Ok(json(StatusCode::OK, &market_detail(&ctx, m)?))
}

pub(crate) async fn current(
    State(ctx): State<Ctx>,
    Path(market): Path<String>,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    Ok(json(StatusCode::OK, &current_of(&ctx, m)?))
}

/// Signed member release policies (V-14), from the committee the market
/// detail carries.
pub(crate) async fn policies(
    State(ctx): State<Ctx>,
    Path(market): Path<String>,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let detail = market_detail(&ctx, m)?;
    let items = detail
        .committee
        .policies_b64
        .iter()
        .map(|b| {
            let s = ReleasePolicyStatement::decode_exact(&b.0).map_err(ApiError::internal)?;
            Ok(PolicyStatementView {
                member: u32::from(s.member),
                statement_b64: b.clone(),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(json(StatusCode::OK, &Items { items }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutorsQuery {
    market: Option<String>,
}

pub(crate) async fn executors(
    State(ctx): State<Ctx>,
    q: Result<Query<ExecutorsQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(q) = q.map_err(|e| ApiError::bad_request("query", e.body_text()))?;
    let market = q
        .market
        .ok_or_else(|| ApiError::bad_request("market", "the market query parameter is required"))?;
    let m = parse_market(&market)?;
    market_detail(&ctx, m)?;
    let directory = ctx.executors.as_ref().ok_or_else(|| {
        ApiError::new(
            ErrorCode::NotFound,
            "this node does not publish executor registrations",
        )
        .with_market(m)
    })?;
    let items = directory.executors(m).await?;
    Ok(json(StatusCode::OK, &Items { items }))
}

// ---- Epoch views ----

/// Internal phases as clients see them (committing -> closed,
/// snapshotted->committed, sealed->revealed).
pub(crate) fn public_phase(p: Phase) -> PublicPhase {
    match p {
        Phase::Scheduled => PublicPhase::Scheduled,
        Phase::Open => PublicPhase::Open,
        Phase::Closed | Phase::Committing => PublicPhase::Closed,
        Phase::Committed | Phase::Snapshotted => PublicPhase::Committed,
        Phase::Revealed | Phase::Sealed => PublicPhase::Revealed,
        Phase::Executing => PublicPhase::Executing,
        Phase::Posted => PublicPhase::Posted,
        Phase::Settled => PublicPhase::Settled,
        Phase::Aborting => PublicPhase::Aborting,
        Phase::Aborted => PublicPhase::Aborted,
    }
}

/// The numbering of `epochs.abort_reason`.
pub(crate) fn abort_reason(code: u8) -> Option<AbortReason> {
    Some(match code {
        1 => AbortReason::Admin,
        2 => AbortReason::Relay,
        3 => AbortReason::BeaconExpired,
        4 => AbortReason::ExecTimeout,
        5 => AbortReason::SettleTimeout,
        6 => AbortReason::QuorumTimeout,
        _ => return None,
    })
}

fn aborting(p: Phase) -> bool {
    matches!(p, Phase::Aborting | Phase::Aborted)
}

fn book(b: BookId) -> Book {
    match b {
        BookId::Single => Book::Single,
        BookId::MakerAskTakerBid => Book::MakerAskTakerBid,
        BookId::MakerBidTakerAsk => Book::MakerBidTakerAsk,
    }
}

fn clearing_view(prices: &[ClearingPrice]) -> Vec<Clearing> {
    prices
        .iter()
        .map(|c| Clearing {
            book: book(c.book),
            tick: U64(c.tick.0),
            volume: U64(c.volume.0),
        })
        .collect()
}

fn band(b: &timescales_core::PriceBand) -> Band {
    Band {
        lo: U64(b.lo.0),
        hi: U64(b.hi.0),
        reference: U64(b.reference.0),
    }
}

fn receipt_of(row: &EpochRow) -> Result<Option<ExecutionReceipt>, ApiError> {
    row.receipt
        .as_deref()
        .map(ExecutionReceipt::decode_exact)
        .transpose()
        .map_err(ApiError::internal)
}

fn receipt_view(r: &ExecutionReceipt) -> Result<ReceiptView, ApiError> {
    if r.version != PROTOCOL_VERSION || r.backend != BackendKind::Tee {
        return Err(ApiError::internal(
            "a stored receipt the v1 API cannot express",
        ));
    }
    let o = &r.outcome;
    Ok(ReceiptView {
        version: u32::from(r.version),
        digest: r.digest().into(),
        backend: ReceiptBackend::Tee,
        executor: B58::from(r.executor),
        attestation: r.attestation.into(),
        proof: r.proof.into(),
        trace: r.trace.into(),
        outcome: OutcomeView {
            header_digest: o.header_digest.into(),
            clearing: clearing_view(&o.clearing),
            fill_count: o.fill_count,
            fills_root: o.fills_root.into(),
            cancelled_root: o.cancelled_root.into(),
            next_state_root: o.next_state_root.into(),
            settlement_count: o.settlement_count,
            settlement_root: o.settlement_root.into(),
            fees: U64(o.fees.0),
        },
    })
}

/// The platform byte of the `Evidence` that ends an
/// `ExecutorAttestationV2` (`executor32 || seal_key32 || header_digest32 ||
/// seq<nonce32> || committee_digest32 || platform u8 ||...`).
pub(crate) fn attestation_platform(attestation: &[u8]) -> Option<EnclavePlatform> {
    let mut r = Reader::new(attestation);
    r.take(96).ok()?;
    let nonces = usize::try_from(r.u32().ok()?).ok()?;
    r.take(nonces.checked_mul(32)?).ok()?;
    r.take(32).ok()?;
    match r.u8().ok()? {
        0 => Some(EnclavePlatform::Simulated),
        1 => Some(EnclavePlatform::IntelTdx),
        _ => None,
    }
}

/// The summary of an epoch that has opened. `None` for a scheduled one.
fn summary(
    m: [u8; 32],
    row: &EpochRow,
    receipt: Option<&ExecutionReceipt>,
    platform: Option<EnclavePlatform>,
) -> Option<EpochSummary> {
    let (opens_at_ms, cutoff_ms) = (row.opens_at_ms?, row.cutoff_ms?);
    // Counts are public once the batch is committed on chain, not before.
    let committed = row.commit_slot.is_some();
    let traded = receipt.filter(|_| !aborting(row.phase));
    Some(EpochSummary {
        market: B58(m),
        epoch: U64(row.epoch),
        phase: public_phase(row.phase),
        opens_at_ms,
        cutoff_ms,
        envelope_count: row.envelope_count.filter(|_| committed),
        clearing: traded.map(|r| clearing_view(&r.outcome.clearing)),
        fill_count: traded.map(|r| r.outcome.fill_count),
        terminal_at_ms: row.phase.is_terminal().then_some(row.updated_at_ms),
        abort_reason: if aborting(row.phase) {
            row.abort_reason.and_then(abort_reason)
        } else {
            None
        },
        tee_platform: platform,
    })
}

/// The platform of the posting enclave, once the artifacts are public.
async fn platform_of(
    ctx: &Ctx,
    m: [u8; 32],
    row: &EpochRow,
) -> Result<Option<EnclavePlatform>, ApiError> {
    if !row.artifacts_public {
        return Ok(None);
    }
    Ok(ctx
        .node
        .store()
        .public_artifacts(m, row.epoch)
        .await?
        .and_then(|a| a.attestation)
        .and_then(|a| attestation_platform(&a)))
}

pub(crate) fn epoch_key(bundle: &EpochKeyBundle, bytes: Vec<u8>) -> EpochKey {
    let a = &bundle.announcement;
    EpochKey {
        epoch: U64(a.epoch.0),
        epoch_pk: Hex32(a.epoch_pk),
        committee_digest: a.committee_digest.into(),
        bundle_b64: B64(bytes),
    }
}

/// The program's status name as far as the node's phase tells it. The
/// node does not persist verification progress, so a posted batch that the
/// chain already counts as verified still reads `receipt_posted` here.
fn batch_status(row: &EpochRow) -> &'static str {
    match row.phase {
        Phase::Settled => "settled",
        Phase::Aborted => "aborted",
        _ if row.receipt_slot.is_some() || row.receipt.is_some() => "receipt_posted",
        _ if row.reveal_slot.is_some() => "beacon_revealed",
        _ => "committed",
    }
}

fn tx_kind(op: &str) -> Option<TxKind> {
    Some(match op {
        "commit" => TxKind::Commit,
        "reveal" => TxKind::Reveal,
        "post" => TxKind::Post,
        "cosign" => TxKind::Cosign,
        "verify" => TxKind::Verify,
        "finalize" => TxKind::Finalize,
        "apply" => TxKind::Apply,
        "close" => TxKind::Close,
        "abort" => TxKind::Abort,
        "reclaim" => TxKind::Reclaim,
        _ => return None,
    })
}

async fn epoch_detail(ctx: &Ctx, m: [u8; 32], e: u64) -> Result<EpochDetail, ApiError> {
    let detail = market_detail(ctx, m)?;
    let repo = ctx.node.store();
    let row = repo.epoch(m, e).await?.ok_or_else(|| {
        ApiError::new(ErrorCode::NotFound, "no such epoch")
            .with_market(m)
            .with_epoch(e)
    })?;
    let receipt = receipt_of(&row)?;
    let public = repo.public_artifacts(m, e).await?;
    let platform = public
        .as_ref()
        .and_then(|a| a.attestation.as_deref())
        .and_then(attestation_platform);
    let summary = summary(m, &row, receipt.as_ref(), platform).ok_or_else(|| {
        not_yet(PublicPhase::Open, "the epoch has not opened")
            .with_market(m)
            .with_epoch(e)
    })?;
    let missing = |what: &str| ApiError::internal(format!("open epoch without {what}"));
    let (Some(b), Some(terms), Some(announcement)) = (
        row.band.as_ref(),
        row.terms_digest,
        row.announcement.clone(),
    ) else {
        return Err(missing("its terms"));
    };
    let bundle_bytes = repo.key_bundle(m, e).await?.ok_or_else(|| {
        ApiError::new(
            ErrorCode::Pruned,
            "the epoch's key bundle is beyond retention",
        )
        .with_market(m)
        .with_epoch(e)
    })?;
    let bundle = EpochKeyBundle::decode_exact(&bundle_bytes).map_err(ApiError::internal)?;

    let posted = receipt.is_some();
    let batch = match (
        row.commit_slot,
        row.commit_sig,
        row.root,
        row.envelope_count,
    ) {
        (Some(commit_slot), Some(sig), Some(root), Some(count)) => {
            let program = ctx.node.info().program_id;
            let (address, _) = timescales_chain::program::batch_pda(&program.0, &m, e)
                .map_err(ApiError::internal)?;
            let live = &detail.executors;
            let mut cosigners: Vec<B58> = Vec::new();
            if let Some(r) = &receipt {
                cosigners.push(B58::from(r.executor));
            }
            for (executor, _) in public.iter().flat_map(|p| p.cosigs.iter()) {
                if !cosigners.iter().any(|c| c.0 == *executor) {
                    cosigners.push(B58(*executor));
                }
            }
            cosigners.retain(|c| live.contains(c));
            let header = row
                .header
                .as_deref()
                .filter(|_| posted)
                .map(BatchHeader::decode_exact)
                .transpose()
                .map_err(ApiError::internal)?;
            let revealed = row.reveal_slot.is_some();
            Some(BatchView {
                address: B58(address),
                status: batch_status(&row).to_owned(),
                root: root.into(),
                count,
                terms_digest: terms.into(),
                commit_slot: U64(commit_slot),
                commit_signature: B58Sig(sig),
                beacon: row.beacon.filter(|_| revealed).map(Into::into),
                // The chain records which slots fed the beacon. The node's
                // row does not, and a skipped target moves them.
                beacon_slots: None,
                reveal_slot: row.reveal_slot.map(U64),
                header_digest: header.as_ref().map(|h| h.digest().into()),
                receipt_digest: receipt.as_ref().map(|r| r.digest().into()),
                outcome_digest: receipt.as_ref().map(|r| r.outcome.digest().into()),
                quorum: Quorum {
                    have: u32::try_from(cosigners.len()).unwrap_or(u32::MAX),
                    need: detail.receipt_quorum,
                },
                cosigners,
                settlement_count: receipt.as_ref().map(|r| r.outcome.settlement_count),
                fees: receipt.as_ref().map(|r| U64(r.outcome.fees.0)),
                context_slot: current_of(ctx, m)?.context_slot,
            })
        }
        _ => None,
    };
    let txs = repo
        .txs_for(m, e)
        .await?
        .into_iter()
        .filter(|t| matches!(t.status.as_str(), "landed" | "pending"))
        .filter_map(|t| {
            Some(TxView {
                op: tx_kind(&t.op)?,
                signature: B58Sig(t.signature),
                slot: t.slot.map(U64),
            })
        })
        .collect();
    let settlement = match (row.phase, &receipt) {
        // Settled means every leaf was verified and applied.
        (Phase::Settled, Some(r)) => {
            let n = r.outcome.settlement_count;
            Some(SettlementView {
                status: SettlementStatus::Settled,
                verified: n,
                applied: n,
                total: n,
            })
        }
        _ => None,
    };
    let abort = if aborting(row.phase) {
        row.abort_reason
            .and_then(abort_reason)
            .map(|reason| AbortView {
                reason,
                detail: row.abort_detail.clone().unwrap_or_default(),
            })
    } else {
        None
    };
    Ok(EpochDetail {
        summary,
        band: band(b),
        terms_digest: terms.into(),
        announcement_b64: B64(announcement),
        key: epoch_key(&bundle, bundle_bytes),
        batch,
        artifacts_public: row.artifacts_public,
        header_b64: row.header.clone().filter(|_| posted).map(B64),
        receipt_b64: row.receipt.clone().map(B64),
        receipt: receipt.as_ref().map(receipt_view).transpose()?,
        settlement,
        txs,
        abort,
    })
}

async fn epoch_row(ctx: &Ctx, m: [u8; 32], e: u64) -> Result<EpochRow, ApiError> {
    market_detail(ctx, m)?;
    ctx.node.store().epoch(m, e).await?.ok_or_else(|| {
        ApiError::new(ErrorCode::NotFound, "no such epoch")
            .with_market(m)
            .with_epoch(e)
    })
}

// ---- Epoch routes ----

pub(crate) async fn epochs(
    State(ctx): State<Ctx>,
    Path(market): Path<String>,
    q: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let (before, limit) = page_args(q)?;
    market_detail(&ctx, m)?;
    let (rows, next) = ctx.node.store().epochs_page(m, before, limit).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let receipt = receipt_of(row)?;
        let platform = platform_of(&ctx, m, row).await?;
        items.extend(summary(m, row, receipt.as_ref(), platform));
    }
    Ok(json(
        StatusCode::OK,
        &Page {
            items,
            next_before: next.map(U64),
        },
    ))
}

pub(crate) async fn epoch(
    State(ctx): State<Ctx>,
    Path((market, epoch)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let e = parse_epoch(&epoch)?;
    let detail = epoch_detail(&ctx, m, e).await?;
    let terminal = matches!(
        detail.summary.phase,
        PublicPhase::Settled | PublicPhase::Aborted
    );
    Ok(json_maybe_immutable(req.headers(), terminal, &detail))
}

/// The epoch whose park window bounds which keys are served: the open
/// one, or while intake is paused the newest epoch that opened.
fn park_base(c: &CurrentEpoch) -> Option<u64> {
    c.open.as_ref().map(|o| o.epoch.0).or_else(|| {
        [&c.previous, &c.inflight]
            .into_iter()
            .flatten()
            .map(|p| p.epoch.0)
            .max()
    })
}

/// A key is served once its epoch opened, or ahead of time within the park
/// window. A key served ahead of time is never replaced.
pub(crate) async fn key(
    State(ctx): State<Ctx>,
    Path((market, epoch)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let e = parse_epoch(&epoch)?;
    let detail = market_detail(&ctx, m)?;
    let current = current_of(&ctx, m)?;
    let repo = ctx.node.store();
    let opened = repo
        .epoch(m, e)
        .await?
        .is_some_and(|r| r.phase >= Phase::Open);
    let base = park_base(&current);
    let ahead = !opened && base.is_some_and(|b| e > b);
    let window = u64::from(detail.timing.max_park_ahead_epochs);
    let too_far = !opened && base.is_none_or(|b| e > b.saturating_add(window));
    if too_far {
        return Err(ApiError::new(
            ErrorCode::EpochTooFar,
            format!("keys are served at most {window} epochs ahead of the open epoch"),
        )
        .with_market(m)
        .with_epoch(e));
    }
    let bytes = repo.key_bundle(m, e).await?.ok_or_else(|| {
        ApiError::new(ErrorCode::NotFound, "no key has been dealt for this epoch")
            .with_market(m)
            .with_epoch(e)
    })?;
    let bundle = EpochKeyBundle::decode_exact(&bytes).map_err(ApiError::internal)?;
    if ahead {
        repo.mark_bundle_served(m, e).await?;
    }
    Ok(json(StatusCode::OK, &epoch_key(&bundle, bytes)))
}

async fn leaves_of(ctx: &Ctx, m: [u8; 32], e: u64) -> Result<(EpochRow, Vec<u8>), ApiError> {
    let row = epoch_row(ctx, m, e).await?;
    if row.commit_slot.is_none() {
        return Err(not_yet(
            PublicPhase::Committed,
            "leaves are published once the batch is committed",
        )
        .with_market(m)
        .with_epoch(e));
    }
    let leaves = ctx.node.store().leaves(m, e).await?.ok_or_else(|| {
        ApiError::new(ErrorCode::Pruned, "the epoch's leaves are beyond retention")
            .with_market(m)
            .with_epoch(e)
    })?;
    Ok((row, leaves))
}

pub(crate) async fn leaves(
    State(ctx): State<Ctx>,
    Path((market, epoch)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let e = parse_epoch(&epoch)?;
    let (row, leaves) = leaves_of(&ctx, m, e).await?;
    let (Some(root), Some(count)) = (row.root, row.envelope_count) else {
        return Err(ApiError::internal("committed epoch without root or count"));
    };
    let body = Leaves {
        market: B58(m),
        epoch: U64(e),
        root: root.into(),
        count,
        leaves_b64: B64(leaves),
    };
    Ok(json_maybe_immutable(
        req.headers(),
        row.phase.is_terminal(),
        &body,
    ))
}

/// The raw `count x 64` bytes.
pub(crate) async fn leaves_bin(
    State(ctx): State<Ctx>,
    Path((market, epoch)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let e = parse_epoch(&epoch)?;
    let (row, leaves) = leaves_of(&ctx, m, e).await?;
    if row.phase.is_terminal() {
        return Ok(immutable(req.headers(), leaves, "application/octet-stream"));
    }
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        leaves,
    )
        .into_response())
}

pub(crate) async fn artifacts(
    State(ctx): State<Ctx>,
    Path((market, epoch)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let e = parse_epoch(&epoch)?;
    let row = epoch_row(&ctx, m, e).await?;
    let a = ctx
        .node
        .store()
        .public_artifacts(m, e)
        .await?
        .ok_or_else(|| {
            not_yet(
                PublicPhase::Posted,
                "artifacts are public once the receipt quorum is on chain",
            )
            .with_market(m)
            .with_epoch(e)
        })?;
    let attestation_platform = a
        .attestation
        .as_deref()
        .and_then(attestation_platform)
        .unwrap_or(ctx.node.info().trust.enclave);
    let body = Artifacts {
        market: B58(m),
        epoch: U64(e),
        header_b64: B64(a.header),
        receipt_b64: B64(a.receipt),
        artifacts_b64: B64(a.artifacts),
        attestation_b64: a.attestation.map(B64),
        attestation_platform,
        cosignatures: a
            .cosigs
            .into_iter()
            .map(|(executor, sig)| CosignatureView {
                executor: B58(executor),
                signature: Hex64(sig),
            })
            .collect(),
    };
    Ok(json_maybe_immutable(
        req.headers(),
        row.phase.is_terminal(),
        &body,
    ))
}

/// The epoch's `BalanceSheet`, public with the artifacts (V-15).
pub(crate) async fn balances(
    State(ctx): State<Ctx>,
    Path((market, epoch)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let e = parse_epoch(&epoch)?;
    let row = epoch_row(&ctx, m, e).await?;
    if !row.artifacts_public {
        return Err(not_yet(
            PublicPhase::Posted,
            "the balance sheet is public once the artifacts are",
        )
        .with_market(m)
        .with_epoch(e));
    }
    let (sheet, _slot) = ctx.node.store().snapshot(m, e).await?.ok_or_else(|| {
        ApiError::new(
            ErrorCode::Pruned,
            "the epoch's balance sheet is beyond retention",
        )
        .with_market(m)
        .with_epoch(e)
    })?;
    if row.phase.is_terminal() {
        return Ok(immutable(req.headers(), sheet, "application/octet-stream"));
    }
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        sheet,
    )
        .into_response())
}

async fn clearing_tape(
    ctx: &Ctx,
    m: [u8; 32],
    before: Option<u64>,
    limit: u32,
) -> Result<Page<TapeRow>, ApiError> {
    let (rows, next) = ctx.node.store().tape_page(m, before, limit).await?;
    Ok(Page {
        items: rows
            .into_iter()
            .map(|r| TapeRow {
                epoch: U64(r.epoch),
                cutoff_ms: r.cutoff_ms,
                phase: public_phase(r.phase),
                clearing: clearing_view(&r.clearing),
                matched_lots: U64(r.matched_lots),
                fill_count: r.fill_count,
                envelope_count: r.envelope_count,
                terminal_at_ms: r.terminal_at_ms,
            })
            .collect(),
        next_before: next.map(U64),
    })
}

pub(crate) async fn clearing(
    State(ctx): State<Ctx>,
    Path(market): Path<String>,
    q: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    let m = parse_market(&market)?;
    let (before, limit) = page_args(q)?;
    market_detail(&ctx, m)?;
    Ok(json(
        StatusCode::OK,
        &clearing_tape(&ctx, m, before, limit).await?,
    ))
}
