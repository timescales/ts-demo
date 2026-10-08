//! Execution: exec and fetch.
//!
//! * [`HttpExecClient`]: the [`ExecClient`] over `SignedClient`, one pinned
//!   peer per configured enclave.
//! * [`execute_job`]: dispatch the sealed batch to `receipt_quorum +
//!   spare_executions` enclaves at once (the designated poster first),
//!   each attempt row durable before its request is sent and each
//!   `ExecuteReady` persisted in its row on arrival. Once `receipt_quorum`
//!   of them agree, hand the poster the others' co-signatures. Check the
//!   `ExecutePosted` fully. Re-send any missing `CoSignReceipt`. Make the
//!   artifacts public only once the quorum is on chain. Attempts stop at
//!   `reveal_slot + exec_timeout_slots`, after which the epoch aborts.
//! * [`fetch_and_post`]: obtain the posted outcome after a restart or when
//!   another process posted (local results, archive, `PublishRequest` to
//!   every enclave, re-execution).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use parking_lot::Mutex;
use timescales_auction::orderbook::OrderStateTable;
use timescales_auction::receipts::{
    BackendKind, ExecutionArtifacts, ExecutionReceipt, cosign_digest,
};
use timescales_chain::program::{AbortReason, BatchAccount, BatchStatus, MarketAccount};
use timescales_chain::{BatchPredicate, Level};
use timescales_core::crypto::{Signature, verify_digest};
use timescales_core::{Decode, Encode, EpochId, ExecutorId, Hash32};
use timescales_executor::ExecutionBatch;
use timescales_service::api::{B58, Clearing, Event, Hex32, U64};
use timescales_service::relay::{ClosedBatch, Submission};
use timescales_service::store::node::{
    DeltaRow, EpochPatch, EpochRow, FillRow, Phase, PostedResult,
};
use timescales_service::wire::{
    EnclaveIdentity, ErrorResponse, ExecutePosted, ExecuteReady, ExecuteRequest, GrantRecord,
    MessageKind, Provenance, ProvenanceEntry, PublishRequest,
};
use timescales_service::{ClientError, SignedClient};
use tokio::time::Instant;

use crate::archive::Archive;
use crate::config::{EnclaveEndpoint, ExecutionConfig};
use crate::market::jobs::{JobCtx, Step, Stop};
use crate::market::recover::{Action, action};
use crate::market::{FenceReason, JobOutput};
use crate::{BoxFuture, ExecClient, ExecClientError};

/// One configured enclave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclaveInfo {
    pub url: String,
    pub identity: [u8; 32],
    pub executor: [u8; 32],
}

impl EnclaveInfo {
    pub fn from_config(e: &EnclaveEndpoint) -> Option<Self> {
        Some(Self {
            url: e.url.trim_end_matches('/').to_owned(),
            identity: crate::config::hex_32(&e.identity)?,
            executor: crate::config::hex_32(&e.executor)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Breaker {
    failures: u32,
    opened_at_ms: Option<u64>,
}

/// The enclaves of the node with a circuit breaker each.
#[derive(Debug)]
pub struct Enclaves {
    pub list: Vec<EnclaveInfo>,
    breakers: Mutex<Vec<Breaker>>,
    open_after: u32,
    half_open_after_ms: u64,
}

impl Enclaves {
    pub fn new(list: Vec<EnclaveInfo>, cfg: &ExecutionConfig) -> Self {
        let n = list.len();
        Self {
            list,
            breakers: Mutex::new(vec![Breaker::default(); n]),
            open_after: cfg.circuit_open_after.max(1),
            half_open_after_ms: cfg.circuit_half_open_after_ms,
        }
    }

    /// Closed, or open long enough to let one probe through.
    pub fn available(&self, i: usize, now_ms: u64) -> bool {
        let b = self.breakers.lock();
        match b.get(i).and_then(|b| b.opened_at_ms) {
            None => true,
            Some(at) => now_ms >= at.saturating_add(self.half_open_after_ms),
        }
    }

    pub fn success(&self, i: usize) {
        if let Some(b) = self.breakers.lock().get_mut(i) {
            *b = Breaker::default();
        }
    }

    pub fn failure(&self, i: usize, now_ms: u64) {
        if let Some(b) = self.breakers.lock().get_mut(i) {
            b.failures = b.failures.saturating_add(1);
            if b.failures >= self.open_after {
                b.opened_at_ms = Some(now_ms);
            }
        }
    }

    /// Indices of enclaves whose executor the market registers, the
    /// epoch's designated poster first (rotating with the epoch).
    pub fn eligible(&self, m: &MarketAccount, epoch: u64) -> Vec<usize> {
        let mut out: Vec<usize> = (0..self.list.len())
            .filter(|i| m.executor_slot(&self.list[*i].executor).is_some())
            .collect();
        if !out.is_empty() {
            let k = usize::try_from(epoch % u64::try_from(out.len()).unwrap_or(1)).unwrap_or(0);
            out.rotate_left(k);
        }
        out
    }
}

/// [`ExecClient`] over `SignedClient` (mutual TLS in production).
pub struct HttpExecClient {
    enclaves: Vec<(String, SignedClient)>,
}

impl core::fmt::Debug for HttpExecClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpExecClient")
            .field("enclaves", &self.enclaves.len())
            .finish()
    }
}

impl HttpExecClient {
    pub fn new(enclaves: Vec<(String, SignedClient)>) -> Self {
        Self { enclaves }
    }

    fn client(&self, i: usize) -> Result<&(String, SignedClient), ExecClientError> {
        self.enclaves
            .get(i)
            .ok_or(ExecClientError::UnknownEnclave(i))
    }

    async fn call(
        &self,
        i: usize,
        path: &str,
        kind: MessageKind,
        body: Vec<u8>,
        expect: MessageKind,
    ) -> Result<Vec<u8>, ExecClientError> {
        let (url, client) = self.client(i)?;
        match client.call(&format!("{url}{path}"), kind, body).await {
            Ok(env) if env.kind == expect => Ok(env.body),
            Ok(env) if env.kind == MessageKind::ErrorResponse => Err(refusal(&env.body)),
            Ok(env) => Err(ExecClientError::Refused {
                code: "BadResponse".into(),
                detail: format!("unexpected {:?} response", env.kind),
            }),
            Err(ClientError::Refused { envelope, .. })
                if envelope.kind == MessageKind::ErrorResponse =>
            {
                Err(refusal(&envelope.body))
            }
            Err(e) => Err(e.into()),
        }
    }
}

fn refusal(body: &[u8]) -> ExecClientError {
    match ErrorResponse::decode_exact(body) {
        Ok(r) => ExecClientError::Refused {
            code: format!("{:?}", r.code),
            detail: r.detail,
        },
        Err(e) => ExecClientError::Decode(e),
    }
}

impl ExecClient for HttpExecClient {
    fn execute(
        &self,
        enclave: usize,
        req: Arc<ExecuteRequest>,
    ) -> BoxFuture<'_, Result<ExecuteReady, ExecClientError>> {
        Box::pin(async move {
            let body = self
                .call(
                    enclave,
                    "/enclave/v1/execute",
                    MessageKind::ExecuteRequest,
                    req.to_bytes(),
                    MessageKind::ExecuteReady,
                )
                .await?;
            Ok(ExecuteReady::decode_exact(&body)?)
        })
    }

    fn publish(
        &self,
        enclave: usize,
        req: PublishRequest,
    ) -> BoxFuture<'_, Result<ExecutePosted, ExecClientError>> {
        Box::pin(async move {
            let body = self
                .call(
                    enclave,
                    "/enclave/v1/publish",
                    MessageKind::PublishRequest,
                    req.to_bytes(),
                    MessageKind::ExecutePosted,
                )
                .await?;
            Ok(ExecutePosted::decode_exact(&body)?)
        })
    }

    /// The identity route is plain JSON over HTTP GET, and the node's
    /// manifest has no general HTTP client. Start-up treats the
    /// platform check as not performed: refused in production unless
    /// `execution.allow_unverified_platform`, a warning otherwise.
    fn identity(&self, enclave: usize) -> BoxFuture<'_, Result<EnclaveIdentity, ExecClientError>> {
        Box::pin(async move {
            self.client(enclave)?;
            Err(ExecClientError::Refused {
                code: "Unavailable".into(),
                detail: "this build cannot fetch /enclave/v1/identity".into(),
            })
        })
    }
}

/// An `ExecuteReady` the node accepted from enclave `index`.
#[derive(Clone, Debug)]
struct Ready {
    index: usize,
    ready: ExecuteReady,
}

/// The checks of one `ExecuteReady`: the pinned executor, our header and a
/// valid co-signature over its outcome.
fn check_ready(
    ready: &ExecuteReady,
    market: &[u8; 32],
    epoch: u64,
    header_digest: &Hash32,
    executor: &[u8; 32],
) -> Result<(), &'static str> {
    if ready.executor.0 != *executor {
        return Err("from another executor than the pinned one");
    }
    if ready.header_digest != *header_digest {
        return Err("for another header");
    }
    let d = cosign_digest(market, EpochId(epoch), header_digest, &ready.outcome_digest);
    verify_digest(executor, &d, &ready.cosign).map_err(|_| "co-signature does not verify")
}

/// The readies persisted in the epoch's attempt rows.
async fn persisted_readies(
    ctx: &JobCtx,
    e: u64,
    header_digest: &Hash32,
) -> Step<BTreeMap<usize, Ready>> {
    let mut out = BTreeMap::new();
    for a in ctx.repo.attempts(ctx.market, e).await? {
        if a.result.as_deref() != Some("ready") {
            continue;
        }
        let Ok(index) = a.enclave.parse::<usize>() else {
            continue;
        };
        let Some(info) = ctx.enclaves.list.get(index) else {
            continue;
        };
        let Some(bytes) = a.detail.as_deref().and_then(|d| hex::decode(d).ok()) else {
            continue;
        };
        let Ok(ready) = ExecuteReady::decode_exact(&bytes) else {
            continue;
        };
        if check_ready(&ready, &ctx.market, e, header_digest, &info.executor).is_ok() {
            out.insert(index, Ready { index, ready });
        }
    }
    Ok(out)
}

/// Attempts made per enclave so far (execute requests only).
async fn attempts_per_enclave(ctx: &JobCtx, e: u64) -> Step<BTreeMap<usize, u32>> {
    let mut out = BTreeMap::new();
    for a in ctx.repo.attempts(ctx.market, e).await? {
        if let Ok(i) = a.enclave.parse::<usize>() {
            *out.entry(i).or_default() += 1;
        }
    }
    Ok(out)
}

/// The provenance of every envelope: the grant of the session that
/// submitted it and the session's signature over the submission.
async fn provenance(ctx: &JobCtx, e: u64, closed: &ClosedBatch) -> Step<Provenance> {
    let subs = ctx.repo.submissions(ctx.market, e).await?;
    let by_key: BTreeMap<_, _> = subs
        .iter()
        .filter_map(|s| s.wallet.map(|w| ((s.commitment, w), s)))
        .collect();
    let mut grants: Vec<GrantRecord> = Vec::new();
    let mut grant_index: BTreeMap<[u8; 32], u32> = BTreeMap::new();
    let mut entries = Vec::with_capacity(closed.envelopes.len());
    let none = ProvenanceEntry {
        grant: ProvenanceEntry::NO_GRANT,
        session_signature: Signature([0; 64]),
    };
    for (env, wallet) in closed.envelopes.iter().zip(&closed.submitters) {
        if *wallet == [0; 32] {
            entries.push(none);
            continue;
        }
        let Some(row) = by_key.get(&(env.commitment, *wallet)) else {
            entries.push(none);
            continue;
        };
        let Ok(sub) = Submission::decode_exact(&row.submission) else {
            entries.push(none);
            continue;
        };
        let session = sub.trader.0;
        let grant = match grant_index.get(&session) {
            Some(g) => *g,
            None => match ctx.repo.session(session).await? {
                Some(s) => {
                    let g = u32::try_from(grants.len()).unwrap_or(u32::MAX);
                    grants.push(GrantRecord {
                        text: s.grant_text,
                        signature: Signature(s.signature),
                        method: s.method,
                    });
                    grant_index.insert(session, g);
                    g
                }
                None => ProvenanceEntry::NO_GRANT,
            },
        };
        entries.push(ProvenanceEntry {
            grant,
            session_signature: sub.signature,
        });
    }
    Ok(Provenance { grants, entries })
}

/// The `ExecuteRequest` of a sealed epoch.
async fn request(ctx: &JobCtx, row: &EpochRow) -> Step<(Arc<ExecuteRequest>, Hash32, ClosedBatch)> {
    let e = row.epoch;
    let (_, batch_bytes) = ctx
        .repo
        .sealed(ctx.market, e)
        .await?
        .ok_or_else(|| Stop::Failed(format!("sealed batch of epoch {e} is missing")))?;
    let batch = ExecutionBatch::decode_exact(&batch_bytes)
        .map_err(|err| Stop::Failed(format!("sealed batch does not decode: {err}")))?;
    let header_digest = batch.header.digest();
    let closed = crate::market::store::closed_batch(&ctx.repo, ctx.market, e)
        .await?
        .ok_or_else(|| Stop::Failed(format!("closed batch of epoch {e} is missing")))?;
    let closed = ClosedBatch::decode_exact(&closed)
        .map_err(|err| Stop::Failed(format!("closed batch does not decode: {err}")))?;
    let bundle = match ctx.keys.get(e) {
        Some(b) => b.bundle,
        None => {
            let bytes = ctx
                .repo
                .key_bundle(ctx.market, e)
                .await?
                .ok_or_else(|| Stop::Failed(format!("key bundle of epoch {e} is missing")))?;
            timescales_service::wire::EpochKeyBundle::decode_exact(&bytes)
                .map_err(|err| Stop::Failed(format!("key bundle does not decode: {err}")))?
        }
    };
    let provenance = provenance(ctx, e, &closed).await?;
    let req = ExecuteRequest {
        version: ExecuteRequest::VERSION,
        market: ctx.market,
        commit_slot: row.commit_slot.unwrap_or(0),
        batch,
        bundle,
        committee: ctx.committee.clone(),
        price_commitment: row.price_commitment.unwrap_or_default(),
        provenance,
    };
    Ok((Arc::new(req), header_digest, closed))
}

/// Execute (phases 8 -> 9 -> 10).
pub(crate) async fn execute_job(ctx: &JobCtx, e: u64) -> Step<JobOutput> {
    let row = ctx.row(e).await?;
    if !matches!(row.phase, Phase::Sealed | Phase::Executing) {
        return Ok(JobOutput::Row(Box::new(row)));
    }
    let (state, batch) = ctx.chain_state(e).await?;
    match action(Some(row.phase), state) {
        Action::Exec => {}
        Action::Fetch | Action::FetchSettle | Action::FetchSettled => {
            return Ok(JobOutput::Row(Box::new(fetch_and_post(ctx, e).await?)));
        }
        Action::MarkAborted => {
            return Ok(JobOutput::Row(Box::new(
                ctx.mark_aborted(e, batch.as_ref()).await?,
            )));
        }
        _ => return Err(Stop::Fence(FenceReason::StateDivergence)),
    }
    let Some(batch) = batch else {
        return Err(Stop::Fence(FenceReason::StateDivergence));
    };
    let m = ctx.chain.market(timescales_chain::Level::Confirmed).await?;
    let slot = ctx.chain.slot(timescales_chain::Level::Confirmed).await?;
    let deadline = row
        .reveal_slot
        .unwrap_or(batch.reveal_slot)
        .saturating_add(m.exec_timeout_slots);
    let need = usize::from(m.receipt_quorum.max(1));
    let order = ctx.enclaves.eligible(&m, e);
    let (req, header_digest, closed) = request(ctx, &row).await?;
    let mut readies = persisted_readies(ctx, e, &header_digest).await?;

    if group_reaching(&readies, need, &order).is_none() {
        if slot > deadline {
            let row = ctx
                .begin_abort(
                    e,
                    AbortReason::ExecTimeout,
                    "no receipt quorum by reveal_slot + exec_timeout_slots",
                    Some(deadline + 1),
                )
                .await?;
            return Ok(JobOutput::Row(Box::new(row)));
        }
        dispatch(
            ctx,
            e,
            &row,
            &order,
            &req,
            &header_digest,
            &closed,
            need,
            &mut readies,
        )
        .await?;
    }
    let Some(group) = group_reaching(&readies, need, &order) else {
        return Err(Stop::Retry(
            format!("{} of {need} matching executions so far", readies.len()),
            ctx.exec_cfg.retry_backoff_ms.max(100),
        ));
    };
    publish(ctx, e, &header_digest, group, need).await
}

/// The readies of the first outcome that `need` enclaves agree on, in
/// `order` (the epoch's eligible list, designated poster first), so the
/// designated poster is asked to publish first whenever it is ready.
fn group_reaching(
    readies: &BTreeMap<usize, Ready>,
    need: usize,
    order: &[usize],
) -> Option<Vec<Ready>> {
    let rank = |i: usize| order.iter().position(|o| *o == i).unwrap_or(usize::MAX);
    let mut sorted: Vec<&Ready> = readies.values().collect();
    sorted.sort_by_key(|r| (rank(r.index), r.index));
    let mut groups: Vec<(Hash32, Vec<Ready>)> = Vec::new();
    for r in sorted {
        match groups
            .iter_mut()
            .find(|(d, _)| *d == r.ready.outcome_digest)
        {
            Some((_, g)) => g.push(r.clone()),
            None => groups.push((r.ready.outcome_digest, vec![r.clone()])),
        }
    }
    groups.into_iter().map(|(_, g)| g).find(|g| g.len() >= need)
}

/// Sends the request to `receipt_quorum + spare_executions` enclaves at
/// once and handles each `ExecuteReady` as it arrives: checked, persisted
/// in its attempt row (so a restarted node can still re-send the
/// co-signatures) and added to `readies`. Returns as soon as `need` of
/// them agree. The attempts still outstanding then are recorded as
/// `abandoned` and their requests dropped, so a hung enclave never holds
/// the epoch past the quorum.
/// Best effort: closes the attempt rows a store error left begun but
/// unfinished, so their results are not mistaken for still in flight. They
/// keep counting against `attempts_per_enclave`, as any abandoned attempt
/// does. A store that just failed may refuse these writes too. The job's
/// retry then sees the rows as begun-only, which also counts them.
async fn abandon_after_store_error(ctx: &JobCtx, e: u64, attempts: BTreeMap<usize, u32>) {
    for (i, n) in attempts {
        if let Err(err) = ctx
            .repo
            .finish_attempt(
                ctx.market,
                e,
                n,
                "abandoned",
                "dispatch interrupted by a store error".into(),
            )
            .await
        {
            tracing::warn!(enclave = i, attempt = n, error = %err, "abandoned attempt not recorded");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    ctx: &JobCtx,
    e: u64,
    row: &EpochRow,
    order: &[usize],
    req: &Arc<ExecuteRequest>,
    header_digest: &Hash32,
    closed: &ClosedBatch,
    need: usize,
    readies: &mut BTreeMap<usize, Ready>,
) -> Step<()> {
    let now = ctx.now();
    let tried = attempts_per_enclave(ctx, e).await?;
    let want = need + usize::try_from(ctx.exec_cfg.spare_executions).unwrap_or(0);
    let chosen: Vec<usize> = order
        .iter()
        .copied()
        .filter(|i| !readies.contains_key(i))
        .filter(|i| tried.get(i).copied().unwrap_or(0) < ctx.exec_cfg.attempts_per_enclave)
        .filter(|i| ctx.enclaves.available(*i, now))
        .take(want.saturating_sub(readies.len()))
        .collect();
    if chosen.is_empty() {
        return Ok(());
    }
    // Every attempt row is durable before any request is sent.
    let mut attempts = BTreeMap::new();
    for i in &chosen {
        match ctx
            .repo
            .begin_attempt(ctx.market, e, i.to_string(), now)
            .await
        {
            Ok(n) => {
                attempts.insert(*i, n);
            }
            Err(err) => {
                abandon_after_store_error(ctx, e, attempts).await;
                return Err(err.into());
            }
        }
    }
    if row.phase == Phase::Sealed {
        ctx.advance(e, Phase::Executing, EpochPatch::default())
            .await?;
        ctx.publish(vec![Event::EpochExecuting {
            market: ctx.b58(),
            epoch: U64(e),
        }])
        .await;
    }
    let poster = order.first().copied();
    let role = |i: usize| {
        if Some(i) == poster {
            "poster"
        } else {
            "cosigner"
        }
    };
    let timeout = Duration::from_millis(ctx.exec_cfg.attempt_timeout_ms);
    let started = std::time::Instant::now();
    let mut pending: FuturesUnordered<_> = chosen
        .iter()
        .map(|i| {
            let req = req.clone();
            let exec = ctx.exec.clone();
            let i = *i;
            async move {
                let r = tokio::time::timeout(timeout, exec.execute(i, req)).await;
                (i, r)
            }
        })
        .collect();
    while let Some((i, r)) = pending.next().await {
        let took = started.elapsed();
        let info = &ctx.enclaves.list[i];
        let (result, detail) = match r {
            Ok(Ok(ready)) => {
                match check_ready(&ready, &ctx.market, e, header_digest, &info.executor) {
                    Ok(()) => {
                        ctx.enclaves.success(i);
                        let detail = hex::encode(ready.to_bytes());
                        ban_unauthenticated(ctx, e, closed, &ready).await;
                        readies.insert(i, Ready { index: i, ready });
                        ("ready", detail)
                    }
                    Err(why) => {
                        ctx.enclaves.failure(i, ctx.now());
                        tracing::error!(enclave = i, why, "ExecuteReady refused");
                        ("invalid", why.to_owned())
                    }
                }
            }
            Ok(Err(err)) => {
                ctx.enclaves.failure(i, ctx.now());
                tracing::warn!(enclave = i, error = %err, "execute failed");
                ("error", err.to_string())
            }
            Err(_) => {
                ctx.enclaves.failure(i, ctx.now());
                ("timeout", String::new())
            }
        };
        ctx.metrics.attempt(i, role(i), result, took);
        if let Some(n) = attempts.remove(&i)
            && let Err(err) = ctx
                .repo
                .finish_attempt(ctx.market, e, n, result, detail)
                .await
        {
            drop(pending);
            abandon_after_store_error(ctx, e, attempts).await;
            return Err(err.into());
        }
        if result == "ready" && group_reaching(readies, need, order).is_some() {
            break;
        }
    }
    drop(pending);
    // Neither a success nor a failure of the enclave: its breaker is left
    // alone and the attempt still counts against `attempts_per_enclave`.
    for (i, n) in attempts {
        ctx.metrics
            .attempt(i, role(i), "abandoned", started.elapsed());
        ctx.repo
            .finish_attempt(
                ctx.market,
                e,
                n,
                "abandoned",
                "receipt quorum reached first".into(),
            )
            .await?;
    }
    let digests: std::collections::BTreeSet<Hash32> =
        readies.values().map(|r| r.ready.outcome_digest).collect();
    if digests.len() > 1 {
        ctx.metrics
            .cosign_mismatch
            .get_or_create(&ctx.metrics.market(&ctx.market))
            .inc();
        for r in readies.values() {
            tracing::error!(
                epoch = e,
                executor = %Hex32(r.ready.executor.0),
                outcome = %Hex32(r.ready.outcome_digest.0),
                cosign = %hex::encode(r.ready.cosign.0),
                "TimescalesCosignMismatch: executors disagree on the outcome"
            );
        }
    }
    Ok(())
}

/// Bans the submitting wallets of envelopes an enclave reports
/// unauthenticated, for `ban_epochs`.
async fn ban_unauthenticated(ctx: &JobCtx, e: u64, closed: &ClosedBatch, ready: &ExecuteReady) {
    for i in &ready.unauthenticated {
        let Some(wallet) = closed
            .submitters
            .get(usize::try_from(*i).unwrap_or(usize::MAX))
        else {
            continue;
        };
        if *wallet == [0; 32] {
            continue;
        }
        let until = e.saturating_add(ctx.settings.quota.ban_epochs);
        if let Err(err) = ctx
            .repo
            .ban(ctx.market, *wallet, until, "unauthenticated")
            .await
        {
            tracing::warn!(error = %err, "ban not stored");
            continue;
        }
        ctx.metrics
            .bans
            .get_or_create(
                &ctx.metrics
                    .with(&ctx.market, &[("code", "unauthenticated")]),
            )
            .inc();
        tracing::warn!(
            wallet_tag = %timescales_service::wallet_tag(wallet),
            until,
            "wallet banned: envelope did not authenticate"
        );
    }
}

/// Hands one enclave of `group` the others' co-signatures. The first that
/// returns a checked `ExecutePosted` wins.
async fn publish(
    ctx: &JobCtx,
    e: u64,
    header_digest: &Hash32,
    group: Vec<Ready>,
    need: usize,
) -> Step<JobOutput> {
    let mut last = String::new();
    for poster in &group {
        let cosigs: Vec<(ExecutorId, Signature)> = group
            .iter()
            .filter(|r| r.index != poster.index)
            .take(need - 1)
            .map(|r| (r.ready.executor, r.ready.cosign))
            .collect();
        let req = PublishRequest {
            market: ctx.market,
            epoch: EpochId(e),
            header_digest: *header_digest,
            cosigs,
        };
        let started = std::time::Instant::now();
        let timeout = Duration::from_millis(ctx.exec_cfg.attempt_timeout_ms);
        match tokio::time::timeout(timeout, ctx.exec.publish(poster.index, req)).await {
            Ok(Ok(posted)) => {
                ctx.metrics
                    .attempt(poster.index, "publish", "posted", started.elapsed());
                let cosigs = group
                    .iter()
                    .map(|r| (r.ready.executor.0, r.ready.cosign.0))
                    .collect();
                let row = accept_posted(ctx, e, posted, cosigs, Expect::Receipt).await?;
                return Ok(JobOutput::Row(Box::new(row)));
            }
            Ok(Err(ExecClientError::Refused { code, detail })) if code == "QuorumPending" => {
                return Err(Stop::Retry(format!("quorum pending: {detail}"), 1_000));
            }
            Ok(Err(err)) => {
                ctx.metrics
                    .attempt(poster.index, "publish", "error", started.elapsed());
                tracing::warn!(enclave = poster.index, error = %err, "publish failed");
                last = err.to_string();
            }
            Err(_) => last = "publish timed out".into(),
        }
    }
    // The receipt may have landed although every answer was lost.
    if let Some(b) = ctx.batch(e).await?
        && b.status >= BatchStatus::ReceiptPosted
    {
        return Ok(JobOutput::Row(Box::new(fetch_and_post(ctx, e).await?)));
    }
    Err(Stop::Retry(format!("no poster published: {last}"), 1_000))
}

/// Which chain digest the posted receipt must match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// Our poster's receipt: `H(receipt) == Batch.receipt`.
    Receipt,
    /// A re-executing enclave's receipt for the same outcome:
    /// `outcome.digest == Batch.outcome_digest` (fetch).
    Outcome,
}

fn check_failure(ctx: &JobCtx, check: &str, detail: String) -> Stop {
    ctx.metrics
        .receipt_check_failures
        .get_or_create(&ctx.metrics.with(&ctx.market, &[("check", check)]))
        .inc();
    tracing::error!(check, detail = %detail, "ReceiptCheckFailure: the posted receipt fails a node check");
    Stop::Failed(format!("receipt check {check}: {detail}"))
}

/// The executing-phase checks on an `ExecutePosted`, the co-signatures the
/// chain is missing, the result stored, the artifacts public once the
/// quorum is on chain, and the epoch moved to `posted`.
async fn accept_posted(
    ctx: &JobCtx,
    e: u64,
    posted: ExecutePosted,
    cosigs: Vec<([u8; 32], [u8; 64])>,
    expect: Expect,
) -> Step<EpochRow> {
    let receipt = posted.receipt;
    let artifacts = posted.artifacts;
    let m = ctx.chain.market(Level::Confirmed).await?;
    let header = ctx.repo.sealed(ctx.market, e).await?.map(|(h, _)| h);
    let batch = ctx
        .batch(e)
        .await?
        .ok_or(Stop::Fence(FenceReason::StateDivergence))?;
    if let Some(h) = &header
        && timescales_core::crypto::hash(timescales_core::crypto::domain::BATCH_HEADER, h)
            != batch.header_digest
        && batch.status >= BatchStatus::ReceiptPosted
    {
        tracing::error!(epoch = e, "the posted header is not ours");
        return Err(Stop::Fence(FenceReason::StateDivergence));
    }
    check_receipt(ctx, e, &receipt, &artifacts, &m, &batch, expect).await?;
    let prior = ctx.prior_state(e).await?;
    let mut next = prior;
    next.apply(
        EpochId(e),
        ctx.settings.params.max_order_lifetime,
        artifacts.fills.iter().map(|f| (f.commitment, f.quantity)),
        artifacts.cancelled.iter().copied(),
    );
    if next.root() != receipt.outcome.next_state_root {
        return Err(check_failure(
            ctx,
            "next_state_root",
            "replayed order state differs".into(),
        ));
    }

    let result = PostedResult {
        market: ctx.market,
        epoch: e,
        receipt: receipt.to_bytes(),
        artifacts: artifacts.to_bytes(),
        attestation: (!posted.attestation.is_empty()).then(|| posted.attestation.clone()),
        cosigs: cosigs.clone(),
        fills: artifacts
            .fills
            .iter()
            .enumerate()
            .map(|(i, f)| FillRow {
                idx: u32::try_from(i).unwrap_or(u32::MAX),
                commitment: f.commitment,
                trader: f.trader.0,
                book: f.book as u8,
                side: f.side as u8,
                role: f.role as u8,
                qty: f.quantity.0,
                tick: f.tick.0,
            })
            .collect(),
        deltas: artifacts
            .settlement
            .deltas
            .iter()
            .enumerate()
            .map(|(i, d)| DeltaRow {
                idx: u32::try_from(i).unwrap_or(u32::MAX),
                trader: d.trader.0,
                base: d.base,
                quote: d.quote,
            })
            .collect(),
        cancelled: artifacts.cancelled.clone(),
        order_state: next.to_bytes(),
        order_state_root: next.root(),
    };
    ctx.repo.put_result(result).await.or_else(|err| match err {
        // Another receipt for the same outcome (a fetch after our own post).
        timescales_service::store::StoreError::Conflict(_) => Ok(()),
        other => Err(other),
    })?;

    let batch = ensure_quorum(ctx, e, &m, batch, &cosigs).await?;
    let have = (batch.cosign_bitmap & m.live_slots()).count_ones();
    let need = u32::from(m.receipt_quorum);
    if header.is_some() {
        ctx.repo.set_artifacts_public(ctx.market, e).await?;
    } else {
        tracing::warn!(epoch = e, "no stored header: artifacts stay private");
    }
    let stored = crate::market::store::result(&ctx.repo, ctx.market, e)
        .await?
        .ok_or_else(|| Stop::Failed("result vanished".into()))?;
    let row = ctx
        .advance(
            e,
            Phase::Posted,
            EpochPatch {
                receipt: Some(stored.receipt.clone()),
                receipt_slot: Some(batch.receipt_slot),
                header: header.map(|h| h.to_vec()),
                ..EpochPatch::default()
            },
        )
        .await?;
    let stored_receipt = ExecutionReceipt::decode_exact(&stored.receipt)
        .map_err(|_| Stop::Failed("stored receipt does not decode".into()))?;
    let mut events = vec![
        Event::EpochQuorum {
            market: ctx.b58(),
            epoch: U64(e),
            have,
            need,
        },
        Event::EpochPosted {
            market: ctx.b58(),
            epoch: U64(e),
            receipt_digest: Hex32(stored_receipt.digest().0),
            clearing: stored_receipt
                .outcome
                .clearing
                .iter()
                .map(|p| Clearing {
                    book: book(p.book),
                    tick: U64(p.tick.0),
                    volume: U64(p.volume.0),
                })
                .collect(),
            fill_count: stored_receipt.outcome.fill_count,
            settlement_count: stored_receipt.outcome.settlement_count,
        },
    ];
    // One event per co-signature the chain counts.
    for (slot, executor) in m.executors.iter().enumerate() {
        if *executor != [0; 32] && batch.cosign_bitmap & (1 << slot) != 0 {
            events.push(Event::EpochCosigned {
                market: ctx.b58(),
                epoch: U64(e),
                executor: B58(*executor),
            });
        }
    }
    ctx.publish(events).await;
    Ok(row)
}

pub(crate) fn book(b: timescales_core::BookId) -> timescales_service::api::Book {
    match b {
        timescales_core::BookId::Single => timescales_service::api::Book::Single,
        timescales_core::BookId::MakerAskTakerBid => {
            timescales_service::api::Book::MakerAskTakerBid
        }
        timescales_core::BookId::MakerBidTakerAsk => {
            timescales_service::api::Book::MakerBidTakerAsk
        }
    }
}

async fn check_receipt(
    ctx: &JobCtx,
    e: u64,
    receipt: &ExecutionReceipt,
    artifacts: &ExecutionArtifacts,
    m: &MarketAccount,
    batch: &BatchAccount,
    expect: Expect,
) -> Step<()> {
    receipt
        .verify_signature()
        .map_err(|err| check_failure(ctx, "signature", err.to_string()))?;
    if m.executor_slot(&receipt.executor.0).is_none() {
        return Err(check_failure(
            ctx,
            "executor",
            "not in Market.executors".into(),
        ));
    }
    if receipt.backend != BackendKind::Tee {
        return Err(check_failure(
            ctx,
            "backend",
            format!("{:?}", receipt.backend),
        ));
    }
    let o = &receipt.outcome;
    if o.market != ctx.settings.params.market || o.epoch != EpochId(e) {
        return Err(check_failure(
            ctx,
            "epoch",
            "for another market or epoch".into(),
        ));
    }
    if batch.status >= BatchStatus::ReceiptPosted && o.header_digest != batch.header_digest {
        return Err(check_failure(
            ctx,
            "header_digest",
            "differs from the batch".into(),
        ));
    }
    artifacts
        .check_against(o)
        .map_err(|err| check_failure(ctx, "artifacts", err.to_string()))?;
    artifacts
        .check_settlement(&ctx.settings.params, EpochId(e))
        .map_err(|err| check_failure(ctx, "settlement", err.to_string()))?;
    let on_chain = match expect {
        Expect::Receipt => receipt.digest() == batch.receipt,
        Expect::Outcome => o.digest() == batch.outcome_digest,
    };
    if !on_chain {
        return Err(check_failure(
            ctx,
            "chain",
            "the batch on chain holds another receipt".into(),
        ));
    }
    Ok(())
}

/// Sends the `CoSignReceipt`s the chain is missing (cranker pays) and waits
/// for the quorum. Artifacts are public only after this.
async fn ensure_quorum(
    ctx: &JobCtx,
    e: u64,
    m: &MarketAccount,
    batch: BatchAccount,
    cosigs: &[([u8; 32], [u8; 64])],
) -> Step<BatchAccount> {
    if m.quorum_met(batch.cosign_bitmap) {
        return Ok(batch);
    }
    let missing: Vec<([u8; 32], [u8; 64])> = cosigs
        .iter()
        .filter(|(k, _)| {
            m.executor_slot(k)
                .is_some_and(|slot| batch.cosign_bitmap & (1 << slot) == 0)
        })
        .copied()
        .collect();
    if !missing.is_empty() && batch.status == BatchStatus::ReceiptPosted {
        ctx.chain
            .ensure_cosigned(e, missing, ctx.cranker.clone())
            .await?;
        ctx.metrics.chain_op("cosign", "ok");
    }
    let deadline = Instant::now() + ctx.wait;
    match ctx
        .chain
        .wait_batch(
            e,
            BatchPredicate::CosignsAtLeast(m.receipt_quorum),
            Level::Confirmed,
            deadline,
        )
        .await
    {
        Ok(b) => Ok(b),
        Err(err) => Err(Stop::Retry(
            format!("receipt quorum not on chain yet: {err}"),
            1_000,
        )),
    }
}

///  "fetch": the posted outcome of epoch `e`, from wherever it still is.
pub(crate) async fn fetch_and_post(ctx: &JobCtx, e: u64) -> Step<EpochRow> {
    let batch = ctx
        .batch(e)
        .await?
        .ok_or(Stop::Fence(FenceReason::StateDivergence))?;
    if batch.status < BatchStatus::ReceiptPosted || batch.status == BatchStatus::Aborted {
        return Err(Stop::Retry("no receipt posted".into(), 1_000));
    }
    if let Some((h, _)) = ctx.repo.sealed(ctx.market, e).await?
        && timescales_core::crypto::hash(timescales_core::crypto::domain::BATCH_HEADER, &h)
            != batch.header_digest
    {
        tracing::error!(
            epoch = e,
            "Batch.header_digest differs from our stored header"
        );
        return Err(Stop::Fence(FenceReason::StateDivergence));
    }
    let row = ctx.row(e).await?;
    if row.phase >= Phase::Posted && row.phase != Phase::Aborting {
        return Ok(row);
    }
    // 1. Local results. 2. The archive.
    let local = crate::market::store::result(&ctx.repo, ctx.market, e).await?;
    let candidate = match local {
        Some(r) => Some((
            r.receipt,
            r.artifacts,
            r.attestation.unwrap_or_default(),
            r.cosigs,
        )),
        None => archived(&ctx.archive, &ctx.market, e).map(|r| {
            (
                r.receipt,
                r.artifacts,
                r.attestation.unwrap_or_default(),
                r.cosigs,
            )
        }),
    };
    if let Some((receipt, artifacts, attestation, cosigs)) = candidate
        && let (Ok(receipt), Ok(artifacts)) = (
            ExecutionReceipt::decode_exact(&receipt),
            ExecutionArtifacts::decode_exact(&artifacts),
        )
    {
        let posted = ExecutePosted {
            receipt,
            artifacts,
            attestation,
            posted: timescales_service::wire::PostedTx {
                signature: [0; 64],
                slot: batch.receipt_slot,
            },
            cosigned: Vec::new(),
        };
        return accept_posted(ctx, e, posted, cosigs, Expect::Outcome).await;
    }
    // 3. Every enclave (idempotent, a poster returns its cached result, an
    // enclave that executed the same outcome co-signs and returns it once
    // the quorum is on chain).
    let header_digest = batch.header_digest;
    let readies = persisted_readies(ctx, e, &header_digest).await?;
    let cosigs: Vec<(ExecutorId, Signature)> = readies
        .values()
        .filter(|r| r.ready.outcome_digest == batch.outcome_digest)
        .map(|r| (r.ready.executor, r.ready.cosign))
        .collect();
    let all: Vec<([u8; 32], [u8; 64])> = cosigs.iter().map(|(k, s)| (k.0, s.0)).collect();
    for i in 0..ctx.enclaves.list.len() {
        let req = PublishRequest {
            market: ctx.market,
            epoch: EpochId(e),
            header_digest,
            cosigs: cosigs
                .iter()
                .filter(|(k, _)| k.0 != ctx.enclaves.list[i].executor)
                .copied()
                .collect(),
        };
        if let Ok(Ok(posted)) = tokio::time::timeout(
            Duration::from_millis(ctx.exec_cfg.attempt_timeout_ms),
            ctx.exec.publish(i, req),
        )
        .await
        {
            return accept_posted(ctx, e, posted, all, Expect::Outcome).await;
        }
    }
    // 4. Re-execution from the stored sealed batch (members re-release for
    // the pinned header while the batch is ReceiptPosted or Verified with
    // nothing applied).
    if ctx.repo.sealed(ctx.market, e).await?.is_some()
        && matches!(
            batch.status,
            BatchStatus::ReceiptPosted | BatchStatus::Verified
        )
        && batch.applied_count == 0
    {
        let (req, _, _) = request(ctx, &row).await?;
        let m = ctx.chain.market(Level::Confirmed).await?;
        for i in ctx.enclaves.eligible(&m, e) {
            let now = ctx.now();
            let n = ctx
                .repo
                .begin_attempt(ctx.market, e, i.to_string(), now)
                .await?;
            let ready = tokio::time::timeout(
                Duration::from_millis(ctx.exec_cfg.attempt_timeout_ms),
                ctx.exec.execute(i, req.clone()),
            )
            .await;
            let Ok(Ok(ready)) = ready else {
                ctx.repo
                    .finish_attempt(ctx.market, e, n, "error", "re-execution failed".into())
                    .await?;
                continue;
            };
            let info = &ctx.enclaves.list[i];
            if check_ready(&ready, &ctx.market, e, &header_digest, &info.executor).is_err()
                || ready.outcome_digest != batch.outcome_digest
            {
                ctx.repo
                    .finish_attempt(ctx.market, e, n, "invalid", "another outcome".into())
                    .await?;
                continue;
            }
            ctx.repo
                .finish_attempt(ctx.market, e, n, "ready", hex::encode(ready.to_bytes()))
                .await?;
            let req = PublishRequest {
                market: ctx.market,
                epoch: EpochId(e),
                header_digest,
                cosigs: Vec::new(),
            };
            match ctx.exec.publish(i, req).await {
                Ok(posted) => {
                    let mut cosigs = all.clone();
                    cosigs.push((ready.executor.0, ready.cosign.0));
                    return accept_posted(ctx, e, posted, cosigs, Expect::Outcome).await;
                }
                Err(err) => tracing::warn!(enclave = i, error = %err, "re-executed publish"),
            }
        }
    }
    ctx.metrics
        .artifacts_lost
        .get_or_create(&ctx.metrics.market(&ctx.market))
        .inc();
    tracing::error!(
        epoch = e,
        "TimescalesArtifactsLost: no source has the posted artifacts; waiting for a timeout or an admin abort"
    );
    Err(Stop::Retry("artifacts unavailable".into(), 30_000))
}

fn archived(archive: &Archive, market: &[u8; 32], e: u64) -> Option<crate::archive::Record> {
    archive.read(market, e).ok().flatten()
}

/// The prior state, as stored for epochs that already settled (used by
/// `recover-state`).
pub fn replay(
    mut table: OrderStateTable,
    epoch: u64,
    lifetime: u32,
    artifacts: &ExecutionArtifacts,
) -> OrderStateTable {
    table.apply(
        EpochId(epoch),
        lifetime,
        artifacts.fills.iter().map(|f| (f.commitment, f.quantity)),
        artifacts.cancelled.iter().copied(),
    );
    table
}
