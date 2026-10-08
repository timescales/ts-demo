//! The task around one [`MarketActor`]: it feeds the actor commands, ticks,
//! job results and chain observations, and carries out the effects in the
//! order the actor emitted them.
//!
//! Writes, replies and events go through one ordered pipeline: a write is
//! queued at the store as soon as it is emitted (so concurrent writes share
//! a group commit), and a reply or an event waits until every write emitted
//! before it is durable (an acknowledgement is sent only after its
//! record is). If one of those writes failed, a submission reply is turned
//! into `OVERLOADED` instead of acknowledging anything.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::StreamExt;
use futures::stream::FuturesOrdered;
use parking_lot::Mutex;
use timescales_service::api::{ErrorCode, Event};
use timescales_service::store::StoreError;
use timescales_service::store::node::NodeRepo;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use super::governance::Watch;
use super::jobs::{self, JobCtx};
use super::{Cmd, Effect, MarketActor, MarketView, Now, Persist, Reply, RequestId};
use crate::events::EventBus;
use crate::telemetry::NodeMetrics;
use crate::{Address, SubmitError};

/// Commands the API may queue per market before it sees OVERLOADED.
pub const MAILBOX: usize = 4096;

/// Replies the runtime owes to waiting API calls.
#[derive(Debug, Default)]
pub struct Replies {
    pending: Mutex<HashMap<RequestId, oneshot::Sender<Reply>>>,
    next: AtomicU64,
}

impl Replies {
    /// A request id and the receiver its reply arrives on.
    pub fn register(&self) -> (RequestId, oneshot::Receiver<Reply>) {
        let id = RequestId(self.next.fetch_add(1, Ordering::Relaxed) + 1);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(id, tx);
        (id, rx)
    }

    pub fn cancel(&self, id: RequestId) {
        self.pending.lock().remove(&id);
    }

    fn complete(&self, reply: Reply) {
        let id = match &reply {
            Reply::Submit { request, .. }
            | Reply::Admin { request, .. }
            | Reply::Retract { request, .. } => *request,
        };
        if let Some(tx) = self.pending.lock().remove(&id) {
            // The caller may have timed out. Nothing to do then.
            let _ = tx.send(reply);
        }
    }
}

/// What the rest of the node holds of a running market.
#[derive(Clone, Debug)]
pub struct MarketHandle {
    pub market: Address,
    /// Bounded mailbox for API commands (`try_send`).
    pub tx: mpsc::Sender<Cmd>,
    /// Unbounded mailbox for the node's own commands (jobs, watcher,
    /// bundles): never dropped.
    pub internal: mpsc::UnboundedSender<Cmd>,
    pub view: watch::Receiver<MarketView>,
    pub replies: Arc<Replies>,
}

/// Timing of the runtime loop.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub tick: Duration,
    pub poll: Duration,
    /// Every this many polls also read ProgramData.
    pub program_every: u32,
}

enum Item {
    Persist(Persist),
    Reply(Reply),
    Publish(Event),
}

type WriteFuture = Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send>>;

fn write(repo: &Arc<NodeRepo>, market: Address, p: Persist) -> WriteFuture {
    let repo = repo.clone();
    Box::pin(async move {
        match p {
            Persist::OpenEpoch { row, injected } => repo.open_epoch(*row, injected).await,
            Persist::Advance {
                epoch,
                phase,
                patch,
            } => repo.advance(market, epoch, phase, *patch).await,
            Persist::Submission(row) => repo.insert_submission(*row).await.map(|_| ()),
            Persist::Parked(rows) => repo.insert_parked(rows).await.map(|_| ()),
            Persist::Retract {
                wallet,
                commitment,
                after,
            } => repo
                .retract_parked(market, wallet, commitment, after)
                .await
                .map(|_| ()),
            Persist::BundleServed { epoch } => repo.mark_bundle_served(market, epoch).await,
        }
    })
}

/// Applies writes, replies and events in order (module docs).
async fn pipeline(
    repo: Arc<NodeRepo>,
    market: Address,
    events: Arc<EventBus>,
    replies: Arc<Replies>,
    metrics: Arc<NodeMetrics>,
    clock: Arc<dyn crate::Clock>,
    mut rx: mpsc::UnboundedReceiver<Item>,
) {
    let mut inflight: FuturesOrdered<WriteFuture> = FuturesOrdered::new();
    let mut failed: Option<StoreError> = None;
    while let Some(item) = rx.recv().await {
        match item {
            Item::Persist(p) => {
                let mut fut = write(&repo, market, p);
                // The first poll queues the write at the store, so writes
                // reach it in emission order.
                match futures::poll!(fut.as_mut()) {
                    std::task::Poll::Ready(Err(e)) => failed = Some(e),
                    std::task::Poll::Ready(Ok(())) => {}
                    std::task::Poll::Pending => inflight.push_back(fut),
                }
            }
            Item::Reply(reply) => {
                while let Some(r) = inflight.next().await {
                    if let Err(e) = r {
                        failed = Some(e);
                    }
                }
                let reply = match (failed.take(), reply) {
                    (Some(e), Reply::Submit { request, results }) => {
                        tracing::warn!(error = %e, "submission not durable; refused");
                        Reply::Submit {
                            request,
                            results: results
                                .into_iter()
                                .map(|r| {
                                    r.and(Err(SubmitError {
                                        code: ErrorCode::Overloaded,
                                        details: serde_json::Value::Null,
                                        retry_after_ms: Some(1_000),
                                        refusal: None,
                                    }))
                                })
                                .collect(),
                        }
                    }
                    (Some(e), other) => {
                        tracing::warn!(error = %e, "a write before this reply failed");
                        other
                    }
                    (None, other) => other,
                };
                if let Reply::Submit { results, .. } = &reply {
                    for r in results {
                        let label = match r {
                            Ok(ok) => match ok.status {
                                timescales_service::api::SubmitStatus::Accepted => "accepted",
                                timescales_service::api::SubmitStatus::Parked => "parked",
                            },
                            Err(e) => e.code.as_str(),
                        };
                        metrics.submission(&market, label);
                        if let Err(e) = r
                            && e.refusal.is_some()
                        {
                            metrics
                                .relay_refusals
                                .get_or_create(&metrics.with(&market, &[("code", e.code.as_str())]))
                                .inc();
                        }
                    }
                }
                replies.complete(reply);
            }
            Item::Publish(event) => {
                while let Some(r) = inflight.next().await {
                    if let Err(e) = r {
                        tracing::warn!(error = %e, "a write before this event failed");
                    }
                }
                if let Err(e) = events
                    .publish(vec![(Some(market), event)], clock.now_ms())
                    .await
                {
                    tracing::warn!(error = %e, "event not published");
                }
            }
        }
    }
    while let Some(r) = inflight.next().await {
        if let Err(e) = r {
            tracing::warn!(error = %e, "write failed at shutdown");
        }
    }
}

/// Starts the market: its actor task, its effect pipeline and its chain
/// watcher. The returned future ends after `shutdown` and the grace period.
pub fn spawn(
    actor: MarketActor,
    ctx: Arc<JobCtx>,
    watch_cfg: Watch,
    timing: Timing,
    shutdown: CancellationToken,
    grace: Duration,
) -> (MarketHandle, tokio::task::JoinHandle<()>) {
    let market = actor.address();
    let (tx, mut api_rx) = mpsc::channel(MAILBOX);
    let (internal, mut internal_rx) = mpsc::unbounded_channel();
    let now = Now {
        ms: ctx.clock.now_ms(),
        slot: 0,
    };
    let (view_tx, view) = watch::channel(actor.view(now));
    let replies = Arc::new(Replies::default());
    let handle = MarketHandle {
        market,
        tx,
        internal: internal.clone(),
        view: view.clone(),
        replies: replies.clone(),
    };
    let (items, items_rx) = mpsc::unbounded_channel();
    let pipe = tokio::spawn(pipeline(
        ctx.repo.clone(),
        market,
        ctx.events.clone(),
        replies,
        ctx.metrics.clone(),
        ctx.clock.clone(),
        items_rx,
    ));

    // Chain watcher.
    let watcher = {
        let internal = internal.clone();
        let view = view.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut polls = 0u32;
            loop {
                let current = view.borrow().clone();
                let with_program = polls.is_multiple_of(timing.program_every.max(1));
                polls = polls.wrapping_add(1);
                if let Some(obs) = watch_cfg.observe(&current, with_program).await {
                    let gone = watch_cfg.rescope_keys(&obs).await;
                    if !gone.is_empty() {
                        let _ = internal.send(Cmd::ParkedInvalidated { epochs: gone });
                    }
                    if internal.send(Cmd::ChainObserved(Box::new(obs))).is_err() {
                        break;
                    }
                }
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(timing.poll) => {}
                }
            }
        })
    };

    let task = tokio::spawn(async move {
        let mut actor = actor;
        let mut slot = 0u64;
        let mut ticker = tokio::time::interval(timing.tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut jobs = tokio::task::JoinSet::new();
        let mut stopping = false;
        loop {
            let cmd = tokio::select! {
                biased;
                () = shutdown.cancelled(), if !stopping => {
                    stopping = true;
                    Cmd::Shutdown
                }
                Some(cmd) = internal_rx.recv() => cmd,
                Some(cmd) = api_rx.recv(), if !stopping => cmd,
                _ = ticker.tick() => Cmd::Tick,
                Some(_) = jobs.join_next(), if !jobs.is_empty() => continue,
            };
            if let Cmd::ChainObserved(obs) = &cmd {
                slot = slot.max(obs.slot);
            }
            let now = Now {
                ms: ctx.clock.now_ms(),
                slot,
            };
            let effects = actor.on(cmd, now);
            for effect in effects {
                match effect {
                    Effect::Persist(p) => {
                        let _ = items.send(Item::Persist(p));
                    }
                    Effect::Reply(r) => {
                        let _ = items.send(Item::Reply(r));
                    }
                    Effect::Publish(e) => {
                        let _ = items.send(Item::Publish(*e));
                    }
                    Effect::Spawn(job) => {
                        if stopping && job.relay.is_none() {
                            continue;
                        }
                        let ctx = ctx.clone();
                        let internal = internal.clone();
                        let id = job.id;
                        tracing::debug!(epoch = job.epoch, kind = job.kind.as_str(), "job");
                        jobs.spawn(async move {
                            let result = jobs::run(ctx, job).await;
                            let _ = internal.send(Cmd::JobDone(id, result));
                        });
                    }
                    Effect::Fence(reason) => {
                        tracing::error!(reason = reason.as_str(), "market fenced");
                    }
                    Effect::PauseIntake(reason) => {
                        let r = format!("{reason:?}").to_lowercase();
                        ctx.metrics
                            .intake_paused
                            .get_or_create(&ctx.metrics.with(&market, &[("reason", &r)]))
                            .set(1);
                        tracing::info!(reason = %r, "intake paused");
                    }
                    Effect::ResumeIntake => {
                        ctx.metrics.intake_paused.clear();
                    }
                }
            }
            let v = actor.view(now);
            let labels = ctx.metrics.market(&market);
            ctx.metrics
                .epoch_current
                .get_or_create(&labels)
                .set(i64::try_from(v.next_epoch).unwrap_or(i64::MAX));
            ctx.metrics
                .epoch_last_settled
                .get_or_create(&labels)
                .set(i64::try_from(v.last_settled).unwrap_or(i64::MAX));
            ctx.metrics
                .keys_ready_ahead
                .get_or_create(&labels)
                .set(i64::from(v.keys_ready_ahead));
            view_tx.send_replace(v);
            if stopping {
                break;
            }
        }
        // Let running jobs reach a durable checkpoint (shutdown).
        let _ =
            tokio::time::timeout(grace, async { while jobs.join_next().await.is_some() {} }).await;
        jobs.abort_all();
        watcher.abort();
        drop(items);
        let _ = pipe.await;
    });
    (handle, task)
}
