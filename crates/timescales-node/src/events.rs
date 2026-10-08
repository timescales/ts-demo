//! Event bus: every event is appended to the persisted log first,
//! which assigns its global `seq` and per-topic `topic_seq`, then
//! broadcast. The log keeps `event_log_hours` of events for `since_seq`
//! resume. `stream_id` changes on every boot, so a client that saw another
//! stream resyncs over REST.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use timescales_service::api::{B58, Event, STATUS_TOPIC, StreamEvent, U64, market_topic};
use timescales_service::store::StoreError;
use timescales_service::store::node::{NodeRepo, StoredEvent};
use tokio::sync::{Mutex, broadcast};

use crate::{Address, EventsSince};

/// Broadcast capacity per market.
pub const BROADCAST_PER_MARKET: usize = 1024;

/// Events returned by one `since_seq` read. A client further behind
/// resyncs.
const MAX_REPLAY: u32 = 10_000;

pub struct EventBus {
    repo: Arc<NodeRepo>,
    tx: broadcast::Sender<StreamEvent>,
    /// Serializes append and broadcast, so subscribers see events in `seq`
    /// order.
    order: Mutex<()>,
    head: AtomicU64,
    stream_id: [u8; 16],
}

impl core::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventBus")
            .field("head", &self.head.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// The topic an event belongs to: `market:<b58>` for market events,
/// `status` for the node's status.
pub fn topic_of(market: Option<Address>) -> String {
    match market {
        Some(m) => market_topic(&B58(m)),
        None => STATUS_TOPIC.to_owned(),
    }
}

impl EventBus {
    /// A bus over `repo`'s event log with a new `stream_id`.
    pub async fn new(
        repo: Arc<NodeRepo>,
        markets: usize,
        stream_id: [u8; 16],
    ) -> Result<Self, StoreError> {
        let head = last_seq(&repo).await?;
        let (tx, _) = broadcast::channel(BROADCAST_PER_MARKET * markets.max(1));
        Ok(Self {
            repo,
            tx,
            order: Mutex::new(()),
            head: AtomicU64::new(head),
            stream_id,
        })
    }

    pub fn stream_id(&self) -> [u8; 16] {
        self.stream_id
    }

    pub fn head_seq(&self) -> u64 {
        self.head.load(Ordering::Acquire)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<StreamEvent> {
        self.tx.subscribe()
    }

    /// Appends `events` to the log in one transaction, then broadcasts
    /// them. Lagging receivers are the API's concern (`resync_required`).
    pub async fn publish(
        &self,
        events: Vec<(Option<Address>, Event)>,
        at_ms: u64,
    ) -> Result<Vec<StreamEvent>, StoreError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let _order = self.order.lock().await;
        let mut rows = Vec::with_capacity(events.len());
        for (market, event) in &events {
            let json = serde_json::to_string(event)
                .map_err(|_| StoreError::Corrupt("event does not serialize"))?;
            rows.push((*market, topic_of(*market), at_ms, json));
        }
        let seqs = self.repo.append_events(rows).await?;
        let mut out = Vec::with_capacity(events.len());
        for ((market, event), (seq, topic_seq)) in events.into_iter().zip(seqs) {
            let e = StreamEvent {
                seq: U64(seq),
                topic_seq: U64(topic_seq),
                topic: topic_of(market),
                at_ms,
                event,
            };
            self.head.fetch_max(seq, Ordering::AcqRel);
            // No receiver is fine: nobody is subscribed.
            let _ = self.tx.send(e.clone());
            out.push(e);
        }
        Ok(out)
    }

    /// Events after `seq` on `topics` (all topics when empty), or `TooOld`
    /// when the log no longer reaches back to `seq` or the client is more
    /// than [`MAX_REPLAY`] events behind.
    pub async fn since(&self, seq: u64, topics: Vec<String>) -> Result<EventsSince, StoreError> {
        let head = self.head_seq();
        let oldest = self.repo.events_since(0, Vec::new(), 1).await?;
        let first = oldest.first().map_or(head.saturating_add(1), |e| e.seq);
        // Events after `seq` must all still be in the log.
        if seq.saturating_add(1) < first && seq < head {
            return Ok(EventsSince::TooOld { head_seq: head });
        }
        if head.saturating_sub(seq) > u64::from(MAX_REPLAY) {
            return Ok(EventsSince::TooOld { head_seq: head });
        }
        let stored = self.repo.events_since(seq, topics, MAX_REPLAY).await?;
        let events = stored
            .into_iter()
            .filter_map(|s| decode(&s))
            .collect::<Vec<_>>();
        Ok(EventsSince::Events {
            events,
            head_seq: head,
        })
    }
}

fn decode(s: &StoredEvent) -> Option<StreamEvent> {
    let event: Event = match serde_json::from_str(&s.event) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(seq = s.seq, error = %e, "unreadable event in the log");
            return None;
        }
    };
    Some(StreamEvent {
        seq: U64(s.seq),
        topic_seq: U64(s.topic_seq),
        topic: s.topic.clone(),
        at_ms: s.at_ms,
        event,
    })
}

/// The highest `seq` in the log. 0 for an empty log.
async fn last_seq(repo: &NodeRepo) -> Result<u64, StoreError> {
    repo.store()
        .read(|c| {
            let seq: Option<i64> = c.query_row("SELECT MAX(seq) FROM events", [], |r| r.get(0))?;
            Ok(seq.and_then(|s| u64::try_from(s).ok()).unwrap_or(0))
        })
        .await
}
