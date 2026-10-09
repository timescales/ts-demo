//! Event bus: every event is appended to the persisted log first,
//! which assigns its global `seq` and per-topic `topic_seq`, then
//! broadcast. The log keeps `event_log_hours` of events for `since_seq`
//! resume. `stream_id` changes on every boot, so a client that saw another
//! stream resyncs over REST.

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::ws::Utf8Bytes;
use timescales_service::api::{
    B58, Event, STATUS_TOPIC, ServerFrame, ServerMessage, StreamEvent, U64, market_topic,
};
use timescales_service::store::StoreError;
use timescales_service::store::node::{NodeRepo, StoredEvent};
use tokio::sync::{Mutex, broadcast};

use crate::{Address, EventsSince};

/// Broadcast capacity per market.
pub const BROADCAST_PER_MARKET: usize = 1024;

/// Events returned by one `since_seq` read. A client further behind
/// resyncs.
const MAX_REPLAY: u32 = 10_000;

/// What subscribers receive: a stream event with its frame serialised
/// once for every connection.
#[derive(Debug)]
pub struct LiveEvent {
    stream: StreamEvent,
    frame: Utf8Bytes,
}

impl LiveEvent {
    pub fn new(stream: StreamEvent) -> Arc<Self> {
        // Frames are plain data. Serializing them cannot fail.
        let frame = serde_json::to_string(&ServerFrame::new(ServerMessage::Event(stream.clone())))
            .unwrap_or_default();
        Arc::new(Self {
            stream,
            frame: frame.into(),
        })
    }

    /// The event's frame, as it goes on the wire.
    pub fn frame(&self) -> &Utf8Bytes {
        &self.frame
    }
}

impl Deref for LiveEvent {
    type Target = StreamEvent;

    fn deref(&self) -> &StreamEvent {
        &self.stream
    }
}

pub struct EventBus {
    repo: Arc<NodeRepo>,
    tx: broadcast::Sender<Arc<LiveEvent>>,
    /// Serializes append and broadcast, so subscribers see events in `seq`
    /// order.
    order: Mutex<()>,
    head: AtomicU64,
    /// The oldest `seq` in the log, read at boot and after every prune.
    oldest: AtomicU64,
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
        let oldest = first_seq(&repo, head).await?;
        let (tx, _) = broadcast::channel(BROADCAST_PER_MARKET * markets.max(1));
        Ok(Self {
            repo,
            tx,
            order: Mutex::new(()),
            head: AtomicU64::new(head),
            oldest: AtomicU64::new(oldest),
            stream_id,
        })
    }

    pub fn stream_id(&self) -> [u8; 16] {
        self.stream_id
    }

    pub fn head_seq(&self) -> u64 {
        self.head.load(Ordering::Acquire)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LiveEvent>> {
        self.tx.subscribe()
    }

    /// Re-reads the oldest `seq` after a prune. It only moves up, so
    /// prunes that overlap settle on the newest reading.
    pub async fn pruned(&self) -> Result<(), StoreError> {
        let first = first_seq(&self.repo, self.head_seq()).await?;
        self.oldest.fetch_max(first, Ordering::AcqRel);
        Ok(())
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
            let _ = self.tx.send(LiveEvent::new(e.clone()));
            out.push(e);
        }
        Ok(out)
    }

    /// Events after `seq` on `topics` (all topics when empty), or `TooOld`
    /// when the log no longer reaches back to `seq` or the client is more
    /// than [`MAX_REPLAY`] events behind.
    pub async fn since(&self, seq: u64, topics: Vec<String>) -> Result<EventsSince, StoreError> {
        let head = self.head_seq();
        let first = self.oldest.load(Ordering::Acquire);
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

/// The oldest `seq` in the log. An empty log holds everything from the
/// next event on, so `head + 1` stands in.
async fn first_seq(repo: &NodeRepo, head: u64) -> Result<u64, StoreError> {
    let oldest = repo.events_since(0, Vec::new(), 1).await?;
    Ok(oldest.first().map_or(head.saturating_add(1), |e| e.seq))
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
