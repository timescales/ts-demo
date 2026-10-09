//! The event stream `GET /v1/stream`.
//!
//! A connection subscribes to topics (`status`, `market:<b58>`). A fresh
//! subscription answers `subscribed` with each topic's current
//! `topic_seq`, then one `snapshot` per market topic. Live events follow.
//! A subscription with `since_seq` replays the log after it instead, but
//! only for an unchanged `stream_id` and a `since_seq` the log still holds.
//! Otherwise the client gets `resync_required` and subscribes again without
//! it. Live events go through a bounded send queue: a client that cannot
//! keep up is closed with 4008, and one that fell behind the node's
//! broadcast gets `resync_required { lagged }`.
//!
//! The upgrade checks `Origin` against `cors_allowed_origins` when the
//! request has one. Clients that are not browsers send none and are
//! admitted, since the check exists to stop other sites' pages.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequest, Request, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use timescales_service::api::{
    B58, ClientMessage, ErrorCode, Hex, RateLimitScope, ResyncReason, STATUS_TOPIC,
    STREAM_SUBPROTOCOL, ServerFrame, ServerMessage, U64,
};
use tokio::sync::{broadcast, mpsc};

use super::Ctx;
use super::errors::ApiError;
use super::limits::{Gcra, IpKey, NodeClock, origin_allowed, peer_of, request_ip_key};
use crate::EventsSince;
use crate::events::LiveEvent;

/// Close codes.
pub(crate) const CLOSE_BAD_MESSAGE: u16 = 4001;
pub(crate) const CLOSE_LAGGED: u16 = 4008;
pub(crate) const CLOSE_TOO_MANY_SUBSCRIPTIONS: u16 = 4009;
pub(crate) const CLOSE_RATE_LIMITED: u16 = 4029;
pub(crate) const CLOSE_DRAINING: u16 = 4503;

/// Pages of the event log replayed for one `since_seq` before the client
/// is told to resynchronise instead.
const MAX_REPLAY_PAGES: usize = 64;

/// Open stream connections, in total and per client.
#[derive(Debug, Default)]
pub(crate) struct Connections {
    total: AtomicUsize,
    per_ip: Mutex<HashMap<IpKey, u32>>,
}

/// One admitted connection. Released when dropped.
struct Admitted {
    ctx: Ctx,
    key: IpKey,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let c = &self.ctx.streams;
        c.total.fetch_sub(1, Ordering::SeqCst);
        let mut per_ip = c.per_ip.lock();
        if let Some(n) = per_ip.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per_ip.remove(&self.key);
            }
        }
    }
}

fn admit(ctx: &Ctx, key: IpKey) -> Option<Admitted> {
    let c = &ctx.streams;
    let max_total = usize::try_from(ctx.cfg.ws_max_connections).unwrap_or(usize::MAX);
    let mut per_ip = c.per_ip.lock();
    let mine = per_ip.get(&key).copied().unwrap_or(0);
    if c.total.load(Ordering::SeqCst) >= max_total || mine >= ctx.cfg.ws_max_connections_per_ip {
        return None;
    }
    c.total.fetch_add(1, Ordering::SeqCst);
    per_ip.insert(key, mine + 1);
    Some(Admitted {
        ctx: ctx.clone(),
        key,
    })
}

/// Checks `Origin`, the subprotocol and the connection limits before the
/// upgrade. Over a limit the answer is 503 `OVERLOADED`.
pub(crate) async fn upgrade(State(ctx): State<Ctx>, req: Request) -> Response {
    let headers = req.headers().clone();
    let key = request_ip_key(&ctx, &headers, peer_of(&req));
    if !origin_allowed(&headers, &ctx.cfg.cors_allowed_origins) {
        return ApiError::bad_request("origin", "this origin may not open the stream")
            .into_response();
    }
    let offered = offered_protocols(&headers);
    if !offered.is_empty() && !offered.iter().any(|p| p == STREAM_SUBPROTOCOL) {
        return ApiError::bad_request(
            "sec-websocket-protocol",
            format!("the stream speaks {STREAM_SUBPROTOCOL}"),
        )
        .into_response();
    }
    let ws = match WebSocketUpgrade::from_request(req, &ctx).await {
        Ok(ws) => ws,
        Err(e) => {
            return ApiError::bad_request("upgrade", format!("not a WebSocket upgrade: {e}"))
                .into_response();
        }
    };
    let Some(admitted) = admit(&ctx, key) else {
        return ApiError::new(ErrorCode::Overloaded, "too many stream connections")
            .with_retry_after_ms(5000)
            .into_response();
    };
    let inbound = usize::try_from(ctx.cfg.ws_inbound_max_bytes).unwrap_or(usize::MAX);
    let ws = ws
        .protocols([STREAM_SUBPROTOCOL])
        // Oversized frames are read up to a bound and refused with 4001.
        .max_message_size(inbound.saturating_mul(4).max(1024))
        .max_frame_size(inbound.saturating_mul(4).max(1024));
    ws.on_upgrade(move |socket| run(ctx, socket, admitted))
}

fn offered_protocols(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(axum::http::header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v: &HeaderValue| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect()
}

fn frame(message: ServerMessage) -> String {
    // Frames are plain data. Serializing them cannot fail.
    serde_json::to_string(&ServerFrame::new(message)).unwrap_or_default()
}

fn error_frame(code: ErrorCode, detail: impl Into<String>) -> String {
    frame(ServerMessage::Error {
        code,
        detail: detail.into(),
    })
}

/// Why the connection ends.
#[derive(Debug, PartialEq, Eq)]
enum End {
    /// The client closed or the socket failed.
    Gone,
    Close(u16, &'static str),
}

/// Per-topic delivery floors: a live event is sent only when it is newer
/// than both.
#[derive(Clone, Copy, Debug, Default)]
struct Floor {
    seq: u64,
    topic_seq: u64,
}

struct Conn {
    ctx: Ctx,
    out: mpsc::Sender<Utf8Bytes>,
    topics: BTreeMap<String, Floor>,
    head_seq: u64,
    inbound: Gcra<u8>,
}

/// The `meta` key under which the store keeps a topic's last `topic_seq`.
/// `NodeRepo::meta` takes `&'static str`. Keys are made only for topics
/// that name a configured market or the status topic, so their number is
/// bounded and each is leaked once.
fn topic_key(topic: &str) -> &'static str {
    static KEYS: OnceLock<Mutex<HashMap<String, &'static str>>> = OnceLock::new();
    let mut keys = KEYS.get_or_init(Mutex::default).lock();
    if let Some(k) = keys.get(topic) {
        return k;
    }
    let k: &'static str = Box::leak(format!("topic_seq:{topic}").into_boxed_str());
    keys.insert(topic.to_owned(), k);
    k
}

impl Conn {
    /// Queues a frame. A full queue means the client cannot keep up.
    fn send(&self, text: impl Into<Utf8Bytes>) -> Result<(), End> {
        match self.out.try_send(text.into()) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(End::Close(CLOSE_LAGGED, "lagged")),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(End::Gone),
        }
    }

    /// Queues a frame and waits for room: answers to a subscribe, whose
    /// number the subscription limit bounds, and replays.
    async fn send_wait(&self, text: String) -> Result<(), End> {
        self.out.send(text.into()).await.map_err(|_| End::Gone)
    }

    fn valid_topic(&self, topic: &str) -> bool {
        if topic == STATUS_TOPIC {
            return true;
        }
        topic
            .strip_prefix("market:")
            .and_then(|m| B58::parse(m).ok())
            .is_some_and(|m| self.ctx.node.market(m.0).is_some())
    }

    async fn topic_head(&self, topic: &str) -> Result<u64, ApiError> {
        match self.ctx.node.store().meta(topic_key(topic)).await? {
            None => Ok(0),
            Some(v) => <[u8; 8]>::try_from(v.as_slice())
                .map(u64::from_le_bytes)
                .map_err(|_| ApiError::internal("malformed topic sequence")),
        }
    }

    /// The newest `seq` of the log.
    fn probe_head(&mut self) -> u64 {
        self.head_seq = self.head_seq.max(self.ctx.node.head_seq());
        self.head_seq
    }

    fn stream_id(&self) -> Hex {
        Hex(self.ctx.node.stream_id().to_vec())
    }

    async fn on_text(&mut self, text: &str) -> Result<(), End> {
        if self.inbound.check(&0).is_err() {
            return Err(End::Close(CLOSE_RATE_LIMITED, "rate limited"));
        }
        let limit = usize::try_from(self.ctx.cfg.ws_inbound_max_bytes).unwrap_or(usize::MAX);
        if text.len() > limit {
            return Err(End::Close(CLOSE_BAD_MESSAGE, "message too large"));
        }
        let Ok(msg) = serde_json::from_str::<ClientMessage>(text) else {
            return Err(End::Close(CLOSE_BAD_MESSAGE, "bad message"));
        };
        match msg {
            ClientMessage::Ping { t } => self.send(frame(ServerMessage::Pong {
                t,
                server_time_ms: self.ctx.now_ms(),
            })),
            ClientMessage::Unsubscribe { topics } => {
                for t in topics {
                    self.topics.remove(&t);
                }
                Ok(())
            }
            ClientMessage::Subscribe {
                topics,
                since_seq,
                stream_id,
            } => {
                self.subscribe(topics, since_seq.map(|s| s.0), stream_id)
                    .await
            }
        }
    }

    async fn subscribe(
        &mut self,
        topics: Vec<String>,
        since_seq: Option<u64>,
        stream_id: Option<Hex>,
    ) -> Result<(), End> {
        let wanted: BTreeSet<String> = topics.into_iter().collect();
        if wanted.is_empty() {
            return self.send(error_frame(
                ErrorCode::BadRequest,
                "subscribe names no topic",
            ));
        }
        if let Some(bad) = wanted.iter().find(|t| !self.valid_topic(t)) {
            return self.send(error_frame(
                ErrorCode::BadRequest,
                format!("unknown topic {bad}"),
            ));
        }
        let after = self
            .topics
            .keys()
            .chain(wanted.iter())
            .collect::<BTreeSet<_>>()
            .len();
        let max = usize::try_from(self.ctx.cfg.ws_max_subscriptions).unwrap_or(usize::MAX);
        if after > max {
            self.send(error_frame(
                ErrorCode::BadRequest,
                format!("at most {max} subscriptions per connection"),
            ))?;
            return Err(End::Close(
                CLOSE_TOO_MANY_SUBSCRIPTIONS,
                "too many subscriptions",
            ));
        }
        match since_seq {
            None => self.subscribe_fresh(wanted).await,
            Some(since) => self.resume(wanted, since, stream_id).await,
        }
    }

    fn internal(&self, e: &ApiError) -> Result<(), End> {
        tracing::error!(code = %e.code, detail = %e.detail, "stream subscription failed");
        self.send(error_frame(ErrorCode::Internal, "internal error"))
    }

    async fn subscribe_fresh(&mut self, wanted: BTreeSet<String>) -> Result<(), End> {
        // Topic heads first, then the snapshots: a change after the head
        // read arrives as a live event, so nothing falls between them.
        let mut heads = BTreeMap::new();
        for t in &wanted {
            match self.topic_head(t).await {
                Ok(h) => {
                    heads.insert(t.clone(), U64(h));
                }
                Err(e) => return self.internal(&e),
            }
        }
        let head = self.probe_head();
        for (t, h) in &heads {
            self.topics.insert(
                t.clone(),
                Floor {
                    seq: 0,
                    topic_seq: h.0,
                },
            );
        }
        self.send_wait(frame(ServerMessage::Subscribed {
            topics: wanted.iter().cloned().collect(),
            head_seq: U64(head),
            stream_id: self.stream_id(),
            topic_seqs: heads.clone(),
        }))
        .await?;
        for (topic, topic_seq) in heads {
            let Some(m) = topic
                .strip_prefix("market:")
                .and_then(|m| B58::parse(m).ok())
            else {
                continue;
            };
            let Some(current) = self.ctx.node.current(m.0) else {
                continue;
            };
            self.send_wait(frame(ServerMessage::Snapshot {
                topic,
                seq: U64(head),
                topic_seq,
                current: Box::new(current),
            }))
            .await?;
        }
        Ok(())
    }

    async fn resume(
        &mut self,
        wanted: BTreeSet<String>,
        since: u64,
        stream_id: Option<Hex>,
    ) -> Result<(), End> {
        let resync = |reason| frame(ServerMessage::ResyncRequired { reason });
        if stream_id.is_some_and(|s| s != self.stream_id()) {
            return self.send(resync(ResyncReason::StreamChanged));
        }
        let head = self.probe_head();
        if since > head {
            return self.send(resync(ResyncReason::UnknownSeq));
        }
        let mut heads = BTreeMap::new();
        for t in &wanted {
            match self.topic_head(t).await {
                Ok(h) => {
                    heads.insert(t.clone(), U64(h));
                }
                Err(e) => return self.internal(&e),
            }
        }
        let topics: Vec<String> = wanted.iter().cloned().collect();
        let mut replay = Vec::new();
        let mut cursor = since;
        let mut caught_up = false;
        for _ in 0..MAX_REPLAY_PAGES {
            match self.ctx.node.events_since(cursor, topics.clone()).await {
                Ok(EventsSince::TooOld { .. }) => {
                    return self.send(resync(ResyncReason::SeqTooOld));
                }
                Ok(EventsSince::Events { events, head_seq }) => {
                    self.head_seq = self.head_seq.max(head_seq);
                    let last = events.last().map(|e| e.seq.0);
                    replay.extend(events.into_iter().filter(|e| e.seq.0 > cursor));
                    match last {
                        Some(l) if l > cursor && l < head_seq => cursor = l,
                        _ => {
                            caught_up = true;
                            break;
                        }
                    }
                }
                Err(e) => return self.internal(&ApiError::from(e)),
            }
        }
        if !caught_up {
            return self.send(resync(ResyncReason::Lagged));
        }
        for t in &wanted {
            let topic_seq = replay
                .iter()
                .filter(|e| &e.topic == t)
                .map(|e| e.topic_seq.0)
                .max()
                .unwrap_or(0);
            self.topics.insert(
                t.clone(),
                Floor {
                    seq: since,
                    topic_seq,
                },
            );
        }
        self.send_wait(frame(ServerMessage::Subscribed {
            topics,
            head_seq: U64(self.head_seq),
            stream_id: self.stream_id(),
            topic_seqs: heads,
        }))
        .await?;
        for event in replay {
            self.send_wait(frame(ServerMessage::Event(event))).await?;
        }
        Ok(())
    }

    fn on_event(&mut self, live: Arc<LiveEvent>) -> Result<(), End> {
        self.head_seq = self.head_seq.max(live.seq.0);
        let Some(floor) = self.topics.get_mut(&live.topic) else {
            return Ok(());
        };
        if live.seq.0 <= floor.seq || live.topic_seq.0 <= floor.topic_seq {
            return Ok(());
        }
        floor.topic_seq = live.topic_seq.0;
        self.send(live.frame().clone())
    }

    fn heartbeat(&self) -> Result<(), End> {
        self.send(frame(ServerMessage::Heartbeat {
            server_time_ms: self.ctx.now_ms(),
            head_seq: U64(self.head_seq),
            stream_id: self.stream_id(),
        }))
    }
}

/// A request to end the connection with a close code.
#[derive(Clone, Copy, Debug)]
struct CloseRequest {
    code: u16,
    reason: &'static str,
    /// Send what is already queued first (an error frame before 4009, say).
    /// Not for a client that cannot keep up.
    flush: bool,
}

/// Sends what a close request asks for: the queued frames when it
/// flushes, then the close frame, within a second.
async fn finish(
    sink: &mut futures::stream::SplitSink<WebSocket, Message>,
    out: &mut mpsc::Receiver<Utf8Bytes>,
    close: Option<CloseRequest>,
) {
    let Some(c) = close else { return };
    let mut pending = Vec::new();
    if c.flush {
        while let Ok(text) = out.try_recv() {
            pending.push(Message::Text(text));
        }
    }
    pending.push(Message::Close(Some(CloseFrame {
        code: c.code,
        reason: c.reason.into(),
    })));
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        for m in pending {
            if sink.send(m).await.is_err() {
                break;
            }
        }
    })
    .await;
}

/// Writes queued frames. On a close request it sends the close frame (or
/// gives up after a second) and stops, even in the middle of a write to a
/// client that does not read.
async fn writer(
    mut sink: futures::stream::SplitSink<WebSocket, Message>,
    mut out: mpsc::Receiver<Utf8Bytes>,
    mut close: mpsc::Receiver<CloseRequest>,
) {
    loop {
        tokio::select! {
            biased;
            c = close.recv() => {
                finish(&mut sink, &mut out, c).await;
                return;
            }
            next = out.recv() => {
                let Some(text) = next else { return };
                tokio::select! {
                    biased;
                    c = close.recv() => {
                        finish(&mut sink, &mut out, c).await;
                        return;
                    }
                    sent = sink.send(Message::Text(text)) => {
                        if sent.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

async fn run(ctx: Ctx, socket: WebSocket, admitted: Admitted) {
    let (sink, mut stream) = socket.split();
    let queue = usize::try_from(ctx.cfg.ws_send_queue.max(1)).unwrap_or(1);
    let (out_tx, out_rx) = mpsc::channel(queue);
    let (close_tx, close_rx) = mpsc::channel(1);
    let writer = tokio::spawn(writer(sink, out_rx, close_rx));
    let mut events = ctx.node.events();
    let rl = &ctx.cfg.rate_limit;
    let mut conn = Conn {
        out: out_tx,
        topics: BTreeMap::new(),
        head_seq: 0,
        inbound: Gcra::new(
            RateLimitScope::Ip,
            rl.per_ip_rps,
            rl.per_ip_burst,
            NodeClock(ctx.clock.clone()),
        ),
        ctx: ctx.clone(),
    };
    // Heartbeats report the log's head from the start.
    conn.probe_head();
    let period = Duration::from_millis(ctx.cfg.ws_heartbeat_ms.max(1));
    let mut heartbeat = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    let end = loop {
        let step = tokio::select! {
            () = ctx.shutdown.cancelled() => Err(End::Close(CLOSE_DRAINING, "draining")),
            msg = stream.next() => match msg {
                Some(Ok(Message::Text(text))) => conn.on_text(text.as_str()).await,
                Some(Ok(Message::Binary(_))) => Err(End::Close(CLOSE_BAD_MESSAGE, "binary frames are not accepted")),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => Ok(()),
                Some(Ok(Message::Close(_)) | Err(_)) | None => Err(End::Gone),
            },
            ev = events.recv() => match ev {
                Ok(event) => conn.on_event(event),
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    conn.send(frame(ServerMessage::ResyncRequired { reason: ResyncReason::Lagged }))
                }
                Err(broadcast::error::RecvError::Closed) => Err(End::Close(CLOSE_DRAINING, "event stream ended")),
            },
            _ = heartbeat.tick() => conn.heartbeat(),
        };
        if let Err(end) = step {
            break end;
        }
    };
    if let End::Close(code, reason) = end {
        let _ = close_tx.try_send(CloseRequest {
            code,
            reason,
            flush: code != CLOSE_LAGGED,
        });
    }
    drop(conn);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    drop(admitted);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_keys_are_made_once() {
        let a = topic_key("status");
        let b = topic_key("status");
        assert!(std::ptr::eq(a, b));
        assert_eq!(a, "topic_seq:status");
    }

    #[test]
    fn resync_frames_name_their_reason() {
        let f = frame(ServerMessage::ResyncRequired {
            reason: ResyncReason::StreamChanged,
        });
        assert_eq!(
            f,
            r#"{"v":1,"type":"resync_required","reason":"stream_changed"}"#
        );
    }
}
