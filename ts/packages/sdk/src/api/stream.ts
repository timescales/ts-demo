import type { Address } from '@solana/kit';
import { z } from 'zod';
import { decodeAnnouncement } from '../core/protocol/announcement.js';
import { epochBinding } from '../core/protocol/binding.js';
import type { AbortReason } from '../solana/accounts.js';
import {
  AbortReasonSchema,
  B58,
  B64,
  BandSchema,
  CurrentEpochSchema,
  EpochKeySchema,
  Hex32,
  Num,
  PauseReasonSchema,
  TimeMs,
  U64,
  enumOf,
  type CurrentEpoch,
} from './schemas.js';

/**
 * An event of the node's stream. Events are hints: the SDK never
 * changes an order's state on one alone. `epoch.opened` carries the fields
 * the node sends with the event. The `current` it builds has the band,
 * times, terms, announcement, key and the binding derived from the
 * announcement, while fields the event does not carry are empty
 * (`observations`, `parkWindow`, `commitmentBytes`), 'unknown' (`source`,
 * `realSlotsLeft`), null (`previous`, `inflight`) or 0 (`contextSlot`).
 * Fetch `TimescalesApi.current` for the full view.
 */
export type StreamEvent = { seq: bigint; topic: string; topicSeq: bigint; atMs: number } & (
  | { kind: 'key.published'; market: Address; epoch: bigint }
  | { kind: 'epoch.opened'; market: Address; epoch: bigint; current: CurrentEpoch }
  | { kind: 'epoch.closed' | 'epoch.executing'; market: Address; epoch: bigint }
  | {
      kind: 'epoch.committed';
      market: Address;
      epoch: bigint;
      root: Uint8Array;
      count: number;
      slot: bigint;
    }
  | { kind: 'epoch.revealed'; market: Address; epoch: bigint; beacon: Uint8Array }
  | { kind: 'epoch.posted'; market: Address; epoch: bigint; receiptDigest: Uint8Array }
  | { kind: 'epoch.quorum'; market: Address; epoch: bigint; have: number; need: number }
  | { kind: 'epoch.cosigned'; market: Address; epoch: bigint; executor: Address }
  | {
      kind: 'epoch.settlement';
      market: Address;
      epoch: bigint;
      stage: 'verifying' | 'applying' | 'unknown';
      done: number;
      total: number;
    }
  | { kind: 'epoch.settled'; market: Address; epoch: bigint; slot: bigint }
  | {
      kind: 'epoch.aborting' | 'epoch.aborted';
      market: Address;
      epoch: bigint;
      reason: AbortReason;
      earliestSlot?: bigint;
    }
  | { kind: 'intake.paused' | 'intake.resumed'; market: Address; reason?: string }
  | {
      kind: 'governance.pending' | 'governance.applied';
      market: Address;
      change: string;
      etaSlot?: bigint;
    }
  | { kind: 'parked.invalidated'; market: Address; epochs: bigint[] }
  | { kind: 'program.upgraded'; slot: bigint }
  | { kind: 'market.state'; market: Address; state: string; halted: boolean }
  | { kind: 'status.changed' }
  | { kind: 'unknown'; raw: unknown }
);

export type StreamState = 'connecting' | 'live' | 'reconnecting' | 'polling' | 'offline' | 'closed';
export type ResyncReason =
  'gap' | 'lagged' | 'seq_too_old' | 'unknown_seq' | 'stream_changed' | 'reconnected' | 'visible';

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
type Payload = DistributiveOmit<StreamEvent, 'seq' | 'topic' | 'topicSeq' | 'atMs'>;

const SUBPROTOCOL = 'timescales.v1';
const CLOSE_LAGGED = 4008;
/** Non-live longer than two default epoch intervals switches to polling. */
const POLL_AFTER_MS = 20_000;
const POLL_EVERY_MS = 10_000;
/** A visible tab whose last message is older than this catches up over REST. */
const STALE_AFTER_MS = 45_000;

const MarketEpoch = { market: B58, epoch: U64 };

// Event payloads (`timescales_service::api::Event`). `kind` is the tag.
const PAYLOADS: Record<string, z.ZodType<Payload>> = {
  'key.published': z
    .object(MarketEpoch)
    .transform((e): Payload => ({ kind: 'key.published', market: e.market, epoch: e.epoch })),
  'epoch.opened': z
    .object({
      ...MarketEpoch,
      opens_at_ms: TimeMs,
      cutoff_ms: TimeMs,
      band: BandSchema,
      terms_digest: Hex32,
      announcement_b64: B64,
      key: EpochKeySchema,
      current: CurrentEpochSchema.optional(),
    })
    .transform((e, ctx): Payload => {
      if (e.current !== undefined) {
        return { kind: 'epoch.opened', market: e.market, epoch: e.epoch, current: e.current };
      }
      let binding: Uint8Array;
      let priceCommitment: Uint8Array;
      try {
        const a = decodeAnnouncement(e.announcement_b64);
        binding = epochBinding(a.priceCommitment, a.keyDigest, a.committeeDigest);
        priceCommitment = a.priceCommitment;
      } catch {
        ctx.issues.push({ code: 'custom', message: 'invalid announcement', input: e });
        return z.NEVER;
      }
      return {
        kind: 'epoch.opened',
        market: e.market,
        epoch: e.epoch,
        current: {
          market: e.market,
          serverTimeMs: e.opens_at_ms,
          intake: 'open',
          open: {
            epoch: e.epoch,
            opensAtMs: e.opens_at_ms,
            cutoffMs: e.cutoff_ms,
            band: e.band,
            binding,
            termsDigest: e.terms_digest,
            priceCommitment: {
              digest: priceCommitment,
              reference: e.band.reference,
              source: 'unknown',
              observations: [],
              commitmentBytes: new Uint8Array(0),
            },
            announcementBytes: e.announcement_b64,
            key: e.key,
            realSlotsLeft: 'unknown',
          },
          parkWindow: [],
          previous: null,
          inflight: null,
          contextSlot: 0n,
        },
      };
    }),
  'epoch.closed': z
    .object(MarketEpoch)
    .transform((e): Payload => ({ kind: 'epoch.closed', market: e.market, epoch: e.epoch })),
  'epoch.executing': z
    .object(MarketEpoch)
    .transform((e): Payload => ({ kind: 'epoch.executing', market: e.market, epoch: e.epoch })),
  'epoch.committed': z
    .object({ ...MarketEpoch, root: Hex32, count: Num, slot: U64 })
    .transform((e): Payload => ({
      kind: 'epoch.committed',
      market: e.market,
      epoch: e.epoch,
      root: e.root,
      count: e.count,
      slot: e.slot,
    })),
  'epoch.revealed': z.object({ ...MarketEpoch, beacon: Hex32 }).transform((e): Payload => ({
    kind: 'epoch.revealed',
    market: e.market,
    epoch: e.epoch,
    beacon: e.beacon,
  })),
  'epoch.posted': z.object({ ...MarketEpoch, receipt_digest: Hex32 }).transform((e): Payload => ({
    kind: 'epoch.posted',
    market: e.market,
    epoch: e.epoch,
    receiptDigest: e.receipt_digest,
  })),
  'epoch.quorum': z.object({ ...MarketEpoch, have: Num, need: Num }).transform((e): Payload => ({
    kind: 'epoch.quorum',
    market: e.market,
    epoch: e.epoch,
    have: e.have,
    need: e.need,
  })),
  'epoch.cosigned': z.object({ ...MarketEpoch, executor: B58 }).transform((e): Payload => ({
    kind: 'epoch.cosigned',
    market: e.market,
    epoch: e.epoch,
    executor: e.executor,
  })),
  'epoch.settlement': z
    .object({ ...MarketEpoch, stage: enumOf(['verifying', 'applying']), done: Num, total: Num })
    .transform((e): Payload => ({
      kind: 'epoch.settlement',
      market: e.market,
      epoch: e.epoch,
      stage: e.stage,
      done: e.done,
      total: e.total,
    })),
  'epoch.settled': z.object({ ...MarketEpoch, slot: U64 }).transform((e): Payload => ({
    kind: 'epoch.settled',
    market: e.market,
    epoch: e.epoch,
    slot: e.slot,
  })),
  'epoch.aborting': z
    .object({ ...MarketEpoch, reason: AbortReasonSchema, earliest_slot: U64.optional() })
    .transform((e): Payload => ({
      kind: 'epoch.aborting',
      market: e.market,
      epoch: e.epoch,
      reason: e.reason,
      ...(e.earliest_slot !== undefined ? { earliestSlot: e.earliest_slot } : {}),
    })),
  'epoch.aborted': z
    .object({ ...MarketEpoch, reason: AbortReasonSchema })
    .transform((e): Payload => ({
      kind: 'epoch.aborted',
      market: e.market,
      epoch: e.epoch,
      reason: e.reason,
    })),
  'intake.paused': z
    .object({ market: B58, reason: PauseReasonSchema.optional() })
    .transform((e): Payload => ({
      kind: 'intake.paused',
      market: e.market,
      ...(e.reason !== undefined ? { reason: e.reason } : {}),
    })),
  'intake.resumed': z
    .object({ market: B58 })
    .transform((e): Payload => ({ kind: 'intake.resumed', market: e.market })),
  'governance.pending': z
    .object({ market: B58, change: z.string(), eta_slot: U64, due: z.boolean() })
    .transform((e): Payload => ({
      kind: 'governance.pending',
      market: e.market,
      change: e.change,
      etaSlot: e.eta_slot,
    })),
  'governance.applied': z
    .object({ market: B58, change: z.string(), slot: U64 })
    .transform((e): Payload => ({
      kind: 'governance.applied',
      market: e.market,
      change: e.change,
    })),
  'parked.invalidated': z.object({ market: B58, epochs: z.array(U64) }).transform((e): Payload => ({
    kind: 'parked.invalidated',
    market: e.market,
    epochs: e.epochs,
  })),
  'program.upgraded': z
    .object({ slot: U64 })
    .transform((e): Payload => ({ kind: 'program.upgraded', slot: e.slot })),
  'market.state': z
    .object({ market: B58, state: z.string(), halted: z.boolean() })
    .transform((e): Payload => ({
      kind: 'market.state',
      market: e.market,
      state: e.state,
      halted: e.halted,
    })),
  'status.changed': z.object({}).transform((): Payload => ({ kind: 'status.changed' })),
};

/** Decodes an event payload. Unknown kinds and payloads this SDK cannot read become `unknown`. */
export function decodeEvent(raw: unknown): Payload {
  const kind = (raw as { kind?: unknown } | null)?.kind;
  const schema = typeof kind === 'string' ? PAYLOADS[kind] : undefined;
  if (schema === undefined) return { kind: 'unknown', raw };
  const parsed = schema.safeParse(raw);
  return parsed.success ? parsed.data : { kind: 'unknown', raw };
}

const Frame = z.object({ v: z.literal(1), type: z.string() }).loose();
const Subscribed = z.object({
  topics: z.array(z.string()),
  head_seq: U64,
  stream_id: z.string(),
  topic_seqs: z.record(z.string(), U64),
});
const Snapshot = z.object({ topic: z.string(), seq: U64, topic_seq: U64 });
const EventFrame = z.object({
  seq: U64,
  topic: z.string(),
  topic_seq: U64,
  at_ms: TimeMs,
  event: z.unknown(),
});
const Heartbeat = z.object({ stream_id: z.string() });
const ResyncRequired = z.object({
  reason: z.enum(['seq_too_old', 'lagged', 'unknown_seq', 'stream_changed']),
});

type Listener<T> = (x: T) => void;

interface State {
  url: string;
  socketImpl: typeof WebSocket | undefined;
  backoff: { initialMs: number; maxMs: number };
  pollFallback: ((topics: string[]) => Promise<void>) | undefined;
  topics: Set<string>;
  socket: WebSocket | null;
  state: StreamState | null;
  events: Set<Listener<StreamEvent>>;
  states: Set<Listener<StreamState>>;
  resyncs: Set<Listener<ResyncReason>>;
  streamId: string | null;
  lastSeq: bigint | null;
  topicSeqs: Map<string, bigint>;
  /** `since_seq` may be sent on the next subscribe. */
  resumable: boolean;
  resuming: boolean;
  everLive: boolean;
  attempts: number;
  reconnectTimer: ReturnType<typeof setTimeout> | null;
  pollCheck: ReturnType<typeof setTimeout> | null;
  pollTimer: ReturnType<typeof setInterval> | null;
  nonLiveSince: number | null;
  lastMessageAt: number;
  closed: boolean;
}

// The class's declared surface is frozen, so its state lives here.
const STATE = new WeakMap<TimescalesStream, State>();

function stateOf(s: TimescalesStream): State {
  const st = STATE.get(s);
  if (st === undefined) throw new TypeError('TimescalesStream used before construction');
  return st;
}

function emit<T>(listeners: Set<Listener<T>>, x: T): void {
  for (const f of [...listeners]) {
    try {
      f(x);
    } catch {
      // A failing listener must not stop the stream or other listeners.
    }
  }
}

function setState(st: State, next: StreamState): void {
  if (st.state === next) return;
  st.state = next;
  if (next === 'live' || next === 'closed') {
    st.nonLiveSince = null;
    if (st.pollCheck !== null) clearTimeout(st.pollCheck);
    st.pollCheck = null;
  } else {
    st.nonLiveSince ??= Date.now();
    armPollCheck(st);
  }
  emit(st.states, next);
}

/** Switches to polling once the stream has been non-live for {@link POLL_AFTER_MS}. */
function armPollCheck(st: State): void {
  if (st.pollCheck !== null || st.pollTimer !== null || st.nonLiveSince === null) return;
  const wait = Math.max(0, st.nonLiveSince + POLL_AFTER_MS - Date.now());
  st.pollCheck = setTimeout(() => {
    st.pollCheck = null;
    maybePoll(st);
  }, wait);
}

function send(st: State, msg: object): void {
  const ws = st.socket;
  if (ws !== null && ws.readyState === 1) {
    ws.send(JSON.stringify(msg, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)));
  }
}

function sendSubscribe(st: State, topics: string[], resume: boolean): void {
  if (topics.length === 0) return;
  st.resuming = resume && st.lastSeq !== null;
  send(st, {
    op: 'subscribe',
    topics,
    ...(st.resuming && st.lastSeq !== null ? { since_seq: st.lastSeq } : {}),
  });
}

function resync(st: State, reason: ResyncReason): void {
  emit(st.resyncs, reason);
}

/** Forgets resume state and subscribes again without `since_seq` (after a lag or a resync request). */
function restart(st: State): void {
  st.resumable = false;
  st.topicSeqs.clear();
  sendSubscribe(st, [...st.topics], false);
}

function stopPolling(st: State): void {
  if (st.pollTimer !== null) clearInterval(st.pollTimer);
  st.pollTimer = null;
}

function maybePoll(st: State): void {
  if (st.closed || st.pollTimer !== null || st.pollFallback === undefined) return;
  if (st.state === 'live' || st.nonLiveSince === null) return;
  if (Date.now() - st.nonLiveSince < POLL_AFTER_MS) return;
  setState(st, 'polling');
  const poll = st.pollFallback;
  const tick = (): void => {
    poll([...st.topics]).catch(() => undefined);
  };
  tick();
  st.pollTimer = setInterval(tick, POLL_EVERY_MS);
}

function onFrame(st: State, data: unknown): void {
  st.lastMessageAt = Date.now();
  let msg: unknown;
  try {
    msg = JSON.parse(typeof data === 'string' ? data : '');
  } catch {
    return;
  }
  const frame = Frame.safeParse(msg);
  if (!frame.success) return;
  switch (frame.data.type) {
    case 'subscribed': {
      const s = Subscribed.safeParse(msg);
      if (!s.success) return;
      const changed = st.streamId !== null && st.streamId !== s.data.stream_id;
      st.streamId = s.data.stream_id;
      const fresh = changed || !st.resuming;
      for (const topic of s.data.topics) {
        const head = s.data.topic_seqs[topic];
        if (head !== undefined && (fresh || !st.topicSeqs.has(topic)))
          st.topicSeqs.set(topic, head);
      }
      st.resuming = false;
      st.resumable = true;
      const wasReconnect = st.everLive && st.state !== 'live';
      st.everLive = true;
      st.attempts = 0;
      stopPolling(st);
      setState(st, 'live');
      if (changed) resync(st, 'stream_changed');
      else if (wasReconnect) resync(st, 'reconnected');
      return;
    }
    case 'snapshot': {
      const s = Snapshot.safeParse(msg);
      if (!s.success) return;
      if (st.lastSeq === null || s.data.seq > st.lastSeq) st.lastSeq = s.data.seq;
      if (st.topics.has(s.data.topic)) st.topicSeqs.set(s.data.topic, s.data.topic_seq);
      return;
    }
    case 'event': {
      const e = EventFrame.safeParse(msg);
      if (!e.success) return;
      const f = e.data;
      if (st.lastSeq === null || f.seq > st.lastSeq) st.lastSeq = f.seq;
      if (!st.topics.has(f.topic)) return;
      const last = st.topicSeqs.get(f.topic);
      if (last !== undefined && f.topic_seq <= last) return;
      st.topicSeqs.set(f.topic, f.topic_seq);
      if (last !== undefined && f.topic_seq > last + 1n) resync(st, 'gap');
      emit(st.events, {
        seq: f.seq,
        topic: f.topic,
        topicSeq: f.topic_seq,
        atMs: f.at_ms,
        ...decodeEvent(f.event),
      } as StreamEvent);
      return;
    }
    case 'heartbeat': {
      const h = Heartbeat.safeParse(msg);
      if (h.success && st.streamId !== null && h.data.stream_id !== st.streamId) {
        st.streamId = h.data.stream_id;
        resync(st, 'stream_changed');
        restart(st);
      }
      return;
    }
    case 'resync_required': {
      const r = ResyncRequired.safeParse(msg);
      resync(st, r.success ? r.data.reason : 'unknown_seq');
      restart(st);
      return;
    }
    default:
      // pong, error and frame types a newer node adds
      return;
  }
}

function scheduleReconnect(st: State): void {
  if (st.closed || st.reconnectTimer !== null) return;
  const cap = Math.min(st.backoff.maxMs, st.backoff.initialMs * 2 ** st.attempts);
  st.attempts++;
  const delay = Math.floor(Math.random() * cap);
  st.reconnectTimer = setTimeout(() => {
    st.reconnectTimer = null;
    connect(st);
  }, delay);
  setState(st, st.pollTimer !== null ? 'polling' : 'reconnecting');
}

function connect(st: State): void {
  if (st.closed || st.topics.size === 0) return;
  if (st.socketImpl === undefined) {
    // No WebSocket at all: poll right away when the caller can.
    st.nonLiveSince = Date.now() - POLL_AFTER_MS;
    if (st.pollFallback !== undefined) maybePoll(st);
    else setState(st, 'offline');
    return;
  }
  if (st.state !== 'polling') setState(st, st.everLive ? 'reconnecting' : 'connecting');
  let ws: WebSocket;
  try {
    ws = new st.socketImpl(st.url, SUBPROTOCOL);
  } catch {
    scheduleReconnect(st);
    return;
  }
  st.socket = ws;
  ws.addEventListener('open', () => {
    if (st.socket !== ws) return;
    sendSubscribe(st, [...st.topics], st.resumable);
  });
  ws.addEventListener('message', (ev: MessageEvent) => {
    if (st.socket === ws) onFrame(st, ev.data);
  });
  ws.addEventListener('close', (ev: CloseEvent) => {
    if (st.socket !== ws) return;
    st.socket = null;
    if (st.closed) return;
    if (ev.code === CLOSE_LAGGED) {
      st.resumable = false;
      st.topicSeqs.clear();
      resync(st, 'lagged');
    }
    scheduleReconnect(st);
  });
}

/**
 * The node's event stream `GET /v1/stream`. One socket. Topics
 * change live. It reconnects with full-jitter backoff and resumes with
 * `since_seq` only while the `stream_id` is unchanged. A `topic_seq` gap on
 * a subscribed topic, `resync_required`, a changed `stream_id`, close 4008
 * and every reconnect emit `resync`, after which the caller refetches over
 * REST. Non-live for more than two default epoch intervals, it switches to
 * `polling` and calls `pollFallback` every interval until the socket is
 * live again.
 */
export class TimescalesStream {
  constructor(o: {
    url: string;
    WebSocketImpl?: typeof WebSocket;
    backoff?: { initialMs: number; maxMs: number };
    pollFallback?: (topics: string[]) => Promise<void>;
  }) {
    const st: State = {
      url: o.url,
      socketImpl: o.WebSocketImpl ?? (globalThis as { WebSocket?: typeof WebSocket }).WebSocket,
      backoff: o.backoff ?? { initialMs: 500, maxMs: 30_000 },
      pollFallback: o.pollFallback,
      topics: new Set(),
      socket: null,
      state: null,
      events: new Set(),
      states: new Set(),
      resyncs: new Set(),
      streamId: null,
      lastSeq: null,
      topicSeqs: new Map(),
      resumable: false,
      resuming: false,
      everLive: false,
      attempts: 0,
      reconnectTimer: null,
      pollCheck: null,
      pollTimer: null,
      nonLiveSince: null,
      lastMessageAt: Date.now(),
      closed: false,
    };
    STATE.set(this, st);
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => {
        if (st.closed || document.visibilityState !== 'visible') return;
        send(st, { op: 'ping', t: Date.now() });
        if (Date.now() - st.lastMessageAt > STALE_AFTER_MS) resync(st, 'visible');
      });
    }
  }

  subscribe(topics: string[]): void {
    const st = stateOf(this);
    if (st.closed) return;
    const added = topics.filter((t) => !st.topics.has(t));
    for (const t of added) st.topics.add(t);
    if (st.socket === null) {
      if (st.reconnectTimer === null) connect(st);
    } else {
      sendSubscribe(st, added, false);
    }
  }

  unsubscribe(topics: string[]): void {
    const st = stateOf(this);
    const removed = topics.filter((t) => st.topics.delete(t));
    for (const t of removed) st.topicSeqs.delete(t);
    if (removed.length > 0) send(st, { op: 'unsubscribe', topics: removed });
  }

  on(ev: 'event', f: (e: StreamEvent) => void): () => void;
  on(ev: 'state', f: (s: StreamState) => void): () => void;
  on(ev: 'resync', f: (reason: ResyncReason) => void): () => void;
  on(ev: 'event' | 'state' | 'resync', f: (x: never) => void): () => void {
    const st = stateOf(this);
    const set = (ev === 'event' ? st.events : ev === 'state' ? st.states : st.resyncs) as Set<
      Listener<unknown>
    >;
    const listener = f as Listener<unknown>;
    set.add(listener);
    return () => {
      set.delete(listener);
    };
  }

  close(): void {
    const st = stateOf(this);
    if (st.closed) return;
    st.closed = true;
    if (st.reconnectTimer !== null) clearTimeout(st.reconnectTimer);
    st.reconnectTimer = null;
    if (st.pollCheck !== null) clearTimeout(st.pollCheck);
    st.pollCheck = null;
    stopPolling(st);
    const ws = st.socket;
    st.socket = null;
    ws?.close(1000);
    setState(st, 'closed');
  }
}
