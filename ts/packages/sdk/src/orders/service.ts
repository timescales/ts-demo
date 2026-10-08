import type { Address } from '@solana/kit';
import type { TimescalesApi } from '../api/client.js';
import type { ServerClock } from '../api/clock.js';
import type { SubmitItemResult } from '../api/schemas.js';
import type { StreamEvent, TimescalesStream } from '../api/stream.js';
import { b58 } from '../core/encoding/base58.js';
import { b64 } from '../core/encoding/base64.js';
import { equal } from '../core/encoding/bytes.js';
import { hex } from '../core/encoding/hex.js';
import { randomBytes, randomU64 } from '../core/crypto/random.js';
import { sealEnvelope } from '../core/crypto/seal.js';
import { bookFor, maxOrderLots, type MarketParams } from '../core/protocol/params.js';
import { commitment } from '../core/protocol/commitment.js';
import { envelopeDigest } from '../core/protocol/envelope.js';
import type { IntentBody } from '../core/protocol/intent.js';
import { OrderError, validateOrder, type Order } from '../core/protocol/order.js';
import { decodeSubmission } from '../core/protocol/submission.js';
import { TimescalesError } from '../errors.js';
import { journalInternals, openJournal, type Journal } from '../journal/journal.js';
import { availableFor } from '../solana/accounts.js';
import type { TimescalesRpc } from '../solana/rpc.js';
import {
  evidenceRecord,
  failureEvidence,
  refusalEvidence,
  type EvidenceRecord,
} from '../verify/evidence.js';
import type { AppPins, VerifiedMarketContext } from '../verify/market.js';
import { verifyPromise, verifyPromiseDigest, verifyRefusal } from '../verify/promise.js';
import { WalletError, toWalletError, type TraderWallet } from '../wallet/port.js';
import { TradingSession, signIntent } from '../wallet/session.js';
import {
  CheckError,
  firstReachable,
  newWatch,
  parkHorizon,
  refreshCurrent,
  verifyContext,
  type MarketWatch,
  type VerifiedKey,
} from './context.js';
import { electLeader, lockName, type Leadership } from './coordinator.js';
import { TERMINAL, reduceWith } from './lifecycle.js';
import type {
  OrderDraft,
  OrderEvent,
  OrderRecord,
  Participation,
  PreparedOrder,
  ReconcileReport,
  SubmitStep,
} from './model.js';
import { outboxGroups, signedBy } from './outbox.js';
import { updateRecord } from './store.js';
import { IN_FLIGHT, PENDING, resealed, sealedDigests, type Supplement } from './participation.js';
import { wouldSelfTrade } from './selfTrade.js';
import { collateralFor, feeEstimate, worstNotional } from './sizing.js';
import { trackEpoch, type Step } from './tracking.js';
import type { OwnFill } from '../verify/fills.js';

/** What the constructor reads. */
export type OrderServiceDeps = ConstructorParameters<typeof OrderService>[0];

/** Default p95 time a wallet takes to sign, until this one is measured. */
const DEFAULT_SIGN_P95_MS = 15_000;
const DEFAULT_SUBMIT_P95_MS = 1_000;
const SUBMIT_MARGIN_MS = 2_000;
const TICK_MS = 10_000;
const RESEND_EVERY_MS = 15_000;
const CALL_TIMEOUT_MS = 120_000;
/** A clearing is shown as delayed after the epoch interval plus this. */
const CLEARING_GRACE_MS = 30_000;
const SAMPLES = 20;

type Call =
  | { op: 'seal'; id: string; record: OrderRecord }
  | { op: 'cancel'; placement: string; cancel: string; record: OrderRecord }
  | { op: 'reconcile'; fromEpoch: bigint };

type Message =
  | { t: 'records'; from: string; records: OrderRecord[] }
  | { t: 'hello'; from: string }
  | ({ t: 'call'; from: string; callId: string } & Call)
  | {
      t: 'reply';
      to: string;
      callId: string;
      ok: boolean;
      value?: unknown;
      error?: { kind: TimescalesError['kind']; code: string; message: string; retryable: boolean };
    };

interface Pending {
  resolve(v: unknown): void;
  reject(e: unknown): void;
  timer: ReturnType<typeof setTimeout>;
}

interface State {
  api: TimescalesApi;
  rpc: TimescalesRpc;
  stream: TimescalesStream;
  clock: ServerClock;
  pins: readonly AppPins[];
  journal: Journal;
  tabId: string;
  wallet: TraderWallet | null;
  session: TradingSession | null;
  role: 'leader' | 'follower' | null;
  leadership: Leadership | null;
  channel: BroadcastChannel | null;
  markets: Map<Address, MarketWatch>;
  records: Map<string, OrderRecord>;
  listeners: Set<(records: readonly OrderRecord[]) => void>;
  cleanups: (() => void)[];
  timer: ReturnType<typeof setInterval> | null;
  signTimes: number[];
  submitTimes: number[];
  pending: Map<string, Pending>;
  locks: Map<string, Promise<unknown>>;
  queue: Promise<unknown>;
  generation: number;
  lastResendAt: number;
  /** The key of a session the node no longer honours: the outbox waits for a new one. */
  lostSession: string | null;
  disposed: boolean;
}

// The class's declared surface is frozen, so its state lives here.
const STATE = new WeakMap<OrderService, State>();

function stateOf(s: OrderService): State {
  const st = STATE.get(s);
  if (st === undefined) throw new TypeError('OrderService used before construction');
  return st;
}

function p95(samples: readonly number[], fallback: number): number {
  if (samples.length === 0) return fallback;
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1)]!;
}

function remember(samples: number[], ms: number): void {
  samples.push(ms);
  if (samples.length > SAMPLES) samples.shift();
}

/** The signing budget: the wallet's p95 time to sign, 2 s, and the p95 submission time. */
function signBudget(st: State): number {
  return (
    p95(st.signTimes, DEFAULT_SIGN_P95_MS) +
    SUBMIT_MARGIN_MS +
    p95(st.submitTimes, DEFAULT_SUBMIT_P95_MS)
  );
}

function now(st: State): number {
  return Math.floor(st.clock.now());
}

function ev<K extends OrderEvent['kind']>(
  st: State,
  kind: K,
  rest?: Omit<Extract<OrderEvent, { kind: K }>, 'kind' | 'atMs'>,
): OrderEvent {
  return { atMs: now(st), kind, ...(rest ?? {}) } as OrderEvent;
}

function notStarted(): TimescalesError {
  return new TimescalesError({
    kind: 'environment',
    code: 'not_started',
    message: 'call OrderService.start with a wallet and a session first',
  });
}

function started(st: State): { wallet: TraderWallet; session: TradingSession } {
  if (st.disposed || st.wallet === null || st.session === null) throw notStarted();
  return { wallet: st.wallet, session: st.session };
}

/** Never sign with account B while showing account A. */
function checkAccount(st: State, trader: Uint8Array): void {
  const { wallet, session } = started(st);
  if (wallet.address !== session.wallet || !equal(b58.decode(wallet.address, 32), trader)) {
    throw new WalletError(
      'account_changed',
      'the wallet now uses another account than this session',
    );
  }
}

function byAge(a: OrderRecord, b: OrderRecord): number {
  const ta = a.history[0]?.atMs ?? 0;
  const tb = b.history[0]?.atMs ?? 0;
  return ta !== tb ? ta - tb : a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

function snapshot(st: State): OrderRecord[] {
  return [...st.records.values()].sort(byAge);
}

function notify(st: State, broadcast = true): void {
  const list = snapshot(st);
  for (const f of [...st.listeners]) {
    try {
      f(list);
    } catch {
      // A failing listener must not stop the service or the other listeners.
    }
  }
  if (broadcast && st.role === 'leader' && st.channel !== null) {
    post(st, { t: 'records', from: st.tabId, records: list });
  }
}

function post(st: State, m: Message): void {
  try {
    st.channel?.postMessage(m);
  } catch {
    // A closed channel only stops mirroring. The journal stays the source of truth.
  }
}

function keep(st: State, r: OrderRecord): OrderRecord {
  const known = st.records.get(r.id);
  if (known === undefined || known.version <= r.version) {
    st.records.set(r.id, r);
    notify(st);
  }
  return r;
}

/** Writes a new record (version 1). A failed write blocks sealing: nothing was sent. */
async function create(st: State, r: OrderRecord): Promise<OrderRecord> {
  const version = await st.journal.put(r, 0);
  return keep(st, { ...r, version });
}

/** A versioned write of `f(current)` that re-applies `f` after a concurrent write. */
async function update(
  st: State,
  id: string,
  f: (r: OrderRecord) => OrderRecord | null,
): Promise<OrderRecord> {
  const { record } = await updateRecord(st.journal, id, f, () => st.records.get(id));
  return keep(st, record);
}

/** Events that only matter through the change they make. A repeat that changes nothing is not journalled. */
const IDEMPOTENT = new Set<OrderEvent['kind']>([
  'epoch_locked',
  'inclusion',
  'revealed',
  'receipt',
  'fills',
  'settlement',
  'settled',
  'aborted',
  'parked_invalidated',
]);

function sameState(a: OrderRecord['state'], b: OrderRecord['state']): boolean {
  return (
    JSON.stringify(a, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)) ===
    JSON.stringify(b, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v))
  );
}

/** Whether `next` (from the reducer) differs from `r` in anything but its history. */
function changed(r: OrderRecord, next: OrderRecord): boolean {
  if (!sameState(r.state, next.state) || r.filled !== next.filled) return true;
  if (r.fills.length !== next.fills.length || r.evidence.length !== next.evidence.length)
    return true;
  if (r.epochs.size !== next.epochs.size) return true;
  for (const [k, p] of next.epochs) if (r.epochs.get(k) !== p) return true;
  return false;
}

/**
 * A V-6 result the history does not hold yet. It is kept even when the
 * participation's state does not change, because the tracker reads it to
 * know that the check ran.
 */
function firstInclusion(r: OrderRecord, e: OrderEvent): boolean {
  return (
    e.kind === 'inclusion' && !r.history.some((h) => h.kind === 'inclusion' && h.epoch === e.epoch)
  );
}

async function apply(
  st: State,
  id: string,
  e: OrderEvent,
  s: Supplement & { fills?: OwnFill[] } = {},
): Promise<OrderRecord> {
  const before = st.records.get(id);
  const r = await update(st, id, (x) => {
    const next = reduceWith(x, e, s);
    return IDEMPOTENT.has(e.kind) && !changed(x, next) && !firstInclusion(x, e) ? null : next;
  });
  if (before !== undefined && !TERMINAL.has(before.state.kind) && TERMINAL.has(r.state.kind)) {
    void retractEnded(st, before, r);
  }
  return r;
}

async function saveEvidence(st: State, e: EvidenceRecord | undefined): Promise<void> {
  if (e !== undefined) await st.journal.putEvidence(e);
}

/** A failed  check: evidence saved, the order marked, trading on the market stopped. */
async function failCheck(
  st: State,
  r: OrderRecord,
  epoch: bigint,
  check: string,
  reason: string,
  inputs: Record<string, Uint8Array>,
): Promise<OrderRecord> {
  const bytes = failureEvidence({ market: r.market, epoch, check, reason, inputs });
  const evidence = evidenceRecord('verification_failed', r.market, epoch, bytes, now(st));
  await saveEvidence(st, evidence);
  const w = st.markets.get(r.market);
  if (w !== undefined) w.failure = { check, reason };
  return apply(st, r.id, ev(st, 'verification_failed', { check }), { evidenceId: evidence.id });
}

function pinsFor(st: State, market: Address): AppPins {
  const p = st.pins.find((x) => x.market === market);
  if (p === undefined) {
    throw new TimescalesError({
      kind: 'environment',
      code: 'pins_missing',
      message: `the app pins no program, cluster and authority for market ${market}`,
    });
  }
  return p;
}

function watchFor(st: State, market: Address): MarketWatch {
  let w = st.markets.get(market);
  if (w === undefined) {
    w = newWatch(market, pinsFor(st, market));
    st.markets.set(market, w);
  }
  return w;
}

function deps(st: State): { api: TimescalesApi; rpc: TimescalesRpc; clock: ServerClock } {
  return { api: st.api, rpc: st.rpc, clock: st.clock };
}

async function verifyWatch(st: State, w: MarketWatch): Promise<VerifiedMarketContext> {
  try {
    const ctx = await verifyContext(deps(st), w, st.wallet?.address);
    if (st.role === 'leader') subscribeMarket(st, w.market);
    return ctx;
  } catch (e) {
    if (e instanceof CheckError && !e.inconclusive) {
      w.failure = { check: e.check, reason: e.message };
      const epoch = w.current?.open?.epoch ?? 0n;
      const bytes = failureEvidence({
        market: w.market,
        epoch,
        check: e.check,
        reason: e.message,
        inputs: {},
      });
      await st.journal
        .putEvidence(evidenceRecord('verification_failed', w.market, epoch, bytes, now(st)))
        .catch(() => undefined);
    }
    throw e;
  }
}

/**
 * The market's verified context, verifying it first when there is none. A
 * failed check is not re-run here: it keeps blocking the market until the
 * app asks for a re-check through `context` ("Re-check").
 */
async function ensureContext(st: State, market: Address): Promise<MarketWatch> {
  const w = watchFor(st, market);
  if (w.ctx === null) await verifyWatch(st, w);
  return w;
}

/** The epochs an intent may be sealed for: the order's window, or the Cancel's epoch. */
function windowOf(r: OrderRecord): { from: bigint; to: bigint } | null {
  if (r.body.kind === 'place') return { from: r.body.order.validFrom, to: r.body.order.expiresAt };
  if (r.body.kind === 'cancel') return { from: r.body.cancel.epoch, to: r.body.cancel.epoch };
  return null;
}

/**
 * Whether a participation the relay did not take may be sealed again: one
 * invalidated (a committee rotation, a voided cancel epoch) or refused for a
 * missing key, and one refused for the parking quota once its epoch is
 * open. Never one the relay refused as a duplicate: another tab or device
 * holds that commitment's envelope for the epoch.
 */
function resealable(r: OrderRecord, p: Participation, w: MarketWatch): boolean {
  if (p.state.kind !== 'not_submitted') return false;
  let last: Extract<OrderEvent, { kind: 'submitted' }> | undefined;
  for (let i = r.history.length - 1; i >= 0 && last === undefined; i--) {
    const h = r.history[i]!;
    if (h.kind === 'submitted' && h.epoch === p.epoch) last = h;
  }
  if (last?.result === 'refused' && last.code === 'DUPLICATE_COMMITMENT') return false;
  switch (p.state.reason) {
    case 'invalidated':
    case 'key_unavailable':
      return true;
    case 'quota': {
      // A parking refusal is retried once the epoch opens. A refusal in the open epoch is final.
      const open = w.current?.open;
      return open?.epoch === p.epoch && last !== undefined && last.atMs < open.opensAtMs;
    }
    default:
      return false;
  }
}

/** Epochs of the record's window that can be sealed now, with their verified keys. */
function sealable(
  st: State,
  w: MarketWatch,
  r: OrderRecord,
  only?: bigint,
): { epoch: bigint; key: VerifiedKey }[] {
  const c = w.current;
  const span = windowOf(r);
  if (c === null || c.open === null || span === null) return [];
  const open = c.open.epoch;
  const first = c.open.cutoffMs > now(st) ? open : open + 1n;
  const horizon = parkHorizon(w) ?? open;
  const out: { epoch: bigint; key: VerifiedKey }[] = [];
  const lo = span.from > first ? span.from : first;
  const hi = span.to < horizon ? span.to : horizon;
  for (let e = lo; e <= hi; e++) {
    if (only !== undefined && e !== only) continue;
    const key = w.keys.get(e);
    if (key === undefined || (e === open && !w.terms.has(e))) continue;
    const p = r.epochs.get(e);
    if (p === undefined || resealable(r, p, w)) out.push({ epoch: e, key });
  }
  return out;
}

/** Whether no epoch of the window can be reached any more. */
function windowPassed(w: MarketWatch, r: OrderRecord, nowMs: number): boolean {
  const c = w.current;
  const span = windowOf(r);
  if (c === null || c.open === null || span === null) return false;
  const first = c.open.cutoffMs > nowMs ? c.open.epoch : c.open.epoch + 1n;
  return span.to < first;
}

/** Runs `f` with exclusive access to one record's sealing and posting. */
function withRecord<T>(st: State, id: string, f: () => Promise<T>): Promise<T> {
  const before = st.locks.get(id) ?? Promise.resolve();
  const run = before.then(f, f);
  const tail = run.catch(() => undefined);
  st.locks.set(id, tail);
  void tail.then(() => {
    if (st.locks.get(id) === tail) st.locks.delete(id);
  });
  return run;
}

function record(st: State, id: string): OrderRecord {
  const r = st.records.get(id);
  if (r === undefined)
    throw new TimescalesError({ kind: 'storage', code: 'missing', message: `no record ${id}` });
  return r;
}

/** Re-reads the market's verified view: context, open epoch, keys (V-3, V-4) and the trader account. */
async function refreshView(st: State, w: MarketWatch): Promise<void> {
  if (w.ctx === null) {
    await verifyWatch(st, w);
  } else {
    try {
      await refreshCurrent(deps(st), w, undefined, st.wallet?.address);
    } catch (e) {
      if (e instanceof CheckError && !e.inconclusive)
        w.failure = { check: e.check, reason: e.message };
      throw e;
    }
  }
  if (st.role === 'leader') subscribeMarket(st, w.market);
}

/**
 * Follows every epoch the market's records have something in, then marks
 * what follows from the view: pauses, expiries and delayed clearings. In
 * this order, so an order never ends before its last epoch was followed.
 */
async function refreshMarket(st: State, w: MarketWatch): Promise<void> {
  await refreshView(st, w);
  for (const epoch of trackedEpochs(st, w)) await trackOne(st, w, epoch);
  await reviewRecords(st, w);
}

async function reviewRecords(st: State, w: MarketWatch): Promise<void> {
  const c = w.current;
  if (c === null || c.open === null) return;
  const t = now(st);
  const first = c.open.cutoffMs > t ? c.open.epoch : c.open.epoch + 1n;
  const closed = c.open.epoch - 1n;
  for (const r of [...st.records.values()]) {
    if (r.market !== w.market) continue;
    const span = windowOf(r);
    if (span === null) continue;
    const k = r.state.kind;
    // An epoch of the window closed with no participation: the order outlived what was sealed.
    if (
      (k === 'working' || k === 'paused_needs_app') &&
      r.body.kind === 'place' &&
      closed >= span.from &&
      closed <= span.to &&
      !r.epochs.has(closed) &&
      !r.history.some((h) => h.kind === 'epoch_locked' && h.epoch === closed)
    ) {
      await apply(st, r.id, ev(st, 'epoch_locked', { epoch: closed }));
    }
    const live = st.records.get(r.id) ?? r;
    const lk = live.state.kind;
    // A participation still waiting in a closed epoch is followed before the order may end.
    const unfollowed = [...live.epochs.values()].some(
      (p) => PENDING.has(p.state.kind) && p.epoch < first && p.promise !== null,
    );
    if (windowPassed(w, live, t) && !unfollowed) {
      if (
        lk === 'submitting' &&
        ![...live.epochs.values()].some((p) => PENDING.has(p.state.kind))
      ) {
        await apply(
          st,
          r.id,
          ev(st, 'submitted', { epoch: span.to, result: 'refused', code: 'EPOCH_CLOSED' }),
        );
      } else if (
        (lk === 'working' ||
          lk === 'paused_needs_app' ||
          lk === 'reseal_needs_consent' ||
          lk === 'submit_failed') &&
        !live.history.some((h) => h.kind === 'expired')
      ) {
        await apply(st, r.id, ev(st, 'expired'));
      }
    }
    // Clearing taking longer than the interval plus 30 s is shown as delayed.
    const interval = w.ctx?.detail.timing.epochIntervalMs ?? 0;
    for (const p of (st.records.get(r.id) ?? r).epochs.values()) {
      if (p.state.kind !== 'clearing' || p.state.delayed) continue;
      const since = [...(st.records.get(r.id) ?? r).history]
        .reverse()
        .find((h) => h.kind === 'revealed' && h.epoch === p.epoch)?.atMs;
      if (since !== undefined && t - since > interval + CLEARING_GRACE_MS) {
        await update(st, r.id, (x) => {
          const q = x.epochs.get(p.epoch);
          if (q?.state.kind !== 'clearing' || q.state.delayed) return null;
          const epochs = new Map(x.epochs);
          epochs.set(p.epoch, { ...q, state: { kind: 'clearing', delayed: true } });
          return { ...x, epochs };
        });
      }
    }
  }
}

async function applySteps(st: State, steps: readonly Step[]): Promise<void> {
  for (const s of steps) {
    await saveEvidence(st, s.evidence);
    if (s.event.kind === 'verification_failed') {
      const r = st.records.get(s.id);
      const w = r === undefined ? undefined : st.markets.get(r.market);
      if (w !== undefined) w.failure = { check: s.event.check, reason: 'see the saved evidence' };
    }
    await apply(st, s.id, s.event, s.supplement ?? {});
  }
}

/**
 * Epochs worth following in a market, ascending: up to the open one, those
 * with something sealed, parked or in flight, or a pending cancel. A later
 * epoch has not closed, so nothing about it can be checked yet.
 */
function trackedEpochs(st: State, w: MarketWatch): bigint[] {
  const upTo = w.current?.open?.epoch ?? null;
  const out = new Set<bigint>();
  for (const r of st.records.values()) {
    if (r.market !== w.market) continue;
    for (const p of r.epochs.values()) {
      if (PENDING.has(p.state.kind) || IN_FLIGHT.has(p.state.kind)) out.add(p.epoch);
    }
    if (r.state.kind === 'cancel_pending') out.add(r.state.epoch);
  }
  return [...out]
    .filter((e) => upTo === null || e <= upTo)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

async function trackOne(st: State, w: MarketWatch, epoch: bigint, scanForeign = false) {
  const { wallet } = started(st);
  const records = [...st.records.values()].filter((r) => r.market === w.market);
  const report = await trackEpoch(
    { api: st.api, rpc: st.rpc, now: () => now(st) },
    w,
    epoch,
    records,
    wallet.address,
    scanForeign,
  );
  await applySteps(st, report.steps);
  if (report.failure !== null && w.failure === null) {
    const { check, reason } = report.failure;
    w.failure = report.failure;
    const bytes = failureEvidence({ market: w.market, epoch, check, reason, inputs: {} });
    await saveEvidence(st, evidenceRecord('verification_failed', w.market, epoch, bytes, now(st)));
  }
  await retractParked(st, w);
  return report;
}

function marketsWithWork(st: State): Address[] {
  const out = new Set<Address>();
  for (const r of st.records.values()) {
    if (!TERMINAL.has(r.state.kind) || r.state.kind === 'verification_failed') out.add(r.market);
  }
  return [...out];
}

function subscribeMarket(st: State, market: Address): void {
  st.stream.subscribe([`market:${market}`]);
}

/** A wallet prompt left open longer than this belongs to a tab that is gone. */
const STALE_PROMPT_MS = 10 * 60_000;

/** Leader job: everything that should have happened by now, for every market with work. */
async function refreshAll(st: State): Promise<void> {
  const t = now(st);
  for (const r of [...st.records.values()]) {
    if (r.state.kind !== 'awaiting_wallet' && r.state.kind !== 'draft') continue;
    if (t - (r.history[r.history.length - 1]?.atMs ?? t) > STALE_PROMPT_MS) {
      await apply(st, r.id, ev(st, 'abandoned'));
    }
  }
  for (const market of marketsWithWork(st)) {
    let w: MarketWatch;
    try {
      w = await ensureContext(st, market);
      await refreshMarket(st, w);
    } catch {
      continue;
    }
    await carryOver(st, w);
  }
}

/**
 * Seals the record for every reachable epoch of its window that has no
 * participation yet, with fresh ephemeral keys and no prompt: the open epoch
 * and parked epochs up to the park horizon (carry-over).
 */
async function carryOver(st: State, w: MarketWatch): Promise<void> {
  for (const r of [...st.records.values()]) {
    if (r.market !== w.market || r.signature.length === 0) continue;
    const k = r.state.kind;
    if (k !== 'working' && k !== 'paused_needs_app' && k !== 'submitting') continue;
    if (sealable(st, w, r).length === 0) continue;
    try {
      await sealAndSubmit(st, r.id, () => undefined);
    } catch {
      // Retried on the next pass.
    }
  }
}

/** Seals and submits the record's reachable epochs: exact bytes journalled first, then one batched request. */
function sealAndSubmit(
  st: State,
  id: string,
  step: (s: SubmitStep) => void,
  only?: bigint,
): Promise<OrderRecord> {
  return withRecord(st, id, () => sealLocked(st, id, step, only, 0));
}

/** {@link sealAndSubmit} for a caller that holds the record's lock. */
async function sealLocked(
  st: State,
  id: string,
  step: (s: SubmitStep) => void,
  only: bigint | undefined,
  depth: number,
): Promise<OrderRecord> {
  const { session } = started(st);
  const r0 = record(st, id);
  const w = await ensureContext(st, r0.market);
  await refreshView(st, w);
  const r = record(st, id);
  // Nothing is sealed to a market whose checks failed.
  if (TERMINAL.has(r.state.kind) || r.signature.length === 0 || w.failure !== null) return r;
  const epochs = sealable(st, w, r, only);
  if (epochs.length === 0) {
    if (
      r.state.kind === 'submitting' &&
      ![...r.epochs.values()].some(
        (p) => PENDING.has(p.state.kind) || IN_FLIGHT.has(p.state.kind),
      ) &&
      windowPassed(w, r, now(st))
    ) {
      const span = windowOf(r)!;
      return apply(
        st,
        id,
        ev(st, 'submitted', { epoch: span.to, result: 'refused', code: 'EPOCH_CLOSED' }),
      );
    }
    return r;
  }
  step('sealing');
  const ctx = w.ctx!;
  // The relay in force now is the one V-5 checks this promise against later.
  const chain = await st.rpc.market(r.market);
  if (chain.value.relay !== ctx.market.relay) await verifyWatch(st, w);
  const relay = chain.value.relay;
  const open = w.current?.open?.epoch ?? -1n;
  const parts: Participation[] = [];
  for (const { epoch, key } of epochs) {
    const envelope = sealEnvelope({
      epochPk: key.epochPk,
      market: ctx.market.params.market,
      epoch,
      commitment: r.commitment,
      intent: { body: r.body, salt: r.salt, signature: r.signature },
    });
    parts.push({
      epoch,
      envelopeDigest: envelopeDigest(envelope),
      submission: await session.signSubmission(envelope),
      promise: null,
      relayAtSubmission: relay,
      state: { kind: epoch === open ? 'sealed' : 'parked' },
    });
  }
  // One journal transaction holds the exact bytes before anything is sent (outbox).
  await update(st, id, (x) => {
    const map = new Map(x.epochs);
    for (const p of parts) map.set(p.epoch, resealed(p, x.epochs.get(p.epoch)));
    return { ...x, epochs: map };
  });
  return postSubmissions(
    st,
    id,
    parts.map((p) => p.epoch),
    step,
    depth,
  );
}

function detailsBytes(details: unknown, field: string): Uint8Array | null {
  const v = (details as Record<string, unknown> | null | undefined)?.[field];
  if (typeof v !== 'string') return null;
  try {
    return b64.decode(v);
  } catch {
    return null;
  }
}

/**
 * Reads a submission status this SDK does not know from the epoch the
 * verified promise names: in the batch once that epoch is open, parked
 * before. Without a view of the open epoch the participation stays where
 * sealing put it.
 */
function followEpoch(st: State, market: Address, p: Participation): 'accepted' | 'parked' {
  const open = st.markets.get(market)?.current?.open?.epoch;
  if (open === undefined) return p.state.kind === 'parked' ? 'parked' : 'accepted';
  return p.epoch > open ? 'parked' : 'accepted';
}

/** Applies one batch item: V-5 on a promise (adopting the original on `DUPLICATE_COMMITMENT`), refusal evidence otherwise. */
async function settleItem(
  st: State,
  id: string,
  epoch: bigint,
  item: SubmitItemResult,
): Promise<boolean> {
  const r = record(st, id);
  const p = r.epochs.get(epoch);
  if (p === undefined) return false;
  const envelope = decodeSubmission(p.submission).envelope;
  if ('ok' in item) {
    const res = item.ok;
    const v = verifyPromise(res.promiseBytes, {
      market: r.market,
      epoch,
      commitment: r.commitment,
      envelope,
      relay: p.relayAtSubmission,
    });
    if (v.kind !== 'ok' || res.epoch !== epoch || !equal(res.commitment, r.commitment)) {
      const reason = v.kind === 'ok' ? 'the result names another epoch or commitment' : v.reason;
      await failCheck(st, r, epoch, 'V-5', reason, { promise: res.promiseBytes });
      return false;
    }
    const result = res.status === 'unknown' ? followEpoch(st, r.market, p) : res.status;
    await apply(st, id, ev(st, 'submitted', { epoch, result }), {
      promise: res.promiseBytes,
    });
    await apply(st, id, ev(st, 'promise_verified', { epoch }));
    return false;
  }
  const err = item.error;
  if (err.code === 'DUPLICATE_COMMITMENT') {
    // The relay holds an earlier envelope for this commitment and epoch (a
    // re-seal, or another tab's seal): adopt its promise if this journal
    // sealed that envelope. A promise for any other envelope is the relay
    // holding bytes the trader never sealed in place of the trader's own.
    const original = detailsBytes(err.details, 'promise_b64');
    if (original !== null) {
      const v = verifyPromiseDigest(original, {
        market: r.market,
        epoch,
        commitment: r.commitment,
        envelopeDigest: null,
        relay: p.relayAtSubmission,
      });
      if (v.kind !== 'ok') {
        await failCheck(st, r, epoch, 'V-5', v.reason, { promise: original });
        return false;
      }
      if (!sealedDigests(p).some((d) => equal(d, v.value.envelopeDigest))) {
        await failCheck(
          st,
          r,
          epoch,
          'V-5',
          'the relay promised another envelope for this commitment than any this journal sealed',
          { promise: original, envelope },
        );
        return false;
      }
      const open = st.markets.get(r.market)?.current?.open?.epoch;
      await apply(
        st,
        id,
        ev(st, 'submitted', {
          epoch,
          result: open !== undefined && epoch > open ? 'parked' : 'accepted',
        }),
        { promise: original, envelopeDigest: v.value.envelopeDigest },
      );
      await apply(st, id, ev(st, 'promise_verified', { epoch }));
      return false;
    }
  }
  const refusal = err.refusalBytes ?? detailsBytes(err.details, 'refusal_b64');
  let evidence: EvidenceRecord | undefined;
  if (refusal !== null) {
    const v = verifyRefusal(refusal, {
      market: r.market,
      epoch,
      envelopeDigest: envelopeDigest(envelope),
      relay: p.relayAtSubmission,
    });
    if (v.kind === 'ok') {
      const bytes = refusalEvidence({
        market: r.market,
        epoch,
        refusal,
        relay: p.relayAtSubmission,
        code: err.code,
      });
      evidence = evidenceRecord('refusal', r.market, epoch, bytes, now(st));
    }
  }
  await saveEvidence(st, evidence);
  await apply(
    st,
    id,
    ev(st, 'submitted', { epoch, result: 'refused', code: err.code }),
    evidence !== undefined ? { evidenceId: evidence.id } : {},
  );
  return err.code === 'EPOCH_CLOSED';
}

/** Session errors after which this session key will not be accepted again. */
const LOST_SESSION = new Set(['SESSION_UNKNOWN', 'SESSION_EXPIRED', 'SESSION_REVOKED']);

async function postSubmissions(
  st: State,
  id: string,
  epochs: bigint[],
  step: (s: SubmitStep) => void,
  depth: number,
): Promise<OrderRecord> {
  const { session } = started(st);
  step('submitting');
  const r = record(st, id);
  const submissions = epochs.map((e) => r.epochs.get(e)!.submission);
  const started_ = Date.now();
  let items: SubmitItemResult[];
  try {
    items = await st.api.submitBatch(r.market, submissions, session);
  } catch (e) {
    if (!(e instanceof TimescalesError)) throw e;
    if (LOST_SESSION.has(e.code)) st.lostSession = hex.encode(session.sessionKey);
    // Nothing is known about these bytes: they stay in the outbox.
    let out = r;
    for (const epoch of epochs) {
      out = await apply(st, id, ev(st, 'submitted', { epoch, result: 'refused', code: e.code }));
    }
    return out;
  }
  remember(st.submitTimes, Date.now() - started_);
  if (items.length !== epochs.length) {
    throw new TimescalesError({
      kind: 'schema',
      code: 'schema_mismatch',
      message: 'the node answered a batched submission with another number of items',
    });
  }
  step('verifying_promise');
  let closed = false;
  for (let i = 0; i < epochs.length; i++) {
    if (await settleItem(st, id, epochs[i]!, items[i]!)) closed = true;
  }
  // Cutoff race: a parked N+1 participation already is the submission
  // for N+1. Otherwise seal N+1 when the signed window still covers it.
  if (closed && depth === 0) {
    const w = st.markets.get(r.market);
    const after = record(st, id);
    if (w !== undefined && !TERMINAL.has(after.state.kind)) {
      await refreshCurrent(deps(st), w, undefined, st.wallet?.address);
      if (sealable(st, w, after).length > 0) await sealLocked(st, id, step, undefined, depth + 1);
    }
  }
  step('done');
  return record(st, id);
}

/**
 * Re-sends journalled submissions with their exact bytes. A submission
 * signed by an earlier session is wrapped again for the current one. Its
 * envelope, and so the promise, does not change.
 */
async function resendOutbox(st: State): Promise<number> {
  const { session } = started(st);
  st.lastResendAt = Date.now();
  // Re-sending with a session the node refused only fails again.
  if (st.lostSession === hex.encode(session.sessionKey)) return 0;
  let sent = 0;
  for (const [id, items] of outboxGroups(await st.journal.outbox())) {
    const r = st.records.get(id);
    if (r === undefined || (TERMINAL.has(r.state.kind) && r.state.kind !== 'verification_failed'))
      continue;
    await withRecord(st, id, async () => {
      const live = record(st, id);
      const epochs = items
        .map((i) => i.epoch)
        .filter((e) => {
          const p = live.epochs.get(e);
          return p !== undefined && p.promise === null && PENDING.has(p.state.kind);
        });
      if (epochs.length === 0) return;
      const stale = epochs.filter(
        (e) => !signedBy(live.epochs.get(e)!.submission, session.sessionKey),
      );
      if (stale.length > 0) {
        const wrapped = new Map<bigint, Uint8Array>();
        for (const e of stale) {
          const envelope = decodeSubmission(live.epochs.get(e)!.submission).envelope;
          wrapped.set(e, await session.signSubmission(envelope));
        }
        await update(st, id, (x) => {
          const map = new Map(x.epochs);
          for (const [e, submission] of wrapped) {
            const p = map.get(e);
            if (p !== undefined && p.promise === null) map.set(e, { ...p, submission });
          }
          return { ...x, epochs: map };
        });
      }
      sent += epochs.length;
      await postSubmissions(st, id, epochs, () => undefined, 1);
    });
  }
  return sent;
}

/**
 * The epoch a Cancel goes into: the first reachable epoch, within the
 * signing budget, in which the order has, or can get, a placement envelope,
 * so the cancel and the placement meet in one batch.
 */
function cancelEpoch(
  st: State,
  w: MarketWatch,
  placement: OrderRecord,
  budgetMs: number,
): bigint | null {
  const c = w.current;
  if (c === null || placement.body.kind !== 'place') return null;
  const first = firstReachable(c, now(st), budgetMs);
  if (first === null || c.open === null) return null;
  const { validFrom, expiresAt } = placement.body.order;
  const horizon = parkHorizon(w) ?? c.open.epoch;
  for (let e = first > validFrom ? first : validFrom; e <= expiresAt && e <= horizon; e++) {
    const p = placement.epochs.get(e);
    if (p !== undefined && PENDING.has(p.state.kind)) return e;
    if ((p === undefined || resealable(placement, p, w)) && w.keys.has(e)) {
      if (e !== c.open.epoch || w.terms.has(e)) return e;
    }
  }
  return null;
}

/**
 * Removes parked envelopes at the relay that must not trade (best effort,
 * operator-trusted): those after a cancel's epoch, once that epoch is open
 * (an earlier retract would take the placement's envelope in the cancel's
 * epoch with it. The protocol-guaranteed cancel is the sealed Cancel),
 * and those of an order whose details a voided epoch made public, which
 * waits for the user's consent. Only epochs after the open one can still be
 * removed. The open epoch's envelope trades. Retried on the next pass until
 * the relay confirms.
 */
async function retractParked(st: State, w: MarketWatch): Promise<void> {
  const open = w.current?.open?.epoch;
  if (open === undefined || st.session === null) return;
  for (const r of [...st.records.values()]) {
    if (r.market !== w.market || r.body.kind !== 'place') continue;
    const s = r.state;
    const due =
      (s.kind === 'cancel_pending' && open >= s.epoch) || s.kind === 'reseal_needs_consent';
    if (!due) continue;
    if (![...r.epochs.values()].some((p) => p.epoch > open && p.state.kind === 'parked')) continue;
    try {
      const res = await st.api.retractParked(r.market, r.commitment, st.session);
      const removed = res.removedEpochs.filter((e) => e > open);
      if (removed.length > 0)
        await apply(st, r.id, ev(st, 'parked_invalidated', { epochs: removed }));
    } catch {
      // Retried on the next pass.
    }
  }
}

/** After a fill, an expiry or a cancel, parked envelopes are retracted (best effort, operator-trusted). */
async function retractEnded(st: State, before: OrderRecord, after: OrderRecord): Promise<void> {
  if (st.role !== 'leader' || st.session === null || after.body.kind !== 'place') return;
  if (after.state.kind === 'verification_failed') return;
  if (![...before.epochs.values()].some((p) => p.state.kind === 'parked')) return;
  try {
    await st.api.retractParked(after.market, after.commitment, st.session);
  } catch {
    // Nothing depends on it: the executor treats these envelopes as spent.
  }
}

/** Leader side of a Cancel: the placement gets an envelope in the cancel's epoch, then the Cancel is sealed and submitted. */
async function sealCancel(
  st: State,
  placementId: string,
  cancelId: string,
  step: (s: SubmitStep) => void,
): Promise<OrderRecord> {
  const cancel = record(st, cancelId);
  if (cancel.body.kind !== 'cancel') throw new TypeError('not a cancel');
  const n = cancel.body.cancel.epoch;
  const placement = record(st, placementId);
  const pn = placement.epochs.get(n);
  if (pn === undefined || !PENDING.has(pn.state.kind)) {
    await sealAndSubmit(st, placementId, () => undefined, n);
  }
  const sealed = await sealAndSubmit(st, cancelId, step);
  const pc = sealed.epochs.get(n);
  if (pc !== undefined && PENDING.has(pc.state.kind) && pc.promise !== null) {
    await apply(st, cancelId, ev(st, 'cancel_submitted', { epoch: n }));
    await apply(st, placementId, ev(st, 'cancel_submitted', { epoch: n }));
    const w = st.markets.get(placement.market);
    if (w !== undefined) await retractParked(st, w);
  }
  return record(st, placementId);
}

/** Runs leader work one job at a time. A job of an earlier generation (before a stop) does nothing. */
function schedule<T>(st: State, job: () => Promise<T>): Promise<T | undefined> {
  const gen = st.generation;
  const run = st.queue.then(async () => {
    if (st.generation !== gen || st.role !== 'leader') return undefined;
    return job();
  });
  st.queue = run.catch(() => undefined);
  return run;
}

async function handleCall(st: State, call: Call): Promise<unknown> {
  switch (call.op) {
    case 'seal':
      if ((await st.journal.get(call.id)) === undefined) await create(st, call.record);
      else keep(st, call.record);
      return sealAndSubmit(st, call.id, () => undefined);
    case 'cancel':
      if ((await st.journal.get(call.cancel)) === undefined) await create(st, call.record);
      else keep(st, call.record);
      return sealCancel(st, call.placement, call.cancel, () => undefined);
    case 'reconcile':
      return reconcileHere(st, call.fromEpoch);
  }
}

function errorOf(e: unknown): NonNullable<Extract<Message, { t: 'reply' }>['error']> {
  if (e instanceof TimescalesError) {
    return { kind: e.kind, code: e.code, message: e.message, retryable: e.retryable };
  }
  return {
    kind: 'api',
    code: 'unknown',
    message: e instanceof Error ? e.message : String(e),
    retryable: false,
  };
}

function onMessage(st: State, m: Message): void {
  switch (m.t) {
    case 'records':
      if (st.role !== 'follower') return;
      for (const r of m.records) {
        const known = st.records.get(r.id);
        if (known === undefined || known.version < r.version) st.records.set(r.id, r);
      }
      notify(st, false);
      return;
    case 'hello':
      if (st.role === 'leader') notify(st);
      return;
    case 'call':
      if (st.role !== 'leader') return;
      void (m.op === 'reconcile' ? schedule(st, () => handleCall(st, m)) : handleCall(st, m)).then(
        (value) => post(st, { t: 'reply', to: m.from, callId: m.callId, ok: true, value }),
        (e: unknown) =>
          post(st, { t: 'reply', to: m.from, callId: m.callId, ok: false, error: errorOf(e) }),
      );
      return;
    case 'reply': {
      if (m.to !== st.tabId) return;
      const p = st.pending.get(m.callId);
      if (p === undefined) return;
      st.pending.delete(m.callId);
      clearTimeout(p.timer);
      if (m.ok) p.resolve(m.value);
      else {
        const e = m.error!;
        p.reject(
          new TimescalesError({
            kind: e.kind,
            code: e.code,
            message: e.message,
            retryable: e.retryable,
          }),
        );
      }
      return;
    }
  }
}

/** Forwards an action to the leader tab, or runs it here when this tab leads. */
function forward<T>(st: State, call: Call): Promise<T> {
  if (st.role === 'leader' || st.channel === null) {
    if (call.op === 'reconcile' && st.role === 'leader') {
      return schedule(st, () => handleCall(st, call)) as Promise<T>;
    }
    return handleCall(st, call) as Promise<T>;
  }
  const callId = hex.encode(randomBytes(8));
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      st.pending.delete(callId);
      reject(
        new TimescalesError({
          kind: 'timeout',
          code: 'leader_unresponsive',
          message: 'the tab that leads this wallet did not answer',
          retryable: true,
        }),
      );
    }, CALL_TIMEOUT_MS);
    st.pending.set(callId, { resolve: resolve as (v: unknown) => void, reject, timer });
    post(st, { t: 'call', from: st.tabId, callId, ...call });
  });
}

/**
 * Epochs a reconcile scans for fills at most, counting back from the last
 * closed one: `BATCH_RETENTION`. Older Batch accounts may be
 * reclaimed, so nothing in them can be verified any more.
 */
const RECONCILE_WINDOW = 1024n;

async function reconcileHere(st: State, fromEpoch: bigint): Promise<ReconcileReport> {
  const report: ReconcileReport = {
    attached: 0,
    foreignFills: 0,
    outboxResent: 0,
    inconclusive: 0,
  };
  report.outboxResent = await resendOutbox(st);
  const markets = new Set<Address>([...st.records.values()].map((r) => r.market));
  for (const m of st.markets.keys()) markets.add(m);
  for (const market of markets) {
    let w: MarketWatch;
    try {
      w = await ensureContext(st, market);
      await refreshView(st, w);
    } catch {
      report.inconclusive++;
      continue;
    }
    const open = w.current?.open ?? null;
    const last = open !== null ? open.epoch - 1n : w.ctx!.market.lastCommitted;
    const oldest = last - RECONCILE_WINDOW + 1n;
    const first = fromEpoch > oldest ? fromEpoch : oldest;
    const tracked = new Set(trackedEpochs(st, w));
    for (let e = first; e <= last; e++) tracked.add(e);
    for (const e of [...tracked].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
      try {
        const res = await trackOne(st, w, e, e >= first && e <= last);
        report.attached += res.attached;
        report.foreignFills += res.foreignFills;
        if (res.inconclusive) report.inconclusive++;
      } catch {
        report.inconclusive++;
      }
    }
    await reviewRecords(st, w);
    await carryOver(st, w);
  }
  return report;
}

/**
 * Stream events are hints the node sends at will. The checks they
 * trigger can fail a market, but never lift a failure: a failed market
 * waits for the app's re-check and is not verified again in the background.
 */
function onStreamEvent(st: State, e: StreamEvent): void {
  if (st.role !== 'leader') return;
  if (e.kind === 'program.upgraded') {
    for (const w of st.markets.values()) {
      void schedule(st, async () => {
        if (w.failure === null) await verifyWatch(st, w).catch(() => undefined);
      });
    }
    return;
  }
  if (!('market' in e)) return;
  const w = st.markets.get(e.market);
  if (w === undefined) return;
  switch (e.kind) {
    case 'epoch.opened':
    case 'key.published':
    case 'intake.paused':
    case 'intake.resumed':
    case 'market.state':
      void schedule(st, async () => {
        await refreshMarket(st, w);
        await retractParked(st, w);
        await carryOver(st, w);
      });
      return;
    case 'parked.invalidated': {
      const epochs = e.epochs;
      void schedule(st, async () => {
        for (const r of [...st.records.values()]) {
          if (
            r.market === w.market &&
            epochs.some((x) => r.epochs.get(x)?.state.kind === 'parked')
          ) {
            await apply(st, r.id, ev(st, 'parked_invalidated', { epochs }));
          }
        }
        // An emergency rotation changes the committee: verify the market again
        // (V-1 to V-4), then seal the listed epochs for their new keys.
        if (w.failure !== null) return;
        await verifyWatch(st, w);
        await carryOver(st, w);
      });
      return;
    }
    case 'governance.applied':
      void schedule(st, async () => {
        if (w.failure === null) await verifyWatch(st, w);
        for (const r of [...st.records.values()]) {
          if (r.market === w.market && !TERMINAL.has(r.state.kind)) {
            await apply(st, r.id, ev(st, 'governance_applied', { change: e.change }));
          }
        }
      });
      return;
    case 'governance.pending':
      return;
    default:
      if ('epoch' in e && typeof e.epoch === 'bigint') {
        const epoch = e.epoch;
        void schedule(st, async () => {
          await refreshView(st, w);
          await trackOne(st, w, epoch);
          await reviewRecords(st, w);
          if (e.kind === 'epoch.closed') await carryOver(st, w);
        });
      }
  }
}

async function becomeLeader(st: State, gen: number): Promise<void> {
  if (st.generation !== gen) return;
  st.role = 'leader';
  st.cleanups.push(st.stream.on('event', (e) => onStreamEvent(st, e)));
  st.cleanups.push(
    st.stream.on('resync', () => {
      void schedule(st, () => refreshAll(st));
    }),
  );
  for (const m of new Set([...marketsWithWork(st), ...st.markets.keys()])) subscribeMarket(st, m);
  st.timer = setInterval(() => {
    void schedule(st, async () => {
      if (Date.now() - st.lastResendAt > RESEND_EVERY_MS) await resendOutbox(st);
      await refreshAll(st);
    });
  }, TICK_MS);
  void schedule(st, async () => {
    await resendOutbox(st);
    await refreshAll(st);
  });
  notify(st);
}

function release(st: State): void {
  st.generation++;
  for (const f of st.cleanups.splice(0)) {
    try {
      f();
    } catch {
      // Best effort.
    }
  }
  if (st.timer !== null) clearInterval(st.timer);
  st.timer = null;
  st.leadership?.release();
  st.leadership = null;
  st.channel?.close();
  st.channel = null;
  for (const [id, p] of st.pending) {
    clearTimeout(p.timer);
    p.reject(notStarted());
    st.pending.delete(id);
  }
  if (st.wallet !== null) {
    const topics = [...st.markets.keys()].map((m) => `market:${m}`);
    if (topics.length > 0) st.stream.unsubscribe(topics);
  }
  st.role = null;
}

/** On an account or chain change or a disconnect: stop, then re-resolve the journal and session for the wallet's address. */
async function onWalletChange(
  svc: OrderService,
  st: State,
  e: { kind: 'accounts' | 'chains' | 'disconnected' },
): Promise<void> {
  const wallet = st.wallet;
  const previousSession = st.session;
  const previous = previousSession?.wallet ?? null;
  await svc.stop();
  st.records.clear();
  st.markets.clear();
  if (e.kind === 'disconnected' || wallet === null) {
    notify(st, false);
    return;
  }
  const address = wallet.address;
  const internals = journalInternals(st.journal);
  if (internals !== null && address !== previous) {
    internals.close();
    st.journal = await openJournal({
      cluster: internals.scope.cluster,
      program: internals.scope.program,
      wallet: address,
    });
  }
  const session =
    address === previous
      ? previousSession
      : await TradingSession.resume({
          api: st.api,
          wallet: address,
          journal: st.journal,
          clock: st.clock,
        });
  for (const r of await st.journal.list()) st.records.set(r.id, r);
  notify(st, false);
  if (session !== null) await svc.start(wallet, session);
}

function newRecord(st: State, market: Address, body: IntentBody, salt: Uint8Array): OrderRecord {
  return {
    id: hex.encode(randomBytes(16)),
    version: 0,
    market,
    body,
    salt,
    signature: new Uint8Array(0),
    commitment: commitment(body, salt),
    state: { kind: 'draft' },
    epochs: new Map(),
    filled: 0n,
    fills: [],
    history: [ev(st, 'prepared')],
    evidence: [],
  };
}

const UNSUPPORTED = new Set<string>(['unsupported_feature', 'modified_message', 'bad_signature']);

/**
 * V-11 then one wallet prompt for the intent digest. Returns the signature,
 * or the record in its wallet outcome. A signature that arrives after the
 * signal aborted is dropped (`abandoned`, nothing sealed).
 */
async function signRecord(
  st: State,
  id: string,
  signal: AbortSignal | undefined,
  step: (s: SubmitStep) => void,
  firstPrompt: boolean,
): Promise<Uint8Array | OrderRecord> {
  const { wallet } = started(st);
  const stored = (await st.journal.get(id)) ?? record(st, id);
  if (!equal(commitment(stored.body, stored.salt), stored.commitment)) {
    const r = await failCheck(
      st,
      stored,
      0n,
      'V-11',
      'the journalled intent does not hash to its commitment',
      {
        commitment: stored.commitment,
      },
    );
    throw new CheckError('V-11', { kind: 'fail', reason: `record ${r.id} is corrupt` });
  }
  if (firstPrompt) await apply(st, id, ev(st, 'wallet_prompted'));
  step('awaiting_wallet');
  const gen = st.generation;
  const switched = (): WalletError =>
    new WalletError('account_changed', 'the wallet changed while signing, nothing was sent');
  const t0 = Date.now();
  try {
    const sig = await signIntent(wallet, stored.commitment, signal);
    if (st.generation !== gen) throw switched();
    remember(st.signTimes, Date.now() - t0);
    return sig;
  } catch (e) {
    // The service stopped for an account change: this record belongs to a journal it closed.
    if (st.generation !== gen) throw switched();
    const we = toWalletError(e);
    const kind =
      we.code === 'rejected'
        ? 'wallet_rejected'
        : UNSUPPORTED.has(we.code)
          ? 'wallet_unsupported'
          : 'abandoned';
    const r = await apply(st, id, ev(st, kind));
    if (kind === 'abandoned' && we.code !== 'abandoned') throw we;
    return r;
  }
}

function isPinList(p: AppPins | readonly AppPins[]): p is readonly AppPins[] {
  return Array.isArray(p);
}

/** Places, tracks and cancels orders. */
export class OrderService {
  /**
   * `pins` is the app's build-time configuration. Without pins for a
   * market the service refuses to verify it, because nothing the node
   * reports may stand in for them.
   */
  constructor(d: {
    api: TimescalesApi;
    rpc: TimescalesRpc;
    journal: Journal;
    stream: TimescalesStream;
    clock: ServerClock;
    pins: AppPins | readonly AppPins[];
  }) {
    STATE.set(this, {
      api: d.api,
      rpc: d.rpc,
      stream: d.stream,
      clock: d.clock,
      pins: isPinList(d.pins) ? [...d.pins] : [d.pins],
      journal: d.journal,
      tabId: hex.encode(randomBytes(8)),
      wallet: null,
      session: null,
      role: null,
      leadership: null,
      channel: null,
      markets: new Map(),
      records: new Map(),
      listeners: new Set(),
      cleanups: [],
      timer: null,
      signTimes: [],
      submitTimes: [],
      pending: new Map(),
      locks: new Map(),
      queue: Promise.resolve(),
      generation: 0,
      lastResendAt: 0,
      lostSession: null,
      disposed: false,
    });
  }

  /** Leader election with navigator.locks ('timescales-orders:<wallet>'). Only the leader runs background jobs and holds the stream. Followers mirror state over BroadcastChannel and forward actions. */
  async start(
    wallet: TraderWallet,
    session: TradingSession,
  ): Promise<{ role: 'leader' | 'follower' }> {
    const st = stateOf(this);
    if (st.disposed) throw notStarted();
    if (st.wallet !== null && st.role !== null) await this.stop();
    if (session.wallet !== wallet.address) {
      throw new WalletError('account_changed', 'the session belongs to another account');
    }
    const internals = journalInternals(st.journal);
    if (internals !== null && internals.scope.wallet !== wallet.address) {
      internals.close();
      st.journal = await openJournal({
        cluster: internals.scope.cluster,
        program: internals.scope.program,
        wallet: wallet.address,
      });
    }
    st.wallet = wallet;
    st.session = session;
    st.generation++;
    const gen = st.generation;
    st.records.clear();
    for (const r of await st.journal.list()) st.records.set(r.id, r);
    st.cleanups.push(
      wallet.onChange((e) => {
        if (st.generation === gen) void onWalletChange(this, st, e);
      }),
    );
    const leadership = await electLeader(wallet.address);
    if (st.generation !== gen) {
      leadership.release();
      throw notStarted();
    }
    st.leadership = leadership;
    if (typeof BroadcastChannel !== 'undefined') {
      const channel = new BroadcastChannel(lockName(wallet.address));
      channel.onmessage = (m: MessageEvent<Message>) => onMessage(st, m.data);
      st.channel = channel;
    }
    if (leadership.role === 'leader') {
      await becomeLeader(st, gen);
    } else {
      st.role = 'follower';
      post(st, { t: 'hello', from: st.tabId });
      void leadership.promoted.then(() => becomeLeader(st, gen));
      notify(st, false);
    }
    return { role: leadership.role };
  }

  async stop(): Promise<void> {
    const st = stateOf(this);
    release(st);
    st.wallet = null;
    st.session = null;
    await st.queue.catch(() => undefined);
  }

  /** One per market with working orders, verified lazily. After a failed check, calling it again is the re-check. */
  async context(market: Address): Promise<VerifiedMarketContext> {
    const st = stateOf(this);
    const w = watchFor(st, market);
    if (w.ctx !== null && w.failure === null) return w.ctx;
    const failure = w.failure;
    const ctx = await verifyWatch(st, w);
    // Only this explicit re-check lifts a failure, and not one found while it ran.
    if (w.failure === failure) w.failure = null;
    return ctx;
  }

  /** Pure: validation, derived book, epochs (sign budget), collateral, fees, warnings, self-trade. */
  prepare(d: OrderDraft): PreparedOrder {
    const st = stateOf(this);
    const { wallet, session } = started(st);
    const w = st.markets.get(d.market);
    const ctx = w?.ctx ?? null;
    const params: MarketParams | null = ctx?.market.params ?? null;
    if (d.side !== 0 && d.side !== 1) throw new OrderError('market', 'side must be 0 or 1');
    if (d.role !== 0 && d.role !== 1) throw new OrderError('market', 'role must be 0 or 1');
    if (d.kind === 1 && d.limitTick !== undefined && d.limitTick !== 0n) {
      throw new OrderError('market_limit', 'a market order has no limit');
    }
    if (d.kind === 0 && (d.limitTick === undefined || d.limitTick <= 0n)) {
      throw new OrderError('market_limit', 'a limit order needs a positive limit tick');
    }
    if (d.quantityLots <= 0n || (params !== null && d.quantityLots > maxOrderLots(params))) {
      throw new OrderError('quantity', 'quantity must be between 1 and 2^b - 1 lots');
    }
    if (
      !Number.isInteger(d.lifetimeEpochs) ||
      d.lifetimeEpochs < 1 ||
      (params !== null && d.lifetimeEpochs > params.maxOrderLifetime + 1)
    ) {
      throw new OrderError(
        'lifetime',
        'lifetime must be between 1 and max_order_lifetime + 1 epochs',
      );
    }
    const blockers: PreparedOrder['blockers'] = [];
    const warnings: PreparedOrder['warnings'] = [];
    if (ctx === null || w!.failure !== null) blockers.push('unverified');
    const budget = signBudget(st);
    const c = w?.current ?? null;
    const t = now(st);
    let from = c === null ? null : firstReachable(c, t, budget);
    if (c === null || c.open === null || c.intake !== 'open' || ctx?.market.halted === true) {
      blockers.push('paused');
    }
    from ??= ctx === null ? 0n : ctx.market.lastCommitted + 1n;
    const to = from + BigInt(d.lifetimeEpochs - 1);
    const horizon = w === undefined ? null : parkHorizon(w);
    const parkedTo = horizon === null ? from : horizon < to ? horizon : to;
    const book = bookFor(params?.flow ?? 0, d.side, d.role);
    const order: Omit<Order, 'nonce'> = {
      market: params?.market ?? 0n,
      trader: b58.decode(wallet.address, 32),
      side: d.side,
      role: d.role,
      kind: d.kind,
      limit: d.kind === 1 ? 0n : d.limitTick!,
      quantity: d.quantityLots,
      validFrom: from,
      expiresAt: to,
    };
    let collateral = { base: 0n, quote: 0n, shortfall: false };
    let fee = 0n;
    let notional = 0n;
    const band = c?.open?.band;
    if (params !== null && band !== undefined) {
      const own = collateralFor(order, params, band);
      fee = feeEstimate(order, params, band);
      notional = worstNotional(order, params, band);
      if (own.base === 0n && own.quote === 0n) warnings.push('outside_band');
      // The prefix rule: the balance must cover every order of the wallet in the batch.
      let base = own.base;
      let quote = own.quote;
      for (const r of st.records.values()) {
        if (r.market !== d.market || r.body.kind !== 'place') continue;
        if (r.state.kind !== 'working' && r.state.kind !== 'submitting') continue;
        const other = collateralFor(
          { ...r.body.order, quantity: r.body.order.quantity - r.filled },
          params,
          band,
        );
        base += other.base;
        quote += other.quote;
      }
      const trader = w?.trader?.value ?? null;
      const available = trader === null ? { base: 0n, quote: 0n } : availableFor(trader, from);
      const shortfall = base > available.base || quote > available.quote;
      collateral = { base: own.base, quote: own.quote, shortfall };
      if (shortfall) warnings.push('undercapitalized');
    }
    if (d.lifetimeEpochs > 1) warnings.push('long_rest_linkable');
    const interval = ctx?.detail.timing.epochIntervalMs ?? 0;
    const endsAt = (c?.open?.cutoffMs ?? t) + (d.lifetimeEpochs - 1) * interval;
    if (session.expiresAtMs < endsAt) warnings.push('second_prompt_needed');
    if (
      params !== null &&
      wouldSelfTrade(snapshot(st), { market: d.market, flow: params.flow, book, side: d.side })
    ) {
      blockers.push('self_trade');
    }
    return {
      draft: d,
      order,
      book,
      epochs: { from, to, parkedTo },
      collateral,
      feeEstimate: fee,
      worstNotional: notional,
      signBudgetMs: budget,
      warnings,
      blockers,
    };
  }

  /** At most one wallet prompt. */
  async submit(
    p: PreparedOrder,
    o?: { signal?: AbortSignal; onStep?: (s: SubmitStep) => void },
  ): Promise<OrderRecord> {
    const st = stateOf(this);
    const { wallet, session } = started(st);
    const step = (s: SubmitStep): void => {
      try {
        o?.onStep?.(s);
      } catch {
        // The caller's progress callback cannot stop a submission.
      }
    };
    step('validating');
    if (p.blockers.length > 0) {
      throw new TimescalesError({
        kind: p.blockers.includes('unverified') ? 'verify' : 'api',
        code: p.blockers[0]!,
        message: `the order cannot be placed: ${p.blockers.join(', ')}`,
      });
    }
    checkAccount(st, p.order.trader);
    const w = await ensureContext(st, p.draft.market);
    const order: Order = { ...p.order, nonce: randomU64() };
    validateOrder(order, w.ctx!.market.params, order.validFrom);
    const r = await create(
      st,
      newRecord(st, p.draft.market, { kind: 'place', order }, randomBytes(32)),
    );
    const signed = await signRecord(st, r.id, o?.signal, step, true);
    if (!(signed instanceof Uint8Array)) return signed;
    if (wallet.address !== session.wallet || !equal(b58.decode(wallet.address, 32), order.trader)) {
      await apply(st, r.id, ev(st, 'abandoned'));
      throw new WalletError(
        'account_changed',
        'the wallet switched accounts while signing, nothing was sent',
      );
    }
    try {
      await refreshCurrent(deps(st), w, undefined, wallet.address);
    } catch {
      // Decide lateness on the last verified view. The relay has the final word.
    }
    const late = windowPassed(w, r, now(st));
    const after = await update(st, r.id, (x) =>
      reduceWith({ ...x, signature: signed }, ev(st, 'signed', { late })),
    );
    if (late) return after;
    if (st.role === 'leader' || st.channel === null) return sealAndSubmit(st, r.id, step);
    step('sealing');
    const rec = await forward<OrderRecord>(st, { op: 'seal', id: r.id, record: after });
    step('done');
    return rec;
  }

  cancel(
    r: OrderRecord,
    o?: {
      signal?: AbortSignal;
      onStep?: (s: SubmitStep) => void;
      confirmSecondPrompt?: () => Promise<boolean>;
    },
  ): Promise<OrderRecord> {
    return cancelOrder(this, r, o);
  }

  /**
   * Re-sends the outbox, follows every epoch with own participations and
   * scans closed epochs from `fromEpoch` for own fills, at most the
   * last 1024 (`BATCH_RETENTION`, older batches may be reclaimed).
   */
  reconcile(fromEpoch: bigint): Promise<ReconcileReport> {
    const st = stateOf(this);
    started(st);
    return forward<ReconcileReport>(st, { op: 'reconcile', fromEpoch });
  }

  subscribe(f: (records: readonly OrderRecord[]) => void): () => void {
    const st = stateOf(this);
    st.listeners.add(f);
    f(snapshot(st));
    return () => {
      st.listeners.delete(f);
    };
  }

  dispose(): void {
    const st = stateOf(this);
    if (st.disposed) return;
    release(st);
    st.listeners.clear();
    st.disposed = true;
  }
}

const CANCELLABLE = new Set<OrderRecord['state']['kind']>([
  'working',
  'paused_needs_app',
  'reseal_needs_consent',
  'submit_failed',
  'cancel_pending',
]);

/**
 * Cancel: one prompt signs `Cancel{target: C, epoch: n}` for the first
 * epoch, within the signing budget, in which the order has or gets a
 * placement envelope. If `n` closes before the signature arrives, a second
 * prompt for a later epoch happens only after `confirmSecondPrompt`.
 * Resolves to the placement record. A declined or abandoned signature
 * rejects with the wallet error after the cancel's own record shows it.
 */
async function cancelOrder(
  svc: OrderService,
  placementIn: OrderRecord,
  o?: {
    signal?: AbortSignal;
    onStep?: (s: SubmitStep) => void;
    confirmSecondPrompt?: () => Promise<boolean>;
  },
): Promise<OrderRecord> {
  const st = stateOf(svc);
  const { wallet } = started(st);
  const step = (s: SubmitStep): void => {
    try {
      o?.onStep?.(s);
    } catch {
      // The caller's progress callback cannot stop a cancel.
    }
  };
  step('validating');
  const placement = (await st.journal.get(placementIn.id)) ?? placementIn;
  if (placement.body.kind !== 'place' || !CANCELLABLE.has(placement.state.kind)) {
    throw new TimescalesError({
      kind: 'api',
      code: 'not_cancellable',
      message: `an order in state ${placement.state.kind} cannot be cancelled`,
    });
  }
  checkAccount(st, placement.body.order.trader);
  const w = await ensureContext(st, placement.market);
  await refreshCurrent(deps(st), w, undefined, wallet.address);
  let n = cancelEpoch(st, w, placement, signBudget(st));
  if (n === null) {
    throw new TimescalesError({
      kind: 'api',
      code: 'nothing_to_cancel',
      message: 'no epoch of the order is left to cancel it in',
    });
  }
  const params = w.ctx!.market.params;
  const cancelBody = (epoch: bigint): IntentBody => ({
    kind: 'cancel',
    cancel: {
      market: params.market,
      trader: b58.decode(wallet.address, 32),
      nonce: randomU64(),
      target: placement.commitment,
      epoch,
    },
  });
  const created = await create(st, newRecord(st, placement.market, cancelBody(n), randomBytes(32)));
  const id = created.id;
  const sign = async (first: boolean): Promise<Uint8Array> => {
    const out = await signRecord(st, id, o?.signal, step, first);
    if (out instanceof Uint8Array) return out;
    throw new WalletError(
      out.state.kind === 'wallet_rejected'
        ? 'rejected'
        : out.state.kind === 'unsupported_wallet'
          ? 'unsupported_feature'
          : 'abandoned',
      'the cancel was not signed, nothing was sent',
    );
  };
  let signature = await sign(true);
  try {
    await refreshCurrent(deps(st), w, undefined, wallet.address);
  } catch {
    // Use the last verified view.
  }
  const reachable = (epoch: bigint): boolean => {
    const c = w.current;
    if (c === null || c.open === null) return false;
    const first = c.open.cutoffMs > now(st) ? c.open.epoch : c.open.epoch + 1n;
    return epoch >= first;
  };
  if (!reachable(n)) {
    // Cancel.epoch is inside the signed body: a later epoch needs another signature.
    const next = cancelEpoch(st, w, record(st, placement.id), 0);
    const agreed =
      next !== null && o?.confirmSecondPrompt !== undefined && (await o.confirmSecondPrompt());
    if (!agreed || next === null) {
      await apply(st, id, ev(st, 'abandoned'));
      throw new TimescalesError({
        kind: 'api',
        code: 'EPOCH_CLOSED',
        message: 'the cancel epoch closed before the wallet signed, nothing was sent',
      });
    }
    n = next;
    const salt = randomBytes(32);
    const body = cancelBody(n);
    await update(st, id, (x) => ({ ...x, body, salt, commitment: commitment(body, salt) }));
    signature = await sign(false);
  }
  const signedRecord = await update(st, id, (x) =>
    reduceWith({ ...x, signature }, ev(st, 'signed', { late: false })),
  );
  const result = await forward<OrderRecord>(st, {
    op: 'cancel',
    placement: placement.id,
    cancel: id,
    record: signedRecord,
  });
  step('done');
  return result;
}
