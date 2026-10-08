import type { Address } from '@solana/kit';
import type { z } from 'zod';
import { b58 } from '../core/encoding/base58.js';
import { b64 } from '../core/encoding/base64.js';
import { utf8 } from '../core/encoding/bytes.js';
import { hex } from '../core/encoding/hex.js';
import { TimescalesError } from '../errors.js';
import { sessionClockOf, type TradingSession } from '../wallet/session.js';
import { observeServerTime, type ServerClock } from './clock.js';
import { problemToError } from './errors.js';
import {
  ArtifactsSchema,
  CurrentEpochSchema,
  EpochDetailSchema,
  EpochKeySchema,
  EpochSummarySchema,
  ExecutorRegistrationSchema,
  InfoSchema,
  MarketDetailSchema,
  MarketSummarySchema,
  ParkedItemSchema,
  PolicyListSchema,
  ProblemSchema,
  RetractResultSchema,
  SessionNonceSchema,
  SessionSchema,
  StatusSchema,
  SubmitItemResultSchema,
  SubmitResultSchema,
  TapeRowSchema,
  TimeSchema,
  itemsOf,
  pageOf,
  toInfo,
  type Artifacts,
  type CreateSessionRequest,
  type CurrentEpoch,
  type EpochDetail,
  type EpochKey,
  type EpochSummary,
  type ExecutorRegistration,
  type Info,
  type MarketDetail,
  type MarketSummary,
  type ParkedItem,
  type RetractResult,
  type Session,
  type SessionNonce,
  type Status,
  type SubmitItemResult,
  type SubmitResult,
  type TapeRow,
} from './schemas.js';

export interface Page<T> {
  items: T[];
  nextBefore: bigint | null;
}

export interface PageReq {
  before?: bigint;
  limit?: number;
}

const BACKOFF_BASE_MS = 250;
const BACKOFF_MAX_MS = 4_000;
/** The longest `Retry-After` waited for inside a call. A longer one is returned to the caller. */
const RETRY_AFTER_MAX_MS = 10_000;
/** Statuses retried with backoff. Other errors are returned to the caller. */
const RETRY_STATUSES = new Set([429, 502, 503, 504]);

interface ApiState {
  baseUrl: string;
  fetch: typeof fetch;
  timeoutMs: number;
  attempts: number;
  clock: ServerClock | null;
}

// The class's declared surface is frozen, so its state lives here.
const STATE = new WeakMap<TimescalesApi, ApiState>();

function stateOf(api: TimescalesApi): ApiState {
  const s = STATE.get(api);
  if (s === undefined) throw new TypeError('TimescalesApi used before construction');
  return s;
}

interface Request<T> {
  method: 'GET' | 'POST' | 'DELETE';
  path: string;
  query?: Record<string, string>;
  body?: unknown;
  session?: TradingSession;
  /** Parses a 2xx JSON body. Absent for binary and empty responses. */
  schema?: z.ZodType<T>;
  binary?: boolean;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoff(attempt: number, retryAfterMs: number | undefined): number {
  const cap = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** (attempt - 1));
  const jitter = Math.floor(Math.random() * cap);
  return Math.max(jitter, retryAfterMs ?? 0);
}

function retryAfterHeader(res: Response): number | undefined {
  const h = res.headers.get('retry-after');
  if (h === null) return undefined;
  const seconds = Number(h);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : undefined;
}

function checked(m: Address): Address {
  try {
    b58.decode(m, 32);
  } catch (cause) {
    throw new TimescalesError({
      kind: 'api',
      code: 'BAD_REQUEST',
      message: `not an address: ${m}`,
      cause,
    });
  }
  return m;
}

function segment(m: Address): string {
  return encodeURIComponent(checked(m));
}

function pageQuery(p?: PageReq): Record<string, string> {
  const q: Record<string, string> = {};
  if (p?.before !== undefined) q.before = p.before.toString();
  if (p?.limit !== undefined) {
    if (!Number.isInteger(p.limit) || p.limit < 1 || p.limit > 200) {
      throw new RangeError('limit must be within 1..200');
    }
    q.limit = String(p.limit);
  }
  return q;
}

async function parseProblem(res: Response): Promise<z.output<typeof ProblemSchema> | null> {
  const type = res.headers.get('content-type') ?? '';
  if (!type.includes('json')) return null;
  try {
    const parsed = ProblemSchema.safeParse(await res.json());
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

async function resync(api: TimescalesApi, session: TradingSession): Promise<void> {
  const clocks = new Set<ServerClock>();
  const own = stateOf(api).clock;
  if (own !== null) clocks.add(own);
  const sessionClock = sessionClockOf(session);
  if (sessionClock !== null) clocks.add(sessionClock);
  await Promise.all([...clocks].map((c) => c.sync(api)));
}

async function request<T>(api: TimescalesApi, r: Request<T>): Promise<T> {
  const s = stateOf(api);
  const search = new URLSearchParams(r.query ?? {}).toString();
  const url = `${s.baseUrl}${r.path}${search.length > 0 ? `?${search}` : ''}`;
  const pathAndQuery = new URL(url).pathname + (search.length > 0 ? `?${search}` : '');
  const body = r.body === undefined ? undefined : JSON.stringify(r.body);
  const bodyBytes = body === undefined ? new Uint8Array(0) : utf8(body);
  let skewRetried = false;
  for (let attempt = 1; ; attempt++) {
    const headers: Record<string, string> = {
      accept: r.binary === true ? 'application/octet-stream' : 'application/json',
    };
    if (body !== undefined) headers['content-type'] = 'application/json';
    // Rebuilt on every attempt: a fresh timestamp, so a retry never hits the replay cache.
    if (r.session !== undefined) {
      headers.authorization = await r.session.authorization(r.method, pathAndQuery, bodyBytes);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), s.timeoutMs);
    const sentAt = Date.now();
    let error: TimescalesError;
    let status = 0;
    try {
      const res = await s.fetch(url, {
        method: r.method,
        headers,
        ...(body !== undefined ? { body } : {}),
        signal: controller.signal,
      });
      status = res.status;
      if (res.ok) {
        const receivedAt = Date.now();
        if (r.binary === true) return new Uint8Array(await res.arrayBuffer()) as T;
        if (r.schema === undefined) return undefined as T;
        const json: unknown = await res.json();
        if (s.clock !== null) {
          const t = (json as { server_time_ms?: unknown } | null)?.server_time_ms;
          if (typeof t === 'number') observeServerTime(s.clock, t, sentAt, receivedAt);
        }
        const parsed = r.schema.safeParse(json);
        if (!parsed.success) {
          const requestId = res.headers.get('x-request-id');
          throw new TimescalesError({
            kind: 'schema',
            code: 'schema_mismatch',
            message: `the node's ${r.method} ${r.path} response does not match the API schema`,
            details: parsed.error.issues,
            ...(requestId !== null ? { requestId } : {}),
          });
        }
        return parsed.data;
      }
      const problem = await parseProblem(res);
      error = problemToError(res.status, problem);
      const retryAfter = retryAfterHeader(res);
      if (retryAfter !== undefined && error.retryAfterMs === undefined) {
        error = new TimescalesError({
          kind: error.kind,
          code: error.code,
          message: error.message,
          retryable: error.retryable,
          retryAfterMs: retryAfter,
          ...(error.requestId !== undefined ? { requestId: error.requestId } : {}),
          ...(error.details !== undefined ? { details: error.details } : {}),
        });
      }
    } catch (e) {
      if (e instanceof TimescalesError) {
        if (e.kind === 'schema') throw e;
        error = e;
      } else {
        const timedOut = controller.signal.aborted;
        error = new TimescalesError({
          kind: timedOut ? 'timeout' : 'network',
          code: timedOut ? 'timeout' : 'network',
          message: timedOut ? `${r.method} ${r.path} timed out` : `${r.method} ${r.path} failed`,
          retryable: true,
          cause: e,
        });
      }
    } finally {
      clearTimeout(timer);
    }
    if (error.code === 'SKEW' && r.session !== undefined && !skewRetried) {
      skewRetried = true;
      await resync(api, r.session);
      attempt--;
      continue;
    }
    const transient = status === 0 || RETRY_STATUSES.has(status);
    if (!transient || attempt >= s.attempts) throw error;
    if (error.retryAfterMs !== undefined && error.retryAfterMs > RETRY_AFTER_MAX_MS) throw error;
    await sleep(backoff(attempt, error.retryAfterMs));
  }
}

const MarketList = itemsOf(MarketSummarySchema);
const EpochPage = pageOf(EpochSummarySchema);
const TapePage = pageOf(TapeRowSchema);
const ExecutorList = itemsOf(ExecutorRegistrationSchema);
const ParkedList = itemsOf(ParkedItemSchema);
const SubmitItems = itemsOf(SubmitItemResultSchema);

/**
 * Client of the node's public API. Every method returns decoded
 * domain types. Requests time out after `timeoutMs`. Network failures,
 * 429, 502, 503 and 504 are retried with full-jitter backoff (250 ms -> 4 s,
 * at most `retries` attempts, honouring a `Retry-After` of up to 10 s. A
 * longer one ends the call with `retryAfterMs` set). Submissions are
 * resent only with the same bytes. A `SKEW` refusal re-syncs the clock and
 * retries once with a fresh authorization.
 */
export class TimescalesApi {
  /** `timeoutMs` defaults to 10000 and `retries` to 3. */
  constructor(o: {
    baseUrl: string;
    fetch?: typeof fetch;
    timeoutMs?: number;
    retries?: number;
    clock?: ServerClock;
  }) {
    const injected = o.fetch;
    STATE.set(this, {
      baseUrl: o.baseUrl.replace(/\/+$/, ''),
      // Resolved per call, so a fetch installed later (a test interceptor) is used.
      fetch: injected ?? ((input, init) => globalThis.fetch(input, init)),
      timeoutMs: o.timeoutMs ?? 10_000,
      attempts: Math.max(1, o.retries ?? 3),
      clock: o.clock ?? null,
    });
  }

  /** Refuses a node whose API major, protocol or header version this SDK does not speak. */
  async info(): Promise<Info> {
    const raw = await request(this, { method: 'GET', path: '/v1/info', schema: InfoSchema });
    const major = raw.api_version.split('.')[0];
    if (major !== '1' || raw.protocol_version !== 1 || raw.header_version !== 2) {
      throw new TimescalesError({
        kind: 'api',
        code: 'VERSION_UNSUPPORTED',
        message: `node speaks API ${raw.api_version}, protocol ${raw.protocol_version}, header ${raw.header_version}`,
      });
    }
    return toInfo(raw);
  }

  status(): Promise<Status> {
    return request(this, { method: 'GET', path: '/v1/status', schema: StatusSchema });
  }

  time(): Promise<{ serverTimeMs: number; slot: bigint }> {
    return request(this, { method: 'GET', path: '/v1/time', schema: TimeSchema });
  }

  markets(): Promise<MarketSummary[]> {
    return request(this, { method: 'GET', path: '/v1/markets', schema: MarketList });
  }

  market(m: Address): Promise<MarketDetail> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}`,
      schema: MarketDetailSchema,
    });
  }

  current(m: Address): Promise<CurrentEpoch> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}/epochs/current`,
      schema: CurrentEpochSchema,
    });
  }

  epochKey(m: Address, e: bigint): Promise<EpochKey> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}/epochs/${e}/key`,
      schema: EpochKeySchema,
    });
  }

  epochs(m: Address, p?: PageReq): Promise<Page<EpochSummary>> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}/epochs`,
      query: pageQuery(p),
      schema: EpochPage,
    });
  }

  epoch(m: Address, e: bigint): Promise<EpochDetail> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}/epochs/${e}`,
      schema: EpochDetailSchema,
    });
  }

  /** `leaves.bin`: count x (C || envelope digest), sorted. */
  leaves(m: Address, e: bigint): Promise<Uint8Array> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}/epochs/${e}/leaves.bin`,
      binary: true,
    });
  }

  artifacts(m: Address, e: bigint): Promise<Artifacts> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}/epochs/${e}/artifacts`,
      schema: ArtifactsSchema,
    });
  }

  /** The epoch's `BalanceSheet` (V-15). */
  balances(m: Address, e: bigint): Promise<Uint8Array> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}/epochs/${e}/balances`,
      binary: true,
    });
  }

  /** The members' signed release policies (V-14), as raw statements. */
  policies(m: Address): Promise<Uint8Array[]> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}/committee/policies`,
      schema: PolicyListSchema,
    });
  }

  clearing(m: Address, p?: PageReq): Promise<Page<TapeRow>> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}/clearing`,
      query: pageQuery(p),
      schema: TapePage,
    });
  }

  executors(m?: Address): Promise<ExecutorRegistration[]> {
    return request(this, {
      method: 'GET',
      path: '/v1/executors',
      ...(m !== undefined ? { query: { market: checked(m) } } : {}),
      schema: ExecutorList,
    });
  }

  sessionNonce(): Promise<SessionNonce> {
    return request(this, { method: 'GET', path: '/v1/sessions/nonce', schema: SessionNonceSchema });
  }

  /** Idempotent for an identical grant: a lost response is retried and returns the existing session. */
  createSession(r: CreateSessionRequest & { minContextSlot?: bigint }): Promise<Session> {
    return request(this, {
      method: 'POST',
      path: '/v1/sessions',
      body: {
        wallet: r.wallet,
        message: r.message,
        signature_b64: b64.encode(r.signatureBytes),
        method: r.method,
        ...(r.minContextSlot !== undefined
          ? { min_context_slot: r.minContextSlot.toString() }
          : {}),
      },
      schema: SessionSchema,
    });
  }

  currentSession(s: TradingSession): Promise<Session> {
    return request(this, {
      method: 'GET',
      path: '/v1/sessions/current',
      session: s,
      schema: SessionSchema,
    });
  }

  revokeSession(s: TradingSession): Promise<void> {
    return request<void>(this, { method: 'DELETE', path: '/v1/sessions/current', session: s });
  }

  submit(m: Address, submission: Uint8Array, s: TradingSession): Promise<SubmitResult> {
    return request(this, {
      method: 'POST',
      path: `/v1/markets/${segment(m)}/submissions`,
      body: { submission_b64: b64.encode(submission) },
      session: s,
      schema: SubmitResultSchema,
    });
  }

  /** One order's open and parked epochs in one request. Per-item results (#19a). */
  submitBatch(
    m: Address,
    submissions: Uint8Array[],
    s: TradingSession,
  ): Promise<SubmitItemResult[]> {
    return request(this, {
      method: 'POST',
      path: `/v1/markets/${segment(m)}/submissions/batch`,
      body: { submissions_b64: submissions.map((x) => b64.encode(x)) },
      session: s,
      schema: SubmitItems,
    });
  }

  parked(m: Address, s: TradingSession): Promise<ParkedItem[]> {
    return request(this, {
      method: 'GET',
      path: `/v1/markets/${segment(m)}/parked`,
      session: s,
      schema: ParkedList,
    });
  }

  /** Operator-trusted removal of queued envelopes after the open epoch. The protocol-guaranteed cancel is a sealed Cancel. */
  retractParked(m: Address, c: Uint8Array, s: TradingSession): Promise<RetractResult> {
    return request(this, {
      method: 'POST',
      path: `/v1/markets/${segment(m)}/parked/retract`,
      body: { commitment: hex.encode(c) },
      session: s,
      schema: RetractResultSchema,
    });
  }
}
