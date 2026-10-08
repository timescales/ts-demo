// The API client over msw: retries and backoff, error mapping and its
// exhaustiveness against the rows, schemas, idempotent submission
// retries, SKEW, the server clock. And the event stream over a scripted
// socket: resume, resync reasons, live topics and the polling fallback.
import { http, HttpResponse, delay } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  ServerClock,
  TimescalesApi,
  TimescalesStream,
  type ResyncReason,
  type StreamEvent,
  type StreamState,
} from '../src/api/index.js';
import {
  ERROR_ROWS,
  ERROR_TABLE,
  KIND_ROWS,
  WALLET_ROWS,
  failureRow,
  problemToError,
  type FailureRow,
} from '../src/api/errors.js';
import {
  ERROR_CODES,
  EpochSummarySchema,
  MarketDetailSchema,
  MarketSummarySchema,
  StatusSchema,
  TapeRowSchema,
} from '../src/api/schemas.js';
import { b58, b64 } from '../src/core/index.js';
import { TimescalesError, type TimescalesErrorKind, type WalletErrorCode } from '../src/errors.js';
import { createTestRng, createTestWallet } from '../src/testing/index.js';
import { createFakeNode } from '../src/testing/node.js';
import { TradingSession } from '../src/wallet/index.js';

const BASE = 'http://api.timescales.test';
const server = setupServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
afterAll(() => server.close());

const api = (o: Partial<ConstructorParameters<typeof TimescalesApi>[0]> = {}) =>
  new TimescalesApi({ baseUrl: BASE, ...o });

function problem(code: string, status: number, extra: Record<string, unknown> = {}) {
  return HttpResponse.json(
    {
      type: `urn:timescales:error:${code.toLowerCase()}`,
      title: code,
      status,
      code,
      detail: `${code} happened`,
      retryable: status >= 500 || status === 429,
      request_id: 'req-1',
      ...extra,
    },
    { status, headers: { 'content-type': 'application/problem+json' } },
  );
}

const STATUS = {
  status: 'ok',
  server_time_ms: 1_000,
  components: [{ name: 'api', status: 'ok', since_ms: 1 }],
  markets: [],
};

describe('TimescalesApi', () => {
  it('retries 503 and network failures with backoff, but not client errors', async () => {
    let calls = 0;
    server.use(
      http.get(`${BASE}/v1/status`, () => {
        calls++;
        if (calls === 1) return HttpResponse.error();
        if (calls === 2) return problem('OVERLOADED', 503);
        return HttpResponse.json(STATUS);
      }),
    );
    expect((await api().status()).status).toBe('ok');
    expect(calls).toBe(3);

    calls = 0;
    server.use(
      http.get(`${BASE}/v1/status`, () => {
        calls++;
        return problem('DRAINING', 503, { retry_after_ms: 1 });
      }),
    );
    await expect(api().status()).rejects.toMatchObject({
      kind: 'api',
      code: 'DRAINING',
      retryable: true,
    });
    expect(calls).toBe(3);

    calls = 0;
    server.use(
      http.get(`${BASE}/v1/markets/:m`, () => {
        calls++;
        return problem('MARKET_UNKNOWN', 404);
      }),
    );
    const m = b58.encode(new Uint8Array(32).fill(1));
    await expect(api().market(m as never)).rejects.toMatchObject({
      code: 'MARKET_UNKNOWN',
      retryable: false,
    });
    expect(calls).toBe(1);
  });

  it('honours Retry-After and maps problems, unknown codes by HTTP class', async () => {
    let calls = 0;
    server.use(
      http.get(`${BASE}/v1/status`, () => {
        calls++;
        return calls === 1
          ? new HttpResponse(null, { status: 429, headers: { 'retry-after': '0' } })
          : HttpResponse.json(STATUS);
      }),
    );
    expect((await api().status()).status).toBe('ok');

    // A node cannot stall a call: a Retry-After beyond 10 s goes back to the caller.
    calls = 0;
    server.use(
      http.get(`${BASE}/v1/status`, () => {
        calls++;
        return new HttpResponse(null, { status: 503, headers: { 'retry-after': '86400' } });
      }),
    );
    await expect(api().status()).rejects.toMatchObject({
      retryable: true,
      retryAfterMs: 86_400_000,
    });
    expect(calls).toBe(1);

    const e = problemToError(409, {
      type: 'x',
      title: 'x',
      status: 409,
      code: 'EPOCH_CLOSED',
      detail: 'cutoff passed',
      retryable: true,
      retryAfterMs: 5,
      requestId: 'r',
      details: { next_epoch: '8' },
    });
    expect(e).toMatchObject({
      kind: 'api',
      code: 'EPOCH_CLOSED',
      retryable: true,
      retryAfterMs: 5,
      requestId: 'r',
      details: { next_epoch: '8' },
    });
    server.use(http.get(`${BASE}/v1/status`, () => problem('A_NEW_CODE', 409)));
    await expect(api().status()).rejects.toMatchObject({ code: 'unknown', retryable: false });
    expect(problemToError(503, null)).toMatchObject({ code: 'unknown', retryable: true });
  });

  it('times out a request that hangs', async () => {
    server.use(
      http.get(`${BASE}/v1/status`, async () => {
        await delay(500);
        return HttpResponse.json(STATUS);
      }),
    );
    await expect(api({ timeoutMs: 20, retries: 1 }).status()).rejects.toMatchObject({
      kind: 'timeout',
    });
  });

  it('treats a 2xx that does not match the schema as a node protocol violation', async () => {
    server.use(http.get(`${BASE}/v1/status`, () => HttpResponse.json({ status: 'ok' })));
    await expect(api().status()).rejects.toMatchObject({ kind: 'schema' });
  });

  it('refuses a node that speaks another API major, protocol or header version', async () => {
    const info = (over: Record<string, unknown>) =>
      http.get(`${BASE}/v1/info`, () =>
        HttpResponse.json({
          api_version: '1.3',
          protocol_version: 1,
          header_version: 2,
          node_version: 'x',
          git_sha: 'x',
          profile: 'devnet',
          cluster: 'devnet',
          genesis_hash: b58.encode(new Uint8Array(32).fill(1)),
          program_id: b58.encode(new Uint8Array(32).fill(2)),
          server_time_ms: 1,
          markets: [],
          trust: {
            enclave: 'some_future_enclave',
            quote_generation: 'simulated',
            quote_verification: 'simulated_vendor',
            key_generation: 'trusted_dealer_feldman',
            dkg: false,
            mpc: 'disabled',
            reference_price: 'fixed',
            receipt_quorum: 2,
            registered_executors: 3,
            notes: [],
          },
          limits: { submit_max_body_bytes: 1, session_max_ttl_s: 1 },
          a_field_from_the_future: true,
          ...over,
        }),
      );
    server.use(info({}));
    const ok = await api().info();
    expect(ok.trust.enclave).toBe('unknown');
    for (const over of [{ api_version: '2.0' }, { protocol_version: 2 }, { header_version: 1 }]) {
      server.use(info(over));
      await expect(api().info()).rejects.toMatchObject({ code: 'VERSION_UNSUPPORTED' });
    }
  });

  it('resends a submission with the same bytes and a fresh authorization', async () => {
    const n = createFakeNode({ seed: createTestRng(new Uint8Array([0xa1])).bytes(32) });
    const wallet = createTestWallet({ seed: new Uint8Array(32).fill(0x44) });
    const clock = new ServerClock();
    await clock.sync(n.api);
    const session = await TradingSession.open({
      api: n.api,
      wallet,
      info: await n.api.info(),
      clock,
      market: null,
    });
    const seen: { body: string; auth: string | null }[] = [];
    server.use(
      http.post(`${BASE}/v1/markets/:m/submissions/batch`, async ({ request }) => {
        seen.push({ body: await request.text(), auth: request.headers.get('authorization') });
        if (seen.length === 1) return problem('OVERLOADED', 503);
        return HttpResponse.json({ items: [] }, { status: 207 });
      }),
    );
    const submission = new Uint8Array(386).fill(3);
    await api().submitBatch(n.market, [submission], session);
    expect(seen).toHaveLength(2);
    expect(seen[0]!.body).toBe(seen[1]!.body);
    expect(JSON.parse(seen[0]!.body)).toEqual({ submissions_b64: [b64.encode(submission)] });
    expect(seen[0]!.auth).not.toBe(seen[1]!.auth);
    expect(seen[1]!.auth).toMatch(/^TimescalesSession [0-9a-f]{64}\.\d+\.[0-9a-f]{128}$/);
  });

  it('re-syncs the clock on SKEW and retries once', async () => {
    const n = createFakeNode({ seed: createTestRng(new Uint8Array([0xa2])).bytes(32) });
    const wallet = createTestWallet({ seed: new Uint8Array(32).fill(0x45) });
    const clock = new ServerClock();
    await clock.sync(n.api);
    const session = await TradingSession.open({
      api: n.api,
      wallet,
      info: await n.api.info(),
      clock,
      market: null,
    });
    let times = 0;
    let calls = 0;
    server.use(
      http.get(`${BASE}/v1/time`, () => {
        times++;
        return HttpResponse.json({ server_time_ms: Date.now() + 60_000, slot: '1' });
      }),
      http.get(`${BASE}/v1/sessions/current`, () => {
        calls++;
        if (calls === 1) return problem('SKEW', 401);
        return HttpResponse.json({
          session_key: '00'.repeat(32),
          wallet: wallet.address,
          market: null,
          expires_at_ms: 1,
          quotas: { max_envelopes_per_wallet_per_epoch: 1, max_parked_per_wallet: 1 },
          evicted: 2,
        });
      }),
    );
    const client = api({ clock });
    const s = await client.currentSession(session);
    expect(s.evicted).toBe(2);
    expect(calls).toBe(2);
    expect(times).toBe(5);
    expect(clock.skewMs()).toBeGreaterThan(55_000);
  });

  it('keeps unknown enum values as unknown and rejects malformed numbers', () => {
    expect(StatusSchema.parse({ ...STATUS, status: 'on_fire', markets: [] }).status).toBe(
      'unknown',
    );
    const market = b58.encode(new Uint8Array(32).fill(1));
    const m = {
      market,
      state: 'levitating',
      intake: 'open',
      pause_reason: 'solar_flare',
      current_epoch: null,
      last_committed: '18446744073709551615',
      last_settled: '0',
      settlement_lag: 0,
      keys_ready_ahead: 1,
    };
    const parsed = StatusSchema.parse({ ...STATUS, markets: [m] });
    expect(parsed.markets[0]).toMatchObject({
      state: 'unknown',
      pauseReason: 'unknown',
      lastCommitted: 2n ** 64n - 1n,
    });
    for (const bad of ['18446744073709551616', '01', '-1', '1.0', 7]) {
      expect(
        StatusSchema.safeParse({ ...STATUS, markets: [{ ...m, last_settled: bad }] }).success,
      ).toBe(false);
    }
    expect(MarketDetailSchema.safeParse({}).success).toBe(false);
  });

  it('leaves clearing entries for a book it does not know out of display lists', () => {
    const market = b58.encode(new Uint8Array(32).fill(1));
    const clearing = [
      { book: 'triple_book', tick: '14995', volume: '12' },
      { book: 'maker_bid_taker_ask', tick: '14990', volume: '0' },
      { book: 'toString', tick: '1', volume: '1' },
    ];
    const known = [{ book: 2, tick: 14990n, volume: 0n }];
    const summary = MarketSummarySchema.parse({
      market,
      name: 'SOL/USDC',
      base_symbol: 'SOL',
      quote_symbol: 'USDC',
      state: 'running',
      halted: false,
      last_clearing: clearing,
    });
    expect(summary.lastClearing).toEqual(known);
    const epoch = EpochSummarySchema.parse({
      market,
      epoch: '40',
      phase: 'finalized',
      opens_at_ms: 1_791_374_380_000,
      cutoff_ms: 1_791_374_390_000,
      envelope_count: 64,
      clearing,
      fill_count: 2,
      terminal_at_ms: null,
      abort_reason: null,
      tee_platform: 'amd_sev_snp',
    });
    expect(epoch).toMatchObject({ phase: 'unknown', teePlatform: 'unknown', clearing: known });
    const tape = {
      epoch: '40',
      cutoff_ms: 1_791_374_390_000,
      phase: 'settled',
      clearing,
      matched_lots: '12',
      fill_count: 2,
      envelope_count: 64,
      terminal_at_ms: null,
    };
    expect(TapeRowSchema.parse(tape).clearing).toEqual(known);
    // A malformed entry still fails the response, whatever its book.
    for (const book of ['single', 'triple_book']) {
      const bad = { ...tape, clearing: [{ book, tick: '-1', volume: '0' }] };
      expect(TapeRowSchema.safeParse(bad).success).toBe(false);
    }
  });
});

describe('failure rows', () => {
  const ROWS: readonly FailureRow[] = [
    'verification_failed',
    'verification_inconclusive',
    'epoch_key_not_vouched',
    'version_mismatch',
    'api_unreachable',
    'response_invalid',
    'clock_skew',
    'intake_paused',
    'market_halted',
    'market_unavailable',
    'wallet_declined',
    'wallet_changed',
    'wallet_busy',
    'session_error',
    'session_evicted',
    'not_eligible',
    'duplicate_commitment',
    'pruned',
    'capacity_refused',
    'partial_parking',
    'rate_limited',
    'journal_unavailable',
    'insecure_context',
  ];
  const WALLET_CODES: WalletErrorCode[] = [
    'rejected',
    'unsupported_feature',
    'modified_message',
    'bad_signature',
    'disconnected',
    'account_changed',
    'locked',
    'busy',
    'timeout',
    'abandoned',
    'unknown',
  ];
  const KINDS: TimescalesErrorKind[] = [
    'api',
    'network',
    'timeout',
    'schema',
    'wallet',
    'decode',
    'storage',
    'verify',
    'environment',
    'aborted',
  ];

  it('map every ErrorCode, WalletErrorCode and error kind to a row', () => {
    expect(Object.keys(ERROR_ROWS).sort()).toEqual([...ERROR_CODES].sort());
    expect(Object.keys(ERROR_TABLE).sort()).toEqual([...ERROR_CODES].sort());
    expect(Object.keys(WALLET_ROWS).sort()).toEqual([...WALLET_CODES].sort());
    expect(Object.keys(KIND_ROWS).sort()).toEqual([...KINDS].sort());
    for (const row of [
      ...Object.values(ERROR_ROWS),
      ...Object.values(WALLET_ROWS),
      ...Object.values(KIND_ROWS),
    ]) {
      expect(ROWS).toContain(row);
    }
    for (const code of ERROR_CODES) {
      expect(failureRow(new TimescalesError({ kind: 'api', code }))).toBe(ERROR_ROWS[code]);
    }
    expect(failureRow(new TimescalesError({ kind: 'api', code: 'SOMETHING_NEW' }))).toBe(
      'api_unreachable',
    );
    expect(failureRow(new TimescalesError({ kind: 'storage', code: 'quota_exceeded' }))).toBe(
      'journal_unavailable',
    );
  });
});

describe('ServerClock', () => {
  it('takes the median of five samples, RTT/2 corrected', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(1_000_000);
    const offsets = [100, 200, 300, 5_000, 250];
    let i = 0;
    server.use(
      http.get(`${BASE}/v1/time`, () =>
        HttpResponse.json({ server_time_ms: Date.now() + offsets[i++ % 5]!, slot: '9' }),
      ),
    );
    const clock = new ServerClock();
    await clock.sync(api());
    expect(clock.skewMs()).toBe(250);
    expect(clock.now()).toBe(1_000_250);
  });
});

type Frame = Record<string, unknown>;

class Socket extends EventTarget {
  static all: Socket[] = [];
  readyState = 0;
  readonly url: string;
  readonly sent: Frame[] = [];

  constructor(url: string) {
    super();
    this.url = url;
    Socket.all.push(this);
  }

  open(): void {
    this.readyState = 1;
    this.dispatchEvent(new Event('open'));
  }

  send(data: string): void {
    this.sent.push(JSON.parse(data) as Frame);
  }

  receive(frame: Frame): void {
    const data = JSON.stringify(frame, (_k, v: unknown) =>
      typeof v === 'bigint' ? v.toString() : v,
    );
    this.dispatchEvent(new MessageEvent('message', { data }));
  }

  close(code = 1000): void {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.dispatchEvent(new CloseEvent('close', { code }));
  }
}

const MARKET = b58.encode(new Uint8Array(32).fill(7));
const TOPIC = `market:${MARKET}`;

function stream(o: { pollFallback?: (topics: string[]) => Promise<void> } = {}) {
  Socket.all = [];
  const s = new TimescalesStream({
    url: 'ws://node.test/v1/stream',
    WebSocketImpl: Socket as unknown as typeof WebSocket,
    backoff: { initialMs: 1, maxMs: 1 },
    ...o,
  });
  const events: StreamEvent[] = [];
  const states: StreamState[] = [];
  const resyncs: ResyncReason[] = [];
  s.on('event', (e) => events.push(e));
  s.on('state', (x) => states.push(x));
  s.on('resync', (r) => resyncs.push(r));
  return { s, events, states, resyncs, sock: () => Socket.all.at(-1)! };
}

function subscribed(streamId: string, head: number, topicSeq: number): Frame {
  return {
    v: 1,
    type: 'subscribed',
    topics: [TOPIC],
    head_seq: String(head),
    stream_id: streamId,
    topic_seqs: { [TOPIC]: String(topicSeq) },
  };
}

function event(seq: number, topicSeq: number, body: Frame, topic = TOPIC): Frame {
  return {
    v: 1,
    type: 'event',
    seq: String(seq),
    topic,
    topic_seq: String(topicSeq),
    at_ms: 5,
    event: body,
  };
}

describe('TimescalesStream', () => {
  it('subscribes, decodes events and detects topic_seq gaps', () => {
    const t = stream();
    t.s.subscribe([TOPIC]);
    expect(t.states).toEqual(['connecting']);
    t.sock().open();
    expect(t.sock().sent).toEqual([{ op: 'subscribe', topics: [TOPIC] }]);
    t.sock().receive(subscribed('aa', 10, 4));
    expect(t.states.at(-1)).toBe('live');
    t.sock().receive(event(11, 5, { kind: 'epoch.closed', market: MARKET, epoch: '9' }));
    t.sock().receive(event(12, 5, { kind: 'epoch.closed', market: MARKET, epoch: '9' }));
    t.sock().receive(event(13, 1, { kind: 'status.changed' }, 'status'));
    t.sock().receive(event(14, 7, { kind: 'a.new.kind', market: MARKET }));
    expect(t.events.map((e) => [e.kind, e.topicSeq])).toEqual([
      ['epoch.closed', 5n],
      ['unknown', 7n],
    ]);
    expect(t.events[0]).toMatchObject({ seq: 11n, market: MARKET, epoch: 9n });
    expect(t.resyncs).toEqual(['gap']);
    t.s.close();
    expect(t.states.at(-1)).toBe('closed');
  });

  it('resumes with since_seq on the same stream and resyncs when it changed', async () => {
    const t = stream();
    t.s.subscribe([TOPIC]);
    t.sock().open();
    t.sock().receive(subscribed('aa', 10, 4));
    t.sock().receive(event(11, 5, { kind: 'epoch.closed', market: MARKET, epoch: '9' }));
    t.sock().close(1006);
    expect(t.states.at(-1)).toBe('reconnecting');
    await vi.waitFor(() => expect(Socket.all).toHaveLength(2));
    t.sock().open();
    expect(t.sock().sent).toEqual([{ op: 'subscribe', topics: [TOPIC], since_seq: '11' }]);
    t.sock().receive(subscribed('aa', 11, 5));
    expect(t.resyncs).toEqual(['reconnected']);
    t.sock().close(1006);
    await vi.waitFor(() => expect(Socket.all).toHaveLength(3));
    t.sock().open();
    t.sock().receive(subscribed('bb', 2, 1));
    expect(t.resyncs).toEqual(['reconnected', 'stream_changed']);
    // Topic sequences restart with the new stream: no false gap.
    t.sock().receive(event(3, 2, { kind: 'epoch.closed', market: MARKET, epoch: '10' }));
    expect(t.resyncs).toHaveLength(2);
    t.s.close();
  });

  it('resyncs after close 4008, resync_required and a heartbeat from another stream', async () => {
    const t = stream();
    t.s.subscribe([TOPIC]);
    t.sock().open();
    t.sock().receive(subscribed('aa', 10, 4));
    t.sock().receive({ v: 1, type: 'resync_required', reason: 'seq_too_old' });
    expect(t.resyncs).toEqual(['seq_too_old']);
    expect(t.sock().sent.at(-1)).toEqual({ op: 'subscribe', topics: [TOPIC] });
    t.sock().receive({
      v: 1,
      type: 'heartbeat',
      server_time_ms: 1,
      head_seq: '1',
      stream_id: 'cc',
    });
    expect(t.resyncs).toEqual(['seq_too_old', 'stream_changed']);
    t.sock().close(4008);
    expect(t.resyncs.at(-1)).toBe('lagged');
    await vi.waitFor(() => expect(Socket.all).toHaveLength(2));
    t.sock().open();
    expect(t.sock().sent).toEqual([{ op: 'subscribe', topics: [TOPIC] }]);
    t.s.close();
  });

  it('changes topics live', () => {
    const t = stream();
    t.s.subscribe([TOPIC]);
    t.sock().open();
    t.sock().receive(subscribed('aa', 1, 1));
    t.s.subscribe([TOPIC, 'status']);
    t.s.unsubscribe([TOPIC]);
    expect(t.sock().sent.slice(1)).toEqual([
      { op: 'subscribe', topics: ['status'] },
      { op: 'unsubscribe', topics: [TOPIC] },
    ]);
    t.sock().receive(event(5, 9, { kind: 'epoch.closed', market: MARKET, epoch: '1' }));
    expect(t.events).toEqual([]);
    t.s.close();
  });

  it('falls back to polling when the socket stays down, and stops once live', async () => {
    vi.useFakeTimers();
    const polls: string[][] = [];
    const t = stream({
      pollFallback: (topics) => {
        polls.push(topics);
        return Promise.resolve();
      },
    });
    t.s.subscribe([TOPIC]);
    await vi.advanceTimersByTimeAsync(19_000);
    expect(polls).toEqual([]);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(t.states).toContain('polling');
    expect(polls).toEqual([[TOPIC]]);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(polls).toHaveLength(2);
    t.sock().open();
    t.sock().receive(subscribed('aa', 1, 1));
    expect(t.states.at(-1)).toBe('live');
    await vi.advanceTimersByTimeAsync(30_000);
    expect(polls).toHaveLength(2);
    t.s.close();
  });

  it('polls at once without any WebSocket', () => {
    const polls: string[][] = [];
    vi.stubGlobal('WebSocket', undefined);
    const t2 = new TimescalesStream({
      url: 'ws://x',
      pollFallback: (topics) => {
        polls.push(topics);
        return Promise.resolve();
      },
    });
    const states: StreamState[] = [];
    t2.on('state', (x) => states.push(x));
    t2.subscribe(['status']);
    expect(states).toEqual(['polling']);
    expect(polls).toEqual([['status']]);
    t2.close();
  });

  it('checks a visible tab and catches up after 45 s of silence', () => {
    const listeners: (() => void)[] = [];
    const doc = {
      visibilityState: 'visible',
      addEventListener: (_: string, f: () => void) => listeners.push(f),
    };
    vi.stubGlobal('document', doc);
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(1_000_000);
    const t = stream();
    t.s.subscribe([TOPIC]);
    t.sock().open();
    t.sock().receive(subscribed('aa', 1, 1));
    for (const f of listeners) f();
    expect(t.sock().sent.at(-1)).toMatchObject({ op: 'ping' });
    expect(t.resyncs).toEqual([]);
    vi.setSystemTime(1_000_000 + 46_000);
    for (const f of listeners) f();
    expect(t.resyncs).toEqual(['visible']);
    t.s.close();
  });
});
