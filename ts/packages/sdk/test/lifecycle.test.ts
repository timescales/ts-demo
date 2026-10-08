// ORDER_LIFECYCLE and PARTICIPATION_LIFECYCLE against the reducer: every
// (state, event) pair, every table row reached, out-of-order events, badge
// precedence, and a model test over random interleavings.
import type { Address } from '@solana/kit';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  ORDER_LIFECYCLE,
  PARTICIPATION_LIFECYCLE,
  badge,
  reduce,
  type OrderEvent,
  type OrderRecord,
  type OrderState,
  type Participation,
  type ParticipationState,
} from '../src/orders/index.js';

const MARKET = '11111111111111111111111111111112' as Address;
const QUANTITY = 10n;

const ORDER_KINDS: OrderState['kind'][] = [
  'draft',
  'awaiting_wallet',
  'wallet_rejected',
  'unsupported_wallet',
  'abandoned',
  'signed_too_late',
  'submitting',
  'submit_failed',
  'working',
  'paused_needs_app',
  'reseal_needs_consent',
  'filled',
  'expired',
  'cancel_pending',
  'cancelled',
  'cancel_too_late',
  'verification_failed',
];

const PARTICIPATION_STATES: ParticipationState[] = [
  { kind: 'sealed' },
  { kind: 'parked' },
  { kind: 'locked' },
  { kind: 'included' },
  { kind: 'excluded', evidenceId: 'e' },
  { kind: 'clearing', delayed: false },
  { kind: 'provisional', have: 1, need: 2 },
  { kind: 'verified', filled: 2n },
  { kind: 'settling', done: 1, total: 2 },
  { kind: 'settled', filled: 2n },
  { kind: 'voided', outcomeWasPublic: false },
  { kind: 'not_submitted', reason: 'quota' },
  { kind: 'not_submitted', reason: 'invalidated' },
];

const IN_FLIGHT = new Set([
  'locked',
  'included',
  'clearing',
  'provisional',
  'verified',
  'settling',
]);
const GATED_ENDS = new Set(['filled', 'expired', 'cancelled', 'cancel_too_late']);

function orderState(kind: OrderState['kind'], epoch = 1n): OrderState {
  switch (kind) {
    case 'submit_failed':
      return { kind, code: 'OVERLOADED', retryable: true };
    case 'reseal_needs_consent':
    case 'cancel_pending':
      return { kind, epoch };
    case 'verification_failed':
      return { kind, check: 'V-7' };
    default:
      return { kind } as OrderState;
  }
}

/** Every event kind with the payload variants the reducer distinguishes, about `epoch`. */
function events(epoch: bigint): OrderEvent[] {
  const e = (x: Record<string, unknown>) => ({ atMs: 1, ...x }) as OrderEvent;
  return [
    e({ kind: 'prepared' }),
    e({ kind: 'wallet_prompted' }),
    e({ kind: 'wallet_rejected' }),
    e({ kind: 'wallet_unsupported' }),
    e({ kind: 'abandoned' }),
    e({ kind: 'signed', late: false }),
    e({ kind: 'signed', late: true }),
    e({ kind: 'submitted', epoch, result: 'accepted' }),
    e({ kind: 'submitted', epoch, result: 'parked' }),
    ...['QUOTA_EXCEEDED', 'BATCH_FULL', 'EPOCH_KEY_UNAVAILABLE', 'EPOCH_CLOSED', 'OVERLOADED'].map(
      (code) => e({ kind: 'submitted', epoch, result: 'refused', code }),
    ),
    e({ kind: 'promise_verified', epoch }),
    e({ kind: 'epoch_locked', epoch }),
    e({ kind: 'epoch_locked', epoch: epoch + 1n }),
    e({ kind: 'inclusion', epoch, inclusion: 'included' }),
    e({ kind: 'inclusion', epoch, inclusion: 'excluded' }),
    e({ kind: 'inclusion', epoch, inclusion: 'substituted' }),
    e({ kind: 'revealed', epoch }),
    e({ kind: 'receipt', epoch, quorumMet: false }),
    e({ kind: 'receipt', epoch, quorumMet: true }),
    e({ kind: 'fills', epoch, filled: 0n }),
    e({ kind: 'fills', epoch, filled: 2n }),
    e({ kind: 'fills', epoch, filled: QUANTITY }),
    e({ kind: 'settlement', epoch, done: 1, total: 2 }),
    e({ kind: 'settled', epoch }),
    e({ kind: 'aborted', epoch, outcomeWasPublic: false }),
    e({ kind: 'aborted', epoch, outcomeWasPublic: true }),
    e({ kind: 'governance_applied', change: 'set_relay' }),
    e({ kind: 'parked_invalidated', epochs: [epoch] }),
    e({ kind: 'expired' }),
    e({ kind: 'cancel_submitted', epoch }),
    e({ kind: 'cancel_result', result: 'cancelled' }),
    e({ kind: 'cancel_result', result: 'too_late' }),
    e({ kind: 'verification_failed', check: 'V-7' }),
  ];
}

function participation(epoch: bigint, state: ParticipationState): Participation {
  return {
    epoch,
    envelopeDigest: new Uint8Array(32).fill(Number(epoch)),
    submission: new Uint8Array(386),
    promise: new Uint8Array(201),
    relayAtSubmission: MARKET,
    state,
  };
}

function record(
  state: OrderState,
  parts: Participation[],
  history: OrderEvent[] = [],
): OrderRecord {
  return {
    id: 'r',
    version: 1,
    market: MARKET,
    body: {
      kind: 'place',
      order: {
        market: 1n,
        trader: new Uint8Array(32).fill(1),
        nonce: 1n,
        side: 0,
        role: 0,
        kind: 0,
        limit: 100n,
        quantity: QUANTITY,
        validFrom: 1n,
        expiresAt: 5n,
      },
    },
    salt: new Uint8Array(32),
    signature: new Uint8Array(64),
    commitment: new Uint8Array(32).fill(2),
    state,
    epochs: new Map(parts.map((p) => [p.epoch, p])),
    filled: 0n,
    fills: [],
    history,
    evidence: [],
  };
}

const key = (r: { from: string; on: string; to: string }) => `${r.from} --${r.on}--> ${r.to}`;

describe('lifecycle tables', () => {
  it('have no duplicate rows and only known kinds', () => {
    for (const table of [ORDER_LIFECYCLE, PARTICIPATION_LIFECYCLE]) {
      const keys = table.map(key);
      expect(new Set(keys).size).toBe(keys.length);
    }
    for (const r of ORDER_LIFECYCLE) {
      expect(ORDER_KINDS).toContain(r.from);
      expect(ORDER_KINDS).toContain(r.to);
      expect(r.from).not.toBe(r.to);
    }
    const pk = new Set(PARTICIPATION_STATES.map((s) => s.kind));
    for (const r of PARTICIPATION_LIFECYCLE) {
      expect(pk.has(r.from) && pk.has(r.to)).toBe(true);
      expect(r.from).not.toBe(r.to);
    }
  });

  it('every participation (state, event) pair moves along a table row or stays put', () => {
    const rows = new Set(PARTICIPATION_LIFECYCLE.map(key));
    const reached = new Set<string>();
    // The participation under test is epoch 3. Epoch 4 holds another one, so
    // events about epoch 4 can end the order around it.
    const others: ParticipationState[] = [
      { kind: 'parked' },
      { kind: 'verified', filled: 0n },
      { kind: 'clearing', delayed: false },
    ];
    const histories: OrderEvent[][] = [[], [{ atMs: 0, kind: 'expired' }]];
    for (const order of ['working', 'cancel_pending'] as const) {
      for (const s of PARTICIPATION_STATES) {
        for (const other of others) {
          for (const history of histories) {
            for (const e of [...events(3n), ...events(4n)]) {
              const r = record(
                orderState(order, 3n),
                [participation(3n, s), participation(4n, other)],
                history,
              );
              const to = reduce(r, e).epochs.get(3n)!.state.kind;
              if (to === s.kind) continue;
              const k = key({ from: s.kind, on: e.kind, to });
              expect(rows.has(k), k).toBe(true);
              reached.add(k);
            }
          }
        }
      }
    }
    expect([...rows].filter((k) => !reached.has(k))).toEqual([]);
  });

  it('every order (state, event) pair moves along a table row or stays put', () => {
    const rows = new Set(ORDER_LIFECYCLE.map(key));
    const reached = new Set<string>();
    const situations: Participation[][] = [
      [],
      [participation(1n, { kind: 'sealed' })],
      [participation(1n, { kind: 'verified', filled: QUANTITY })],
      [participation(1n, { kind: 'verified', filled: 2n })],
      [participation(1n, { kind: 'clearing', delayed: false })],
      [participation(1n, { kind: 'included' })],
      [participation(1n, { kind: 'settled', filled: 2n }), participation(2n, { kind: 'parked' })],
      [
        participation(1n, { kind: 'settled', filled: QUANTITY }),
        participation(2n, { kind: 'locked' }),
      ],
      [
        participation(1n, { kind: 'locked' }),
        participation(2n, { kind: 'settled', filled: QUANTITY }),
      ],
    ];
    const histories: OrderEvent[][] = [
      [],
      [{ atMs: 0, kind: 'expired' }],
      [
        { atMs: 0, kind: 'cancel_submitted', epoch: 1n },
        { atMs: 0, kind: 'cancel_result', result: 'cancelled' },
      ],
      [
        { atMs: 0, kind: 'cancel_submitted', epoch: 1n },
        { atMs: 0, kind: 'cancel_result', result: 'too_late' },
      ],
    ];
    for (const kind of ORDER_KINDS) {
      for (const parts of situations) {
        for (const history of histories) {
          for (const e of [...events(1n), ...events(2n)]) {
            const next = reduce(record(orderState(kind), parts, history), e);
            if (next.state.kind === kind) continue;
            const k = key({ from: kind, on: e.kind, to: next.state.kind });
            expect(rows.has(k), k).toBe(true);
            reached.add(k);
          }
        }
      }
    }
    expect([...rows].filter((k) => !reached.has(k))).toEqual([]);
  });
});

describe('reducer', () => {
  it('ignores events that arrive out of order', () => {
    const r = record({ kind: 'working' }, [participation(1n, { kind: 'sealed' })]);
    const e = (x: Record<string, unknown>) => ({ atMs: 1, ...x }) as OrderEvent;
    // Settled, fills and a reveal before the epoch is even locked change nothing.
    for (const early of [
      e({ kind: 'settled', epoch: 1n }),
      e({ kind: 'fills', epoch: 1n, filled: 3n }),
      e({ kind: 'revealed', epoch: 1n }),
      e({ kind: 'receipt', epoch: 1n, quorumMet: false }),
    ]) {
      expect(reduce(r, early).epochs.get(1n)!.state).toEqual({ kind: 'sealed' });
    }
    // Events about another epoch leave this one alone.
    expect(
      reduce(r, e({ kind: 'aborted', epoch: 2n, outcomeWasPublic: false })).epochs.get(1n)!.state,
    ).toEqual({ kind: 'sealed' });
    // A late exclusion still reaches a participation that is already clearing.
    const clearing = record({ kind: 'working' }, [
      participation(1n, { kind: 'clearing', delayed: false }),
    ]);
    expect(
      reduce(clearing, e({ kind: 'inclusion', epoch: 1n, inclusion: 'excluded' })).epochs.get(1n)!
        .state.kind,
    ).toBe('excluded');
  });

  it('drops the quantity of a verified participation that a late V-6 result excludes', () => {
    const e = (x: Record<string, unknown>) => ({ atMs: 1, ...x }) as OrderEvent;
    let r = record({ kind: 'working' }, [participation(1n, { kind: 'clearing', delayed: false })]);
    r = reduce(r, e({ kind: 'fills', epoch: 1n, filled: 4n }));
    expect(r.filled).toBe(4n);
    r = reduce(r, e({ kind: 'inclusion', epoch: 1n, inclusion: 'excluded' }));
    expect(r.epochs.get(1n)!.state.kind).toBe('excluded');
    expect(r.filled).toBe(0n);
    expect(badge(r)).toEqual({ state: 'excluded', epoch: 1n });
  });

  it('keeps the history, the filled quantity and the fills of each epoch', () => {
    const e = (x: Record<string, unknown>) => ({ atMs: 1, ...x }) as OrderEvent;
    let r = record({ kind: 'working' }, [
      participation(1n, { kind: 'included' }),
      participation(2n, { kind: 'parked' }),
    ]);
    r = reduce(r, e({ kind: 'fills', epoch: 1n, filled: 4n }));
    expect(r.filled).toBe(4n);
    r = reduce(r, e({ kind: 'settlement', epoch: 1n, done: 1, total: 3 }));
    expect(r.epochs.get(1n)!.state).toEqual({ kind: 'settling', done: 1, total: 3 });
    expect(r.filled).toBe(4n);
    r = reduce(r, e({ kind: 'settled', epoch: 1n }));
    expect(r.epochs.get(1n)!.state).toEqual({ kind: 'settled', filled: 4n });
    expect(r.state.kind).toBe('working');
    expect(r.history.map((h) => h.kind)).toEqual(['fills', 'settlement', 'settled']);
  });

  it('ends a filled order only once nothing is in flight, and withdraws what still waits', () => {
    const e = (x: Record<string, unknown>) => ({ atMs: 1, ...x }) as OrderEvent;
    let r = record({ kind: 'working' }, [
      participation(1n, { kind: 'included' }),
      participation(2n, { kind: 'parked' }),
    ]);
    r = reduce(r, e({ kind: 'fills', epoch: 1n, filled: QUANTITY }));
    expect(r.state.kind).toBe('working');
    r = reduce(r, e({ kind: 'settled', epoch: 1n }));
    expect(r.state.kind).toBe('filled');
    expect(r.epochs.get(2n)!.state).toEqual({ kind: 'not_submitted', reason: 'invalidated' });
    // A late response cannot revive a finished order's envelope.
    expect(
      reduce(r, e({ kind: 'submitted', epoch: 2n, result: 'accepted' })).epochs.get(2n)!.state.kind,
    ).toBe('not_submitted');
  });

  it('keeps a refused submission in the outbox when the relay did not decide', () => {
    const e = (x: Record<string, unknown>) => ({ atMs: 1, ...x }) as OrderEvent;
    const r = record({ kind: 'submitting' }, [
      { ...participation(1n, { kind: 'sealed' }), promise: null },
    ]);
    const shed = reduce(
      r,
      e({ kind: 'submitted', epoch: 1n, result: 'refused', code: 'OVERLOADED' }),
    );
    expect(shed.state).toEqual({ kind: 'submit_failed', code: 'OVERLOADED', retryable: true });
    expect(shed.epochs.get(1n)!.state.kind).toBe('sealed');
    // A session the node no longer honours: the bytes wait for a new session.
    for (const code of ['SESSION_UNKNOWN', 'SESSION_EXPIRED', 'SESSION_REVOKED']) {
      const lost = reduce(r, e({ kind: 'submitted', epoch: 1n, result: 'refused', code }));
      expect(lost.state).toEqual({ kind: 'submit_failed', code, retryable: true });
      expect(lost.epochs.get(1n)!.state.kind).toBe('sealed');
    }
    const full = reduce(
      r,
      e({ kind: 'submitted', epoch: 1n, result: 'refused', code: 'BATCH_FULL' }),
    );
    expect(full.state).toEqual({ kind: 'submit_failed', code: 'BATCH_FULL', retryable: false });
    expect(full.epochs.get(1n)!.state).toEqual({ kind: 'not_submitted', reason: 'batch_full' });
  });
});

describe('badge', () => {
  const p = (epoch: bigint, state: ParticipationState) => participation(epoch, state);

  it('follows the precedence', () => {
    expect(
      badge(
        record({ kind: 'verification_failed', check: 'V-6' }, [
          p(1n, { kind: 'excluded', evidenceId: 'x' }),
        ]),
      ),
    ).toEqual({ state: 'verification_failed' });
    expect(
      badge(record({ kind: 'filled' }, [p(1n, { kind: 'excluded', evidenceId: 'x' })])),
    ).toEqual({
      state: 'excluded',
      epoch: 1n,
    });
    expect(
      badge(record({ kind: 'cancel_pending', epoch: 4n }, [p(3n, { kind: 'locked' })])),
    ).toEqual({
      state: 'cancel_pending',
      epoch: 4n,
    });
    expect(badge(record({ kind: 'expired' }, []))).toEqual({ state: 'expired' });
    const parts = [
      p(1n, { kind: 'settling', done: 1, total: 2 }),
      p(2n, { kind: 'clearing', delayed: false }),
      p(3n, { kind: 'parked' }),
    ];
    expect(badge(record({ kind: 'working' }, parts))).toEqual({ state: 'clearing', epoch: 2n });
    expect(
      badge(record({ kind: 'working' }, [p(3n, { kind: 'parked' }), p(2n, { kind: 'parked' })])),
    ).toEqual({ state: 'parked', epoch: 2n });
    expect(
      badge(record({ kind: 'working' }, [p(1n, { kind: 'voided', outcomeWasPublic: false })])),
    ).toEqual({ state: 'working' });
  });

  it('orders in-flight participations provisional, clearing, included, locked, settling, verified, sealed, parked', () => {
    const order: ParticipationState[] = [
      { kind: 'provisional', have: 1, need: 2 },
      { kind: 'clearing', delayed: true },
      { kind: 'included' },
      { kind: 'locked' },
      { kind: 'settling', done: 0, total: 1 },
      { kind: 'verified', filled: 0n },
      { kind: 'sealed' },
      { kind: 'parked' },
    ];
    for (let i = 0; i < order.length; i++) {
      // The lower-priority states sit in earlier epochs: priority beats age.
      const parts = order.slice(i).map((s, j) => p(BigInt(order.length - j), s));
      expect(badge(record({ kind: 'working' }, parts)).state).toBe(order[i]!.kind);
    }
  });
});

describe('model', () => {
  const EPOCHS = [1n, 2n, 3n];
  const arbEvent = fc.tuple(fc.constantFrom(...EPOCHS), fc.nat({ max: 1000 })).map(([epoch, i]) => {
    const all = events(epoch);
    return all[i % all.length]!;
  });

  it('never ends an order while a participation is in flight, and anything at the relay can still be voided', () => {
    fc.assert(
      fc.property(fc.array(arbEvent, { maxLength: 60 }), (seq) => {
        let r = record({ kind: 'working' }, [
          participation(1n, { kind: 'sealed' }),
          participation(2n, { kind: 'parked' }),
          participation(3n, { kind: 'parked' }),
        ]);
        for (const e of seq) {
          r = reduce(r, e);
          if (GATED_ENDS.has(r.state.kind)) {
            for (const x of r.epochs.values()) expect(IN_FLIGHT.has(x.state.kind)).toBe(false);
          }
        }
        for (const x of r.epochs.values()) {
          if (
            x.state.kind === 'sealed' ||
            x.state.kind === 'parked' ||
            IN_FLIGHT.has(x.state.kind)
          ) {
            const voided = reduce(r, {
              atMs: 2,
              kind: 'aborted',
              epoch: x.epoch,
              outcomeWasPublic: false,
            });
            expect(voided.epochs.get(x.epoch)!.state.kind).toBe('voided');
          }
        }
      }),
      { numRuns: 500 },
    );
  });
});
