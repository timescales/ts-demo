import type { OwnFill } from '../verify/fills.js';
import type {
  OrderEvent,
  OrderRecord,
  OrderState,
  Participation,
  ParticipationState,
} from './model.js';
import {
  IN_FLIGHT,
  PENDING,
  filledIn,
  nextParticipation,
  resendable,
  type Supplement,
} from './participation.js';

type OrderKind = OrderState['kind'];

/** Order states that only a verification failure can leave. */
export const TERMINAL: ReadonlySet<OrderKind> = new Set<OrderKind>([
  'wallet_rejected',
  'unsupported_wallet',
  'abandoned',
  'signed_too_late',
  'filled',
  'expired',
  'cancelled',
  'cancel_too_late',
  'verification_failed',
]);

/** A resting order: it ends (filled or expired) once nothing is in flight. */
const RESTING: readonly OrderKind[] = ['working', 'paused_needs_app', 'reseal_needs_consent'];

/** Events that can end the last participation in flight, or record why the order ends. */
const ENDING: readonly OrderEvent['kind'][] = ['settled', 'aborted', 'inclusion', 'expired'];

type Row = { from: OrderKind; on: OrderEvent['kind']; to: OrderKind };

function rows(
  from: readonly OrderKind[],
  on: readonly OrderEvent['kind'][],
  to: OrderKind[],
): Row[] {
  return from.flatMap((f) => on.flatMap((o) => to.map((t) => ({ from: f, on: o, to: t }))));
}

/**
 * Order-level transitions. Rows with the same `from` and `on` are
 * alternatives chosen by the event's payload and the record: `filled`,
 * `expired`, `cancelled` and `cancel_too_late` are reached only by an event
 * after which no participation is in flight. Pairs not listed leave the
 * order state unchanged. `verification_failed` is reachable from every
 * other state.
 */
export const ORDER_LIFECYCLE: ReadonlyArray<{
  from: OrderState['kind'];
  on: OrderEvent['kind'];
  to: OrderState['kind'];
}> = Object.freeze([
  // Signing (V-11): one wallet prompt.
  { from: 'draft', on: 'wallet_prompted', to: 'awaiting_wallet' },
  { from: 'draft', on: 'abandoned', to: 'abandoned' },
  { from: 'awaiting_wallet', on: 'wallet_rejected', to: 'wallet_rejected' },
  { from: 'awaiting_wallet', on: 'wallet_unsupported', to: 'unsupported_wallet' },
  { from: 'awaiting_wallet', on: 'abandoned', to: 'abandoned' },
  { from: 'awaiting_wallet', on: 'signed', to: 'submitting' },
  { from: 'awaiting_wallet', on: 'signed', to: 'signed_too_late' },
  // Submission. A failure keeps the exact bytes in the outbox.
  { from: 'submitting', on: 'submitted', to: 'working' },
  { from: 'submitting', on: 'submitted', to: 'submit_failed' },
  { from: 'submit_failed', on: 'submitted', to: 'working' },
  { from: 'paused_needs_app', on: 'submitted', to: 'working' },
  // Resting across epochs.
  { from: 'working', on: 'epoch_locked', to: 'paused_needs_app' },
  { from: 'working', on: 'aborted', to: 'reseal_needs_consent' },
  { from: 'paused_needs_app', on: 'aborted', to: 'reseal_needs_consent' },
  // Cancel: a sealed Cancel in the placement's epoch.
  ...rows(
    ['working', 'paused_needs_app', 'reseal_needs_consent', 'submit_failed'],
    ['cancel_submitted'],
    ['cancel_pending'],
  ),
  { from: 'cancel_pending', on: 'aborted', to: 'working' },
  // The cancel's epoch was voided after the order filled or its window ran out.
  { from: 'cancel_pending', on: 'aborted', to: 'filled' },
  { from: 'cancel_pending', on: 'aborted', to: 'expired' },
  ...rows(
    ['cancel_pending'],
    ['cancel_result', 'settled', 'aborted', 'inclusion', 'expired'],
    ['cancelled', 'cancel_too_late'],
  ),
  // Ends that wait until nothing is in flight.
  ...rows(RESTING, ['settled', 'aborted', 'inclusion'], ['filled', 'expired']),
  ...rows(RESTING, ['expired'], ['expired']),
  { from: 'submit_failed', on: 'expired', to: 'expired' },
  // Any failed verifier check.
  ...(
    [
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
    ] as const
  ).map((from) => ({
    from,
    on: 'verification_failed' as const,
    to: 'verification_failed' as const,
  })),
]);

function inFlight(epochs: ReadonlyMap<bigint, Participation>): boolean {
  for (const p of epochs.values()) if (IN_FLIGHT.has(p.state.kind)) return true;
  return false;
}

/** At the relay, or about to be: sealed, parked or in flight. */
function live(epochs: ReadonlyMap<bigint, Participation>): boolean {
  for (const p of epochs.values()) {
    if (PENDING.has(p.state.kind) || IN_FLIGHT.has(p.state.kind)) return true;
  }
  return false;
}

/** The quantity filled in verified, settling and settled participations. */
function filledTotal(
  epochs: ReadonlyMap<bigint, Participation>,
  history: readonly OrderEvent[],
): bigint {
  let total = 0n;
  for (const p of epochs.values()) {
    const s = p.state;
    if (s.kind === 'verified' || s.kind === 'settled') total += s.filled;
    else if (s.kind === 'settling') total += filledIn(history, p.epoch);
  }
  return total;
}

/**
 * The last epoch a participation covered (anything but `not_submitted`), or
 * null. An epoch of the window that closes after it means the order outlived
 * its participations while no tab could seal it again.
 */
function lastCovered(epochs: ReadonlyMap<bigint, Participation>): bigint | null {
  let last: bigint | null = null;
  for (const p of epochs.values()) {
    if (p.state.kind !== 'not_submitted' && (last === null || p.epoch > last)) last = p.epoch;
  }
  return last;
}

/** The order an intent places, if it places one. */
function placed(r: OrderRecord): { quantity: bigint; validFrom: bigint; expiresAt: bigint } | null {
  return r.body.kind === 'place' ? r.body.order : null;
}

function lastOf<K extends OrderEvent['kind']>(
  history: readonly OrderEvent[],
  kind: K,
): Extract<OrderEvent, { kind: K }> | undefined {
  for (let i = history.length - 1; i >= 0; i--) {
    const h = history[i]!;
    if (h.kind === kind) return h as Extract<OrderEvent, { kind: K }>;
  }
  return undefined;
}

/** The result of the current cancel, if one arrived after the last cancel submission. */
function cancelOutcome(history: readonly OrderEvent[]): 'cancelled' | 'too_late' | null {
  for (let i = history.length - 1; i >= 0; i--) {
    const h = history[i]!;
    if (h.kind === 'cancel_submitted') return null;
    if (h.kind === 'cancel_result') return h.result === 'cancelled' ? 'cancelled' : 'too_late';
  }
  return null;
}

/**
 * Fills of `epoch`, appended when it was verified. Epochs verify in order
 * (one batch in flight per market), so its fills are the trailing ones
 * whose quantities add up to what that epoch's `fills` event reported.
 */
function withoutEpochFills(
  fills: OwnFill[],
  history: readonly OrderEvent[],
  epoch: bigint,
): OwnFill[] {
  let left = filledIn(history, epoch);
  let cut = fills.length;
  while (left > 0n && cut > 0) {
    left -= fills[cut - 1]!.quantity;
    cut--;
  }
  return fills.slice(0, cut);
}

/**
 * The pure reducer, with the data some events do not carry: the live
 * quorum of a `receipt`, the evidence saved for an exclusion or refusal, the
 * verified promise of a `submitted`, and the own fills behind `fills`.
 */
export function reduceWith(
  r: OrderRecord,
  e: OrderEvent,
  s: Supplement & { fills?: OwnFill[] } = {},
): OrderRecord {
  const history = [...r.history, e];
  const epochs = new Map(r.epochs);
  let fills = r.fills;
  const ended = TERMINAL.has(r.state.kind) && r.state.kind !== 'verification_failed';

  for (const [at, p] of r.epochs) {
    // A finished order is not resubmitted, whatever a late response says.
    if (ended && e.kind === 'submitted') break;
    const next = nextParticipation(p, e, s, r.history);
    let q: Participation = next === null ? p : { ...p, state: next };
    if (
      e.kind === 'submitted' &&
      e.result !== 'refused' &&
      at === e.epoch &&
      (PENDING.has(q.state.kind) || q.state.kind === 'not_submitted')
    ) {
      if (s.promise !== undefined) q = { ...q, promise: s.promise };
      if (s.envelopeDigest !== undefined) q = { ...q, envelopeDigest: s.envelopeDigest };
    }
    if (next !== null && e.kind === 'fills' && next.kind === 'verified' && s.fills !== undefined) {
      fills = [...fills, ...s.fills];
    }
    if (
      next !== null &&
      (next.kind === 'voided' || next.kind === 'excluded') &&
      (p.state.kind === 'verified' || p.state.kind === 'settling')
    ) {
      fills = withoutEpochFills(fills, r.history, p.epoch);
    }
    if (q !== p) epochs.set(at, q);
  }

  let evidence = r.evidence;
  if (s.evidenceId !== undefined && s.evidenceId.length > 0 && !evidence.includes(s.evidenceId)) {
    evidence = [...evidence, s.evidenceId];
  }

  const order = placed(r);
  let state: OrderState = r.state;
  const k = state.kind;
  switch (e.kind) {
    case 'wallet_prompted':
      if (k === 'draft') state = { kind: 'awaiting_wallet' };
      break;
    case 'wallet_rejected':
      if (k === 'awaiting_wallet') state = { kind: 'wallet_rejected' };
      break;
    case 'wallet_unsupported':
      if (k === 'awaiting_wallet') state = { kind: 'unsupported_wallet' };
      break;
    case 'abandoned':
      if (k === 'draft' || k === 'awaiting_wallet') state = { kind: 'abandoned' };
      break;
    case 'signed':
      if (k === 'awaiting_wallet') {
        state = e.late ? { kind: 'signed_too_late' } : { kind: 'submitting' };
      }
      break;
    case 'submitted':
      if (e.result !== 'refused') {
        if (k === 'submitting' || k === 'submit_failed' || k === 'paused_needs_app') {
          state = { kind: 'working' };
        }
      } else if (k === 'submitting' || k === 'submit_failed') {
        const code = e.code ?? 'unknown';
        if (resendable(code)) state = { kind: 'submit_failed', code, retryable: true };
        else if (!live(epochs)) state = { kind: 'submit_failed', code, retryable: false };
      }
      break;
    case 'epoch_locked': {
      const last = lastCovered(epochs);
      if (
        k === 'working' &&
        order !== null &&
        last !== null &&
        e.epoch > last &&
        e.epoch >= order.validFrom &&
        e.epoch <= order.expiresAt
      ) {
        state = { kind: 'paused_needs_app' };
      }
      break;
    }
    case 'aborted':
      if (
        e.outcomeWasPublic &&
        order !== null &&
        (k === 'working' || k === 'paused_needs_app') &&
        r.epochs.has(e.epoch)
      ) {
        state = { kind: 'reseal_needs_consent', epoch: e.epoch };
      } else if (
        k === 'cancel_pending' &&
        state.kind === 'cancel_pending' &&
        state.epoch === e.epoch
      ) {
        // The cancel's own epoch was voided: the order rests again.
        state = { kind: 'working' };
      }
      break;
    case 'cancel_submitted':
      if (
        k === 'working' ||
        k === 'paused_needs_app' ||
        k === 'reseal_needs_consent' ||
        k === 'submit_failed' ||
        k === 'cancel_pending'
      ) {
        state = { kind: 'cancel_pending', epoch: e.epoch };
      }
      break;
    case 'verification_failed':
      if (k !== 'verification_failed') state = { kind: 'verification_failed', check: e.check };
      break;
    default:
      break;
  }

  // Ends that wait until no participation is in flight.
  const sk = state.kind;
  // A failed submission has nothing in flight. Only its window running out ends it.
  const ending =
    sk === 'submit_failed'
      ? e.kind === 'expired'
      : RESTING.includes(sk)
        ? ENDING.includes(e.kind)
        : sk === 'cancel_pending' && (ENDING.includes(e.kind) || e.kind === 'cancel_result');
  if (ending && !inFlight(epochs)) {
    let end: OrderState | null = null;
    if (sk === 'cancel_pending') {
      const outcome = cancelOutcome(history);
      if (outcome === 'cancelled') end = { kind: 'cancelled' };
      else if (outcome === 'too_late') end = { kind: 'cancel_too_late' };
    } else if (
      sk !== 'submit_failed' &&
      order !== null &&
      filledTotal(epochs, history) >= order.quantity
    ) {
      end = { kind: 'filled' };
    } else if (lastOf(history, 'expired') !== undefined) {
      end = { kind: 'expired' };
    }
    if (end !== null) {
      state = end;
      // Whatever still waits at the relay is spent: the executor will not trade it.
      for (const [at, p] of epochs) {
        if (PENDING.has(p.state.kind)) {
          epochs.set(at, { ...p, state: { kind: 'not_submitted', reason: 'invalidated' } });
        }
      }
    }
  }

  const filled = order === null ? 0n : filledTotal(epochs, history);
  return { ...r, state, epochs, filled, fills, history, evidence };
}

/** Pure reducer: transitions are driven only by verified objects. */
export function reduce(r: OrderRecord, e: OrderEvent): OrderRecord {
  return reduceWith(r, e);
}

const BADGE_ORDER: readonly ParticipationState['kind'][] = [
  'provisional',
  'clearing',
  'included',
  'locked',
  'settling',
  'verified',
  'sealed',
  'parked',
];

function earliest(r: OrderRecord, kind: ParticipationState['kind']): bigint | null {
  let at: bigint | null = null;
  for (const p of r.epochs.values()) {
    if (p.state.kind === kind && (at === null || p.epoch < at)) at = p.epoch;
  }
  return at;
}

/**
 * The badge an order shows (precedence): a failed verification, then
 * any exclusion, then the order-level state unless the order is simply
 * working, then the earliest participation in flight in the order
 * provisional, clearing, included, locked, settling, verified, sealed,
 * parked, and finally `working`.
 */
export function badge(r: OrderRecord): {
  state: OrderState['kind'] | ParticipationState['kind'];
  epoch?: bigint;
} {
  if (r.state.kind === 'verification_failed') return { state: 'verification_failed' };
  const excluded = earliest(r, 'excluded');
  if (excluded !== null) return { state: 'excluded', epoch: excluded };
  if (r.state.kind !== 'working') {
    const s = r.state;
    return s.kind === 'cancel_pending' || s.kind === 'reseal_needs_consent'
      ? { state: s.kind, epoch: s.epoch }
      : { state: s.kind };
  }
  for (const kind of BADGE_ORDER) {
    const at = earliest(r, kind);
    if (at !== null) return { state: kind, epoch: at };
  }
  return { state: 'working' };
}
