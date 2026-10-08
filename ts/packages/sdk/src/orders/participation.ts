import { equal } from '../core/encoding/bytes.js';
import type { OrderEvent, Participation, ParticipationState } from './model.js';

type Kind = ParticipationState['kind'];
type NotSubmittedReason = Extract<ParticipationState, { kind: 'not_submitted' }>['reason'];

/** Participations whose epoch is being decided: an order cannot end while one exists. */
export const IN_FLIGHT: ReadonlySet<Kind> = new Set<Kind>([
  'locked',
  'included',
  'clearing',
  'provisional',
  'verified',
  'settling',
]);

/** Accepted by the relay (or waiting in the outbox) and not yet locked into a batch. */
export const PENDING: ReadonlySet<Kind> = new Set<Kind>(['sealed', 'parked']);

/** States an epoch's abort voids: everything at the relay that has not settled. */
const VOIDABLE: readonly Kind[] = [
  'sealed',
  'parked',
  'locked',
  'included',
  'clearing',
  'provisional',
  'verified',
  'settling',
];

const UNTIL_RECEIPT: readonly Kind[] = ['locked', 'included', 'clearing', 'provisional'];

/**
 * States a V-6 exclusion reaches: anything at the relay short of settled.
 * The tracker keeps a participation at `locked` until V-6 passes. The
 * reducer still takes a late exclusion whatever was applied before it.
 */
const EXCLUDABLE: readonly Kind[] = [
  'sealed',
  'parked',
  'locked',
  'clearing',
  'provisional',
  'verified',
  'settling',
];

/**
 * Per-epoch participation transitions. Every row is a UI test. Each
 * event names its epoch (`parked_invalidated` names several). Rows with the
 * same `from` and `on` are alternatives chosen by the event's payload or by
 * the verified data behind it: `submitted.result`, `inclusion.inclusion`,
 * `receipt.quorumMet`. Pairs not listed leave the participation unchanged.
 *
 * `not_submitted{invalidated}` covers every participation that will not be
 * submitted as it is: its epoch closed before the relay received it, its
 * parked envelope was invalidated by an emergency committee rotation, it was
 * retracted, or its order ended while it was still waiting.
 */
export const PARTICIPATION_LIFECYCLE: ReadonlyArray<{
  from: ParticipationState['kind'];
  on: OrderEvent['kind'];
  to: ParticipationState['kind'];
}> = Object.freeze([
  // 202 accepted or parked with a verified promise (V-5), or a refusal.
  { from: 'sealed', on: 'submitted', to: 'parked' },
  { from: 'sealed', on: 'submitted', to: 'not_submitted' },
  { from: 'parked', on: 'submitted', to: 'sealed' },
  { from: 'parked', on: 'submitted', to: 'not_submitted' },
  { from: 'not_submitted', on: 'submitted', to: 'sealed' },
  { from: 'not_submitted', on: 'submitted', to: 'parked' },
  // epoch.closed / epoch.committed
  { from: 'sealed', on: 'epoch_locked', to: 'locked' },
  { from: 'parked', on: 'epoch_locked', to: 'locked' },
  // V-6
  { from: 'sealed', on: 'inclusion', to: 'included' },
  { from: 'parked', on: 'inclusion', to: 'included' },
  { from: 'locked', on: 'inclusion', to: 'included' },
  ...EXCLUDABLE.map((from) => ({ from, on: 'inclusion' as const, to: 'excluded' as const })),
  // epoch.revealed
  { from: 'locked', on: 'revealed', to: 'clearing' },
  { from: 'included', on: 'revealed', to: 'clearing' },
  // V-7 below the quorum: "Result posted, awaiting co-signature".
  ...UNTIL_RECEIPT.filter((k) => k !== 'provisional').map((from) => ({
    from,
    on: 'receipt' as const,
    to: 'provisional' as const,
  })),
  // V-7 with the quorum met, V-8 and V-9.
  ...UNTIL_RECEIPT.map((from) => ({ from, on: 'fills' as const, to: 'verified' as const })),
  // epoch.settlement
  { from: 'verified', on: 'settlement', to: 'settling' },
  // V-10
  { from: 'verified', on: 'settled', to: 'settled' },
  { from: 'settling', on: 'settled', to: 'settled' },
  // epoch.aborted voids everything that has not settled.
  ...VOIDABLE.map((from) => ({ from, on: 'aborted' as const, to: 'voided' as const })),
  // An emergency committee rotation invalidates parked envelopes.
  { from: 'parked', on: 'parked_invalidated', to: 'not_submitted' },
  // The order ended (filled, expired or cancelled) with envelopes still
  // waiting: the executor treats them as spent, so they are not followed.
  ...(['sealed', 'parked'] as const).flatMap((from) =>
    (['settled', 'aborted', 'inclusion', 'expired', 'cancel_result'] as const).map((on) => ({
      from,
      on,
      to: 'not_submitted' as const,
    })),
  ),
]);

/** Refusal codes of a submission and the participation reason they mean. */
export function refusalReason(code: string | undefined): NotSubmittedReason {
  switch (code) {
    case 'QUOTA_EXCEEDED':
      return 'quota';
    case 'BATCH_FULL':
      return 'batch_full';
    case 'EPOCH_KEY_UNAVAILABLE':
    case 'EPOCH_TOO_FAR':
      return 'key_unavailable';
    default:
      return 'invalidated';
  }
}

/**
 * Failures after which the same bytes may still be accepted: the relay did
 * not decide about the envelope (transport, overload, a paused intake, a
 * session the node no longer honours). The participation stays in the
 * outbox and is re-sent unchanged. After a session error, once a new
 * session exists, wrapped for it.
 */
export function resendable(code: string | undefined): boolean {
  switch (code) {
    case 'network':
    case 'timeout':
    case 'unknown':
    case 'RATE_LIMITED':
    case 'OVERLOADED':
    case 'DRAINING':
    case 'INTERNAL':
    case 'MARKET_UNAVAILABLE':
    case 'INTAKE_PAUSED':
    case 'SKEW':
    case 'SESSION_UNKNOWN':
    case 'SESSION_EXPIRED':
    case 'SESSION_REVOKED':
      return true;
    default:
      return false;
  }
}

/**
 * A participation as the journal keeps it. `sealedBefore` holds the digests
 * of envelopes sealed earlier for the same epoch and replaced by a later
 * seal (a re-seal, or another tab's): the relay may still hold one of them
 * and answer the later one with `DUPLICATE_COMMITMENT` and its promise.
 */
export interface StoredParticipation extends Participation {
  sealedBefore?: Uint8Array[];
}

/** The digests of every envelope this journal sealed for the participation's epoch. */
export function sealedDigests(p: Participation): Uint8Array[] {
  return [p.envelopeDigest, ...((p as StoredParticipation).sealedBefore ?? [])];
}

/** `next`, a new seal for the epoch of `before`, remembering the digests sealed until now. */
export function resealed(next: Participation, before: Participation | undefined): Participation {
  if (before === undefined) return next;
  const earlier: Uint8Array[] = [];
  for (const d of sealedDigests(before)) {
    if (!equal(d, next.envelopeDigest) && !earlier.some((x) => equal(x, d))) earlier.push(d);
  }
  if (earlier.length === 0) return next;
  const stored: StoredParticipation = { ...next, sealedBefore: earlier };
  return stored;
}

/** Data an event does not carry, supplied by the order service when it reduces. */
export interface Supplement {
  /** Live co-signatures and the quorum, for `receipt` (V-7). */
  quorum?: { have: number; need: number };
  /** The evidence record saved for this event (exclusion, refusal, failed check). */
  evidenceId?: string;
  /** The verified promise, for `submitted` with `accepted` or `parked`. */
  promise?: Uint8Array;
  /** The envelope digest the promise names, when it differs from ours (`DUPLICATE_COMMITMENT`). */
  envelopeDigest?: Uint8Array;
}

/** The epoch an event is about, or null for order-level events. */
export function eventEpoch(e: OrderEvent): bigint | null {
  return 'epoch' in e && typeof e.epoch === 'bigint' ? e.epoch : null;
}

/** The quantity the last `fills` event for `epoch` verified, which `settled` keeps. */
export function filledIn(history: readonly OrderEvent[], epoch: bigint): bigint {
  for (let i = history.length - 1; i >= 0; i--) {
    const h = history[i]!;
    if (h.kind === 'fills' && h.epoch === epoch) return h.filled;
  }
  return 0n;
}

/** The next state of one participation, or null when the event leaves it unchanged. */
export function nextParticipation(
  p: Participation,
  e: OrderEvent,
  s: Supplement,
  history: readonly OrderEvent[],
): ParticipationState | null {
  const from = p.state.kind;
  if (e.kind === 'parked_invalidated') {
    return from === 'parked' && e.epochs.includes(p.epoch)
      ? { kind: 'not_submitted', reason: 'invalidated' }
      : null;
  }
  if (eventEpoch(e) !== p.epoch) return null;
  switch (e.kind) {
    case 'submitted': {
      if (!PENDING.has(from) && from !== 'not_submitted') return null;
      if (e.result === 'accepted') return from === 'sealed' ? null : { kind: 'sealed' };
      if (e.result === 'parked') return from === 'parked' ? null : { kind: 'parked' };
      if (from === 'not_submitted' || resendable(e.code)) return null;
      return { kind: 'not_submitted', reason: refusalReason(e.code) };
    }
    case 'epoch_locked':
      return PENDING.has(from) ? { kind: 'locked' } : null;
    case 'inclusion':
      if (e.inclusion === 'included') {
        return PENDING.has(from) || from === 'locked' ? { kind: 'included' } : null;
      }
      return EXCLUDABLE.includes(from)
        ? { kind: 'excluded', evidenceId: s.evidenceId ?? '' }
        : null;
    case 'revealed':
      return from === 'locked' || from === 'included' ? { kind: 'clearing', delayed: false } : null;
    case 'receipt': {
      if (e.quorumMet || !UNTIL_RECEIPT.includes(from)) return null;
      const q = s.quorum ?? (p.state.kind === 'provisional' ? p.state : { have: 0, need: 0 });
      if (p.state.kind === 'provisional' && p.state.have === q.have && p.state.need === q.need) {
        return null;
      }
      return { kind: 'provisional', have: q.have, need: q.need };
    }
    case 'fills':
      return UNTIL_RECEIPT.includes(from) ? { kind: 'verified', filled: e.filled } : null;
    case 'settlement':
      return from === 'verified' || from === 'settling'
        ? { kind: 'settling', done: e.done, total: e.total }
        : null;
    case 'settled':
      if (p.state.kind === 'verified') return { kind: 'settled', filled: p.state.filled };
      return from === 'settling' ? { kind: 'settled', filled: filledIn(history, p.epoch) } : null;
    case 'aborted':
      return VOIDABLE.includes(from)
        ? { kind: 'voided', outcomeWasPublic: e.outcomeWasPublic }
        : null;
    default:
      return null;
  }
}
