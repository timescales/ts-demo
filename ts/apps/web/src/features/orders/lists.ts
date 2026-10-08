// Which records appear on which Orders tab.
import type { OrderRecord, OrderState, ParticipationState } from '@timescales/sdk/orders';

/** Order states only a verification failure can leave. */
const ENDED = new Set<OrderState['kind']>([
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

/** Participations whose epoch is still being decided. */
const IN_FLIGHT = new Set<ParticipationState['kind']>([
  'locked',
  'included',
  'clearing',
  'provisional',
  'verified',
  'settling',
]);

export function inFlight(r: OrderRecord): boolean {
  for (const p of r.epochs.values()) if (IN_FLIGHT.has(p.state.kind)) return true;
  return false;
}

/** Working tab: anything not ended, or with a participation still in flight. */
export function isOpenRecord(r: OrderRecord): boolean {
  if (r.body.kind !== 'place' || r.state.kind === 'draft') return false;
  return !ENDED.has(r.state.kind) || inFlight(r);
}

/** History tab: placements that ended, including those that ended after voided epochs. */
export function isHistoryRecord(r: OrderRecord): boolean {
  return r.body.kind === 'place' && ENDED.has(r.state.kind) && !inFlight(r);
}

/** When the record last changed: its newest event. */
export function updatedAt(r: OrderRecord): number {
  return r.history[r.history.length - 1]?.atMs ?? 0;
}

export function newestFirst(a: OrderRecord, b: OrderRecord): number {
  return updatedAt(b) - updatedAt(a);
}

/** First and last epoch of the order's window. */
export function epochWindow(r: OrderRecord): { from: bigint; to: bigint } | null {
  if (r.body.kind !== 'place') return null;
  return { from: r.body.order.validFrom, to: r.body.order.expiresAt };
}
