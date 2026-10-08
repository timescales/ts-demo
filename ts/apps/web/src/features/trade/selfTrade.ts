// The self-trade guard, evaluated as soon as side and role are chosen
// so the ticket can block before the order is complete. prepare applies
// the same rule to the finished order.
import type { BookId, Side } from '@timescales/sdk/core';
import { bookFor } from '@timescales/sdk/core';
import type { OrderRecord } from '@timescales/sdk/orders';

const MAY_TRADE = new Set<OrderRecord['state']['kind']>([
  'awaiting_wallet',
  'submitting',
  'submit_failed',
  'working',
  'paused_needs_app',
  'reseal_needs_consent',
  'cancel_pending',
]);

/** Working orders on the other side of the same derived book. */
export function selfTradeConflicts(
  records: readonly OrderRecord[],
  a: { market: string; flow: 0 | 1; book: BookId; side: Side },
): OrderRecord[] {
  return records.filter((r) => {
    if (r.market !== a.market || r.body.kind !== 'place' || !MAY_TRADE.has(r.state.kind)) {
      return false;
    }
    if (r.state.kind === 'submit_failed' && !r.state.retryable) return false;
    const o = r.body.order;
    return o.side !== a.side && bookFor(a.flow, o.side, o.role) === a.book && o.quantity > r.filled;
  });
}
