import type { Address } from '@solana/kit';
import { bookFor, type BookId, type Side } from '../core/protocol/params.js';
import type { OrderRecord, OrderState } from './model.js';

/** Order states in which an order may still trade, or is about to be submitted. */
const MAY_TRADE: ReadonlySet<OrderState['kind']> = new Set<OrderState['kind']>([
  'awaiting_wallet',
  'submitting',
  'submit_failed',
  'working',
  'paused_needs_app',
  'reseal_needs_consent',
  'cancel_pending',
]);

/**
 * True when the wallet has working quantity on the opposite side of the
 * same derived book: the executor then rejects all of the wallet's orders
 * in that book (`crates/timescales-auction/src/orderbook`).
 */
export function wouldSelfTrade(
  records: readonly OrderRecord[],
  a: { market: Address; flow: 0 | 1; book: BookId; side: Side },
): boolean {
  return records.some((r) => {
    if (r.market !== a.market || r.body.kind !== 'place' || !MAY_TRADE.has(r.state.kind)) {
      return false;
    }
    if (r.state.kind === 'submit_failed' && !r.state.retryable) return false;
    const o = r.body.order;
    return o.side !== a.side && bookFor(a.flow, o.side, o.role) === a.book && o.quantity > r.filled;
  });
}
