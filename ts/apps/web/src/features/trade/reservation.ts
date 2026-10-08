// Local estimate of the collateral working orders reserve,
// the same rule the SDK's prepare applies to the order being placed.
import type { MarketParams, PriceBand } from '@timescales/sdk/core';
import { effectiveLimit, feeCeilPerUnit, slot } from '@timescales/sdk/core';
import type { OrderRecord } from '@timescales/sdk/orders';

import { atomsToDecimal } from './units';

export interface Amounts {
  base: bigint;
  quote: bigint;
}

const RESERVING = new Set<OrderRecord['state']['kind']>(['working', 'submitting']);

/** What one order reserves for its remaining quantity in this band. */
export function reservationOf(
  order: { side: 0 | 1; role: 0 | 1; kind: 0 | 1; limit: bigint; quantity: bigint },
  params: MarketParams,
  band: PriceBand,
): Amounts {
  const s = slot(
    band,
    order.side,
    effectiveLimit({
      ...order,
      market: 0n,
      trader: new Uint8Array(32),
      nonce: 0n,
      validFrom: 0n,
      expiresAt: 0n,
    }),
  );
  if (s === null || order.quantity <= 0n) return { base: 0n, quote: 0n };
  if (order.side === 1) return { base: order.quantity * params.baseLotSize, quote: 0n };
  const price = (band.lo + BigInt(s)) * params.tickSize;
  const fee = order.role === 0 ? params.makerFeeBps : params.takerFeeBps;
  return { base: 0n, quote: order.quantity * (price + feeCeilPerUnit(fee, price)) };
}

/** Sum over the wallet's working orders in one market (the prefix rule: all of them must be covered). */
export function reservedByOrders(
  records: readonly OrderRecord[],
  market: string,
  params: MarketParams,
  band: PriceBand,
  except?: string,
): Amounts {
  let base = 0n;
  let quote = 0n;
  for (const r of records) {
    if (r.market !== market || r.id === except || r.body.kind !== 'place') continue;
    if (!RESERVING.has(r.state.kind)) continue;
    const o = r.body.order;
    const own = reservationOf({ ...o, quantity: o.quantity - r.filled }, params, band);
    base += own.base;
    quote += own.quote;
  }
  return { base, quote };
}

/**
 * Lots of an order the balance can still cover once the other working
 * orders are reserved ("Undercapitalized: only X can fill").
 */
export function coverableLots(
  ownPerLot: Amounts,
  available: Amounts,
  others: Amounts,
  quantity: bigint,
): bigint {
  const left = (a: bigint, b: bigint) => (a > b ? a - b : 0n);
  const byBase =
    ownPerLot.base > 0n ? left(available.base, others.base) / ownPerLot.base : quantity;
  const byQuote =
    ownPerLot.quote > 0n ? left(available.quote, others.quote) / ownPerLot.quote : quantity;
  const lots = byBase < byQuote ? byBase : byQuote;
  return lots < quantity ? lots : quantity;
}

export function formatAmounts(
  a: Amounts,
  u: { baseDecimals: number; quoteDecimals: number },
  symbols: { base: string; quote: string },
): string {
  const parts: string[] = [];
  if (a.base !== 0n) parts.push(`${atomsToDecimal(a.base, u.baseDecimals)} ${symbols.base}`);
  if (a.quote !== 0n || parts.length === 0) {
    parts.push(`${atomsToDecimal(a.quote, u.quoteDecimals)} ${symbols.quote}`);
  }
  return parts.join(' + ');
}
