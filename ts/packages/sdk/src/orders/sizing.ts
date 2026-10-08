import { feeCeilPerUnit, feeOn, slot, type PriceBand } from '../core/protocol/band.js';
import { effectiveLimit, type Order } from '../core/protocol/order.js';
import type { MarketParams } from '../core/protocol/params.js';

const U64_MAX = (1n << 64n) - 1n;

function roleFee(o: Pick<Order, 'role'>, params: MarketParams): number {
  return o.role === 0 ? params.makerFeeBps : params.takerFeeBps;
}

/** Quote atoms per lot at band slot `s`: `(lo + s) * tick_size`, saturating like the executor. */
function priceAt(band: PriceBand, s: number, params: MarketParams): bigint {
  const p = (band.lo + BigInt(s)) * params.tickSize;
  return p > U64_MAX ? U64_MAX : p;
}

/**
 * Collateral an order reserves in a band (`timescales_auction::collateral::requirement`):
 * a buy locks `q * (price(slot) + ceil(price(slot) * fee / 10000))` quote at
 * its role's fee, a sell `q * base_lot_size` base. `o.quantity` is the
 * remaining quantity. An order with no slot in the band reserves nothing.
 */
export function collateralFor(
  o: Omit<Order, 'nonce'>,
  params: MarketParams,
  band: PriceBand,
): { base: bigint; quote: bigint } {
  const s = slot(band, o.side, effectiveLimit({ ...o, nonce: 0n }));
  if (s === null) return { base: 0n, quote: 0n };
  if (o.side === 1) return { base: o.quantity * params.baseLotSize, quote: 0n };
  const price = priceAt(band, s, params);
  return { base: 0n, quote: o.quantity * (price + feeCeilPerUnit(roleFee(o, params), price)) };
}

/**
 * The most quote an order can move in this band, before fees: a buy pays at
 * most its slot's price, a sell receives at least its limit (or the band's
 * low end). Zero when it cannot trade in the band.
 */
export function worstNotional(
  o: Omit<Order, 'nonce'>,
  params: MarketParams,
  band: PriceBand,
): bigint {
  const s = slot(band, o.side, effectiveLimit({ ...o, nonce: 0n }));
  if (s === null) return 0n;
  return o.quantity * priceAt(band, s, params);
}

/**
 * The fee the order pays at most if fully filled in this band: the buy-side
 * reservation's fee part, or the sell fee on the worst notional.
 */
export function feeEstimate(
  o: Omit<Order, 'nonce'>,
  params: MarketParams,
  band: PriceBand,
): bigint {
  const s = slot(band, o.side, effectiveLimit({ ...o, nonce: 0n }));
  if (s === null) return 0n;
  const price = priceAt(band, s, params);
  if (o.side === 0) return o.quantity * feeCeilPerUnit(roleFee(o, params), price);
  return feeOn(roleFee(o, params), o.quantity * price);
}
