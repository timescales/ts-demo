import type { Reader } from '../encoding/codec.js';
import { DecodeError, Writer } from '../encoding/codec.js';
import { MAX_BAND_TICKS, maxOrderLots, type MarketParams, type Side } from './params.js';

export interface PriceBand {
  lo: bigint;
  hi: bigint;
  reference: bigint;
}

export type BandErrorReason = 'underflow' | 'overflow' | 'notional';

export class BandError extends Error {
  readonly reason: BandErrorReason;

  constructor(reason: BandErrorReason, message: string) {
    super(message);
    this.name = 'BandError';
    this.reason = reason;
  }
}

const U64_MAX = (1n << 64n) - 1n;
const I64_MAX = (1n << 63n) - 1n;

/** `ceil(price * bps / 10000)`, saturating at `u64::MAX` like `FeeBps::fee_ceil_per_unit`. */
export function feeCeilPerUnit(bps: number, price: bigint): bigint {
  const f = (price * BigInt(bps) + 9_999n) / 10_000n;
  return f > U64_MAX ? U64_MAX : f;
}

/** `floor(notional * bps / 10000)`, like `FeeBps::fee_on`. */
export function feeOn(bps: number, notional: bigint): bigint {
  const f = (notional * BigInt(bps)) / 10_000n;
  return f > U64_MAX ? U64_MAX : f;
}

/**
 * Exact port of `MarketParams::band`. The bound on a trader's
 * aggregate notional is computed in exact bigint arithmetic.
 */
export function band(p: MarketParams, reference: bigint): PriceBand {
  const w = BigInt(p.bandHalfWidth);
  if (reference <= w) {
    throw new BandError(
      'underflow',
      `reference tick ${reference} too close to zero for half width ${w}`,
    );
  }
  const lo = reference - w;
  const hi = reference + w;
  if (hi > U64_MAX) throw new BandError('overflow', 'band upper tick overflows');
  const price = hi * p.tickSize;
  if (price > U64_MAX)
    throw new BandError('notional', `worst-case notional at tick ${hi} overflows`);
  const perLot = price + feeCeilPerUnit(Math.max(p.makerFeeBps, p.takerFeeBps), price);
  const perTrader = maxOrderLots(p) * BigInt(p.maxOrdersPerTrader);
  if (perTrader * perLot > I64_MAX) {
    throw new BandError(
      'notional',
      `worst-case notional at tick ${hi} does not fit settlement range`,
    );
  }
  return { lo, hi, reference };
}

export function bandTicks(b: PriceBand): number {
  return Number(b.hi - b.lo + 1n);
}

/** Band slot of an effective limit (`PriceBand::slot`). Null when the order cannot trade in the band. */
export function slot(b: PriceBand, side: Side, effectiveLimit: bigint): number | null {
  const k = bandTicks(b);
  if (side === 0) {
    if (effectiveLimit < b.lo) return null;
    if (effectiveLimit >= b.hi) return k - 1;
  } else {
    if (effectiveLimit > b.hi) return null;
    if (effectiveLimit <= b.lo) return 0;
  }
  return Number(effectiveLimit - b.lo);
}

export function readBand(r: Reader): PriceBand {
  const b = { lo: r.u64(), hi: r.u64(), reference: r.u64() };
  if (
    b.lo > b.hi ||
    b.hi - b.lo >= BigInt(MAX_BAND_TICKS) ||
    b.reference < b.lo ||
    b.reference > b.hi
  ) {
    throw new DecodeError('value', 'PriceBand');
  }
  return b;
}

export function writeBand(w: Writer, b: PriceBand): void {
  w.u64(b.lo).u64(b.hi).u64(b.reference);
}

export function encodeBand(b: PriceBand): Uint8Array {
  const w = new Writer();
  writeBand(w, b);
  return w.finish();
}
