import type { Reader } from '../encoding/codec.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';

export type Side = 0 | 1;
export type Role = 0 | 1;
export type OrderKind = 0 | 1;
export type BookId = 0 | 1 | 2;

export const SIDE = { buy: 0, sell: 1 } as const;
export const ROLE = { maker: 0, taker: 1 } as const;
export const ORDER_KIND = { limit: 0, market: 1 } as const;
export const BOOK = { single: 0, makerAskTakerBid: 1, makerBidTakerAsk: 2 } as const;

/** `MarketParams` (46 B). `flow`: 0 SingleBook, 1 DualFlow. `rationing`: 0 Lottery, 1 ProRata. `commitmentScheme`: 0 SHA-256, 1 Poseidon. */
export interface MarketParams {
  market: bigint;
  baseLotSize: bigint;
  tickSize: bigint;
  bandHalfWidth: number;
  maxOrderLotsLog2: number;
  maxOrdersPerTrader: number;
  maxBatchEnvelopes: number;
  maxOrderLifetime: number;
  makerFeeBps: number;
  takerFeeBps: number;
  flow: 0 | 1;
  rationing: 0 | 1;
  commitmentScheme: 0 | 1;
}

export const MARKET_PARAMS_LEN = 46;
export const MAX_BAND_TICKS = 1025;
export const MAX_BATCH_ENVELOPES = 1 << 21;
/** = the program's `MAX_DELTAS`. */
export const MAX_SETTLEMENT_DELTAS = 1024;
const I64_MAX = (1n << 63n) - 1n;

export type ParamsErrorReason = 'invalid_param' | 'base_overflow' | 'onchain';

export class ParamsError extends Error {
  readonly reason: ParamsErrorReason;

  constructor(reason: ParamsErrorReason, message: string) {
    super(message);
    this.name = 'ParamsError';
    this.reason = reason;
  }
}

function flag(r: Reader): 0 | 1 {
  const v = r.u8();
  if (v > 1) throw new DecodeError('tag', `enum tag ${v}`);
  return v as 0 | 1;
}

export function readMarketParams(r: Reader): MarketParams {
  return {
    market: r.u64(),
    baseLotSize: r.u64(),
    tickSize: r.u64(),
    bandHalfWidth: r.u32(),
    maxOrderLotsLog2: r.u8(),
    maxOrdersPerTrader: r.u16(),
    maxBatchEnvelopes: r.u32(),
    maxOrderLifetime: r.u32(),
    makerFeeBps: r.u16(),
    takerFeeBps: r.u16(),
    flow: flag(r),
    rationing: flag(r),
    commitmentScheme: flag(r),
  };
}

export function writeMarketParams(w: Writer, p: MarketParams): void {
  for (const v of [p.flow, p.rationing, p.commitmentScheme]) {
    if (v !== 0 && v !== 1) throw new RangeError(`enum tag ${String(v)}`);
  }
  w.u64(p.market)
    .u64(p.baseLotSize)
    .u64(p.tickSize)
    .u32(p.bandHalfWidth)
    .u8(p.maxOrderLotsLog2)
    .u16(p.maxOrdersPerTrader)
    .u32(p.maxBatchEnvelopes)
    .u32(p.maxOrderLifetime)
    .u16(p.makerFeeBps)
    .u16(p.takerFeeBps)
    .u8(p.flow)
    .u8(p.rationing)
    .u8(p.commitmentScheme);
}

/** Decodes exactly 46 bytes. Like Rust's `Decode`, this does not validate. Call {@link validateMarketParams}. */
export function decodeMarketParams(b: Uint8Array): MarketParams {
  return decodeExact(b, readMarketParams);
}

export function encodeMarketParams(p: MarketParams): Uint8Array {
  const w = new Writer();
  writeMarketParams(w, p);
  return w.finish();
}

/** `2^b - 1`, the largest order quantity in lots. */
export function maxOrderLots(p: MarketParams): bigint {
  return (1n << BigInt(p.maxOrderLotsLog2)) - 1n;
}

/**
 * Port of `MarketParams::validate` (`crates/timescales-core/src/market.rs`)
 * with the production additions: the per-trader base exposure must fit
 * `i64` (`base_overflow`), and with `onchain` the program's `validate_onchain`
 * rules (`max_batch_envelopes <= 1024`, SHA-256 commitments).
 */
export function validateMarketParams(p: MarketParams, o?: { onchain?: boolean }): void {
  const bad = (m: string): never => {
    throw new ParamsError('invalid_param', m);
  };
  if (p.baseLotSize === 0n) bad('base_lot_size must be positive');
  if (p.tickSize === 0n) bad('tick_size must be positive');
  if (p.bandHalfWidth === 0 || 2 * p.bandHalfWidth + 1 > MAX_BAND_TICKS)
    bad('band_half_width out of range');
  if (p.maxOrderLotsLog2 < 1 || p.maxOrderLotsLog2 > 48)
    bad('max_order_lots_log2 must be in 1..=48');
  if (p.maxOrdersPerTrader === 0) bad('max_orders_per_trader must be positive');
  if (p.maxBatchEnvelopes === 0 || p.maxBatchEnvelopes > MAX_BATCH_ENVELOPES) {
    bad('max_batch_envelopes out of range');
  }
  const envBits = 32 - Math.clz32(p.maxBatchEnvelopes - 1);
  if (p.maxOrderLotsLog2 + envBits > 63) {
    bad('max_order_lots_log2 + log2(max_batch_envelopes) exceeds 63');
  }
  if (p.makerFeeBps > 10_000 || p.takerFeeBps > 10_000) bad('fee above 100%');
  if (p.baseLotSize * maxOrderLots(p) * BigInt(p.maxOrdersPerTrader) > I64_MAX) {
    throw new ParamsError(
      'base_overflow',
      'worst-case base exposure per trader does not fit settlement range',
    );
  }
  if (o?.onchain === true) {
    if (p.maxBatchEnvelopes > MAX_SETTLEMENT_DELTAS) {
      throw new ParamsError('onchain', 'max_batch_envelopes exceeds the on-chain settlement limit');
    }
    if (p.commitmentScheme !== 0) {
      throw new ParamsError('onchain', 'on-chain markets use SHA-256 commitments');
    }
  }
}

/** `H(MARKET_PARAMS, params46)`, compared with `Market.params_digest` (V-1). */
export function paramsDigest(p: MarketParams): Uint8Array {
  return H('MARKET_PARAMS', encodeMarketParams(p));
}

/** Book an order is routed to (`order.rs:50-58`). Derived, never chosen. */
export function bookFor(flow: 0 | 1, side: Side, role: Role): BookId {
  if (flow === 0) return 0;
  // DualFlow: (Maker, Sell) and (Taker, Buy) meet in MakerAskTakerBid.
  return (role === 0) === (side === 1) ? 1 : 2;
}
