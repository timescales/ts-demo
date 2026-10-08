import type { Reader } from '../encoding/codec.js';
import { DecodeError, Writer } from '../encoding/codec.js';
import { maxOrderLots, type MarketParams, type OrderKind, type Role, type Side } from './params.js';

/** `Order` (83 B). `trader` is the wallet's Ed25519 key. `expiresAt` is inclusive. */
export interface Order {
  market: bigint;
  trader: Uint8Array;
  nonce: bigint;
  side: Side;
  role: Role;
  kind: OrderKind;
  limit: bigint;
  quantity: bigint;
  validFrom: bigint;
  expiresAt: bigint;
}

/** `Cancel` (88 B): applies to `target` placed in the same batch (`epoch`). */
export interface Cancel {
  market: bigint;
  trader: Uint8Array;
  nonce: bigint;
  target: Uint8Array;
  epoch: bigint;
}

export const ORDER_LEN = 83;
export const CANCEL_LEN = 88;
const U64_MAX = (1n << 64n) - 1n;

function tag01(r: Reader): 0 | 1 {
  const v = r.u8();
  if (v > 1) throw new DecodeError('tag', `enum tag ${v}`);
  return v as 0 | 1;
}

export function readOrder(r: Reader): Order {
  const o: Order = {
    market: r.u64(),
    trader: r.fixed(32),
    nonce: r.u64(),
    side: tag01(r),
    role: tag01(r),
    kind: tag01(r),
    limit: r.u64(),
    quantity: r.u64(),
    validFrom: r.u64(),
    expiresAt: r.u64(),
  };
  if (o.kind === 1 && o.limit !== 0n) throw new DecodeError('value', 'market order with a limit');
  return o;
}

/** Encodes after the decode-side canonicality check (a market order must carry limit 0), which Rust's encoder does not make. */
export function writeOrder(w: Writer, o: Order): void {
  if (o.kind === 1 && o.limit !== 0n) throw new RangeError('market order must have limit 0');
  for (const v of [o.side, o.role, o.kind])
    if (v !== 0 && v !== 1) throw new RangeError('enum tag');
  w.u64(o.market)
    .fixed(o.trader, 32)
    .u64(o.nonce)
    .u8(o.side)
    .u8(o.role)
    .u8(o.kind)
    .u64(o.limit)
    .u64(o.quantity)
    .u64(o.validFrom)
    .u64(o.expiresAt);
}

export function readCancel(r: Reader): Cancel {
  return {
    market: r.u64(),
    trader: r.fixed(32),
    nonce: r.u64(),
    target: r.fixed(32),
    epoch: r.u64(),
  };
}

export function writeCancel(w: Writer, c: Cancel): void {
  w.u64(c.market).fixed(c.trader, 32).u64(c.nonce).fixed(c.target, 32).u64(c.epoch);
}

export function encodeOrder(o: Order): Uint8Array {
  const w = new Writer();
  writeOrder(w, o);
  return w.finish();
}

export function encodeCancel(c: Cancel): Uint8Array {
  const w = new Writer();
  writeCancel(w, c);
  return w.finish();
}

/** Limit used for matching: the limit, or `u64::MAX` / 0 for market buys / sells (`order.rs:90-96`). */
export function effectiveLimit(o: Order): bigint {
  if (o.kind === 0) return o.limit;
  return o.side === 0 ? U64_MAX : 0n;
}

export type OrderErrorReason =
  'market' | 'market_limit' | 'quantity' | 'lifetime' | 'window' | 'trader';

export class OrderError extends Error {
  readonly reason: OrderErrorReason;

  constructor(reason: OrderErrorReason, message: string) {
    super(message);
    this.name = 'OrderError';
    this.reason = reason;
  }
}

/** The market uses a commitment scheme the SDK does not produce (Poseidon). */
export class UnsupportedScheme extends Error {
  constructor(scheme: number) {
    super(
      `commitment scheme ${scheme} is not supported: the SDK produces SHA-256 commitments only`,
    );
    this.name = 'UnsupportedScheme';
  }
}

/**
 * The executor's order checks (the auction crate's `risk` and `orderbook` modules)
 * that a client can make before signing: market, market => limit 0,
 * `quantity < 2^b`, `expiresAt - validFrom <= maxOrderLifetime`, and
 * `validFrom <= epoch <= expiresAt`.
 */
export function validateOrder(o: Order, p: MarketParams, epoch: bigint): void {
  if (p.commitmentScheme !== 0) throw new UnsupportedScheme(p.commitmentScheme);
  if (o.trader.length !== 32) throw new OrderError('trader', 'trader must be a 32-byte key');
  if (o.market !== p.market) throw new OrderError('market', 'order is for another market');
  if (o.kind === 1 && o.limit !== 0n)
    throw new OrderError('market_limit', 'market order must have limit 0');
  if (o.quantity > maxOrderLots(p))
    throw new OrderError('quantity', 'quantity exceeds 2^b - 1 lots');
  if (o.expiresAt < o.validFrom || o.expiresAt - o.validFrom > BigInt(p.maxOrderLifetime)) {
    throw new OrderError('lifetime', 'validity window exceeds max_order_lifetime');
  }
  if (epoch < o.validFrom || epoch > o.expiresAt) {
    throw new OrderError('window', 'epoch outside the validity window');
  }
}
