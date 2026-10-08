import { compare } from '../encoding/bytes.js';
import type { Reader } from '../encoding/codec.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { feeOn } from './band.js';
import { MAX_BATCH_ENVELOPES, type MarketParams } from './params.js';
import type { Fill } from './artifacts.js';
import { merkleRoot } from './merkle.js';

/** Settlement leaf (48 B): `trader32 || base i64 || quote i64`. */
export interface AccountDelta {
  trader: Uint8Array;
  base: bigint;
  quote: bigint;
}

export interface SettlementBatch {
  market: bigint;
  epoch: bigint;
  deltas: AccountDelta[];
  fees: bigint;
}

export const ACCOUNT_DELTA_LEN = 48;
const U64_MAX = (1n << 64n) - 1n;
const I64_MAX = (1n << 63n) - 1n;
const I64_MIN = -(1n << 63n);

export type SettlementErrorReason = 'overflow' | 'conservation';

export class SettlementError extends Error {
  readonly reason: SettlementErrorReason;

  constructor(reason: SettlementErrorReason, message: string) {
    super(message);
    this.name = 'SettlementError';
    this.reason = reason;
  }
}

export function encodeAccountDelta(d: AccountDelta): Uint8Array {
  return new Writer().fixed(d.trader, 32).i64(d.base).i64(d.quote).finish();
}

function readDelta(r: Reader): AccountDelta {
  return { trader: r.fixed(32), base: r.i64(), quote: r.i64() };
}

/**
 * Hardened decoder: traders strictly increasing and every delta
 * non-zero in base or quote, so the encoding of a settlement is canonical.
 */
export function readSettlementBatch(r: Reader): SettlementBatch {
  const market = r.u64();
  const epoch = r.u64();
  const deltas = r.seq(MAX_BATCH_ENVELOPES, readDelta, ACCOUNT_DELTA_LEN);
  for (let i = 0; i < deltas.length; i++) {
    const d = deltas[i]!;
    if (d.base === 0n && d.quote === 0n) throw new DecodeError('value', 'zero settlement delta');
    if (i > 0 && compare(deltas[i - 1]!.trader, d.trader) >= 0) {
      throw new DecodeError('value', 'settlement traders not strictly increasing');
    }
  }
  return { market, epoch, deltas, fees: r.u64() };
}

export function writeSettlementBatch(w: Writer, s: SettlementBatch): void {
  w.u64(s.market)
    .u64(s.epoch)
    .seq(s.deltas, MAX_BATCH_ENVELOPES, (x, d) => x.fixed(d.trader, 32).i64(d.base).i64(d.quote))
    .u64(s.fees);
}

export function decodeSettlementBatch(b: Uint8Array): SettlementBatch {
  return decodeExact(b, readSettlementBatch);
}

export function encodeSettlementBatch(s: SettlementBatch): Uint8Array {
  const w = new Writer();
  writeSettlementBatch(w, s);
  return w.finish();
}

export function settlementRoot(deltas: AccountDelta[]): Uint8Array {
  return merkleRoot(deltas.map(encodeAccountDelta));
}

/** `sumbase = 0` and `sumquote + fees = 0`. */
export function checkConservation(s: SettlementBatch): void {
  let base = 0n;
  let quote = 0n;
  for (const d of s.deltas) {
    base += d.base;
    quote += d.quote;
  }
  if (base !== 0n || quote + s.fees !== 0n) {
    throw new SettlementError('conservation', 'settlement does not conserve base and quote');
  }
}

/**
 * Port of `timescales_auction::settlement::settle`: per fill `notional = q * tick *
 * tickSize` (must fit u64), fee `floor(notional * role fee / 10000)`. Buyers
 * receive base and pay `notional + fee`, sellers the reverse with
 * `notional - fee`. Deltas are netted per trader, sorted by trader, and a
 * trader whose net base and quote are both zero is omitted.
 */
export function settle(p: MarketParams, epoch: bigint, fills: Fill[]): SettlementBatch {
  const net = new Map<string, { trader: Uint8Array; base: bigint; quote: bigint }>();
  let fees = 0n;
  for (const f of fills) {
    const notional = f.quantity * f.tick * p.tickSize;
    if (notional > U64_MAX) throw new SettlementError('overflow', 'fill notional overflows u64');
    const fee = feeOn(f.role === 0 ? p.makerFeeBps : p.takerFeeBps, notional);
    const base = f.quantity * p.baseLotSize;
    const key = Array.from(f.trader, (x) => x.toString(16).padStart(2, '0')).join('');
    let e = net.get(key);
    if (e === undefined) {
      e = { trader: f.trader, base: 0n, quote: 0n };
      net.set(key, e);
    }
    if (f.side === 0) {
      e.base += base;
      e.quote -= notional + fee;
    } else {
      e.base -= base;
      e.quote += notional - fee;
    }
    fees += fee;
  }
  const deltas: AccountDelta[] = [];
  for (const e of [...net.values()].sort((a, b) => compare(a.trader, b.trader))) {
    if (e.base === 0n && e.quote === 0n) continue;
    if (e.base > I64_MAX || e.base < I64_MIN || e.quote > I64_MAX || e.quote < I64_MIN) {
      throw new SettlementError('overflow', 'settlement delta overflows i64');
    }
    deltas.push({ trader: e.trader, base: e.base, quote: e.quote });
  }
  if (fees > U64_MAX) throw new SettlementError('overflow', 'fees overflow u64');
  const batch = { market: p.market, epoch, deltas, fees };
  checkConservation(batch);
  return batch;
}
