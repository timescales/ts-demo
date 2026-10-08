// Exact conversions between what the trader types and the integers that are
// signed (ticket fields 5 and 6). Everything is bigint or a canonical
// decimal string. No value passes through a float.
import type { Clearing } from '@timescales/sdk/api';
import type { BookId, MarketParams, PriceBand, Side, UnitContext } from '@timescales/sdk/core';
import {
  baseToLots,
  feeCeilPerUnit,
  hex,
  intentDigest,
  lotsToBase,
  maxOrderLots,
  parseDecimal,
  priceToTick,
  tickToPrice,
} from '@timescales/sdk/core';

import { tradeCopy } from './copy';
import type { NumberFormat } from './services';

export type ParseError = 'empty' | 'syntax' | 'ambiguous' | 'zero' | 'too_large';

export type QuantityParse =
  { ok: true; lots: bigint; base: string; exact: boolean } | { ok: false; error: ParseError };

export type PriceParse =
  | { ok: true; tick: bigint; typed: string; price: string; exact: boolean }
  | { ok: false; error: ParseError };

function parseError(e: unknown): ParseError {
  const reason = (e as { reason?: unknown } | null)?.reason;
  if (reason === 'ambiguous') return 'ambiguous';
  if (reason === 'range') return 'too_large';
  return 'syntax';
}

/** Canonical decimal of the input in the declared format, or the reason it is not one. */
export function canonical(
  text: string,
  format: NumberFormat,
): { ok: true; value: string } | { ok: false; error: ParseError } {
  if (text.trim() === '') return { ok: false, error: 'empty' };
  try {
    return { ok: true, value: parseDecimal(text, format) };
  } catch (e) {
    return { ok: false, error: parseError(e) };
  }
}

/** Quantity in lots, rounded down. The shown base amount is the exact one that is signed. */
export function parseQuantity(text: string, format: NumberFormat, u: UnitContext): QuantityParse {
  const c = canonical(text, format);
  if (!c.ok) return c;
  try {
    const { lots, exact } = baseToLots(u, c.value, 'down');
    if (lots === 0n) return { ok: false, error: 'zero' };
    if (lots > maxOrderLots(u.params)) return { ok: false, error: 'too_large' };
    return { ok: true, lots, base: lotsToBase(u, lots), exact };
  } catch (e) {
    return { ok: false, error: parseError(e) };
  }
}

/**
 * Limit price as the tick that will be signed: a buy rounds down and a sell
 * rounds up, so rounding never makes the limit worse for the trader.
 */
export function parseLimit(
  text: string,
  format: NumberFormat,
  u: UnitContext,
  side: Side,
): PriceParse {
  const c = canonical(text, format);
  if (!c.ok) return c;
  try {
    const { tick, exact } = priceToTick(u, c.value, side, side === 0 ? 'down' : 'up');
    if (tick === 0n) return { ok: false, error: 'zero' };
    return { ok: true, tick, typed: c.value, price: priceOf(u, tick), exact };
  } catch (e) {
    return { ok: false, error: parseError(e) };
  }
}

/** Exact price of a tick. Ticks whose price has no finite decimal show as the tick. */
export function priceOf(u: UnitContext, tick: bigint): string {
  try {
    return tickToPrice(u, tick);
  } catch {
    return tradeCopy.tickFallback(tick.toString());
  }
}

/** `atoms / 10^decimals` as an exact canonical decimal. */
export function atomsToDecimal(atoms: bigint, decimals: number): string {
  const negative = atoms < 0n;
  const abs = negative ? -atoms : atoms;
  const scale = 10n ** BigInt(decimals);
  const int = (abs / scale).toString();
  const frac = (abs % scale).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${negative ? '-' : ''}${int}${frac ? `.${frac}` : ''}`;
}

/** Decimal amount to atoms, or null when it has more digits than the token. */
export function decimalToAtoms(value: string, decimals: number): bigint | null {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(value);
  if (m === null) return null;
  const frac = m[2] ?? '';
  if (frac.length > decimals) return null;
  return BigInt(m[1]! + frac.padEnd(decimals, '0'));
}

/** A canonical decimal in the declared format, with group separators. */
export function localize(value: string, format: NumberFormat): string {
  const negative = value.startsWith('-');
  const [int = '0', frac] = (negative ? value.slice(1) : value).split('.');
  const grouped = format.group === '' ? int : int.replace(/\B(?=(\d{3})+(?!\d))/g, format.group);
  return `${negative ? '−' : ''}${grouped}${frac ? `${format.decimal}${frac}` : ''}`;
}

/** Signed deviation of `tick` from `reference` in percent, two decimals, rounded half away from zero. */
export function deviationPercent(tick: bigint, reference: bigint): string {
  if (reference <= 0n) return '0.00';
  const diff = tick - reference;
  const negative = diff < 0n;
  const abs = negative ? -diff : diff;
  const hundredths = (abs * 20_000n + reference) / (2n * reference);
  const text = `${hundredths / 100n}.${(hundredths % 100n).toString().padStart(2, '0')}`;
  if (hundredths === 0n) return '0.00';
  return `${negative ? '−' : '+'}${text}`;
}

/** Exact base amount of `lots`. */
export function lotsToBaseText(u: UnitContext, lots: bigint): string {
  return lotsToBase(u, lots);
}

/** Largest quantity an order may carry: `2^b - 1` lots. */
export function maxLots(params: MarketParams): bigint {
  return maxOrderLots(params);
}

/** Quote atoms one lot reserves at `tick` for a buy, fee included. */
export function buyCostPerLot(params: MarketParams, tick: bigint, feeBps: number): bigint {
  const price = tick * params.tickSize;
  return price + feeCeilPerUnit(feeBps, price);
}

/** Lots a share of the available balance buys or sells (the 25/50/100 % buttons). */
export function lotsForShare(a: {
  params: MarketParams;
  side: Side;
  feeBps: number;
  available: { base: bigint; quote: bigint };
  /** Tick the buy reserves at: its limit inside the band, or the band's top for a market buy. */
  tick: bigint;
  percent: 25 | 50 | 100;
}): bigint {
  const share = (v: bigint) => (v * BigInt(a.percent)) / 100n;
  let lots: bigint;
  if (a.side === 1) {
    lots = share(a.available.base) / a.params.baseLotSize;
  } else {
    const perLot = buyCostPerLot(a.params, a.tick, a.feeBps);
    lots = perLot === 0n ? 0n : share(a.available.quote) / perLot;
  }
  const cap = maxOrderLots(a.params);
  return lots > cap ? cap : lots < 0n ? 0n : lots;
}

/** The tick a buy reserves at: its limit clamped into the band (slot). */
export function reserveTick(band: PriceBand, side: Side, kind: 0 | 1, limit: bigint): bigint {
  if (kind === 1) return side === 0 ? band.hi : band.lo;
  if (limit > band.hi) return band.hi;
  if (limit < band.lo) return band.lo;
  return limit;
}

/** Last clearing tick of a book, if it cleared. */
export function clearingTick(clearing: readonly Clearing[] | null, book: BookId): bigint | null {
  return clearing?.find((c) => c.book === book)?.tick ?? null;
}

/**
 * The order fingerprint (limit 2): the first 8 characters of the intent
 * digest in the wallet's display encoding, hex by default.
 */
export function orderFingerprint(commitment: Uint8Array): string {
  return hex.encode(intentDigest(commitment)).slice(0, 8);
}
