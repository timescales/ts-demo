import type { MarketParams, Side } from './params.js';

/**
 * Exact unit conversions between protocol integers (ticks, lots, atoms) and
 * the decimal strings the UI shows. Nothing here goes through `number`.
 *
 * A lot is `baseLotSize` base atoms. One lot at tick `t` costs
 * `t * tickSize` quote atoms. A price is quote tokens per base token.
 */
export interface UnitContext {
  params: MarketParams;
  baseDecimals: number;
  quoteDecimals: number;
}

export type Rounding = 'down' | 'up' | 'nearest';

export type UnitsErrorReason = 'syntax' | 'ambiguous' | 'range' | 'non_terminating';

export class UnitsError extends Error {
  readonly reason: UnitsErrorReason;

  constructor(reason: UnitsErrorReason, message: string) {
    super(message);
    this.name = 'UnitsError';
    this.reason = reason;
  }
}

const U64_MAX = (1n << 64n) - 1n;

function pow10(n: number): bigint {
  if (!Number.isInteger(n) || n < 0 || n > 255) throw new UnitsError('range', `bad decimals ${n}`);
  return 10n ** BigInt(n);
}

function gcd(a: bigint, b: bigint): bigint {
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

/** Exact decimal string of `num / den`, or a `non_terminating` error. */
function ratioToDecimal(num: bigint, den: bigint): string {
  const g = gcd(num, den);
  const n = num / (g === 0n ? 1n : g);
  const d = den / (g === 0n ? 1n : g);
  let twos = 0;
  let fives = 0;
  let rest = d;
  while (rest % 2n === 0n) {
    rest /= 2n;
    twos++;
  }
  while (rest % 5n === 0n) {
    rest /= 5n;
    fives++;
  }
  if (rest !== 1n)
    throw new UnitsError('non_terminating', `${num}/${den} has no finite decimal expansion`);
  const scale = Math.max(twos, fives);
  return formatScaled(n * (10n ** BigInt(scale) / d), scale);
}

/** `v / 10^scale` as a canonical decimal string (no trailing fraction zeros). */
function formatScaled(v: bigint, scale: number): string {
  if (scale === 0) return v.toString();
  const s = v.toString().padStart(scale + 1, '0');
  const int = s.slice(0, s.length - scale);
  const frac = s.slice(s.length - scale).replace(/0+$/, '');
  return frac.length === 0 ? int : `${int}.${frac}`;
}

/** Parses a canonical decimal (`digits[.digits]`) into `v / 10^scale`. */
function parseCanonical(s: string): { v: bigint; scale: number } {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(s);
  if (m === null) throw new UnitsError('syntax', `not a canonical decimal: ${JSON.stringify(s)}`);
  const frac = m[2] ?? '';
  return { v: BigInt(m[1]! + frac), scale: frac.length };
}

/** `num / den` rounded. Ties go up when `tieUp`, down otherwise. */
function divRound(
  num: bigint,
  den: bigint,
  mode: Rounding,
  tieUp: boolean,
): { q: bigint; exact: boolean } {
  const q = num / den;
  const r = num % den;
  if (r === 0n) return { q, exact: true };
  if (mode === 'down') return { q, exact: false };
  if (mode === 'up') return { q: q + 1n, exact: false };
  const twice = 2n * r;
  if (twice > den || (twice === den && tieUp)) return { q: q + 1n, exact: false };
  return { q, exact: false };
}

function checkU64(v: bigint, what: string): bigint {
  if (v < 0n || v > U64_MAX) throw new UnitsError('range', `${what} out of u64 range`);
  return v;
}

/** Exact price of `tick` in quote tokens per base token. Throws `non_terminating` when no finite decimal exists. */
export function tickToPrice(u: UnitContext, tick: bigint): string {
  checkU64(tick, 'tick');
  const num = tick * u.params.tickSize * pow10(u.baseDecimals);
  const den = u.params.baseLotSize * pow10(u.quoteDecimals);
  return ratioToDecimal(num, den);
}

/**
 * Tick for a canonical decimal price. With `nearest`, an exact tie rounds in
 * the trader's favour as a limit: down for a buy, up for a sell.
 */
export function priceToTick(
  u: UnitContext,
  price: string,
  side: Side,
  mode: Rounding,
): { tick: bigint; exact: boolean } {
  const { v, scale } = parseCanonical(price);
  const num = v * u.params.baseLotSize * pow10(u.quoteDecimals);
  const den = u.params.tickSize * pow10(u.baseDecimals) * pow10(scale);
  const { q, exact } = divRound(num, den, mode, side === 1);
  return { tick: checkU64(q, 'tick'), exact };
}

/** Exact base-token amount of `lots`. */
export function lotsToBase(u: UnitContext, lots: bigint): string {
  checkU64(lots, 'lots');
  return formatScaled(lots * u.params.baseLotSize, u.baseDecimals);
}

/** Lots for a canonical decimal base amount. `nearest` rounds ties up. */
export function baseToLots(
  u: UnitContext,
  base: string,
  mode: Rounding,
): { lots: bigint; exact: boolean } {
  const { v, scale } = parseCanonical(base);
  const num = v * pow10(u.baseDecimals);
  const den = u.params.baseLotSize * pow10(scale);
  const { q, exact } = divRound(num, den, mode, true);
  return { lots: checkU64(q, 'lots'), exact };
}

const SPACES = new Set([' ', ' ', ' ']);
const SEPARATOR_LIKE = new Set(['.', ',', "'", '’', '_', ...SPACES]);

/**
 * Parses user input in a locale into a canonical decimal string
 * (`digits[.digits]`, no leading or trailing zeros beyond what the value
 * needs). Group separators must sit between groups of exactly three digits
 * in the integer part. Any separator-like character that is neither the
 * locale's decimal nor its group separator, a second decimal separator, or a
 * misplaced group separator throws `ambiguous`, so `1,234` is never read as
 * 1.234 in a `.`-decimal locale and vice versa.
 */
export function parseDecimal(
  input: string,
  locale: { decimal: '.' | ','; group: ',' | '.' | ' ' | '' },
): string {
  if (locale.decimal === locale.group) {
    throw new UnitsError('ambiguous', 'decimal and group separators are the same');
  }
  const s = input.trim();
  if (s.length === 0) throw new UnitsError('syntax', 'empty number');
  const isGroup = (c: string): boolean =>
    locale.group !== '' && (c === locale.group || (locale.group === ' ' && SPACES.has(c)));
  let fracPart: string | null = null;
  const groups: string[] = [];
  let current = '';
  for (const c of s) {
    if (c >= '0' && c <= '9') {
      if (fracPart === null) current += c;
      else fracPart += c;
    } else if (c === locale.decimal) {
      if (fracPart !== null) throw new UnitsError('ambiguous', 'more than one decimal separator');
      groups.push(current);
      current = '';
      fracPart = '';
    } else if (isGroup(c)) {
      if (fracPart !== null)
        throw new UnitsError('ambiguous', 'group separator after the decimal separator');
      groups.push(current);
      current = '';
    } else if (SEPARATOR_LIKE.has(c)) {
      throw new UnitsError('ambiguous', `unexpected separator ${JSON.stringify(c)}`);
    } else {
      throw new UnitsError('syntax', `unexpected character ${JSON.stringify(c)}`);
    }
  }
  if (fracPart === null) groups.push(current);
  if (groups.length > 1) {
    const [first, ...rest] = groups;
    if (first!.length < 1 || first!.length > 3 || rest.some((g) => g.length !== 3)) {
      throw new UnitsError('ambiguous', 'misplaced group separator');
    }
  }
  const intPart = groups.join('');
  const frac = (fracPart ?? '').replace(/0+$/, '');
  if (intPart.length === 0 && (fracPart === null || fracPart.length === 0)) {
    throw new UnitsError('syntax', 'no digits');
  }
  const int = intPart.replace(/^0+(?=\d)/, '') || '0';
  return frac.length === 0 ? int : `${int}.${frac}`;
}
