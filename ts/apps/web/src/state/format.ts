// Display formatting shared by the shell and the feature screens. Amounts are
// exact decimal strings from the SDK's unit conversions, never floats.
import type { Clearing, MarketDetail } from '@timescales/sdk/api';
import type { UnitContext } from '@timescales/sdk/core';
import { tickToPrice } from '@timescales/sdk/core';

/** Solana's target slot time. Durations derived from slot counts are estimates. */
export const SLOT_MS = 400;

export function unitsOf(detail: MarketDetail): UnitContext {
  return {
    params: detail.params,
    baseDecimals: detail.baseDecimals,
    quoteDecimals: detail.quoteDecimals,
  };
}

/** The exact price of a tick, or the raw tick when the market's units are not known. */
export function formatTick(detail: MarketDetail | undefined, tick: bigint): string {
  if (detail === undefined) return `tick ${tick}`;
  try {
    return tickToPrice(unitsOf(detail), tick);
  } catch {
    return `tick ${tick}`;
  }
}

/** Clearing prices per book: "182.37", or "ask 182.37, bid 182.40" for dual-flow markets. */
export function formatClearing(
  detail: MarketDetail | undefined,
  clearing: readonly Clearing[],
): string {
  if (clearing.length === 1) return formatTick(detail, clearing[0]!.tick);
  return clearing
    .map((c) => {
      const label = detail?.books.find((b) => b.book === c.book)?.label ?? `book ${c.book}`;
      return `${label} ${formatTick(detail, c.tick)}`;
    })
    .join(', ');
}

/** "45 s", "12 min", "23 h", "3 d". */
export function formatDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} s`;
  const min = Math.round(s / 60);
  if (min < 60) return `${min} min`;
  const h = Math.round(min / 60);
  if (h < 48) return `${h} h`;
  return `${Math.round(h / 24)} d`;
}

/** An estimate from a slot count ("~ 23 h"). */
export function formatSlots(slots: bigint): string {
  const ms = Number(slots > 0n ? slots : 0n) * SLOT_MS;
  return `~ ${formatDuration(ms)}`;
}

/** Local wall-clock time of a server timestamp, hh:mm:ss. */
export function formatClock(ms: number): string {
  const d = new Date(ms);
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((n) => String(n).padStart(2, '0'))
    .join(':');
}

/** Local date and time, for history views. */
export function formatDateTime(ms: number): string {
  const d = new Date(ms);
  const date = [d.getFullYear(), d.getMonth() + 1, d.getDate()]
    .map((n, i) => (i === 0 ? String(n) : String(n).padStart(2, '0')))
    .join('-');
  return `${date} ${formatClock(ms)}`;
}

export function shortHex(bytes: Uint8Array, keep = 8): string {
  let out = '';
  for (const b of bytes.subarray(0, keep / 2)) out += b.toString(16).padStart(2, '0');
  return `${out}...`;
}
