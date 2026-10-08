// Own fills per epoch. A record's `fills` grow by the fills of one verified
// epoch at a time, in the order of its `fills` events (one batch in flight
// per market), and a voided epoch's fills are removed again. Walking the
// events in order attributes every fill to its epoch.
import type { OrderRecord } from '@timescales/sdk/orders';
import type { OwnFill } from '@timescales/sdk/verify';

export interface EpochFill extends OwnFill {
  epoch: bigint;
  /** The participation reached `settled` (V-10). Until then the fill is provisional. */
  settled: boolean;
}

const COUNTED = new Set(['verified', 'settling', 'settled']);

export function fillsByEpoch(record: OrderRecord): EpochFill[] {
  const out: EpochFill[] = [];
  let next = 0;
  for (const e of record.history) {
    if (e.kind !== 'fills' || e.filled === 0n) continue;
    const p = record.epochs.get(e.epoch);
    if (p === undefined || !COUNTED.has(p.state.kind)) continue;
    let left = e.filled;
    while (left > 0n && next < record.fills.length) {
      const f = record.fills[next++]!;
      out.push({ ...f, epoch: e.epoch, settled: p.state.kind === 'settled' });
      left -= f.quantity;
    }
  }
  return out;
}

/** The tick an order traded at in an epoch (uniform clearing price), if it traded there. */
export function fillTick(record: OrderRecord, epoch: bigint): bigint | null {
  return fillsByEpoch(record).find((f) => f.epoch === epoch)?.tick ?? null;
}

const PLAIN_NUMBER = /^-?\d+(\.\d+)?$/;
const FORMULA_START = /^[=+\-@\t\r]/;

/**
 * RFC 4180 field: quoted when it holds a comma, quote or line break. Market
 * names and symbols come from the operator, so a text cell a spreadsheet would
 * read as a formula gets a leading apostrophe. Plain numbers stay as they are.
 */
function csvField(v: string): string {
  const safe = FORMULA_START.test(v) && !PLAIN_NUMBER.test(v) ? `'${v}` : v;
  return /[",\r\n]/.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
}

export function toCsv(header: readonly string[], rows: readonly (readonly string[])[]): string {
  return [header, ...rows].map((r) => r.map(csvField).join(',')).join('\r\n') + '\r\n';
}
