import { TimescalesError } from '../errors.js';
import type { Journal } from '../journal/journal.js';
import type { OrderRecord } from './model.js';

const ATTEMPTS = 8;

function isConflict(e: unknown): boolean {
  return e instanceof TimescalesError && e.code === 'version_conflict';
}

/**
 * Versioned single-transaction write of `f(current)`: when another tab
 * wrote the record meanwhile the journal refuses the stale version, and the
 * record is read again and `f` applied again, so no update is lost. `f`
 * returns null to leave the record as it is.
 */
export async function updateRecord(
  journal: Journal,
  id: string,
  f: (r: OrderRecord) => OrderRecord | null,
  fallback?: () => OrderRecord | undefined,
): Promise<{ record: OrderRecord; written: boolean }> {
  for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
    const current = (await journal.get(id)) ?? fallback?.();
    if (current === undefined) {
      throw new TimescalesError({ kind: 'storage', code: 'missing', message: `no record ${id}` });
    }
    const next = f(current);
    if (next === null) return { record: current, written: false };
    try {
      const version = await journal.put(next, current.version);
      return { record: { ...next, version }, written: true };
    } catch (e) {
      if (isConflict(e)) continue;
      throw e;
    }
  }
  throw new TimescalesError({
    kind: 'storage',
    code: 'version_conflict',
    message: `record ${id} kept changing under concurrent writes`,
  });
}
