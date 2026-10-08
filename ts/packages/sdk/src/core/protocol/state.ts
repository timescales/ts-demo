import { compare } from '../encoding/bytes.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';
import { utf8 } from '../encoding/bytes.js';
import { merkleRoot } from './merkle.js';

/** Cross-epoch order state (49 B): `C || filled u64 || cancelled bool || created u64`. */
export interface StateEntry {
  commitment: Uint8Array;
  filled: bigint;
  cancelled: boolean;
  created: bigint;
}

/** One balance-sheet entry: `trader32 || base u64 || quote u64`. */
export interface BalanceEntry {
  trader: Uint8Array;
  base: bigint;
  quote: bigint;
}

export const STATE_ENTRY_LEN = 49;
export const BALANCE_ENTRY_LEN = 48;
const MAX_TABLE = 1 << 24;

export function encodeStateEntry(e: StateEntry): Uint8Array {
  return new Writer()
    .fixed(e.commitment, 32)
    .u64(e.filled)
    .bool(e.cancelled)
    .u64(e.created)
    .finish();
}

/** `OrderStateTable`: entries strictly increasing by commitment. */
export function decodeStateTable(b: Uint8Array): StateEntry[] {
  return decodeExact(b, (r) => {
    const v = r.seq(
      MAX_TABLE,
      (x) => ({ commitment: x.fixed(32), filled: x.u64(), cancelled: x.bool(), created: x.u64() }),
      STATE_ENTRY_LEN,
    );
    for (let i = 1; i < v.length; i++) {
      if (compare(v[i - 1]!.commitment, v[i]!.commitment) >= 0) {
        throw new DecodeError('value', 'OrderStateTable order');
      }
    }
    return v;
  });
}

/** Root over entries sorted by commitment (a copy is sorted). */
export function stateRoot(entries: StateEntry[]): Uint8Array {
  return merkleRoot(
    [...entries].sort((a, b) => compare(a.commitment, b.commitment)).map(encodeStateEntry),
  );
}

export function encodeBalanceEntry(e: BalanceEntry): Uint8Array {
  return new Writer().fixed(e.trader, 32).u64(e.base).u64(e.quote).finish();
}

/** `BalanceSheet`: entries strictly increasing by trader. */
export function decodeBalanceSheet(b: Uint8Array): BalanceEntry[] {
  return decodeExact(b, (r) => {
    const v = r.seq(
      MAX_TABLE,
      (x) => ({ trader: x.fixed(32), base: x.u64(), quote: x.u64() }),
      BALANCE_ENTRY_LEN,
    );
    for (let i = 1; i < v.length; i++) {
      if (compare(v[i - 1]!.trader, v[i]!.trader) >= 0)
        throw new DecodeError('value', 'BalanceSheet order');
    }
    return v;
  });
}

export function encodeBalanceSheet(entries: BalanceEntry[]): Uint8Array {
  const sorted = [...entries].sort((a, b) => compare(a.trader, b.trader));
  return new Writer()
    .seq(sorted, MAX_TABLE, (w, e) => w.fixed(e.trader, 32).u64(e.base).u64(e.quote))
    .finish();
}

/** The header's `balances_root`: Merkle root over entries in trader order. */
export function balancesRoot(entries: BalanceEntry[]): Uint8Array {
  return merkleRoot(
    [...entries].sort((a, b) => compare(a.trader, b.trader)).map(encodeBalanceEntry),
  );
}

/** `H(SETTLEMENT, "balances" || balances_root)`. */
export function balancesDigest(entries: BalanceEntry[]): Uint8Array {
  return H('SETTLEMENT', utf8('balances'), balancesRoot(entries));
}
