import { utf8, u32le, u64le, readU64le } from '../encoding/bytes.js';
import { H } from '../crypto/hash.js';

/** Entries the SlotHashes sysvar holds at most. */
export const MAX_SLOT_HASHES = 512;
const ENTRY_LEN = 40;

/**
 * Beacon v2, byte-identical to the program:
 * `H(BATCH_SEED, "slot-hash-beacon/v2" || market32 || epoch || root || count || slot_a || hash_a || slot_b || hash_b)`.
 */
export function beaconV2(
  market: Uint8Array,
  epoch: bigint,
  root: Uint8Array,
  count: number,
  a: readonly [bigint, Uint8Array],
  b: readonly [bigint, Uint8Array],
): Uint8Array {
  if (market.length !== 32 || root.length !== 32 || a[1].length !== 32 || b[1].length !== 32) {
    throw new RangeError('beacon inputs must be 32 bytes');
  }
  return H(
    'BATCH_SEED',
    utf8('slot-hash-beacon/v2'),
    market,
    u64le(epoch),
    root,
    u32le(count),
    u64le(a[0]),
    a[1],
    u64le(b[0]),
    b[1],
  );
}

/**
 * The SlotHashes entry with the smallest slot `>= target`, from sysvar data
 * `u64 N || N x (slot u64 || hash32)` (slots descending). Null when no entry
 * reaches `target`, `N > 512`, or the data is short. Reads only the entries a
 * binary search visits, as the program does.
 */
export function slotHashesEntry(
  data: Uint8Array,
  target: bigint,
): readonly [bigint, Uint8Array] | null {
  if (data.length < 8) return null;
  const n = readU64le(data, 0);
  if (n > BigInt(MAX_SLOT_HASHES)) return null;
  const count = Number(n);
  if (data.length < 8 + count * ENTRY_LEN) return null;
  const slotAt = (i: number): bigint => readU64le(data, 8 + i * ENTRY_LEN);
  let lo = 0;
  let hi = count;
  while (lo < hi) {
    const mid = lo + Math.floor((hi - lo) / 2);
    if (slotAt(mid) >= target) lo = mid + 1;
    else hi = mid;
  }
  if (lo === 0) return null;
  const i = lo - 1;
  const at = 8 + i * ENTRY_LEN + 8;
  return [slotAt(i), data.slice(at, at + 32)] as const;
}
