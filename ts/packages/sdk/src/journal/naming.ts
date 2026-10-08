import type { Address } from '@solana/kit';
import { b58 } from '../core/encoding/base58.js';
import { utf8 } from '../core/encoding/bytes.js';
import { hex } from '../core/encoding/hex.js';
import { hashTagged } from '../core/crypto/hash.js';

/** Local tag of the database-name hash. Not a protocol domain. */
const NAME_TAG = 'timescales-journal-v2/db-name';

export const DEVICE_DB = 'timescales-device';
export const JOURNAL_DB_PREFIX = 'timescales-journal-v2-';

/**
 * `timescales-journal-v2-<hex(H(device salt || cluster || program || wallet))[..16]>`.
 * The random per-device salt keeps the wallet out of every name a browser
 * profile shows. The cluster is length-prefixed so the parts cannot run
 * together.
 */
export function journalDatabaseName(
  deviceSalt: Uint8Array,
  cluster: string,
  program: Address,
  wallet: Address,
): string {
  if (deviceSalt.length !== 16) throw new RangeError('device salt must be 16 bytes');
  const c = utf8(cluster);
  if (c.length > 255) throw new RangeError('cluster name too long');
  const digest = hashTagged(
    NAME_TAG,
    deviceSalt,
    Uint8Array.of(c.length),
    c,
    b58.decode(program, 32),
    b58.decode(wallet, 32),
  );
  return JOURNAL_DB_PREFIX + hex.encode(digest).slice(0, 16);
}
