import type { Address } from '@solana/kit';
import { b58 } from '../encoding/base58.js';
import { readU64le } from '../encoding/bytes.js';
import { H } from '../crypto/hash.js';

/** `LE64(H(MARKET_ID, program32 || creator32 || salt32)[0..8])`. */
export function deriveMarketId(program: Address, creator: Address, salt: Uint8Array): bigint {
  if (salt.length !== 32) throw new RangeError('salt must be 32 bytes');
  return readU64le(H('MARKET_ID', b58.decode(program, 32), b58.decode(creator, 32), salt), 0);
}
