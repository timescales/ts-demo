import { u64le } from '../encoding/bytes.js';
import { H } from '../crypto/hash.js';

/**
 * `H(RECEIPT_COSIGN, market32 || epoch || header digest || outcome digest)`: what a
 * co-signing executor signs. `header` and `outcome` are the 32-byte digests.
 */
export function cosignDigest(
  market: Uint8Array,
  epoch: bigint,
  header: Uint8Array,
  outcome: Uint8Array,
): Uint8Array {
  if (market.length !== 32 || header.length !== 32 || outcome.length !== 32) {
    throw new RangeError('cosign inputs must be 32 bytes');
  }
  return H('RECEIPT_COSIGN', market, u64le(epoch), header, outcome);
}
