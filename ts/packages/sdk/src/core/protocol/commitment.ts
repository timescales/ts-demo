import { H } from '../crypto/hash.js';
import { encodeIntentBody, type IntentBody } from './intent.js';

/**
 * SHA-256 commitment `H(ORDER_COMMITMENT, kind || body || salt)`. The kind byte
 * equals the `IntentBody` tag, so the preimage is `encode(body) || salt`.
 * Markets with Poseidon commitments are refused by
 * `validateOrder` with `UnsupportedScheme`.
 */
export function commitment(body: IntentBody, salt: Uint8Array): Uint8Array {
  if (salt.length !== 32) throw new RangeError('salt must be 32 bytes');
  return H('ORDER_COMMITMENT', encodeIntentBody(body), salt);
}
