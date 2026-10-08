import { x25519 } from '@noble/curves/ed25519.js';
import { isZero } from '../encoding/bytes.js';

export function x25519PublicKey(secret: Uint8Array): Uint8Array {
  if (secret.length !== 32) throw new RangeError('X25519 secret must be 32 bytes');
  return x25519.getPublicKey(secret);
}

/**
 * X25519 with the contributory check of x25519-dalek's `was_contributory`:
 * an all-zero shared secret (a low-order peer key) is rejected, whether or
 * not the library already refused it.
 */
export function x25519Shared(secret: Uint8Array, peer: Uint8Array): Uint8Array {
  if (secret.length !== 32 || peer.length !== 32)
    throw new RangeError('X25519 keys must be 32 bytes');
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(secret, peer);
  } catch (cause) {
    throw new Error('non-contributory X25519 exchange', { cause });
  }
  if (isZero(shared)) throw new Error('non-contributory X25519 exchange');
  return shared;
}
