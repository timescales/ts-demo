import { ed25519 } from '@noble/curves/ed25519.js';

export { verifyStrict } from './verifyStrict.js';

/**
 * RFC 8032 Ed25519 signature over `msg` (in the protocol always a 32-byte
 * tagged digest, signed raw: no prehash, no context). Deterministic.
 */
export function ed25519Sign(seed: Uint8Array, msg: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new RangeError('Ed25519 seed must be 32 bytes');
  return ed25519.sign(msg, seed);
}

/** The 32-byte public key of an RFC 8032 seed. */
export function ed25519PublicKey(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new RangeError('Ed25519 seed must be 32 bytes');
  return ed25519.getPublicKey(seed);
}
