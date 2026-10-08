import { chacha20 } from '@noble/ciphers/chacha.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToBigIntLE } from '../core/encoding/bytes.js';

/** A deterministic byte source for tests. */
export interface TestRng {
  bytes(n: number): Uint8Array;
  u64(): bigint;
}

const BLOCK = 64;
const NONCE = new Uint8Array(12);

/**
 * ChaCha20 keyed with `SHA-256(seed)`: the same seed gives the same stream
 * on every platform. For tests only. It is not a CSPRNG for real keys.
 */
export function createTestRng(seed: Uint8Array): TestRng {
  const key = sha256(seed);
  let counter = 0;
  let buffer = new Uint8Array(0);
  const bytes = (n: number): Uint8Array => {
    if (!Number.isInteger(n) || n < 0) throw new RangeError('byte count must be a natural number');
    while (buffer.length < n) {
      const blocks = Math.max(1, Math.ceil((n - buffer.length) / BLOCK));
      const fresh = chacha20(key, NONCE, new Uint8Array(blocks * BLOCK), undefined, counter);
      counter += blocks;
      const next = new Uint8Array(buffer.length + fresh.length);
      next.set(buffer);
      next.set(fresh, buffer.length);
      buffer = next;
    }
    const out = buffer.slice(0, n);
    buffer = buffer.slice(n);
    return out;
  };
  return { bytes, u64: () => bytesToBigIntLE(bytes(8)) };
}

/** Routes `crypto.getRandomValues` through `rng` until the returned function restores it. */
export function installTestRandom(rng: TestRng): () => void {
  const c = globalThis.crypto;
  if (c === undefined) throw new Error('no crypto object to patch');
  const own = Object.getOwnPropertyDescriptor(c, 'getRandomValues');
  Object.defineProperty(c, 'getRandomValues', {
    configurable: true,
    writable: true,
    value: <T extends ArrayBufferView | null>(array: T): T => {
      if (array === null) return array;
      const view = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
      view.set(rng.bytes(view.length));
      return array;
    },
  });
  return () => {
    if (own !== undefined) Object.defineProperty(c, 'getRandomValues', own);
    else delete (c as { getRandomValues?: unknown }).getRandomValues;
  };
}
