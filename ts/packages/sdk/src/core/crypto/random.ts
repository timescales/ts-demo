import { TimescalesError } from '../../errors.js';
import { bytesToBigIntLE } from '../encoding/bytes.js';

function csprng(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (c === undefined || typeof c.getRandomValues !== 'function') {
    throw new TimescalesError({
      kind: 'environment',
      code: 'no_csprng',
      message: 'no cryptographically secure random source is available',
    });
  }
  return c;
}

/** `n` bytes from `crypto.getRandomValues`. Throws when no CSPRNG exists. */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  const c = csprng();
  for (let at = 0; at < n; at += 65536)
    c.getRandomValues(out.subarray(at, Math.min(n, at + 65536)));
  return out;
}

/** A uniformly random u64 (order nonces). */
export function randomU64(): bigint {
  return bytesToBigIntLE(randomBytes(8));
}
