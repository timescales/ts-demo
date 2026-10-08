import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToBigIntLE, concat, equal } from '../encoding/bytes.js';

const Point = ed25519.Point;
/** Order of the prime subgroup. */
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/**
 * ed25519-dalek 2.x `verify_strict`: `s < L`, strict point
 * decoding, small-order `A` and `R` rejected, and the cofactorless equation
 * `[s]B - [k]A == R` compared byte for byte with the signature's `R`.
 * Returns false for any malformed input. Never throws.
 */
export function verifyStrict(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (pub.length !== 32 || sig.length !== 64) return false;
  const rBytes = sig.subarray(0, 32);
  const s = bytesToBigIntLE(sig.subarray(32));
  if (s >= L) return false;
  let A;
  let R;
  try {
    A = Point.fromBytes(pub, false);
    R = Point.fromBytes(rBytes, false);
  } catch {
    return false;
  }
  if (A.isSmallOrder() || R.isSmallOrder()) return false;
  const k = bytesToBigIntLE(sha512(concat(rBytes, pub, msg))) % L;
  const rPrime = Point.BASE.multiplyUnsafe(s).subtract(A.multiplyUnsafe(k));
  return equal(rPrime.toBytes(), rBytes);
}
