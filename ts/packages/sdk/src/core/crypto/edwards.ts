import { ed25519 } from '@noble/curves/ed25519.js';
import { bigIntToBytesLE } from '../encoding/bytes.js';

const Point = ed25519.Point;
type EdPoint = InstanceType<typeof Point>;
const P = 2n ** 255n - 19n;

function mod(a: bigint): bigint {
  const r = a % P;
  return r < 0n ? r + P : r;
}

function inv(a: bigint): bigint {
  let r = 1n;
  let b = mod(a);
  let e = P - 2n;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}

/** Strict decompression (canonical encodings only). Null when the bytes are not a point. */
export function decompress(compressed: Uint8Array): EdPoint | null {
  if (compressed.length !== 32) return null;
  try {
    return Point.fromBytes(compressed, false);
  } catch {
    return null;
  }
}

/** True for a point in the prime-order subgroup other than the identity. */
export function isPrimeOrder(p: EdPoint): boolean {
  return !p.is0() && p.isTorsionFree();
}

/** The Montgomery u-coordinate `(1 + y) / (1 - y) mod p`, little-endian. */
export function montgomeryU(p: EdPoint): Uint8Array {
  const { y } = p.toAffine();
  return bigIntToBytesLE(mod((1n + y) * inv(1n - y)), 32);
}

/**
 * `u` for a canonical, torsion-free, non-identity Edwards point (the
 * Feldman `C_0` check), or null. `u(s*B)` is the X25519 public key of
 * the scalar `s`.
 */
export function edwardsU(compressed: Uint8Array): Uint8Array | null {
  const p = decompress(compressed);
  if (p === null || !isPrimeOrder(p)) return null;
  return montgomeryU(p);
}
