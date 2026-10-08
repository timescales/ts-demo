// verifyStrict against ed25519-dalek's verify_strict rules.
// Hand-built cases. The V9 matrix replaces them once it exists.
import { ED25519_TORSION_SUBGROUP, ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import {
  ED25519_ORDER as L,
  bigIntToBytesLE,
  bytesToBigIntLE,
  concat,
  ed25519PublicKey,
  ed25519Sign,
  hex,
  utf8,
  verifyStrict,
} from '../src/core/index.js';
import { referenceVerifyStrict } from './support/ed25519Reference.js';

const Point = ed25519.Point;
const seed = new Uint8Array(32).fill(7);
const pub = ed25519PublicKey(seed);
const msg = utf8('timescales verify-strict');
const sig = ed25519Sign(seed, msg);
const torsion = ED25519_TORSION_SUBGROUP.map((h) => hex.decode(h));
const order8 = torsion.filter((t) => {
  const p = Point.fromBytes(t, true);
  return !p.multiplyUnsafe(4n).is0();
});

/** noble's cofactored ZIP-215 check, which the protocol must not use. */
function cofactored(p: Uint8Array, m: Uint8Array, s: Uint8Array): boolean {
  // eslint-disable-next-line no-restricted-syntax -- the comparison target, not a protocol check
  return ed25519.verify(s, m, p, { zip215: true });
}

function scalar(bytes: Uint8Array): bigint {
  return bytesToBigIntLE(bytes) % L;
}

/** Signs with secret scalar `a` under an arbitrary public encoding `aPub` (RFC 8032 with a forced key). */
function signWith(
  a: bigint,
  aPub: Uint8Array,
  m: Uint8Array,
  r: bigint,
  rPoint?: Uint8Array,
): Uint8Array {
  const rBytes = rPoint ?? Point.BASE.multiply(r).toBytes();
  const k = scalar(sha512(concat(rBytes, aPub, m)));
  const s = (r + k * a) % L;
  return concat(rBytes, bigIntToBytesLE(s, 32));
}

describe('verifyStrict', () => {
  it('accepts a genuine signature and matches the reference', () => {
    expect(verifyStrict(pub, msg, sig)).toBe(true);
    expect(referenceVerifyStrict(pub, msg, sig)).toBe(true);
  });

  it('rejects wrong lengths, a wrong message and a flipped bit without throwing', () => {
    expect(verifyStrict(pub.subarray(1), msg, sig)).toBe(false);
    expect(verifyStrict(pub, msg, sig.subarray(1))).toBe(false);
    expect(verifyStrict(pub, utf8('other'), sig)).toBe(false);
    const flipped = Uint8Array.from(sig);
    flipped[5]! ^= 1;
    expect(verifyStrict(pub, msg, flipped)).toBe(false);
  });

  it('rejects s >= L (non-canonical scalar) that the cofactored check would also reject', () => {
    const s = bytesToBigIntLE(sig.subarray(32));
    const malleated = concat(sig.subarray(0, 32), bigIntToBytesLE(s + L, 32));
    expect(verifyStrict(pub, msg, malleated)).toBe(false);
    expect(referenceVerifyStrict(pub, msg, malleated)).toBe(false);
  });

  it('rejects every small-order public key, including the identity', () => {
    for (const t of torsion) {
      // With A of small order and R = [s]B, the cofactored equation holds for any s.
      const r = 12345n;
      const forged = concat(Point.BASE.multiply(r).toBytes(), bigIntToBytesLE(r, 32));
      expect(verifyStrict(t, msg, forged)).toBe(false);
      expect(referenceVerifyStrict(t, msg, forged)).toBe(false);
    }
  });

  it('rejects a small-order R', () => {
    for (const t of torsion) {
      const forged = concat(t, new Uint8Array(32));
      expect(verifyStrict(pub, msg, forged)).toBe(false);
      expect(referenceVerifyStrict(pub, msg, forged)).toBe(false);
    }
  });

  it('rejects a mixed-order public key that the cofactored check accepts (k mod 8 != 0)', () => {
    const a = 0x1234_5678_9abc_def0n;
    const mixed = Point.BASE.multiply(a).add(Point.fromBytes(order8[0]!, true)).toBytes();
    let rejected = 0;
    let accepted = 0;
    for (let i = 0; i < 32; i++) {
      const m = utf8(`mixed ${i}`);
      const r = 1000n + BigInt(i);
      const s = signWith(a, mixed, m, r);
      const k = scalar(sha512(concat(s.subarray(0, 32), mixed, m)));
      expect(cofactored(mixed, m, s)).toBe(true);
      // [s]B - [k]A' = R - [k]T, which equals R exactly when k == 0 (mod 8): dalek accepts those too.
      const strict = verifyStrict(mixed, m, s);
      expect(strict).toBe(k % 8n === 0n);
      expect(referenceVerifyStrict(mixed, m, s)).toBe(strict);
      if (strict) accepted++;
      else rejected++;
    }
    expect(rejected).toBeGreaterThan(0);
    expect(accepted + rejected).toBe(32);
  });

  it('rejects a mixed-order R that the cofactored check accepts', () => {
    const a = scalar(sha512(seed).subarray(0, 32));
    const aPub = Point.BASE.multiply(a).toBytes();
    const r = 777n;
    const mixedR = Point.BASE.multiply(r).add(Point.fromBytes(order8[1]!, true)).toBytes();
    const s = signWith(a, aPub, msg, r, mixedR);
    expect(cofactored(aPub, msg, s)).toBe(true);
    expect(verifyStrict(aPub, msg, s)).toBe(false);
    expect(referenceVerifyStrict(aPub, msg, s)).toBe(false);
  });

  it('rejects non-canonical encodings of R and A (y >= p)', () => {
    // y = p + 1 encodes the same point as y = 1 (the identity) non-canonically.
    const p = 2n ** 255n - 19n;
    const nonCanonical = bigIntToBytesLE(p + 1n, 32);
    expect(verifyStrict(nonCanonical, msg, sig)).toBe(false);
    expect(verifyStrict(pub, msg, concat(nonCanonical, sig.subarray(32)))).toBe(false);
    // x = 0 with the sign bit set.
    const negZero = bigIntToBytesLE(1n, 32);
    negZero[31]! |= 0x80;
    expect(verifyStrict(negZero, msg, sig)).toBe(false);
  });

  it('rejects an R that is not on the curve', () => {
    const onCurve = (b: Uint8Array): boolean => {
      try {
        Point.fromBytes(b, false);
        return true;
      } catch {
        return false;
      }
    };
    let y = 2n;
    while (onCurve(bigIntToBytesLE(y, 32))) y++;
    const bad = bigIntToBytesLE(y, 32);
    expect(verifyStrict(pub, msg, concat(bad, sig.subarray(32)))).toBe(false);
    expect(referenceVerifyStrict(pub, msg, concat(bad, sig.subarray(32)))).toBe(false);
  });
});
