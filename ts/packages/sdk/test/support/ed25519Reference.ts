import { sha512 } from '@noble/hashes/sha2.js';

/**
 * Pure-BigInt Ed25519 (RFC 8032 arithmetic, independent of noble's point
 * code) with ed25519-dalek's `verify_strict` rules, used to cross-check
 * `verifyStrict` on random inputs.
 */
const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

function mod(a: bigint, m = P): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function pow(b: bigint, e: bigint): bigint {
  let r = 1n;
  b = mod(b);
  while (e > 0n) {
    if (e & 1n) r = mod(r * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return r;
}

function inv(a: bigint): bigint {
  return pow(a, P - 2n);
}

type Pt = [bigint, bigint, bigint, bigint];
const ZERO: Pt = [0n, 1n, 1n, 0n];

function add(p: Pt, q: Pt): Pt {
  const [x1, y1, z1, t1] = p;
  const [x2, y2, z2, t2] = q;
  const a = mod((y1 - x1) * (y2 - x2));
  const b = mod((y1 + x1) * (y2 + x2));
  const c = mod(2n * D * t1 * t2);
  const d = mod(2n * z1 * z2);
  const e = b - a;
  const f = d - c;
  const g = d + c;
  const h = b + a;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

function mul(s: bigint, p: Pt): Pt {
  let r = ZERO;
  let q = p;
  while (s > 0n) {
    if (s & 1n) r = add(r, q);
    q = add(q, q);
    s >>= 1n;
  }
  return r;
}

function neg([x, y, z, t]: Pt): Pt {
  return [mod(-x), y, z, mod(-t)];
}

function isZero([x, y, z]: Pt): boolean {
  return x === 0n && mod(y - z) === 0n;
}

function encode([x, y, z]: Pt): Uint8Array {
  const zi = inv(z);
  const ax = mod(x * zi);
  const ay = mod(y * zi);
  const out = new Uint8Array(32);
  let v = ay;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (ax & 1n) out[31]! |= 0x80;
  return out;
}

function le(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
  return v;
}

/** RFC 8032 section 5.1.3 decoding, canonical only (y < p, x = 0 with the sign bit set is rejected). */
function decode(b: Uint8Array): Pt | null {
  const sign = (b[31]! & 0x80) !== 0;
  const yb = Uint8Array.from(b);
  yb[31]! &= 0x7f;
  const y = le(yb);
  if (y >= P) return null;
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  if (vx2 === u) {
    // root found
  } else if (vx2 === mod(-u)) {
    x = mod(x * SQRT_M1);
  } else {
    return null;
  }
  if (x === 0n && sign) return null;
  if ((x & 1n) !== (sign ? 1n : 0n)) x = mod(-x);
  return [x, y, 1n, mod(x * y)];
}

const GY = mod(4n * inv(5n));
const BASE = decode(
  (() => {
    const out = new Uint8Array(32);
    let v = GY;
    for (let i = 0; i < 32; i++) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  })(),
)!;

export function referenceVerifyStrict(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (pub.length !== 32 || sig.length !== 64) return false;
  const rBytes = sig.subarray(0, 32);
  const s = le(sig.subarray(32));
  if (s >= L) return false;
  const A = decode(pub);
  const R = decode(rBytes);
  if (A === null || R === null) return false;
  if (isZero(mul(8n, A)) || isZero(mul(8n, R))) return false;
  const k = mod(le(sha512(new Uint8Array([...rBytes, ...pub, ...msg]))), L);
  const rp = add(mul(s, BASE), neg(mul(k, A)));
  const enc = encode(rp);
  return enc.every((x, i) => x === rBytes[i]);
}
