const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

export function utf8(s: string): Uint8Array {
  return utf8Encoder.encode(s);
}

/** Strict UTF-8 decode: invalid sequences throw instead of becoming U+FFFD. */
export function fromUtf8(b: Uint8Array): string {
  return utf8Decoder.decode(b);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** Lexicographic byte order, as Rust's `Ord` for byte arrays. */
export function compare(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a[i]! - b[i]!;
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

export function isZero(b: Uint8Array): boolean {
  let d = 0;
  for (const x of b) d |= x;
  return d === 0;
}

export const U64_MAX = (1n << 64n) - 1n;
export const I64_MAX = (1n << 63n) - 1n;
export const I64_MIN = -(1n << 63n);

export function u64le(v: bigint): Uint8Array {
  if (v < 0n || v > U64_MAX) throw new RangeError(`u64 out of range: ${v}`);
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v, true);
  return b;
}

export function u32le(v: number): Uint8Array {
  if (!Number.isInteger(v) || v < 0 || v > 0xffff_ffff)
    throw new RangeError(`u32 out of range: ${v}`);
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v, true);
  return b;
}

export function readU64le(b: Uint8Array, at = 0): bigint {
  if (b.length < at + 8) throw new RangeError('short input');
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(at, true);
}

/** Little-endian unsigned integer of any width. */
export function bytesToBigIntLE(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
  return v;
}

export function bigIntToBytesLE(v: bigint, len: number): Uint8Array {
  if (v < 0n || v >= 1n << BigInt(8 * len)) throw new RangeError('value does not fit');
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
