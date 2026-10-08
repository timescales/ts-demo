import { I64_MAX, I64_MIN, U64_MAX } from './bytes.js';

export type DecodeErrorKind = 'eof' | 'tag' | 'length' | 'trailing' | 'value' | 'version';

/** A canonical decode failed. `kind` matches the node's `DECODE_FAILED` reasons. */
export class DecodeError extends Error {
  readonly kind: DecodeErrorKind;

  constructor(kind: DecodeErrorKind, message?: string) {
    super(message === undefined ? `decode failed: ${kind}` : `decode failed: ${kind}: ${message}`);
    this.name = 'DecodeError';
    this.kind = kind;
  }
}

function checkUint(v: number, bits: number, what: string): void {
  if (!Number.isInteger(v) || v < 0 || v >= 2 ** bits) {
    throw new RangeError(`${what} out of range: ${v}`);
  }
}

/** Canonical little-endian encoder. Every value is range-checked before it is written. */
export class Writer {
  private buf = new Uint8Array(64);
  private len = 0;

  private reserve(n: number): DataView {
    if (this.len + n > this.buf.length) {
      let cap = this.buf.length * 2;
      while (cap < this.len + n) cap *= 2;
      const next = new Uint8Array(cap);
      next.set(this.buf.subarray(0, this.len));
      this.buf = next;
    }
    return new DataView(this.buf.buffer, this.len, n);
  }

  u8(v: number): this {
    checkUint(v, 8, 'u8');
    this.reserve(1).setUint8(0, v);
    this.len += 1;
    return this;
  }

  u16(v: number): this {
    checkUint(v, 16, 'u16');
    this.reserve(2).setUint16(0, v, true);
    this.len += 2;
    return this;
  }

  u32(v: number): this {
    checkUint(v, 32, 'u32');
    this.reserve(4).setUint32(0, v, true);
    this.len += 4;
    return this;
  }

  u64(v: bigint): this {
    if (typeof v !== 'bigint' || v < 0n || v > U64_MAX)
      throw new RangeError(`u64 out of range: ${v}`);
    this.reserve(8).setBigUint64(0, v, true);
    this.len += 8;
    return this;
  }

  i64(v: bigint): this {
    if (typeof v !== 'bigint' || v < I64_MIN || v > I64_MAX) {
      throw new RangeError(`i64 out of range: ${v}`);
    }
    this.reserve(8).setBigInt64(0, v, true);
    this.len += 8;
    return this;
  }

  bool(v: boolean): this {
    return this.u8(v ? 1 : 0);
  }

  /** Exactly `n` bytes, no length prefix. */
  fixed(b: Uint8Array, n: number): this {
    if (b.length !== n) throw new RangeError(`expected ${n} bytes, got ${b.length}`);
    this.reserve(n);
    this.buf.set(b, this.len);
    this.len += n;
    return this;
  }

  /** `u32` length prefix, then the bytes. At most `max` bytes. */
  bytes(b: Uint8Array, max: number): this {
    if (b.length > max) throw new RangeError(`byte string longer than ${max}`);
    this.u32(b.length);
    this.reserve(b.length);
    this.buf.set(b, this.len);
    this.len += b.length;
    return this;
  }

  /** `u32` count prefix, then each element. At most `max` elements. */
  seq<T>(xs: readonly T[], max: number, f: (w: Writer, x: T) => void): this {
    if (xs.length > max) throw new RangeError(`sequence longer than ${max}`);
    this.u32(xs.length);
    for (const x of xs) f(this, x);
    return this;
  }

  finish(): Uint8Array {
    return this.buf.slice(0, this.len);
  }
}

/**
 * Canonical decoder. Lengths are checked against their bound before anything
 * is allocated, and `bool` and enum tags are strict.
 */
export class Reader {
  private readonly b: Uint8Array;
  private readonly view: DataView;
  private at = 0;

  constructor(b: Uint8Array) {
    this.b = b;
    this.view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }

  private take(n: number): number {
    if (n > this.b.length - this.at) {
      throw new DecodeError('eof', `need ${n} bytes, ${this.b.length - this.at} left`);
    }
    const start = this.at;
    this.at += n;
    return start;
  }

  u8(): number {
    return this.view.getUint8(this.take(1));
  }

  u16(): number {
    return this.view.getUint16(this.take(2), true);
  }

  u32(): number {
    return this.view.getUint32(this.take(4), true);
  }

  u64(): bigint {
    return this.view.getBigUint64(this.take(8), true);
  }

  i64(): bigint {
    return this.view.getBigInt64(this.take(8), true);
  }

  bool(): boolean {
    const v = this.u8();
    if (v > 1) throw new DecodeError('tag', `bool ${v}`);
    return v === 1;
  }

  fixed(n: number): Uint8Array {
    const start = this.take(n);
    return this.b.slice(start, start + n);
  }

  bytes(max: number): Uint8Array {
    const n = this.u32();
    if (n > max) throw new DecodeError('length', `byte string of ${n} exceeds ${max}`);
    return this.fixed(n);
  }

  /**
   * `u32` count, then elements. Capacity is reserved for at most
   * `remaining / minLen` elements, so a hostile count cannot reserve more
   * memory than the input could describe.
   */
  seq<T>(max: number, f: (r: Reader) => T, minLen = 1): T[] {
    if (!Number.isInteger(minLen) || minLen < 1) throw new RangeError('minLen must be >= 1');
    const n = this.u32();
    if (n > max) throw new DecodeError('length', `sequence of ${n} exceeds ${max}`);
    const out = new Array<T>(Math.min(n, Math.floor(this.remaining() / minLen)));
    for (let i = 0; i < n; i++) {
      const v = f(this);
      if (i < out.length) out[i] = v;
      else out.push(v);
    }
    return out;
  }

  remaining(): number {
    return this.b.length - this.at;
  }

  finish(): void {
    const left = this.remaining();
    if (left !== 0) throw new DecodeError('trailing', `${left} trailing bytes`);
  }
}

/** Decodes `b` with `f` and rejects trailing bytes. */
export function decodeExact<T>(b: Uint8Array, f: (r: Reader) => T): T {
  const r = new Reader(b);
  const v = f(r);
  r.finish();
  return v;
}
