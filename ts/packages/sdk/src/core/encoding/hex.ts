import { DecodeError } from './codec.js';

const ALPHABET = '0123456789abcdef';

function nibble(c: number): number {
  if (c >= 48 && c <= 57) return c - 48;
  if (c >= 97 && c <= 102) return c - 87;
  if (c >= 65 && c <= 70) return c - 55;
  return -1;
}

/** Lowercase hex without a prefix. Decode accepts either case and checks `len` when given. */
export const hex: { encode(b: Uint8Array): string; decode(s: string, len?: number): Uint8Array } = {
  encode(b: Uint8Array): string {
    let s = '';
    for (const x of b) s += ALPHABET[x >> 4]! + ALPHABET[x & 15]!;
    return s;
  },
  decode(s: string, len?: number): Uint8Array {
    if (s.length % 2 !== 0) throw new DecodeError('value', 'odd-length hex');
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
      const hi = nibble(s.charCodeAt(2 * i));
      const lo = nibble(s.charCodeAt(2 * i + 1));
      if (hi < 0 || lo < 0) throw new DecodeError('value', 'invalid hex digit');
      out[i] = (hi << 4) | lo;
    }
    if (len !== undefined && out.length !== len) {
      throw new DecodeError('length', `expected ${len} bytes, got ${out.length}`);
    }
    return out;
  },
};
