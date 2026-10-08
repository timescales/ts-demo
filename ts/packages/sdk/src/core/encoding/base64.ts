import { DecodeError } from './codec.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;

/**
 * Standard base64 (RFC 4648 section 4) with padding. Decoding is canonical: padding
 * is required, unused bits must be zero and no whitespace is accepted.
 */
export const b64: { encode(b: Uint8Array): string; decode(s: string, len?: number): Uint8Array } = {
  encode(b: Uint8Array): string {
    let s = '';
    let i = 0;
    for (; i + 2 < b.length; i += 3) {
      const v = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
      s +=
        ALPHABET[v >> 18]! +
        ALPHABET[(v >> 12) & 63]! +
        ALPHABET[(v >> 6) & 63]! +
        ALPHABET[v & 63]!;
    }
    const rest = b.length - i;
    if (rest === 1) {
      const v = b[i]! << 16;
      s += ALPHABET[v >> 18]! + ALPHABET[(v >> 12) & 63]! + '==';
    } else if (rest === 2) {
      const v = (b[i]! << 16) | (b[i + 1]! << 8);
      s += ALPHABET[v >> 18]! + ALPHABET[(v >> 12) & 63]! + ALPHABET[(v >> 6) & 63]! + '=';
    }
    return s;
  },
  decode(s: string, len?: number): Uint8Array {
    if (s.length % 4 !== 0) throw new DecodeError('value', 'base64 length not a multiple of 4');
    const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
    const out = new Uint8Array((s.length / 4) * 3 - pad);
    const sextet = (i: number): number => {
      const c = s.charCodeAt(i);
      const v = c < 128 ? LOOKUP[c]! : -1;
      if (v < 0) throw new DecodeError('value', 'invalid base64 character');
      return v;
    };
    let o = 0;
    for (let i = 0; i < s.length; i += 4) {
      const last = i + 4 === s.length;
      const a = sextet(i);
      const b = sextet(i + 1);
      if (last && pad === 2) {
        if ((b & 15) !== 0) throw new DecodeError('value', 'non-canonical base64');
        out[o] = (a << 2) | (b >> 4);
        break;
      }
      const c = sextet(i + 2);
      if (last && pad === 1) {
        if ((c & 3) !== 0) throw new DecodeError('value', 'non-canonical base64');
        out[o] = (a << 2) | (b >> 4);
        out[o + 1] = ((b & 15) << 4) | (c >> 2);
        break;
      }
      const d = sextet(i + 3);
      out[o++] = (a << 2) | (b >> 4);
      out[o++] = ((b & 15) << 4) | (c >> 2);
      out[o++] = ((c & 3) << 6) | d;
    }
    if (len !== undefined && out.length !== len) {
      throw new DecodeError('length', `expected ${len} bytes, got ${out.length}`);
    }
    return out;
  },
};
