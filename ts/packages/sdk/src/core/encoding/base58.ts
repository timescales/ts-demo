import { DecodeError } from './codec.js';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;

/** Bitcoin-alphabet base58, as used for Solana addresses and signatures. */
export const b58: { encode(b: Uint8Array): string; decode(s: string, len?: number): Uint8Array } = {
  encode(b: Uint8Array): string {
    let zeros = 0;
    while (zeros < b.length && b[zeros] === 0) zeros++;
    const digits: number[] = [];
    for (let i = zeros; i < b.length; i++) {
      let carry = b[i]!;
      for (let j = 0; j < digits.length; j++) {
        carry += digits[j]! << 8;
        digits[j] = carry % 58;
        carry = Math.floor(carry / 58);
      }
      while (carry > 0) {
        digits.push(carry % 58);
        carry = Math.floor(carry / 58);
      }
    }
    let s = '1'.repeat(zeros);
    for (let i = digits.length - 1; i >= 0; i--) s += ALPHABET[digits[i]!]!;
    return s;
  },
  decode(s: string, len?: number): Uint8Array {
    let zeros = 0;
    while (zeros < s.length && s[zeros] === '1') zeros++;
    const bytes: number[] = [];
    for (let i = zeros; i < s.length; i++) {
      const c = s.charCodeAt(i);
      let carry = c < 128 ? LOOKUP[c]! : -1;
      if (carry < 0) throw new DecodeError('value', 'invalid base58 character');
      for (let j = 0; j < bytes.length; j++) {
        carry += bytes[j]! * 58;
        bytes[j] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) {
        bytes.push(carry & 0xff);
        carry >>= 8;
      }
    }
    const out = new Uint8Array(zeros + bytes.length);
    for (let i = 0; i < bytes.length; i++) out[out.length - 1 - i] = bytes[i]!;
    if (len !== undefined && out.length !== len) {
      throw new DecodeError('length', `expected ${len} bytes, got ${out.length}`);
    }
    return out;
  },
};
