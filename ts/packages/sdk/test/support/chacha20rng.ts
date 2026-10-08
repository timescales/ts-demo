import { chacha20orig } from '@noble/ciphers/chacha.js';

const MASK64 = (1n << 64n) - 1n;

/**
 * `rand_core` 0.6 `SeedableRng::seed_from_u64`: PCG32 expands a u64 into the
 * 32-byte ChaCha key, four bytes per step.
 */
export function seedFromU64(state: bigint): Uint8Array {
  const MUL = 6364136223846793005n;
  const INC = 11634580027462260723n;
  const seed = new Uint8Array(32);
  const view = new DataView(seed.buffer);
  let s = state & MASK64;
  for (let i = 0; i < 8; i++) {
    s = (s * MUL + INC) & MASK64;
    const xorshifted = Number((((s >> 18n) ^ s) >> 27n) & 0xffff_ffffn);
    const rot = Number(s >> 59n);
    const x = ((xorshifted >>> rot) | (xorshifted << ((32 - rot) & 31))) >>> 0;
    view.setUint32(4 * i, x, true);
  }
  return seed;
}

/**
 * The first `n` bytes of `rand_chacha` 0.3 `ChaCha20Rng` seeded with `key`
 * after `set_stream(stream)`: original-ChaCha layout, 64-bit block counter
 * from zero in words 12-13 and the 64-bit stream id in words 14-15.
 */
export function chacha20RngBytes(key: Uint8Array, stream: bigint, n: number): Uint8Array {
  const nonce = new Uint8Array(8);
  new DataView(nonce.buffer).setBigUint64(0, stream, true);
  return chacha20orig(key, nonce, new Uint8Array(n));
}
