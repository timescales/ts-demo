import { H } from '../crypto/hash.js';
import { encodeBand, type PriceBand } from './band.js';

/** `H(EPOCH_BINDING, price_commitment || key digest || committee digest)`: header v2 bytes `[87..119]`. */
export function epochBinding(
  priceCommitment: Uint8Array,
  keyDigest: Uint8Array,
  committeeDigest: Uint8Array,
): Uint8Array {
  for (const x of [priceCommitment, keyDigest, committeeDigest]) {
    if (x.length !== 32) throw new RangeError('binding inputs must be 32 bytes');
  }
  return H('EPOCH_BINDING', priceCommitment, keyDigest, committeeDigest);
}

/** `H(EPOCH_TERMS, band24 || binding)`, equal to the program's check over header bytes `[63..119]`. */
export function termsDigest(band: PriceBand, binding: Uint8Array): Uint8Array {
  if (binding.length !== 32) throw new RangeError('binding must be 32 bytes');
  return H('EPOCH_TERMS', encodeBand(band), binding);
}
