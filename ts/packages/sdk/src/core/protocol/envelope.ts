import type { Reader } from '../encoding/codec.js';
import { Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';

/** Sealed envelope (289 B). `ciphertext` includes the 16-byte Poly1305 tag. */
export interface SealedEnvelope {
  version: number;
  market: bigint;
  epoch: bigint;
  commitment: Uint8Array;
  ephemeral: Uint8Array;
  ciphertext: Uint8Array;
}

export const ENVELOPE_LEN = 289;
export const ENVELOPE_VERSION = 1;
/** AAD length: `version || market || epoch || C`. */
export const ENVELOPE_AAD_LEN = 49;

/** Like Rust's `Decode`, the version byte is not checked here. Opening checks it. */
export function readEnvelope(r: Reader): SealedEnvelope {
  return {
    version: r.u8(),
    market: r.u64(),
    epoch: r.u64(),
    commitment: r.fixed(32),
    ephemeral: r.fixed(32),
    ciphertext: r.fixed(208),
  };
}

export function writeEnvelope(w: Writer, e: SealedEnvelope): void {
  w.u8(e.version)
    .u64(e.market)
    .u64(e.epoch)
    .fixed(e.commitment, 32)
    .fixed(e.ephemeral, 32)
    .fixed(e.ciphertext, 208);
}

export function decodeEnvelope(b: Uint8Array): SealedEnvelope {
  return decodeExact(b, readEnvelope);
}

export function encodeEnvelope(e: SealedEnvelope): Uint8Array {
  const w = new Writer();
  writeEnvelope(w, e);
  return w.finish();
}

/** `H(ENVELOPE_COMMITMENT, envelope289)`: the digest promises and v2 batch leaves bind. */
export function envelopeDigest(envelope: Uint8Array): Uint8Array {
  if (envelope.length !== ENVELOPE_LEN)
    throw new RangeError(`envelope must be ${ENVELOPE_LEN} bytes`);
  return H('ENVELOPE_COMMITMENT', envelope);
}
