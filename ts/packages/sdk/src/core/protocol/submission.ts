import type { Reader } from '../encoding/codec.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';
import { ENVELOPE_LEN } from './envelope.js';

/** Submission without a masked encoding: `envelope289 || 0x00 || trader32 || sig64`. */
export const SUBMISSION_LEN = 386;

/** `H(RELAY_SUBMISSION, envelope || trader)`. With no masked intent nothing else is hashed. */
export function submissionDigest(envelope: Uint8Array, trader: Uint8Array): Uint8Array {
  if (envelope.length !== ENVELOPE_LEN)
    throw new RangeError(`envelope must be ${ENVELOPE_LEN} bytes`);
  if (trader.length !== 32) throw new RangeError('trader must be 32 bytes');
  return H('RELAY_SUBMISSION', envelope, trader);
}

/** The 386-byte submission. `trader` is the session key that signed `submissionDigest`. */
export function encodeSubmission(
  envelope: Uint8Array,
  trader: Uint8Array,
  sig: Uint8Array,
): Uint8Array {
  return new Writer().fixed(envelope, ENVELOPE_LEN).u8(0).fixed(trader, 32).fixed(sig, 64).finish();
}

/** Decodes a submission. Masked (MPC) encodings are refused: the node has no MPC path. */
export function decodeSubmission(b: Uint8Array): {
  envelope: Uint8Array;
  trader: Uint8Array;
  signature: Uint8Array;
} {
  return decodeExact(b, (r: Reader) => {
    const envelope = r.fixed(ENVELOPE_LEN);
    if (r.bool()) throw new DecodeError('value', 'masked submissions are not supported');
    return { envelope, trader: r.fixed(32), signature: r.fixed(64) };
  });
}
