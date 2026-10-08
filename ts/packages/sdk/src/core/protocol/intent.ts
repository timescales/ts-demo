import type { Reader } from '../encoding/codec.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';
import { utf8 } from '../encoding/bytes.js';
import { hex } from '../encoding/hex.js';
import {
  readCancel,
  readOrder,
  writeCancel,
  writeOrder,
  type Cancel,
  type Order,
} from './order.js';

export type IntentBody =
  { kind: 'noop' } | { kind: 'place'; order: Order } | { kind: 'cancel'; cancel: Cancel };

/** `IntentBody || salt32 || signature64`. A noop carries a zero signature. */
export interface PrivateIntent {
  body: IntentBody;
  salt: Uint8Array;
  signature: Uint8Array;
}

/** Envelope plaintext size. Every intent is zero-padded to it. */
export const PLAINTEXT_LEN = 192;

export function readIntentBody(r: Reader): IntentBody {
  const tag = r.u8();
  switch (tag) {
    case 0:
      return { kind: 'noop' };
    case 1:
      return { kind: 'place', order: readOrder(r) };
    case 2:
      return { kind: 'cancel', cancel: readCancel(r) };
    default:
      throw new DecodeError('tag', `IntentBody ${tag}`);
  }
}

export function writeIntentBody(w: Writer, b: IntentBody): void {
  switch (b.kind) {
    case 'noop':
      w.u8(0);
      return;
    case 'place':
      w.u8(1);
      writeOrder(w, b.order);
      return;
    case 'cancel':
      w.u8(2);
      writeCancel(w, b.cancel);
      return;
  }
}

export function encodeIntentBody(b: IntentBody): Uint8Array {
  const w = new Writer();
  writeIntentBody(w, b);
  return w.finish();
}

export function readPrivateIntent(r: Reader): PrivateIntent {
  return { body: readIntentBody(r), salt: r.fixed(32), signature: r.fixed(64) };
}

export function encodePrivateIntent(i: PrivateIntent): Uint8Array {
  const w = new Writer();
  writeIntentBody(w, i.body);
  w.fixed(i.salt, 32).fixed(i.signature, 64);
  return w.finish();
}

export function decodePrivateIntent(b: Uint8Array): PrivateIntent {
  return decodeExact(b, readPrivateIntent);
}

/** The trader named in a body, or null for a noop. */
export function intentTrader(b: IntentBody): Uint8Array | null {
  if (b.kind === 'place') return b.order.trader;
  if (b.kind === 'cancel') return b.cancel.trader;
  return null;
}

/** `H(INTENT_SIGNATURE, C)`, shown to the user as the order's short code. */
export function intentDigest(c: Uint8Array): Uint8Array {
  if (c.length !== 32) throw new RangeError('commitment must be 32 bytes');
  return H('INTENT_SIGNATURE', c);
}

/**
 * The UTF-8 text the wallet signs for an intent: the digest as a short code.
 * Wallets refuse to sign raw bytes that could be a transaction.
 */
export function intentMessage(c: Uint8Array): Uint8Array {
  return utf8(
    `Timescales order\nCode: ${hex.encode(intentDigest(c))}\nSign this only on the Timescales app.`,
  );
}
