import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concat, equal, isZero, u64le, utf8 } from '../encoding/bytes.js';
import { DecodeError, Reader } from '../encoding/codec.js';
import { commitment as commitmentOf } from '../protocol/commitment.js';
import {
  ENVELOPE_AAD_LEN,
  ENVELOPE_LEN,
  ENVELOPE_VERSION,
  decodeEnvelope,
} from '../protocol/envelope.js';
import {
  PLAINTEXT_LEN,
  encodePrivateIntent,
  intentMessage,
  intentTrader,
  readPrivateIntent,
  type PrivateIntent,
} from '../protocol/intent.js';
import { randomBytes } from './random.js';
import { DOMAIN } from './tags.js';
import { verifyStrict } from './verifyStrict.js';
import { x25519PublicKey, x25519Shared } from './x25519.js';

const ZERO_NONCE = new Uint8Array(12);

/** HKDF info: `"timescales/v1/seal" || "envelope" || market || epoch` (raw, no length byte). */
function sealInfo(market: bigint, epoch: bigint): Uint8Array {
  return concat(utf8(DOMAIN.SEAL_KDF), utf8('envelope'), u64le(market), u64le(epoch));
}

function aadFor(market: bigint, epoch: bigint, c: Uint8Array): Uint8Array {
  return concat(Uint8Array.of(ENVELOPE_VERSION), u64le(market), u64le(epoch), c);
}

/**
 * Seals an intent to an epoch key. Every call draws a fresh
 * ephemeral X25519 key, including re-seals of the same intent, because the
 * AEAD nonce is fixed at zero. `ephemeralSecret` exists for vectors only.
 * The commitment must match the intent's body and salt.
 */
export function sealEnvelope(a: {
  epochPk: Uint8Array;
  market: bigint;
  epoch: bigint;
  commitment: Uint8Array;
  intent: PrivateIntent;
  ephemeralSecret?: Uint8Array;
}): Uint8Array {
  if (a.epochPk.length !== 32) throw new RangeError('epoch key must be 32 bytes');
  if (!equal(commitmentOf(a.intent.body, a.intent.salt), a.commitment)) {
    throw new Error('commitment does not match the intent');
  }
  const plain = encodePrivateIntent(a.intent);
  if (plain.length > PLAINTEXT_LEN) throw new RangeError('intent does not fit the envelope');
  const pt = new Uint8Array(PLAINTEXT_LEN);
  pt.set(plain);
  const eph = a.ephemeralSecret ?? randomBytes(32);
  if (eph.length !== 32) throw new RangeError('ephemeral secret must be 32 bytes');
  const ephPk = x25519PublicKey(eph);
  const shared = x25519Shared(eph, a.epochPk);
  const key = hkdf(sha256, shared, concat(ephPk, a.epochPk), sealInfo(a.market, a.epoch), 32);
  const aad = aadFor(a.market, a.epoch, a.commitment);
  const ct = chacha20poly1305(key, ZERO_NONCE, aad).encrypt(pt);
  const out = concat(aad, ephPk, ct);
  if (out.length !== ENVELOPE_LEN) throw new Error('envelope length');
  return out;
}

/**
 * Opens an envelope with an X25519 epoch secret and runs the executor's
 * checks in order: version, contributory exchange, AEAD,
 * strict intent decode, zero padding, commitment, intent signature. For
 * tests and local tooling. Traders never hold an epoch secret.
 */
export function openEnvelope(secret: Uint8Array, envelope: Uint8Array): PrivateIntent {
  const e = decodeEnvelope(envelope);
  if (e.version !== ENVELOPE_VERSION)
    throw new DecodeError('version', `envelope version ${e.version}`);
  const shared = x25519Shared(secret, e.ephemeral);
  const recipient = x25519PublicKey(secret);
  const key = hkdf(sha256, shared, concat(e.ephemeral, recipient), sealInfo(e.market, e.epoch), 32);
  const pt = chacha20poly1305(key, ZERO_NONCE, envelope.subarray(0, ENVELOPE_AAD_LEN)).decrypt(
    e.ciphertext,
  );
  const r = new Reader(pt);
  const intent = readPrivateIntent(r);
  if (!isZero(pt.subarray(PLAINTEXT_LEN - r.remaining())))
    throw new DecodeError('value', 'non-zero padding');
  if (!equal(commitmentOf(intent.body, intent.salt), e.commitment))
    throw new Error('commitment mismatch');
  const trader = intentTrader(intent.body);
  if (trader !== null && !verifyStrict(trader, intentMessage(e.commitment), intent.signature)) {
    throw new Error('bad intent signature');
  }
  return intent;
}
