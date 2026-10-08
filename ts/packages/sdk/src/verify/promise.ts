import type { Address } from '@solana/kit';
import { b58 } from '../core/encoding/base58.js';
import { equal } from '../core/encoding/bytes.js';
import { verifyStrict } from '../core/crypto/verifyStrict.js';
import { envelopeDigest } from '../core/protocol/envelope.js';
import { decodePromiseV2, promiseV2Digest, type PromiseV2 } from '../core/protocol/promise.js';
import {
  decodeRelayRefusal,
  relayRefusalDigest,
  type RelayRefusal,
} from '../core/protocol/refusal.js';
import { check, must, type Verdict } from './verdict.js';

/**
 * V-5 against an envelope digest rather than envelope bytes, for a promise
 * the relay returns for bytes another tab or device submitted
 * (`DUPLICATE_COMMITMENT`).
 */
export function verifyPromiseDigest(
  raw: Uint8Array,
  expect: {
    market: Address;
    epoch: bigint;
    commitment: Uint8Array;
    envelopeDigest: Uint8Array | null;
    relay: Address;
  },
): Verdict<PromiseV2> {
  return check('V-5 promise', () => {
    const p = decodePromiseV2(raw);
    const relay = b58.decode(expect.relay, 32);
    must(equal(p.market, b58.decode(expect.market, 32)), 'the promise is for another market');
    must(p.epoch === expect.epoch, 'the promise is for another epoch');
    must(equal(p.commitment, expect.commitment), 'the promise is for another commitment');
    must(
      expect.envelopeDigest === null || equal(p.envelopeDigest, expect.envelopeDigest),
      'the promise is for another envelope',
    );
    must(equal(p.relay, relay), 'the promise names another relay');
    must(
      verifyStrict(relay, promiseV2Digest(p), p.signature),
      'the promise is not signed by the relay in force at submission',
    );
    return p;
  });
}

/**
 * V-5: the 201-byte promise v2 decodes exactly and is signed by the relay
 * the client read from `Market.relay` when it submitted (a later `SetRelay`
 * does not invalidate it), for this market, epoch, commitment and the digest
 * of the exact envelope submitted.
 */
export function verifyPromise(
  raw: Uint8Array,
  expect: {
    market: Address;
    epoch: bigint;
    commitment: Uint8Array;
    envelope: Uint8Array;
    relay: Address;
  },
): Verdict<PromiseV2> {
  let digest: Uint8Array;
  try {
    digest = envelopeDigest(expect.envelope);
  } catch (e) {
    return { kind: 'fail', reason: `V-5 promise: ${(e as Error).message}` };
  }
  return verifyPromiseDigest(raw, { ...expect, envelopeDigest: digest });
}

/**
 * A relay-signed refusal for this market, epoch and envelope,
 * signed by the relay in force at submission. Kept as evidence that intake
 * refused an otherwise valid envelope.
 */
export function verifyRefusal(
  raw: Uint8Array,
  expect: { market: Address; epoch: bigint; envelopeDigest: Uint8Array; relay: Address },
): Verdict<RelayRefusal> {
  return check('relay refusal', () => {
    const r = decodeRelayRefusal(raw);
    const relay = b58.decode(expect.relay, 32);
    must(equal(r.market, b58.decode(expect.market, 32)), 'the refusal is for another market');
    must(r.epoch === expect.epoch, 'the refusal is for another epoch');
    must(equal(r.envelopeDigest, expect.envelopeDigest), 'the refusal is for another envelope');
    must(equal(r.relay, relay), 'the refusal names another relay');
    must(
      verifyStrict(relay, relayRefusalDigest(r), r.signature),
      'the refusal is not signed by the relay',
    );
    return r;
  });
}
