import { utf8, u64le } from '../encoding/bytes.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';

/** Relay inclusion promise v2 (201 B). `market` is the market account address. */
export interface PromiseV2 {
  market: Uint8Array;
  epoch: bigint;
  commitment: Uint8Array;
  envelopeDigest: Uint8Array;
  relay: Uint8Array;
  signature: Uint8Array;
}

/** Legacy v1 promise (144 B), used by tests and vectors. */
export interface PromiseV1 {
  market: bigint;
  epoch: bigint;
  commitment: Uint8Array;
  relay: Uint8Array;
  signature: Uint8Array;
}

export const PROMISE_V2_LEN = 201;
export const PROMISE_V1_LEN = 144;

export function decodePromiseV2(b: Uint8Array): PromiseV2 {
  return decodeExact(b, (r) => {
    const version = r.u8();
    if (version !== 2) throw new DecodeError('version', `promise version ${version}`);
    return {
      market: r.fixed(32),
      epoch: r.u64(),
      commitment: r.fixed(32),
      envelopeDigest: r.fixed(32),
      relay: r.fixed(32),
      signature: r.fixed(64),
    };
  });
}

export function encodePromiseV2(p: PromiseV2): Uint8Array {
  return new Writer()
    .u8(2)
    .fixed(p.market, 32)
    .u64(p.epoch)
    .fixed(p.commitment, 32)
    .fixed(p.envelopeDigest, 32)
    .fixed(p.relay, 32)
    .fixed(p.signature, 64)
    .finish();
}

/** `H(RELAY_SUBMISSION, "promise/v2" || market32 || epoch || C || d)`. */
export function promiseV2Digest(p: PromiseV2): Uint8Array {
  if (p.market.length !== 32 || p.commitment.length !== 32 || p.envelopeDigest.length !== 32) {
    throw new RangeError('promise fields must be 32 bytes');
  }
  return H(
    'RELAY_SUBMISSION',
    utf8('promise/v2'),
    p.market,
    u64le(p.epoch),
    p.commitment,
    p.envelopeDigest,
  );
}

export function decodePromiseV1(b: Uint8Array): PromiseV1 {
  return decodeExact(b, (r) => ({
    market: r.u64(),
    epoch: r.u64(),
    commitment: r.fixed(32),
    relay: r.fixed(32),
    signature: r.fixed(64),
  }));
}

export function encodePromiseV1(p: PromiseV1): Uint8Array {
  return new Writer()
    .u64(p.market)
    .u64(p.epoch)
    .fixed(p.commitment, 32)
    .fixed(p.relay, 32)
    .fixed(p.signature, 64)
    .finish();
}

/** `H(RELAY_SUBMISSION, "promise" || market8 || epoch8 || C)`. */
export function promiseV1Digest(p: Pick<PromiseV1, 'market' | 'epoch' | 'commitment'>): Uint8Array {
  return H('RELAY_SUBMISSION', utf8('promise'), u64le(p.market), u64le(p.epoch), p.commitment);
}
