import { Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';

/**
 * Relay-signed refusal (177 B): portable evidence that intake
 * refused an envelope (batch full, intake paused, quota, epoch closed).
 */
export interface RelayRefusal {
  market: Uint8Array;
  epoch: bigint;
  envelopeDigest: Uint8Array;
  code: number;
  atMs: bigint;
  relay: Uint8Array;
  signature: Uint8Array;
}

export const RELAY_REFUSAL_LEN = 177;

export function decodeRelayRefusal(b: Uint8Array): RelayRefusal {
  return decodeExact(b, (r) => ({
    market: r.fixed(32),
    epoch: r.u64(),
    envelopeDigest: r.fixed(32),
    code: r.u8(),
    atMs: r.u64(),
    relay: r.fixed(32),
    signature: r.fixed(64),
  }));
}

export function encodeRelayRefusal(x: RelayRefusal): Uint8Array {
  return new Writer()
    .fixed(x.market, 32)
    .u64(x.epoch)
    .fixed(x.envelopeDigest, 32)
    .u8(x.code)
    .u64(x.atMs)
    .fixed(x.relay, 32)
    .fixed(x.signature, 64)
    .finish();
}

/** `H(RELAY_REFUSAL, bytes before the signature)`, which `relay` signs. */
export function relayRefusalDigest(x: RelayRefusal): Uint8Array {
  return H('RELAY_REFUSAL', encodeRelayRefusal(x).subarray(0, RELAY_REFUSAL_LEN - 64));
}
