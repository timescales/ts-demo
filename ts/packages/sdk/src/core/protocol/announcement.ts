import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';
import { readBand, writeBand, type PriceBand } from './band.js';

/** Relay-signed epoch announcement (273 B). */
export interface EpochAnnouncement {
  market: Uint8Array;
  epoch: bigint;
  opensAtMs: bigint;
  cutoffMs: bigint;
  band: PriceBand;
  priceCommitment: Uint8Array;
  keyDigest: Uint8Array;
  committeeDigest: Uint8Array;
  relay: Uint8Array;
  signature: Uint8Array;
}

export const EPOCH_ANNOUNCEMENT_VERSION = 1;
export const EPOCH_ANNOUNCEMENT_LEN = 273;

export function decodeAnnouncement(b: Uint8Array): EpochAnnouncement {
  return decodeExact(b, (r) => {
    const version = r.u8();
    if (version !== EPOCH_ANNOUNCEMENT_VERSION)
      throw new DecodeError('version', `announcement version ${version}`);
    return {
      market: r.fixed(32),
      epoch: r.u64(),
      opensAtMs: r.u64(),
      cutoffMs: r.u64(),
      band: readBand(r),
      priceCommitment: r.fixed(32),
      keyDigest: r.fixed(32),
      committeeDigest: r.fixed(32),
      relay: r.fixed(32),
      signature: r.fixed(64),
    };
  });
}

export function encodeAnnouncement(a: EpochAnnouncement): Uint8Array {
  const w = new Writer()
    .u8(EPOCH_ANNOUNCEMENT_VERSION)
    .fixed(a.market, 32)
    .u64(a.epoch)
    .u64(a.opensAtMs)
    .u64(a.cutoffMs);
  writeBand(w, a.band);
  return w
    .fixed(a.priceCommitment, 32)
    .fixed(a.keyDigest, 32)
    .fixed(a.committeeDigest, 32)
    .fixed(a.relay, 32)
    .fixed(a.signature, 64)
    .finish();
}

/** `H(EPOCH_ANNOUNCEMENT, bytes before the signature)`, which the relay signs (V-4). */
export function epochAnnouncementDigest(a: EpochAnnouncement): Uint8Array {
  return H('EPOCH_ANNOUNCEMENT', encodeAnnouncement(a).subarray(0, EPOCH_ANNOUNCEMENT_LEN - 64));
}
