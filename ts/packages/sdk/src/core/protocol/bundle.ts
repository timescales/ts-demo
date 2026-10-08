import type { Reader } from '../encoding/codec.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';
import { MAX_COMMITTEE } from './committee.js';

/**
 * Epoch-key announcement: `ver u8 || market32 || epoch u64 ||
 * committee_digest32 || scheme u8 || epoch_pk32 || seq<[32]>` with `t` Feldman
 * commitments, or none for the simulation-only dev scheme.
 */
export interface EpochKeyAnnouncement {
  version: number;
  market: Uint8Array;
  epoch: bigint;
  committeeDigest: Uint8Array;
  scheme: 'dev' | 'feldman';
  epochPk: Uint8Array;
  commitments: Uint8Array[];
}

/** The announcement and the members' acks (strictly increasing member index). */
export interface EpochKeyBundle {
  announcement: EpochKeyAnnouncement;
  acks: { member: number; policyDigest: Uint8Array; signature: Uint8Array }[];
}

export const ANNOUNCEMENT_VERSION = 1;
const SCHEMES = ['dev', 'feldman'] as const;

export function readKeyAnnouncement(r: Reader): EpochKeyAnnouncement {
  const version = r.u8();
  if (version !== ANNOUNCEMENT_VERSION)
    throw new DecodeError('version', `announcement version ${version}`);
  const market = r.fixed(32);
  const epoch = r.u64();
  const committeeDigest = r.fixed(32);
  const tag = r.u8();
  const scheme = SCHEMES[tag];
  if (scheme === undefined) throw new DecodeError('tag', `KeyScheme ${tag}`);
  const epochPk = r.fixed(32);
  const commitments = r.seq(MAX_COMMITTEE, (x) => x.fixed(32), 32);
  return { version, market, epoch, committeeDigest, scheme, epochPk, commitments };
}

export function writeKeyAnnouncement(w: Writer, a: EpochKeyAnnouncement): void {
  w.u8(a.version)
    .fixed(a.market, 32)
    .u64(a.epoch)
    .fixed(a.committeeDigest, 32)
    .u8(SCHEMES.indexOf(a.scheme))
    .fixed(a.epochPk, 32)
    .seq(a.commitments, MAX_COMMITTEE, (x, c) => x.fixed(c, 32));
}

export function decodeKeyAnnouncement(b: Uint8Array): EpochKeyAnnouncement {
  return decodeExact(b, readKeyAnnouncement);
}

export function encodeKeyAnnouncement(a: EpochKeyAnnouncement): Uint8Array {
  const w = new Writer();
  writeKeyAnnouncement(w, a);
  return w.finish();
}

/** `H(EPOCH_KEY, encoding)`: the key digest bound into the epoch binding (V-3, V-4). */
export function announcementDigest(a: EpochKeyAnnouncement): Uint8Array {
  return H('EPOCH_KEY', encodeKeyAnnouncement(a));
}

/** `H(EPOCH_KEY_ACK, announcement digest || policy digest)`, which a member signs. */
export function ackDigest(
  announcementDigestValue: Uint8Array,
  policyDigest: Uint8Array,
): Uint8Array {
  if (announcementDigestValue.length !== 32 || policyDigest.length !== 32)
    throw new RangeError('digests must be 32 bytes');
  return H('EPOCH_KEY_ACK', announcementDigestValue, policyDigest);
}

export function decodeBundle(b: Uint8Array): EpochKeyBundle {
  return decodeExact(b, (r) => {
    const announcement = readKeyAnnouncement(r);
    const acks = r.seq(
      MAX_COMMITTEE,
      (x) => ({ member: x.u8(), policyDigest: x.fixed(32), signature: x.fixed(64) }),
      97,
    );
    for (let i = 1; i < acks.length; i++) {
      if (acks[i - 1]!.member >= acks[i]!.member)
        throw new DecodeError('value', 'acks not strictly increasing');
    }
    return { announcement, acks };
  });
}

export function encodeBundle(b: EpochKeyBundle): Uint8Array {
  const w = new Writer();
  writeKeyAnnouncement(w, b.announcement);
  w.seq(b.acks, MAX_COMMITTEE, (x, a) =>
    x.u8(a.member).fixed(a.policyDigest, 32).fixed(a.signature, 64),
  );
  return w.finish();
}
