import { equal, isZero } from '../encoding/bytes.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';
import { decompress } from '../crypto/edwards.js';

/** Key-release committee: `ver u8 || market32 || t u8 || seq<(index u8 || identity32 || transport32)>` (1..=16). */
export interface CommitteeDescription {
  version: number;
  market: Uint8Array;
  threshold: number;
  members: { index: number; identity: Uint8Array; transport: Uint8Array }[];
}

export const COMMITTEE_VERSION = 1;
export const MAX_COMMITTEE = 16;

export function decodeCommittee(b: Uint8Array): CommitteeDescription {
  return decodeExact(b, (r) => {
    const version = r.u8();
    if (version !== COMMITTEE_VERSION)
      throw new DecodeError('version', `committee version ${version}`);
    const market = r.fixed(32);
    const threshold = r.u8();
    const members = r.seq(
      MAX_COMMITTEE,
      (x) => ({ index: x.u8(), identity: x.fixed(32), transport: x.fixed(32) }),
      65,
    );
    if (members.length === 0) throw new DecodeError('length', 'empty committee');
    return { version, market, threshold, members };
  });
}

export function encodeCommittee(c: CommitteeDescription): Uint8Array {
  return new Writer()
    .u8(c.version)
    .fixed(c.market, 32)
    .u8(c.threshold)
    .seq(c.members, MAX_COMMITTEE, (w, m) =>
      w.u8(m.index).fixed(m.identity, 32).fixed(m.transport, 32),
    )
    .finish();
}

/** `H(COMMITTEE, description bytes)`, compared with `Market.committee_digest` (V-2). */
export function committeeDigest(raw: Uint8Array): Uint8Array {
  return H('COMMITTEE', raw);
}

export class CommitteeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CommitteeError';
  }
}

/**
 * `CommitteeDescription::validate`: `1 <= t <= n <= 16`, `n <= 2t - 1` (no two
 * disjoint quorums), indices `1..=n` in order, keys non-zero and distinct,
 * identities valid Edwards points.
 */
export function validateCommittee(c: CommitteeDescription): void {
  const n = c.members.length;
  const t = c.threshold;
  if (t < 1 || t > n || n > MAX_COMMITTEE) throw new CommitteeError('threshold out of range');
  if (n > 2 * t - 1) throw new CommitteeError('two disjoint quorums are possible (n > 2t - 1)');
  c.members.forEach((m, i) => {
    if (m.index !== i + 1) throw new CommitteeError('member indices must be 1..=n in order');
    if (isZero(m.identity) || isZero(m.transport)) throw new CommitteeError('zero member key');
    if (decompress(m.identity) === null)
      throw new CommitteeError('member identity is not a valid point');
  });
  const keys = c.members.flatMap((m) => [m.identity, m.transport]);
  for (let i = 0; i < keys.length; i++) {
    for (let j = i + 1; j < keys.length; j++) {
      if (equal(keys[i]!, keys[j]!)) throw new CommitteeError('duplicate member key');
    }
  }
}
