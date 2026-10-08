import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';

/**
 * A member's signed release policy (221 B): `ver u8 || market32 ||
 * member u8 || committee_digest32 || platforms u8 || measurement_set_digest32 ||
 * allow_debug bool || min_tcb u8 || mr_config_id48 || from_epoch u64 || sig64`.
 */
export interface ReleasePolicyStatement {
  market: Uint8Array;
  member: number;
  committeeDigest: Uint8Array;
  platforms: { simulated: boolean; intelTdx: boolean };
  measurementSetDigest: Uint8Array;
  allowDebug: boolean;
  minTcb: number;
  mrConfigId: Uint8Array;
  fromEpoch: bigint;
  signature: Uint8Array;
}

export const POLICY_VERSION = 1;
export const POLICY_LEN = 221;

export function decodePolicyStatement(b: Uint8Array): ReleasePolicyStatement {
  return decodeExact(b, (r) => {
    const version = r.u8();
    if (version !== POLICY_VERSION) throw new DecodeError('version', `policy version ${version}`);
    const market = r.fixed(32);
    const member = r.u8();
    const committeeDigest = r.fixed(32);
    const platforms = r.u8();
    if ((platforms & ~3) !== 0)
      throw new DecodeError('value', `unknown platform bits ${platforms}`);
    return {
      market,
      member,
      committeeDigest,
      platforms: { simulated: (platforms & 1) !== 0, intelTdx: (platforms & 2) !== 0 },
      measurementSetDigest: r.fixed(32),
      allowDebug: r.bool(),
      minTcb: r.u8(),
      mrConfigId: r.fixed(48),
      fromEpoch: r.u64(),
      signature: r.fixed(64),
    };
  });
}

export function encodePolicyStatement(s: ReleasePolicyStatement): Uint8Array {
  return new Writer()
    .u8(POLICY_VERSION)
    .fixed(s.market, 32)
    .u8(s.member)
    .fixed(s.committeeDigest, 32)
    .u8((s.platforms.simulated ? 1 : 0) | (s.platforms.intelTdx ? 2 : 0))
    .fixed(s.measurementSetDigest, 32)
    .bool(s.allowDebug)
    .u8(s.minTcb)
    .fixed(s.mrConfigId, 48)
    .u64(s.fromEpoch)
    .fixed(s.signature, 64)
    .finish();
}

/** `H(RELEASE_POLICY, bytes before the signature)`. The digest every ack carries (V-14). */
export function policyDigest(raw: Uint8Array): Uint8Array {
  if (raw.length !== POLICY_LEN)
    throw new DecodeError('length', `policy statement must be ${POLICY_LEN} bytes`);
  return H('RELEASE_POLICY', raw.subarray(0, POLICY_LEN - 64));
}
