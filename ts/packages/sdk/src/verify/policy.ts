import { equal } from '../core/encoding/bytes.js';
import { verifyStrict } from '../core/crypto/verifyStrict.js';
import type { EpochKeyBundle } from '../core/protocol/bundle.js';
import {
  committeeDigest,
  encodeCommittee,
  type CommitteeDescription,
} from '../core/protocol/committee.js';
import { decodePolicyStatement, policyDigest } from '../core/protocol/policy.js';
import { validAcks } from './epochKey.js';
import type { VerifiedMarketContext } from './market.js';
import { check, must, type Verdict } from './verdict.js';

/**
 * V-14. The browser cannot verify DCAP quotes. It verifies the members'
 * signed release policies instead. The enclave is labelled Intel TDX only
 * when at least `t` members of this committee published a statement that
 * excludes the simulated platform and whose digest their ack in the bundle
 * carries, so no `t` members would release a key to a simulated enclave.
 * Otherwise it is `simulated` when any valid statement allows simulation,
 * else `operator_reported`. Statements for another market or committee, or
 * not yet in force for the bundle's epoch, are ignored. A statement that
 * claims a member of this committee but is not signed by it fails.
 */
export function verifyPolicies(
  statements: Uint8Array[],
  committee: CommitteeDescription,
  bundle: EpochKeyBundle,
): Verdict<{ enclaveLabel: VerifiedMarketContext['enclaveLabel'] }> {
  return check('V-14 policies', () => {
    const digestOfCommittee = committeeDigest(encodeCommittee(committee));
    const acked = validAcks(bundle, committee);
    const epoch = bundle.announcement.epoch;
    const vouching = new Set<number>();
    let simulated = false;
    for (const raw of statements) {
      const s = decodePolicyStatement(raw);
      if (!equal(s.market, committee.market) || !equal(s.committeeDigest, digestOfCommittee))
        continue;
      const member = committee.members.find((m) => m.index === s.member);
      must(
        member !== undefined,
        `a policy statement names member ${s.member}, who is not in the committee`,
      );
      const digest = policyDigest(raw);
      must(
        verifyStrict(member.identity, digest, s.signature),
        `member ${s.member}'s policy statement is not signed by that member`,
      );
      if (s.fromEpoch > epoch) continue;
      if (s.platforms.simulated) simulated = true;
      const ack = acked.get(s.member);
      if (
        !s.platforms.simulated &&
        s.platforms.intelTdx &&
        ack !== undefined &&
        equal(ack, digest)
      ) {
        vouching.add(s.member);
      }
    }
    const enclaveLabel =
      vouching.size >= committee.threshold
        ? 'intel_tdx_vouched'
        : simulated
          ? 'simulated'
          : 'operator_reported';
    return { enclaveLabel };
  });
}
