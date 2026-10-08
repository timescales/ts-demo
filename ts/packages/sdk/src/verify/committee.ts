import { b58 } from '../core/encoding/base58.js';
import { equal } from '../core/encoding/bytes.js';
import {
  committeeDigest,
  decodeCommittee,
  validateCommittee,
  type CommitteeDescription,
} from '../core/protocol/committee.js';
import type { MarketAccount } from '../solana/accounts.js';
import { CheckFailed, check, must, type Verdict } from './verdict.js';

/** Whether `digest` is the market's current or previous committee digest (graceful rotation). */
export function committeeKnown(chain: MarketAccount, digest: Uint8Array): boolean {
  return (
    equal(digest, chain.committeeDigest) ||
    (chain.prevCommitteeDigest !== null && equal(digest, chain.prevCommitteeDigest))
  );
}

/**
 * V-2: `H(COMMITTEE, description)` equals `Market.committee_digest`, or
 * `prev_committee_digest` when `forEpochDigest` names an epoch dealt before
 * a rotation. The description is for this market and passes `validate`
 * (incl. `n <= 2t - 1`).
 */
export function verifyCommittee(
  description: Uint8Array,
  chain: MarketAccount,
  forEpochDigest?: Uint8Array,
): Verdict<CommitteeDescription> {
  return check('V-2 committee', () => {
    const expected = forEpochDigest ?? chain.committeeDigest;
    must(
      committeeKnown(chain, expected),
      'the committee digest is neither the current nor the previous one on chain',
    );
    must(
      equal(committeeDigest(description), expected),
      'the committee description does not hash to the digest on chain',
    );
    const c = decodeCommittee(description);
    try {
      validateCommittee(c);
    } catch (e) {
      throw new CheckFailed(`the committee is invalid: ${(e as Error).message}`);
    }
    must(equal(c.market, b58.decode(chain.address, 32)), 'the committee is for another market');
    return c;
  });
}
