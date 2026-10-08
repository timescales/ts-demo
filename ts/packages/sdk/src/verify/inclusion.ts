import type { Address } from '@solana/kit';
import { equal } from '../core/encoding/bytes.js';
import { batchRootV2, decodeLeaves, type BatchLeaf } from '../core/protocol/leaves.js';
import type { BatchAccount, Observed } from '../solana/accounts.js';
import { exclusionEvidence } from './evidence.js';
import { verifyPromiseDigest } from './promise.js';
import { CheckFailed, check, must, mustBeReady, type Verdict } from './verdict.js';

export type Inclusion =
  | { status: 'included' }
  | { status: 'excluded'; evidence: Uint8Array }
  | { status: 'substituted'; evidence: Uint8Array };

/**
 * V-6, once the batch is committed: the downloaded leaves must hash to
 * `Batch.root` with `Batch.count` leaves. The own leaf `(C, d)` present means
 * included. Absent despite a valid promise is portable exclusion evidence.
 * `C` present with another envelope digest is the same evidence flagged as a
 * substitution. A batch the RPC does not show yet is inconclusive.
 */
export function checkInclusion(
  own: BatchLeaf,
  promiseRaw: Uint8Array,
  relayAtSubmission: Address,
  leavesRaw: Uint8Array,
  batch: Observed<BatchAccount> | null,
): Verdict<Inclusion> {
  return check('V-6 inclusion', () => {
    mustBeReady(batch !== null, 'the batch is not visible on the RPC yet');
    const b = batch.value;
    const promise = verifyPromiseDigest(promiseRaw, {
      market: b.market,
      epoch: b.epoch,
      commitment: own.commitment,
      envelopeDigest: own.envelopeDigest,
      relay: relayAtSubmission,
    });
    if (promise.kind !== 'ok')
      throw new CheckFailed(`the promise does not verify: ${promise.reason}`);
    const leaves = decodeLeaves(leavesRaw);
    must(leaves.length === b.count, 'the leaves do not match the committed count');
    must(equal(batchRootV2(leaves), b.root), 'the leaves do not hash to the committed root');
    let substituted = false;
    for (const l of leaves) {
      if (!equal(l.commitment, own.commitment)) continue;
      if (equal(l.envelopeDigest, own.envelopeDigest)) return { status: 'included' } as const;
      substituted = true;
    }
    const evidence = exclusionEvidence({
      kind: substituted ? 'substitution' : 'exclusion',
      own,
      promise: promiseRaw,
      relayAtSubmission,
      leaves: leavesRaw,
      batch,
    });
    return substituted
      ? ({ status: 'substituted', evidence } as const)
      : ({ status: 'excluded', evidence } as const);
  });
}
