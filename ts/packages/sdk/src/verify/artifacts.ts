import { equal } from '../core/encoding/bytes.js';
import {
  cancelledRoot,
  decodeArtifacts,
  fillsRoot,
  type ExecutionArtifacts,
} from '../core/protocol/artifacts.js';
import type { MarketParams } from '../core/protocol/params.js';
import type { ExecutionReceipt } from '../core/protocol/receipt.js';
import {
  checkConservation,
  encodeSettlementBatch,
  settle,
  settlementRoot,
} from '../core/protocol/settlement.js';
import { CheckFailed, check, must, type Verdict } from './verdict.js';

/**
 * V-8: the artifacts recompute the outcome's fills, cancelled and settlement
 * roots and counts. `settle(params, epoch, fills)` reproduces the
 * settlement exactly, and the settlement conserves base and quote.
 */
export function verifyArtifacts(
  raw: Uint8Array,
  receipt: ExecutionReceipt,
  params: MarketParams,
  epoch: bigint,
): Verdict<ExecutionArtifacts> {
  return check('V-8 artifacts', () => {
    const a = decodeArtifacts(raw);
    const o = receipt.outcome;
    must(o.market === params.market && o.epoch === epoch, 'the receipt is for another batch');
    must(
      a.fills.length === o.fillCount && equal(fillsRoot(a.fills), o.fillsRoot),
      'the fills do not match the outcome',
    );
    must(
      equal(cancelledRoot(a.cancelled), o.cancelledRoot),
      'the cancelled list does not match the outcome',
    );
    const s = a.settlement;
    must(s.market === params.market && s.epoch === epoch, 'the settlement is for another batch');
    must(
      s.deltas.length === o.settlementCount &&
        equal(settlementRoot(s.deltas), o.settlementRoot) &&
        s.fees === o.fees,
      'the settlement does not match the outcome',
    );
    let expected;
    try {
      expected = settle(params, epoch, a.fills);
    } catch (e) {
      throw new CheckFailed(`the fills do not settle: ${(e as Error).message}`);
    }
    must(
      equal(encodeSettlementBatch(expected), encodeSettlementBatch(s)),
      'the settlement is not the one the fills imply',
    );
    try {
      checkConservation(s);
    } catch (e) {
      throw new CheckFailed((e as Error).message);
    }
    return a;
  });
}
