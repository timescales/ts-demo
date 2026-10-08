import { b58 } from '../core/encoding/base58.js';
import { equal } from '../core/encoding/bytes.js';
import { verifyStrict } from '../core/crypto/verifyStrict.js';
import { termsDigest } from '../core/protocol/binding.js';
import { decodeHeader, headerDigest } from '../core/protocol/header.js';
import { encodeMarketParams } from '../core/protocol/params.js';
import {
  decodeReceipt,
  outcomeDigest,
  receiptDigest,
  type ExecutionReceipt,
} from '../core/protocol/receipt.js';
import {
  liveExecutorSlots,
  popcount,
  type BatchAccount,
  type MarketAccount,
  type Observed,
} from '../solana/accounts.js';
import { check, must, mustBeReady, type Verdict } from './verdict.js';

/** Co-signatures of executors still registered, against the market's quorum. */
export function quorumOf(
  market: MarketAccount,
  batch: BatchAccount,
): { have: number; need: number; met: boolean } {
  const have = popcount(batch.cosignBitmap & liveExecutorSlots(market));
  return { have, need: market.receiptQuorum, met: have >= market.receiptQuorum };
}

/**
 * V-7: the receipt decodes exactly with version 1 (checked before hashing),
 * its executor's strict signature verifies, the executor holds a slot, its
 * digest is `Batch.receipt`, and its outcome is the one recorded on chain
 * for a version-2 header whose digest, root, count, beacon, params and
 * terms match the batch and whose prior state root and receipt match the
 * market while the batch is the next to settle. The result is provisional
 * until live co-signatures reach `Market.receipt_quorum`.
 */
export function verifyReceipt(
  raw: Uint8Array,
  header: Uint8Array,
  chain: { market: MarketAccount; batch: Observed<BatchAccount> },
): Verdict<{ receipt: ExecutionReceipt; quorum: { have: number; need: number; met: boolean } }> {
  return check('V-7 receipt', () => {
    const m = chain.market;
    const b = chain.batch.value;
    mustBeReady(b.receipt !== null, 'no receipt is posted on chain yet');
    must(b.market === m.address, 'the batch belongs to another market');
    const receipt = decodeReceipt(raw);
    const digest = receiptDigest(raw);
    must(
      verifyStrict(receipt.executor, digest, receipt.signature),
      'the receipt is not signed by its executor',
    );
    const executor = b58.encode(receipt.executor);
    must(
      m.executors.some((e) => e === executor),
      'the receipt executor is not registered',
    );
    must(receipt.backend === 'tee', 'only TEE receipts settle');
    must(equal(digest, b.receipt), 'the receipt is not the one posted on chain');

    const o = receipt.outcome;
    must(o.market === m.marketId && o.epoch === b.epoch, 'the receipt is for another batch');
    const hd = headerDigest(header);
    must(equal(o.headerDigest, hd), 'the receipt executed another header');
    must(
      b.headerDigest !== null && equal(b.headerDigest, hd),
      'the header is not the one posted on chain',
    );
    must(
      b.outcomeDigest !== null && equal(outcomeDigest(o), b.outcomeDigest),
      'the outcome is not the one posted on chain',
    );
    must(
      b.nextStateRoot !== null &&
        equal(o.nextStateRoot, b.nextStateRoot) &&
        b.settlementRoot !== null &&
        equal(o.settlementRoot, b.settlementRoot) &&
        o.settlementCount === b.settlementCount &&
        o.fees === b.fees,
      'the outcome disagrees with the settlement recorded on chain',
    );

    const h = decodeHeader(header);
    must(h.version === 2, 'the header is not version 2');
    must(h.market === m.marketId && h.epoch === b.epoch, 'the header is for another batch');
    must(
      equal(encodeMarketParams(h.params), encodeMarketParams(m.params)),
      'the header carries other params',
    );
    must(
      h.envelopeCount === b.count && equal(h.batchRoot, b.root),
      'the header names another batch root',
    );
    must(b.beacon !== null && equal(h.beacon, b.beacon), 'the header carries another beacon');
    must(
      equal(termsDigest(h.band, h.priceCommitmentOrBinding), b.termsDigest),
      'the header carries other terms than the batch committed',
    );
    // The market moves on once this batch settles. Before that, the header
    // must chain onto the market's current state and receipt.
    if (m.lastSettled + 1n === b.epoch) {
      must(
        equal(h.priorStateRoot, m.stateRoot) && equal(h.prevReceipt, m.prevReceipt),
        'the header does not chain onto the settled state',
      );
    } else if (m.lastSettled === b.epoch && b.status === 'settled') {
      must(
        equal(m.prevReceipt, digest) && equal(m.stateRoot, o.nextStateRoot),
        'the market did not record this receipt when it settled',
      );
    }
    return { receipt, quorum: quorumOf(m, b) };
  });
}
