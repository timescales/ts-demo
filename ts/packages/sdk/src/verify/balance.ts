import { b58 } from '../core/encoding/base58.js';
import { I64_MAX, equal } from '../core/encoding/bytes.js';
import { decodeBalanceSheet } from '../core/protocol/state.js';
import {
  availableFor,
  type BatchAccount,
  type Observed,
  type TraderAccount,
} from '../solana/accounts.js';
import { check, must, mustBeReady, type Verdict } from './verdict.js';

const RETRY_LATER_MS = 60_000;

function capped(v: bigint): bigint {
  return v > I64_MAX ? I64_MAX : v;
}

/**
 * V-15, once the epoch's balance sheet is public. The node snapshots every
 * trader's available balance for the batch at a slot at or after the commit,
 * and available never decreases between commit and apply:
 *
 * - Account unchanged since before the commit: the entry equals the current
 *   available balance.
 * - Changed after the commit while the batch was in flight and nothing was
 *   applied yet: the entry lies between the floor captured at the first
 *   change (when `floor_epoch == e`) and the current available balance.
 * - Changed after deltas were applied or the batch ended: the current
 *   balance no longer bounds the entry, so only the floor is checked and
 *   the result is otherwise inconclusive.
 */
export function verifyOwnBalance(
  sheet: Uint8Array,
  own: Observed<TraderAccount>,
  batch: BatchAccount,
  epoch: bigint,
): Verdict {
  return check('V-15 balance entry', () => {
    const t = own.value;
    must(batch.epoch === epoch, 'the batch is for another epoch');
    must(batch.market === t.market, 'the batch is for another market');
    const owner = b58.decode(t.owner, 32);
    const entry = decodeBalanceSheet(sheet).find((e) => equal(e.trader, owner));
    const now = availableFor(t, epoch);
    const unchanged = t.lastChangeSlot < batch.commitSlot;
    if (unchanged) {
      must(entry !== undefined, 'the balance sheet leaves out this account');
      must(
        entry.base === capped(now.base) && entry.quote === capped(now.quote),
        'the balance sheet does not show this account’s available balance',
      );
      return;
    }
    const floor = t.floorEpoch === epoch ? { base: t.floorBase, quote: t.floorQuote } : null;
    if (floor !== null) {
      must(entry !== undefined, 'the balance sheet leaves out this account');
      must(
        entry.base >= capped(floor.base) && entry.quote >= capped(floor.quote),
        'the balance sheet shows less than this account had available at the commit',
      );
    }
    const applying =
      batch.appliedCount > 0 || batch.status === 'settled' || batch.status === 'aborted';
    mustBeReady(
      !applying,
      'the account changed after the batch ended, the entry cannot be checked further',
      RETRY_LATER_MS,
    );
    if (entry !== undefined) {
      must(
        entry.base <= capped(now.base) && entry.quote <= capped(now.quote),
        'the balance sheet shows more than this account has available',
      );
    }
  });
}
