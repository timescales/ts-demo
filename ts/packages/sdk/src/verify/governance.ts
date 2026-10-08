import type { MarketAccount, PendingChange } from '../solana/accounts.js';

/** Timelocks below this on a non-localnet cluster are labelled "No effective timelock" (V-13). */
export const EFFECTIVE_TIMELOCK_SLOTS = 216_000n;

/**
 * V-13: the market's pending governance change of any kind, with the quorum
 * and timelock decreases marked so they can be shown as warnings. The
 * account decoder already parsed the payload strictly. This recomputes the
 * comparisons against the account's current values.
 */
export function decodePendingChange(chain: MarketAccount): PendingChange | null {
  const p = chain.pending;
  if (p === null) return null;
  switch (p.kind) {
    case 'set_executors':
      return { ...p, executors: [...p.executors], quorumDecrease: p.quorum < chain.receiptQuorum };
    case 'set_timelock':
      return { ...p, decrease: p.slots < chain.timelockSlots };
    case 'set_committee_digest':
      return { ...p, digest: p.digest.slice() };
    default:
      return { ...p };
  }
}
