// The balance buckets of one market.
import type { MarketParams, PriceBand } from '@timescales/sdk/core';
import type { OrderRecord } from '@timescales/sdk/orders';
import type { MarketAccount, TraderAccount } from '@timescales/sdk/solana';
import { withdrawStatus } from '@timescales/sdk/solana';

import { fillsByEpoch } from '../orders/fills';
import type { Amounts } from '../trade/reservation';
import { reservedByOrders } from '../trade/reservation';

/**
 * Own verified deltas of epochs not yet settled: a buy adds base and pays
 * quote plus its fee, a sell gives base and receives quote less its fee.
 * The account balance changes when they apply.
 */
export function pendingSettlement(
  records: readonly OrderRecord[],
  market: string,
  params: MarketParams,
): Amounts {
  let base = 0n;
  let quote = 0n;
  for (const r of records) {
    if (r.market !== market) continue;
    for (const f of fillsByEpoch(r)) {
      if (f.settled) continue;
      const notional = f.quantity * f.tick * params.tickSize;
      const size = f.quantity * params.baseLotSize;
      if (f.side === 0) {
        base += size;
        quote -= notional + f.feeQuote;
      } else {
        base -= size;
        quote += notional - f.feeQuote;
      }
    }
  }
  return { base, quote };
}

export interface Buckets {
  wallet: { base: bigint | null; quote: bigint | null };
  inAccount: Amounts | null;
  reserved: Amounts | null;
  pending: Amounts;
  requested: Amounts | null;
  withdrawable: Amounts | null;
  /** The epoch a pending request waits for, when it is still locked. */
  unlockEpoch: bigint | null;
}

export function buckets(a: {
  wallet: { base: bigint | null; quote: bigint | null };
  market: MarketAccount;
  trader: TraderAccount | null;
  records: readonly OrderRecord[];
  band: PriceBand | null;
}): Buckets {
  const { market, trader } = a;
  const status = trader ? withdrawStatus(market, trader) : null;
  return {
    wallet: a.wallet,
    inAccount: trader ? { base: trader.base, quote: trader.quote } : null,
    reserved: a.band ? reservedByOrders(a.records, market.address, market.params, a.band) : null,
    pending: pendingSettlement(a.records, market.address, market.params),
    requested: trader ? { base: trader.requestedBase, quote: trader.requestedQuote } : null,
    withdrawable:
      status === null ? null : status.withdrawable ? status.payoutUpTo : { base: 0n, quote: 0n },
    unlockEpoch: status?.reason === 'locked' ? status.unlocksAfterEpoch : null,
  };
}
