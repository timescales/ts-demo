import type { MarketAccount } from '@timescales/sdk/solana';
import { describe, expect, it } from 'vitest';

import { fixtureParams, placeRecord, traderAccount } from '../trade/testing/fakes';
import { buckets, pendingSettlement } from './balances';

const MARKET = 'Market1111111111111111111111111111111111111' as never;
const params = fixtureParams();
const fill = (side: 0 | 1, quantity: bigint) => ({
  commitment: new Uint8Array(32),
  book: 1 as const,
  side,
  role: 0 as const,
  quantity,
  tick: 15_000n,
  feeQuote: 15n,
});

describe('pendingSettlement', () => {
  it('sums own verified fills of epochs not yet settled', () => {
    const buy = placeRecord({
      market: MARKET,
      params,
      epochs: [[42n, { kind: 'settling', done: 1, total: 2 }]],
      history: [{ atMs: 1, kind: 'fills', epoch: 42n, filled: 2n }],
      fills: [fill(0, 2n)],
    });
    const sell = placeRecord({
      market: MARKET,
      params,
      side: 1,
      epochs: [[42n, { kind: 'verified', filled: 1n }]],
      history: [{ atMs: 1, kind: 'fills', epoch: 42n, filled: 1n }],
      fills: [fill(1, 1n)],
    });
    const settled = placeRecord({
      market: MARKET,
      params,
      epochs: [[41n, { kind: 'settled', filled: 5n }]],
      history: [{ atMs: 1, kind: 'fills', epoch: 41n, filled: 5n }],
      fills: [fill(0, 5n)],
    });
    // Buy 2 lots: +2,000,000 base atoms, -(300,000 + 15) quote. Sell 1 lot: -1,000,000, +(150,000 - 15).
    expect(pendingSettlement([buy, sell, settled], MARKET, params)).toEqual({
      base: 1_000_000n,
      quote: -150_030n,
    });
  });
});

describe('buckets', () => {
  const market = {
    address: MARKET,
    params,
    lastCommitted: 42n,
    lastSettled: 41n,
  } as unknown as MarketAccount;

  it('reports a locked request with the epoch it waits for', () => {
    const b = buckets({
      wallet: { base: 1n, quote: null },
      market,
      trader: traderAccount({ requestedQuote: 7n, requestEpoch: 42n }),
      records: [],
      band: null,
    });
    expect(b.requested).toEqual({ base: 0n, quote: 7n });
    expect(b.withdrawable).toEqual({ base: 0n, quote: 0n });
    expect(b.unlockEpoch).toBe(42n);
    expect(b.reserved).toBeNull();
  });

  it('makes the request withdrawable once its epoch is terminal', () => {
    const b = buckets({
      wallet: { base: null, quote: null },
      market,
      trader: traderAccount({ requestedQuote: 7n, requestEpoch: 41n }),
      records: [],
      band: { lo: 14_968n, hi: 15_032n, reference: 15_000n },
    });
    expect(b.withdrawable).toEqual({ base: 0n, quote: 7n });
    expect(b.unlockEpoch).toBeNull();
    expect(b.reserved).toEqual({ base: 0n, quote: 0n });
  });

  it('has no account buckets without a trader account', () => {
    const b = buckets({
      wallet: { base: null, quote: null },
      market,
      trader: null,
      records: [],
      band: null,
    });
    expect(b.inAccount).toBeNull();
    expect(b.withdrawable).toBeNull();
  });
});
