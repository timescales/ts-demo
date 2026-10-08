import { TimescalesError } from '@timescales/sdk';
import { b58 } from '@timescales/sdk/core';
import type { TimescalesRpc } from '@timescales/sdk/solana';
import type { VerifiedMarketContext } from '@timescales/sdk/verify';
import { describe, expect, it } from 'vitest';

import { slotOnlyRpc, testConfig } from '../app/testing/renderApp';
import type { OrdersController } from './orders';
import type { Address } from './types';
import type { VerificationController } from './verification';
import { createVerificationController } from './verification';

const MARKET = b58.encode(new Uint8Array(32).fill(21)) as Address;

const failed = () =>
  new TimescalesError({
    kind: 'verify',
    code: 'verification_failed',
    details: { check: 'V-1', reason: 'the node reports other token decimals' },
  });

const verifiedContext = {
  market: {
    pending: null,
    baseMint: b58.encode(new Uint8Array(32).fill(22)),
    quoteMint: b58.encode(new Uint8Array(32).fill(23)),
    timelockSlots: 0n,
  },
  program: { lastDeploySlot: 0n },
} as unknown as VerifiedMarketContext;

/** An orders controller whose verifier answers each `context` call with the next queued outcome. */
function ordersWith(outcomes: (() => Promise<VerifiedMarketContext>)[]) {
  const calls = { n: 0 };
  const orders = {
    verifier: () => ({
      context: () => {
        const next = outcomes[calls.n++];
        if (next === undefined) throw new Error('unexpected check');
        return next();
      },
    }),
  } as unknown as OrdersController;
  return { orders, calls };
}

function controller(orders: OrdersController, rpc: TimescalesRpc): VerificationController {
  const config = testConfig({ markets: [MARKET], genesisHash: 'test-genesis' });
  return createVerificationController({ config, orders, rpc });
}

async function settled(v: VerificationController) {
  for (let i = 0; i < 20; i++) await Promise.resolve();
  return v.state.get().markets.get(MARKET);
}

describe('verification across an RPC change', () => {
  it('re-checks a failed market through the new RPC and never leaves it without a result', async () => {
    const { orders, calls } = ordersWith([
      () => Promise.reject(failed()),
      () => Promise.resolve(verifiedContext),
    ]);
    const v = controller(orders, slotOnlyRpc());
    v.ensure(MARKET);
    expect((await settled(v))?.status).toBe('fail');
    v.setRpc(slotOnlyRpc());
    expect(v.state.get().markets.get(MARKET)?.status).toBe('checking');
    expect((await settled(v))?.status).toBe('ok');
    expect(calls.n).toBe(2);
    v.dispose();
  });

  it('drops a result read through the RPC the user replaced', async () => {
    let resolveOld: (ctx: VerifiedMarketContext) => void = () => {};
    const { orders } = ordersWith([
      () => new Promise((resolve) => (resolveOld = resolve)),
      () => Promise.reject(failed()),
    ]);
    const v = controller(orders, slotOnlyRpc());
    v.ensure(MARKET);
    await settled(v);
    expect(v.state.get().markets.get(MARKET)?.status).toBe('checking');
    v.setRpc(slotOnlyRpc());
    expect((await settled(v))?.status).toBe('fail');
    // The check started on the old RPC passes late. It must not lift the failure.
    resolveOld(verifiedContext);
    expect((await settled(v))?.status).toBe('fail');
    v.dispose();
  });
});
