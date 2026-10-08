// Welcome's account and deposit steps against the SDK's fake node: money
// moves only on a market the app verified, with the verified decimals.
import 'fake-indexeddb/auto';

import type { MarketDetail } from '@timescales/sdk/api';
import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FakeNode } from '../../app/testing/fakeNode';
import {
  fakeNode,
  nodeConfig,
  nodeRuntime,
  overrideApi,
  seed,
  testWallet,
} from '../../app/testing/fakeNode';
import { installLocks } from '../../app/testing/locks';
import type { RenderedApp } from '../../app/testing/renderApp';
import { renderApp, resetAppState } from '../../app/testing/renderApp';
import { updateWelcome } from '../../state/firstRun';
import { welcomeCopy } from './copy';

let app: RenderedApp | null = null;
let restoreLocks: (() => void) | null = null;

beforeEach(() => {
  restoreLocks = installLocks();
  // The rent pre-check posts to the allowlisted RPC URL itself. Answer it here.
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    Response.json({ jsonrpc: '2.0', id: 1, result: 1_920_960 }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  restoreLocks?.();
  app?.unmount();
  app = null;
  resetAppState();
});

function currentStep(): HTMLElement {
  const steps = screen.getByRole('list', { name: 'Getting started' });
  return steps.querySelector('[aria-current="step"]') as HTMLElement;
}

/** Opens Welcome at the deposit step: wallet connected, market chosen, empty trader account. */
function atDeposit(node: FakeNode, decimals?: number) {
  const wallet = testWallet({ seed: seed(1) });
  node.fund(wallet.address, 0n, 0n);
  updateWelcome({ understoodPublic: true, market: node.market });
  const api =
    decimals === undefined
      ? node.api
      : overrideApi(node.api, {
          market: async (m) => {
            const d: MarketDetail = await node.api.market(m);
            return { ...d, quoteDecimals: decimals };
          },
        });
  app = renderApp('/welcome', {
    welcomed: false,
    config: nodeConfig(node),
    runtime: nodeRuntime(node, { api }),
  });
  act(() => app!.runtime.wallets.use(wallet));
  return app;
}

describe('Welcome deposit', () => {
  it('enables the deposit once the market verifies', async () => {
    const node = fakeNode();
    const a = atDeposit(node);
    await waitFor(() => expect(currentStep().textContent).toContain('Deposit'), {
      timeout: 5000,
    });
    await waitFor(
      () => expect(a.runtime.verification.state.get().markets.get(node.market)?.status).toBe('ok'),
      { timeout: 5000 },
    );
    const deposit = within(currentStep()).getByRole('button', { name: 'Deposit' });
    await waitFor(() => expect(deposit.hasAttribute('disabled')).toBe(false));
  });

  it('forgets a remembered market the node no longer lists', async () => {
    const node = fakeNode();
    const wallet = testWallet({ seed: seed(1) });
    node.fund(wallet.address, 0n, 0n);
    // A market from an earlier deployment: not listed by this node, not pinned by this build.
    updateWelcome({ understoodPublic: true, market: testWallet({ seed: seed(2) }).address });
    app = renderApp('/welcome', {
      welcomed: false,
      config: nodeConfig(node),
      runtime: nodeRuntime(node),
    });
    act(() => app!.runtime.wallets.use(wallet));
    await waitFor(() => expect(currentStep().textContent).toContain('Choose a market'), {
      timeout: 5000,
    });
    expect(screen.queryByText(welcomeCopy.gate.unpinned)).toBeNull();
  });

  it('refuses the deposit when the node reports other token decimals', async () => {
    const node = fakeNode();
    const a = atDeposit(node, 9);
    await waitFor(
      () =>
        expect(a.runtime.verification.state.get().markets.get(node.market)).toMatchObject({
          status: 'fail',
          check: 'V-1',
        }),
      { timeout: 5000 },
    );
    await waitFor(() => expect(currentStep().textContent).toContain('Deposit'));
    const step = currentStep();
    expect(within(step).getByRole('button', { name: 'Deposit' }).hasAttribute('disabled')).toBe(
      true,
    );
    expect(within(step).getByText(/This market failed verification in this app/)).toBeTruthy();
  });
});
