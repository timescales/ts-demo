// The shell against the SDK's fake node (real keys, real verifier checks): the
// tampered-key refusal, account switching mid-session, session eviction and
// a sign-in for another site.
import 'fake-indexeddb/auto';

import { TimescalesError } from '@timescales/sdk';
import type { CurrentEpoch, TimescalesApi } from '@timescales/sdk/api';
import type { TimescalesRpc } from '@timescales/sdk/solana';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../components/testing/a11y';
import { tradeCopy } from '../features/trade/copy';
import { updateSettings } from '../state/settings';
import { CROSS_CHECK, canSeal } from '../state/verification';
import type { FakeNode } from './testing/fakeNode';
import {
  NODE_ORIGIN,
  fakeNode,
  nodeConfig,
  nodeRuntime,
  overrideApi,
  seed,
  setPageUrl,
  testWallet,
} from './testing/fakeNode';
import type { RenderedApp } from './testing/renderApp';
import { installLocks } from './testing/locks';
import { flush, renderApp, resetAppState } from './testing/renderApp';

let app: RenderedApp | null = null;
let restoreUrl: (() => void) | null = null;
let restoreLocks: (() => void) | null = null;

beforeEach(() => {
  restoreLocks = installLocks();
});

afterEach(() => {
  restoreLocks?.();
  app?.unmount();
  app = null;
  restoreUrl?.();
  restoreUrl = null;
  resetAppState();
});

function render(node: FakeNode, path: string, api?: TimescalesApi) {
  app = renderApp(path, {
    config: nodeConfig(node),
    runtime: nodeRuntime(node, api ? { api } : {}),
  });
  return app;
}

function tampered(node: FakeNode): TimescalesApi {
  return overrideApi(node.api, {
    current: async (m) => {
      const c: CurrentEpoch = await node.api.current(m);
      if (c.open === null) return c;
      // A byte of the epoch public key inside the announcement the members
      // acknowledged: every ack then fails. (One corrupt ack alone is
      // tolerated while t valid ones remain.)
      const bundle = c.open.key.bundleBytes.slice();
      bundle[80]! ^= 0x01;
      return { ...c, open: { ...c.open, key: { ...c.open.key, bundleBytes: bundle } } };
    },
  });
}

describe('epoch key verification (V-3)', () => {
  it('verifies an honest market and allows sealing', async () => {
    const node = fakeNode();
    const a = render(node, `/epochs/${node.market}`);
    await waitFor(
      () => expect(a.runtime.verification.state.get().markets.get(node.market)?.status).toBe('ok'),
      { timeout: 5000 },
    );
    await waitFor(() =>
      expect(canSeal(a.runtime.verification.state.get(), node.market, node.open)).toBe(true),
    );
    expect(screen.queryByText(/Could not verify/)).toBeNull();
    const footer = screen.getByRole('contentinfo', { name: 'System status' });
    expect(footer.textContent).toContain('Enclave: SIMULATED');
  });

  it('refuses a tampered epoch-key bundle: blocking banner, nothing can be sealed', async () => {
    const node = fakeNode();
    const a = render(node, `/epochs/${node.market}`, tampered(node));
    const announce = vi.spyOn(a.runtime.announcer, 'announce');
    const section = await waitFor(
      () => {
        const found = screen
          .getAllByText('Could not verify the encryption key of the open epoch.')
          .map((e) => e.closest('section'))
          .find((e) => e !== null);
        if (!found) throw new Error('no banner yet');
        return found;
      },
      { timeout: 5000 },
    );
    expect(section.getAttribute('data-severity')).toBe('critical');
    expect(
      within(section).getByText(/Trading in this market is paused on this device/),
    ).toBeTruthy();
    const check = a.runtime.verification.state.get().markets.get(node.market);
    expect(check).toMatchObject({ status: 'fail', check: 'V-3' });
    expect(canSeal(a.runtime.verification.state.get(), node.market, node.open)).toBe(false);
    // The assertive region speaks the critical banner, once, however often the shell re-renders.
    await waitFor(() =>
      expect(screen.getByTestId('live-assertive').textContent).toBe(
        'Could not verify the encryption key of the open epoch.',
      ),
    );
    await flush(1_100);
    expect(announce.mock.calls.filter(([, category]) => category === 'critical')).toEqual([
      ['Could not verify the encryption key of the open epoch.', 'critical'],
    ]);
    // Critical banners cannot be dismissed. Re-check runs the checks again.
    expect(within(section).queryByRole('button', { name: 'Dismiss' })).toBeNull();
    fireEvent.click(within(section).getByRole('button', { name: 'Re-check' }));
    await waitFor(() =>
      expect(a.runtime.verification.state.get().markets.get(node.market)?.status).toBe('fail'),
    );
    await expectNoSeriousAxeViolations();
  });
});

describe('sessions and accounts', () => {
  it('opens a session with one wallet prompt, then tears down and re-resolves on an account switch', async () => {
    restoreUrl = setPageUrl(`${NODE_ORIGIN}/`);
    const node = fakeNode();
    const wallet = testWallet({ seed: seed(1) });
    const a = render(node, `/epochs/${node.market}`);
    act(() => a.runtime.wallets.use(wallet));
    await waitFor(() => expect(a.runtime.orders.state.get().journal).not.toBeNull());
    await act(async () => {
      await a.runtime.session.open({ market: null });
    });
    expect(a.runtime.session.state.get().status).toBe('active');
    // A localnet session signs its text directly: wallets refuse a localnet Sign-In.
    expect(wallet.calls.filter((c) => c.method === 'signMessage')).toHaveLength(1);
    expect(wallet.calls.filter((c) => c.method === 'signIn')).toHaveLength(0);
    await waitFor(() => expect(a.runtime.orders.state.get().role).toBe('leader'));
    const first = wallet.address;

    act(() => wallet.switchAccount(seed(2)));
    const second = wallet.address;
    expect(second).not.toBe(first);
    expect(a.runtime.wallets.state.get().notice).toEqual({ kind: 'switched', address: second });
    // The fake node serves no /v1/status and reports a recent deploy, so two
    // warnings come first and this one may sit behind "+N more".
    const more = screen.queryByRole('button', { name: /more notices/ });
    if (more) fireEvent.click(more);
    await screen.findByText(
      `Your wallet switched to another account. ${document.title.split(' - ')[1]} reloaded for ${second.slice(0, 4)}...${second.slice(-4)}.`,
    );
    await waitFor(() => expect(a.runtime.orders.state.get().wallet).toBe(second));
    // The old session belongs to the old account: nothing signs for B with A's key.
    await waitFor(() =>
      expect(a.runtime.session.state.get()).toMatchObject({ wallet: second, status: 'none' }),
    );
    expect(a.runtime.orders.state.get().role).toBeNull();
  });

  it('shows eviction by a session started elsewhere on the chip', async () => {
    restoreUrl = setPageUrl(`${NODE_ORIGIN}/`);
    const node = fakeNode();
    const wallet = testWallet({ seed: seed(3) });
    const a = render(node, `/epochs/${node.market}`);
    act(() => a.runtime.wallets.use(wallet));
    await waitFor(() => expect(a.runtime.orders.state.get().journal).not.toBeNull());
    await act(async () => {
      await a.runtime.session.open({ market: null });
    });
    node.fake.respond('GET', '/v1/sessions/current', 401, {
      type: 'urn:timescales:error:session_revoked',
      title: 'Session revoked',
      status: 401,
      code: 'SESSION_REVOKED',
      detail: 'evicted by a newer session',
      retryable: false,
      request_id: 'fake',
    });
    await act(async () => {
      await a.runtime.session.check();
    });
    expect(a.runtime.session.state.get().status).toBe('revoked');
    expect(
      await screen.findByRole('button', {
        name: 'You signed in elsewhere, so this session ended. Renew (1 wallet signature).',
      }),
    ).toBeTruthy();
  });

  it('reports a sign-in for another site in the session dialog', async () => {
    // The page is not on the node's session domain.
    const node = fakeNode();
    const wallet = testWallet({ seed: seed(4) });
    const a = render(node, `/epochs/${node.market}`);
    act(() => a.runtime.wallets.use(wallet));
    await waitFor(() => expect(a.runtime.orders.state.get().journal).not.toBeNull());
    fireEvent.click(await screen.findByRole('button', { name: 'Start session' }));
    fireEvent.click(
      await screen.findByRole('button', { name: 'Start session (1 wallet signature)' }),
    );
    await screen.findByText('This sign-in was for another site.');
    const error = a.runtime.session.state.get().error;
    expect(error instanceof TimescalesError && error.code).toBe('SESSION_DOMAIN_MISMATCH');
  });
});

describe('cross-check RPC (Settings › Network)', () => {
  const PRIMARY = 'https://primary.rpc.test/';
  const CROSS = 'https://cross.rpc.test/';

  function renderWithCrossCheck(node: FakeNode, cross: TimescalesRpc) {
    updateSettings({ rpcPrimary: 'primary', rpcCrossCheck: 'cross' });
    app = renderApp(`/epochs/${node.market}`, {
      config: nodeConfig(node, {
        rpcAllowlist: [
          { id: 'primary', label: 'Primary', url: PRIMARY },
          { id: 'cross', label: 'Cross', url: CROSS },
        ],
      }),
      runtime: {
        api: node.api,
        rpc: (url) => (url === CROSS ? cross : node.rpc),
        WebSocketImpl: node.WebSocket,
      },
    });
    return app;
  }

  it('verifies a market both RPCs agree on', async () => {
    const node = fakeNode();
    const a = renderWithCrossCheck(node, node.rpc);
    await waitFor(
      () => expect(a.runtime.verification.state.get().markets.get(node.market)?.status).toBe('ok'),
      { timeout: 5000 },
    );
  });

  it('stops trading on a market the cross-check RPC reports differently', async () => {
    const node = fakeNode();
    const cross: TimescalesRpc = {
      ...node.rpc,
      market: async (address, minContextSlot) => {
        const m = await node.rpc.market(address, minContextSlot);
        return { ...m, value: { ...m.value, quoteVault: m.value.baseVault } };
      },
    };
    const a = renderWithCrossCheck(node, cross);
    await waitFor(
      () =>
        expect(a.runtime.verification.state.get().markets.get(node.market)).toMatchObject({
          status: 'fail',
          check: CROSS_CHECK,
        }),
      { timeout: 5000 },
    );
    const title = await screen.findAllByText(
      'Your Solana RPC and your cross-check RPC disagree about this market.',
    );
    expect(title[0]!.closest('section')?.getAttribute('data-severity')).toBe('critical');
    expect(canSeal(a.runtime.verification.state.get(), node.market, node.open)).toBe(false);
    // Turning the cross-check off checks the market again, through the primary RPC alone.
    act(() => updateSettings({ rpcCrossCheck: null }));
    await waitFor(() =>
      expect(a.runtime.verification.state.get().markets.get(node.market)?.status).toBe('ok'),
    );
  });
});

describe('primary RPC change (Settings › Network)', () => {
  const A = 'https://a.rpc.test/';
  const B = 'https://b.rpc.test/';

  // B answers for another cluster. Every read of the cluster or a Market account through it is counted.
  function renderWithTwoRpcs(node: FakeNode) {
    const reads = { genesisHash: 0, market: 0 };
    const other: TimescalesRpc = {
      ...node.rpc,
      genesisHash: () => {
        reads.genesisHash += 1;
        return Promise.resolve('another-cluster-genesis-hash');
      },
      market: (address, minContextSlot) => {
        reads.market += 1;
        return node.rpc.market(address, minContextSlot);
      },
    };
    updateSettings({ rpcPrimary: 'a', rpcCrossCheck: null });
    app = renderApp(`/epochs/${node.market}`, {
      config: nodeConfig(node, {
        rpcAllowlist: [
          { id: 'a', label: 'A', url: A },
          { id: 'b', label: 'B', url: B },
        ],
      }),
      runtime: {
        api: node.api,
        rpc: (url) => (url === B ? other : node.rpc),
        WebSocketImpl: node.WebSocket,
      },
    });
    return { a: app, reads };
  }

  it('re-verifies through the new RPC with a wallet attached, not through the old service', async () => {
    restoreUrl = setPageUrl(`${NODE_ORIGIN}/`);
    const node = fakeNode();
    const { a, reads } = renderWithTwoRpcs(node);
    const wallet = testWallet({ seed: seed(5) });
    act(() => a.runtime.wallets.use(wallet));
    await waitFor(() => expect(a.runtime.orders.state.get().service).not.toBeNull());
    await waitFor(
      () => expect(a.runtime.verification.state.get().markets.get(node.market)?.status).toBe('ok'),
      { timeout: 5000 },
    );
    const before = a.runtime.orders.state.get().service;

    act(() => updateSettings({ rpcPrimary: 'b' }));
    expect(a.runtime.verification.state.get().markets.get(node.market)?.status).not.toBe('ok');
    await waitFor(
      () =>
        expect(a.runtime.verification.state.get().markets.get(node.market)?.status).toBe('fail'),
      { timeout: 5000 },
    );
    expect(reads.genesisHash + reads.market).toBeGreaterThan(0);
    expect(canSeal(a.runtime.verification.state.get(), node.market, node.open)).toBe(false);
    // The wallet is attached again, on a service built for the new RPC.
    await waitFor(() => {
      const after = a.runtime.orders.state.get().service;
      expect(after).not.toBeNull();
      expect(after).not.toBe(before);
    });
  });
});

describe('trader services from the shell', () => {
  it("hands the Trade screen the wallet, then the runtime's order service once a session is open", async () => {
    restoreUrl = setPageUrl(`${NODE_ORIGIN}/`);
    const node = fakeNode();
    const wallet = testWallet({ seed: seed(6) });
    const a = render(node, `/trade/${node.market}`);
    await screen.findAllByText(tradeCopy.states.noWallet);
    act(() => a.runtime.wallets.use(wallet));
    await screen.findAllByText(tradeCopy.states.noSession);
    // The screen's Start session opens the shell's session dialog.
    fireEvent.click(
      within(screen.getByRole('main')).getAllByRole('button', {
        name: tradeCopy.states.startSession,
      })[0]!,
    );
    await screen.findByRole('dialog', { name: 'Trading session' });
    await waitFor(() => expect(a.runtime.orders.state.get().journal).not.toBeNull());
    await act(async () => {
      await a.runtime.session.open({ market: null });
    });
    await waitFor(() => expect(a.runtime.orders.state.get().role).toBe('leader'));
    // The session dialog says the same. The screen itself no longer asks for a session.
    await waitFor(() =>
      expect(
        within(screen.getByRole('main')).queryAllByText(tradeCopy.states.noSession),
      ).toHaveLength(0),
    );
  });
});
