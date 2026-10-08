// Test-only: renders the whole app (shell and routes) on a memory router
// with a runtime the test controls.
import type { TimescalesRpc } from '@timescales/sdk/solana';
import { act, cleanup, render } from '@testing-library/react';
import { createMemoryRouter } from 'react-router';

import { appRoutes } from '../../routes/routes';
import { resetWelcome, updateWelcome } from '../../state/firstRun';
import type { Runtime, RuntimeOptions } from '../../state/runtime';
import { createRuntime } from '../../state/runtime';
import { resetSettings } from '../../state/settings';
import { AppProviders } from '../App';
import type { AppConfig } from '../config';
import { readConfig } from '../config';

/** happy-dom's page origin: same-origin requests need no CORS preflight. */
export const API = 'http://localhost:3000';
export const STREAM = 'ws://localhost:3000/v1/stream';

/** An RPC that answers a moving slot and nothing else (no chain behind it). */
export function slotOnlyRpc(start = 361_200_100n): TimescalesRpc & { slotNow: bigint } {
  const rpc = {
    slotNow: start,
    async slot() {
      rpc.slotNow += 1n;
      return rpc.slotNow;
    },
    market: () => Promise.reject(new Error('no chain in this test')),
    trader: () => Promise.resolve(null),
    batch: () => Promise.resolve(null),
    account: () => Promise.resolve(null),
    tokenBalance: () => Promise.resolve(0n),
    genesisHash: () => Promise.reject(new Error('no chain in this test')),
    blockTime: () => Promise.resolve(null),
  };
  return rpc;
}

export function testConfig(patch: Partial<AppConfig> = {}): AppConfig {
  return {
    ...readConfig({ VITE_CLUSTER: 'localnet' }),
    apiBaseUrl: API,
    streamUrl: STREAM,
    // Fixture markets are not pinned: the fixtures are shapes, not a chain.
    markets: [],
    ...patch,
  };
}

export interface RenderedApp {
  runtime: Runtime;
  router: ReturnType<typeof createMemoryRouter>;
  unmount(): void;
}

export function renderApp(
  path: string,
  o: { config?: AppConfig; runtime?: RuntimeOptions; welcomed?: boolean } = {},
): RenderedApp {
  if (o.welcomed !== false) updateWelcome({ done: true });
  const rpc = slotOnlyRpc();
  const runtime = createRuntime(o.config ?? testConfig(), {
    rpc: () => rpc,
    clockSync: false,
    ...o.runtime,
  });
  const router = createMemoryRouter(appRoutes(), { initialEntries: [path] });
  const view = render(<AppProviders runtime={runtime} router={router} />);
  return {
    runtime,
    router,
    unmount() {
      view.unmount();
      runtime.dispose();
    },
  };
}

/** Forgets what a test stored in this window. */
export function resetAppState(): void {
  cleanup();
  try {
    localStorage.clear();
  } catch {
    // no storage in this environment
  }
  resetSettings();
  resetWelcome();
  document.documentElement.removeAttribute('data-theme');
  document.documentElement.removeAttribute('data-palette');
  document.documentElement.removeAttribute('data-motion');
}

export async function flush(ms = 0): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, ms));
  });
}
