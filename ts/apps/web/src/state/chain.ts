// Health of the user's own RPC ("RPC down or stale": slot unchanged for
// 10 s) and the few JSON-RPC reads the SDK's port does not cover.
import type { TimescalesRpc } from '@timescales/sdk/solana';

import type { Store } from './store';
import { createStore } from './store';

export type RpcHealth = 'ok' | 'degraded' | 'down';

export interface ChainState {
  slot: bigint | null;
  /** When the slot last moved (ms). */
  changedAtMs: number | null;
  health: RpcHealth;
  /** No new slot for STALE_AFTER_MS, or the RPC is not answering. */
  stale: boolean;
}

export interface ChainController {
  readonly state: Store<ChainState>;
  setRpc(rpc: TimescalesRpc): void;
  dispose(): void;
}

export const STALE_AFTER_MS = 10_000;
const POLL_MS = 2_000;

export function createChainController(d: {
  rpc: TimescalesRpc;
  now?: () => number;
  pollMs?: number;
}): ChainController {
  const now = d.now ?? (() => Date.now());
  let rpc = d.rpc;
  const state = createStore<ChainState>({
    slot: null,
    changedAtMs: null,
    health: 'degraded',
    stale: false,
  });
  let failures = 0;
  let busy = false;
  const startedAt = now();

  const poll = async () => {
    if (busy) return;
    busy = true;
    const from = rpc;
    try {
      const slot = await from.slot();
      if (from !== rpc) return;
      failures = 0;
      state.set((s) => {
        const moved = s.slot === null || slot > s.slot;
        const changedAtMs = moved ? now() : (s.changedAtMs ?? now());
        const stale = now() - changedAtMs >= STALE_AFTER_MS;
        return {
          slot: moved ? slot : s.slot,
          changedAtMs,
          stale,
          health: stale ? 'down' : 'ok',
        };
      });
    } catch {
      if (from !== rpc) return;
      failures++;
      state.set((s) => {
        const since = s.changedAtMs ?? startedAt;
        const stale = now() - since >= STALE_AFTER_MS;
        return { ...s, stale, health: failures >= 3 || stale ? 'down' : 'degraded' };
      });
    } finally {
      busy = false;
    }
  };

  void poll();
  const timer = setInterval(() => void poll(), d.pollMs ?? POLL_MS);

  return {
    state,
    setRpc(next) {
      rpc = next;
      failures = 0;
      state.set({ slot: null, changedAtMs: null, health: 'degraded', stale: false });
      void poll();
    },
    dispose() {
      clearInterval(timer);
    },
  };
}

/** `getMinimumBalanceForRentExemption` (open-account pre-check), in lamports. */
export async function rentExemption(
  rpcUrl: string,
  dataLen: number,
  fetchImpl: typeof fetch = fetch,
): Promise<bigint> {
  const res = await fetchImpl(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'getMinimumBalanceForRentExemption',
      params: [dataLen],
    }),
  });
  const body = (await res.json()) as { result?: unknown };
  if (typeof body.result !== 'number' || !Number.isSafeInteger(body.result) || body.result < 0) {
    throw new Error('the RPC returned no rent amount');
  }
  return BigInt(body.result);
}

/** Lamports as SOL with up to 9 decimals, trailing zeros trimmed. */
export function formatSol(lamports: bigint): string {
  const whole = lamports / 1_000_000_000n;
  const frac = (lamports % 1_000_000_000n).toString().padStart(9, '0').replace(/0+$/, '');
  return frac.length > 0 ? `${whole}.${frac}` : whole.toString();
}

/** `getHealth`: whether an RPC endpoint reports itself healthy. */
export async function rpcHealthy(
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  try {
    const res = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getHealth' }),
    });
    const body = (await res.json()) as { result?: unknown };
    return body.result === 'ok';
  } catch {
    return false;
  }
}
