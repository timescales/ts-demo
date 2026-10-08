import { afterEach, describe, expect, it, vi } from 'vitest';

import { slotOnlyRpc } from '../app/testing/renderApp';
import { STALE_AFTER_MS, createChainController, formatSol } from './chain';

afterEach(() => {
  vi.useRealTimers();
});

describe('RPC freshness ( "slot unchanged 10 s")', () => {
  it('is healthy while the slot moves and stale once it stops', async () => {
    vi.useFakeTimers();
    let t = 0;
    const rpc = slotOnlyRpc(100n);
    let moving = true;
    const slot = rpc.slot.bind(rpc);
    rpc.slot = async () => (moving ? slot() : rpc.slotNow);
    const chain = createChainController({ rpc, now: () => t, pollMs: 1_000 });
    await vi.advanceTimersByTimeAsync(0);
    expect(chain.state.get()).toMatchObject({ health: 'ok', stale: false });
    moving = false;
    for (let i = 0; i < 9; i++) {
      t += 1_000;
      await vi.advanceTimersByTimeAsync(1_000);
    }
    expect(chain.state.get().stale).toBe(false);
    t += STALE_AFTER_MS;
    await vi.advanceTimersByTimeAsync(1_000);
    expect(chain.state.get()).toMatchObject({ health: 'down', stale: true });
    moving = true;
    await vi.advanceTimersByTimeAsync(1_000);
    expect(chain.state.get()).toMatchObject({ health: 'ok', stale: false });
    chain.dispose();
  });

  it('marks an RPC that keeps failing down', async () => {
    vi.useFakeTimers();
    const rpc = slotOnlyRpc();
    rpc.slot = () => Promise.reject(new Error('down'));
    const chain = createChainController({ rpc, pollMs: 1_000 });
    await vi.advanceTimersByTimeAsync(3_000);
    expect(chain.state.get().health).toBe('down');
    chain.dispose();
  });

  it('formats lamports as SOL exactly', () => {
    expect(formatSol(1_920_960n)).toBe('0.00192096');
    expect(formatSol(2_000_000_000n)).toBe('2');
  });
});
