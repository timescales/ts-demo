import { z } from 'zod';
import { describe, expect, it, vi } from 'vitest';

const ENTRIES: [string, () => Promise<Record<string, unknown>>][] = [
  ['@timescales/sdk', () => import('../src/index.js')],
  ['core', () => import('../src/core/index.js')],
  ['verify', () => import('../src/verify/index.js')],
  ['api', () => import('../src/api/index.js')],
  ['solana', () => import('../src/solana/index.js')],
  ['wallet', () => import('../src/wallet/index.js')],
  ['journal', () => import('../src/journal/index.js')],
  ['orders', () => import('../src/orders/index.js')],
  ['testing', () => import('../src/testing/index.js')],
];

describe('entry points', () => {
  it.each(ENTRIES)('%s loads and turns off zod’s JIT', async (_name, load) => {
    vi.resetModules();
    z.config({ jitless: false });
    const mod = await load();
    expect(Object.keys(mod).length).toBeGreaterThan(0);
    expect(z.config().jitless).toBe(true);
  });

  it('the API client is implemented, not a stub', async () => {
    const { TimescalesApi } = await import('../src/api/client.js');
    expect(() => new TimescalesApi({ baseUrl: 'http://localhost' })).not.toThrow();
  });
});
