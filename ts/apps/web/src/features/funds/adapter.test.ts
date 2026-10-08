import type { MarketDetail } from '@timescales/sdk/api';
import type { MarketAccount, TimescalesRpc } from '@timescales/sdk/solana';
import { associatedTokenAddress } from '@timescales/sdk/solana';
import type { TraderWallet } from '@timescales/sdk/wallet';
import { describe, expect, it, vi } from 'vitest';

import type { Address } from '../trade/services';
import { chainTokens, createFundsPort, traderRent } from './adapter';
import { NODE_RPC_MISMATCH } from './port';

const addr = (s: string) => s as Address;
const MARKET = addr('SysvarC1ock11111111111111111111111111111111');
const PROGRAM = addr('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const OWNER = addr('Vote111111111111111111111111111111111111111');
const tokens = {
  baseMint: addr('So11111111111111111111111111111111111111112'),
  quoteMint: addr('Stake11111111111111111111111111111111111111'),
  baseVault: addr('Config1111111111111111111111111111111111111'),
  quoteVault: addr('BPFLoaderUpgradeab1e11111111111111111111111'),
};
const OTHER_MINT = addr('SysvarRecentB1ockHashes11111111111111111111');

function chain(over: Partial<MarketAccount> = {}): MarketAccount {
  return {
    address: MARKET,
    ...tokens,
    halted: false,
    lastCommitted: 1n,
    lastSettled: 1n,
    ...over,
  } as MarketAccount;
}

function port(detail: Partial<MarketDetail>, market: MarketAccount) {
  const tokenBalance = vi.fn(() => Promise.resolve(5n));
  const rpc = {
    market: () => Promise.resolve({ value: market, contextSlot: 9n }),
    trader: () => Promise.resolve(null),
    account: () => Promise.resolve({ value: new Uint8Array(0), contextSlot: 9n }),
    tokenBalance,
  } as unknown as TimescalesRpc;
  const api = { market: () => Promise.resolve({ ...tokens, ...detail } as MarketDetail) };
  const wallet = { address: OWNER } as unknown as TraderWallet;
  return { port: createFundsPort({ api, rpc, wallet, program: PROGRAM }), tokenBalance };
}

describe('node and RPC agreement on mints and vaults (V-1)', () => {
  it('reads wallet balances at the mints the RPC names', async () => {
    const { port: p, tokenBalance } = port({}, chain());
    const snap = await p.snapshot(MARKET);
    expect(snap.wallet).toEqual({ base: 5n, quote: 5n });
    expect(tokenBalance.mock.calls.map((c) => (c as unknown[])[0])).toEqual([
      await associatedTokenAddress(OWNER, tokens.baseMint),
      await associatedTokenAddress(OWNER, tokens.quoteMint),
    ]);
  });

  it('refuses a snapshot when the node names another mint', async () => {
    const { port: p, tokenBalance } = port({ quoteMint: OTHER_MINT }, chain());
    await expect(p.snapshot(MARKET)).rejects.toMatchObject({
      kind: 'verify',
      code: NODE_RPC_MISMATCH,
    });
    expect(tokenBalance).not.toHaveBeenCalled();
  });

  it('refuses to build a deposit or withdrawal against a vault the RPC does not confirm', async () => {
    const { port: p } = port({ baseVault: OTHER_MINT }, chain());
    await expect(
      p.build(MARKET, { kind: 'deposit', side: 'base', amount: 1n }),
    ).rejects.toMatchObject({ code: NODE_RPC_MISMATCH });
    await expect(p.build(MARKET, { kind: 'withdraw' })).rejects.toMatchObject({
      code: NODE_RPC_MISMATCH,
    });
  });

  it('returns the chain values when both agree', () => {
    expect(chainTokens({ ...tokens } as MarketDetail, chain())).toEqual(tokens);
  });
});

describe('traderRent', () => {
  it('prices a 148-byte trader account from the Rent sysvar', () => {
    const sysvar = new Uint8Array(17);
    const view = new DataView(sysvar.buffer);
    view.setBigUint64(0, 3480n, true);
    view.setFloat64(8, 2, true);
    sysvar[16] = 50;
    // (128 + 148) * 3480 * 2
    expect(traderRent(sysvar)).toBe(1_920_960n);
  });

  it('gives up on a malformed sysvar', () => {
    expect(traderRent(new Uint8Array(4))).toBeNull();
  });
});
