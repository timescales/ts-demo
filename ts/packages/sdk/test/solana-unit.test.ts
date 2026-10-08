// Solana client pieces: PDAs and ATAs against kit's own
// derivation, account decoders against the account offsets, instruction bytes,
// transactions checked after the wallet signs them, confirmation, program
// failures and the RPC over a mocked JSON-RPC endpoint.
import type { Address, Instruction } from '@solana/kit';
// The SDK confines kit's runtime to three files. This test uses kit's
// own derivation as an independent reference for the hand-written PDAs.
// eslint-disable-next-line @typescript-eslint/no-restricted-imports
import { getProgramDerivedAddress } from '@solana/kit';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  b58,
  b64,
  ed25519PublicKey,
  encodeMarketParams,
  hex,
  paramsDigest,
  u64le,
  utf8,
} from '../src/core/index.js';
import {
  associatedTokenAddress,
  availableFor,
  batchPda,
  buildTraderTx,
  cancelWithdrawRequestIx,
  checkSignedTx,
  closeStatus,
  closeTraderIx,
  computeUnitLimitIx,
  computeUnitPriceIx,
  confirmSignature,
  createAtaIdempotentIx,
  createTimescalesRpc,
  decodeBatchAccount,
  decodeMarketAccount,
  decodeMint,
  decodeProgramData,
  decodeProgramFailure,
  decodeTraderAccount,
  depositIx,
  marketPda,
  openTraderIx,
  requestWithdrawIx,
  revealBeaconIx,
  sendAndConfirm,
  traderPda,
  withdrawIx,
  withdrawStatus,
  type MarketAccount,
  type TimescalesRpc,
  type TraderAccount,
} from '../src/solana/index.js';
import { RPC_EXTRAS, type RpcExtras } from '../src/solana/rpc.js';
import { priorityFee } from '../src/solana/tx.js';
import { createTestWallet, testMarketParams } from '../src/testing/index.js';

const addr = (fill: number): Address => b58.encode(new Uint8Array(32).fill(fill)) as Address;
const PROGRAM = 'FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL' as Address;
const TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const ATA = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const SYSTEM = '11111111111111111111111111111111';

describe('program addresses', () => {
  it('derive the market, trader and batch PDAs and ATAs exactly as kit does', async () => {
    for (let i = 1; i <= 8; i++) {
      const owner = b58.encode(ed25519PublicKey(new Uint8Array(32).fill(i))) as Address;
      const mint = addr(i + 40);
      const id = BigInt(i) * 0x0123_4567_89abn;
      const market = (await marketPda(PROGRAM, id))[0];
      expect(await marketPda(PROGRAM, id)).toEqual(
        await getProgramDerivedAddress({
          programAddress: PROGRAM,
          seeds: [utf8('market'), u64le(id)],
        }),
      );
      expect(await traderPda(PROGRAM, market, owner)).toEqual(
        await getProgramDerivedAddress({
          programAddress: PROGRAM,
          seeds: [utf8('trader'), b58.decode(market, 32), b58.decode(owner, 32)],
        }),
      );
      expect(await batchPda(PROGRAM, market, BigInt(i))).toEqual(
        await getProgramDerivedAddress({
          programAddress: PROGRAM,
          seeds: [utf8('batch'), b58.decode(market, 32), u64le(BigInt(i))],
        }),
      );
      const [ata] = await getProgramDerivedAddress({
        programAddress: ATA as Address,
        seeds: [b58.decode(owner, 32), b58.decode(TOKEN, 32), b58.decode(mint, 32)],
      });
      expect(await associatedTokenAddress(owner, mint)).toBe(ata);
    }
  });
});

// Account bytes laid out from the account offset tables, independently of the decoders.
function marketBytes(m: MarketAccount, o: { bump?: number; layout?: number; tag?: number } = {}) {
  const d = new Uint8Array(1103);
  const v = new DataView(d.buffer);
  d[0] = o.tag ?? 0x21;
  d[1] = o.bump ?? 254;
  d[2] = o.layout ?? 2;
  d[3] = m.halted ? 1 : 0;
  v.setBigUint64(4, m.marketId, true);
  const put = (at: number, a: Address | null) =>
    d.set(a === null ? new Uint8Array(32) : b58.decode(a, 32), at);
  put(12, m.creator);
  put(44, m.admin);
  put(76, m.pendingAdmin);
  put(108, m.relay);
  put(140, m.baseMint);
  put(172, m.quoteMint);
  put(204, m.baseVault);
  put(236, m.quoteVault);
  d.set(encodeMarketParams(m.params), 268);
  d.set(m.paramsDigest, 314);
  d.set(m.committeeDigest, 346);
  d[378] = m.executors.filter((e) => e !== null).length;
  d[379] = m.receiptQuorum;
  m.executors.forEach((e, i) => put(380 + 32 * i, e));
  v.setUint16(636, m.beaconDelaySlots, true);
  v.setBigUint64(638, m.timelockSlots, true);
  v.setBigUint64(646, m.execTimeoutSlots, true);
  v.setBigUint64(654, m.settleTimeoutSlots, true);
  v.setBigUint64(662, m.lastCommitted, true);
  v.setBigUint64(670, m.lastSettled, true);
  v.setBigUint64(678, m.lastProgressSlot, true);
  v.setBigUint64(686, m.feesAccrued, true);
  v.setBigUint64(694, m.feesClaimed, true);
  d.set(m.prevReceipt, 702);
  d.set(m.stateRoot, 734);
  d.set(m.salt, 1039);
  if (m.prevCommitteeDigest !== null) d.set(m.prevCommitteeDigest, 1071);
  return d;
}

function setPending(d: Uint8Array, kind: number, eta: bigint, payload: Uint8Array): Uint8Array {
  const v = new DataView(d.buffer);
  d[766] = kind;
  v.setBigUint64(767, eta, true);
  v.setUint16(775, payload.length, true);
  d.set(payload, 777);
  return d;
}

function sampleMarket(): MarketAccount {
  const params = testMarketParams({ market: 77n });
  return {
    address: addr(1),
    marketId: 77n,
    salt: new Uint8Array(32).fill(2),
    creator: addr(3),
    admin: addr(4),
    pendingAdmin: null,
    relay: addr(5),
    baseMint: addr(6),
    quoteMint: addr(7),
    baseVault: addr(8),
    quoteVault: addr(9),
    params,
    paramsDigest: paramsDigest(params),
    committeeDigest: new Uint8Array(32).fill(10),
    prevCommitteeDigest: null,
    executors: [addr(11), null, addr(12), null, null, null, null, null],
    receiptQuorum: 2,
    halted: true,
    beaconDelaySlots: 8,
    timelockSlots: 216_000n,
    execTimeoutSlots: 750n,
    settleTimeoutSlots: 9_000n,
    lastCommitted: 41n,
    lastSettled: 40n,
    lastProgressSlot: 1234n,
    feesAccrued: 5n,
    feesClaimed: 1n,
    prevReceipt: new Uint8Array(32).fill(13),
    stateRoot: new Uint8Array(32).fill(14),
    pending: null,
  };
}

function sampleTrader(t: Partial<TraderAccount> = {}): TraderAccount {
  return {
    address: addr(20),
    market: addr(1),
    owner: addr(21),
    base: 1000n,
    quote: 5000n,
    requestedBase: 0n,
    requestedQuote: 0n,
    requestEpoch: 0n,
    lastLeafEpoch: 0n,
    lastChangeSlot: 9n,
    floorEpoch: 0n,
    floorBase: 0n,
    floorQuote: 0n,
    ...t,
  };
}

function traderBytes(t: TraderAccount): Uint8Array {
  const d = new Uint8Array(148);
  const v = new DataView(d.buffer);
  d[0] = 0x22;
  d[1] = 255;
  d[2] = 2;
  d.set(b58.decode(t.market, 32), 4);
  d.set(b58.decode(t.owner, 32), 36);
  [
    t.base,
    t.quote,
    t.requestedBase,
    t.requestedQuote,
    t.requestEpoch,
    t.lastLeafEpoch,
    t.lastChangeSlot,
    t.floorEpoch,
    t.floorBase,
    t.floorQuote,
  ].forEach((x, i) => v.setBigUint64(68 + 8 * i, x, true));
  return d;
}

describe('account decoders', () => {
  it('decode the Market account at the offsets', () => {
    const m = sampleMarket();
    expect(decodeMarketAccount(m.address, marketBytes(m))).toEqual(m);
    const withPrev = {
      ...m,
      prevCommitteeDigest: new Uint8Array(32).fill(15),
      pendingAdmin: addr(16),
    };
    expect(decodeMarketAccount(m.address, marketBytes(withPrev))).toEqual(withPrev);
    expect(() => decodeMarketAccount(m.address, marketBytes(m).subarray(0, 1102))).toThrow(/1103/);
    expect(() => decodeMarketAccount(m.address, marketBytes(m, { tag: 0x11 }))).toThrow(/tag/);
    expect(() => decodeMarketAccount(m.address, marketBytes(m, { layout: 1 }))).toThrow(/layout/);
  });

  it('decode every pending change kind, strictly', () => {
    const m = sampleMarket();
    const set = decodeMarketAccount(
      m.address,
      setPending(marketBytes(m), 1, 500n, b58.decode(addr(30), 32)),
    );
    expect(set.pending).toEqual({ kind: 'set_relay', etaSlot: 500n, due: false, relay: addr(30) });
    const execs = new Uint8Array([1, ...b58.decode(addr(31), 32), 1]);
    expect(
      decodeMarketAccount(m.address, setPending(marketBytes(m), 2, 9n, execs)).pending,
    ).toMatchObject({
      kind: 'set_executors',
      executors: [addr(31)],
      quorum: 1,
      quorumDecrease: true,
    });
    expect(() =>
      decodeMarketAccount(m.address, setPending(marketBytes(m), 1, 9n, new Uint8Array(33))),
    ).toThrow();
    expect(() =>
      decodeMarketAccount(m.address, setPending(marketBytes(m), 9, 9n, new Uint8Array(0))),
    ).toThrow();
  });

  it('decode Trader and Batch accounts', () => {
    const t = sampleTrader({
      requestedQuote: 7n,
      requestEpoch: 3n,
      floorEpoch: 4n,
      floorBase: 2n,
      floorQuote: 1n,
    });
    expect(decodeTraderAccount(t.address, traderBytes(t))).toEqual(t);
    expect(() => decodeTraderAccount(t.address, new Uint8Array(148))).toThrow();

    const d = new Uint8Array(688);
    const v = new DataView(d.buffer);
    d[0] = 0x23;
    d[2] = 2;
    d[3] = 6;
    d[4] = 6;
    d[5] = 2;
    d[6] = 0b101;
    d.set(b58.decode(addr(1), 32), 8);
    v.setBigUint64(40, 12n, true);
    d.set(new Uint8Array(32).fill(3), 48);
    v.setUint32(80, 17, true);
    v.setBigUint64(116, 1000n, true);
    v.setBigUint64(124, 1004n, true);
    v.setBigUint64(132, 1008n, true);
    d.set(new Uint8Array(32).fill(4), 140);
    v.setBigUint64(172, 1010n, true);
    v.setUint32(348, 5, true);
    v.setBigUint64(352, 99n, true);
    v.setUint32(360, 5, true);
    v.setUint32(364, 0, true);
    const b = decodeBatchAccount(addr(40), d);
    expect(b).toMatchObject({
      status: 'aborted',
      abortReason: 'quorum_timeout',
      cosignCount: 2,
      cosignBitmap: 5,
      epoch: 12n,
      count: 17,
      commitSlot: 1000n,
      beaconSlots: [1004n, 1008n],
      revealSlot: 1010n,
      receiptSlot: null,
      headerDigest: null,
      settlementCount: 5,
      fees: 99n,
      verifiedCount: 5,
      appliedCount: 0,
    });
    d[3] = 7;
    expect(() => decodeBatchAccount(addr(40), d)).toThrow(/status/);
  });

  it('decode mints and ProgramData', () => {
    const mint = (tag: number, initialized: number) => {
      const d = new Uint8Array(82);
      const v = new DataView(d.buffer);
      v.setUint32(0, 1, true);
      d.set(new Uint8Array(32).fill(1), 4);
      v.setBigUint64(36, 10n ** 9n, true);
      d[44] = 6;
      d[45] = initialized;
      v.setUint32(46, tag, true);
      d.set(new Uint8Array(32).fill(2), 50);
      return d;
    };
    expect(decodeMint(mint(1, 1))).toEqual({
      decimals: 6,
      mintAuthority: addr(1),
      freezeAuthority: addr(2),
    });
    expect(decodeMint(mint(0, 1)).freezeAuthority).toBeNull();
    expect(() => decodeMint(mint(2, 1))).toThrow();
    expect(() => decodeMint(mint(0, 0))).toThrow(/initialized/);
    expect(() => decodeMint(new Uint8Array(83))).toThrow();

    const pd = new Uint8Array(45 + 100);
    new DataView(pd.buffer).setUint32(0, 3, true);
    new DataView(pd.buffer).setBigUint64(4, 777n, true);
    pd[12] = 1;
    pd.set(new Uint8Array(32).fill(9), 13);
    expect(decodeProgramData(pd)).toEqual({ upgradeAuthority: addr(9), lastDeploySlot: 777n });
    pd[12] = 0;
    expect(decodeProgramData(pd).upgradeAuthority).toBeNull();
    pd[0] = 2;
    expect(() => decodeProgramData(pd)).toThrow();
    expect(() => decodeProgramData(new Uint8Array(44))).toThrow();
  });
});

describe('withdrawals and closing', () => {
  const m = sampleMarket();

  it('reserve a pending request from the next batch on', () => {
    const t = sampleTrader({ requestedBase: 300n, requestedQuote: 9000n, requestEpoch: 41n });
    expect(availableFor(t, 41n)).toEqual({ base: 1000n, quote: 5000n });
    expect(availableFor(t, 42n)).toEqual({ base: 700n, quote: 0n });
  });

  it('unlock once the batch in flight at request time is terminal', () => {
    const t = sampleTrader({ requestedBase: 300n, requestedQuote: 9000n, requestEpoch: 41n });
    expect(withdrawStatus(m, t)).toEqual({
      withdrawable: false,
      reason: 'locked',
      unlocksAfterEpoch: 41n,
      payoutUpTo: { base: 300n, quote: 5000n },
    });
    expect(withdrawStatus({ ...m, lastSettled: 41n }, t).withdrawable).toBe(true);
    expect(withdrawStatus(m, sampleTrader()).reason).toBe('none');
  });

  it('close only empty accounts without a leaf in the batch in flight', () => {
    const empty = sampleTrader({ base: 0n, quote: 0n });
    expect(closeStatus(m, sampleTrader())).toEqual({ closable: false, reason: 'not_empty' });
    expect(closeStatus(m, { ...empty, lastLeafEpoch: 41n })).toEqual({
      closable: false,
      reason: 'leaf_in_flight',
      availableAfterEpoch: 41n,
    });
    expect(closeStatus(m, { ...empty, lastLeafEpoch: 40n })).toEqual({
      closable: true,
      reason: 'ok',
    });
    expect(closeStatus({ ...m, lastSettled: 41n }, { ...empty, lastLeafEpoch: 41n }).closable).toBe(
      true,
    );
  });
});

describe('instructions', () => {
  const owner = addr(50);
  const market = addr(51);

  it('encode trader instructions with their accounts and roles', async () => {
    const [trader] = await traderPda(PROGRAM, market, owner);
    const roles = (ix: Instruction) => (ix.accounts ?? []).map((a) => [a.address, a.role]);
    const open = await openTraderIx({ program: PROGRAM, owner, market });
    expect([...open.data!]).toEqual([1]);
    expect(roles(open)).toEqual([
      [owner, 3],
      [market, 0],
      [trader, 1],
      ['11111111111111111111111111111111', 0],
    ]);
    const dep = await depositIx({
      program: PROGRAM,
      owner,
      market,
      source: addr(52),
      vault: addr(53),
      side: 'quote',
      amount: 258n,
    });
    expect(hex.encode(new Uint8Array(dep.data!))).toBe('02010201000000000000');
    expect(roles(dep).map((r) => r[1])).toEqual([2, 0, 1, 1, 1, 0]);
    await expect(
      depositIx({
        program: PROGRAM,
        owner,
        market,
        source: addr(52),
        vault: addr(53),
        side: 'base',
        amount: 0n,
      }),
    ).rejects.toThrow();
    const req = await requestWithdrawIx({ program: PROGRAM, owner, market, base: 1n, quote: 2n });
    expect(hex.encode(new Uint8Array(req.data!))).toBe(
      `03${'0100000000000000'}${'0200000000000000'}`,
    );
    await expect(
      requestWithdrawIx({ program: PROGRAM, owner, market, base: 0n, quote: 0n }),
    ).rejects.toThrow();
    expect([...(await cancelWithdrawRequestIx({ program: PROGRAM, owner, market })).data!]).toEqual(
      [14],
    );
    const wd = await withdrawIx({
      program: PROGRAM,
      owner,
      market,
      vault: addr(53),
      dest: addr(54),
      side: 'base',
    });
    expect([...wd.data!]).toEqual([4, 0]);
    expect(roles(wd).map((r) => r[1])).toEqual([2, 0, 1, 1, 1, 0]);
    const close = await closeTraderIx({ program: PROGRAM, owner, market });
    expect([...close.data!]).toEqual([23]);
    expect(roles(close)).toEqual([
      [owner, 3],
      [market, 0],
      [trader, 1],
    ]);
    const reveal = await revealBeaconIx({ program: PROGRAM, cranker: owner, market, epoch: 9n });
    expect([...reveal.data!]).toEqual([12]);
    expect(roles(reveal)).toEqual([
      [owner, 2],
      [market, 0],
      [(await batchPda(PROGRAM, market, 9n))[0], 1],
      ['SysvarS1otHashes111111111111111111111111111', 0],
    ]);
  });

  it('build ATA and compute-budget instructions by hand', async () => {
    const ix = await createAtaIdempotentIx({ payer: addr(60), owner: addr(61), mint: addr(62) });
    expect(ix.programAddress).toBe(ATA);
    expect([...ix.data!]).toEqual([1]);
    expect((ix.accounts ?? []).map((a) => a.role)).toEqual([3, 1, 0, 0, 0, 0]);
    expect(ix.accounts![1]!.address).toBe(await associatedTokenAddress(addr(61), addr(62)));
    expect(hex.encode(new Uint8Array(computeUnitLimitIx(200_000).data!))).toBe('02400d0300');
    expect(hex.encode(new Uint8Array(computeUnitPriceIx(5n).data!))).toBe('030500000000000000');
    expect(computeUnitPriceIx(5n).programAddress).toBe(
      'ComputeBudget111111111111111111111111111111',
    );
  });
});

describe('program failures', () => {
  it('attributes failures to the failing program, CPIs included', () => {
    const logs = (lines: string[]) => lines;
    expect(
      decodeProgramFailure(
        logs([
          'Program ComputeBudget111111111111111111111111111111 invoke [1]',
          'Program ComputeBudget111111111111111111111111111111 success',
          `Program ${PROGRAM} invoke [1]`,
          `Program ${PROGRAM} failed: custom program error: 0x1781`,
        ]),
        PROGRAM,
      ),
    ).toEqual({ program: 'settlement', code: 6017, name: 'WithdrawLocked', instructionIndex: 1 });
    expect(
      decodeProgramFailure(
        logs([
          `Program ${PROGRAM} invoke [1]`,
          `Program ${TOKEN} invoke [2]`,
          `Program ${TOKEN} failed: custom program error: 0x1`,
          `Program ${PROGRAM} failed: custom program error: 0x1`,
        ]),
        PROGRAM,
      ),
    ).toEqual({ program: 'token', code: 1, name: 'InsufficientFunds', instructionIndex: 0 });
    expect(
      decodeProgramFailure(
        logs([
          `Program 11111111111111111111111111111111 invoke [1]`,
          'Program 11111111111111111111111111111111 failed: custom program error: 0x0',
        ]),
        PROGRAM,
      ),
    ).toEqual({ program: 'system', code: 0, name: 'AccountAlreadyInUse', instructionIndex: 0 });
    expect(
      decodeProgramFailure(
        [
          `Program ${PROGRAM} invoke [1]`,
          `Program ${PROGRAM} failed: invalid account data for instruction`,
        ],
        PROGRAM,
      ),
    ).toEqual({
      program: 'settlement',
      code: -1,
      name: 'invalid account data for instruction',
      instructionIndex: 0,
    });
    expect(
      decodeProgramFailure(
        [`Program ${PROGRAM} invoke [1]`, `Program ${PROGRAM} success`],
        PROGRAM,
      ),
    ).toBeNull();
  });
});

/** A TimescalesRpc whose transaction calls are scripted. */
function scriptedRpc(
  o: Partial<RpcExtras> = {},
): TimescalesRpc & { [RPC_EXTRAS]: RpcExtras; sent: Uint8Array[] } {
  const sent: Uint8Array[] = [];
  const blockhash = b58.encode(new Uint8Array(32).fill(0x17));
  const extras: RpcExtras = {
    accountInfo: () => Promise.resolve(null),
    latestBlockhash: () => Promise.resolve({ blockhash, lastValidBlockHeight: 900n }),
    sendTransaction: (wire) => {
      sent.push(wire);
      return Promise.resolve('sig');
    },
    signatureStatus: () => Promise.resolve(null),
    blockHeight: () => Promise.resolve(850n),
    transactionLogs: () => Promise.resolve(null),
    recentPrioritizationFees: () => Promise.resolve([]),
    minimumBalanceForRentExemption: () => Promise.resolve(0n),
    balance: () => Promise.resolve(0n),
    ...o,
  };
  const never = () => Promise.reject(new Error('not scripted'));
  return {
    [RPC_EXTRAS]: extras,
    sent,
    market: never,
    trader: never,
    batch: never,
    account: never,
    tokenBalance: never,
    slot: never,
    genesisHash: never,
    blockTime: never,
  };
}

describe('transactions', () => {
  const seed = new Uint8Array(32).fill(0x33);
  const owner = b58.encode(ed25519PublicKey(seed)) as Address;

  async function built(rpc: TimescalesRpc, extra: Instruction[] = []) {
    const ixs = [...extra, await openTraderIx({ program: PROGRAM, owner, market: addr(51) })];
    return buildTraderTx({ rpc, feePayer: owner, instructions: ixs, priorityMicroLamports: 10n });
  }

  it('accepts what an honest wallet returns, including added compute-budget instructions', async () => {
    const rpc = scriptedRpc();
    const { wire, lastValidBlockHeight } = await built(rpc);
    expect(lastValidBlockHeight).toBe(900n);
    const honest = createTestWallet({ seed });
    const signed = await honest.signTransaction!(wire);
    expect(checkSignedTx(wire, signed)).toEqual({
      kind: 'ok',
      value: { lastValidBlockHeight: 900n },
    });
    const budgeted = await honest.signTransaction!(
      (await built(rpc, [computeUnitLimitIx(50_000)])).wire,
    );
    expect(checkSignedTx(wire, budgeted).kind).toBe('ok');
  });

  it('refuses a rewritten, unsigned or foreign transaction', async () => {
    const rpc = scriptedRpc();
    const { wire } = await built(rpc);
    const mutating = createTestWallet({ seed, behaviour: 'tx_mutating' });
    expect(checkSignedTx(wire, await mutating.signTransaction!(wire))).toMatchObject({
      kind: 'fail',
    });
    expect(checkSignedTx(wire, wire)).toMatchObject({
      kind: 'fail',
      reason: expect.stringMatching(/not signed/),
    });
    const other = createTestWallet({ seed: new Uint8Array(32).fill(0x34) });
    const foreign = await buildTraderTx({
      rpc,
      feePayer: other.address,
      instructions: [await openTraderIx({ program: PROGRAM, owner, market: addr(51) })],
    });
    expect(checkSignedTx(wire, await other.signTransaction!(foreign.wire))).toMatchObject({
      kind: 'fail',
      reason: expect.stringMatching(/fee payer/),
    });
    expect(checkSignedTx(wire, new Uint8Array(3)).kind).toBe('fail');
  });

  it('sends, re-broadcasts and confirms; reports failures and expiry', async () => {
    vi.useFakeTimers();
    try {
      const honest = createTestWallet({ seed });
      let polls = 0;
      const rpc = scriptedRpc({
        signatureStatus: () => {
          polls++;
          return Promise.resolve(
            polls < 4 ? null : { slot: 77n, confirmationStatus: 'confirmed' as const, err: null },
          );
        },
      });
      const signed = await honest.signTransaction!((await built(rpc)).wire);
      const pending = sendAndConfirm(rpc, signed, 900n);
      await vi.advanceTimersByTimeAsync(5_000);
      const result = await pending;
      expect(result).toMatchObject({ status: 'confirmed', slot: 77n });
      expect(rpc.sent.length).toBeGreaterThanOrEqual(2);
      expect(rpc.sent.every((w) => hex.encode(w) === hex.encode(signed))).toBe(true);

      const failing = scriptedRpc({
        signatureStatus: () =>
          Promise.resolve({
            slot: 5n,
            confirmationStatus: 'processed' as const,
            err: { InstructionError: [1, { Custom: 6019 }] },
          }),
        transactionLogs: () =>
          Promise.resolve([
            'Program ComputeBudget111111111111111111111111111111 invoke [1]',
            'Program ComputeBudget111111111111111111111111111111 success',
            `Program ${PROGRAM} invoke [1]`,
            `Program ${PROGRAM} failed: custom program error: 0x1783`,
          ]),
      });
      expect(await confirmSignature(failing, 'sig', 900n)).toEqual({
        status: 'failed',
        signature: 'sig',
        failure: { program: 'settlement', code: 6019, name: 'Halted', instructionIndex: 1 },
      });

      // Only the program buildTraderTx built for is the settlement program: an
      // instruction a wallet added (here one that runs first and fails) is not.
      const added = addr(77);
      const guarded = scriptedRpc({
        signatureStatus: () =>
          Promise.resolve({
            slot: 5n,
            confirmationStatus: 'processed' as const,
            err: { InstructionError: [0, { Custom: 6019 }] },
          }),
        transactionLogs: () =>
          Promise.resolve([
            `Program ${added} invoke [1]`,
            `Program ${added} failed: custom program error: 0x1783`,
          ]),
      });
      expect(await confirmSignature(guarded, 'sig', 900n)).toEqual({
        status: 'failed',
        signature: 'sig',
        failure: { program: 'other', code: 6019, name: null, instructionIndex: 0 },
      });

      const expiring = scriptedRpc({ blockHeight: () => Promise.resolve(901n) });
      expect(await confirmSignature(expiring, 'sig', 900n)).toEqual({
        status: 'expired',
        signature: 'sig',
      });

      const ac = new AbortController();
      const waiting = confirmSignature(scriptedRpc(), 'sig', 900n, ac.signal);
      // Attached before the timers run, so the rejection is never unhandled.
      const refused = expect(waiting).rejects.toMatchObject({ kind: 'aborted' });
      ac.abort();
      await vi.advanceTimersByTimeAsync(1_000);
      await refused;
    } finally {
      vi.useRealTimers();
    }
  });

  it('picks the p75 priority fee under the cap', async () => {
    const rpc = scriptedRpc({
      recentPrioritizationFees: () => Promise.resolve([5n, 1n, 9n, 3n, 7n, 2n, 8n, 4n]),
    });
    expect(await priorityFee(rpc, [addr(1)], 100n)).toBe(7n);
    expect(await priorityFee(rpc, [addr(1)], 6n)).toBe(6n);
    expect(await priorityFee(scriptedRpc(), [addr(1)], 6n)).toBe(0n);
  });
});

describe('createTimescalesRpc', () => {
  const url = 'http://rpc.timescales.test';
  const accounts = new Map<string, { owner: string; data: Uint8Array }>();
  const slot = 500;
  const server = setupServer(
    http.post(url, async ({ request }) => {
      const req = (await request.json()) as { id: number; method: string; params: unknown[] };
      const reply = (result: unknown) => HttpResponse.json({ jsonrpc: '2.0', id: req.id, result });
      const error = (code: number, message: string) =>
        HttpResponse.json({ jsonrpc: '2.0', id: req.id, error: { code, message } });
      switch (req.method) {
        case 'getAccountInfo': {
          const cfg = (req.params[1] ?? {}) as { minContextSlot?: number };
          if (cfg.minContextSlot !== undefined && cfg.minContextSlot > slot) {
            return error(-32016, 'Minimum context slot has not been reached');
          }
          const a = accounts.get(req.params[0] as string);
          return reply({
            context: { slot },
            value:
              a === undefined
                ? null
                : {
                    data: [b64.encode(a.data), 'base64'],
                    executable: false,
                    lamports: 10,
                    owner: a.owner,
                    rentEpoch: 0,
                    space: a.data.length,
                  },
          });
        }
        case 'getGenesisHash':
          return reply(b58.encode(new Uint8Array(32).fill(0x0f)));
        case 'getSlot':
          return reply(slot);
        case 'getBlockTime':
          return req.params[0] === 1 ? error(-32007, 'Slot 1 was skipped') : reply(1_700_000_000);
        default:
          return error(-32601, 'method not found');
      }
    }),
  );
  beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
  afterEach(() => accounts.clear());
  afterAll(() => server.close());

  it('reads and decodes accounts at their PDAs, slot-aware', async () => {
    const m = sampleMarket();
    const [address, bump] = await marketPda(PROGRAM, m.marketId);
    accounts.set(address, { owner: PROGRAM, data: marketBytes({ ...m, address }, { bump }) });
    const rpc = createTimescalesRpc(url);
    const read = await rpc.market(address);
    expect(read.contextSlot).toBe(500n);
    expect(read.value).toEqual({ ...m, address });
    await expect(rpc.market(address, 600n)).rejects.toMatchObject({
      code: 'min_context_slot_not_reached',
      retryable: true,
    });
    // The same bytes owned by another program are not its PDA.
    accounts.set(address, { owner: TOKEN, data: marketBytes({ ...m, address }, { bump }) });
    await expect(rpc.market(address)).rejects.toMatchObject({ code: 'account_not_pda' });
    await expect(rpc.market(addr(99))).rejects.toMatchObject({ code: 'account_missing' });
    const t = sampleTrader({ market: address });
    const [ta, tb] = await traderPda(PROGRAM, address, t.owner);
    const bytes = traderBytes({ ...t, address: ta });
    bytes[1] = tb;
    accounts.set(ta, { owner: PROGRAM, data: bytes });
    expect((await rpc.trader(ta))?.value).toEqual({ ...t, address: ta });
    expect(await rpc.trader(addr(98))).toBeNull();
    expect(await rpc.genesisHash()).toBe(b58.encode(new Uint8Array(32).fill(0x0f)));
    expect(await rpc.slot()).toBe(500n);
    expect(await rpc.blockTime(2n)).toBe(1_700_000_000_000);
    expect(await rpc.blockTime(1n)).toBeNull();
  });

  it('reads lamports sent to a program address before the program created it as no account', async () => {
    const m = sampleMarket();
    const [market] = await marketPda(PROGRAM, m.marketId);
    const [trader] = await traderPda(PROGRAM, market, addr(7));
    const [batch] = await batchPda(PROGRAM, market, 9n);
    // What anyone can create by a transfer, and what closing an account leaves.
    for (const a of [market, trader, batch]) {
      accounts.set(a, { owner: SYSTEM, data: new Uint8Array(0) });
    }
    const rpc = createTimescalesRpc(url);
    expect(await rpc.trader(trader)).toBeNull();
    expect(await rpc.batch(batch)).toBeNull();
    await expect(rpc.market(market)).rejects.toMatchObject({ code: 'account_missing' });
    // Data at the address is not the program's to ignore: it fails to decode.
    accounts.set(batch, { owner: SYSTEM, data: new Uint8Array(688) });
    await expect(rpc.batch(batch)).rejects.toMatchObject({ name: 'DecodeError' });
  });
});
