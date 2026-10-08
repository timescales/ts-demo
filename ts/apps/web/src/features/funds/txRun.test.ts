import type { TxResult } from '@timescales/sdk/solana';
import { describe, expect, it, vi } from 'vitest';

import { fundsCopy } from './copy';
import type { FundsPort } from './port';
import type { TxProgress } from './txRun';
import { programErrorMessage, runTx } from './txRun';

const MARKET = 'Market1111111111111111111111111111111111111' as never;
const built = { wire: new Uint8Array([1]), lastValidBlockHeight: 100n };

function port(over: Partial<FundsPort> = {}): FundsPort {
  return {
    snapshot: vi.fn(),
    build: vi.fn(() => Promise.resolve(built)),
    sign: vi.fn(() => Promise.resolve({ kind: 'signed' as const, wire: new Uint8Array([2]) })),
    checkSigned: vi.fn(() => ({ kind: 'ok' as const, value: { lastValidBlockHeight: null } })),
    send: vi.fn(() =>
      Promise.resolve<TxResult>({ status: 'confirmed', signature: 'sig', slot: 1n }),
    ),
    ...over,
  };
}

async function run(p: FundsPort, unlockEpoch: bigint | null = null) {
  const steps: TxProgress[] = [];
  const outcome = await runTx(p, MARKET, { kind: 'withdraw' }, (s) => steps.push(s), {
    unlockEpoch,
  });
  return { outcome, steps: steps.map((s) => s.step) };
}

describe('runTx', () => {
  it('signs, sends and confirms', async () => {
    const { outcome, steps } = await run(port());
    expect(outcome).toEqual({ kind: 'confirmed', signature: 'sig' });
    expect(steps).toEqual(['build', 'sign', 'send', 'done']);
  });

  it('refuses a transaction the wallet rewrote, before anything is sent', async () => {
    const p = port({
      checkSigned: vi.fn(() => ({ kind: 'fail' as const, reason: 'instructions changed' })),
    });
    const { outcome } = await run(p);
    expect(outcome).toMatchObject({ kind: 'failed', message: fundsCopy.tx.rewritten });
    expect(p.send).not.toHaveBeenCalled();
  });

  it('decodes a program error, naming the epoch a locked withdrawal waits for', async () => {
    const p = port({
      send: vi.fn(() =>
        Promise.resolve<TxResult>({
          status: 'failed',
          signature: 'sig',
          failure: {
            program: 'settlement',
            code: 6017,
            name: 'WithdrawLocked',
            instructionIndex: 1,
          },
        }),
      ),
    });
    const { outcome } = await run(p, 42n);
    expect(outcome).toEqual({
      kind: 'failed',
      message: fundsCopy.tx.failed('Withdrawal locked until epoch #42 is settled.'),
      signature: 'sig',
      retry: true,
    });
  });

  it('reports an expired transaction as changing nothing', async () => {
    const p = port({
      send: vi.fn(() => Promise.resolve<TxResult>({ status: 'expired', signature: 's' })),
    });
    expect((await run(p)).outcome).toMatchObject({ message: fundsCopy.tx.expired, retry: true });
  });

  it('skips the check when the wallet sent the transaction itself', async () => {
    const p = port({
      sign: vi.fn(() => Promise.resolve({ kind: 'sent' as const, signature: 'w' })),
    });
    await run(p);
    expect(p.checkSigned).not.toHaveBeenCalled();
    expect(p.send).toHaveBeenCalledWith({ kind: 'sent', signature: 'w' }, built, undefined);
  });

  it('a declined signature sends nothing and can be retried', async () => {
    const p = port({
      sign: vi.fn(() =>
        Promise.reject(Object.assign(new Error('no'), { kind: 'wallet', code: 'rejected' })),
      ),
    });
    expect((await run(p)).outcome).toEqual({
      kind: 'failed',
      message: fundsCopy.tx.rejected,
      signature: null,
      retry: true,
    });
    expect(p.send).not.toHaveBeenCalled();
  });
});

describe('programErrorMessage', () => {
  it('attributes token and system failures by program', () => {
    expect(
      programErrorMessage(
        { program: 'system', code: 1, name: 'ResultWithNegativeLamports', instructionIndex: 0 },
        null,
      ),
    ).toBe(fundsCopy.tx.insufficientSol);
    expect(
      programErrorMessage(
        { program: 'token', code: 1, name: 'InsufficientFunds', instructionIndex: 0 },
        null,
      ),
    ).toBe(fundsCopy.programErrors.InsufficientFunds);
    expect(
      programErrorMessage({ program: 'other', code: 3, name: null, instructionIndex: 0 }, null),
    ).toBe('Error (other program, code 3).');
  });
});
