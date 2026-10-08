// sign -> send -> confirmed / failed with the decoded program error / expired
// (TxStepper). A transaction the wallet rewrote is refused before
// anything is sent.
import type { ProgramFailure, TxResult } from '@timescales/sdk/solana';

import { errorInfo } from '../trade/errors';
import type { Address } from '../trade/services';
import { fundsCopy } from './copy';
import type { FundsAction, FundsPort } from './port';

export type TxStep = 'build' | 'sign' | 'send' | 'done';

export type TxOutcome =
  | { kind: 'confirmed'; signature: string }
  | { kind: 'failed'; message: string; signature: string | null; retry: boolean };

export interface TxProgress {
  step: TxStep;
  outcome: TxOutcome | null;
}

/** Copy for a program error, with the epoch a locked withdrawal waits for. */
export function programErrorMessage(f: ProgramFailure, unlockEpoch: bigint | null): string {
  const p = fundsCopy.programErrors;
  if (f.program === 'system' && f.name === 'ResultWithNegativeLamports') {
    return fundsCopy.tx.insufficientSol;
  }
  if (f.program === 'token' && f.name === 'InsufficientFunds') return p.InsufficientFunds;
  if (f.program === 'settlement') {
    switch (f.name) {
      case 'WithdrawLocked':
        return p.WithdrawLocked(unlockEpoch === null ? '?' : unlockEpoch.toString());
      case 'WithdrawPending':
      case 'NothingToWithdraw':
      case 'Insolvent':
      case 'Halted':
      case 'InFlight':
      case 'AccountNotEmpty':
      case 'DuplicateTrader':
      case 'BalanceCap':
      case 'InvalidTokenAccount':
        return p[f.name];
    }
  }
  return p.other(f.program, f.code, f.name);
}

function resultOutcome(r: TxResult, unlockEpoch: bigint | null): TxOutcome {
  if (r.status === 'confirmed') return { kind: 'confirmed', signature: r.signature };
  if (r.status === 'expired') {
    return { kind: 'failed', message: fundsCopy.tx.expired, signature: r.signature, retry: true };
  }
  return {
    kind: 'failed',
    message: fundsCopy.tx.failed(programErrorMessage(r.failure, unlockEpoch)),
    signature: r.signature,
    retry: true,
  };
}

function walletMessage(e: unknown): { message: string; retry: boolean } {
  const info = errorInfo(e);
  if (info.kind === 'wallet' && info.code === 'rejected') {
    return { message: fundsCopy.tx.rejected, retry: true };
  }
  if (info.kind === 'wallet' && info.code === 'unsupported_feature') {
    return { message: fundsCopy.tx.noSigner, retry: false };
  }
  return { message: fundsCopy.tx.generic, retry: true };
}

/** Runs one transaction, reporting each step. Never throws. */
export async function runTx(
  port: FundsPort,
  market: Address,
  action: FundsAction,
  onProgress: (p: TxProgress) => void,
  o: { signal?: AbortSignal; unlockEpoch?: bigint | null } = {},
): Promise<TxOutcome> {
  const unlock = o.unlockEpoch ?? null;
  const finish = (step: TxStep, outcome: TxOutcome): TxOutcome => {
    onProgress({ step, outcome });
    return outcome;
  };
  onProgress({ step: 'build', outcome: null });
  let built;
  try {
    built = await port.build(market, action);
  } catch (e) {
    return finish('build', { kind: 'failed', signature: null, ...walletMessage(e) });
  }
  onProgress({ step: 'sign', outcome: null });
  let signed;
  try {
    signed = await port.sign(built, o.signal);
  } catch (e) {
    return finish('sign', { kind: 'failed', signature: null, ...walletMessage(e) });
  }
  if (signed.kind === 'signed') {
    const check = port.checkSigned(built.wire, signed.wire);
    if (check.kind !== 'ok') {
      return finish('sign', {
        kind: 'failed',
        message: fundsCopy.tx.rewritten,
        signature: null,
        retry: true,
      });
    }
  }
  onProgress({ step: 'send', outcome: null });
  try {
    const result = await port.send(signed, built, o.signal);
    const outcome = resultOutcome(result, unlock);
    return finish(outcome.kind === 'confirmed' ? 'done' : 'send', outcome);
  } catch (e) {
    return finish('send', { kind: 'failed', signature: null, ...walletMessage(e) });
  }
}
