// A trader transaction from build to confirmation: the wallet signs. A
// transaction the wallet returns is checked (same fee payer, our
// instructions byte-identical, only compute-budget changes) before it is sent
// through the user's own RPC.
import type { ProgramFailure, TimescalesRpc, TxResult, openTraderIx } from '@timescales/sdk/solana';
import {
  buildTraderTx,
  checkSignedTx,
  confirmSignature,
  sendAndConfirm,
} from '@timescales/sdk/solana';
import type { TraderWallet } from '@timescales/sdk/wallet';
import { WalletError } from '@timescales/sdk/wallet';

import type { Address } from './types';

export type Instruction = Awaited<ReturnType<typeof openTraderIx>>;
export type TxStep = 'building' | 'signing' | 'sending' | 'confirming';

export type TxOutcome =
  | TxResult
  /** The wallet changed the transaction. It was not sent. */
  | { status: 'rewritten'; reason: string };

export async function runTraderTx(a: {
  rpc: TimescalesRpc;
  wallet: TraderWallet;
  instructions: Instruction[];
  signal?: AbortSignal;
  onStep?: (s: TxStep) => void;
}): Promise<TxOutcome> {
  a.onStep?.('building');
  const built = await buildTraderTx({
    rpc: a.rpc,
    feePayer: a.wallet.address as Address,
    instructions: a.instructions,
  });
  a.onStep?.('signing');
  if (a.wallet.signTransaction !== undefined) {
    const signed = await a.wallet.signTransaction(built.wire, a.signal);
    const v = checkSignedTx(built.wire, signed);
    if (v.kind !== 'ok') return { status: 'rewritten', reason: v.reason };
    a.onStep?.('sending');
    return sendAndConfirm(
      a.rpc,
      signed,
      v.value.lastValidBlockHeight ?? built.lastValidBlockHeight,
      a.signal,
    );
  }
  if (a.wallet.signAndSendTransaction !== undefined) {
    const { signature } = await a.wallet.signAndSendTransaction(built.wire, a.signal);
    a.onStep?.('confirming');
    return confirmSignature(a.rpc, signature, built.lastValidBlockHeight, a.signal);
  }
  throw new WalletError('unsupported_feature', 'the wallet cannot sign transactions');
}

/** The decoded program error, e.g. "settlement error 6012 (WithdrawLocked)". */
export function failureText(f: ProgramFailure): string {
  return f.name === null
    ? `${f.program} error ${f.code}`
    : `${f.name} (${f.program} error ${f.code})`;
}
