// @timescales/sdk/solana: PDAs, trader instructions, account decoders, RPC and transactions (kit 8.4).
import { z } from 'zod';

z.config({ jitless: true });

export {
  type MarketAccount,
  type PendingChange,
  type TraderAccount,
  type BatchStatus,
  type BatchAccount,
  type AbortReason,
  type Observed,
  decodeMarketAccount,
  decodeTraderAccount,
  decodeBatchAccount,
  decodeMint,
  availableFor,
  withdrawStatus,
  closeStatus,
} from './accounts.js';
export { decodeProgramData } from './program.js';
export { marketPda, traderPda, batchPda } from './pdas.js';
export { associatedTokenAddress, createAtaIdempotentIx } from './ata.js';
export { computeUnitLimitIx, computeUnitPriceIx } from './computeBudget.js';
export {
  openTraderIx,
  depositIx,
  requestWithdrawIx,
  cancelWithdrawRequestIx,
  withdrawIx,
  closeTraderIx,
  revealBeaconIx,
} from './instructions.js';
export { type ProgramFailure, decodeProgramFailure } from './errors.js';
export { type TimescalesRpc, createTimescalesRpc } from './rpc.js';
export {
  type TxResult,
  buildTraderTx,
  checkSignedTx,
  sendAndConfirm,
  confirmSignature,
} from './tx.js';
