// What the Funds screen needs from Solana and the wallet. adapter.ts
// implements it with the SDK. Tests use fakes.
import type { MarketDetail } from '@timescales/sdk/api';
import type { MarketAccount, TraderAccount, TxResult } from '@timescales/sdk/solana';
import type { Verdict } from '@timescales/sdk/verify';

import type { Address } from '../trade/services';

export type TokenSide = 'base' | 'quote';

/** Error code of a snapshot or build refused because the node and the user's RPC disagree (V-1). */
export const NODE_RPC_MISMATCH = 'NODE_RPC_MISMATCH';

/** One public, wallet-signed transaction of the trader flows. */
export type FundsAction =
  | { kind: 'open' }
  | { kind: 'deposit'; side: TokenSide; amount: bigint }
  | { kind: 'request_withdraw'; base: bigint; quote: bigint }
  | { kind: 'cancel_request' }
  | { kind: 'withdraw' }
  | { kind: 'close' };

export interface FundsSnapshot {
  detail: MarketDetail;
  market: MarketAccount;
  /** Null when the wallet has no trader account in this market. */
  trader: TraderAccount | null;
  /** SPL balances of the wallet's associated token accounts. Null when the account does not exist. */
  wallet: { base: bigint | null; quote: bigint | null };
  /** Rent for a trader account, read from the RPC. Null when the RPC could not tell. */
  traderRentLamports: bigint | null;
  contextSlot: bigint;
}

export interface BuiltTx {
  wire: Uint8Array;
  lastValidBlockHeight: bigint;
}

/** What the wallet gave back: a signed transaction for us to send, or the signature of one it sent itself. */
export type WalletTx = { kind: 'signed'; wire: Uint8Array } | { kind: 'sent'; signature: string };

export interface FundsPort {
  snapshot(market: Address): Promise<FundsSnapshot>;
  build(market: Address, action: FundsAction): Promise<BuiltTx>;
  sign(tx: BuiltTx, signal?: AbortSignal): Promise<WalletTx>;
  /** `checkSignedTx`: refuses a transaction the wallet changed beyond compute-budget instructions. */
  checkSigned(
    original: Uint8Array,
    returned: Uint8Array,
  ): Verdict<{ lastValidBlockHeight: bigint | null }>;
  send(tx: WalletTx, built: BuiltTx, signal?: AbortSignal): Promise<TxResult>;
}
