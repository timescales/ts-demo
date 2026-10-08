// The Funds port on the SDK: reads through the user's RPC, builds the
// trader transactions, has the wallet sign them and confirms them.
import type { MarketDetail } from '@timescales/sdk/api';
import type { MarketAccount, TimescalesRpc } from '@timescales/sdk/solana';
import {
  associatedTokenAddress,
  buildTraderTx,
  cancelWithdrawRequestIx,
  checkSignedTx,
  closeTraderIx,
  confirmSignature,
  createAtaIdempotentIx,
  depositIx,
  openTraderIx,
  requestWithdrawIx,
  sendAndConfirm,
  traderPda,
  withdrawIx,
} from '@timescales/sdk/solana';
import type { TraderWallet } from '@timescales/sdk/wallet';

import type { Address, PublicApi } from '../trade/services';
import type { BuiltTx, FundsAction, FundsPort, FundsSnapshot, WalletTx } from './port';
import { NODE_RPC_MISMATCH } from './port';

type Instruction = Awaited<ReturnType<typeof openTraderIx>>;

/** `Trader` account size, the length  asks the RPC to price. */
const TRADER_LEN = 148n;
/** Solana's per-account storage overhead in the rent formula. */
const ACCOUNT_STORAGE_OVERHEAD = 128n;
const RENT_SYSVAR = 'SysvarRent111111111111111111111111111111111' as Address;

/**
 * Rent-exempt minimum for a trader account from the Rent sysvar
 * (`lamports_per_byte_year u64 || exemption_threshold f64 || burn_percent u8`),
 * computed as the runtime does: `(overhead + len) * lamports_per_byte_year * threshold`.
 */
export function traderRent(rentSysvar: Uint8Array): bigint | null {
  if (rentSysvar.length < 17) return null;
  const view = new DataView(rentSysvar.buffer, rentSysvar.byteOffset, rentSysvar.byteLength);
  const perByteYear = view.getBigUint64(0, true);
  const threshold = view.getFloat64(8, true);
  if (!Number.isFinite(threshold) || threshold < 0) return null;
  return BigInt(
    Math.floor(Number((ACCOUNT_STORAGE_OVERHEAD + TRADER_LEN) * perByteYear) * threshold),
  );
}

function walletError(code: string, message: string): Error {
  return Object.assign(new Error(message), { kind: 'wallet', code, retryable: false });
}

type MarketTokens = Pick<MarketAccount, 'baseMint' | 'quoteMint' | 'baseVault' | 'quoteVault'>;

/**
 * Mints and vaults are immutable (V-1), so the node and the RPC must agree at
 * any slot. The chain values are the ones used. A disagreement refuses.
 */
export function chainTokens(detail: MarketDetail, chain: MarketAccount): MarketTokens {
  const fields = ['baseMint', 'quoteMint', 'baseVault', 'quoteVault'] as const;
  const differ = fields.filter((f) => detail[f] !== chain[f]);
  if (differ.length > 0) {
    throw Object.assign(new Error(`the node and the RPC disagree about ${differ.join(', ')}`), {
      kind: 'verify',
      code: NODE_RPC_MISMATCH,
      retryable: false,
    });
  }
  return {
    baseMint: chain.baseMint,
    quoteMint: chain.quoteMint,
    baseVault: chain.baseVault,
    quoteVault: chain.quoteVault,
  };
}

export interface FundsAdapterDeps {
  api: Pick<PublicApi, 'market'>;
  rpc: TimescalesRpc;
  wallet: TraderWallet;
  /** The pinned settlement program (AppPins.programId). Never taken from the node. */
  program: Address;
}

export function createFundsPort({ api, rpc, wallet, program }: FundsAdapterDeps): FundsPort {
  const owner = wallet.address;
  const details = new Map<Address, MarketDetail>();
  const detailOf = async (market: Address) => {
    let d = details.get(market);
    if (d === undefined) {
      d = await api.market(market);
      details.set(market, d);
    }
    return d;
  };
  const tokensOf = async (market: Address): Promise<MarketTokens> => {
    const [detail, chain] = await Promise.all([detailOf(market), rpc.market(market)]);
    return chainTokens(detail, chain.value);
  };
  const balanceOf = async (mint: Address): Promise<bigint | null> => {
    const ata = await associatedTokenAddress(owner, mint);
    return (await rpc.account(ata)) === null ? null : rpc.tokenBalance(ata);
  };

  const instructions = async (market: Address, action: FundsAction): Promise<Instruction[]> => {
    const base = { program, owner, market };
    switch (action.kind) {
      case 'open':
        return [await openTraderIx(base)];
      case 'deposit': {
        const d = await tokensOf(market);
        const mint = action.side === 'base' ? d.baseMint : d.quoteMint;
        return [
          await depositIx({
            ...base,
            source: await associatedTokenAddress(owner, mint),
            vault: action.side === 'base' ? d.baseVault : d.quoteVault,
            side: action.side,
            amount: action.amount,
          }),
        ];
      }
      case 'request_withdraw':
        return [await requestWithdrawIx({ ...base, base: action.base, quote: action.quote })];
      case 'cancel_request':
        return [await cancelWithdrawRequestIx(base)];
      case 'withdraw': {
        const d = await tokensOf(market);
        const [traderAddress] = await traderPda(program, market, owner);
        const trader = (await rpc.trader(traderAddress))?.value ?? null;
        const out: Instruction[] = [];
        const sides = [
          {
            side: 'base' as const,
            mint: d.baseMint,
            vault: d.baseVault,
            wants: trader?.requestedBase ?? 0n,
          },
          {
            side: 'quote' as const,
            mint: d.quoteMint,
            vault: d.quoteVault,
            wants: trader?.requestedQuote ?? 0n,
          },
        ];
        for (const s of sides) {
          if (s.wants === 0n) continue;
          out.push(await createAtaIdempotentIx({ payer: owner, owner, mint: s.mint }));
          out.push(
            await withdrawIx({
              ...base,
              vault: s.vault,
              dest: await associatedTokenAddress(owner, s.mint),
              side: s.side,
            }),
          );
        }
        return out;
      }
      case 'close':
        return [await closeTraderIx(base)];
    }
  };

  return {
    async snapshot(market): Promise<FundsSnapshot> {
      const [traderAddress] = await traderPda(program, market, owner);
      const [detail, chain] = await Promise.all([detailOf(market), rpc.market(market)]);
      const tokens = chainTokens(detail, chain.value);
      const [trader, walletBase, walletQuote, rent] = await Promise.all([
        rpc.trader(traderAddress),
        balanceOf(tokens.baseMint),
        balanceOf(tokens.quoteMint),
        rpc.account(RENT_SYSVAR).catch(() => null),
      ]);
      return {
        detail,
        market: chain.value,
        trader: trader?.value ?? null,
        wallet: { base: walletBase, quote: walletQuote },
        traderRentLamports: rent === null ? null : traderRent(rent.value),
        contextSlot: chain.contextSlot,
      };
    },

    async build(market, action): Promise<BuiltTx> {
      return buildTraderTx({
        rpc,
        feePayer: owner,
        instructions: await instructions(market, action),
      });
    },

    async sign(tx, signal): Promise<WalletTx> {
      if (wallet.signTransaction) {
        return { kind: 'signed', wire: await wallet.signTransaction(tx.wire, signal) };
      }
      if (wallet.signAndSendTransaction) {
        const { signature } = await wallet.signAndSendTransaction(tx.wire, signal);
        return { kind: 'sent', signature };
      }
      throw walletError('unsupported_feature', 'the wallet signs no Solana transactions');
    },

    checkSigned: checkSignedTx,

    async send(tx, built, signal) {
      if (tx.kind === 'sent') {
        return confirmSignature(rpc, tx.signature, built.lastValidBlockHeight, signal);
      }
      // The wallet may have replaced the blockhash. Its own lifetime is the one to wait for.
      const check = checkSignedTx(built.wire, tx.wire);
      const lastValid =
        check.kind === 'ok' && check.value.lastValidBlockHeight !== null
          ? check.value.lastValidBlockHeight
          : built.lastValidBlockHeight;
      return sendAndConfirm(rpc, tx.wire, lastValid, signal);
    },
  };
}
