import {
  createSolanaRpc,
  isSolanaError,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_BLOCK_CLEANED_UP,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_BLOCK_NOT_AVAILABLE,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_LONG_TERM_STORAGE_SLOT_SKIPPED,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SLOT_SKIPPED,
  type Address,
  type Base64EncodedWireTransaction,
  type Signature,
} from '@solana/kit';
import { b64 } from '../core/encoding/base64.js';
import { b58 } from '../core/encoding/base58.js';
import { TimescalesError } from '../errors.js';
import {
  decodeBatchAccount,
  decodeMarketAccount,
  decodeTraderAccount,
  type BatchAccount,
  type MarketAccount,
  type Observed,
  type TraderAccount,
} from './accounts.js';
import { batchSeeds, createProgramAddressSync, marketSeeds, traderSeeds } from './pdas.js';
import { SYSTEM_PROGRAM } from './program.js';

export interface TimescalesRpc {
  market(a: Address, minContextSlot?: bigint): Promise<Observed<MarketAccount>>;
  trader(a: Address, minContextSlot?: bigint): Promise<Observed<TraderAccount> | null>;
  batch(a: Address, minContextSlot?: bigint): Promise<Observed<BatchAccount> | null>;
  account(a: Address): Promise<Observed<Uint8Array> | null>;
  tokenBalance(a: Address): Promise<bigint>;
  slot(): Promise<bigint>;
  genesisHash(): Promise<string>;
  /** Unix time of the slot's block in milliseconds, or null when the RPC has none. */
  blockTime(slot: bigint): Promise<number | null>;
}

export interface AccountSnapshot {
  owner: Address;
  lamports: bigint;
  executable: boolean;
  data: Uint8Array;
}

export type SignatureStatus = {
  slot: bigint;
  confirmationStatus: 'processed' | 'confirmed' | 'finalized' | null;
  err: unknown;
};

/**
 * RPC calls the SDK needs beyond the frozen {@link TimescalesRpc}: owners,
 * transactions and fees. The RPC from {@link createTimescalesRpc} carries
 * them under {@link RPC_EXTRAS}. Test doubles may too.
 */
export interface RpcExtras {
  accountInfo(a: Address, minContextSlot?: bigint): Promise<Observed<AccountSnapshot> | null>;
  latestBlockhash(): Promise<{ blockhash: string; lastValidBlockHeight: bigint }>;
  /** Sends a signed wire transaction with preflight. Throws {@link PreflightFailure} when simulation fails. */
  sendTransaction(wire: Uint8Array): Promise<string>;
  signatureStatus(signature: string): Promise<SignatureStatus | null>;
  blockHeight(): Promise<bigint>;
  transactionLogs(signature: string): Promise<readonly string[] | null>;
  recentPrioritizationFees(accounts: readonly Address[]): Promise<bigint[]>;
  minimumBalanceForRentExemption(len: number): Promise<bigint>;
  balance(a: Address): Promise<bigint>;
}

export const RPC_EXTRAS: unique symbol = Symbol('timescales.rpcExtras');

/** A transaction refused by preflight simulation, with the simulated logs. */
export class PreflightFailure extends Error {
  readonly logs: readonly string[];
  readonly err: unknown;

  constructor(logs: readonly string[], err: unknown) {
    super('transaction simulation failed');
    this.name = 'PreflightFailure';
    this.logs = logs;
    this.err = err;
  }
}

export function rpcExtras(rpc: TimescalesRpc): RpcExtras {
  const extras = (rpc as { [RPC_EXTRAS]?: RpcExtras })[RPC_EXTRAS];
  if (extras === undefined) {
    throw new TimescalesError({
      kind: 'environment',
      code: 'rpc_unsupported',
      message: 'this TimescalesRpc cannot send transactions, use createTimescalesRpc',
    });
  }
  return extras;
}

function missing(what: string, a: Address): TimescalesError {
  return new TimescalesError({
    kind: 'verify',
    code: 'account_missing',
    message: `no ${what} account at ${a}`,
  });
}

/**
 * The account must sit at the program address its own owner derives from the
 * seeds stored in it. Only the owner can create data at its PDA, so a market,
 * trader or batch read this way was written by the program that owns it. V-1
 * then pins that program by deriving the market address from the app's
 * program id.
 */
function checkPda(
  a: Address,
  owner: Address,
  seeds: Uint8Array[],
  bump: number,
  what: string,
): void {
  if (createProgramAddressSync([...seeds, Uint8Array.of(bump)], owner) !== a) {
    throw new TimescalesError({
      kind: 'verify',
      code: 'account_not_pda',
      message: `${what} at ${a} is not its owner's program address`,
    });
  }
}

/**
 * Anyone can send lamports to a program address before the program creates
 * the account there, and closing an account hands it back to the System
 * program. The program adopts such a System-owned account without data
 * (`init_pda`), so until it does, no program account exists at the address.
 */
function unclaimed(s: AccountSnapshot): boolean {
  return s.owner === SYSTEM_PROGRAM && s.data.length === 0;
}

interface ProgramAccounts {
  market: MarketAccount;
  trader: TraderAccount;
  batch: BatchAccount;
}

const DECODE: {
  [K in keyof ProgramAccounts]: (a: Address, s: Observed<AccountSnapshot>) => ProgramAccounts[K];
} = {
  market(a, { value: s, contextSlot }) {
    const v = decodeMarketAccount(a, s.data);
    checkPda(a, s.owner, marketSeeds(v.marketId), s.data[1]!, 'market');
    if (v.pending !== null) v.pending.due = contextSlot >= v.pending.etaSlot;
    return v;
  },
  trader(a, { value: s }) {
    const v = decodeTraderAccount(a, s.data);
    checkPda(a, s.owner, traderSeeds(v.market, v.owner), s.data[1]!, 'trader');
    return v;
  },
  batch(a, { value: s }) {
    const v = decodeBatchAccount(a, s.data);
    checkPda(a, s.owner, batchSeeds(v.market, v.epoch), s.data[1]!, 'batch');
    return v;
  },
};

/**
 * Decodes what the RPC returned for the program account of `kind` at `a`:
 * null when nothing, or only an unclaimed System account, is there. A
 * `DecodeError` or `account_not_pda` when something else is.
 */
export function programAccountAt<K extends keyof ProgramAccounts>(
  kind: K,
  a: Address,
  s: Observed<AccountSnapshot> | null,
): Observed<ProgramAccounts[K]> | null {
  if (s === null || unclaimed(s.value)) return null;
  return { value: DECODE[kind](a, s), contextSlot: s.contextSlot, commitment: s.commitment };
}

const NO_BLOCK = [
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_BLOCK_CLEANED_UP,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_BLOCK_NOT_AVAILABLE,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_LONG_TERM_STORAGE_SLOT_SKIPPED,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SLOT_SKIPPED,
] as const;

function rpcError(e: unknown): unknown {
  if (isSolanaError(e, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED)) {
    return new TimescalesError({
      kind: 'network',
      code: 'min_context_slot_not_reached',
      message: 'the RPC has not reached the requested slot yet',
      retryable: true,
      cause: e,
    });
  }
  if (e instanceof TimescalesError) return e;
  return new TimescalesError({
    kind: 'network',
    code: 'rpc_failed',
    message: e instanceof Error ? e.message : 'RPC request failed',
    retryable: true,
    cause: e,
  });
}

async function call<T>(f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch (e) {
    throw rpcError(e);
  }
}

/** `url` must be on the app's RPC allowlist. Reads use `commitment` (default confirmed). */
export function createTimescalesRpc(
  url: string,
  o?: { commitment?: 'confirmed' | 'finalized' },
): TimescalesRpc {
  const rpc = createSolanaRpc(url);
  const commitment = o?.commitment ?? 'confirmed';

  const accountInfo = async (
    a: Address,
    minContextSlot?: bigint,
  ): Promise<Observed<AccountSnapshot> | null> => {
    const res = await call(() =>
      rpc
        .getAccountInfo(a, {
          encoding: 'base64',
          commitment,
          ...(minContextSlot !== undefined ? { minContextSlot } : {}),
        })
        .send(),
    );
    if (res.value === null) return null;
    return {
      value: {
        owner: res.value.owner,
        lamports: BigInt(res.value.lamports),
        executable: res.value.executable,
        data: b64.decode(res.value.data[0]),
      },
      contextSlot: BigInt(res.context.slot),
      commitment,
    };
  };

  const extras: RpcExtras = {
    accountInfo,
    async latestBlockhash() {
      const res = await call(() => rpc.getLatestBlockhash({ commitment }).send());
      return {
        blockhash: res.value.blockhash,
        lastValidBlockHeight: BigInt(res.value.lastValidBlockHeight),
      };
    },
    async sendTransaction(wire) {
      try {
        return await rpc
          .sendTransaction(b64.encode(wire) as Base64EncodedWireTransaction, {
            encoding: 'base64',
            preflightCommitment: commitment,
          })
          .send();
      } catch (e) {
        if (
          isSolanaError(e, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE)
        ) {
          throw new PreflightFailure(e.context.logs ?? [], e.cause);
        }
        throw rpcError(e);
      }
    },
    async signatureStatus(signature) {
      const res = await call(() =>
        rpc
          .getSignatureStatuses([signature as Signature], { searchTransactionHistory: false })
          .send(),
      );
      const s = res.value[0];
      if (s === undefined || s === null) return null;
      return { slot: BigInt(s.slot), confirmationStatus: s.confirmationStatus, err: s.err };
    },
    async blockHeight() {
      return BigInt(await call(() => rpc.getBlockHeight({ commitment }).send()));
    },
    async transactionLogs(signature) {
      const tx = await call(() =>
        rpc
          .getTransaction(signature as Signature, {
            encoding: 'json',
            commitment,
            maxSupportedTransactionVersion: 0,
          })
          .send(),
      );
      return tx?.meta?.logMessages ?? null;
    },
    async recentPrioritizationFees(accounts) {
      const res = await call(() => rpc.getRecentPrioritizationFees([...accounts]).send());
      return res.map((f) => BigInt(f.prioritizationFee));
    },
    async minimumBalanceForRentExemption(len) {
      return BigInt(await call(() => rpc.getMinimumBalanceForRentExemption(BigInt(len)).send()));
    },
    async balance(a) {
      const res = await call(() => rpc.getBalance(a, { commitment }).send());
      return BigInt(res.value);
    },
  };

  const out: TimescalesRpc & { [RPC_EXTRAS]: RpcExtras } = {
    [RPC_EXTRAS]: extras,
    async market(a, minContextSlot) {
      const m = programAccountAt('market', a, await accountInfo(a, minContextSlot));
      if (m === null) throw missing('market', a);
      return m;
    },
    async trader(a, minContextSlot) {
      return programAccountAt('trader', a, await accountInfo(a, minContextSlot));
    },
    async batch(a, minContextSlot) {
      return programAccountAt('batch', a, await accountInfo(a, minContextSlot));
    },
    async account(a) {
      const s = await accountInfo(a);
      return s === null ? null : { value: s.value.data, contextSlot: s.contextSlot, commitment };
    },
    async tokenBalance(a) {
      const res = await call(() => rpc.getTokenAccountBalance(a, { commitment }).send());
      return BigInt(res.value.amount);
    },
    async slot() {
      return BigInt(await call(() => rpc.getSlot({ commitment }).send()));
    },
    async genesisHash() {
      const h = await call(() => rpc.getGenesisHash().send());
      b58.decode(h, 32);
      return h;
    },
    async blockTime(slot) {
      try {
        const t = await rpc.getBlockTime(slot).send();
        return Number(t) * 1000;
      } catch (e) {
        // Skipped slots and pruned history have no block time.
        if (NO_BLOCK.some((code) => isSolanaError(e, code))) return null;
        throw rpcError(e);
      }
    },
  };
  return out;
}
