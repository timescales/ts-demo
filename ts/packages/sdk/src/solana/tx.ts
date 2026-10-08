import {
  appendTransactionMessageInstructions,
  compileTransaction,
  createTransactionMessage,
  decompileTransactionMessage,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
  getTransactionEncoder,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type Blockhash,
  type Instruction,
} from '@solana/kit';
import { b58 } from '../core/encoding/base58.js';
import { equal } from '../core/encoding/bytes.js';
import { verifyStrict } from '../core/crypto/verifyStrict.js';
import { TimescalesError } from '../errors.js';
import type { Verdict } from '../verify/verdict.js';
import { computeUnitPriceIx } from './computeBudget.js';
import { decodeFailure, type ProgramFailure } from './errors.js';
import {
  ASSOCIATED_TOKEN_PROGRAM,
  COMPUTE_BUDGET_PROGRAM,
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
} from './program.js';
import { PreflightFailure, rpcExtras, type TimescalesRpc } from './rpc.js';

export type TxResult =
  | { status: 'confirmed'; signature: string; slot: bigint }
  | { status: 'failed'; signature: string; failure: ProgramFailure }
  | { status: 'expired'; signature: string };

const POLL_MS = 1_000;
const RESEND_EVERY_POLLS = 2;
/** A blockhash stays valid for 150 blocks after the block it names. */
const BLOCKHASH_VALIDITY = 151n;
const BUILTIN = new Set<string>([
  COMPUTE_BUDGET_PROGRAM,
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  ASSOCIATED_TOKEN_PROGRAM,
]);

// lastValidBlockHeight of the blockhashes this module built transactions
// with, so a wallet-returned transaction that kept the blockhash can be
// confirmed against it (checkSignedTx). Bounded. Oldest entries go first.
const LIFETIMES = new Map<string, bigint>();
const MAX_LIFETIMES = 64;

// The settlement program ids buildTraderTx built instructions for: the
// app's pinned program. A failure is attributed to the settlement program
// only when one of these failed. A wallet may add instructions of other
// programs (signAndSendTransaction). Bounded. Oldest entries go first.
const SETTLEMENT_PROGRAMS = new Set<string>();
const MAX_SETTLEMENT_PROGRAMS = 8;

function rememberSettlementPrograms(instructions: readonly Instruction[]): void {
  for (const ix of instructions) {
    if (BUILTIN.has(ix.programAddress)) continue;
    SETTLEMENT_PROGRAMS.delete(ix.programAddress);
    SETTLEMENT_PROGRAMS.add(ix.programAddress);
  }
  while (SETTLEMENT_PROGRAMS.size > MAX_SETTLEMENT_PROGRAMS) {
    const oldest = SETTLEMENT_PROGRAMS.values().next().value;
    if (oldest === undefined) break;
    SETTLEMENT_PROGRAMS.delete(oldest);
  }
}

function rememberLifetime(blockhash: string, lastValidBlockHeight: bigint): void {
  LIFETIMES.delete(blockhash);
  LIFETIMES.set(blockhash, lastValidBlockHeight);
  while (LIFETIMES.size > MAX_LIFETIMES) {
    const oldest = LIFETIMES.keys().next().value;
    if (oldest === undefined) break;
    LIFETIMES.delete(oldest);
  }
}

/**
 * A legacy transaction for the wallet to sign: an optional compute-unit
 * price first, then `instructions`, with the RPC's latest blockhash.
 */
export async function buildTraderTx(a: {
  rpc: TimescalesRpc;
  feePayer: Address;
  instructions: Instruction[];
  priorityMicroLamports?: bigint;
}): Promise<{ wire: Uint8Array; lastValidBlockHeight: bigint }> {
  const { blockhash, lastValidBlockHeight } = await rpcExtras(a.rpc).latestBlockhash();
  const instructions =
    a.priorityMicroLamports !== undefined && a.priorityMicroLamports > 0n
      ? [computeUnitPriceIx(a.priorityMicroLamports), ...a.instructions]
      : a.instructions;
  const message = pipe(
    createTransactionMessage({ version: 'legacy' }),
    (m) => setTransactionMessageFeePayer(a.feePayer, m),
    (m) =>
      setTransactionMessageLifetimeUsingBlockhash(
        { blockhash: blockhash as Blockhash, lastValidBlockHeight },
        m,
      ),
    (m) => appendTransactionMessageInstructions(instructions, m),
  );
  const wire = new Uint8Array(getTransactionEncoder().encode(compileTransaction(message)));
  rememberLifetime(blockhash, lastValidBlockHeight);
  rememberSettlementPrograms(a.instructions);
  return { wire, lastValidBlockHeight };
}

interface DecodedTx {
  messageBytes: Uint8Array;
  signatures: Readonly<Record<string, Uint8Array | null>>;
  feePayer: Address;
  blockhash: string | null;
  instructions: readonly Instruction[];
}

function decodeTx(wire: Uint8Array): DecodedTx {
  const tx = getTransactionDecoder().decode(wire);
  const compiled = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
  const message = decompileTransactionMessage(compiled);
  const lifetime = message.lifetimeConstraint as { blockhash?: string };
  return {
    messageBytes: new Uint8Array(tx.messageBytes),
    signatures: tx.signatures as Readonly<Record<string, Uint8Array | null>>,
    feePayer: message.feePayer.address,
    blockhash: lifetime.blockhash ?? null,
    instructions: message.instructions,
  };
}

function sameInstruction(a: Instruction, b: Instruction): boolean {
  if (a.programAddress !== b.programAddress) return false;
  const aa = a.accounts ?? [];
  const bb = b.accounts ?? [];
  if (aa.length !== bb.length) return false;
  for (let i = 0; i < aa.length; i++) {
    if (aa[i]!.address !== bb[i]!.address || aa[i]!.role !== bb[i]!.role) return false;
  }
  return equal(new Uint8Array(a.data ?? []), new Uint8Array(b.data ?? []));
}

/** Checks a wallet-returned transaction: same fee payer, Timescales instructions byte-identical, only compute-budget instructions added or changed. */
export function checkSignedTx(
  original: Uint8Array,
  returned: Uint8Array,
): Verdict<{ lastValidBlockHeight: bigint | null }> {
  let a: DecodedTx;
  let b: DecodedTx;
  try {
    a = decodeTx(original);
  } catch {
    return { kind: 'fail', reason: 'the original transaction does not decode' };
  }
  try {
    b = decodeTx(returned);
  } catch {
    return { kind: 'fail', reason: 'the wallet returned a transaction that does not decode' };
  }
  if (a.feePayer !== b.feePayer) {
    return { kind: 'fail', reason: 'the wallet changed the fee payer' };
  }
  const own = (ixs: readonly Instruction[]): Instruction[] =>
    ixs.filter((ix) => ix.programAddress !== COMPUTE_BUDGET_PROGRAM);
  const before = own(a.instructions);
  const after = own(b.instructions);
  if (before.length !== after.length || before.some((ix, i) => !sameInstruction(ix, after[i]!))) {
    return {
      kind: 'fail',
      reason: 'the wallet changed instructions other than compute-budget ones',
    };
  }
  const sig = b.signatures[b.feePayer];
  if (sig === undefined || sig === null) {
    return { kind: 'fail', reason: 'the returned transaction is not signed by the fee payer' };
  }
  if (!verifyStrict(b58.decode(b.feePayer, 32), b.messageBytes, sig)) {
    return { kind: 'fail', reason: "the fee payer's signature does not verify" };
  }
  const lastValidBlockHeight =
    b.blockhash !== null && b.blockhash === a.blockhash
      ? (LIFETIMES.get(b.blockhash) ?? null)
      : null;
  return { kind: 'ok', value: { lastValidBlockHeight } };
}

/** The base58 transaction signature: the first signature of the wire transaction. */
export function wireSignature(wire: Uint8Array): string {
  const tx = getTransactionDecoder().decode(wire);
  const compiled = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
  const payer = compiled.staticAccounts[0];
  const sig = payer === undefined ? null : tx.signatures[payer];
  if (sig === undefined || sig === null) {
    throw new TimescalesError({
      kind: 'wallet',
      code: 'unsigned',
      message: 'transaction is not signed',
    });
  }
  return b58.encode(new Uint8Array(sig));
}

function aborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) {
    throw new TimescalesError({
      kind: 'aborted',
      code: 'aborted',
      message: 'confirmation abandoned',
    });
  }
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(t);
      reject(
        new TimescalesError({
          kind: 'aborted',
          code: 'aborted',
          message: 'confirmation abandoned',
        }),
      );
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** A failure from a transaction error without logs: only the instruction and custom code are known. */
function failureFromError(err: unknown): ProgramFailure {
  const ie = (err as { InstructionError?: unknown } | null)?.InstructionError;
  if (Array.isArray(ie) && ie.length === 2) {
    const index = Number(ie[0]);
    const custom = (ie[1] as { Custom?: unknown } | null)?.Custom;
    if (custom !== undefined) {
      return { program: 'other', code: Number(custom), name: null, instructionIndex: index };
    }
    return { program: 'other', code: -1, name: String(ie[1]), instructionIndex: index };
  }
  return {
    program: 'other',
    code: -1,
    name: JSON.stringify(err, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)),
    instructionIndex: -1,
  };
}

async function failure(
  rpc: TimescalesRpc,
  signature: string,
  err: unknown,
  logs: readonly string[] | null,
): Promise<ProgramFailure> {
  const lines =
    logs ??
    (await rpcExtras(rpc)
      .transactionLogs(signature)
      .catch(() => null));
  if (lines !== null) {
    const f = decodeFailure(lines, (id) => SETTLEMENT_PROGRAMS.has(id));
    if (f !== null) return f;
  }
  return failureFromError(err);
}

async function confirmLoop(
  rpc: TimescalesRpc,
  signature: string,
  lastValidBlockHeight: bigint | null,
  signal: AbortSignal | undefined,
  resend: (() => Promise<void>) | null,
): Promise<TxResult> {
  const extras = rpcExtras(rpc);
  const deadline = lastValidBlockHeight ?? (await extras.blockHeight()) + BLOCKHASH_VALIDITY;
  for (let poll = 0; ; poll++) {
    aborted(signal);
    const status = await extras.signatureStatus(signature);
    if (status !== null) {
      if (status.err !== null && status.err !== undefined) {
        return {
          status: 'failed',
          signature,
          failure: await failure(rpc, signature, status.err, null),
        };
      }
      if (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized') {
        return { status: 'confirmed', signature, slot: status.slot };
      }
    } else if ((await extras.blockHeight()) > deadline) {
      // The status may have landed between the two reads.
      if ((await extras.signatureStatus(signature)) === null)
        return { status: 'expired', signature };
      continue;
    }
    if (resend !== null && poll > 0 && poll % RESEND_EVERY_POLLS === 0) {
      await resend().catch(() => undefined);
    }
    await sleep(POLL_MS, signal);
  }
}

/** Sends a signed transaction through the user's RPC (with preflight), re-broadcasts it until it lands, and confirms it. */
export async function sendAndConfirm(
  rpc: TimescalesRpc,
  signedWire: Uint8Array,
  lastValidBlockHeight: bigint,
  signal?: AbortSignal,
): Promise<TxResult> {
  aborted(signal);
  const extras = rpcExtras(rpc);
  const signature = wireSignature(signedWire);
  try {
    await extras.sendTransaction(signedWire);
  } catch (e) {
    if (e instanceof PreflightFailure) {
      return { status: 'failed', signature, failure: await failure(rpc, signature, e.err, e.logs) };
    }
    throw e;
  }
  return confirmLoop(rpc, signature, lastValidBlockHeight, signal, async () => {
    await extras.sendTransaction(signedWire);
  });
}

/**
 * Confirms a signature the wallet sent (`signAndSendTransaction`). With no
 * known lifetime it waits one blockhash validity. A failure is attributed to
 * the settlement program only for a program `buildTraderTx` built
 * instructions for.
 */
export function confirmSignature(
  rpc: TimescalesRpc,
  signature: string,
  lastValidBlockHeight: bigint | null,
  signal?: AbortSignal,
): Promise<TxResult> {
  return confirmLoop(rpc, signature, lastValidBlockHeight, signal, null);
}

/** p75 of the recent prioritization fees for `accounts`, capped. */
export async function priorityFee(
  rpc: TimescalesRpc,
  accounts: readonly Address[],
  capMicroLamports: bigint,
): Promise<bigint> {
  const fees = (await rpcExtras(rpc).recentPrioritizationFees(accounts)).sort((x, y) =>
    x < y ? -1 : x > y ? 1 : 0,
  );
  if (fees.length === 0) return 0n;
  const p75 = fees[Math.min(fees.length - 1, Math.ceil(fees.length * 0.75) - 1)]!;
  return p75 > capMicroLamports ? capMicroLamports : p75;
}
