import type { Reader } from '../encoding/codec.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';
import type { BookId } from './params.js';

export interface ClearingPrice {
  book: BookId;
  tick: bigint;
  volume: bigint;
}

/** Backend-independent result of one batch (`196 + 17n` B). */
export interface ExecutionOutcome {
  market: bigint;
  epoch: bigint;
  headerDigest: Uint8Array;
  clearing: ClearingPrice[];
  fillCount: number;
  fillsRoot: Uint8Array;
  cancelledRoot: Uint8Array;
  nextStateRoot: Uint8Array;
  settlementCount: number;
  settlementRoot: Uint8Array;
  fees: bigint;
}

export type Backend = 'tee' | 'reference' | 'mpc';

/** Executor-signed receipt (`390 + 17n` B). */
export interface ExecutionReceipt {
  version: 1;
  outcome: ExecutionOutcome;
  backend: Backend;
  executor: Uint8Array;
  attestation: Uint8Array;
  proof: Uint8Array;
  trace: Uint8Array;
  signature: Uint8Array;
}

export const RECEIPT_VERSION = 1;
export const MAX_CLEARING = 2;
const BACKENDS: readonly Backend[] = ['reference', 'tee', 'mpc'];

export function readBook(r: Reader): BookId {
  const b = r.u8();
  if (b > 2) throw new DecodeError('tag', `BookId ${b}`);
  return b as BookId;
}

export function readOutcome(r: Reader): ExecutionOutcome {
  return {
    market: r.u64(),
    epoch: r.u64(),
    headerDigest: r.fixed(32),
    clearing: r.seq(
      MAX_CLEARING,
      (x) => ({ book: readBook(x), tick: x.u64(), volume: x.u64() }),
      17,
    ),
    fillCount: r.u32(),
    fillsRoot: r.fixed(32),
    cancelledRoot: r.fixed(32),
    nextStateRoot: r.fixed(32),
    settlementCount: r.u32(),
    settlementRoot: r.fixed(32),
    fees: r.u64(),
  };
}

export function writeOutcome(w: Writer, o: ExecutionOutcome): void {
  w.u64(o.market)
    .u64(o.epoch)
    .fixed(o.headerDigest, 32)
    .seq(o.clearing, MAX_CLEARING, (x, c) => x.u8(c.book).u64(c.tick).u64(c.volume))
    .u32(o.fillCount)
    .fixed(o.fillsRoot, 32)
    .fixed(o.cancelledRoot, 32)
    .fixed(o.nextStateRoot, 32)
    .u32(o.settlementCount)
    .fixed(o.settlementRoot, 32)
    .u64(o.fees);
}

export function encodeOutcome(o: ExecutionOutcome): Uint8Array {
  const w = new Writer();
  writeOutcome(w, o);
  return w.finish();
}

/** Decodes a receipt. The version byte must be 1 (Rust's `Decode` does not check it, so the SDK does). */
export function decodeReceipt(b: Uint8Array): ExecutionReceipt {
  return decodeExact(b, (r) => {
    const version = r.u8();
    if (version !== RECEIPT_VERSION) throw new DecodeError('version', `receipt version ${version}`);
    const outcome = readOutcome(r);
    const tag = r.u8();
    const backend = BACKENDS[tag];
    if (backend === undefined) throw new DecodeError('tag', `BackendKind ${tag}`);
    return {
      version: 1,
      outcome,
      backend,
      executor: r.fixed(32),
      attestation: r.fixed(32),
      proof: r.fixed(32),
      trace: r.fixed(32),
      signature: r.fixed(64),
    };
  });
}

export function encodeReceipt(x: ExecutionReceipt): Uint8Array {
  const w = new Writer().u8(x.version);
  writeOutcome(w, x.outcome);
  return w
    .u8(BACKENDS.indexOf(x.backend))
    .fixed(x.executor, 32)
    .fixed(x.attestation, 32)
    .fixed(x.proof, 32)
    .fixed(x.trace, 32)
    .fixed(x.signature, 64)
    .finish();
}

/**
 * `H(RECEIPT, receipt[..len-64])`. Rust hashes the constant protocol version
 * rather than byte 0, so the formula holds only for `raw[0] === 1`, which is
 * required here.
 */
export function receiptDigest(raw: Uint8Array): Uint8Array {
  if (raw.length < 65) throw new DecodeError('eof', 'receipt too short');
  if (raw[0] !== RECEIPT_VERSION) throw new DecodeError('version', `receipt version ${raw[0]}`);
  return H('RECEIPT', raw.subarray(0, raw.length - 64));
}

/** `H(OUTCOME, encode(outcome))`. */
export function outcomeDigest(o: ExecutionOutcome): Uint8Array {
  return H('OUTCOME', encodeOutcome(o));
}
