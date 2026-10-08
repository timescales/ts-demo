import type { Reader } from '../encoding/codec.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { MAX_BATCH_ENVELOPES, type BookId, type Role, type Side } from './params.js';
import { readBook } from './receipt.js';
import { merkleRoot } from './merkle.js';
import { readSettlementBatch, writeSettlementBatch, type SettlementBatch } from './settlement.js';

/** Fill (83 B). */
export interface Fill {
  commitment: Uint8Array;
  trader: Uint8Array;
  book: BookId;
  side: Side;
  role: Role;
  quantity: bigint;
  tick: bigint;
}

/** Lists committed to by an outcome's roots: `seq<Fill> || seq<C32> || SettlementBatch`. */
export interface ExecutionArtifacts {
  fills: Fill[];
  cancelled: Uint8Array[];
  settlement: SettlementBatch;
}

export const FILL_LEN = 83;

function tag01(r: Reader): 0 | 1 {
  const v = r.u8();
  if (v > 1) throw new DecodeError('tag', `enum tag ${v}`);
  return v as 0 | 1;
}

export function readFill(r: Reader): Fill {
  return {
    commitment: r.fixed(32),
    trader: r.fixed(32),
    book: readBook(r),
    side: tag01(r),
    role: tag01(r),
    quantity: r.u64(),
    tick: r.u64(),
  };
}

export function writeFill(w: Writer, f: Fill): void {
  w.fixed(f.commitment, 32)
    .fixed(f.trader, 32)
    .u8(f.book)
    .u8(f.side)
    .u8(f.role)
    .u64(f.quantity)
    .u64(f.tick);
}

export function encodeFill(f: Fill): Uint8Array {
  const w = new Writer();
  writeFill(w, f);
  return w.finish();
}

export function decodeArtifacts(b: Uint8Array): ExecutionArtifacts {
  return decodeExact(b, (r) => ({
    fills: r.seq(MAX_BATCH_ENVELOPES, readFill, FILL_LEN),
    cancelled: r.seq(MAX_BATCH_ENVELOPES, (x) => x.fixed(32), 32),
    settlement: readSettlementBatch(r),
  }));
}

export function encodeArtifacts(a: ExecutionArtifacts): Uint8Array {
  const w = new Writer()
    .seq(a.fills, MAX_BATCH_ENVELOPES, writeFill)
    .seq(a.cancelled, MAX_BATCH_ENVELOPES, (x, c) => x.fixed(c, 32));
  writeSettlementBatch(w, a.settlement);
  return w.finish();
}

export function fillsRoot(fills: Fill[]): Uint8Array {
  return merkleRoot(fills.map(encodeFill));
}

/** Root over the raw cancelled commitments, in validation order. */
export function cancelledRoot(cancelled: Uint8Array[]): Uint8Array {
  return merkleRoot(cancelled);
}
