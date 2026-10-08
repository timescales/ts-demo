import { compare } from '../encoding/bytes.js';
import { DecodeError } from '../encoding/codec.js';
import { merkleRoot } from './merkle.js';

/** Header v2 batch leaf: the commitment and the digest of the exact envelope carrying it. */
export interface BatchLeaf {
  commitment: Uint8Array;
  envelopeDigest: Uint8Array;
}

export const BATCH_LEAF_LEN = 64;

export function encodeLeaf(l: BatchLeaf): Uint8Array {
  if (l.commitment.length !== 32 || l.envelopeDigest.length !== 32)
    throw new RangeError('leaf fields must be 32 bytes');
  const b = new Uint8Array(BATCH_LEAF_LEN);
  b.set(l.commitment, 0);
  b.set(l.envelopeDigest, 32);
  return b;
}

/** Header v2 root: Merkle root over the 64-byte leaves sorted bytewise (a copy is sorted). */
export function batchRootV2(leaves: BatchLeaf[]): Uint8Array {
  return merkleRoot(leaves.map(encodeLeaf).sort(compare));
}

/** Header v1 root: Merkle root over the sorted raw commitments (`v1.json` conformance). */
export function batchRootV1(commitments: Uint8Array[]): Uint8Array {
  return merkleRoot([...commitments].sort(compare));
}

/** `leaves.bin` (`Leaves.leaves_b64`): `count x (C || d)`, sorted. */
export function decodeLeaves(b: Uint8Array): BatchLeaf[] {
  if (b.length % BATCH_LEAF_LEN !== 0) throw new DecodeError('length', 'leaves are 64 bytes each');
  const out: BatchLeaf[] = [];
  for (let at = 0; at < b.length; at += BATCH_LEAF_LEN) {
    if (
      at > 0 &&
      compare(b.subarray(at - BATCH_LEAF_LEN, at), b.subarray(at, at + BATCH_LEAF_LEN)) > 0
    ) {
      throw new DecodeError('value', 'leaves are not sorted');
    }
    out.push({ commitment: b.slice(at, at + 32), envelopeDigest: b.slice(at + 32, at + 64) });
  }
  return out;
}

export function encodeLeaves(leaves: BatchLeaf[]): Uint8Array {
  const sorted = leaves.map(encodeLeaf).sort(compare);
  const out = new Uint8Array(sorted.length * BATCH_LEAF_LEN);
  sorted.forEach((l, i) => out.set(l, i * BATCH_LEAF_LEN));
  return out;
}
