import type { Reader } from '../encoding/codec.js';
import { Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';

/**
 * RFC 6962/9162-shaped Merkle tree (`crates/timescales-core/src/merkle`):
 * leaf `H(MERKLE_LEAF, data)`, node `H(MERKLE_NODE, l || r)`, empty root
 * `H(MERKLE_NODE)`, split at the largest power of two strictly below n.
 */
export function leafHash(data: Uint8Array): Uint8Array {
  return H('MERKLE_LEAF', data);
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return H('MERKLE_NODE', left, right);
}

export function emptyRoot(): Uint8Array {
  return H('MERKLE_NODE');
}

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function subRoot(leaves: readonly Uint8Array[], from: number, to: number): Uint8Array {
  const n = to - from;
  if (n === 0) return emptyRoot();
  if (n === 1) return leaves[from]!;
  const k = split(n);
  return nodeHash(subRoot(leaves, from, from + k), subRoot(leaves, from + k, to));
}

/** Root over leaf hashes. */
export function rootOfLeafHashes(leaves: readonly Uint8Array[]): Uint8Array {
  return subRoot(leaves, 0, leaves.length);
}

/** Root over raw leaf data (each element is leaf-hashed). */
export function merkleRoot(data: Uint8Array[]): Uint8Array {
  return rootOfLeafHashes(data.map(leafHash));
}

/** Audit path for `index`, ordered leaf to root, over raw leaf data. */
export function auditPath(data: Uint8Array[], index: number): Uint8Array[] {
  if (!Number.isInteger(index) || index < 0 || index >= data.length)
    throw new RangeError('index out of range');
  const leaves = data.map(leafHash);
  const out: Uint8Array[] = [];
  const walk = (from: number, to: number, m: number): void => {
    const n = to - from;
    if (n <= 1) return;
    const k = split(n);
    if (m < k) {
      walk(from, from + k, m);
      out.push(subRoot(leaves, from + k, to));
    } else {
      walk(from + k, to, m - k);
      out.push(subRoot(leaves, from, from + k));
    }
  };
  walk(0, leaves.length, index);
  return out;
}

/**
 * Root implied by an audit path (RFC 9162 section 2.1.3.2), or null when the index
 * is out of range or the path has the wrong length. `leaf` is the leaf hash.
 */
export function rootFor(
  index: bigint,
  size: bigint,
  path: Uint8Array[],
  leaf: Uint8Array,
): Uint8Array | null {
  if (index < 0n || index >= size) return null;
  let fn = index;
  let sn = size - 1n;
  let r = leaf;
  for (const p of path) {
    if (sn === 0n) return null;
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n ? r : null;
}

export interface InclusionProof {
  index: bigint;
  treeSize: bigint;
  path: Uint8Array[];
}

/** Longest audit path a decoder accepts (as the Rust decoder does). */
export const MAX_PROOF_PATH = 64;

export function encodeInclusionProof(p: InclusionProof): Uint8Array {
  return new Writer()
    .u64(p.index)
    .u64(p.treeSize)
    .seq(p.path, MAX_PROOF_PATH, (w, h) => w.fixed(h, 32))
    .finish();
}

export function decodeInclusionProof(b: Uint8Array): InclusionProof {
  return decodeExact(b, (r: Reader) => ({
    index: r.u64(),
    treeSize: r.u64(),
    path: r.seq(MAX_PROOF_PATH, (x) => x.fixed(32), 32),
  }));
}
