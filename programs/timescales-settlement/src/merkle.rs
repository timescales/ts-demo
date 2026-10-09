//! Domain-separated hashing and RFC 9162 inclusion verification, matching
//! the core crate byte for byte.

use solana_program::hash::hashv;

pub const MERKLE_LEAF: &[u8] = b"timescales/v1/merkle-leaf";
pub const MERKLE_NODE: &[u8] = b"timescales/v1/merkle-node";
pub const RECEIPT: &[u8] = b"timescales/v1/execution-receipt";
pub const OUTCOME: &[u8] = b"timescales/v1/execution-outcome";
pub const BATCH_HEADER: &[u8] = b"timescales/v1/batch-header";
pub const BATCH_SEED: &[u8] = b"timescales/v1/batch-seed";
pub const MARKET_PARAMS: &[u8] = b"timescales/v1/market-params";
pub const MARKET_ID: &[u8] = b"timescales/v1/market-id";
pub const EPOCH_TERMS: &[u8] = b"timescales/v1/epoch-terms";
pub const RECEIPT_COSIGN: &[u8] = b"timescales/v1/receipt-cosign";

/// Most parts any caller passes: the beacon hashes nine.
const MAX_PARTS: usize = 9;

/// `SHA-256(len(tag) || tag || parts...)`, over every part, in one syscall.
pub fn hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let len = [tag.len() as u8];
    let mut all: [&[u8]; MAX_PARTS + 2] = [&[]; MAX_PARTS + 2];
    all[0] = &len;
    all[1] = tag;
    all[2..2 + parts.len()].copy_from_slice(parts);
    hashv(&all[..2 + parts.len()]).to_bytes()
}

pub fn leaf(data: &[u8]) -> [u8; 32] {
    hash(MERKLE_LEAF, &[data])
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    hash(MERKLE_NODE, &[l, r])
}

/// Root implied by an audit path for leaf `index` in a tree of `size`.
pub fn root_from_path(
    leaf: [u8; 32],
    index: u64,
    size: u64,
    path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if index >= size {
        return None;
    }
    let mut f = index;
    let mut s = size - 1;
    let mut r = leaf;
    for p in path {
        if s == 0 {
            return None;
        }
        if f & 1 == 1 || f == s {
            r = node(p, &r);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            r = node(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    (s == 0).then_some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_part_is_hashed() {
        // v1 silently dropped parts after the sixth.
        let parts: Vec<[u8; 1]> = (0u8..9).map(|i| [i]).collect();
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        let joined: Vec<u8> = (0u8..9).collect();
        assert_eq!(hash(OUTCOME, &refs), hash(OUTCOME, &[&joined]));
        let mut fewer = refs.clone();
        fewer.pop();
        assert_ne!(hash(OUTCOME, &refs), hash(OUTCOME, &fewer));
    }
}
