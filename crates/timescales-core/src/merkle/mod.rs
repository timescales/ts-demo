//! Merkle trees with the shape of RFC 6962 / RFC 9162.
//!
//! * Leaf hash: `H(MERKLE_LEAF, data)`
//! * Node hash: `H(MERKLE_NODE, left || right)`
//! * An `n`-leaf tree splits at the largest power of two strictly below `n`
//!
//! The split rule means the tree for a given leaf sequence is unique and no
//! leaf is ever duplicated to pad the tree, which rules out the classic
//! "duplicate last leaf" second-preimage ambiguity. Domain separation between
//! leaves and nodes rules out the leaf/node confusion.
//!
//! The empty tree has root `H(MERKLE_NODE, "")`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use crate::crypto::{Hasher, domain, hash};
use crate::{Decode, DecodeError, Encode, Hash32, Reader};
use thiserror::Error;

/// Inclusion proofs are bounded by the tree depth. 64 covers any `u64` size.
pub const MAX_PROOF_LEN: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MerkleError {
    #[error("leaf index {index} out of range for tree of size {size}")]
    IndexOutOfRange { index: u64, size: u64 },
    #[error("proof has wrong length")]
    BadProofLength,
    #[error("root mismatch")]
    RootMismatch,
}

pub fn leaf_hash(data: &[u8]) -> Hash32 {
    hash(domain::MERKLE_LEAF, data)
}

pub fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    Hasher::new(domain::MERKLE_NODE)
        .chain(left.as_bytes())
        .chain(right.as_bytes())
        .finalize()
}

pub fn empty_root() -> Hash32 {
    hash(domain::MERKLE_NODE, &[])
}

/// Largest power of two strictly less than `n` (`n >= 2`).
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Tree over precomputed leaf hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleTree {
    leaves: Vec<Hash32>,
    root: Hash32,
}

impl MerkleTree {
    pub fn from_leaf_hashes(leaves: Vec<Hash32>) -> Self {
        let root = if leaves.is_empty() {
            empty_root()
        } else {
            subtree_root(&leaves)
        };
        Self { leaves, root }
    }

    pub fn from_data<T: AsRef<[u8]>>(items: &[T]) -> Self {
        Self::from_leaf_hashes(items.iter().map(|d| leaf_hash(d.as_ref())).collect())
    }

    pub fn root(&self) -> Hash32 {
        self.root
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn leaf(&self, index: usize) -> Option<&Hash32> {
        self.leaves.get(index)
    }

    /// Every level of the tree, bottom up: the leaf hashes first and, for a
    /// non-empty tree, the root alone last. A node without a right sibling
    /// moves up unchanged, which yields exactly the tree of the RFC 6962
    /// split rule. The empty tree has one empty level. Its root
    /// ([`empty_root`]) is not a node.
    pub fn levels(&self) -> Vec<Vec<Hash32>> {
        let mut levels = vec![self.leaves.clone()];
        while let Some(below) = levels.last().filter(|l| l.len() > 1) {
            let above = below
                .chunks(2)
                .map(|pair| match pair {
                    [left, right] => node_hash(left, right),
                    [promoted] => *promoted,
                    _ => unreachable!("chunks(2) yields one or two hashes"),
                })
                .collect();
            levels.push(above);
        }
        levels
    }

    /// Inclusion proofs for every leaf, in leaf order. The levels are built
    /// once, so all `n` proofs cost `O(n)` hashing instead of `O(n)` each.
    pub fn proofs_all(&self) -> Vec<InclusionProof> {
        let levels = self.levels();
        let below_root = &levels[..levels.len() - 1];
        (0..self.leaves.len())
            .map(|index| {
                let mut path = Vec::with_capacity(below_root.len());
                let mut at = index;
                for level in below_root {
                    // A left node at the end of its level has no sibling and
                    // was promoted unchanged.
                    if let Some(sibling) = level.get(at ^ 1) {
                        path.push(*sibling);
                    }
                    at >>= 1;
                }
                InclusionProof {
                    index: index as u64,
                    tree_size: self.leaves.len() as u64,
                    path,
                }
            })
            .collect()
    }

    /// Audit path for `index`, ordered from the leaf upwards.
    pub fn proof(&self, index: usize) -> Result<InclusionProof, MerkleError> {
        if index >= self.leaves.len() {
            return Err(MerkleError::IndexOutOfRange {
                index: index as u64,
                size: self.leaves.len() as u64,
            });
        }
        let mut path = Vec::new();
        audit_path(&self.leaves, index, &mut path);
        Ok(InclusionProof {
            index: index as u64,
            tree_size: self.leaves.len() as u64,
            path,
        })
    }
}

fn subtree_root(leaves: &[Hash32]) -> Hash32 {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&subtree_root(&leaves[..k]), &subtree_root(&leaves[k..]))
        }
    }
}

/// Pushes siblings bottom-up (the recursion bottoms out first).
fn audit_path(leaves: &[Hash32], m: usize, out: &mut Vec<Hash32>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split_point(n);
    if m < k {
        audit_path(&leaves[..k], m, out);
        out.push(subtree_root(&leaves[k..]));
    } else {
        audit_path(&leaves[k..], m - k, out);
        out.push(subtree_root(&leaves[..k]));
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: u64,
    pub tree_size: u64,
    pub path: Vec<Hash32>,
}

impl InclusionProof {
    /// RFC 9162 section 2.1.3.2 verification.
    pub fn root_for(&self, leaf: &Hash32) -> Result<Hash32, MerkleError> {
        if self.index >= self.tree_size {
            return Err(MerkleError::IndexOutOfRange {
                index: self.index,
                size: self.tree_size,
            });
        }
        let mut fn_ = self.index;
        let mut sn = self.tree_size - 1;
        let mut r = *leaf;
        for p in &self.path {
            if sn == 0 {
                return Err(MerkleError::BadProofLength);
            }
            if fn_ & 1 == 1 || fn_ == sn {
                r = node_hash(p, &r);
                if fn_ & 1 == 0 {
                    while fn_ & 1 == 0 && fn_ != 0 {
                        fn_ >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                r = node_hash(&r, p);
            }
            fn_ >>= 1;
            sn >>= 1;
        }
        if sn != 0 {
            return Err(MerkleError::BadProofLength);
        }
        Ok(r)
    }

    pub fn verify(&self, root: &Hash32, leaf: &Hash32) -> Result<(), MerkleError> {
        if self.root_for(leaf)? == *root {
            Ok(())
        } else {
            Err(MerkleError::RootMismatch)
        }
    }
}

impl Encode for InclusionProof {
    fn encode(&self, out: &mut Vec<u8>) {
        self.index.encode(out);
        self.tree_size.encode(out);
        crate::encoding::put_seq(out, &self.path);
    }
}

impl Decode for InclusionProof {
    const MIN_ENCODED_LEN: usize = 8 + 8 + 4;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(InclusionProof {
            index: r.u64()?,
            tree_size: r.u64()?,
            path: r.seq(MAX_PROOF_LEN)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn tree(n: usize) -> MerkleTree {
        let data: Vec<Vec<u8>> = (0..n).map(|i| (i as u64).to_le_bytes().to_vec()).collect();
        MerkleTree::from_data(&data)
    }

    #[test]
    fn small_trees_match_definition() {
        let t1 = tree(1);
        assert_eq!(t1.root(), leaf_hash(&0u64.to_le_bytes()));
        let t3 = tree(3);
        let l: Vec<_> = (0..3u64).map(|i| leaf_hash(&i.to_le_bytes())).collect();
        assert_eq!(t3.root(), node_hash(&node_hash(&l[0], &l[1]), &l[2]));
        assert_eq!(tree(0).root(), empty_root());
    }

    #[test]
    fn proof_rejects_wrong_position() {
        let t = tree(7);
        let p = t.proof(3).unwrap();
        let mut wrong = p.clone();
        wrong.index = 4;
        assert!(wrong.verify(&t.root(), t.leaf(3).unwrap()).is_err());
        let mut short = p.clone();
        short.path.pop();
        assert!(short.verify(&t.root(), t.leaf(3).unwrap()).is_err());
        let mut long = p;
        long.path.push(Hash32::ZERO);
        assert!(long.verify(&t.root(), t.leaf(3).unwrap()).is_err());
    }

    #[test]
    fn every_merkle_error_is_produced() {
        // Exhaustive on purpose: a new variant must be produced here.
        fn variant(e: &MerkleError) -> usize {
            match e {
                MerkleError::IndexOutOfRange { .. } => 0,
                MerkleError::BadProofLength => 1,
                MerkleError::RootMismatch => 2,
            }
        }
        let t = tree(5);
        let leaf = t.leaf(2).unwrap();
        let mut short = t.proof(2).unwrap();
        short.path.pop();
        let errors = [
            t.proof(5).map(|_| ()),
            short.verify(&t.root(), leaf),
            t.proof(2).unwrap().verify(&Hash32::ZERO, leaf),
        ];
        let seen: Vec<usize> = errors
            .iter()
            .map(|e| variant(e.as_ref().unwrap_err()))
            .collect();
        assert_eq!(seen, [0, 1, 2]);
    }

    #[test]
    fn levels_build_the_split_rule_tree() {
        assert_eq!(tree(0).levels(), vec![Vec::<Hash32>::new()]);
        for n in 1..=70 {
            let t = tree(n);
            let levels = t.levels();
            assert_eq!(levels[0].len(), n);
            assert_eq!(levels.last().map(Vec::as_slice), Some(&[t.root()][..]));
            // Each level halves, rounding up.
            for pair in levels.windows(2) {
                assert_eq!(pair[1].len(), pair[0].len().div_ceil(2));
            }
        }
    }

    #[test]
    fn shortest_proof_encoding() {
        let p = tree(1).proof(0).unwrap();
        assert!(p.path.is_empty());
        assert_eq!(p.to_bytes().len(), InclusionProof::MIN_ENCODED_LEN);
    }

    #[test]
    fn proofs_all_equals_each_proof() {
        assert!(tree(0).proofs_all().is_empty());
        for n in 1..=70 {
            let t = tree(n);
            let all = t.proofs_all();
            assert_eq!(all.len(), n);
            for (i, p) in all.iter().enumerate() {
                assert_eq!(p, &t.proof(i).unwrap(), "n={n} i={i}");
                assert!(p.verify(&t.root(), t.leaf(i).unwrap()).is_ok());
            }
        }
    }

    proptest! {
        #[test]
        fn proofs_all_matches_proof(n in 1usize..1100, pick in any::<prop::sample::Index>()) {
            let t = tree(n);
            let all = t.proofs_all();
            let i = pick.index(n);
            prop_assert_eq!(&all[i], &t.proof(i).unwrap());
            prop_assert!(all[i].verify(&t.root(), t.leaf(i).unwrap()).is_ok());
        }

        #[test]
        fn every_leaf_proves(n in 1usize..200, pick in any::<prop::sample::Index>()) {
            let t = tree(n);
            let i = pick.index(n);
            let p = t.proof(i).unwrap();
            prop_assert!(p.verify(&t.root(), t.leaf(i).unwrap()).is_ok());
            prop_assert_eq!(InclusionProof::decode_exact(&p.to_bytes()).unwrap(), p);
        }
    }
}
