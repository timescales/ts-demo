//! Audit paths for every leaf of a settlement tree from one pass over the
//! tree. `timescales_core::merkle::MerkleTree::proof` rebuilds the subtrees
//! for each proof, which is quadratic over a whole batch.

use timescales_core::Hash32;
use timescales_core::merkle::{leaf_hash, node_hash};

/// Every level of the RFC 6962 tree, leaves first. Adjacent nodes pair up
/// and an odd last node moves up unchanged. For any leaf count this is the
/// tree that splits at the largest power of two below the count, built with
/// `n - 1` node hashes.
pub(crate) struct Levels(Vec<Vec<Hash32>>);

impl Levels {
    pub(crate) fn over<T: AsRef<[u8]>>(leaves: impl IntoIterator<Item = T>) -> Self {
        let mut levels = vec![
            leaves
                .into_iter()
                .map(|d| leaf_hash(d.as_ref()))
                .collect::<Vec<_>>(),
        ];
        while let Some(level) = levels.last()
            && level.len() > 1
        {
            let up = level
                .chunks(2)
                .filter_map(|pair| pair.iter().copied().reduce(|l, r| node_hash(&l, &r)))
                .collect();
            levels.push(up);
        }
        Self(levels)
    }

    /// Siblings of leaf `index` from the leaf upwards, the order of
    /// `timescales_core::merkle::InclusionProof::path`. A node that moved up
    /// unchanged has no sibling at that level.
    pub(crate) fn path(&self, mut index: usize) -> Vec<Hash32> {
        let below_root = self.0.len().saturating_sub(1);
        let mut path = Vec::with_capacity(below_root);
        for level in &self.0[..below_root] {
            if let Some(sibling) = level.get(index ^ 1) {
                path.push(*sibling);
            }
            index /= 2;
        }
        path
    }

    #[cfg(test)]
    fn root(&self) -> Option<Hash32> {
        self.0.last()?.first().copied()
    }
}

#[cfg(test)]
mod tests {
    use timescales_core::merkle::{MerkleTree, empty_root};

    use super::*;

    fn check(n: usize, indices: impl Iterator<Item = usize>) {
        let data: Vec<[u8; 8]> = (0..n as u64).map(u64::to_le_bytes).collect();
        let reference = MerkleTree::from_data(&data);
        let levels = Levels::over(&data);
        assert_eq!(
            levels.root().unwrap_or_else(empty_root),
            reference.root(),
            "n = {n}"
        );
        for i in indices {
            assert_eq!(
                levels.path(i),
                reference.proof(i).unwrap().path,
                "n = {n}, i = {i}"
            );
        }
    }

    #[test]
    fn same_root_and_paths_as_the_reference_tree() {
        for n in 0..=70 {
            check(n, 0..n);
        }
        // Around powers of two and at the batch limit. The reference proof
        // is linear in n, so only some leaves.
        for n in [127, 128, 129, 255, 256, 257, 511, 513, 1000, 1024] {
            check(n, (0..n).step_by(37).chain([n / 2, n - 2, n - 1]));
        }
    }
}
