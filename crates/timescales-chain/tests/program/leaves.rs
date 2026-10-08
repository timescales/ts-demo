//! `leaves` gives every delta of a settlement batch with the audit path the
//! program verifies against the batch's settlement root.

#![allow(clippy::unwrap_used)]

use super::common;

use common::{Rng, settlement};
use timescales_chain::program::{ClientError, MAX_DELTAS, leaves};
use timescales_core::Encode;
use timescales_core::merkle::{InclusionProof, leaf_hash};

#[test]
fn every_leaf_proves_against_the_settlement_root() {
    let mut rng = Rng::new(1);
    let sizes = (0..=40).chain([63, 64, 65, 127, 128, 129, 300, 512, 513, 1000, MAX_DELTAS]);
    for n in sizes {
        let batch = settlement(&mut rng, n);
        let tree = batch.tree();
        let root = batch.root();
        let all = leaves(&batch).unwrap();
        assert_eq!(all.len(), n);
        for (i, leaf) in all.iter().enumerate() {
            assert_eq!(usize::try_from(leaf.index).unwrap(), i);
            assert_eq!(leaf.delta, batch.deltas[i]);
            let proof = InclusionProof {
                index: u64::from(leaf.index),
                tree_size: n as u64,
                path: leaf.path.clone(),
            };
            proof
                .verify(&root, &leaf_hash(&leaf.delta.to_bytes()))
                .unwrap();
            // The reference proof is linear in n. Compare a sample.
            if n <= 40 || i % 97 == 0 || i + 1 == n {
                assert_eq!(leaf.path, tree.proof(i).unwrap().path, "n = {n}, i = {i}");
            }
        }
    }
}

#[test]
fn more_deltas_than_a_batch_can_verify_are_refused() {
    let batch = settlement(&mut Rng::new(2), MAX_DELTAS + 1);
    assert!(matches!(
        leaves(&batch),
        Err(ClientError::InvalidArgument(_))
    ));
}
