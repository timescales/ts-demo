//! Exact serialized sizes of legacy transactions and the verify/apply chunk
//! planner.

use std::collections::BTreeSet;
use std::ops::Range;

use crate::program::instructions::encode_leaf;
use crate::program::{Ix, Key, Leaf};

/// Largest serialized transaction a Solana packet carries.
pub const MAX_TX_SIZE: usize = 1232;

/// Bytes of a compact-u16 length prefix.
fn short_vec_len(n: usize) -> usize {
    match n {
        0..=0x7f => 1,
        0x80..=0x3fff => 2,
        _ => 3,
    }
}

/// `signatures || header(3) || keys || recent blockhash || instructions`, where
/// each instruction is `program index u8 || account indices || data`.
fn wire_size(
    signatures: usize,
    keys: usize,
    instructions: impl ExactSizeIterator<Item = (usize, usize)>,
) -> usize {
    let mut size = short_vec_len(signatures)
        + 64 * signatures
        + 3
        + short_vec_len(keys)
        + 32 * keys
        + 32
        + short_vec_len(instructions.len());
    for (accounts, data) in instructions {
        size += 1 + short_vec_len(accounts) + accounts + short_vec_len(data) + data;
    }
    size
}

/// Serialized size of a legacy transaction carrying `ixs` with fee payer
/// `payer`, as `Message::new(ixs, Some(payer))` compiles it: every distinct
/// key once, the payer and every key marked as a signer anywhere signing.
/// `signers` is the number of signatures. A transaction carries at least one
/// per signing key, so a smaller value counts as that number.
pub fn legacy_tx_size(ixs: &[Ix], payer: &Key, signers: usize) -> usize {
    let mut keys: BTreeSet<&Key> = BTreeSet::from([payer]);
    let mut signing: BTreeSet<&Key> = BTreeSet::from([payer]);
    for ix in ixs {
        keys.insert(&ix.program);
        for m in &ix.accounts {
            keys.insert(&m.key);
            if m.signer {
                signing.insert(&m.key);
            }
        }
    }
    wire_size(
        signers.max(signing.len()),
        keys.len(),
        ixs.iter().map(|ix| (ix.accounts.len(), ix.data.len())),
    )
}

/// Splits `leaves` into consecutive chunks such that each `VerifyDeltas` or
/// `ApplyDeltas` transaction for a chunk serializes to at most
/// [`MAX_TX_SIZE`] bytes, using as few chunks as possible (each chunk is
/// filled greedily, which is optimal for consecutive chunks).
///
/// The transaction is `[SetComputeUnitLimit, SetComputeUnitPrice]` (with
/// `with_compute_budget`) followed by the delta instruction, signed and paid
/// for by its cranker `payer` alone. Its size depends only on how many
/// distinct accounts it names, not on their addresses: the payer, the
/// program, the market, the batch, the compute-budget program and one
/// Trader PDA per distinct trader. With the compute-budget instructions at
/// least 4 / 3 / 2 leaves fit when their audit paths have at most 4 / 7 /
/// 10 hashes. A single leaf too large for any transaction (a path the
/// program refuses anyway) still gets its own chunk.
pub fn plan_delta_chunks(
    leaves: &[Leaf],
    _payer: &Key,
    with_compute_budget: bool,
) -> Vec<Range<usize>> {
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < leaves.len() {
        let mut end = start + 1;
        while end < leaves.len()
            && end - start < usize::from(u8::MAX)
            && delta_tx_size(&leaves[start..=end], with_compute_budget) <= MAX_TX_SIZE
        {
            end += 1;
        }
        chunks.push(start..end);
        start = end;
    }
    chunks
}

/// [`legacy_tx_size`] of the planner's transaction for `chunk`.
fn delta_tx_size(chunk: &[Leaf], with_compute_budget: bool) -> usize {
    let traders: BTreeSet<_> = chunk.iter().map(|l| l.delta.trader).collect();
    let mut data = vec![0u8; 2];
    for leaf in chunk {
        if encode_leaf(&mut data, leaf).is_err() {
            // A path longer than 255 hashes cannot be encoded at all.
            return usize::MAX;
        }
    }
    let delta = (3 + chunk.len(), data.len());
    if with_compute_budget {
        // SetComputeUnitLimit (u32) and SetComputeUnitPrice (u64).
        wire_size(1, 5 + traders.len(), [(0, 5), (0, 9), delta].into_iter())
    } else {
        wire_size(1, 4 + traders.len(), [delta].into_iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_vec_boundaries() {
        assert_eq!(short_vec_len(0), 1);
        assert_eq!(short_vec_len(0x7f), 1);
        assert_eq!(short_vec_len(0x80), 2);
        assert_eq!(short_vec_len(0x3fff), 2);
        assert_eq!(short_vec_len(0x4000), 3);
    }
}
