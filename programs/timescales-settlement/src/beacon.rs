//! Beacon v2: two SlotHashes entries chosen after the root is fixed.
//!
//! ```text
//! target_a = commit_slot + d,  target_b = commit_slot + 2d
//! entry(t) = the SlotHashes entry with the smallest slot >= t
//! beacon   = H(BATCH_SEED, "slot-hash-beacon/v2" || market32 || epoch || root || count
//!                          || slot_a || hash_a || slot_b || hash_b)
//! ```
//!
//! Inside the reveal window both targets are still in SlotHashes, so the
//! result depends only on fork history, not on who reveals or when.
//! Mirrored off chain by `timescales_auction::{beacon_v2, slot_hashes_entry}`.

use crate::merkle::{self, BATCH_SEED};

pub const MAX_SLOT_HASHES: usize = 512;
const ENTRY_LEN: usize = 8 + 32;

#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    Found(u64, [u8; 32]),
    /// No entry has reached the target yet.
    NotReady,
    /// The data is not a SlotHashes encoding.
    Malformed,
}

/// The entry with the smallest slot `>= target` in SlotHashes account data
/// (`u64 N || N x (slot u64 || hash32)`, slots strictly descending). Binary
/// search, so only `log2(N)` entries are read.
pub fn slot_hashes_entry(data: &[u8], target: u64) -> Lookup {
    let Some(n) = data
        .get(..8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0xff; 8])))
    else {
        return Lookup::Malformed;
    };
    let n = match usize::try_from(n) {
        Ok(n) if n <= MAX_SLOT_HASHES && data.len() >= 8 + n * ENTRY_LEN => n,
        _ => return Lookup::Malformed,
    };
    let slot_at = |i: usize| {
        let at = 8 + i * ENTRY_LEN;
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[at..at + 8]);
        u64::from_le_bytes(b)
    };
    // Entries with slot >= target form a prefix. Find its length.
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if slot_at(mid) >= target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let Some(i) = lo.checked_sub(1) else {
        return Lookup::NotReady;
    };
    let at = 8 + i * ENTRY_LEN + 8;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[at..at + 32]);
    Lookup::Found(slot_at(i), hash)
}

pub fn beacon_v2(
    market: &[u8; 32],
    epoch: u64,
    root: &[u8; 32],
    count: u32,
    (slot_a, hash_a): (u64, [u8; 32]),
    (slot_b, hash_b): (u64, [u8; 32]),
) -> [u8; 32] {
    merkle::hash(
        BATCH_SEED,
        &[
            b"slot-hash-beacon/v2",
            market,
            &epoch.to_le_bytes(),
            root,
            &count.to_le_bytes(),
            &slot_a.to_le_bytes(),
            &hash_a,
            &slot_b.to_le_bytes(),
            &hash_b,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(slots: &[u64]) -> Vec<u8> {
        let mut d = (slots.len() as u64).to_le_bytes().to_vec();
        for s in slots {
            d.extend_from_slice(&s.to_le_bytes());
            d.extend_from_slice(&[*s as u8; 32]);
        }
        d
    }

    #[test]
    fn smallest_slot_at_or_after_target() {
        let d = data(&[20, 18, 15, 11]);
        assert_eq!(slot_hashes_entry(&d, 15), Lookup::Found(15, [15; 32]));
        assert_eq!(slot_hashes_entry(&d, 16), Lookup::Found(18, [18; 32]));
        assert_eq!(slot_hashes_entry(&d, 0), Lookup::Found(11, [11; 32]));
        assert_eq!(slot_hashes_entry(&d, 21), Lookup::NotReady);
        assert_eq!(slot_hashes_entry(&data(&[]), 1), Lookup::NotReady);
    }

    #[test]
    fn malformed_data() {
        assert_eq!(slot_hashes_entry(&[1, 0], 0), Lookup::Malformed);
        let mut d = data(&[5]);
        d.pop();
        assert_eq!(slot_hashes_entry(&d, 0), Lookup::Malformed);
        let mut big = 513u64.to_le_bytes().to_vec();
        big.resize(8 + 513 * 40, 0);
        assert_eq!(slot_hashes_entry(&big, 0), Lookup::Malformed);
    }
}
