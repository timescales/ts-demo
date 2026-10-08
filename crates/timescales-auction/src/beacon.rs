//! Slot-hash beacon v2, byte-identical to the settlement program.
//!
//! ```text
//! target_a = commit_slot + d,  target_b = commit_slot + 2d
//! entry(t) = the SlotHashes entry with the smallest slot >= t
//! beacon   = H(BATCH_SEED, "slot-hash-beacon/v2" || market32 || epoch || root || count
//!                          || slot_a || hash_a || slot_b || hash_b)
//! ```

use timescales_core::crypto::{Hasher, domain};
use timescales_core::{EpochId, Hash32};

/// Entries the SlotHashes sysvar holds at most.
pub const MAX_SLOT_HASHES: usize = 512;

const ENTRY_LEN: usize = 8 + 32;

pub fn beacon_v2(
    market: &[u8; 32],
    epoch: EpochId,
    root: &Hash32,
    count: u32,
    (slot_a, hash_a): (u64, Hash32),
    (slot_b, hash_b): (u64, Hash32),
) -> Hash32 {
    Hasher::new(domain::BATCH_SEED)
        .chain(b"slot-hash-beacon/v2")
        .chain(market)
        .chain(&epoch.0.to_le_bytes())
        .chain(root.as_bytes())
        .chain(&count.to_le_bytes())
        .chain(&slot_a.to_le_bytes())
        .chain(hash_a.as_bytes())
        .chain(&slot_b.to_le_bytes())
        .chain(hash_b.as_bytes())
        .finalize()
}

/// The entry with the smallest slot `>= target` in SlotHashes account data
/// (`u64 N || N x (slot u64 || hash32)`, slots strictly descending).
///
/// `None` when no entry reaches `target`, when `N` exceeds
/// [`MAX_SLOT_HASHES`], or when the data is shorter than `N` entries. Only
/// the entries the binary search visits are read, as on chain.
pub fn slot_hashes_entry(data: &[u8], target: u64) -> Option<(u64, Hash32)> {
    let n = usize::try_from(u64::from_le_bytes(data.get(..8)?.try_into().ok()?)).ok()?;
    if n > MAX_SLOT_HASHES || data.len() < 8 + n * ENTRY_LEN {
        return None;
    }
    let slot_at = |i: usize| {
        let at = 8 + i * ENTRY_LEN;
        u64::from_le_bytes(data[at..at + 8].try_into().unwrap_or([0; 8]))
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
    let i = lo.checked_sub(1)?;
    let at = 8 + i * ENTRY_LEN + 8;
    let hash: [u8; 32] = data[at..at + 32].try_into().ok()?;
    Some((slot_at(i), Hash32(hash)))
}
