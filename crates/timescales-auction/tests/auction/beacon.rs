//! Beacon v2 and the SlotHashes lookup against hand-built sysvar data.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::BTreeSet;

use proptest::prelude::*;
use timescales_auction::beacon::MAX_SLOT_HASHES;
use timescales_auction::{beacon_v2, slot_hashes_entry};
use timescales_core::crypto::{domain, hash};
use timescales_core::{EpochId, Hash32};

/// Program constant `REVEAL_WINDOW`.
const REVEAL_WINDOW: u64 = 400;

/// A recognisable hash for `slot`: its little-endian bytes, then a marker.
fn slot_hash(slot: u64) -> Hash32 {
    let mut h = [0xa5; 32];
    h[..8].copy_from_slice(&slot.to_le_bytes());
    Hash32(h)
}

/// SlotHashes account data `u64 N || N x (slot u64 || hash32)` for `slots`,
/// which must already be in the sysvar's descending order.
fn sysvar(slots: &[u64]) -> Vec<u8> {
    let mut d = (slots.len() as u64).to_le_bytes().to_vec();
    for s in slots {
        d.extend_from_slice(&s.to_le_bytes());
        d.extend_from_slice(slot_hash(*s).as_bytes());
    }
    d
}

fn entry(slot: u64) -> Option<(u64, Hash32)> {
    Some((slot, slot_hash(slot)))
}

#[test]
fn smallest_slot_at_or_after_the_target() {
    // Slots 103, 106 and 107 were skipped.
    let d = sysvar(&[110, 109, 108, 105, 104, 102, 101, 100]);
    let cases = [
        (110, entry(110)),
        (108, entry(108)),
        (107, entry(108)),
        (106, entry(108)),
        (105, entry(105)),
        (103, entry(104)),
        (100, entry(100)),
        (99, entry(100)),
        (0, entry(100)),
        (111, None),
        (u64::MAX, None),
    ];
    for (target, want) in cases {
        assert_eq!(slot_hashes_entry(&d, target), want, "target {target}");
    }
}

proptest! {
    /// The binary search agrees with a scan for the smallest slot at or
    /// after the target, for any strictly descending sysvar.
    #[test]
    fn lookup_matches_a_linear_scan(
        slots in prop::collection::btree_set(0u64..4_000, 0..=MAX_SLOT_HASHES),
        target in 0u64..4_100,
    ) {
        let descending: Vec<u64> = slots.iter().rev().copied().collect();
        let scan = slots.range(target..).next().map(|s| (*s, slot_hash(*s)));
        prop_assert_eq!(slot_hashes_entry(&sysvar(&descending), target), scan);
    }
}

#[test]
fn single_entry_and_empty_sysvars() {
    let d = sysvar(&[42]);
    assert_eq!(slot_hashes_entry(&d, 42), entry(42));
    assert_eq!(slot_hashes_entry(&d, 7), entry(42));
    assert_eq!(slot_hashes_entry(&d, 43), None);
    assert_eq!(slot_hashes_entry(&sysvar(&[]), 0), None);
}

#[test]
fn malformed_data_yields_nothing() {
    assert_eq!(slot_hashes_entry(&[], 0), None);
    assert_eq!(slot_hashes_entry(&[1, 0, 0], 0), None, "short length");

    let mut short = sysvar(&[9, 8, 7]);
    short.pop();
    assert_eq!(
        slot_hashes_entry(&short, 0),
        None,
        "N says more than present"
    );

    // N above the sysvar's capacity is refused even if the bytes are there.
    let mut too_many = ((MAX_SLOT_HASHES + 1) as u64).to_le_bytes().to_vec();
    too_many.resize(8 + (MAX_SLOT_HASHES + 1) * 40, 0);
    assert_eq!(slot_hashes_entry(&too_many, 0), None);
}

#[test]
fn full_sysvar_with_trailing_space() {
    // The account is allocated for 512 entries. Bytes past N entries are
    // ignored.
    let slots: Vec<u64> = (0..MAX_SLOT_HASHES as u64)
        .rev()
        .map(|i| 1_000 + 2 * i)
        .collect();
    let mut d = sysvar(&slots);
    let used = d.len();
    d.resize(used + 40, 0xff);
    assert_eq!(slot_hashes_entry(&d, 1_000), entry(1_000));
    assert_eq!(slot_hashes_entry(&d, 1_001), entry(1_002));
    let newest = 1_000 + 2 * (MAX_SLOT_HASHES as u64 - 1);
    assert_eq!(slot_hashes_entry(&d, newest), entry(newest));
    assert_eq!(slot_hashes_entry(&d, newest + 1), None);
}

#[test]
fn beacon_v2_layout() {
    let market = [0x11; 32];
    let root = Hash32([0x22; 32]);
    let a = (1_004, Hash32([0xa1; 32]));
    let b = (1_009, Hash32([0xb2; 32]));
    let beacon = beacon_v2(&market, EpochId(7), &root, 64, a, b);

    let mut preimage = b"slot-hash-beacon/v2".to_vec();
    preimage.extend_from_slice(&market);
    preimage.extend_from_slice(&7u64.to_le_bytes());
    preimage.extend_from_slice(root.as_bytes());
    preimage.extend_from_slice(&64u32.to_le_bytes());
    preimage.extend_from_slice(&a.0.to_le_bytes());
    preimage.extend_from_slice(a.1.as_bytes());
    preimage.extend_from_slice(&b.0.to_le_bytes());
    preimage.extend_from_slice(b.1.as_bytes());
    assert_eq!(beacon, hash(domain::BATCH_SEED, &preimage));
    // Computed independently (Python hashlib) from the header layout.
    assert_eq!(
        beacon.to_hex(),
        "8d91f6c654fb8a994d3e83a432232e551740c911cacf99d5989a247a8fe0ee3c"
    );

    // Every input is bound.
    let others = [
        beacon_v2(&[0x12; 32], EpochId(7), &root, 64, a, b),
        beacon_v2(&market, EpochId(8), &root, 64, a, b),
        beacon_v2(&market, EpochId(7), &Hash32([0x23; 32]), 64, a, b),
        beacon_v2(&market, EpochId(7), &root, 65, a, b),
        beacon_v2(&market, EpochId(7), &root, 64, (1_005, a.1), b),
        beacon_v2(
            &market,
            EpochId(7),
            &root,
            64,
            a,
            (1_009, Hash32([0xb3; 32])),
        ),
        beacon_v2(&market, EpochId(7), &root, 64, b, a),
    ];
    for o in others {
        assert_ne!(o, beacon);
    }
}

/// SlotHashes as the program sees it while executing in `slot`: the newest
/// `MAX_SLOT_HASHES` produced slots before it, newest first.
fn sysvar_at(slot: u64, produced: &BTreeSet<u64>) -> Vec<u8> {
    let slots: Vec<u64> = produced
        .range(..slot)
        .rev()
        .take(MAX_SLOT_HASHES)
        .copied()
        .collect();
    sysvar(&slots)
}

/// Inside the reveal window the beacon depends only on the fork
/// history, never on when the reveal lands, and skipped targets move to the
/// next produced slot.
#[test]
fn reveal_time_does_not_change_the_beacon() {
    let (commit_slot, d) = (2_000u64, 4u64);
    let (target_a, target_b) = (commit_slot + d, commit_slot + 2 * d);
    let skipped: BTreeSet<u64> = [target_a, target_b, target_b + 1, 2_100].into();
    let produced: BTreeSet<u64> = (1_000..3_000).filter(|s| !skipped.contains(s)).collect();
    let market = [0x33; 32];
    let root = Hash32([0x44; 32]);

    let lookup = |slot| {
        let data = sysvar_at(slot, &produced);
        Some((
            slot_hashes_entry(&data, target_a)?,
            slot_hashes_entry(&data, target_b)?,
        ))
    };

    // Before a slot at or after target_b has been produced and hashed, the
    // reveal is not ready.
    for slot in commit_slot..=target_b + 2 {
        assert!(lookup(slot).is_none(), "ready too early at {slot}");
    }

    let first_ready = target_b + 3;
    let (a, b) = lookup(first_ready).unwrap();
    assert_eq!(a, (target_a + 1, slot_hash(target_a + 1)));
    assert_eq!(b, (target_b + 2, slot_hash(target_b + 2)));
    let beacon = beacon_v2(&market, EpochId(5), &root, 16, a, b);
    for slot in first_ready..=commit_slot + d + REVEAL_WINDOW {
        let (a2, b2) = lookup(slot).unwrap();
        assert_eq!(
            beacon_v2(&market, EpochId(5), &root, 16, a2, b2),
            beacon,
            "reveal at {slot}"
        );
    }

    // Once target_a has left the 512 entries the lookup would pick a later
    // slot, so the program refuses reveals after the window.
    let late = commit_slot + d + 600;
    let (late_a, _) = lookup(late).unwrap();
    assert_ne!(late_a, a);
}
