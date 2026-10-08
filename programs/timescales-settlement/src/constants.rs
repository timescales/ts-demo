//! Protocol constants and configuration bounds.

pub const MAX_EXECUTORS: usize = 8;
/// Settlement deltas per batch. Equals `MAX_SETTLEMENT_DELTAS` off chain.
/// `InitMarket` requires `max_batch_envelopes <= MAX_DELTAS`, so a batch can
/// never have more deltas than its bitmaps hold.
pub const MAX_DELTAS: usize = 1024;
pub const MAX_PATH: usize = 16;
pub const HEADER_LEN: usize = 283;
pub const HEADER_VERSION: u8 = 2;
pub const RECEIPT_VERSION: u8 = 1;
/// Only TEE receipts settle (`BackendKind::Tee`).
pub const BACKEND_TEE: u8 = 1;

/// Slots after `commit_slot + d` during which the beacon can be revealed.
/// Both targets stay inside the 512-entry SlotHashes for the whole window.
pub const REVEAL_WINDOW: u64 = 400;

/// Lower bound for `timelock_slots` outside local builds (about one day).
pub const PRODUCTION_MIN_TIMELOCK: u64 = 216_000;
/// Lower bound for `timelock_slots` in this build: zero for the local
/// validator and LiteSVM, so tests and the local stack need not wait a day.
pub const MIN_TIMELOCK: u64 = if cfg!(feature = "localnet") {
    0
} else {
    PRODUCTION_MIN_TIMELOCK
};
pub const MAX_TIMELOCK: u64 = 2_592_000;

pub const MIN_BEACON_DELAY: u16 = 4;
pub const MAX_BEACON_DELAY: u16 = 64;
pub const MIN_EXEC_TIMEOUT: u64 = 150;
pub const MAX_EXEC_TIMEOUT: u64 = 216_000;
pub const MAX_SETTLE_TIMEOUT: u64 = 1_296_000;

/// Epochs a terminal batch is kept before `ReclaimBatch`.
pub const BATCH_RETENTION: u64 = 1024;
/// Deposit cap, so balances stay representable as `i64` off chain.
pub const MAX_BALANCE: u64 = i64::MAX as u64;

/// `H_merkle-node("")`: the state root of a market before its first batch,
/// equal to `timescales_core::merkle::empty_root`.
pub const EMPTY_STATE_ROOT: [u8; 32] = [
    0x70, 0xce, 0x57, 0x60, 0x30, 0x71, 0x45, 0x2b, 0x06, 0xad, 0xa7, 0x13, 0xd6, 0x0a, 0xf7, 0x3a,
    0xe1, 0x64, 0x13, 0x8e, 0x22, 0x90, 0xa7, 0x94, 0x27, 0x41, 0xa3, 0xf5, 0x19, 0x17, 0x44, 0x66,
];

/// Bounds on the timing configuration, shared by `InitMarket` and
/// `SetTimings`.
pub fn timings_in_bounds(beacon_delay: u16, exec_timeout: u64, settle_timeout: u64) -> bool {
    (MIN_BEACON_DELAY..=MAX_BEACON_DELAY).contains(&beacon_delay)
        && (MIN_EXEC_TIMEOUT..=MAX_EXEC_TIMEOUT).contains(&exec_timeout)
        && exec_timeout
            .checked_mul(2)
            .is_some_and(|lo| (lo..=MAX_SETTLE_TIMEOUT).contains(&settle_timeout))
}

/// `min_timelock <= slots <= MAX_TIMELOCK`. The program passes
/// [`MIN_TIMELOCK`].
pub fn timelock_in_bounds(slots: u64, min_timelock: u64) -> bool {
    (min_timelock..=MAX_TIMELOCK).contains(&slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_timelock_depends_only_on_the_localnet_feature() {
        if cfg!(feature = "localnet") {
            assert_eq!(MIN_TIMELOCK, 0);
        } else {
            assert_eq!(MIN_TIMELOCK, 216_000);
        }
    }

    #[test]
    fn a_production_build_refuses_a_timelock_below_one_day() {
        assert!(!timelock_in_bounds(0, PRODUCTION_MIN_TIMELOCK));
        assert!(!timelock_in_bounds(215_999, PRODUCTION_MIN_TIMELOCK));
        assert!(timelock_in_bounds(216_000, PRODUCTION_MIN_TIMELOCK));
        assert!(timelock_in_bounds(MAX_TIMELOCK, PRODUCTION_MIN_TIMELOCK));
        assert!(!timelock_in_bounds(
            MAX_TIMELOCK + 1,
            PRODUCTION_MIN_TIMELOCK
        ));
        assert!(timelock_in_bounds(0, 0));
    }

    #[test]
    fn timing_bounds() {
        assert!(timings_in_bounds(4, 150, 300));
        assert!(timings_in_bounds(64, 216_000, 1_296_000));
        assert!(!timings_in_bounds(3, 150, 300));
        assert!(!timings_in_bounds(65, 150, 300));
        assert!(!timings_in_bounds(4, 149, 300));
        assert!(!timings_in_bounds(4, 150, 299));
        assert!(!timings_in_bounds(4, 216_001, 1_296_000));
        assert!(!timings_in_bounds(4, 150, 1_296_001));
    }

    #[test]
    fn empty_state_root_is_the_empty_merkle_node_hash() {
        assert_eq!(
            crate::merkle::hash(crate::merkle::MERKLE_NODE, &[]),
            EMPTY_STATE_ROOT
        );
    }
}
