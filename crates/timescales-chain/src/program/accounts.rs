//! Decoders of the v2 Market, Trader and Batch accounts.
//!
//! Each decoder requires what the program's `load` requires: the exact
//! length, the account tag and layout version 2, so a v1 account or a
//! future layout is `Malformed`. It also refuses values the program never
//! writes and the client types cannot hold: an unknown status, abort reason
//! or governance kind, a pending payload of the wrong length, params that
//! do not decode, and a settlement count beyond the bitmaps.

use timescales_core::{Decode, Hash32, MarketParams};

use crate::program::governance::{GovernanceChange, MAX_PAYLOAD, PendingChange};
use crate::program::instructions::{AbortReason, Side};
use crate::program::{ClientError, Key, MAX_DELTAS, MAX_EXECUTORS};

pub const LAYOUT_VERSION: u8 = 2;
pub const MARKET_TAG: u8 = 0x21;
pub const TRADER_TAG: u8 = 0x22;
pub const BATCH_TAG: u8 = 0x23;
pub const MARKET_LEN: usize = 1103;
pub const TRADER_LEN: usize = 148;
pub const BATCH_LEN: usize = 688;

const PARAMS_LEN: usize = 46;
const BITMAP_LEN: usize = MAX_DELTAS / 8;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BatchStatus {
    Committed = 1,
    BeaconRevealed = 2,
    ReceiptPosted = 3,
    Verified = 4,
    Settled = 5,
    Aborted = 6,
}

impl BatchStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Aborted)
    }
}

impl TryFrom<u8> for BatchStatus {
    type Error = ClientError;

    fn try_from(v: u8) -> Result<Self, ClientError> {
        Ok(match v {
            1 => Self::Committed,
            2 => Self::BeaconRevealed,
            3 => Self::ReceiptPosted,
            4 => Self::Verified,
            5 => Self::Settled,
            6 => Self::Aborted,
            _ => return Err(ClientError::Malformed),
        })
    }
}

/// Every field of the v2 Market account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketAccount {
    pub bump: u8,
    pub layout_version: u8,
    /// Bit 0 of the flags byte, the only bit the program reads.
    pub halted: bool,
    pub market_id: u64,
    pub creator: Key,
    pub admin: Key,
    /// `None` when zero.
    pub pending_admin: Option<Key>,
    pub relay: Key,
    pub base_mint: Key,
    pub quote_mint: Key,
    pub base_vault: Key,
    pub quote_vault: Key,
    pub params: MarketParams,
    pub params_digest: Hash32,
    pub committee_digest: Hash32,
    pub executor_count: u8,
    pub receipt_quorum: u8,
    /// Slots are stable. A zero key is an empty slot.
    pub executors: [Key; 8],
    pub beacon_delay_slots: u16,
    pub timelock_slots: u64,
    pub exec_timeout_slots: u64,
    pub settle_timeout_slots: u64,
    pub last_committed: u64,
    pub last_settled: u64,
    pub last_progress_slot: u64,
    pub fees_accrued: u64,
    pub fees_claimed: u64,
    pub prev_receipt: Hash32,
    pub state_root: Hash32,
    pub pending: Option<PendingChange>,
    pub salt: [u8; 32],
    /// Zero until the first `SetCommitteeDigest` applies.
    pub prev_committee_digest: Hash32,
}

impl MarketAccount {
    /// A batch is committed and not yet settled or aborted.
    pub fn in_flight(&self) -> bool {
        self.last_committed != self.last_settled
    }

    pub fn mint(&self, side: Side) -> Key {
        match side {
            Side::Base => self.base_mint,
            Side::Quote => self.quote_mint,
        }
    }

    pub fn vault(&self, side: Side) -> Key {
        match side {
            Side::Base => self.base_vault,
            Side::Quote => self.quote_vault,
        }
    }

    /// The executor slot holding `key`. Zero is never a registered key.
    pub fn executor_slot(&self, key: &Key) -> Option<usize> {
        if *key == [0; 32] {
            return None;
        }
        self.executors.iter().position(|k| k == key)
    }

    /// Bit `i` set for every non-empty executor slot.
    pub fn live_slots(&self) -> u8 {
        self.executors
            .iter()
            .enumerate()
            .filter(|(_, k)| **k != [0; 32])
            .fold(0, |m, (i, _)| m | (1 << i))
    }

    /// Co-signatures of live executors reach the receipt quorum. A removed
    /// executor's signature stops counting.
    pub fn quorum_met(&self, cosign_bitmap: u8) -> bool {
        (cosign_bitmap & self.live_slots()).count_ones() >= u32::from(self.receipt_quorum)
    }

    /// Fees accrued by settled batches and not yet claimed.
    pub fn unclaimed_fees(&self) -> u64 {
        self.fees_accrued.saturating_sub(self.fees_claimed)
    }
}

/// Every field of the v2 Trader account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraderAccount {
    pub bump: u8,
    pub layout_version: u8,
    pub market: Key,
    pub owner: Key,
    /// Credited balance, including any requested amount.
    pub base: u64,
    pub quote: u64,
    pub requested_base: u64,
    pub requested_quote: u64,
    pub request_epoch: u64,
    pub last_leaf_epoch: u64,
    pub last_change_slot: u64,
    pub floor_epoch: u64,
    pub floor_base: u64,
    pub floor_quote: u64,
}

impl TraderAccount {
    /// Per side, the part of the balance batch `epoch` may not use:
    /// `epoch > request_epoch ? min(requested, balance): 0`.
    pub fn reserved(&self, epoch: u64) -> (u64, u64) {
        if epoch > self.request_epoch {
            (
                self.requested_base.min(self.base),
                self.requested_quote.min(self.quote),
            )
        } else {
            (0, 0)
        }
    }
}

/// Every field of the v2 Batch account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchAccount {
    pub bump: u8,
    pub layout_version: u8,
    pub status: BatchStatus,
    pub abort_reason: Option<AbortReason>,
    pub cosign_count: u8,
    pub cosign_bitmap: u8,
    pub market: Key,
    pub epoch: u64,
    pub root: Hash32,
    pub count: u32,
    pub terms_digest: Hash32,
    pub commit_slot: u64,
    pub beacon_slot_a: u64,
    pub beacon_slot_b: u64,
    pub beacon: Hash32,
    pub reveal_slot: u64,
    pub receipt_slot: u64,
    pub header_digest: Hash32,
    pub receipt: Hash32,
    pub outcome_digest: Hash32,
    pub next_state_root: Hash32,
    pub settlement_root: Hash32,
    pub settlement_count: u32,
    pub fees: u64,
    pub verified_count: u32,
    pub applied_count: u32,
    pub sum_base: i128,
    pub sum_quote: i128,
    pub verified: [u8; 128],
    pub applied: [u8; 128],
}

impl BatchAccount {
    /// Leaf indices below `settlement_count` that no `VerifyDeltas` has
    /// verified yet, ascending.
    pub fn missing_verified(&self) -> Vec<u32> {
        missing(&self.verified, self.settlement_count)
    }

    /// Leaf indices below `settlement_count` that no `ApplyDeltas` has
    /// applied yet, ascending.
    pub fn missing_applied(&self) -> Vec<u32> {
        missing(&self.applied, self.settlement_count)
    }
}

/// Leaf `i` is byte `i / 8`, bit `i % 8`, least significant bit first. A
/// count beyond the bitmap (only a hand-built value can have one) reports
/// the leaves it cannot hold as missing.
fn missing(bitmap: &[u8; BITMAP_LEN], count: u32) -> Vec<u32> {
    (0..count)
        .filter(|i| {
            let i = *i as usize;
            bitmap.get(i / 8).is_none_or(|b| b & (1 << (i % 8)) == 0)
        })
        .collect()
}

/// Available balance per side for batch `epoch`: `balance - reserved(t,
/// epoch)`, capped at `i64::MAX` like every off-chain balance. This is
/// the formula of the node's snapshot and the enclave's balance check.
pub fn available(t: &TraderAccount, epoch: u64) -> (u64, u64) {
    const CAP: u64 = i64::MAX as u64;
    let (rb, rq) = t.reserved(epoch);
    ((t.base - rb).min(CAP), (t.quote - rq).min(CAP))
}

/// Exact length, Market tag and layout version.
pub fn decode_market(d: &[u8]) -> Result<MarketAccount, ClientError> {
    let mut r = Reader::account(d, MARKET_LEN, MARKET_TAG)?;
    let (bump, layout_version, flags) = r.prefix()?;
    let market_id = r.u64()?;
    let creator = r.key()?;
    let admin = r.key()?;
    let pending_admin = Some(r.key()?).filter(|k| *k != [0; 32]);
    let relay = r.key()?;
    let base_mint = r.key()?;
    let quote_mint = r.key()?;
    let base_vault = r.key()?;
    let quote_vault = r.key()?;
    let params = MarketParams::decode_exact(&r.array::<PARAMS_LEN>()?)
        .map_err(|_| ClientError::Malformed)?;
    let params_digest = r.hash()?;
    let committee_digest = r.hash()?;
    let executor_count = r.u8()?;
    let receipt_quorum = r.u8()?;
    let mut executors = [[0u8; 32]; MAX_EXECUTORS];
    for e in &mut executors {
        *e = r.key()?;
    }
    let beacon_delay_slots = r.u16()?;
    let timelock_slots = r.u64()?;
    let exec_timeout_slots = r.u64()?;
    let settle_timeout_slots = r.u64()?;
    let last_committed = r.u64()?;
    let last_settled = r.u64()?;
    let last_progress_slot = r.u64()?;
    let fees_accrued = r.u64()?;
    let fees_claimed = r.u64()?;
    let prev_receipt = r.hash()?;
    let state_root = r.hash()?;
    let pending_kind = r.u8()?;
    let pending_eta = r.u64()?;
    let pending_len = r.u16()?;
    let pending_payload = r.array::<MAX_PAYLOAD>()?;
    let pending = pending_change(pending_kind, pending_eta, pending_len, &pending_payload)?;
    let salt = r.key()?;
    let prev_committee_digest = r.hash()?;
    r.finish()?;
    Ok(MarketAccount {
        bump,
        layout_version,
        halted: flags & 1 == 1,
        market_id,
        creator,
        admin,
        pending_admin,
        relay,
        base_mint,
        quote_mint,
        base_vault,
        quote_vault,
        params,
        params_digest,
        committee_digest,
        executor_count,
        receipt_quorum,
        executors,
        beacon_delay_slots,
        timelock_slots,
        exec_timeout_slots,
        settle_timeout_slots,
        last_committed,
        last_settled,
        last_progress_slot,
        fees_accrued,
        fees_claimed,
        prev_receipt,
        state_root,
        pending,
        salt,
        prev_committee_digest,
    })
}

/// Kind 0 is no pending change, whatever the other bytes hold, as in the
/// program.
fn pending_change(
    kind: u8,
    eta_slot: u64,
    len: u16,
    payload: &[u8; MAX_PAYLOAD],
) -> Result<Option<PendingChange>, ClientError> {
    if kind == 0 {
        return Ok(None);
    }
    let payload = payload
        .get(..usize::from(len))
        .ok_or(ClientError::Malformed)?;
    Ok(Some(PendingChange {
        eta_slot,
        change: GovernanceChange::decode(kind, payload)?,
    }))
}

/// Exact length, Trader tag and layout version.
pub fn decode_trader(d: &[u8]) -> Result<TraderAccount, ClientError> {
    let mut r = Reader::account(d, TRADER_LEN, TRADER_TAG)?;
    let (bump, layout_version, _reserved) = r.prefix()?;
    let t = TraderAccount {
        bump,
        layout_version,
        market: r.key()?,
        owner: r.key()?,
        base: r.u64()?,
        quote: r.u64()?,
        requested_base: r.u64()?,
        requested_quote: r.u64()?,
        request_epoch: r.u64()?,
        last_leaf_epoch: r.u64()?,
        last_change_slot: r.u64()?,
        floor_epoch: r.u64()?,
        floor_base: r.u64()?,
        floor_quote: r.u64()?,
    };
    r.finish()?;
    Ok(t)
}

/// Exact length, Batch tag and layout version. The status and abort reason
/// must be known values and `settlement_count` must fit the bitmaps.
pub fn decode_batch(d: &[u8]) -> Result<BatchAccount, ClientError> {
    let mut r = Reader::account(d, BATCH_LEN, BATCH_TAG)?;
    let (bump, layout_version, status) = r.prefix()?;
    let status = BatchStatus::try_from(status)?;
    let abort_reason = match r.u8()? {
        0 => None,
        v => Some(AbortReason::try_from(v)?),
    };
    let cosign_count = r.u8()?;
    let cosign_bitmap = r.u8()?;
    r.u8()?;
    let b = BatchAccount {
        bump,
        layout_version,
        status,
        abort_reason,
        cosign_count,
        cosign_bitmap,
        market: r.key()?,
        epoch: r.u64()?,
        root: r.hash()?,
        count: r.u32()?,
        terms_digest: r.hash()?,
        commit_slot: r.u64()?,
        beacon_slot_a: r.u64()?,
        beacon_slot_b: r.u64()?,
        beacon: r.hash()?,
        reveal_slot: r.u64()?,
        receipt_slot: r.u64()?,
        header_digest: r.hash()?,
        receipt: r.hash()?,
        outcome_digest: r.hash()?,
        next_state_root: r.hash()?,
        settlement_root: r.hash()?,
        settlement_count: r.u32()?,
        fees: r.u64()?,
        verified_count: r.u32()?,
        applied_count: r.u32()?,
        sum_base: r.i128()?,
        sum_quote: r.i128()?,
        verified: r.array()?,
        applied: r.array()?,
    };
    r.array::<32>()?;
    r.finish()?;
    if b.settlement_count as usize > MAX_DELTAS {
        return Err(ClientError::Malformed);
    }
    Ok(b)
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Checks length, tag and layout version, then reads from offset 0.
    fn account(d: &'a [u8], len: usize, tag: u8) -> Result<Self, ClientError> {
        if d.len() != len || d.first() != Some(&tag) || d.get(2) != Some(&LAYOUT_VERSION) {
            return Err(ClientError::Malformed);
        }
        Ok(Self { rest: d })
    }

    /// `tag, bump, layout_version, b3`: returns the last three.
    fn prefix(&mut self) -> Result<(u8, u8, u8), ClientError> {
        let [_tag, bump, version, b3] = self.array()?;
        Ok((bump, version, b3))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ClientError> {
        let (head, tail) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(ClientError::Malformed)?;
        self.rest = tail;
        Ok(*head)
    }

    fn u8(&mut self) -> Result<u8, ClientError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ClientError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ClientError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ClientError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn i128(&mut self) -> Result<i128, ClientError> {
        Ok(i128::from_le_bytes(self.array()?))
    }

    fn key(&mut self) -> Result<Key, ClientError> {
        self.array()
    }

    fn hash(&mut self) -> Result<Hash32, ClientError> {
        Ok(Hash32(self.array()?))
    }

    fn finish(&self) -> Result<(), ClientError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(ClientError::Malformed)
        }
    }
}
