//! Account layouts. Fixed size, little-endian, no framework: what is
//! written here is exactly what the chain crate decodes off chain. The
//! offsets are the ones clients filter on.
//!
//! Accounts are read and written in place through views, so an
//! instruction copies only the fields it reads and rewrites only the
//! bytes it changes.

use core::cell::{Ref, RefMut};
use core::ops::{Deref, DerefMut};

use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;

use crate::constants::{MAX_DELTAS, MAX_EXECUTORS};
use crate::error::TimescalesError;

pub const LAYOUT_VERSION: u8 = 2;
pub const MARKET_TAG: u8 = 0x21;
pub const TRADER_TAG: u8 = 0x22;
pub const BATCH_TAG: u8 = 0x23;

pub const MARKET_LEN: usize = 1103;
pub const TRADER_LEN: usize = 148;
pub const BATCH_LEN: usize = 688;

const BITMAP: usize = MAX_DELTAS / 8;
pub const PARAMS_LEN: usize = 46;
pub const MAX_PAYLOAD: usize = 262;

pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(TimescalesError::InvalidInstruction)?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(TimescalesError::InvalidInstruction)?;
        self.pos = end;
        Ok(s)
    }

    /// `N` bytes, borrowed.
    pub fn fixed<const N: usize>(&mut self) -> Result<&'a [u8; N], ProgramError> {
        self.take(N)?
            .try_into()
            .map_err(|_| TimescalesError::InvalidInstruction.into())
    }

    /// `n` runs of `N` bytes, borrowed.
    pub fn chunks<const N: usize>(&mut self, n: usize) -> Result<&'a [[u8; N]], ProgramError> {
        let len = n
            .checked_mul(N)
            .ok_or(TimescalesError::InvalidInstruction)?;
        Ok(self.take(len)?.as_chunks::<N>().0)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProgramError> {
        Ok(*self.fixed()?)
    }

    pub fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }

    /// A strict boolean byte: `0` or `1`, anything else is malformed.
    pub fn flag(&mut self) -> Result<bool, ProgramError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(TimescalesError::InvalidInstruction.into()),
        }
    }

    pub fn u16(&mut self) -> Result<u16, ProgramError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, ProgramError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, ProgramError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn i64(&mut self) -> Result<i64, ProgramError> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    pub fn key(&mut self) -> Result<[u8; 32], ProgramError> {
        self.array()
    }

    pub fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Account data behind a view, borrowed shared.
pub type Shared<'r> = Ref<'r, [u8]>;
/// Account data behind a view, borrowed exclusively.
pub type Exclusive<'r> = RefMut<'r, [u8]>;

/// A borrow that fails only when the account is already held by this
/// instruction, which means it was passed in two roles.
pub fn shared<'r>(acc: &'r AccountInfo<'_>) -> Result<Shared<'r>, ProgramError> {
    let d = acc
        .try_borrow_data()
        .map_err(|_| TimescalesError::InvalidAccount)?;
    Ok(Ref::map(d, |d| &**d))
}

pub fn exclusive<'r>(acc: &'r AccountInfo<'_>) -> Result<Exclusive<'r>, ProgramError> {
    let d = acc
        .try_borrow_mut_data()
        .map_err(|_| TimescalesError::InvalidAccount)?;
    Ok(RefMut::map(d, |d| &mut **d))
}

/// Exact length, tag and layout version. Anything else (including a v1
/// account) is `InvalidAccount`.
fn header(d: &[u8], len: usize, tag: u8) -> Result<(), ProgramError> {
    if d.len() != len || d[0] != tag || d[2] != LAYOUT_VERSION {
        return Err(TimescalesError::InvalidAccount.into());
    }
    Ok(())
}

/// A fixed-width little-endian field.
trait Field: Copy {
    const LEN: usize;
    fn read(b: &[u8]) -> Self;
    fn write(self, b: &mut [u8]);
}

macro_rules! int_fields {
    ($($t:ty),*) => {$(
        impl Field for $t {
            const LEN: usize = core::mem::size_of::<$t>();

            fn read(b: &[u8]) -> Self {
                Self::from_le_bytes(b.try_into().expect("field width"))
            }

            fn write(self, b: &mut [u8]) {
                b.copy_from_slice(&self.to_le_bytes());
            }
        }
    )*};
}

int_fields!(u8, u16, u32, u64, i128);

/// A view type over one layout. `ints` are read by value and `bytes` by
/// reference, each at its offset.
macro_rules! view {
    (
        $(#[$doc:meta])*
        $name:ident, $len:expr, $tag:expr;
        ints { $( $f:ident / $s:ident : $t:ty = $o:expr; )* }
        bytes { $( $bf:ident / $bs:ident : $n:tt = $bo:expr; )* }
    ) => {
        $(#[$doc])*
        pub struct $name<D>(D);

        impl<D: Deref<Target = [u8]>> $name<D> {
            /// A view over an existing account.
            pub fn view(d: D) -> Result<Self, ProgramError> {
                header(&d, $len, $tag)?;
                Ok(Self(d))
            }

            fn get<T: Field>(&self, off: usize) -> T {
                T::read(&self.0[off..off + T::LEN])
            }

            fn bytes<const N: usize>(&self, off: usize) -> &[u8; N] {
                self.0[off..off + N].try_into().expect("field width")
            }

            pub fn bump(&self) -> u8 {
                self.0[1]
            }

            $( pub fn $f(&self) -> $t { self.get($o) } )*
            $( pub fn $bf(&self) -> &[u8; $n] { self.bytes($bo) } )*
        }

        impl<D: DerefMut<Target = [u8]>> $name<D> {
            /// A view over a freshly created account: every byte zero,
            /// then the tag, bump and layout version.
            pub fn init(mut d: D, bump: u8) -> Result<Self, ProgramError> {
                if d.len() != $len {
                    return Err(TimescalesError::InvalidAccount.into());
                }
                d.fill(0);
                d[0] = $tag;
                d[1] = bump;
                d[2] = LAYOUT_VERSION;
                Ok(Self(d))
            }

            fn set<T: Field>(&mut self, off: usize, v: T) {
                v.write(&mut self.0[off..off + T::LEN]);
            }

            fn put<const N: usize>(&mut self, off: usize, v: &[u8; N]) {
                self.0[off..off + N].copy_from_slice(v);
            }

            $( pub fn $s(&mut self, v: $t) { self.set($o, v) } )*
            $( pub fn $bs(&mut self, v: &[u8; $n]) { self.put($bo, v) } )*
        }
    };
}

view! {
    /// The market: configuration, vaults, the executor set, the batch
    /// cursor and the pending governance change.
    Market, MARKET_LEN, MARKET_TAG;
    ints {
        market_id / set_market_id: u64 = 4;
        executor_count / set_executor_count: u8 = 378;
        receipt_quorum / set_receipt_quorum: u8 = 379;
        beacon_delay_slots / set_beacon_delay_slots: u16 = 636;
        timelock_slots / set_timelock_slots: u64 = 638;
        exec_timeout_slots / set_exec_timeout_slots: u64 = 646;
        settle_timeout_slots / set_settle_timeout_slots: u64 = 654;
        last_committed / set_last_committed: u64 = 662;
        last_settled / set_last_settled: u64 = 670;
        last_progress_slot / set_last_progress_slot: u64 = 678;
        fees_accrued / set_fees_accrued: u64 = 686;
        fees_claimed / set_fees_claimed: u64 = 694;
        pending_kind / set_pending_kind: u8 = 766;
        pending_eta_slot / set_pending_eta_slot: u64 = 767;
        pending_len / set_pending_len: u16 = 775;
    }
    bytes {
        creator / set_creator: 32 = 12;
        admin / set_admin: 32 = 44;
        pending_admin / set_pending_admin: 32 = 76;
        relay / set_relay: 32 = 108;
        base_mint / set_base_mint: 32 = 140;
        quote_mint / set_quote_mint: 32 = 172;
        base_vault / set_base_vault: 32 = 204;
        quote_vault / set_quote_vault: 32 = 236;
        params / set_params: PARAMS_LEN = 268;
        params_digest / set_params_digest: 32 = 314;
        committee_digest / set_committee_digest: 32 = 346;
        prev_receipt / set_prev_receipt: 32 = 702;
        state_root / set_state_root: 32 = 734;
        salt / set_salt: 32 = 1039;
        prev_committee_digest / set_prev_committee_digest: 32 = 1071;
    }
}

const HALTED: usize = 3;
const EXECUTORS: usize = 380;
const EXECUTORS_END: usize = EXECUTORS + 32 * MAX_EXECUTORS;
const PENDING: usize = 766;
const PAYLOAD: usize = 777;
const PAYLOAD_END: usize = PAYLOAD + MAX_PAYLOAD;

impl<D: Deref<Target = [u8]>> Market<D> {
    pub fn halted(&self) -> bool {
        self.0[HALTED] & 1 == 1
    }

    /// Every executor slot, zero where empty.
    pub fn executors(&self) -> &[[u8; 32]] {
        self.0[EXECUTORS..EXECUTORS_END].as_chunks::<32>().0
    }

    pub fn pending_payload(&self) -> &[u8] {
        let len = usize::from(self.pending_len()).min(MAX_PAYLOAD);
        &self.0[PAYLOAD..PAYLOAD + len]
    }

    /// `params.max_batch_envelopes` (params bytes 31..35).
    pub fn max_batch_envelopes(&self) -> u32 {
        self.get(268 + 31)
    }

    pub fn vault(&self, quote: bool) -> &[u8; 32] {
        if quote {
            self.quote_vault()
        } else {
            self.base_vault()
        }
    }

    /// Bit `i` set for every non-zero executor slot.
    pub fn live_slots(&self) -> u8 {
        self.executors()
            .iter()
            .enumerate()
            .filter(|(_, k)| **k != [0u8; 32])
            .fold(0u8, |m, (i, _)| m | (1 << i))
    }

    pub fn executor_slot(&self, key: &[u8; 32]) -> Option<usize> {
        if *key == [0u8; 32] {
            return None;
        }
        self.executors().iter().position(|k| k == key)
    }

    /// Signatures of live executors on the posted outcome reach the quorum.
    /// A removed executor's signature stops counting.
    pub fn quorum_met(&self, cosign_bitmap: u8) -> bool {
        (cosign_bitmap & self.live_slots()).count_ones() >= u32::from(self.receipt_quorum())
    }

    pub fn in_flight(&self) -> bool {
        self.last_committed() != self.last_settled()
    }
}

impl<D: DerefMut<Target = [u8]>> Market<D> {
    pub fn set_halted(&mut self, halted: bool) {
        self.0[HALTED] = u8::from(halted);
    }

    /// `keys` into the first slots, the rest empty.
    pub fn set_executors(&mut self, keys: &[[u8; 32]]) {
        let slots = self.0[EXECUTORS..EXECUTORS_END].as_chunks_mut::<32>().0;
        slots.fill([0u8; 32]);
        for (slot, k) in slots.iter_mut().zip(keys) {
            *slot = *k;
        }
        self.set_executor_count(keys.len() as u8);
    }

    pub fn clear_executor(&mut self, slot: usize) {
        self.put(EXECUTORS + 32 * slot, &[0u8; 32]);
    }

    pub fn set_pending(&mut self, kind: u8, eta_slot: u64, payload: &[u8]) {
        self.set_pending_kind(kind);
        self.set_pending_eta_slot(eta_slot);
        self.set_pending_len(payload.len() as u16);
        let buf = &mut self.0[PAYLOAD..PAYLOAD_END];
        buf.fill(0);
        buf[..payload.len()].copy_from_slice(payload);
    }

    pub fn clear_pending(&mut self) {
        self.0[PENDING..PAYLOAD_END].fill(0);
    }
}

view! {
    /// A trader's balances in one market.
    Trader, TRADER_LEN, TRADER_TAG;
    ints {
        base / set_base: u64 = 68;
        quote / set_quote: u64 = 76;
        requested_base / set_requested_base: u64 = 84;
        requested_quote / set_requested_quote: u64 = 92;
        request_epoch / set_request_epoch: u64 = 100;
        last_leaf_epoch / set_last_leaf_epoch: u64 = 108;
        last_change_slot / set_last_change_slot: u64 = 116;
        floor_epoch / set_floor_epoch: u64 = 124;
        floor_base / set_floor_base: u64 = 132;
        floor_quote / set_floor_quote: u64 = 140;
    }
    bytes {
        market / set_market: 32 = 4;
        owner / set_owner: 32 = 36;
    }
}

impl<D: Deref<Target = [u8]>> Trader<D> {
    pub fn balance(&self, quote: bool) -> u64 {
        if quote { self.quote() } else { self.base() }
    }

    pub fn requested(&self, quote: bool) -> u64 {
        if quote {
            self.requested_quote()
        } else {
            self.requested_base()
        }
    }

    /// Per side, the part of the balance a batch after `request_epoch` may
    /// not use: `e > request_epoch ? min(requested, balance): 0`.
    pub fn reserved(&self, epoch: u64) -> (u64, u64) {
        if epoch > self.request_epoch() {
            (
                self.requested_base().min(self.base()),
                self.requested_quote().min(self.quote()),
            )
        } else {
            (0, 0)
        }
    }

    /// `balance - reserved` per side for batch `epoch`.
    pub fn available(&self, epoch: u64) -> (u64, u64) {
        let (rb, rq) = self.reserved(epoch);
        (self.base() - rb, self.quote() - rq)
    }

    pub fn is_empty(&self) -> bool {
        self.base() == 0
            && self.quote() == 0
            && self.requested_base() == 0
            && self.requested_quote() == 0
    }
}

impl<D: DerefMut<Target = [u8]>> Trader<D> {
    pub fn set_balance(&mut self, quote: bool, v: u64) {
        if quote {
            self.set_quote(v);
        } else {
            self.set_base(v);
        }
    }

    pub fn set_requested(&mut self, quote: bool, v: u64) {
        if quote {
            self.set_requested_quote(v);
        } else {
            self.set_requested_base(v);
        }
    }

    /// Records the available balance for the batch in flight before the
    /// first change to this account while it is in flight. Available
    /// never decreases between commit and apply, so this is the available
    /// balance at the commit.
    pub fn capture_floor<M: Deref<Target = [u8]>>(&mut self, market: &Market<M>) {
        let e = market.last_committed();
        if market.in_flight() && self.floor_epoch() != e {
            let (b, q) = self.available(e);
            self.set_floor_epoch(e);
            self.set_floor_base(b);
            self.set_floor_quote(q);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Committed = 1,
    BeaconRevealed = 2,
    ReceiptPosted = 3,
    Verified = 4,
    Settled = 5,
    Aborted = 6,
}

impl Status {
    fn from_u8(v: u8) -> Result<Self, ProgramError> {
        Ok(match v {
            1 => Status::Committed,
            2 => Status::BeaconRevealed,
            3 => Status::ReceiptPosted,
            4 => Status::Verified,
            5 => Status::Settled,
            6 => Status::Aborted,
            _ => return Err(TimescalesError::InvalidAccount.into()),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AbortReason {
    Admin = 1,
    Relay = 2,
    BeaconExpired = 3,
    ExecTimeout = 4,
    SettleTimeout = 5,
    QuorumTimeout = 6,
}

impl AbortReason {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => AbortReason::Admin,
            2 => AbortReason::Relay,
            3 => AbortReason::BeaconExpired,
            4 => AbortReason::ExecTimeout,
            5 => AbortReason::SettleTimeout,
            6 => AbortReason::QuorumTimeout,
            _ => return None,
        })
    }
}

view! {
    /// One epoch's batch: what was committed, the beacon, the receipt and
    /// the verification and apply progress.
    Batch, BATCH_LEN, BATCH_TAG;
    ints {
        abort_reason / set_abort_reason: u8 = 4;
        cosign_count / set_cosign_count: u8 = 5;
        cosign_bitmap / set_cosign_bitmap: u8 = 6;
        epoch / set_epoch: u64 = 40;
        count / set_count: u32 = 80;
        commit_slot / set_commit_slot: u64 = 116;
        beacon_slot_a / set_beacon_slot_a: u64 = 124;
        beacon_slot_b / set_beacon_slot_b: u64 = 132;
        reveal_slot / set_reveal_slot: u64 = 172;
        receipt_slot / set_receipt_slot: u64 = 180;
        settlement_count / set_settlement_count: u32 = 348;
        fees / set_fees: u64 = 352;
        verified_count / set_verified_count: u32 = 360;
        applied_count / set_applied_count: u32 = 364;
        sum_base / set_sum_base: i128 = 368;
        sum_quote / set_sum_quote: i128 = 384;
    }
    bytes {
        market / set_market: 32 = 8;
        root / set_root: 32 = 48;
        terms_digest / set_terms_digest: 32 = 84;
        beacon / set_beacon: 32 = 140;
        header_digest / set_header_digest: 32 = 188;
        receipt / set_receipt: 32 = 220;
        outcome_digest / set_outcome_digest: 32 = 252;
        next_state_root / set_next_state_root: 32 = 284;
        settlement_root / set_settlement_root: 32 = 316;
    }
}

const STATUS: usize = 3;
const VERIFIED: usize = 400;
const APPLIED: usize = VERIFIED + BITMAP;

impl<D: Deref<Target = [u8]>> Batch<D> {
    /// [`Batch::view`] with a known status byte.
    pub fn checked(d: D) -> Result<Self, ProgramError> {
        let b = Self::view(d)?;
        Status::from_u8(b.0[STATUS])?;
        Ok(b)
    }

    pub fn status(&self) -> Status {
        Status::from_u8(self.0[STATUS]).expect("checked by the view")
    }
}

impl<D: DerefMut<Target = [u8]>> Batch<D> {
    pub fn set_status(&mut self, status: Status) {
        self.0[STATUS] = status as u8;
    }

    /// Marks leaf `i` verified and returns whether it already was.
    pub fn test_and_set_verified(&mut self, i: u32) -> bool {
        test_and_set(&mut self.0[VERIFIED..APPLIED], i)
    }

    /// Marks leaf `i` applied and returns whether it already was.
    pub fn test_and_set_applied(&mut self, i: u32) -> bool {
        test_and_set(&mut self.0[APPLIED..APPLIED + BITMAP], i)
    }
}

/// Sets bit `i` (leaf `i` -> byte `i / 8`, bit `i % 8`, LSB first) and
/// returns whether it was already set. `i` must be below `MAX_DELTAS`.
fn test_and_set(map: &mut [u8], i: u32) -> bool {
    let i = i as usize;
    let bit = 1u8 << (i % 8);
    let was = map[i / 8] & bit != 0;
    map[i / 8] |= bit;
    was
}

#[cfg(test)]
mod tests {
    use super::*;

    fn market() -> Market<Vec<u8>> {
        let mut m = Market::init(vec![0u8; MARKET_LEN], 254).unwrap();
        m.set_halted(true);
        m.set_market_id(7);
        m.set_creator(&[1; 32]);
        m.set_admin(&[2; 32]);
        m.set_pending_admin(&[3; 32]);
        m.set_relay(&[4; 32]);
        m.set_base_mint(&[5; 32]);
        m.set_quote_mint(&[6; 32]);
        m.set_base_vault(&[7; 32]);
        m.set_quote_vault(&[8; 32]);
        m.set_params(&[9; PARAMS_LEN]);
        m.set_params_digest(&[10; 32]);
        m.set_committee_digest(&[11; 32]);
        m.set_executors(&[[12; 32]; 2]);
        m.set_receipt_quorum(2);
        m.set_beacon_delay_slots(0x1314);
        m.set_timelock_slots(15);
        m.set_exec_timeout_slots(16);
        m.set_settle_timeout_slots(17);
        m.set_last_committed(18);
        m.set_last_settled(19);
        m.set_last_progress_slot(20);
        m.set_fees_accrued(21);
        m.set_fees_claimed(22);
        m.set_prev_receipt(&[23; 32]);
        m.set_state_root(&[24; 32]);
        m.set_pending(25, 26, &[28; 27]);
        m.set_salt(&[29; 32]);
        m.set_prev_committee_digest(&[30; 32]);
        m
    }

    #[test]
    fn market_layout() {
        let m = market();
        let d = &m.0;
        assert_eq!(&d[..4], &[0x21, 254, 2, 1]);
        for (off, v) in [
            (4, 7),
            (12, 1),
            (76, 3),
            (108, 4),
            (268, 9),
            (314, 10),
            (346, 11),
            (378, 2),
            (379, 2),
            (380, 12),
            (636, 0x14),
            (637, 0x13),
            (638, 15),
            (662, 18),
            (670, 19),
            (678, 20),
            (686, 21),
            (694, 22),
            (702, 23),
            (734, 24),
            (766, 25),
            (767, 26),
            (775, 27),
            (777, 28),
            (1039, 29),
            (1071, 30),
        ] {
            assert_eq!(d[off], v, "offset {off}");
        }
        let back = Market::view(d.as_slice()).unwrap();
        assert!(back.halted());
        assert_eq!(back.market_id(), 7);
        assert_eq!(back.admin(), &[2; 32]);
        assert_eq!(back.executors()[1], [12; 32]);
        assert_eq!(back.executors()[2], [0; 32]);
        assert_eq!(back.executor_count(), 2);
        assert_eq!(back.live_slots(), 0b11);
        assert_eq!(back.beacon_delay_slots(), 0x1314);
        assert_eq!(back.pending_kind(), 25);
        assert_eq!(back.pending_eta_slot(), 26);
        assert_eq!(back.pending_payload(), &[28; 27][..]);
        assert_eq!(back.prev_committee_digest(), &[30; 32]);
    }

    #[test]
    fn trader_layout() {
        let mut t = Trader::init(vec![0u8; TRADER_LEN], 9).unwrap();
        t.set_market(&[1; 32]);
        t.set_owner(&[2; 32]);
        t.set_base(3);
        t.set_quote(4);
        t.set_requested_base(5);
        t.set_requested_quote(6);
        t.set_request_epoch(7);
        t.set_last_leaf_epoch(8);
        t.set_last_change_slot(0x77);
        t.set_floor_epoch(10);
        t.set_floor_base(11);
        t.set_floor_quote(12);
        let d = &t.0;
        assert_eq!(&d[..4], &[0x22, 9, 2, 0]);
        for (off, v) in [
            (4, 1),
            (36, 2),
            (68, 3),
            (76, 4),
            (84, 5),
            (92, 6),
            (100, 7),
            (108, 8),
            (116, 0x77),
            (124, 10),
            (132, 11),
            (140, 12),
        ] {
            assert_eq!(d[off], v, "offset {off}");
        }
        let back = Trader::view(d.as_slice()).unwrap();
        assert_eq!(back.bump(), 9);
        assert_eq!(back.owner(), &[2; 32]);
        assert_eq!(back.balance(true), 4);
        assert_eq!(back.requested(false), 5);
        assert_eq!(back.floor_quote(), 12);
    }

    #[test]
    fn batch_layout() {
        let mut b = Batch::init(vec![0u8; BATCH_LEN], 5).unwrap();
        b.set_status(Status::Aborted);
        b.set_abort_reason(6);
        b.set_cosign_count(3);
        b.set_cosign_bitmap(0b101);
        b.set_market(&[1; 32]);
        b.set_epoch(2);
        b.set_root(&[3; 32]);
        b.set_count(4);
        b.set_terms_digest(&[5; 32]);
        b.set_commit_slot(6);
        b.set_beacon_slot_a(7);
        b.set_beacon_slot_b(8);
        b.set_beacon(&[9; 32]);
        b.set_reveal_slot(10);
        b.set_receipt_slot(11);
        b.set_header_digest(&[12; 32]);
        b.set_receipt(&[13; 32]);
        b.set_outcome_digest(&[14; 32]);
        b.set_next_state_root(&[15; 32]);
        b.set_settlement_root(&[16; 32]);
        b.set_settlement_count(17);
        b.set_fees(18);
        b.set_verified_count(19);
        b.set_applied_count(20);
        b.set_sum_base(21);
        b.set_sum_quote(22);
        assert!(!b.test_and_set_verified(0));
        assert!(b.test_and_set_verified(0));
        assert!(!b.test_and_set_applied(1023));
        let d = &b.0;
        assert_eq!(&d[..8], &[0x23, 5, 2, 6, 6, 3, 0b101, 0]);
        for (off, v) in [
            (8, 1),
            (40, 2),
            (48, 3),
            (80, 4),
            (84, 5),
            (116, 6),
            (124, 7),
            (132, 8),
            (140, 9),
            (172, 10),
            (180, 11),
            (188, 12),
            (220, 13),
            (252, 14),
            (284, 15),
            (316, 16),
            (348, 17),
            (352, 18),
            (360, 19),
            (364, 20),
            (368, 21),
            (384, 22),
            (400, 1),
            (655, 0x80),
        ] {
            assert_eq!(d[off], v, "offset {off}");
        }
        assert!(d[656..].iter().all(|b| *b == 0));
        let back = Batch::checked(d.as_slice()).unwrap();
        assert_eq!(back.status(), Status::Aborted);
        assert_eq!(back.sum_quote(), 22);
        assert_eq!(back.settlement_root(), &[16; 32]);
    }

    #[test]
    fn wrong_length_tag_version_or_status_is_refused() {
        let d = Trader::init(vec![0u8; TRADER_LEN], 1).unwrap().0;
        let mut v1 = d.clone();
        v1[0] = 2;
        assert!(Trader::view(v1.as_slice()).is_err());
        let mut old = d.clone();
        old[2] = 1;
        assert!(Trader::view(old.as_slice()).is_err());
        assert!(Trader::view(&d[..147]).is_err());
        assert!(Market::view(d.as_slice()).is_err());
        let mut bad = Batch::init(vec![0u8; BATCH_LEN], 1).unwrap().0;
        bad[STATUS] = 9;
        assert!(Batch::checked(bad.as_slice()).is_err());
    }

    #[test]
    fn floor_is_available_at_first_change_in_flight() {
        let mut m = market();
        m.set_last_settled(4);
        m.set_last_committed(5);
        let mut t = Trader::init(vec![0u8; TRADER_LEN], 1).unwrap();
        t.set_base(100);
        t.set_quote(50);
        t.set_requested_quote(80);
        t.set_request_epoch(3);
        t.capture_floor(&m);
        assert_eq!(
            (t.floor_epoch(), t.floor_base(), t.floor_quote()),
            (5, 100, 0)
        );
        t.set_base(1);
        t.capture_floor(&m);
        assert_eq!(t.floor_base(), 100, "only the first change captures");
        m.set_last_settled(5);
        t.set_floor_epoch(0);
        t.capture_floor(&m);
        assert_eq!(t.floor_epoch(), 0, "nothing in flight, nothing captured");
    }
}
