//! Account layouts. Fixed size, little-endian, no framework: what is
//! written here is exactly what the chain crate decodes off chain.
//! Fields are laid out in declaration order. The offsets in the comments
//! are the ones clients filter on.

use solana_program::program_error::ProgramError;

use crate::constants::{MAX_DELTAS, MAX_EXECUTORS};
use crate::error::TimescalesError;

pub const LAYOUT_VERSION: u8 = 2;
pub const MARKET_TAG: u8 = 0x21;
pub const TRADER_TAG: u8 = 0x22;
pub const BATCH_TAG: u8 = 0x23;

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

    pub fn i128(&mut self) -> Result<i128, ProgramError> {
        Ok(i128::from_le_bytes(self.array()?))
    }

    pub fn key(&mut self) -> Result<[u8; 32], ProgramError> {
        self.array()
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    pub fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn put(&mut self, b: &[u8]) -> Result<(), ProgramError> {
        let end = self.pos + b.len();
        self.buf
            .get_mut(self.pos..end)
            .ok_or(TimescalesError::InvalidAccount)?
            .copy_from_slice(b);
        self.pos = end;
        Ok(())
    }

    fn u64(&mut self, v: u64) -> Result<(), ProgramError> {
        self.put(&v.to_le_bytes())
    }

    fn u32(&mut self, v: u32) -> Result<(), ProgramError> {
        self.put(&v.to_le_bytes())
    }

    fn done(self) -> Result<(), ProgramError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(TimescalesError::InvalidAccount.into())
        }
    }
}

/// Exact length, tag and layout version. Anything else (including a v1
/// account) is `InvalidAccount`.
fn header(d: &[u8], len: usize, tag: u8) -> Result<Cursor<'_>, ProgramError> {
    if d.len() != len || d[0] != tag || d[2] != LAYOUT_VERSION {
        return Err(TimescalesError::InvalidAccount.into());
    }
    Ok(Cursor::new(d))
}

fn invalid_account(_: ProgramError) -> ProgramError {
    TimescalesError::InvalidAccount.into()
}

/// A timelocked governance change. `kind == 0` means none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub kind: u8,
    pub eta_slot: u64,
    pub len: u16,
    pub payload: [u8; MAX_PAYLOAD],
}

impl Pending {
    pub const NONE: Pending = Pending {
        kind: 0,
        eta_slot: 0,
        len: 0,
        payload: [0; MAX_PAYLOAD],
    };

    pub fn payload(&self) -> &[u8] {
        &self.payload[..usize::from(self.len).min(MAX_PAYLOAD)]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Market {
    pub bump: u8,
    pub halted: bool,
    pub market_id: u64,
    pub creator: [u8; 32],
    pub admin: [u8; 32],
    pub pending_admin: [u8; 32],
    pub relay: [u8; 32],
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    pub base_vault: [u8; 32],
    pub quote_vault: [u8; 32],
    pub params: [u8; PARAMS_LEN],
    pub params_digest: [u8; 32],
    pub committee_digest: [u8; 32],
    pub executor_count: u8,
    pub receipt_quorum: u8,
    pub executors: [[u8; 32]; MAX_EXECUTORS],
    pub beacon_delay_slots: u16,
    pub timelock_slots: u64,
    pub exec_timeout_slots: u64,
    pub settle_timeout_slots: u64,
    pub last_committed: u64,
    pub last_settled: u64,
    pub last_progress_slot: u64,
    pub fees_accrued: u64,
    pub fees_claimed: u64,
    pub prev_receipt: [u8; 32],
    pub state_root: [u8; 32],
    pub pending: Pending,
    pub salt: [u8; 32],
    pub prev_committee_digest: [u8; 32],
}

impl Market {
    pub const LEN: usize = 1103;

    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        let mut c = header(d, Self::LEN, MARKET_TAG)?;
        Self::read(&mut c).map_err(invalid_account)
    }

    fn read(c: &mut Cursor<'_>) -> Result<Self, ProgramError> {
        c.u8()?;
        let bump = c.u8()?;
        c.u8()?;
        let halted = c.u8()? & 1 == 1;
        let market_id = c.u64()?;
        let creator = c.key()?;
        let admin = c.key()?;
        let pending_admin = c.key()?;
        let relay = c.key()?;
        let base_mint = c.key()?;
        let quote_mint = c.key()?;
        let base_vault = c.key()?;
        let quote_vault = c.key()?;
        let params = c.array()?;
        let params_digest = c.key()?;
        let committee_digest = c.key()?;
        let executor_count = c.u8()?;
        let receipt_quorum = c.u8()?;
        let mut executors = [[0u8; 32]; MAX_EXECUTORS];
        for e in executors.iter_mut() {
            *e = c.key()?;
        }
        Ok(Market {
            bump,
            halted,
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
            beacon_delay_slots: c.u16()?,
            timelock_slots: c.u64()?,
            exec_timeout_slots: c.u64()?,
            settle_timeout_slots: c.u64()?,
            last_committed: c.u64()?,
            last_settled: c.u64()?,
            last_progress_slot: c.u64()?,
            fees_accrued: c.u64()?,
            fees_claimed: c.u64()?,
            prev_receipt: c.key()?,
            state_root: c.key()?,
            pending: Pending {
                kind: c.u8()?,
                eta_slot: c.u64()?,
                len: c.u16()?,
                payload: c.array()?,
            },
            salt: c.key()?,
            prev_committee_digest: c.key()?,
        })
    }

    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = Writer::new(d);
        w.put(&[MARKET_TAG, self.bump, LAYOUT_VERSION, u8::from(self.halted)])?;
        w.u64(self.market_id)?;
        for k in [
            &self.creator,
            &self.admin,
            &self.pending_admin,
            &self.relay,
            &self.base_mint,
            &self.quote_mint,
            &self.base_vault,
            &self.quote_vault,
        ] {
            w.put(k)?;
        }
        w.put(&self.params)?;
        w.put(&self.params_digest)?;
        w.put(&self.committee_digest)?;
        w.put(&[self.executor_count, self.receipt_quorum])?;
        for e in &self.executors {
            w.put(e)?;
        }
        w.put(&self.beacon_delay_slots.to_le_bytes())?;
        for v in [
            self.timelock_slots,
            self.exec_timeout_slots,
            self.settle_timeout_slots,
            self.last_committed,
            self.last_settled,
            self.last_progress_slot,
            self.fees_accrued,
            self.fees_claimed,
        ] {
            w.u64(v)?;
        }
        w.put(&self.prev_receipt)?;
        w.put(&self.state_root)?;
        w.put(&[self.pending.kind])?;
        w.u64(self.pending.eta_slot)?;
        w.put(&self.pending.len.to_le_bytes())?;
        w.put(&self.pending.payload)?;
        w.put(&self.salt)?;
        w.put(&self.prev_committee_digest)?;
        w.done()
    }

    /// `params.max_batch_envelopes` (params bytes 31..35).
    pub fn max_batch_envelopes(&self) -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.params[31..35]);
        u32::from_le_bytes(b)
    }

    /// Bit `i` set for every non-zero executor slot.
    pub fn live_slots(&self) -> u8 {
        self.executors
            .iter()
            .enumerate()
            .filter(|(_, k)| **k != [0u8; 32])
            .fold(0u8, |m, (i, _)| m | (1 << i))
    }

    pub fn executor_slot(&self, key: &[u8; 32]) -> Option<usize> {
        if *key == [0u8; 32] {
            return None;
        }
        self.executors.iter().position(|k| k == key)
    }

    /// Signatures of live executors on the posted outcome reach the quorum.
    /// A removed executor's signature stops counting.
    pub fn quorum_met(&self, cosign_bitmap: u8) -> bool {
        (cosign_bitmap & self.live_slots()).count_ones() >= u32::from(self.receipt_quorum)
    }

    pub fn in_flight(&self) -> bool {
        self.last_committed != self.last_settled
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trader {
    pub bump: u8,
    pub market: [u8; 32],
    pub owner: [u8; 32],
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

impl Trader {
    pub const LEN: usize = 148;

    pub fn new(bump: u8, market: [u8; 32], owner: [u8; 32], slot: u64) -> Self {
        Trader {
            bump,
            market,
            owner,
            base: 0,
            quote: 0,
            requested_base: 0,
            requested_quote: 0,
            request_epoch: 0,
            last_leaf_epoch: 0,
            last_change_slot: slot,
            floor_epoch: 0,
            floor_base: 0,
            floor_quote: 0,
        }
    }

    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        let mut c = header(d, Self::LEN, TRADER_TAG)?;
        Self::read(&mut c).map_err(invalid_account)
    }

    fn read(c: &mut Cursor<'_>) -> Result<Self, ProgramError> {
        c.u8()?;
        let bump = c.u8()?;
        c.take(2)?;
        Ok(Trader {
            bump,
            market: c.key()?,
            owner: c.key()?,
            base: c.u64()?,
            quote: c.u64()?,
            requested_base: c.u64()?,
            requested_quote: c.u64()?,
            request_epoch: c.u64()?,
            last_leaf_epoch: c.u64()?,
            last_change_slot: c.u64()?,
            floor_epoch: c.u64()?,
            floor_base: c.u64()?,
            floor_quote: c.u64()?,
        })
    }

    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = Writer::new(d);
        w.put(&[TRADER_TAG, self.bump, LAYOUT_VERSION, 0])?;
        w.put(&self.market)?;
        w.put(&self.owner)?;
        for v in [
            self.base,
            self.quote,
            self.requested_base,
            self.requested_quote,
            self.request_epoch,
            self.last_leaf_epoch,
            self.last_change_slot,
            self.floor_epoch,
            self.floor_base,
            self.floor_quote,
        ] {
            w.u64(v)?;
        }
        w.done()
    }

    /// Per side, the part of the balance a batch after `request_epoch` may
    /// not use: `e > request_epoch ? min(requested, balance): 0`.
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

    /// `balance - reserved` per side for batch `epoch`.
    pub fn available(&self, epoch: u64) -> (u64, u64) {
        let (rb, rq) = self.reserved(epoch);
        (self.base - rb, self.quote - rq)
    }

    /// Records the available balance for the batch in flight before the
    /// first change to this account while it is in flight. Available
    /// never decreases between commit and apply, so this is the available
    /// balance at the commit.
    pub fn capture_floor(&mut self, market: &Market) {
        let e = market.last_committed;
        if market.in_flight() && self.floor_epoch != e {
            let (b, q) = self.available(e);
            self.floor_epoch = e;
            self.floor_base = b;
            self.floor_quote = q;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.base == 0 && self.quote == 0 && self.requested_base == 0 && self.requested_quote == 0
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub bump: u8,
    pub status: Status,
    /// 0 unless aborted.
    pub abort_reason: u8,
    pub cosign_count: u8,
    pub cosign_bitmap: u8,
    pub market: [u8; 32],
    pub epoch: u64,
    pub root: [u8; 32],
    pub count: u32,
    pub terms_digest: [u8; 32],
    pub commit_slot: u64,
    pub beacon_slot_a: u64,
    pub beacon_slot_b: u64,
    pub beacon: [u8; 32],
    pub reveal_slot: u64,
    pub receipt_slot: u64,
    pub header_digest: [u8; 32],
    pub receipt: [u8; 32],
    pub outcome_digest: [u8; 32],
    pub next_state_root: [u8; 32],
    pub settlement_root: [u8; 32],
    pub settlement_count: u32,
    pub fees: u64,
    pub verified_count: u32,
    pub applied_count: u32,
    pub sum_base: i128,
    pub sum_quote: i128,
    pub verified: [u8; BITMAP],
    pub applied: [u8; BITMAP],
}

impl Batch {
    pub const LEN: usize = 688;

    pub fn committed(
        bump: u8,
        market: [u8; 32],
        epoch: u64,
        root: [u8; 32],
        count: u32,
        terms_digest: [u8; 32],
        commit_slot: u64,
    ) -> Self {
        Batch {
            bump,
            status: Status::Committed,
            abort_reason: 0,
            cosign_count: 0,
            cosign_bitmap: 0,
            market,
            epoch,
            root,
            count,
            terms_digest,
            commit_slot,
            beacon_slot_a: 0,
            beacon_slot_b: 0,
            beacon: [0; 32],
            reveal_slot: 0,
            receipt_slot: 0,
            header_digest: [0; 32],
            receipt: [0; 32],
            outcome_digest: [0; 32],
            next_state_root: [0; 32],
            settlement_root: [0; 32],
            settlement_count: 0,
            fees: 0,
            verified_count: 0,
            applied_count: 0,
            sum_base: 0,
            sum_quote: 0,
            verified: [0; BITMAP],
            applied: [0; BITMAP],
        }
    }

    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        let mut c = header(d, Self::LEN, BATCH_TAG)?;
        Self::read(&mut c).map_err(invalid_account)
    }

    fn read(c: &mut Cursor<'_>) -> Result<Self, ProgramError> {
        c.u8()?;
        let bump = c.u8()?;
        c.u8()?;
        let status = Status::from_u8(c.u8()?)?;
        let abort_reason = c.u8()?;
        let cosign_count = c.u8()?;
        let cosign_bitmap = c.u8()?;
        c.u8()?;
        Ok(Batch {
            bump,
            status,
            abort_reason,
            cosign_count,
            cosign_bitmap,
            market: c.key()?,
            epoch: c.u64()?,
            root: c.key()?,
            count: c.u32()?,
            terms_digest: c.key()?,
            commit_slot: c.u64()?,
            beacon_slot_a: c.u64()?,
            beacon_slot_b: c.u64()?,
            beacon: c.key()?,
            reveal_slot: c.u64()?,
            receipt_slot: c.u64()?,
            header_digest: c.key()?,
            receipt: c.key()?,
            outcome_digest: c.key()?,
            next_state_root: c.key()?,
            settlement_root: c.key()?,
            settlement_count: c.u32()?,
            fees: c.u64()?,
            verified_count: c.u32()?,
            applied_count: c.u32()?,
            sum_base: c.i128()?,
            sum_quote: c.i128()?,
            verified: c.array()?,
            applied: c.array()?,
        })
    }

    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = Writer::new(d);
        w.put(&[
            BATCH_TAG,
            self.bump,
            LAYOUT_VERSION,
            self.status as u8,
            self.abort_reason,
            self.cosign_count,
            self.cosign_bitmap,
            0,
        ])?;
        w.put(&self.market)?;
        w.u64(self.epoch)?;
        w.put(&self.root)?;
        w.u32(self.count)?;
        w.put(&self.terms_digest)?;
        for v in [self.commit_slot, self.beacon_slot_a, self.beacon_slot_b] {
            w.u64(v)?;
        }
        w.put(&self.beacon)?;
        w.u64(self.reveal_slot)?;
        w.u64(self.receipt_slot)?;
        for k in [
            &self.header_digest,
            &self.receipt,
            &self.outcome_digest,
            &self.next_state_root,
            &self.settlement_root,
        ] {
            w.put(k)?;
        }
        w.u32(self.settlement_count)?;
        w.u64(self.fees)?;
        w.u32(self.verified_count)?;
        w.u32(self.applied_count)?;
        w.put(&self.sum_base.to_le_bytes())?;
        w.put(&self.sum_quote.to_le_bytes())?;
        w.put(&self.verified)?;
        w.put(&self.applied)?;
        w.put(&[0u8; 32])?;
        w.done()
    }

    /// Sets bit `i` (leaf `i` -> byte `i / 8`, bit `i % 8`, LSB first) and
    /// returns whether it was already set. `i` must be below `MAX_DELTAS`.
    pub fn test_and_set(map: &mut [u8; BITMAP], i: u32) -> bool {
        let i = i as usize;
        let bit = 1u8 << (i % 8);
        let was = map[i / 8] & bit != 0;
        map[i / 8] |= bit;
        was
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn market() -> Market {
        Market {
            bump: 254,
            halted: true,
            market_id: 7,
            creator: [1; 32],
            admin: [2; 32],
            pending_admin: [3; 32],
            relay: [4; 32],
            base_mint: [5; 32],
            quote_mint: [6; 32],
            base_vault: [7; 32],
            quote_vault: [8; 32],
            params: [9; PARAMS_LEN],
            params_digest: [10; 32],
            committee_digest: [11; 32],
            executor_count: 2,
            receipt_quorum: 2,
            executors: [[12; 32]; MAX_EXECUTORS],
            beacon_delay_slots: 0x1314,
            timelock_slots: 15,
            exec_timeout_slots: 16,
            settle_timeout_slots: 17,
            last_committed: 18,
            last_settled: 19,
            last_progress_slot: 20,
            fees_accrued: 21,
            fees_claimed: 22,
            prev_receipt: [23; 32],
            state_root: [24; 32],
            pending: Pending {
                kind: 25,
                eta_slot: 26,
                len: 27,
                payload: [28; MAX_PAYLOAD],
            },
            salt: [29; 32],
            prev_committee_digest: [30; 32],
        }
    }

    #[test]
    fn market_offsets_match_c3() {
        let m = market();
        let mut d = vec![0u8; Market::LEN];
        m.store(&mut d).unwrap();
        assert_eq!(&d[..4], &[0x21, 254, 2, 1]);
        assert_eq!(d[4], 7);
        assert_eq!(d[12], 1);
        assert_eq!(d[76], 3);
        assert_eq!(d[108], 4);
        assert_eq!(d[268], 9);
        assert_eq!(d[314], 10);
        assert_eq!(d[346], 11);
        assert_eq!(&d[378..380], &[2, 2]);
        assert_eq!(d[380], 12);
        assert_eq!(&d[636..638], &[0x14, 0x13]);
        assert_eq!(d[638], 15);
        assert_eq!(d[662], 18);
        assert_eq!(d[670], 19);
        assert_eq!(d[678], 20);
        assert_eq!(d[686], 21);
        assert_eq!(d[694], 22);
        assert_eq!(d[702], 23);
        assert_eq!(d[734], 24);
        assert_eq!(d[766], 25);
        assert_eq!(d[767], 26);
        assert_eq!(d[775], 27);
        assert_eq!(d[777], 28);
        assert_eq!(d[1039], 29);
        assert_eq!(d[1071], 30);
        assert_eq!(Market::load(&d).unwrap(), m);
    }

    #[test]
    fn trader_offsets_match_c3() {
        let mut t = Trader::new(9, [1; 32], [2; 32], 0x77);
        t.base = 3;
        t.quote = 4;
        t.requested_base = 5;
        t.requested_quote = 6;
        t.request_epoch = 7;
        t.last_leaf_epoch = 8;
        t.floor_epoch = 10;
        t.floor_base = 11;
        t.floor_quote = 12;
        let mut d = vec![0u8; Trader::LEN];
        t.store(&mut d).unwrap();
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
        assert_eq!(Trader::load(&d).unwrap(), t);
    }

    #[test]
    fn batch_offsets_match_c3() {
        let mut b = Batch::committed(5, [1; 32], 2, [3; 32], 4, [5; 32], 6);
        b.status = Status::Aborted;
        b.abort_reason = 6;
        b.cosign_count = 3;
        b.cosign_bitmap = 0b101;
        b.beacon_slot_a = 7;
        b.beacon_slot_b = 8;
        b.beacon = [9; 32];
        b.reveal_slot = 10;
        b.receipt_slot = 11;
        b.header_digest = [12; 32];
        b.receipt = [13; 32];
        b.outcome_digest = [14; 32];
        b.next_state_root = [15; 32];
        b.settlement_root = [16; 32];
        b.settlement_count = 17;
        b.fees = 18;
        b.verified_count = 19;
        b.applied_count = 20;
        b.sum_base = 21;
        b.sum_quote = 22;
        b.verified = [23; BITMAP];
        b.applied = [24; BITMAP];
        let mut d = vec![0u8; Batch::LEN];
        b.store(&mut d).unwrap();
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
            (400, 23),
            (528, 24),
        ] {
            assert_eq!(d[off], v, "offset {off}");
        }
        assert!(d[656..].iter().all(|b| *b == 0));
        assert_eq!(Batch::load(&d).unwrap(), b);
    }

    #[test]
    fn wrong_length_tag_or_version_is_refused() {
        let t = Trader::new(1, [1; 32], [2; 32], 0);
        let mut d = vec![0u8; Trader::LEN];
        t.store(&mut d).unwrap();
        let mut v1 = d.clone();
        v1[0] = 2;
        assert!(Trader::load(&v1).is_err());
        let mut old = d.clone();
        old[2] = 1;
        assert!(Trader::load(&old).is_err());
        assert!(Trader::load(&d[..147]).is_err());
        assert!(Market::load(&d).is_err());
    }

    #[test]
    fn floor_is_available_at_first_change_in_flight() {
        let mut m = market();
        m.last_settled = 4;
        m.last_committed = 5;
        let mut t = Trader::new(1, [1; 32], [2; 32], 0);
        t.base = 100;
        t.quote = 50;
        t.requested_quote = 80;
        t.request_epoch = 3;
        t.capture_floor(&m);
        assert_eq!((t.floor_epoch, t.floor_base, t.floor_quote), (5, 100, 0));
        t.base = 1;
        t.capture_floor(&m);
        assert_eq!(t.floor_base, 100, "only the first change captures");
        m.last_settled = 5;
        t.floor_epoch = 0;
        t.capture_floor(&m);
        assert_eq!(t.floor_epoch, 0, "nothing in flight, nothing captured");
    }
}
