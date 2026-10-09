//! Governance: immediate halt and executor removal, timelocked
//! changes, two-step admin, fee claims.
//!
//! "Between batches" kinds (relay, executors, committee, timings) apply only
//! while no batch is in flight, and once one is due `CommitBatch` refuses
//! with `ChangeDue`, so a relay cannot starve it by closing and committing
//! in one transaction.

use core::ops::DerefMut;

use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::constants::{MAX_EXECUTORS, MIN_TIMELOCK, timelock_in_bounds, timings_in_bounds};
use crate::cpi::token_transfer;
use crate::error::TimescalesError;
use crate::processor::{current_slot, load_market_mut, market_seeds, require};
use crate::state::{Cursor, Exclusive, Market};

pub const SET_RELAY: u8 = 1;
pub const SET_EXECUTORS: u8 = 2;
pub const SET_COMMITTEE_DIGEST: u8 = 3;
pub const SET_ADMIN: u8 = 4;
pub const SET_TIMINGS: u8 = 5;
pub const SET_TIMELOCK: u8 = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    SetRelay([u8; 32]),
    SetExecutors {
        keys: Vec<[u8; 32]>,
        quorum: u8,
    },
    SetCommitteeDigest([u8; 32]),
    SetAdmin([u8; 32]),
    SetTimings {
        beacon_delay_slots: u16,
        exec_timeout_slots: u64,
        settle_timeout_slots: u64,
    },
    SetTimelock(u64),
}

/// Kinds that may only apply while no batch is in flight.
pub fn between_batches(kind: u8) -> bool {
    matches!(
        kind,
        SET_RELAY | SET_EXECUTORS | SET_COMMITTEE_DIGEST | SET_TIMINGS
    )
}

/// `1 <= n <= 8` keys, non-zero and distinct, and `1 <= quorum <= n`.
pub fn executors_valid(keys: &[[u8; 32]], quorum: u8) -> bool {
    let n = keys.len();
    (1..=MAX_EXECUTORS).contains(&n)
        && keys.iter().all(|k| *k != [0u8; 32])
        && keys.iter().enumerate().all(|(i, k)| !keys[..i].contains(k))
        && quorum >= 1
        && usize::from(quorum) <= n
}

fn nonzero(c: &mut Cursor<'_>) -> Result<[u8; 32], ProgramError> {
    let k = c.key()?;
    require(k != [0u8; 32], TimescalesError::InvalidConfig)?;
    Ok(k)
}

fn decode(kind: u8, payload: &[u8]) -> Result<Change, ProgramError> {
    let mut c = Cursor::new(payload);
    let change = match kind {
        SET_RELAY => Change::SetRelay(nonzero(&mut c)?),
        SET_EXECUTORS => {
            let n = usize::from(c.u8()?);
            require(n <= MAX_EXECUTORS, TimescalesError::InvalidConfig)?;
            let keys = c.chunks(n)?.to_vec();
            let quorum = c.u8()?;
            require(
                executors_valid(&keys, quorum),
                TimescalesError::InvalidConfig,
            )?;
            Change::SetExecutors { keys, quorum }
        }
        SET_COMMITTEE_DIGEST => Change::SetCommitteeDigest(nonzero(&mut c)?),
        SET_ADMIN => Change::SetAdmin(nonzero(&mut c)?),
        SET_TIMINGS => {
            let beacon_delay_slots = c.u16()?;
            let exec_timeout_slots = c.u64()?;
            let settle_timeout_slots = c.u64()?;
            require(
                timings_in_bounds(beacon_delay_slots, exec_timeout_slots, settle_timeout_slots),
                TimescalesError::InvalidConfig,
            )?;
            Change::SetTimings {
                beacon_delay_slots,
                exec_timeout_slots,
                settle_timeout_slots,
            }
        }
        SET_TIMELOCK => {
            let slots = c.u64()?;
            require(
                timelock_in_bounds(slots, MIN_TIMELOCK),
                TimescalesError::InvalidConfig,
            )?;
            Change::SetTimelock(slots)
        }
        _ => return Err(TimescalesError::InvalidConfig.into()),
    };
    require(c.is_empty(), TimescalesError::InvalidConfig)?;
    Ok(change)
}

/// Decodes and validates a payload for `kind`. Any failure, including a
/// short or overlong payload, is `InvalidConfig`.
pub fn parse(kind: u8, payload: &[u8]) -> Result<Change, ProgramError> {
    decode(kind, payload).map_err(|_| TimescalesError::InvalidConfig.into())
}

fn apply<D: DerefMut<Target = [u8]>>(m: &mut Market<D>, change: Change) {
    match change {
        Change::SetRelay(k) => m.set_relay(&k),
        Change::SetExecutors { keys, quorum } => {
            m.set_executors(&keys);
            m.set_receipt_quorum(quorum);
        }
        Change::SetCommitteeDigest(d) => {
            let prev = *m.committee_digest();
            m.set_prev_committee_digest(&prev);
            m.set_committee_digest(&d);
        }
        Change::SetAdmin(k) => m.set_pending_admin(&k),
        Change::SetTimings {
            beacon_delay_slots,
            exec_timeout_slots,
            settle_timeout_slots,
        } => {
            m.set_beacon_delay_slots(beacon_delay_slots);
            m.set_exec_timeout_slots(exec_timeout_slots);
            m.set_settle_timeout_slots(settle_timeout_slots);
        }
        Change::SetTimelock(slots) => m.set_timelock_slots(slots),
    }
}

/// `[admin (s), market (w)]` with the admin check.
fn admin_market<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'_>],
) -> Result<Market<Exclusive<'a>>, ProgramError> {
    let it = &mut accounts.iter();
    let admin = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let m = load_market_mut(program_id, market_acc)?;
    require(
        admin.is_signer && admin.key.as_array() == m.admin(),
        TimescalesError::Unauthorised,
    )?;
    Ok(m)
}

pub fn set_halted(program_id: &Pubkey, accounts: &[AccountInfo], halted: bool) -> ProgramResult {
    let mut m = admin_market(program_id, accounts)?;
    m.set_halted(halted);
    Ok(())
}

pub fn propose_change(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    kind: u8,
    payload: &[u8],
) -> ProgramResult {
    let mut m = admin_market(program_id, accounts)?;
    require(m.pending_kind() == 0, TimescalesError::ChangePending)?;
    parse(kind, payload)?;
    let eta_slot = current_slot()?
        .checked_add(m.timelock_slots())
        .ok_or(TimescalesError::Overflow)?;
    m.set_pending(kind, eta_slot, payload);
    Ok(())
}

/// Permissionless once the timelock has passed.
pub fn apply_change(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let cranker = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    require(cranker.is_signer, TimescalesError::Unauthorised)?;
    let mut m = load_market_mut(program_id, market_acc)?;
    require(m.pending_kind() != 0, TimescalesError::NoPendingChange)?;
    require(
        current_slot()? >= m.pending_eta_slot(),
        TimescalesError::Timelocked,
    )?;
    require(
        !between_batches(m.pending_kind()) || !m.in_flight(),
        TimescalesError::InFlight,
    )?;
    let change = parse(m.pending_kind(), m.pending_payload())?;
    apply(&mut m, change);
    m.clear_pending();
    Ok(())
}

pub fn cancel_change(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let mut m = admin_market(program_id, accounts)?;
    require(m.pending_kind() != 0, TimescalesError::NoPendingChange)?;
    m.clear_pending();
    Ok(())
}

pub fn accept_admin(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let signer = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let mut m = load_market_mut(program_id, market_acc)?;
    require(
        signer.is_signer
            && *m.pending_admin() != [0u8; 32]
            && signer.key.as_array() == m.pending_admin(),
        TimescalesError::NotPendingAdmin,
    )?;
    let admin = *m.pending_admin();
    m.set_admin(&admin);
    m.set_pending_admin(&[0u8; 32]);
    Ok(())
}

/// Immediate. The quorum is left alone: if it now exceeds the live
/// executors, receipts cannot finalize until a timelocked `SetExecutors`
/// (safety over liveness).
pub fn remove_executor(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    key: &[u8; 32],
) -> ProgramResult {
    let mut m = admin_market(program_id, accounts)?;
    let slot = m
        .executor_slot(key)
        .ok_or(TimescalesError::UnknownExecutor)?;
    m.clear_executor(slot);
    m.set_executor_count(m.executor_count().saturating_sub(1));
    Ok(())
}

pub fn claim_fees(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let it = &mut accounts.iter();
    let admin = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let dest = next_account_info(it)?;
    let token = next_account_info(it)?;
    let mut m = load_market_mut(program_id, market_acc)?;
    require(
        admin.is_signer && admin.key.as_array() == m.admin(),
        TimescalesError::Unauthorised,
    )?;
    let unclaimed = m.fees_accrued().saturating_sub(m.fees_claimed());
    require(amount <= unclaimed, TimescalesError::Insolvent)?;
    require(
        vault.key.as_array() == m.quote_vault(),
        TimescalesError::InvalidAccount,
    )?;
    m.set_fees_claimed(m.fees_claimed() + amount);
    let (id, bump) = (m.market_id().to_le_bytes(), m.bump());
    // The market signs the transfer, so its view goes first.
    drop(m);
    if amount > 0 {
        let seeds = market_seeds(&id, &bump);
        token_transfer(token, vault, dest, market_acc, amount, Some(&seeds))?;
    }
    Ok(())
}
