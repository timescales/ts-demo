use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::{instructions as ix_sysvar, slot_hashes, Sysvar},
};

use crate::beacon::{self, Lookup};
use crate::constants::{
    timelock_in_bounds, timings_in_bounds, BACKEND_TEE, BATCH_RETENTION, EMPTY_STATE_ROOT,
    HEADER_LEN, HEADER_VERSION, MAX_BALANCE, MAX_DELTAS, MAX_EXECUTORS, MIN_TIMELOCK,
    RECEIPT_VERSION, REVEAL_WINDOW,
};
use crate::cpi::{check_mint, check_vault, close_account, init_pda, pda_bump, token_transfer};
use crate::error::TimescalesError;
use crate::governance;
use crate::instruction::{InitMarket, Instruction, Leaf};
use crate::merkle::{
    self, BATCH_HEADER, EPOCH_TERMS, MARKET_ID, MARKET_PARAMS, OUTCOME, RECEIPT, RECEIPT_COSIGN,
};
use crate::state::{AbortReason, Batch, Cursor, Market, Pending, Status, Trader, PARAMS_LEN};

const ED25519_PROGRAM: Pubkey =
    solana_program::pubkey!("Ed25519SigVerify111111111111111111111111111");

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match Instruction::unpack(data)? {
        Instruction::InitMarket(a) => init_market(program_id, accounts, &a),
        Instruction::OpenTrader => open_trader(program_id, accounts),
        Instruction::Deposit { quote, amount } => deposit(program_id, accounts, quote, amount),
        Instruction::RequestWithdraw { base, quote } => {
            request_withdraw(program_id, accounts, base, quote)
        }
        Instruction::CancelWithdrawRequest => cancel_withdraw_request(program_id, accounts),
        Instruction::Withdraw { quote } => withdraw(program_id, accounts, quote),
        Instruction::CloseTrader => close_trader(program_id, accounts),
        Instruction::CommitBatch {
            epoch,
            root,
            count,
            terms_digest,
        } => commit_batch(program_id, accounts, epoch, root, count, terms_digest),
        Instruction::RevealBeacon => reveal_beacon(program_id, accounts),
        Instruction::PostReceipt { header, receipt } => {
            post_receipt(program_id, accounts, header, receipt)
        }
        Instruction::CoSignReceipt => cosign_receipt(program_id, accounts),
        Instruction::VerifyDeltas { leaves } => verify_deltas(program_id, accounts, &leaves),
        Instruction::FinalizeVerification => finalize(program_id, accounts),
        Instruction::ApplyDeltas { leaves } => apply_deltas(program_id, accounts, &leaves),
        Instruction::CloseBatch => close_batch(program_id, accounts),
        Instruction::AbortBatch { reason } => abort_batch(program_id, accounts, reason),
        Instruction::ReclaimBatch => reclaim_batch(program_id, accounts),
        Instruction::SetHalted { halted } => governance::set_halted(program_id, accounts, halted),
        Instruction::ProposeChange { kind, payload } => {
            governance::propose_change(program_id, accounts, kind, payload)
        }
        Instruction::ApplyChange => governance::apply_change(program_id, accounts),
        Instruction::CancelChange => governance::cancel_change(program_id, accounts),
        Instruction::AcceptAdmin => governance::accept_admin(program_id, accounts),
        Instruction::RemoveExecutor { key } => {
            governance::remove_executor(program_id, accounts, key)
        }
        Instruction::ClaimFees { amount } => governance::claim_fees(program_id, accounts, amount),
    }
}

pub fn require(cond: bool, e: TimescalesError) -> ProgramResult {
    if cond {
        Ok(())
    } else {
        Err(e.into())
    }
}

pub fn current_slot() -> Result<u64, ProgramError> {
    Ok(Clock::get()?.slot)
}

/// `LE64(H(MARKET_ID, program_id || creator || salt)[0..8])`.
pub fn derive_market_id(program_id: &Pubkey, creator: &Pubkey, salt: &[u8; 32]) -> u64 {
    let h = merkle::hash(MARKET_ID, &[program_id.as_ref(), creator.as_ref(), salt]);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h[..8]);
    u64::from_le_bytes(b)
}

/// Signer seeds of the Market PDA.
pub fn market_seeds<'a>(id: &'a [u8; 8], bump: &'a u8) -> [&'a [u8]; 3] {
    [b"market", id, core::slice::from_ref(bump)]
}

pub fn load_market(program_id: &Pubkey, acc: &AccountInfo) -> Result<Market, ProgramError> {
    require(acc.owner == program_id, TimescalesError::InvalidAccount)?;
    let m = Market::load(&acc.try_borrow_data()?)?;
    let id = m.market_id.to_le_bytes();
    let expected = Pubkey::create_program_address(&market_seeds(&id, &m.bump), program_id)
        .map_err(|_| TimescalesError::InvalidAccount)?;
    require(*acc.key == expected, TimescalesError::InvalidAccount)?;
    Ok(m)
}

pub fn store_market(acc: &AccountInfo, m: &Market) -> ProgramResult {
    m.store(&mut acc.try_borrow_mut_data()?)
}

fn load_trader(
    program_id: &Pubkey,
    market: &Pubkey,
    acc: &AccountInfo,
) -> Result<Trader, ProgramError> {
    require(acc.owner == program_id, TimescalesError::InvalidAccount)?;
    let t = Trader::load(&acc.try_borrow_data()?)?;
    require(
        t.market == market.to_bytes(),
        TimescalesError::InvalidAccount,
    )?;
    let expected = Pubkey::create_program_address(
        &[b"trader", market.as_ref(), &t.owner, &[t.bump]],
        program_id,
    )
    .map_err(|_| TimescalesError::InvalidAccount)?;
    require(*acc.key == expected, TimescalesError::InvalidAccount)?;
    Ok(t)
}

/// The trader account, owned by the signing `owner`.
fn owned_trader(
    program_id: &Pubkey,
    market: &Pubkey,
    owner: &AccountInfo,
    acc: &AccountInfo,
) -> Result<Trader, ProgramError> {
    let t = load_trader(program_id, market, acc)?;
    require(
        owner.is_signer && t.owner == owner.key.to_bytes(),
        TimescalesError::Unauthorised,
    )?;
    Ok(t)
}

fn load_batch(
    program_id: &Pubkey,
    market: &Pubkey,
    acc: &AccountInfo,
) -> Result<Batch, ProgramError> {
    require(acc.owner == program_id, TimescalesError::InvalidAccount)?;
    let b = Batch::load(&acc.try_borrow_data()?)?;
    require(
        b.market == market.to_bytes(),
        TimescalesError::InvalidAccount,
    )?;
    let expected = Pubkey::create_program_address(
        &[b"batch", market.as_ref(), &b.epoch.to_le_bytes(), &[b.bump]],
        program_id,
    )
    .map_err(|_| TimescalesError::InvalidAccount)?;
    require(*acc.key == expected, TimescalesError::InvalidAccount)?;
    Ok(b)
}

/// `MarketParams` checks that the program can enforce: the
/// off-chain `MarketParams::validate`, plus `max_batch_envelopes <= 1024`
/// (so deltas fit the bitmaps), the Sha256 commitment scheme and strict
/// enum bytes.
fn params_valid(p: &[u8; PARAMS_LEN], market_id: u64) -> Result<bool, ProgramError> {
    let mut c = Cursor::new(p);
    let market = c.u64()?;
    let base_lot_size = c.u64()?;
    let tick_size = c.u64()?;
    let band_half_width = c.u32()?;
    let lots_log2 = c.u8()?;
    let max_orders_per_trader = c.u16()?;
    let max_batch_envelopes = c.u32()?;
    let _max_order_lifetime = c.u32()?;
    let maker_fee = c.u16()?;
    let taker_fee = c.u16()?;
    let flow = c.u8()?;
    let rationing = c.u8()?;
    let scheme = c.u8()?;
    let band_ticks = band_half_width.saturating_mul(2).saturating_add(1);
    let envelopes_ok = (1..=MAX_DELTAS as u32).contains(&max_batch_envelopes);
    let env_bits = if envelopes_ok {
        32 - (max_batch_envelopes - 1).leading_zeros()
    } else {
        0
    };
    Ok(market == market_id
        && base_lot_size > 0
        && tick_size > 0
        && band_half_width > 0
        && band_ticks <= 1025
        && (1..=48).contains(&lots_log2)
        && max_orders_per_trader > 0
        && envelopes_ok
        && u32::from(lots_log2) + env_bits <= 63
        && maker_fee <= 10_000
        && taker_fee <= 10_000
        && flow <= 1
        && rationing <= 1
        && scheme == 0)
}

fn init_market(program_id: &Pubkey, accounts: &[AccountInfo], a: &InitMarket) -> ProgramResult {
    let it = &mut accounts.iter();
    let creator = next_account_info(it)?;
    let market = next_account_info(it)?;
    let base_mint = next_account_info(it)?;
    let quote_mint = next_account_info(it)?;
    let base_vault = next_account_info(it)?;
    let quote_vault = next_account_info(it)?;
    let system = next_account_info(it)?;

    require(creator.is_signer, TimescalesError::Unauthorised)?;
    require(
        a.market_id == derive_market_id(program_id, creator.key, a.salt),
        TimescalesError::InvalidMarketId,
    )?;
    let id = a.market_id.to_le_bytes();
    let bump = pda_bump(program_id, market, &[b"market", &id])?;
    require(
        params_valid(a.params, a.market_id)?,
        TimescalesError::InvalidParams,
    )?;
    check_mint(base_mint)?;
    check_mint(quote_mint)?;
    require(
        base_mint.key != quote_mint.key,
        TimescalesError::InvalidTokenAccount,
    )?;
    check_vault(base_vault, base_mint.key, market.key)?;
    check_vault(quote_vault, quote_mint.key, market.key)?;
    require(
        base_vault.key != quote_vault.key,
        TimescalesError::InvalidTokenAccount,
    )?;
    require(
        governance::executors_valid(a.executors, a.receipt_quorum)
            && *a.admin != [0u8; 32]
            && *a.relay != [0u8; 32]
            && *a.committee_digest != [0u8; 32]
            && timings_in_bounds(
                a.beacon_delay_slots,
                a.exec_timeout_slots,
                a.settle_timeout_slots,
            )
            && timelock_in_bounds(a.timelock_slots, MIN_TIMELOCK),
        TimescalesError::InvalidConfig,
    )?;

    init_pda(
        program_id,
        creator,
        market,
        system,
        &[b"market", &id],
        bump,
        Market::LEN,
    )?;
    let mut executors = [[0u8; 32]; MAX_EXECUTORS];
    for (slot, k) in executors.iter_mut().zip(a.executors) {
        *slot = *k;
    }
    let m = Market {
        bump,
        halted: false,
        market_id: a.market_id,
        creator: creator.key.to_bytes(),
        admin: *a.admin,
        pending_admin: [0; 32],
        relay: *a.relay,
        base_mint: base_mint.key.to_bytes(),
        quote_mint: quote_mint.key.to_bytes(),
        base_vault: base_vault.key.to_bytes(),
        quote_vault: quote_vault.key.to_bytes(),
        params: *a.params,
        params_digest: merkle::hash(MARKET_PARAMS, &[a.params]),
        committee_digest: *a.committee_digest,
        executor_count: a.executors.len() as u8,
        receipt_quorum: a.receipt_quorum,
        executors,
        beacon_delay_slots: a.beacon_delay_slots,
        timelock_slots: a.timelock_slots,
        exec_timeout_slots: a.exec_timeout_slots,
        settle_timeout_slots: a.settle_timeout_slots,
        last_committed: 0,
        last_settled: 0,
        last_progress_slot: current_slot()?,
        fees_accrued: 0,
        fees_claimed: 0,
        prev_receipt: [0; 32],
        state_root: EMPTY_STATE_ROOT,
        pending: Pending::NONE,
        salt: *a.salt,
        prev_committee_digest: [0; 32],
    };
    store_market(market, &m)
}

fn open_trader(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let market = next_account_info(it)?;
    let trader = next_account_info(it)?;
    let system = next_account_info(it)?;
    require(owner.is_signer, TimescalesError::Unauthorised)?;
    load_market(program_id, market)?;
    let seeds: [&[u8]; 3] = [b"trader", market.key.as_ref(), owner.key.as_ref()];
    let bump = pda_bump(program_id, trader, &seeds)?;
    init_pda(program_id, owner, trader, system, &seeds, bump, Trader::LEN)?;
    let t = Trader::new(
        bump,
        market.key.to_bytes(),
        owner.key.to_bytes(),
        current_slot()?,
    );
    t.store(&mut trader.try_borrow_mut_data()?)
}

fn vault_for(m: &Market, quote: bool) -> [u8; 32] {
    if quote {
        m.quote_vault
    } else {
        m.base_vault
    }
}

fn deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    quote: bool,
    amount: u64,
) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let trader_acc = next_account_info(it)?;
    let source = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let token = next_account_info(it)?;
    let m = load_market(program_id, market_acc)?;
    require(!m.halted, TimescalesError::Halted)?;
    require(amount > 0, TimescalesError::InvalidInstruction)?;
    let mut t = owned_trader(program_id, market_acc.key, owner, trader_acc)?;
    require(
        vault.key.to_bytes() == vault_for(&m, quote),
        TimescalesError::InvalidAccount,
    )?;
    let balance = if quote { t.quote } else { t.base };
    require(
        balance
            .checked_add(amount)
            .is_some_and(|b| b <= MAX_BALANCE),
        TimescalesError::BalanceCap,
    )?;
    t.capture_floor(&m);
    token_transfer(token, source, vault, owner, amount, None)?;
    let side = if quote { &mut t.quote } else { &mut t.base };
    *side = side.checked_add(amount).ok_or(TimescalesError::Overflow)?;
    t.last_change_slot = current_slot()?;
    t.store(&mut trader_acc.try_borrow_mut_data()?)
}

/// Reserves, does not debit: the request is paid out by `Withdraw`
/// once every batch that could have used the balance is terminal.
fn request_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    base: u64,
    quote: u64,
) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let trader_acc = next_account_info(it)?;
    let m = load_market(program_id, market_acc)?;
    let mut t = owned_trader(program_id, market_acc.key, owner, trader_acc)?;
    require(
        t.requested_base == 0 && t.requested_quote == 0,
        TimescalesError::WithdrawPending,
    )?;
    require(base != 0 || quote != 0, TimescalesError::NothingToWithdraw)?;
    require(
        base <= t.base && quote <= t.quote,
        TimescalesError::Insolvent,
    )?;
    t.capture_floor(&m);
    t.requested_base = base;
    t.requested_quote = quote;
    t.request_epoch = m.last_committed;
    t.last_change_slot = current_slot()?;
    t.store(&mut trader_acc.try_borrow_mut_data()?)
}

fn cancel_withdraw_request(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let trader_acc = next_account_info(it)?;
    let m = load_market(program_id, market_acc)?;
    let mut t = owned_trader(program_id, market_acc.key, owner, trader_acc)?;
    t.capture_floor(&m);
    t.requested_base = 0;
    t.requested_quote = 0;
    t.last_change_slot = current_slot()?;
    t.store(&mut trader_acc.try_borrow_mut_data()?)
}

/// Pays `min(requested, balance)` for one side once the batch in flight at
/// request time is terminal. A batch committed before the request may have
/// used part of the requested amount.
fn withdraw(program_id: &Pubkey, accounts: &[AccountInfo], quote: bool) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let trader_acc = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let dest = next_account_info(it)?;
    let token = next_account_info(it)?;
    let m = load_market(program_id, market_acc)?;
    let mut t = owned_trader(program_id, market_acc.key, owner, trader_acc)?;
    let requested = if quote {
        t.requested_quote
    } else {
        t.requested_base
    };
    require(requested > 0, TimescalesError::NothingToWithdraw)?;
    require(
        m.last_settled >= t.request_epoch,
        TimescalesError::WithdrawLocked,
    )?;
    require(
        vault.key.to_bytes() == vault_for(&m, quote),
        TimescalesError::InvalidAccount,
    )?;
    t.capture_floor(&m);
    let (balance, req) = if quote {
        (&mut t.quote, &mut t.requested_quote)
    } else {
        (&mut t.base, &mut t.requested_base)
    };
    let amount = requested.min(*balance);
    *balance -= amount;
    *req = 0;
    t.last_change_slot = current_slot()?;
    t.store(&mut trader_acc.try_borrow_mut_data()?)?;
    if amount > 0 {
        let id = m.market_id.to_le_bytes();
        let seeds = market_seeds(&id, &m.bump);
        token_transfer(token, vault, dest, market_acc, amount, Some(&seeds))?;
    }
    Ok(())
}

/// An empty account cannot hold a leaf of the batch in flight: its
/// available balance at the snapshot was zero (a withdrawal that emptied
/// it was reserved for that batch), so it could not fill. The leaf
/// check is defence in depth.
fn close_trader(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let trader_acc = next_account_info(it)?;
    let m = load_market(program_id, market_acc)?;
    let t = owned_trader(program_id, market_acc.key, owner, trader_acc)?;
    require(t.is_empty(), TimescalesError::AccountNotEmpty)?;
    require(
        !m.in_flight() || t.last_leaf_epoch != m.last_committed,
        TimescalesError::InFlight,
    )?;
    close_account(trader_acc, owner)
}

fn commit_batch(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    epoch: u64,
    root: &[u8; 32],
    count: u32,
    terms_digest: &[u8; 32],
) -> ProgramResult {
    let it = &mut accounts.iter();
    let relay = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let batch_acc = next_account_info(it)?;
    let system = next_account_info(it)?;
    let mut m = load_market(program_id, market_acc)?;
    require(
        relay.is_signer && relay.key.to_bytes() == m.relay,
        TimescalesError::Unauthorised,
    )?;
    require(!m.halted, TimescalesError::Halted)?;
    require(
        m.last_committed.checked_add(1) == Some(epoch),
        TimescalesError::OutOfOrder,
    )?;
    require(!m.in_flight(), TimescalesError::InFlight)?;
    let slot = current_slot()?;
    require(
        !(governance::between_batches(m.pending.kind) && slot >= m.pending.eta_slot),
        TimescalesError::ChangeDue,
    )?;
    require(
        count >= 1 && count <= m.max_batch_envelopes(),
        TimescalesError::InvalidBatchCount,
    )?;
    require(*root != [0u8; 32], TimescalesError::InvalidInstruction)?;

    let epoch_le = epoch.to_le_bytes();
    let seeds: [&[u8]; 3] = [b"batch", market_acc.key.as_ref(), &epoch_le];
    let bump = pda_bump(program_id, batch_acc, &seeds)?;
    init_pda(
        program_id,
        relay,
        batch_acc,
        system,
        &seeds,
        bump,
        Batch::LEN,
    )?;
    // SlotHashes is not read here: the beacon is fixed only after the root
    // and count are.
    let b = Batch::committed(
        bump,
        market_acc.key.to_bytes(),
        epoch,
        *root,
        count,
        *terms_digest,
        slot,
    );
    b.store(&mut batch_acc.try_borrow_mut_data()?)?;
    m.last_committed = epoch;
    m.last_progress_slot = slot;
    store_market(market_acc, &m)
}

fn reveal_beacon(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let cranker = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let batch_acc = next_account_info(it)?;
    let hashes = next_account_info(it)?;
    require(cranker.is_signer, TimescalesError::Unauthorised)?;
    let m = load_market(program_id, market_acc)?;
    let mut b = load_batch(program_id, market_acc.key, batch_acc)?;
    require(
        *hashes.key == slot_hashes::ID,
        TimescalesError::InvalidAccount,
    )?;
    require(b.status == Status::Committed, TimescalesError::WrongStatus)?;
    let d = u64::from(m.beacon_delay_slots);
    let slot = current_slot()?;
    require(
        slot <= b.commit_slot + d + REVEAL_WINDOW,
        TimescalesError::BeaconExpired,
    )?;
    let (target_a, target_b) = (b.commit_slot + d, b.commit_slot + 2 * d);
    let lookup = |target| -> Result<(u64, [u8; 32]), ProgramError> {
        match beacon::slot_hashes_entry(&hashes.try_borrow_data()?, target) {
            Lookup::Found(s, h) => Ok((s, h)),
            Lookup::NotReady => Err(TimescalesError::BeaconNotReady.into()),
            Lookup::Malformed => Err(TimescalesError::InvalidAccount.into()),
        }
    };
    let entry_b = lookup(target_b)?;
    let entry_a = lookup(target_a)?;
    b.beacon = beacon::beacon_v2(
        &market_acc.key.to_bytes(),
        b.epoch,
        &b.root,
        b.count,
        entry_a,
        entry_b,
    );
    b.beacon_slot_a = entry_a.0;
    b.beacon_slot_b = entry_b.0;
    b.reveal_slot = slot;
    b.status = Status::BeaconRevealed;
    b.store(&mut batch_acc.try_borrow_mut_data()?)
}

/// What an Ed25519 precompile instruction verified.
struct Ed25519Entry {
    pubkey: [u8; 32],
    signature: [u8; 64],
    message: [u8; 32],
}

/// An Ed25519 precompile instruction immediately before this one, with one
/// signature over a 32-byte message and every offset inside its own data.
fn preceding_ed25519(instructions: &AccountInfo) -> Result<Ed25519Entry, ProgramError> {
    require(
        *instructions.key == ix_sysvar::ID,
        TimescalesError::InvalidAccount,
    )?;
    let current = ix_sysvar::load_current_index_checked(instructions)?;
    require(current > 0, TimescalesError::BadSignature)?;
    let ix = ix_sysvar::load_instruction_at_checked(usize::from(current - 1), instructions)?;
    require(
        ix.program_id == ED25519_PROGRAM,
        TimescalesError::BadSignature,
    )?;
    let d = &ix.data;
    let bad = |_| ProgramError::from(TimescalesError::BadSignature);
    let mut c = Cursor::new(d);
    require(c.u8().map_err(bad)? == 1, TimescalesError::BadSignature)?;
    c.u8().map_err(bad)?;
    let mut field = || c.u16().map_err(bad);
    let sig_off = usize::from(field()?);
    let sig_ix = field()?;
    let pk_off = usize::from(field()?);
    let pk_ix = field()?;
    let msg_off = usize::from(field()?);
    let msg_len = usize::from(field()?);
    let msg_ix = field()?;
    require(
        sig_ix == u16::MAX && pk_ix == u16::MAX && msg_ix == u16::MAX && msg_len == 32,
        TimescalesError::BadSignature,
    )?;
    let get = |off: usize, len: usize| {
        d.get(off..off + len)
            .ok_or(ProgramError::from(TimescalesError::BadSignature))
    };
    let mut e = Ed25519Entry {
        pubkey: [0; 32],
        signature: [0; 64],
        message: [0; 32],
    };
    e.pubkey.copy_from_slice(get(pk_off, 32)?);
    e.signature.copy_from_slice(get(sig_off, 64)?);
    e.message.copy_from_slice(get(msg_off, 32)?);
    Ok(e)
}

fn le_u32(b: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[..4]);
    u32::from_le_bytes(a)
}

fn le_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

fn key_at(b: &[u8], at: usize) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&b[at..at + 32]);
    k
}

/// Header v2 (283 B): version, market, epoch, params [17..63], band and
/// epoch binding [63..119], count, batch root, beacon, prior state root
/// [187..219], balances root, previous receipt [251..283].
///
/// Receipt v1 (390 + 17k B): version, outcome [1..197+17k] (market, epoch,
/// header digest, k clearing prices, fill count, fills / cancelled /
/// next-state roots, settlement count and root, fees), backend, executor,
/// attestation, proof, trace, signature (last 64 bytes).
fn post_receipt(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    header: &[u8],
    receipt: &[u8],
) -> ProgramResult {
    let it = &mut accounts.iter();
    let cranker = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let batch_acc = next_account_info(it)?;
    let instructions = next_account_info(it)?;
    require(cranker.is_signer, TimescalesError::Unauthorised)?;
    let m = load_market(program_id, market_acc)?;
    let mut b = load_batch(program_id, market_acc.key, batch_acc)?;
    require(!m.halted, TimescalesError::Halted)?;
    require(
        b.status == Status::BeaconRevealed,
        TimescalesError::WrongStatus,
    )?;
    require(b.epoch == m.last_settled + 1, TimescalesError::OutOfOrder)?;
    require(
        header.len() == HEADER_LEN
            && header[0] == HEADER_VERSION
            && receipt.first() == Some(&RECEIPT_VERSION),
        TimescalesError::UnsupportedVersion,
    )?;

    let h = header;
    require(
        le_u64(&h[1..9]) == m.market_id && le_u64(&h[9..17]) == b.epoch,
        TimescalesError::HeaderMismatch,
    )?;
    require(h[17..63] == m.params, TimescalesError::ParamsMismatch)?;
    require(
        merkle::hash(EPOCH_TERMS, &[&h[63..119]]) == b.terms_digest,
        TimescalesError::TermsMismatch,
    )?;
    require(
        le_u32(&h[119..123]) == b.count
            && h[123..155] == b.root
            && h[155..187] == b.beacon
            && h[251..283] == m.prev_receipt,
        TimescalesError::HeaderMismatch,
    )?;
    require(
        h[187..219] == m.state_root,
        TimescalesError::StateRootMismatch,
    )?;
    let header_digest = merkle::hash(BATCH_HEADER, &[h]);

    let r = receipt;
    require(r.len() >= 53, TimescalesError::ReceiptMismatch)?;
    require(
        le_u64(&r[1..9]) == m.market_id
            && le_u64(&r[9..17]) == b.epoch
            && r[17..49] == header_digest,
        TimescalesError::ReceiptMismatch,
    )?;
    let k = le_u32(&r[49..53]) as usize;
    require(
        k <= 2 && r.len() == 390 + 17 * k,
        TimescalesError::ReceiptMismatch,
    )?;
    let o = 17 * k;
    let next_state_root = key_at(r, 121 + o);
    let settlement_count = le_u32(&r[153 + o..]);
    let settlement_root = key_at(r, 157 + o);
    let fees = le_u64(&r[189 + o..]);
    let backend = r[197 + o];
    let executor = key_at(r, 198 + o);
    let (signed, signature) = r.split_at(326 + o);
    require(
        settlement_count as usize <= MAX_DELTAS && settlement_count <= b.count,
        TimescalesError::TooManyDeltas,
    )?;
    require(backend == BACKEND_TEE, TimescalesError::BackendNotAllowed)?;
    let poster = m
        .executor_slot(&executor)
        .ok_or(TimescalesError::UnknownExecutor)?;
    let digest = merkle::hash(RECEIPT, &[signed]);
    let sig = preceding_ed25519(instructions)?;
    require(
        sig.pubkey == executor && sig.signature[..] == *signature && sig.message == digest,
        TimescalesError::BadSignature,
    )?;

    b.header_digest = header_digest;
    b.receipt = digest;
    b.outcome_digest = merkle::hash(OUTCOME, &[&r[1..197 + o]]);
    b.next_state_root = next_state_root;
    b.settlement_root = settlement_root;
    b.settlement_count = settlement_count;
    b.fees = fees;
    b.receipt_slot = current_slot()?;
    b.cosign_bitmap = 1 << poster;
    b.cosign_count = 1;
    b.status = Status::ReceiptPosted;
    b.store(&mut batch_acc.try_borrow_mut_data()?)
}

/// `H(RECEIPT_COSIGN, market32 || epoch || header_digest || outcome_digest)`.
pub fn cosign_digest(market: &Pubkey, b: &Batch) -> [u8; 32] {
    merkle::hash(
        RECEIPT_COSIGN,
        &[
            market.as_ref(),
            &b.epoch.to_le_bytes(),
            &b.header_digest,
            &b.outcome_digest,
        ],
    )
}

fn cosign_receipt(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let cranker = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let batch_acc = next_account_info(it)?;
    let instructions = next_account_info(it)?;
    require(cranker.is_signer, TimescalesError::Unauthorised)?;
    let m = load_market(program_id, market_acc)?;
    let mut b = load_batch(program_id, market_acc.key, batch_acc)?;
    require(!m.halted, TimescalesError::Halted)?;
    require(
        b.status == Status::ReceiptPosted,
        TimescalesError::WrongStatus,
    )?;
    let sig = preceding_ed25519(instructions)?;
    let slot = m
        .executor_slot(&sig.pubkey)
        .ok_or(TimescalesError::UnknownExecutor)?;
    require(
        b.cosign_bitmap & (1 << slot) == 0,
        TimescalesError::AlreadyCosigned,
    )?;
    require(
        sig.message == cosign_digest(market_acc.key, &b),
        TimescalesError::BadSignature,
    )?;
    b.cosign_bitmap |= 1 << slot;
    b.cosign_count = b.cosign_count.saturating_add(1);
    b.store(&mut batch_acc.try_borrow_mut_data()?)
}

fn leaf_root(b: &Batch, leaf: &Leaf) -> Option<[u8; 32]> {
    merkle::root_from_path(
        merkle::leaf(&leaf.bytes()),
        u64::from(leaf.index),
        u64::from(b.settlement_count),
        leaf.path,
    )
}

fn verify_deltas(program_id: &Pubkey, accounts: &[AccountInfo], leaves: &[Leaf]) -> ProgramResult {
    let it = &mut accounts.iter();
    let cranker = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let batch_acc = next_account_info(it)?;
    require(cranker.is_signer, TimescalesError::Unauthorised)?;
    let m = load_market(program_id, market_acc)?;
    let mut b = load_batch(program_id, market_acc.key, batch_acc)?;
    require(!m.halted, TimescalesError::Halted)?;
    require(
        b.status == Status::ReceiptPosted,
        TimescalesError::WrongStatus,
    )?;
    // No settlement leaf is processed before the quorum agrees.
    require(m.quorum_met(b.cosign_bitmap), TimescalesError::QuorumNotMet)?;
    for leaf in leaves {
        let trader_acc = next_account_info(it)?;
        let mut t = load_trader(program_id, market_acc.key, trader_acc)?;
        require(t.owner == *leaf.trader, TimescalesError::InvalidAccount)?;
        require(leaf.index < b.settlement_count, TimescalesError::BadProof)?;
        require(
            !Batch::test_and_set(&mut b.verified, leaf.index),
            TimescalesError::DuplicateLeaf,
        )?;
        require(
            t.last_leaf_epoch != b.epoch,
            TimescalesError::DuplicateTrader,
        )?;
        require(
            leaf_root(&b, leaf) == Some(b.settlement_root),
            TimescalesError::BadProof,
        )?;
        let (res_base, res_quote) = t.reserved(b.epoch);
        for (balance, delta, reserved) in [
            (t.base, leaf.base, res_base),
            (t.quote, leaf.quote, res_quote),
        ] {
            let after = i128::from(balance) + i128::from(delta);
            require(after >= i128::from(reserved), TimescalesError::Insolvent)?;
            require(after <= i128::from(u64::MAX), TimescalesError::Overflow)?;
        }
        b.verified_count += 1;
        b.sum_base += i128::from(leaf.base);
        b.sum_quote += i128::from(leaf.quote);
        t.last_leaf_epoch = b.epoch;
        t.store(&mut trader_acc.try_borrow_mut_data()?)?;
    }
    b.store(&mut batch_acc.try_borrow_mut_data()?)
}

fn finalize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let cranker = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let batch_acc = next_account_info(it)?;
    require(cranker.is_signer, TimescalesError::Unauthorised)?;
    let m = load_market(program_id, market_acc)?;
    let mut b = load_batch(program_id, market_acc.key, batch_acc)?;
    require(!m.halted, TimescalesError::Halted)?;
    require(
        b.status == Status::ReceiptPosted,
        TimescalesError::WrongStatus,
    )?;
    require(
        b.verified_count == b.settlement_count,
        TimescalesError::Incomplete,
    )?;
    // sum(inputs) == sum(outputs) + fees
    require(
        b.sum_base == 0 && b.sum_quote + i128::from(b.fees) == 0,
        TimescalesError::NotConserved,
    )?;
    // A removed executor's signature stops counting.
    require(m.quorum_met(b.cosign_bitmap), TimescalesError::QuorumNotMet)?;
    b.status = Status::Verified;
    b.store(&mut batch_acc.try_borrow_mut_data()?)
}

/// After `FinalizeVerification` every leaf applies (available never
/// decreases between verify and apply). The balance checks here are
/// defence in depth.
fn apply_deltas(program_id: &Pubkey, accounts: &[AccountInfo], leaves: &[Leaf]) -> ProgramResult {
    let it = &mut accounts.iter();
    let cranker = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let batch_acc = next_account_info(it)?;
    require(cranker.is_signer, TimescalesError::Unauthorised)?;
    let m = load_market(program_id, market_acc)?;
    let mut b = load_batch(program_id, market_acc.key, batch_acc)?;
    require(b.status == Status::Verified, TimescalesError::WrongStatus)?;
    // A halt never strands a half-applied batch.
    require(!m.halted || b.applied_count > 0, TimescalesError::Halted)?;
    let slot = current_slot()?;
    for leaf in leaves {
        let trader_acc = next_account_info(it)?;
        let mut t = load_trader(program_id, market_acc.key, trader_acc)?;
        require(
            t.owner == *leaf.trader && t.last_leaf_epoch == b.epoch,
            TimescalesError::InvalidAccount,
        )?;
        require(
            leaf.index < b.settlement_count && leaf_root(&b, leaf) == Some(b.settlement_root),
            TimescalesError::BadProof,
        )?;
        require(
            !Batch::test_and_set(&mut b.applied, leaf.index),
            TimescalesError::DuplicateLeaf,
        )?;
        let base = i128::from(t.base) + i128::from(leaf.base);
        let quote = i128::from(t.quote) + i128::from(leaf.quote);
        require(base >= 0 && quote >= 0, TimescalesError::Insolvent)?;
        let base = u64::try_from(base).map_err(|_| TimescalesError::Overflow)?;
        let quote = u64::try_from(quote).map_err(|_| TimescalesError::Overflow)?;
        t.capture_floor(&m);
        t.base = base;
        t.quote = quote;
        t.last_change_slot = slot;
        t.store(&mut trader_acc.try_borrow_mut_data()?)?;
        b.applied_count += 1;
    }
    b.store(&mut batch_acc.try_borrow_mut_data()?)
}

fn close_batch(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let cranker = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let batch_acc = next_account_info(it)?;
    require(cranker.is_signer, TimescalesError::Unauthorised)?;
    let mut m = load_market(program_id, market_acc)?;
    let mut b = load_batch(program_id, market_acc.key, batch_acc)?;
    require(b.status == Status::Verified, TimescalesError::WrongStatus)?;
    require(
        b.applied_count == b.settlement_count,
        TimescalesError::Incomplete,
    )?;
    b.status = Status::Settled;
    b.store(&mut batch_acc.try_borrow_mut_data()?)?;
    m.fees_accrued = m
        .fees_accrued
        .checked_add(b.fees)
        .ok_or(TimescalesError::Overflow)?;
    m.last_settled = b.epoch;
    m.prev_receipt = b.receipt;
    m.state_root = b.next_state_root;
    m.last_progress_slot = current_slot()?;
    store_market(market_acc, &m)
}

/// The abort matrix. Every timer starts at an event of this batch,
/// so no batch can be timed out while waiting behind another one.
fn abort_batch(program_id: &Pubkey, accounts: &[AccountInfo], reason: u8) -> ProgramResult {
    let it = &mut accounts.iter();
    let signer = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let batch_acc = next_account_info(it)?;
    require(signer.is_signer, TimescalesError::Unauthorised)?;
    let mut m = load_market(program_id, market_acc)?;
    let mut b = load_batch(program_id, market_acc.key, batch_acc)?;
    require(b.epoch == m.last_settled + 1, TimescalesError::OutOfOrder)?;
    require(b.applied_count == 0, TimescalesError::WrongStatus)?;
    require(
        matches!(
            b.status,
            Status::Committed | Status::BeaconRevealed | Status::ReceiptPosted | Status::Verified
        ),
        TimescalesError::WrongStatus,
    )?;
    let reason = AbortReason::from_u8(reason).ok_or(TimescalesError::InvalidAbortReason)?;
    let slot = current_slot()?;
    let signer_key = signer.key.to_bytes();
    let d = u64::from(m.beacon_delay_slots);
    let expired = |deadline: u64| require(slot > deadline, TimescalesError::NotExpired);
    match reason {
        AbortReason::Admin => require(signer_key == m.admin, TimescalesError::Unauthorised)?,
        AbortReason::Relay => {
            require(signer_key == m.relay, TimescalesError::Unauthorised)?;
            require(b.status == Status::Committed, TimescalesError::WrongStatus)?;
            // Only before either beacon input exists: the relay never gets
            // to choose an outcome after seeing the beacon.
            require(slot < b.commit_slot + d, TimescalesError::Unauthorised)?;
        }
        AbortReason::BeaconExpired => {
            require(b.status == Status::Committed, TimescalesError::WrongStatus)?;
            expired(b.commit_slot + d + REVEAL_WINDOW)?;
        }
        AbortReason::ExecTimeout => {
            require(
                b.status == Status::BeaconRevealed,
                TimescalesError::WrongStatus,
            )?;
            expired(b.reveal_slot + m.exec_timeout_slots)?;
        }
        AbortReason::SettleTimeout => {
            require(
                matches!(b.status, Status::ReceiptPosted | Status::Verified),
                TimescalesError::WrongStatus,
            )?;
            expired(b.receipt_slot + m.settle_timeout_slots)?;
        }
        AbortReason::QuorumTimeout => {
            // A receipt that reached its quorum is not in this state.
            require(
                b.status == Status::ReceiptPosted && !m.quorum_met(b.cosign_bitmap),
                TimescalesError::WrongStatus,
            )?;
            expired(b.receipt_slot + m.exec_timeout_slots)?;
        }
    }
    b.status = Status::Aborted;
    b.abort_reason = reason as u8;
    b.store(&mut batch_acc.try_borrow_mut_data()?)?;
    m.last_settled = b.epoch;
    m.last_progress_slot = slot;
    store_market(market_acc, &m)
}

fn reclaim_batch(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let cranker = next_account_info(it)?;
    let market_acc = next_account_info(it)?;
    let batch_acc = next_account_info(it)?;
    let relay = next_account_info(it)?;
    require(cranker.is_signer, TimescalesError::Unauthorised)?;
    let m = load_market(program_id, market_acc)?;
    let b = load_batch(program_id, market_acc.key, batch_acc)?;
    require(
        relay.key.to_bytes() == m.relay,
        TimescalesError::InvalidAccount,
    )?;
    require(
        matches!(b.status, Status::Settled | Status::Aborted),
        TimescalesError::WrongStatus,
    )?;
    require(
        b.epoch.saturating_add(BATCH_RETENTION) <= m.last_settled,
        TimescalesError::RetentionNotReached,
    )?;
    close_account(batch_acc, relay)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(market: u64) -> [u8; PARAMS_LEN] {
        let mut p = [0u8; PARAMS_LEN];
        p[..8].copy_from_slice(&market.to_le_bytes());
        p[8..16].copy_from_slice(&1u64.to_le_bytes());
        p[16..24].copy_from_slice(&1u64.to_le_bytes());
        p[24..28].copy_from_slice(&4u32.to_le_bytes());
        p[28] = 40;
        p[29..31].copy_from_slice(&8u16.to_le_bytes());
        p[31..35].copy_from_slice(&1024u32.to_le_bytes());
        p
    }

    #[test]
    fn params_validation() {
        assert!(params_valid(&params(9), 9).unwrap());
        assert!(!params_valid(&params(9), 8).unwrap());
        let mut too_many = params(9);
        too_many[31..35].copy_from_slice(&1025u32.to_le_bytes());
        assert!(!params_valid(&too_many, 9).unwrap());
        let mut poseidon = params(9);
        poseidon[45] = 1;
        assert!(!params_valid(&poseidon, 9).unwrap());
        let mut flow = params(9);
        flow[43] = 2;
        assert!(!params_valid(&flow, 9).unwrap());
        let mut bits = params(9);
        bits[28] = 48;
        assert!(params_valid(&bits, 9).unwrap());
        bits[28] = 49;
        assert!(!params_valid(&bits, 9).unwrap());
    }

    #[test]
    fn market_id_is_the_first_eight_digest_bytes() {
        let program = Pubkey::new_from_array([1; 32]);
        let creator = Pubkey::new_from_array([2; 32]);
        let h = merkle::hash(MARKET_ID, &[&[1; 32], &[2; 32], &[3; 32]]);
        assert_eq!(
            derive_market_id(&program, &creator, &[3; 32]).to_le_bytes(),
            h[..8]
        );
        assert_ne!(
            derive_market_id(&program, &creator, &[3; 32]),
            derive_market_id(&creator, &program, &[3; 32])
        );
    }
}
