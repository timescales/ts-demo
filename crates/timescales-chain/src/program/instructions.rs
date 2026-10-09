//! Builders for the 24 program instructions and the Ed25519 precompile
//! instruction that `PostReceipt` and `CoSignReceipt` introspect.
//!
//! Data is one tag byte followed by fixed-width little-endian fields, and the
//! account lists follow the table exactly (`[w]` writable, `[s]` signer).
//! Builders refuse only what cannot be encoded or can never be accepted
//! (more than eight executors, more than 255 leaves, over-long fields). Every
//! other check is the program's.

use timescales_auction::settlement::{AccountDelta, SettlementBatch};
use timescales_core::{Encode, Hash32, MarketParams};

use crate::program::governance::GovernanceChange;
use crate::program::merkle::Levels;
use crate::program::pda::{batch_pda, derive_market_id, market_pda, trader_pda};
use crate::program::{
    ClientError, ED25519_PROGRAM, INSTRUCTIONS_SYSVAR, Ix, Key, MAX_DELTAS, MAX_EXECUTORS, Meta,
    SLOT_HASHES_SYSVAR, SYSTEM_PROGRAM, TOKEN_PROGRAM,
};

mod tag {
    pub(super) const INIT_MARKET: u8 = 0;
    pub(super) const OPEN_TRADER: u8 = 1;
    pub(super) const DEPOSIT: u8 = 2;
    pub(super) const REQUEST_WITHDRAW: u8 = 3;
    pub(super) const WITHDRAW: u8 = 4;
    pub(super) const COMMIT_BATCH: u8 = 5;
    pub(super) const POST_RECEIPT: u8 = 6;
    pub(super) const VERIFY_DELTAS: u8 = 7;
    pub(super) const FINALIZE_VERIFICATION: u8 = 8;
    pub(super) const APPLY_DELTAS: u8 = 9;
    pub(super) const CLOSE_BATCH: u8 = 10;
    pub(super) const ABORT_BATCH: u8 = 11;
    pub(super) const REVEAL_BEACON: u8 = 12;
    pub(super) const COSIGN_RECEIPT: u8 = 13;
    pub(super) const CANCEL_WITHDRAW_REQUEST: u8 = 14;
    pub(super) const SET_HALTED: u8 = 15;
    pub(super) const PROPOSE_CHANGE: u8 = 16;
    pub(super) const APPLY_CHANGE: u8 = 17;
    pub(super) const CANCEL_CHANGE: u8 = 18;
    pub(super) const ACCEPT_ADMIN: u8 = 19;
    pub(super) const REMOVE_EXECUTOR: u8 = 20;
    pub(super) const CLAIM_FEES: u8 = 21;
    pub(super) const RECLAIM_BATCH: u8 = 22;
    pub(super) const CLOSE_TRADER: u8 = 23;
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    Base = 0,
    Quote = 1,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AbortReason {
    Admin = 1,
    Relay = 2,
    BeaconExpired = 3,
    ExecTimeout = 4,
    SettleTimeout = 5,
    QuorumTimeout = 6,
}

impl TryFrom<u8> for AbortReason {
    type Error = ClientError;

    fn try_from(v: u8) -> Result<Self, ClientError> {
        Ok(match v {
            1 => Self::Admin,
            2 => Self::Relay,
            3 => Self::BeaconExpired,
            4 => Self::ExecTimeout,
            5 => Self::SettleTimeout,
            6 => Self::QuorumTimeout,
            _ => return Err(ClientError::Malformed),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitMarketArgs {
    pub salt: [u8; 32],
    pub admin: Key,
    pub relay: Key,
    pub params: MarketParams,
    pub committee_digest: Hash32,
    pub beacon_delay_slots: u16,
    pub timelock_slots: u64,
    pub exec_timeout_slots: u64,
    pub settle_timeout_slots: u64,
    pub receipt_quorum: u8,
    pub executors: Vec<Key>,
}

/// One settlement leaf with its audit path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub index: u32,
    pub delta: AccountDelta,
    pub path: Vec<Hash32>,
}

fn ix(program: &Key, accounts: Vec<Meta>, data: Vec<u8>) -> Ix {
    Ix {
        program: *program,
        accounts,
        data,
    }
}

/// Tag 0. `market_id` is derived from `program`, `creator` and `a.salt`,
/// and the market PDA from the id.
pub fn init_market(
    program: &Key,
    creator: &Key,
    base_mint: &Key,
    quote_mint: &Key,
    base_vault: &Key,
    quote_vault: &Key,
    a: &InitMarketArgs,
) -> Result<Ix, ClientError> {
    if a.executors.len() > MAX_EXECUTORS {
        return Err(ClientError::TooManyExecutors);
    }
    let n = u8::try_from(a.executors.len()).map_err(|_| ClientError::TooManyExecutors)?;
    let market_id = derive_market_id(program, creator, &a.salt);
    let (market, _) = market_pda(program, market_id)?;
    let mut d = Vec::with_capacity(211 + 32 * a.executors.len());
    d.push(tag::INIT_MARKET);
    d.extend_from_slice(&market_id.to_le_bytes());
    d.extend_from_slice(&a.salt);
    d.extend_from_slice(&a.admin);
    d.extend_from_slice(&a.relay);
    a.params.encode(&mut d);
    d.extend_from_slice(a.committee_digest.as_bytes());
    d.extend_from_slice(&a.beacon_delay_slots.to_le_bytes());
    d.extend_from_slice(&a.timelock_slots.to_le_bytes());
    d.extend_from_slice(&a.exec_timeout_slots.to_le_bytes());
    d.extend_from_slice(&a.settle_timeout_slots.to_le_bytes());
    d.push(a.receipt_quorum);
    d.push(n);
    for e in &a.executors {
        d.extend_from_slice(e);
    }
    Ok(ix(
        program,
        vec![
            Meta::w(*creator, true),
            Meta::w(market, false),
            Meta::r(*base_mint, false),
            Meta::r(*quote_mint, false),
            Meta::r(*base_vault, false),
            Meta::r(*quote_vault, false),
            Meta::r(SYSTEM_PROGRAM, false),
        ],
        d,
    ))
}

/// Tag 1. The owner pays the Trader account's rent.
pub fn open_trader(program: &Key, owner: &Key, market: &Key) -> Result<Ix, ClientError> {
    Ok(ix(
        program,
        vec![
            Meta::w(*owner, true),
            Meta::r(*market, false),
            Meta::w(trader_pda(program, market, owner)?.0, false),
            Meta::r(SYSTEM_PROGRAM, false),
        ],
        vec![tag::OPEN_TRADER],
    ))
}

/// Tag 2. `vault` must be the market's vault for `side`.
pub fn deposit(
    program: &Key,
    owner: &Key,
    market: &Key,
    source: &Key,
    vault: &Key,
    side: Side,
    amount: u64,
) -> Result<Ix, ClientError> {
    let mut d = vec![tag::DEPOSIT, side as u8];
    d.extend_from_slice(&amount.to_le_bytes());
    Ok(ix(
        program,
        vec![
            Meta::r(*owner, true),
            Meta::r(*market, false),
            Meta::w(trader_pda(program, market, owner)?.0, false),
            Meta::w(*source, false),
            Meta::w(*vault, false),
            Meta::r(TOKEN_PROGRAM, false),
        ],
        d,
    ))
}

/// The three-account trader instructions: owner, market, trader PDA.
fn owner_ix(program: &Key, owner: &Key, market: &Key, data: Vec<u8>) -> Result<Ix, ClientError> {
    Ok(ix(
        program,
        vec![
            Meta::r(*owner, true),
            Meta::r(*market, false),
            Meta::w(trader_pda(program, market, owner)?.0, false),
        ],
        data,
    ))
}

/// Tag 3. Reserves, does not debit.
pub fn request_withdraw(
    program: &Key,
    owner: &Key,
    market: &Key,
    base: u64,
    quote: u64,
) -> Result<Ix, ClientError> {
    let mut d = vec![tag::REQUEST_WITHDRAW];
    d.extend_from_slice(&base.to_le_bytes());
    d.extend_from_slice(&quote.to_le_bytes());
    owner_ix(program, owner, market, d)
}

/// Tag 14.
pub fn cancel_withdraw_request(
    program: &Key,
    owner: &Key,
    market: &Key,
) -> Result<Ix, ClientError> {
    owner_ix(program, owner, market, vec![tag::CANCEL_WITHDRAW_REQUEST])
}

/// Tag 4. Pays `min(requested, balance)` of `side` from `vault` (the
/// market's vault for that side) to `dest`.
pub fn withdraw(
    program: &Key,
    owner: &Key,
    market: &Key,
    vault: &Key,
    dest: &Key,
    side: Side,
) -> Result<Ix, ClientError> {
    Ok(ix(
        program,
        vec![
            Meta::r(*owner, true),
            Meta::r(*market, false),
            Meta::w(trader_pda(program, market, owner)?.0, false),
            Meta::w(*vault, false),
            Meta::w(*dest, false),
            Meta::r(TOKEN_PROGRAM, false),
        ],
        vec![tag::WITHDRAW, side as u8],
    ))
}

/// Tag 23. The rent goes back to the owner.
pub fn close_trader(program: &Key, owner: &Key, market: &Key) -> Result<Ix, ClientError> {
    Ok(ix(
        program,
        vec![
            Meta::w(*owner, true),
            Meta::r(*market, false),
            Meta::w(trader_pda(program, market, owner)?.0, false),
        ],
        vec![tag::CLOSE_TRADER],
    ))
}

/// Tag 5. The relay signs and pays the Batch account's rent.
pub fn commit_batch(
    program: &Key,
    relay: &Key,
    market: &Key,
    epoch: u64,
    root: &Hash32,
    count: u32,
    terms: &Hash32,
) -> Result<Ix, ClientError> {
    let mut d = Vec::with_capacity(77);
    d.push(tag::COMMIT_BATCH);
    d.extend_from_slice(&epoch.to_le_bytes());
    d.extend_from_slice(root.as_bytes());
    d.extend_from_slice(&count.to_le_bytes());
    d.extend_from_slice(terms.as_bytes());
    Ok(ix(
        program,
        vec![
            Meta::w(*relay, true),
            Meta::w(*market, false),
            Meta::w(batch_pda(program, market, epoch)?.0, false),
            Meta::r(SYSTEM_PROGRAM, false),
        ],
        d,
    ))
}

/// Tag 12. Permissionless. Reads the SlotHashes sysvar.
pub fn reveal_beacon(
    program: &Key,
    cranker: &Key,
    market: &Key,
    epoch: u64,
) -> Result<Ix, ClientError> {
    Ok(ix(
        program,
        vec![
            Meta::r(*cranker, true),
            Meta::r(*market, false),
            Meta::w(batch_pda(program, market, epoch)?.0, false),
            Meta::r(SLOT_HASHES_SYSVAR, false),
        ],
        vec![tag::REVEAL_BEACON],
    ))
}

/// The Ed25519 precompile instruction verifying one signature over a
/// 32-byte message, everything inline (144 bytes of data, no accounts). It
/// must immediately precede `PostReceipt` (message = receipt digest) or
/// `CoSignReceipt` (message = cosign digest).
pub fn ed25519_verify(public: &Key, message: &Hash32, signature: &[u8; 64]) -> Ix {
    const PK: u16 = 16;
    const SIG: u16 = PK + 32;
    const MSG: u16 = SIG + 64;
    let mut d = Vec::with_capacity(144);
    d.extend_from_slice(&[1, 0]);
    for v in [SIG, u16::MAX, PK, u16::MAX, MSG, 32, u16::MAX] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(public);
    d.extend_from_slice(signature);
    d.extend_from_slice(message.as_bytes());
    ix(&ED25519_PROGRAM, vec![], d)
}

fn len_u16(b: &[u8], what: &'static str) -> Result<[u8; 2], ClientError> {
    Ok(u16::try_from(b.len())
        .map_err(|_| ClientError::InvalidArgument(what))?
        .to_le_bytes())
}

/// Tag 6: `6 || hl u16 || header || rl u16 || receipt`. The market is read-only.
pub fn post_receipt(
    program: &Key,
    cranker: &Key,
    market: &Key,
    epoch: u64,
    header: &[u8],
    receipt: &[u8],
) -> Result<Ix, ClientError> {
    let mut d = Vec::with_capacity(5 + header.len() + receipt.len());
    d.push(tag::POST_RECEIPT);
    d.extend_from_slice(&len_u16(header, "header longer than 65535 bytes")?);
    d.extend_from_slice(header);
    d.extend_from_slice(&len_u16(receipt, "receipt longer than 65535 bytes")?);
    d.extend_from_slice(receipt);
    Ok(ix(
        program,
        vec![
            Meta::r(*cranker, true),
            Meta::r(*market, false),
            Meta::w(batch_pda(program, market, epoch)?.0, false),
            Meta::r(INSTRUCTIONS_SYSVAR, false),
        ],
        d,
    ))
}

/// Tag 13. Any fee payer. The co-signer's signature is in the preceding
/// Ed25519 instruction.
pub fn cosign_receipt(
    program: &Key,
    cranker: &Key,
    market: &Key,
    epoch: u64,
) -> Result<Ix, ClientError> {
    Ok(ix(
        program,
        vec![
            Meta::r(*cranker, true),
            Meta::r(*market, false),
            Meta::w(batch_pda(program, market, epoch)?.0, false),
            Meta::r(INSTRUCTIONS_SYSVAR, false),
        ],
        vec![tag::COSIGN_RECEIPT],
    ))
}

/// Settlement leaves of `s` with their audit paths, in tree order. The tree
/// levels are built once for the whole batch, not once per proof.
pub fn leaves(s: &SettlementBatch) -> Result<Vec<Leaf>, ClientError> {
    if s.deltas.len() > MAX_DELTAS {
        return Err(ClientError::InvalidArgument(
            "more settlement deltas than a batch can verify",
        ));
    }
    let levels = Levels::over(s.deltas.iter().map(Encode::to_bytes));
    s.deltas
        .iter()
        .enumerate()
        .map(|(i, delta)| {
            Ok(Leaf {
                index: u32::try_from(i).map_err(|_| ClientError::Malformed)?,
                delta: *delta,
                path: levels.path(i),
            })
        })
        .collect()
}

/// `index u32 || trader32 || base i64 || quote i64 || p u8 || path32xp` per leaf.
pub(crate) fn encode_leaf(out: &mut Vec<u8>, leaf: &Leaf) -> Result<(), ClientError> {
    let p = u8::try_from(leaf.path.len())
        .map_err(|_| ClientError::InvalidArgument("audit path longer than 255 hashes"))?;
    out.extend_from_slice(&leaf.index.to_le_bytes());
    leaf.delta.encode(out);
    out.push(p);
    for h in &leaf.path {
        out.extend_from_slice(h.as_bytes());
    }
    Ok(())
}

fn delta_ix(
    tag: u8,
    program: &Key,
    cranker: &Key,
    market: &Key,
    epoch: u64,
    leaves: &[Leaf],
    trader: &mut dyn FnMut(&Key) -> Result<Key, ClientError>,
) -> Result<Ix, ClientError> {
    let n = u8::try_from(leaves.len()).map_err(|_| ClientError::TooManyLeaves)?;
    let mut d = vec![tag, n];
    let mut accounts = vec![
        Meta::r(*cranker, true),
        Meta::r(*market, false),
        Meta::w(batch_pda(program, market, epoch)?.0, false),
    ];
    for leaf in leaves {
        encode_leaf(&mut d, leaf)?;
        accounts.push(Meta::w(trader(&leaf.delta.trader.0)?, false));
    }
    Ok(ix(program, accounts, d))
}

/// Tag 7: `7 || n u8 || leaves`. The leaves' Trader PDAs follow the batch,
/// writable (verification records `last_leaf_epoch`). Size the chunks with
/// [`crate::program::plan_delta_chunks`].
pub fn verify_deltas(
    program: &Key,
    cranker: &Key,
    market: &Key,
    epoch: u64,
    leaves: &[Leaf],
) -> Result<Ix, ClientError> {
    verify_deltas_with(program, cranker, market, epoch, leaves, &mut |owner| {
        Ok(trader_pda(program, market, owner)?.0)
    })
}

/// [`verify_deltas`] with the Trader PDAs supplied by `trader`, for a caller
/// that derives each one once and settles many chunks.
pub fn verify_deltas_with(
    program: &Key,
    cranker: &Key,
    market: &Key,
    epoch: u64,
    leaves: &[Leaf],
    trader: &mut dyn FnMut(&Key) -> Result<Key, ClientError>,
) -> Result<Ix, ClientError> {
    delta_ix(
        tag::VERIFY_DELTAS,
        program,
        cranker,
        market,
        epoch,
        leaves,
        trader,
    )
}

/// Tag 9: same layout and accounts as [`verify_deltas`].
pub fn apply_deltas(
    program: &Key,
    cranker: &Key,
    market: &Key,
    epoch: u64,
    leaves: &[Leaf],
) -> Result<Ix, ClientError> {
    apply_deltas_with(program, cranker, market, epoch, leaves, &mut |owner| {
        Ok(trader_pda(program, market, owner)?.0)
    })
}

/// [`apply_deltas`] with the Trader PDAs supplied by `trader`.
pub fn apply_deltas_with(
    program: &Key,
    cranker: &Key,
    market: &Key,
    epoch: u64,
    leaves: &[Leaf],
    trader: &mut dyn FnMut(&Key) -> Result<Key, ClientError>,
) -> Result<Ix, ClientError> {
    delta_ix(
        tag::APPLY_DELTAS,
        program,
        cranker,
        market,
        epoch,
        leaves,
        trader,
    )
}

/// Signer, market, batch (writable). These builders take the batch address
/// instead of the epoch, so they cannot fail.
fn batch_ix(program: &Key, signer: &Key, market: Meta, batch: &Key, data: Vec<u8>) -> Ix {
    ix(
        program,
        vec![Meta::r(*signer, true), market, Meta::w(*batch, false)],
        data,
    )
}

/// Tag 8 (`FinalizeVerification`). The market is read-only.
pub fn finalize(program: &Key, cranker: &Key, market: &Key, batch: &Key) -> Ix {
    let market = Meta::r(*market, false);
    batch_ix(
        program,
        cranker,
        market,
        batch,
        vec![tag::FINALIZE_VERIFICATION],
    )
}

/// Tag 10.
pub fn close_batch(program: &Key, cranker: &Key, market: &Key, batch: &Key) -> Ix {
    let market = Meta::w(*market, false);
    batch_ix(program, cranker, market, batch, vec![tag::CLOSE_BATCH])
}

/// Tag 11: `11 || reason u8`. Who may sign depends on the reason.
pub fn abort_batch(
    program: &Key,
    market: &Key,
    batch: &Key,
    signer: &Key,
    reason: AbortReason,
) -> Ix {
    let market = Meta::w(*market, false);
    batch_ix(
        program,
        signer,
        market,
        batch,
        vec![tag::ABORT_BATCH, reason as u8],
    )
}

/// The governance instructions: signer, market (writable).
fn market_ix(program: &Key, signer: &Key, market: &Key, data: Vec<u8>) -> Ix {
    ix(
        program,
        vec![Meta::r(*signer, true), Meta::w(*market, false)],
        data,
    )
}

/// Tag 15: `15 || halted u8`. Immediate.
pub fn set_halted(program: &Key, admin: &Key, market: &Key, halted: bool) -> Ix {
    market_ix(
        program,
        admin,
        market,
        vec![tag::SET_HALTED, u8::from(halted)],
    )
}

/// Tag 16: `16 || kind u8 || len u16 || payload`.
pub fn propose_change(
    program: &Key,
    admin: &Key,
    market: &Key,
    c: &GovernanceChange,
) -> Result<Ix, ClientError> {
    let payload = c.payload()?;
    let mut d = vec![tag::PROPOSE_CHANGE, c.kind()];
    d.extend_from_slice(&len_u16(&payload, "payload longer than 65535 bytes")?);
    d.extend_from_slice(&payload);
    Ok(market_ix(program, admin, market, d))
}

/// Tag 17. Permissionless once the timelock has passed.
pub fn apply_change(program: &Key, cranker: &Key, market: &Key) -> Ix {
    market_ix(program, cranker, market, vec![tag::APPLY_CHANGE])
}

/// Tag 18.
pub fn cancel_change(program: &Key, admin: &Key, market: &Key) -> Ix {
    market_ix(program, admin, market, vec![tag::CANCEL_CHANGE])
}

/// Tag 19. Signed by the pending admin.
pub fn accept_admin(program: &Key, pending_admin: &Key, market: &Key) -> Ix {
    market_ix(program, pending_admin, market, vec![tag::ACCEPT_ADMIN])
}

/// Tag 20: `20 || key32`. Immediate.
pub fn remove_executor(program: &Key, admin: &Key, market: &Key, key: &Key) -> Ix {
    let mut d = vec![tag::REMOVE_EXECUTOR];
    d.extend_from_slice(key);
    market_ix(program, admin, market, d)
}

/// Tag 21: `21 || amount u64`, paid from the quote vault to `dest`.
pub fn claim_fees(
    program: &Key,
    admin: &Key,
    market: &Key,
    quote_vault: &Key,
    dest: &Key,
    amount: u64,
) -> Ix {
    let mut d = vec![tag::CLAIM_FEES];
    d.extend_from_slice(&amount.to_le_bytes());
    ix(
        program,
        vec![
            Meta::r(*admin, true),
            Meta::w(*market, false),
            Meta::w(*quote_vault, false),
            Meta::w(*dest, false),
            Meta::r(TOKEN_PROGRAM, false),
        ],
        d,
    )
}

/// Tag 22. The rent goes to `relay`, which must be the market's relay.
pub fn reclaim_batch(program: &Key, cranker: &Key, market: &Key, batch: &Key, relay: &Key) -> Ix {
    ix(
        program,
        vec![
            Meta::r(*cranker, true),
            Meta::r(*market, false),
            Meta::w(*batch, false),
            Meta::w(*relay, false),
        ],
        vec![tag::RECLAIM_BATCH],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_instruction_is_144_bytes_with_inline_offsets() {
        let ixn = ed25519_verify(&[1; 32], &Hash32([3; 32]), &[2; 64]);
        assert_eq!(ixn.program, ED25519_PROGRAM);
        assert!(ixn.accounts.is_empty());
        assert_eq!(ixn.data.len(), 144);
        assert_eq!(
            ixn.data[..16],
            [
                1, 0, 48, 0, 0xff, 0xff, 16, 0, 0xff, 0xff, 112, 0, 32, 0, 0xff, 0xff
            ]
        );
        assert_eq!(ixn.data[16..48], [1; 32]);
        assert_eq!(ixn.data[48..112], [2; 64]);
        assert_eq!(ixn.data[112..], [3; 32]);
    }

    #[test]
    fn abort_reasons_round_trip() {
        for v in 1..=6u8 {
            assert_eq!(AbortReason::try_from(v).unwrap() as u8, v);
        }
        assert!(AbortReason::try_from(0).is_err());
        assert!(AbortReason::try_from(7).is_err());
    }
}
