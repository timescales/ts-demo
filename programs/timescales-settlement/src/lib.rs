//! Timescales settlement program, v2 (the design).
//!
//! Holds traders' assets, records one batch per epoch, fixes a beacon after
//! the batch root, accepts an executor-signed receipt that a quorum of
//! registered executors co-signs, and applies the receipt's balance deltas
//! only after checking that they conserve both assets and keep every
//! account solvent.
//!
//! Lifecycle of epoch `e` (one batch in flight per market):
//!
//! ```text
//! CommitBatch(e, root, count, terms)  relay, last_committed == last_settled == e - 1
//! RevealBeacon                        anyone, SlotHashes at commit_slot + d and + 2d
//! PostReceipt(header, receipt)        poster's Ed25519 signature via the precompile
//! CoSignReceipt*                      one per further executor of the quorum
//! VerifyDeltas(leaves..)*             quorum met, Merkle proofs, solvency net of
//!                                     reserved withdrawals, running sums
//! FinalizeVerification                all leaves seen, conserved, quorum met
//! ApplyDeltas(leaves..)*              balances move
//! CloseBatch                          last_settled = e, state root and receipt chain
//! AbortBatch(reason)                  admin, relay (before the beacon inputs exist),
//!                                     or anyone after a deadline of this batch
//! ```
//!
//! Withdrawals reserve rather than debit and pay out once the batch in
//! flight at request time is terminal, so a request never breaks a batch
//! and an apply after verification cannot fail.
//!
//! Every hash matches the off-chain protocol: domain
//! separated SHA-256 and RFC 6962 shaped Merkle trees.

#![allow(unexpected_cfgs)]

pub mod beacon;
pub mod constants;
pub mod cpi;
pub mod error;
pub mod governance;
pub mod instruction;
pub mod merkle;
pub mod processor;
pub mod state;

use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};

solana_program::declare_id!("FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL");

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint_no_alloc!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    processor::process(program_id, accounts, data)
}
