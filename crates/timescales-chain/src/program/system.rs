//! System program instructions for bootstrap and tests: create an account
//! (a mint or a token account before the SPL instructions initialize it)
//! and transfer lamports.

use crate::program::{Ix, Key, Meta, SYSTEM_PROGRAM};

/// `CreateAccount` (`0 u32 || lamports u64 || space u64 || owner32`). Both the
/// payer and the new account sign.
pub fn create_account(payer: &Key, new: &Key, lamports: u64, space: u64, owner: &Key) -> Ix {
    let mut data = Vec::with_capacity(52);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner);
    Ix {
        program: SYSTEM_PROGRAM,
        accounts: vec![Meta::w(*payer, true), Meta::w(*new, true)],
        data,
    }
}

/// `Transfer` (`2 u32 || lamports u64`).
pub fn transfer(from: &Key, to: &Key, lamports: u64) -> Ix {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Ix {
        program: SYSTEM_PROGRAM,
        accounts: vec![Meta::w(*from, true), Meta::w(*to, false)],
        data,
    }
}
