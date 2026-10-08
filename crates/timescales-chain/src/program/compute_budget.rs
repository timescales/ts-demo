//! Compute Budget program instructions. They must precede the Ed25519
//! instruction in a `PostReceipt` or `CoSignReceipt` transaction, because
//! the program introspects the instruction right before its own.

use crate::program::{COMPUTE_BUDGET_PROGRAM, Ix};

/// `SetComputeUnitLimit`: `2 || units u32`.
pub fn set_limit(units: u32) -> Ix {
    let mut data = vec![2];
    data.extend_from_slice(&units.to_le_bytes());
    Ix {
        program: COMPUTE_BUDGET_PROGRAM,
        accounts: vec![],
        data,
    }
}

/// `SetComputeUnitPrice`: `3 || micro_lamports u64` per compute unit.
pub fn set_price(micro_lamports: u64) -> Ix {
    let mut data = vec![3];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Ix {
        program: COMPUTE_BUDGET_PROGRAM,
        accounts: vec![],
        data,
    }
}
