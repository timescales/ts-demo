//! Instruction encoding: one tag byte followed by fixed-width
//! little-endian fields. Trailing bytes are rejected. The chain crate
//! builds exactly these bytes.

use solana_program::program_error::ProgramError;

use crate::constants::MAX_PATH;
use crate::error::TimescalesError;
use crate::state::{Cursor, MAX_PAYLOAD, PARAMS_LEN};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub index: u32,
    pub trader: [u8; 32],
    pub base: i64,
    pub quote: i64,
    pub path: Vec<[u8; 32]>,
}

impl Leaf {
    /// The settlement leaf as encoded off chain (`AccountDelta`).
    pub fn bytes(&self) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[..32].copy_from_slice(&self.trader);
        b[32..40].copy_from_slice(&self.base.to_le_bytes());
        b[40..].copy_from_slice(&self.quote.to_le_bytes());
        b
    }
}

/// `InitMarket` arguments, in wire order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitMarket {
    pub market_id: u64,
    pub salt: [u8; 32],
    pub admin: [u8; 32],
    pub relay: [u8; 32],
    pub params: [u8; PARAMS_LEN],
    pub committee_digest: [u8; 32],
    pub beacon_delay_slots: u16,
    pub timelock_slots: u64,
    pub exec_timeout_slots: u64,
    pub settle_timeout_slots: u64,
    pub receipt_quorum: u8,
    pub executors: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    InitMarket(Box<InitMarket>),
    OpenTrader,
    Deposit {
        quote: bool,
        amount: u64,
    },
    RequestWithdraw {
        base: u64,
        quote: u64,
    },
    Withdraw {
        quote: bool,
    },
    CommitBatch {
        epoch: u64,
        root: [u8; 32],
        count: u32,
        terms_digest: [u8; 32],
    },
    PostReceipt {
        header: Vec<u8>,
        receipt: Vec<u8>,
    },
    VerifyDeltas {
        leaves: Vec<Leaf>,
    },
    FinalizeVerification,
    ApplyDeltas {
        leaves: Vec<Leaf>,
    },
    CloseBatch,
    AbortBatch {
        reason: u8,
    },
    RevealBeacon,
    CoSignReceipt,
    CancelWithdrawRequest,
    SetHalted {
        halted: bool,
    },
    ProposeChange {
        kind: u8,
        payload: Vec<u8>,
    },
    ApplyChange,
    CancelChange,
    AcceptAdmin,
    RemoveExecutor {
        key: [u8; 32],
    },
    ClaimFees {
        amount: u64,
    },
    ReclaimBatch,
    CloseTrader,
}

fn leaves(c: &mut Cursor<'_>) -> Result<Vec<Leaf>, ProgramError> {
    let n = c.u8()?;
    let mut out = Vec::with_capacity(usize::from(n));
    for _ in 0..n {
        let index = c.u32()?;
        let trader = c.key()?;
        let base = c.i64()?;
        let quote = c.i64()?;
        let len = usize::from(c.u8()?);
        if len > MAX_PATH {
            return Err(TimescalesError::InvalidInstruction.into());
        }
        let mut path = Vec::with_capacity(len);
        for _ in 0..len {
            path.push(c.key()?);
        }
        out.push(Leaf {
            index,
            trader,
            base,
            quote,
            path,
        });
    }
    Ok(out)
}

fn init_market(c: &mut Cursor<'_>) -> Result<InitMarket, ProgramError> {
    let market_id = c.u64()?;
    let salt = c.key()?;
    let admin = c.key()?;
    let relay = c.key()?;
    let mut params = [0u8; PARAMS_LEN];
    params.copy_from_slice(c.take(PARAMS_LEN)?);
    let committee_digest = c.key()?;
    let beacon_delay_slots = c.u16()?;
    let timelock_slots = c.u64()?;
    let exec_timeout_slots = c.u64()?;
    let settle_timeout_slots = c.u64()?;
    let receipt_quorum = c.u8()?;
    // The count is bounded by the processor (`InvalidConfig`), not here.
    let n = usize::from(c.u8()?);
    let mut executors = Vec::with_capacity(n);
    for _ in 0..n {
        executors.push(c.key()?);
    }
    Ok(InitMarket {
        market_id,
        salt,
        admin,
        relay,
        params,
        committee_digest,
        beacon_delay_slots,
        timelock_slots,
        exec_timeout_slots,
        settle_timeout_slots,
        receipt_quorum,
        executors,
    })
}

impl Instruction {
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let mut c = Cursor::new(data);
        let ix = match c.u8()? {
            0 => Instruction::InitMarket(Box::new(init_market(&mut c)?)),
            1 => Instruction::OpenTrader,
            2 => Instruction::Deposit {
                quote: c.flag()?,
                amount: c.u64()?,
            },
            3 => Instruction::RequestWithdraw {
                base: c.u64()?,
                quote: c.u64()?,
            },
            4 => Instruction::Withdraw { quote: c.flag()? },
            5 => Instruction::CommitBatch {
                epoch: c.u64()?,
                root: c.key()?,
                count: c.u32()?,
                terms_digest: c.key()?,
            },
            6 => {
                let hl = usize::from(c.u16()?);
                let header = c.take(hl)?.to_vec();
                let rl = usize::from(c.u16()?);
                let receipt = c.take(rl)?.to_vec();
                Instruction::PostReceipt { header, receipt }
            }
            7 => Instruction::VerifyDeltas {
                leaves: leaves(&mut c)?,
            },
            8 => Instruction::FinalizeVerification,
            9 => Instruction::ApplyDeltas {
                leaves: leaves(&mut c)?,
            },
            10 => Instruction::CloseBatch,
            11 => Instruction::AbortBatch { reason: c.u8()? },
            12 => Instruction::RevealBeacon,
            13 => Instruction::CoSignReceipt,
            14 => Instruction::CancelWithdrawRequest,
            15 => Instruction::SetHalted { halted: c.flag()? },
            16 => {
                let kind = c.u8()?;
                let len = usize::from(c.u16()?);
                if len > MAX_PAYLOAD {
                    return Err(TimescalesError::InvalidInstruction.into());
                }
                Instruction::ProposeChange {
                    kind,
                    payload: c.take(len)?.to_vec(),
                }
            }
            17 => Instruction::ApplyChange,
            18 => Instruction::CancelChange,
            19 => Instruction::AcceptAdmin,
            20 => Instruction::RemoveExecutor { key: c.key()? },
            21 => Instruction::ClaimFees { amount: c.u64()? },
            22 => Instruction::ReclaimBatch,
            23 => Instruction::CloseTrader,
            _ => return Err(TimescalesError::InvalidInstruction.into()),
        };
        if !c.is_empty() {
            return Err(TimescalesError::InvalidInstruction.into());
        }
        Ok(ix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(data: &[u8]) -> ProgramError {
        Instruction::unpack(data).unwrap_err()
    }

    #[test]
    fn flag_bytes_are_strict() {
        let invalid: ProgramError = TimescalesError::InvalidInstruction.into();
        assert_eq!(err(&[4, 2]), invalid);
        assert_eq!(err(&[15, 0xff]), invalid);
        let mut deposit = vec![2, 2];
        deposit.extend_from_slice(&5u64.to_le_bytes());
        assert_eq!(err(&deposit), invalid);
        assert_eq!(
            Instruction::unpack(&[4, 1]).unwrap(),
            Instruction::Withdraw { quote: true }
        );
    }

    #[test]
    fn trailing_bytes_and_unknown_tags_are_refused() {
        let invalid: ProgramError = TimescalesError::InvalidInstruction.into();
        assert_eq!(err(&[8, 0]), invalid);
        assert_eq!(err(&[24]), invalid);
        assert_eq!(err(&[]), invalid);
    }

    #[test]
    fn init_market_is_211_plus_32n_bytes() {
        let mut d = vec![0u8];
        d.extend_from_slice(&[0u8; 8 + 32 * 3 + 46 + 32 + 2 + 24 + 1]);
        d.push(2);
        d.extend_from_slice(&[7u8; 64]);
        assert_eq!(d.len(), 211 + 64);
        match Instruction::unpack(&d).unwrap() {
            Instruction::InitMarket(a) => assert_eq!(a.executors, vec![[7u8; 32]; 2]),
            other => panic!("{other:?}"),
        }
    }
}
