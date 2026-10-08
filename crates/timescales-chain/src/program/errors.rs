//! Program errors, `Custom(6000 + n)`, and the attribution of a
//! failed instruction to the program that actually failed. A failed CPI
//! into Token or System surfaces as the caller's `Custom(code)` with the
//! callee's code, so the failing program is read from the logs, not
//! inferred from the code.

use std::fmt;

use crate::program::{Key, SYSTEM_PROGRAM, TOKEN_PROGRAM, decode_base58};

/// Every program error is `Custom(ERROR_BASE + n)`.
pub const ERROR_BASE: u32 = 6000;

/// Codes that are allocated but never returned.
pub const RESERVED: &[(u32, &str)] = &[(6016, "Settling")];

macro_rules! program_errors {
    ($($name:ident = $code:literal,)*) => {
        /// Program error codes. 6001-6019 keep the v1 order. 6016 is
        /// reserved.
        #[repr(u32)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum TimescalesProgramError {
            $($name = $code,)*
        }

        impl TimescalesProgramError {
            /// Every error the program returns, by ascending code.
            pub const ALL: &'static [Self] = &[$(Self::$name,)*];

            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$name => stringify!($name),)*
                }
            }
        }
    };
}

program_errors! {
    InvalidInstruction = 6001,
    InvalidAccount = 6002,
    Unauthorised = 6003,
    OutOfOrder = 6004,
    HeaderMismatch = 6005,
    ReceiptMismatch = 6006,
    BadSignature = 6007,
    UnknownExecutor = 6008,
    BadProof = 6009,
    DuplicateLeaf = 6010,
    Insolvent = 6011,
    NotConserved = 6012,
    Incomplete = 6013,
    WrongStatus = 6014,
    TooManyDeltas = 6015,
    WithdrawLocked = 6017,
    Overflow = 6018,
    Halted = 6019,
    BeaconNotReady = 6020,
    BeaconExpired = 6021,
    InFlight = 6022,
    NotExpired = 6023,
    DuplicateTrader = 6024,
    ParamsMismatch = 6025,
    StateRootMismatch = 6026,
    UnsupportedVersion = 6027,
    TermsMismatch = 6028,
    InvalidParams = 6029,
    InvalidConfig = 6030,
    WithdrawPending = 6031,
    NothingToWithdraw = 6032,
    Timelocked = 6033,
    ChangePending = 6034,
    NoPendingChange = 6035,
    NotPendingAdmin = 6036,
    RetentionNotReached = 6037,
    BalanceCap = 6038,
    QuorumNotMet = 6039,
    AlreadyCosigned = 6040,
    BackendNotAllowed = 6041,
    InvalidBatchCount = 6042,
    AccountNotEmpty = 6043,
    InvalidTokenAccount = 6044,
    InvalidAbortReason = 6045,
    ChangeDue = 6046,
    InvalidMarketId = 6047,
}

impl TimescalesProgramError {
    pub const fn code(self) -> u32 {
        self as u32
    }

    pub fn from_code(code: u32) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.code() == code)
    }
}

impl fmt::Display for TimescalesProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.code())
    }
}

/// SPL Token `TokenError`, by code.
const TOKEN_ERRORS: [&str; 20] = [
    "NotRentExempt",
    "InsufficientFunds",
    "InvalidMint",
    "MintMismatch",
    "OwnerMismatch",
    "FixedSupply",
    "AlreadyInUse",
    "InvalidNumberOfProvidedSigners",
    "InvalidNumberOfRequiredSigners",
    "UninitializedState",
    "NativeNotSupported",
    "NonNativeHasBalance",
    "InvalidInstruction",
    "InvalidState",
    "Overflow",
    "AuthorityTypeNotSupported",
    "MintCannotFreeze",
    "AccountFrozen",
    "MintDecimalsMismatch",
    "NonNativeNotSupported",
];

/// System program `SystemError`, by code.
const SYSTEM_ERRORS: [&str; 9] = [
    "AccountAlreadyInUse",
    "ResultWithNegativeLamports",
    "InvalidProgramId",
    "InvalidAccountDataLength",
    "MaxSeedLengthExceeded",
    "AddressWithSeedMismatch",
    "NonceNoRecentBlockhashes",
    "NonceBlockhashNotExpired",
    "NonceUnexpectedBlockhashValue",
];

/// Which program a failing instruction failed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProgramKind {
    Settlement,
    Token,
    System,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramFailure {
    /// Index of the failing top-level instruction in the transaction.
    pub ix_index: u8,
    pub program: ProgramKind,
    pub code: u32,
    /// The error's name in the failing program's table, if known.
    pub name: Option<&'static str>,
    /// Set when the settlement program itself failed with a known code.
    pub error: Option<TimescalesProgramError>,
}

/// Name of a settlement program error code. `None` for reserved and
/// unknown codes.
pub fn name(code: u32) -> Option<&'static str> {
    TimescalesProgramError::from_code(code).map(TimescalesProgramError::name)
}

/// Attributes `InstructionError(ix_index, Custom(code))` of a transaction
/// to the failing program, given the settlement `program` id and the
/// transaction's logs.
///
/// The runtime logs `Program <id> failed: custom program error: 0x<code>`
/// for the failing program and then for each caller up the CPI stack, so
/// the first such line names the program that produced the code. Log lines
/// that a program writes itself start with `Program log:` or `Program
/// data:` and never parse as an address. When the logs carry no such line
/// (missing or truncated), a code from the settlement table is attributed
/// to the settlement program, the only one in Timescales transactions that
/// uses that range, and any other code to [`ProgramKind::Other`].
pub fn decode(ix_index: u8, program: &Key, code: u32, logs: &[String]) -> ProgramFailure {
    let known = TimescalesProgramError::from_code(code);
    let kind = match failing_program(logs, code) {
        Some(id) if id == *program => ProgramKind::Settlement,
        Some(id) if id == TOKEN_PROGRAM => ProgramKind::Token,
        Some(id) if id == SYSTEM_PROGRAM => ProgramKind::System,
        Some(_) => ProgramKind::Other,
        None if known.is_some() => ProgramKind::Settlement,
        None => ProgramKind::Other,
    };
    let table_name = |table: &[&'static str]| {
        usize::try_from(code)
            .ok()
            .and_then(|i| table.get(i))
            .copied()
    };
    let (name, error) = match kind {
        ProgramKind::Settlement => (known.map(TimescalesProgramError::name), known),
        ProgramKind::Token => (table_name(&TOKEN_ERRORS), None),
        ProgramKind::System => (table_name(&SYSTEM_ERRORS), None),
        ProgramKind::Other => (None, None),
    };
    ProgramFailure {
        ix_index,
        program: kind,
        code,
        name,
        error,
    }
}

fn failing_program(logs: &[String], code: u32) -> Option<Key> {
    let suffix = format!(" failed: custom program error: {code:#x}");
    logs.iter().find_map(|line| {
        let id = line
            .strip_prefix("Program ")?
            .strip_suffix(suffix.as_str())?;
        decode_base58(id)
    })
}
