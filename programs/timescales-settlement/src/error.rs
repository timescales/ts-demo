use solana_program::program_error::ProgramError;

/// First custom error code. Every error is `Custom(ERROR_BASE + n)` so that
/// codes never collide with SPL Token or System errors.
pub const ERROR_BASE: u32 = 6000;

/// Program errors. 6001-6019 keep the v1 order. 6016 is reserved
/// (it was `Settling`, which v2 no longer has).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TimescalesError {
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

/// Codes that are allocated but never returned.
pub const RESERVED: &[(u32, &str)] = &[(6016, "Settling")];

impl TimescalesError {
    pub const ALL: [TimescalesError; 46] = {
        use TimescalesError::*;
        [
            InvalidInstruction,
            InvalidAccount,
            Unauthorised,
            OutOfOrder,
            HeaderMismatch,
            ReceiptMismatch,
            BadSignature,
            UnknownExecutor,
            BadProof,
            DuplicateLeaf,
            Insolvent,
            NotConserved,
            Incomplete,
            WrongStatus,
            TooManyDeltas,
            WithdrawLocked,
            Overflow,
            Halted,
            BeaconNotReady,
            BeaconExpired,
            InFlight,
            NotExpired,
            DuplicateTrader,
            ParamsMismatch,
            StateRootMismatch,
            UnsupportedVersion,
            TermsMismatch,
            InvalidParams,
            InvalidConfig,
            WithdrawPending,
            NothingToWithdraw,
            Timelocked,
            ChangePending,
            NoPendingChange,
            NotPendingAdmin,
            RetentionNotReached,
            BalanceCap,
            QuorumNotMet,
            AlreadyCosigned,
            BackendNotAllowed,
            InvalidBatchCount,
            AccountNotEmpty,
            InvalidTokenAccount,
            InvalidAbortReason,
            ChangeDue,
            InvalidMarketId,
        ]
    };

    pub const fn code(self) -> u32 {
        self as u32
    }

    pub fn from_code(code: u32) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.code() == code)
    }

    pub const fn name(self) -> &'static str {
        use TimescalesError::*;
        match self {
            InvalidInstruction => "InvalidInstruction",
            InvalidAccount => "InvalidAccount",
            Unauthorised => "Unauthorised",
            OutOfOrder => "OutOfOrder",
            HeaderMismatch => "HeaderMismatch",
            ReceiptMismatch => "ReceiptMismatch",
            BadSignature => "BadSignature",
            UnknownExecutor => "UnknownExecutor",
            BadProof => "BadProof",
            DuplicateLeaf => "DuplicateLeaf",
            Insolvent => "Insolvent",
            NotConserved => "NotConserved",
            Incomplete => "Incomplete",
            WrongStatus => "WrongStatus",
            TooManyDeltas => "TooManyDeltas",
            WithdrawLocked => "WithdrawLocked",
            Overflow => "Overflow",
            Halted => "Halted",
            BeaconNotReady => "BeaconNotReady",
            BeaconExpired => "BeaconExpired",
            InFlight => "InFlight",
            NotExpired => "NotExpired",
            DuplicateTrader => "DuplicateTrader",
            ParamsMismatch => "ParamsMismatch",
            StateRootMismatch => "StateRootMismatch",
            UnsupportedVersion => "UnsupportedVersion",
            TermsMismatch => "TermsMismatch",
            InvalidParams => "InvalidParams",
            InvalidConfig => "InvalidConfig",
            WithdrawPending => "WithdrawPending",
            NothingToWithdraw => "NothingToWithdraw",
            Timelocked => "Timelocked",
            ChangePending => "ChangePending",
            NoPendingChange => "NoPendingChange",
            NotPendingAdmin => "NotPendingAdmin",
            RetentionNotReached => "RetentionNotReached",
            BalanceCap => "BalanceCap",
            QuorumNotMet => "QuorumNotMet",
            AlreadyCosigned => "AlreadyCosigned",
            BackendNotAllowed => "BackendNotAllowed",
            InvalidBatchCount => "InvalidBatchCount",
            AccountNotEmpty => "AccountNotEmpty",
            InvalidTokenAccount => "InvalidTokenAccount",
            InvalidAbortReason => "InvalidAbortReason",
            ChangeDue => "ChangeDue",
            InvalidMarketId => "InvalidMarketId",
        }
    }
}

impl From<TimescalesError> for ProgramError {
    fn from(e: TimescalesError) -> Self {
        ProgramError::Custom(e.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_ascending_and_skip_the_reserved_one() {
        let codes: Vec<u32> = TimescalesError::ALL.iter().map(|e| e.code()).collect();
        assert!(codes.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(codes.first(), Some(&(ERROR_BASE + 1)));
        assert_eq!(codes.last(), Some(&(ERROR_BASE + 47)));
        for (code, _) in RESERVED {
            assert!(!codes.contains(code));
        }
        assert_eq!(codes.len() + RESERVED.len(), 47);
    }

    #[test]
    fn names_round_trip() {
        for e in TimescalesError::ALL {
            assert_eq!(TimescalesError::from_code(e.code()), Some(e));
            assert_eq!(format!("{e:?}"), e.name());
        }
    }
}
