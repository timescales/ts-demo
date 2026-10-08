//! Error codes and RFC 9457 problem documents.

use std::fmt;

use crate::wire::RelayRefusal;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use timescales_core::DecodeError;

use crate::api::{B58, B64, PauseReason, PublicPhase, U64};

/// Prefix of every problem `type`: `urn:timescales:error:<code lowercase>`.
pub const PROBLEM_TYPE_PREFIX: &str = "urn:timescales:error:";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    BadRequest,
    DecodeFailed,
    UnsupportedMediaType,
    BodyTooLarge,
    VersionUnsupported,
    WrongMarket,
    MaskedNotSupported,
    BadSignature,
    Skew,
    SessionUnknown,
    SessionExpired,
    SessionRevoked,
    SessionTemplateInvalid,
    SessionDomainMismatch,
    SessionNonceInvalid,
    SessionMethodRefused,
    WalletNotEligible,
    MarketHalted,
    MarketUnknown,
    NotFound,
    NotYetAvailable,
    Pruned,
    EpochClosed,
    EpochTooFar,
    DuplicateCommitment,
    BatchFull,
    QuotaExceeded,
    RateLimited,
    EpochKeyUnavailable,
    IntakePaused,
    MarketUnavailable,
    Overloaded,
    Draining,
    Internal,
}

/// The "Retryable" column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetryPolicy {
    No,
    Yes,
    /// Retry in the next epoch.
    NextEpoch,
    /// The per-wallet quota frees up only after the next epoch.
    AfterNextEpoch,
}

impl ErrorCode {
    /// Every code, in the order.
    pub const ALL: [ErrorCode; 34] = [
        ErrorCode::BadRequest,
        ErrorCode::DecodeFailed,
        ErrorCode::UnsupportedMediaType,
        ErrorCode::BodyTooLarge,
        ErrorCode::VersionUnsupported,
        ErrorCode::WrongMarket,
        ErrorCode::MaskedNotSupported,
        ErrorCode::BadSignature,
        ErrorCode::Skew,
        ErrorCode::SessionUnknown,
        ErrorCode::SessionExpired,
        ErrorCode::SessionRevoked,
        ErrorCode::SessionTemplateInvalid,
        ErrorCode::SessionDomainMismatch,
        ErrorCode::SessionNonceInvalid,
        ErrorCode::SessionMethodRefused,
        ErrorCode::WalletNotEligible,
        ErrorCode::MarketHalted,
        ErrorCode::MarketUnknown,
        ErrorCode::NotFound,
        ErrorCode::NotYetAvailable,
        ErrorCode::Pruned,
        ErrorCode::EpochClosed,
        ErrorCode::EpochTooFar,
        ErrorCode::DuplicateCommitment,
        ErrorCode::BatchFull,
        ErrorCode::QuotaExceeded,
        ErrorCode::RateLimited,
        ErrorCode::EpochKeyUnavailable,
        ErrorCode::IntakePaused,
        ErrorCode::MarketUnavailable,
        ErrorCode::Overloaded,
        ErrorCode::Draining,
        ErrorCode::Internal,
    ];

    /// The JSON name, e.g. `"EPOCH_CLOSED"`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "BAD_REQUEST",
            ErrorCode::DecodeFailed => "DECODE_FAILED",
            ErrorCode::UnsupportedMediaType => "UNSUPPORTED_MEDIA_TYPE",
            ErrorCode::BodyTooLarge => "BODY_TOO_LARGE",
            ErrorCode::VersionUnsupported => "VERSION_UNSUPPORTED",
            ErrorCode::WrongMarket => "WRONG_MARKET",
            ErrorCode::MaskedNotSupported => "MASKED_NOT_SUPPORTED",
            ErrorCode::BadSignature => "BAD_SIGNATURE",
            ErrorCode::Skew => "SKEW",
            ErrorCode::SessionUnknown => "SESSION_UNKNOWN",
            ErrorCode::SessionExpired => "SESSION_EXPIRED",
            ErrorCode::SessionRevoked => "SESSION_REVOKED",
            ErrorCode::SessionTemplateInvalid => "SESSION_TEMPLATE_INVALID",
            ErrorCode::SessionDomainMismatch => "SESSION_DOMAIN_MISMATCH",
            ErrorCode::SessionNonceInvalid => "SESSION_NONCE_INVALID",
            ErrorCode::SessionMethodRefused => "SESSION_METHOD_REFUSED",
            ErrorCode::WalletNotEligible => "WALLET_NOT_ELIGIBLE",
            ErrorCode::MarketHalted => "MARKET_HALTED",
            ErrorCode::MarketUnknown => "MARKET_UNKNOWN",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::NotYetAvailable => "NOT_YET_AVAILABLE",
            ErrorCode::Pruned => "PRUNED",
            ErrorCode::EpochClosed => "EPOCH_CLOSED",
            ErrorCode::EpochTooFar => "EPOCH_TOO_FAR",
            ErrorCode::DuplicateCommitment => "DUPLICATE_COMMITMENT",
            ErrorCode::BatchFull => "BATCH_FULL",
            ErrorCode::QuotaExceeded => "QUOTA_EXCEEDED",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::EpochKeyUnavailable => "EPOCH_KEY_UNAVAILABLE",
            ErrorCode::IntakePaused => "INTAKE_PAUSED",
            ErrorCode::MarketUnavailable => "MARKET_UNAVAILABLE",
            ErrorCode::Overloaded => "OVERLOADED",
            ErrorCode::Draining => "DRAINING",
            ErrorCode::Internal => "INTERNAL",
        }
    }

    /// HTTP status of the code.
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::BadRequest
            | ErrorCode::DecodeFailed
            | ErrorCode::VersionUnsupported
            | ErrorCode::WrongMarket
            | ErrorCode::MaskedNotSupported
            | ErrorCode::SessionTemplateInvalid
            | ErrorCode::SessionDomainMismatch
            | ErrorCode::SessionNonceInvalid
            | ErrorCode::SessionMethodRefused => 400,
            ErrorCode::BadSignature
            | ErrorCode::Skew
            | ErrorCode::SessionUnknown
            | ErrorCode::SessionExpired
            | ErrorCode::SessionRevoked => 401,
            ErrorCode::WalletNotEligible | ErrorCode::MarketHalted => 403,
            ErrorCode::MarketUnknown | ErrorCode::NotFound | ErrorCode::NotYetAvailable => 404,
            ErrorCode::EpochClosed
            | ErrorCode::EpochTooFar
            | ErrorCode::DuplicateCommitment
            | ErrorCode::BatchFull => 409,
            ErrorCode::Pruned => 410,
            ErrorCode::BodyTooLarge => 413,
            ErrorCode::UnsupportedMediaType => 415,
            ErrorCode::QuotaExceeded | ErrorCode::RateLimited => 429,
            ErrorCode::Internal => 500,
            ErrorCode::EpochKeyUnavailable
            | ErrorCode::IntakePaused
            | ErrorCode::MarketUnavailable
            | ErrorCode::Overloaded
            | ErrorCode::Draining => 503,
        }
    }

    /// When a request that failed with this code may succeed if repeated.
    pub fn retry_policy(self) -> RetryPolicy {
        match self {
            ErrorCode::Skew
            | ErrorCode::NotYetAvailable
            | ErrorCode::RateLimited
            | ErrorCode::EpochKeyUnavailable
            | ErrorCode::IntakePaused
            | ErrorCode::MarketUnavailable
            | ErrorCode::Overloaded
            | ErrorCode::Draining
            | ErrorCode::Internal => RetryPolicy::Yes,
            ErrorCode::EpochClosed | ErrorCode::BatchFull => RetryPolicy::NextEpoch,
            ErrorCode::QuotaExceeded => RetryPolicy::AfterNextEpoch,
            ErrorCode::BadRequest
            | ErrorCode::DecodeFailed
            | ErrorCode::UnsupportedMediaType
            | ErrorCode::BodyTooLarge
            | ErrorCode::VersionUnsupported
            | ErrorCode::WrongMarket
            | ErrorCode::MaskedNotSupported
            | ErrorCode::BadSignature
            | ErrorCode::SessionUnknown
            | ErrorCode::SessionExpired
            | ErrorCode::SessionRevoked
            | ErrorCode::SessionTemplateInvalid
            | ErrorCode::SessionDomainMismatch
            | ErrorCode::SessionNonceInvalid
            | ErrorCode::SessionMethodRefused
            | ErrorCode::WalletNotEligible
            | ErrorCode::MarketHalted
            | ErrorCode::MarketUnknown
            | ErrorCode::NotFound
            | ErrorCode::Pruned
            | ErrorCode::EpochTooFar
            | ErrorCode::DuplicateCommitment => RetryPolicy::No,
        }
    }

    /// The `retryable` flag of a problem with this code.
    pub fn retryable(self) -> bool {
        self.retry_policy() != RetryPolicy::No
    }

    /// Short human-readable summary, the problem `title`.
    pub fn title(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "Bad request",
            ErrorCode::DecodeFailed => "Canonical decoding failed",
            ErrorCode::UnsupportedMediaType => "Unsupported media type",
            ErrorCode::BodyTooLarge => "Request body too large",
            ErrorCode::VersionUnsupported => "Unsupported version",
            ErrorCode::WrongMarket => "Envelope is for another market",
            ErrorCode::MaskedNotSupported => "Masked submissions are not supported",
            ErrorCode::BadSignature => "Invalid signature",
            ErrorCode::Skew => "Request time outside the allowed skew",
            ErrorCode::SessionUnknown => "Unknown session",
            ErrorCode::SessionExpired => "Session expired",
            ErrorCode::SessionRevoked => "Session revoked",
            ErrorCode::SessionTemplateInvalid => "Session grant text is invalid",
            ErrorCode::SessionDomainMismatch => "Session grant names another domain",
            ErrorCode::SessionNonceInvalid => "Session nonce is invalid",
            ErrorCode::SessionMethodRefused => "Sign-message grants are refused",
            ErrorCode::WalletNotEligible => "Wallet not eligible",
            ErrorCode::MarketHalted => "Market halted",
            ErrorCode::MarketUnknown => "Unknown market",
            ErrorCode::NotFound => "Not found",
            ErrorCode::NotYetAvailable => "Not yet available",
            ErrorCode::Pruned => "Beyond retention",
            ErrorCode::EpochClosed => "Epoch closed",
            ErrorCode::EpochTooFar => "Epoch beyond the park window",
            ErrorCode::DuplicateCommitment => "Duplicate commitment",
            ErrorCode::BatchFull => "Batch full",
            ErrorCode::QuotaExceeded => "Quota exceeded",
            ErrorCode::RateLimited => "Rate limited",
            ErrorCode::EpochKeyUnavailable => "Epoch key unavailable",
            ErrorCode::IntakePaused => "Intake paused",
            ErrorCode::MarketUnavailable => "Market unavailable",
            ErrorCode::Overloaded => "Overloaded",
            ErrorCode::Draining => "Draining",
            ErrorCode::Internal => "Internal error",
        }
    }

    /// `urn:timescales:error:<code lowercase>`.
    pub fn type_uri(self) -> String {
        format!(
            "{PROBLEM_TYPE_PREFIX}{}",
            self.as_str().to_ascii_lowercase()
        )
    }

    /// The `code` byte of the relay-signed `RelayRefusal` (#16c) that
    /// accompanies this error: only the four refusals of an otherwise valid
    /// submission have one. The numbering is the wire crate's, with 0
    /// reserved.
    pub fn refusal_code(self) -> Option<u8> {
        match self {
            ErrorCode::BatchFull => Some(RelayRefusal::BATCH_FULL),
            ErrorCode::IntakePaused => Some(RelayRefusal::INTAKE_PAUSED),
            ErrorCode::QuotaExceeded => Some(RelayRefusal::QUOTA_EXCEEDED),
            ErrorCode::EpochClosed => Some(RelayRefusal::EPOCH_CLOSED),
            _ => None,
        }
    }

    /// The error a `RelayRefusal` with this `code` byte reports.
    pub fn from_refusal_code(code: u8) -> Option<ErrorCode> {
        ErrorCode::ALL
            .into_iter()
            .find(|c| c.refusal_code() == Some(code))
    }

    /// The `details` schema of problems with this code, if they carry any.
    pub fn details_schema(self) -> Option<&'static str> {
        match self {
            ErrorCode::BadRequest => Some("BadRequestDetails"),
            ErrorCode::DecodeFailed => Some("DecodeFailedDetails"),
            ErrorCode::WalletNotEligible => Some("WalletNotEligibleDetails"),
            ErrorCode::NotYetAvailable => Some("NotYetAvailableDetails"),
            ErrorCode::EpochClosed => Some("EpochClosedDetails"),
            ErrorCode::DuplicateCommitment => Some("DuplicateCommitmentDetails"),
            ErrorCode::BatchFull => Some("BatchFullDetails"),
            ErrorCode::QuotaExceeded => Some("QuotaExceededDetails"),
            ErrorCode::RateLimited => Some("RateLimitedDetails"),
            ErrorCode::IntakePaused => Some("IntakePausedDetails"),
            _ => None,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `application/problem+json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Problem {
    /// `urn:timescales:error:<code lowercase>`.
    #[serde(rename = "type")]
    pub type_: String,
    pub title: String,
    pub status: u16,
    pub code: ErrorCode,
    pub detail: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<u32>")]
    pub retry_after_ms: Option<u64>,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market: Option<B58>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<U64>,
    /// Code-specific details: the `*Details` definition named by the code
    /// in `errors.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Map<String, serde_json::Value>>")]
    pub details: Option<serde_json::Value>,
}

impl Problem {
    /// A problem with the type, title, status and retryable flag of `code`.
    pub fn new(code: ErrorCode, detail: impl Into<String>, request_id: impl Into<String>) -> Self {
        Problem {
            type_: code.type_uri(),
            title: code.title().to_owned(),
            status: code.http_status(),
            code,
            detail: detail.into(),
            retryable: code.retryable(),
            retry_after_ms: None,
            request_id: request_id.into(),
            market: None,
            epoch: None,
            details: None,
        }
    }

    /// A problem whose code is the one `details` belong to.
    pub fn from_details(
        details: ProblemDetails,
        detail: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        let mut p = Problem::new(details.code(), detail, request_id);
        p.details = Some(details.to_value());
        p
    }

    pub fn with_market(mut self, market: B58) -> Self {
        self.market = Some(market);
        self
    }

    pub fn with_epoch(mut self, epoch: u64) -> Self {
        self.epoch = Some(U64(epoch));
        self
    }

    pub fn with_retry_after_ms(mut self, ms: u64) -> Self {
        self.retry_after_ms = Some(ms);
        self
    }

    /// The details as the typed shape of this problem's code. `Ok(None)`
    /// when the problem has none or its code defines none.
    pub fn parsed_details(&self) -> Result<Option<ProblemDetails>, serde_json::Error> {
        let Some(v) = &self.details else {
            return Ok(None);
        };
        let v = v.clone();
        Ok(Some(match self.code {
            ErrorCode::BadRequest => ProblemDetails::BadRequest(serde_json::from_value(v)?),
            ErrorCode::DecodeFailed => ProblemDetails::DecodeFailed(serde_json::from_value(v)?),
            ErrorCode::WalletNotEligible => {
                ProblemDetails::WalletNotEligible(serde_json::from_value(v)?)
            }
            ErrorCode::NotYetAvailable => {
                ProblemDetails::NotYetAvailable(serde_json::from_value(v)?)
            }
            ErrorCode::EpochClosed => ProblemDetails::EpochClosed(serde_json::from_value(v)?),
            ErrorCode::DuplicateCommitment => {
                ProblemDetails::DuplicateCommitment(serde_json::from_value(v)?)
            }
            ErrorCode::BatchFull => ProblemDetails::BatchFull(serde_json::from_value(v)?),
            ErrorCode::QuotaExceeded => ProblemDetails::QuotaExceeded(serde_json::from_value(v)?),
            ErrorCode::RateLimited => ProblemDetails::RateLimited(serde_json::from_value(v)?),
            ErrorCode::IntakePaused => ProblemDetails::IntakePaused(serde_json::from_value(v)?),
            _ => return Ok(None),
        }))
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Problem {}

/// `details` of `BAD_REQUEST`: the offending field, query parameter or
/// path segment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BadRequestDetails {
    pub field: String,
}

/// Which canonical decoding rule failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DecodeReason {
    Eof,
    Tag,
    Length,
    Trailing,
    Value,
}

impl From<&DecodeError> for DecodeReason {
    fn from(e: &DecodeError) -> Self {
        match e {
            DecodeError::UnexpectedEof { .. } => DecodeReason::Eof,
            DecodeError::InvalidTag { .. } => DecodeReason::Tag,
            DecodeError::LengthExceeded { .. } => DecodeReason::Length,
            DecodeError::TrailingBytes(_) => DecodeReason::Trailing,
            DecodeError::InvalidValue(_) => DecodeReason::Value,
        }
    }
}

/// `details` of `DECODE_FAILED`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DecodeFailedDetails {
    pub reason: DecodeReason,
}

/// `details` of `WALLET_NOT_ELIGIBLE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum WalletNotEligibleDetails {
    NoTraderAccount,
    InsufficientAvailable { min_available_value_quote: U64 },
    Banned { until_epoch: U64 },
}

/// `details` of `NOT_YET_AVAILABLE`: the phase after which the resource
/// exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NotYetAvailableDetails {
    pub available_after: PublicPhase,
}

/// `details` of `EPOCH_CLOSED`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EpochClosedDetails {
    pub next_epoch: U64,
    pub next_opens_at_ms: u64,
    /// Relay-signed `RelayRefusal`.
    pub refusal_b64: B64,
}

/// `details` of `DUPLICATE_COMMITMENT`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DuplicateCommitmentDetails {
    /// The original `InclusionPromiseV2` for this (commitment, wallet).
    pub promise_b64: B64,
}

/// `details` of `BATCH_FULL`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BatchFullDetails {
    /// Present when the per-wallet fair share applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fair_share: Option<u32>,
    /// Relay-signed `RelayRefusal`.
    pub refusal_b64: B64,
}

/// `details` of `QUOTA_EXCEEDED`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuotaExceededDetails {
    /// Relay-signed `RelayRefusal`.
    pub refusal_b64: B64,
}

/// What a rate limit was keyed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    Ip,
    Session,
    Wallet,
}

/// `details` of `RATE_LIMITED`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RateLimitedDetails {
    pub scope: RateLimitScope,
}

/// `details` of `INTAKE_PAUSED`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IntakePausedDetails {
    pub reason: PauseReason,
    /// Relay-signed `RelayRefusal`.
    pub refusal_b64: B64,
}

/// The `details` payloads, one variant per code that has any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProblemDetails {
    BadRequest(BadRequestDetails),
    DecodeFailed(DecodeFailedDetails),
    WalletNotEligible(WalletNotEligibleDetails),
    NotYetAvailable(NotYetAvailableDetails),
    EpochClosed(EpochClosedDetails),
    DuplicateCommitment(DuplicateCommitmentDetails),
    BatchFull(BatchFullDetails),
    QuotaExceeded(QuotaExceededDetails),
    RateLimited(RateLimitedDetails),
    IntakePaused(IntakePausedDetails),
}

impl ProblemDetails {
    pub fn code(&self) -> ErrorCode {
        match self {
            ProblemDetails::BadRequest(_) => ErrorCode::BadRequest,
            ProblemDetails::DecodeFailed(_) => ErrorCode::DecodeFailed,
            ProblemDetails::WalletNotEligible(_) => ErrorCode::WalletNotEligible,
            ProblemDetails::NotYetAvailable(_) => ErrorCode::NotYetAvailable,
            ProblemDetails::EpochClosed(_) => ErrorCode::EpochClosed,
            ProblemDetails::DuplicateCommitment(_) => ErrorCode::DuplicateCommitment,
            ProblemDetails::BatchFull(_) => ErrorCode::BatchFull,
            ProblemDetails::QuotaExceeded(_) => ErrorCode::QuotaExceeded,
            ProblemDetails::RateLimited(_) => ErrorCode::RateLimited,
            ProblemDetails::IntakePaused(_) => ErrorCode::IntakePaused,
        }
    }

    /// The relay-signed refusal the details carry, for the four refusals of
    /// an otherwise valid submission.
    pub fn refusal(&self) -> Option<&B64> {
        match self {
            ProblemDetails::EpochClosed(d) => Some(&d.refusal_b64),
            ProblemDetails::BatchFull(d) => Some(&d.refusal_b64),
            ProblemDetails::QuotaExceeded(d) => Some(&d.refusal_b64),
            ProblemDetails::IntakePaused(d) => Some(&d.refusal_b64),
            _ => None,
        }
    }

    pub fn to_value(&self) -> serde_json::Value {
        let v = match self {
            ProblemDetails::BadRequest(d) => serde_json::to_value(d),
            ProblemDetails::DecodeFailed(d) => serde_json::to_value(d),
            ProblemDetails::WalletNotEligible(d) => serde_json::to_value(d),
            ProblemDetails::NotYetAvailable(d) => serde_json::to_value(d),
            ProblemDetails::EpochClosed(d) => serde_json::to_value(d),
            ProblemDetails::DuplicateCommitment(d) => serde_json::to_value(d),
            ProblemDetails::BatchFull(d) => serde_json::to_value(d),
            ProblemDetails::QuotaExceeded(d) => serde_json::to_value(d),
            ProblemDetails::RateLimited(d) => serde_json::to_value(d),
            ProblemDetails::IntakePaused(d) => serde_json::to_value(d),
        };
        // Plain structs of strings, numbers and enums: serializing them into
        // a `Value` cannot fail.
        v.expect("problem details serialize to JSON")
    }
}

impl From<&DecodeError> for ProblemDetails {
    fn from(e: &DecodeError) -> Self {
        ProblemDetails::DecodeFailed(DecodeFailedDetails { reason: e.into() })
    }
}
