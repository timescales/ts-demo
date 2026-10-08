//! Public API of `timescales-node` (`/v1`): request and response DTOs
//! with their wire field names, the stream events and frames, error codes
//! and `Problem`, and the JSON Schema export.
//!
//! Encodings: every protocol u64 is a decimal string ([`U64`]),
//! hashes and keys are lowercase hex ([`Hex32`], [`Hex64`]), Solana accounts
//! are base58 ([`B58`]) and canonical binary objects are standard base64
//! ([`B64`]) in fields ending in `_b64`.
//!
//! Request bodies refuse unknown fields. Responses accept them, because
//! v1 grows by adding fields. The `convert` module builds DTOs from
//! protocol types.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

mod dto;
mod encoding;
mod errors;
mod events;
pub mod schema;

pub mod convert;

pub use dto::*;
pub use encoding::{
    B58, B58Sig, B64, EncodingError, Hex, Hex32, Hex64, I64, I64_PATTERN, U64, U64_PATTERN,
};
pub use errors::{
    BadRequestDetails, BatchFullDetails, DecodeFailedDetails, DecodeReason,
    DuplicateCommitmentDetails, EpochClosedDetails, ErrorCode, IntakePausedDetails,
    NotYetAvailableDetails, PROBLEM_TYPE_PREFIX, Problem, ProblemDetails, QuotaExceededDetails,
    RateLimitScope, RateLimitedDetails, RetryPolicy, WalletNotEligibleDetails,
};
pub use events::{
    ClientMessage, Event, ResyncReason, STATUS_TOPIC, STREAM_FRAME_VERSION, STREAM_SUBPROTOCOL,
    ServerFrame, ServerMessage, SettlementStage, StreamEvent, market_topic,
};

/// The API version this crate describes, sent as `Timescales-Api-Version`
/// and `Info.api_version`. The path carries the major.
pub const API_VERSION: &str = "1.0";
