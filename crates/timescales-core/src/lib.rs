//! Canonical protocol types for Timescales.
//!
//! This crate has no serialization framework dependency on purpose: the
//! encoding of every hashed or signed object is defined in [`encoding`] and is
//! part of the protocol.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod encoding;
pub mod ids;
pub mod market;
pub mod order;
pub mod units;

pub use encoding::{Decode, DecodeError, Encode, Reader};
pub use ids::{ExecutorId, Hash32, OrderCommitment, TraderId};
pub use market::{
    CommitmentScheme, FlowMode, MAX_BAND_TICKS, MAX_BATCH_ENVELOPES, MarketError, MarketParams,
    PriceBand, Rationing,
};
pub use order::{BookId, ClearingPrice, Fill, Order, OrderKind, Role, Side};
pub use units::{BaseAtoms, EpochId, FeeBps, Lots, MarketId, QuoteAtoms, SignedAmount, Tick};

/// Protocol version carried by envelopes, receipts and settlement records.
pub const PROTOCOL_VERSION: u8 = 1;

/// Most settlement leaves one batch may produce. Equals the program's
/// `MAX_DELTAS`, and on-chain markets cap `max_batch_envelopes` at it.
pub const MAX_SETTLEMENT_DELTAS: u32 = 1024;

/// Batch header version whose root commits to `commitment || envelope digest`
/// leaves and whose bytes `[87..119]` carry the epoch binding.
pub const HEADER_VERSION_ENVELOPE_BOUND: u8 = 2;

pub mod crypto;
