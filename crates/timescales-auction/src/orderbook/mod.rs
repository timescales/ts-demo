//! Batch validation.
//!
//! Turns the decrypted intents of one batch, in canonical order, into the
//! per-book order lists the matcher consumes. The steps and their order are
//! part of the protocol:
//!
//! 1. Envelopes that failed to open are rejected with their reason.
//! 2. Cover traffic is dropped.
//! 3. Repeated commitments are rejected after the first.
//! 4. Cancels for this market and epoch are collected.
//! 5. Each placement, in canonical order: stateless risk checks, per-trader
//!    nonce uniqueness, in-batch cancellation, cross-epoch state (spent or
//!    cancelled), per-trader order limit.
//! 6. self-trade prevention per book.
//! 7. collateral, prefix rule.
//! 8. Survivors go to their book with their remaining quantity.
//!
//! Orders whose limit cannot trade in the band are *accepted* with no slot:
//! they reserve nothing and receive no fill. Rejecting them would leak band
//! position through the receipt.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod state;

pub use state::{OrderStateTable, StateEntry};

use std::collections::{BTreeMap, BTreeSet};

use crate::collateral::{BalanceSheet, PrefixAdmission, requirement};
use crate::risk::{OrderCounter, RiskViolation, check_order, self_trade_conflicts};
use thiserror::Error;
use timescales_core::intent::{IntentBody, IntentError, PrivateIntent};
use timescales_core::{
    BookId, EpochId, FeeBps, Hash32, Lots, MarketParams, Order, OrderCommitment, PriceBand, Role,
    Side, TraderId,
};

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    #[error("envelope could not be decrypted or parsed")]
    Malformed,
    #[error("commitment did not open")]
    CommitmentMismatch,
    #[error("bad intent signature")]
    BadSignature,
    #[error("unsupported envelope version")]
    UnsupportedVersion,
    #[error("risk: {0}")]
    Risk(RiskViolation),
    #[error("commitment repeated in batch")]
    Duplicate,
    #[error("nonce repeated for trader in batch")]
    DuplicateNonce,
    #[error("order was cancelled in an earlier batch")]
    Spent,
    #[error("cancelled in this batch")]
    Cancelled,
    #[error("cancel is for another epoch or market")]
    StaleCancel,
    #[error("insufficient collateral")]
    InsufficientCollateral,
}

impl From<&IntentError> for RejectReason {
    fn from(e: &IntentError) -> Self {
        match e {
            IntentError::CommitmentMismatch | IntentError::Commitment(_) => {
                RejectReason::CommitmentMismatch
            }
            IntentError::BadSignature | IntentError::WrongSigner => RejectReason::BadSignature,
            IntentError::UnsupportedVersion(_) => RejectReason::UnsupportedVersion,
            IntentError::Crypto(_) | IntentError::Malformed(_) => RejectReason::Malformed,
        }
    }
}

/// One envelope after opening, in canonical position.
#[derive(Clone)]
pub struct Candidate {
    pub commitment: OrderCommitment,
    pub priority: Hash32,
    pub intent: Result<PrivateIntent, RejectReason>,
}

/// Shows the public commitment and priority and, for an envelope that did
/// not open, why. Never the decrypted intent.
impl core::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        struct Intent<'a>(&'a Result<PrivateIntent, RejectReason>);
        impl core::fmt::Debug for Intent<'_> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self.0 {
                    Ok(_) => f.write_str("Ok(..)"),
                    Err(reason) => f.debug_tuple("Err").field(reason).finish(),
                }
            }
        }
        f.debug_struct("Candidate")
            .field("commitment", &self.commitment)
            .field("priority", &self.priority)
            .field("intent", &Intent(&self.intent))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Noop,
    CancelApplied,
    CancelIgnored,
    Rejected(RejectReason),
    Accepted,
}

impl Disposition {
    /// Stable name of the disposition for the execution trace. The strings
    /// are exactly what `Debug` printed when the trace hashed `{:?}`, so
    /// traces (and the v1 vector receipts) stay byte-identical, while the
    /// protocol no longer depends on derived `Debug` output.
    pub fn trace_label(&self) -> &'static str {
        use RejectReason as R;
        use RiskViolation as V;
        match self {
            Disposition::Noop => "Noop",
            Disposition::CancelApplied => "CancelApplied",
            Disposition::CancelIgnored => "CancelIgnored",
            Disposition::Accepted => "Accepted",
            Disposition::Rejected(reason) => match reason {
                R::Malformed => "Rejected(Malformed)",
                R::CommitmentMismatch => "Rejected(CommitmentMismatch)",
                R::BadSignature => "Rejected(BadSignature)",
                R::UnsupportedVersion => "Rejected(UnsupportedVersion)",
                R::Risk(V::WrongMarket) => "Rejected(Risk(WrongMarket))",
                R::Risk(V::NotLive) => "Rejected(Risk(NotLive))",
                R::Risk(V::LifetimeTooLong) => "Rejected(Risk(LifetimeTooLong))",
                R::Risk(V::QuantityTooLarge) => "Rejected(Risk(QuantityTooLarge))",
                R::Risk(V::TooManyOrders) => "Rejected(Risk(TooManyOrders))",
                R::Risk(V::SelfTrade) => "Rejected(Risk(SelfTrade))",
                R::Duplicate => "Rejected(Duplicate)",
                R::DuplicateNonce => "Rejected(DuplicateNonce)",
                R::Spent => "Rejected(Spent)",
                R::Cancelled => "Rejected(Cancelled)",
                R::StaleCancel => "Rejected(StaleCancel)",
                R::InsufficientCollateral => "Rejected(InsufficientCollateral)",
            },
        }
    }
}

/// An accepted order as the matcher sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookOrder {
    pub commitment: OrderCommitment,
    pub trader: TraderId,
    pub side: Side,
    pub role: Role,
    /// `None`: cannot trade anywhere in the band.
    pub slot: Option<u32>,
    /// Remaining quantity after previous epochs' fills.
    pub quantity: Lots,
}

#[derive(Clone, Debug, Default)]
pub struct ValidatedBatch {
    /// Per-book orders in canonical order.
    pub books: BTreeMap<BookId, Vec<BookOrder>>,
    /// Disposition of every candidate, in canonical order.
    pub dispositions: Vec<(OrderCommitment, Disposition)>,
    /// Orders cancelled by this batch.
    pub cancelled: Vec<OrderCommitment>,
}

impl ValidatedBatch {
    pub fn accepted(&self) -> usize {
        self.books.values().map(Vec::len).sum()
    }

    pub fn rejected(&self) -> usize {
        self.dispositions
            .iter()
            .filter(|(_, d)| matches!(d, Disposition::Rejected(_)))
            .count()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ValidationContext<'a> {
    pub params: &'a MarketParams,
    pub band: &'a PriceBand,
    pub epoch: EpochId,
    pub state: &'a OrderStateTable,
    pub balances: &'a BalanceSheet,
}

pub fn fee_for(params: &MarketParams, role: Role) -> FeeBps {
    match role {
        Role::Maker => params.maker_fee,
        Role::Taker => params.taker_fee,
    }
}

struct Pending {
    pos: usize,
    commitment: OrderCommitment,
    order: Order,
    book: BookId,
    slot: Option<u32>,
    quantity: Lots,
}

pub fn validate(ctx: &ValidationContext<'_>, candidates: &[Candidate]) -> ValidatedBatch {
    let params = ctx.params;
    let mut dispositions: Vec<(OrderCommitment, Disposition)> = candidates
        .iter()
        .map(|c| (c.commitment, Disposition::Noop))
        .collect();

    // Steps 1-3.
    let mut seen = BTreeSet::new();
    let mut live: Vec<(usize, &PrivateIntent)> = Vec::with_capacity(candidates.len());
    for (i, c) in candidates.iter().enumerate() {
        match &c.intent {
            Err(r) => dispositions[i].1 = Disposition::Rejected(*r),
            Ok(intent) if intent.body == IntentBody::Noop => {}
            Ok(intent) => {
                if seen.insert(c.commitment) {
                    live.push((i, intent));
                } else {
                    dispositions[i].1 = Disposition::Rejected(RejectReason::Duplicate);
                }
            }
        }
    }

    // Step 4: cancels keyed by target. Only the order's own trader may cancel.
    let mut cancels: BTreeMap<OrderCommitment, Vec<(usize, TraderId)>> = BTreeMap::new();
    for (i, intent) in &live {
        if let IntentBody::Cancel(c) = intent.body {
            if c.market != params.market || c.epoch != ctx.epoch {
                dispositions[*i].1 = Disposition::Rejected(RejectReason::StaleCancel);
            } else {
                dispositions[*i].1 = Disposition::CancelIgnored;
                cancels.entry(c.target).or_default().push((*i, c.trader));
            }
        }
    }

    // Step 5.
    let mut nonces = BTreeSet::new();
    let mut counter = OrderCounter::default();
    let mut cancelled = Vec::new();
    let mut pending = Vec::new();
    for (i, intent) in &live {
        let IntentBody::Place(order) = intent.body else {
            continue;
        };
        let commitment = candidates[*i].commitment;
        let reject =
            |d: &mut Vec<(OrderCommitment, Disposition)>, r| d[*i].1 = Disposition::Rejected(r);

        if let Err(v) = check_order(params, ctx.epoch, &order) {
            reject(&mut dispositions, RejectReason::Risk(v));
            continue;
        }
        if !nonces.insert((order.trader, order.nonce)) {
            reject(&mut dispositions, RejectReason::DuplicateNonce);
            continue;
        }
        if let Some(cs) = cancels.get(&commitment) {
            let own: Vec<usize> = cs
                .iter()
                .filter(|(_, t)| *t == order.trader)
                .map(|(j, _)| *j)
                .collect();
            if !own.is_empty() {
                for j in own {
                    dispositions[j].1 = Disposition::CancelApplied;
                }
                cancelled.push(commitment);
                reject(&mut dispositions, RejectReason::Cancelled);
                continue;
            }
        }
        let filled = match ctx.state.get(&commitment) {
            Some(e) if e.cancelled => {
                reject(&mut dispositions, RejectReason::Spent);
                continue;
            }
            Some(e) => e.filled,
            None => Lots::ZERO,
        };
        // Exhausted orders stay in with zero quantity rather than being
        // rejected. See the note on `check_order`.
        let remaining = order.quantity.saturating_sub(filled);
        if let Err(v) = counter.admit(params, order.trader) {
            reject(&mut dispositions, RejectReason::Risk(v));
            continue;
        }
        pending.push(Pending {
            pos: *i,
            commitment,
            order,
            book: order.book(params.flow),
            slot: order.slot(ctx.band),
            quantity: remaining,
        });
    }

    // Step 6: only orders that can actually trade count towards a conflict.
    let conflicts = self_trade_conflicts(pending.iter().map(|p| {
        let q = if p.slot.is_some() {
            p.quantity
        } else {
            Lots::ZERO
        };
        (&p.order.trader, p.book, p.order.side, q)
    }));

    // Steps 7-8.
    let mut admission = PrefixAdmission::default();
    let mut books: BTreeMap<BookId, Vec<BookOrder>> = BookId::books(params.flow)
        .iter()
        .map(|b| (*b, Vec::new()))
        .collect();
    for p in pending {
        if conflicts.contains_key(&(p.order.trader, p.book)) {
            dispositions[p.pos].1 =
                Disposition::Rejected(RejectReason::Risk(RiskViolation::SelfTrade));
            continue;
        }
        let fee = fee_for(params, p.order.role);
        let req = requirement(params, ctx.band, p.order.side, p.slot, p.quantity.0, fee);
        if !admission.admit(ctx.balances, p.order.trader, req) {
            dispositions[p.pos].1 = Disposition::Rejected(RejectReason::InsufficientCollateral);
            continue;
        }
        dispositions[p.pos].1 = Disposition::Accepted;
        books.entry(p.book).or_default().push(BookOrder {
            commitment: p.commitment,
            trader: p.order.trader,
            side: p.order.side,
            role: p.order.role,
            slot: p.slot,
            quantity: p.quantity,
        });
    }

    ValidatedBatch {
        books,
        dispositions,
        cancelled,
    }
}

#[cfg(test)]
mod tests;
