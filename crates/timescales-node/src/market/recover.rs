//! Crash recovery: the total (persisted phase x observed chain
//! state) table, and the start-up reconciliation that applies it before
//! the actor of a market starts.
//!
//! The table is one function, [`action`]. Start-up applies the cells that
//! need the closed batch and the chain side by side (AHEAD, adopt, fence,
//! aborted). Every other cell is what the job of the persisted phase does
//! when it runs, because the jobs consult the same function.

use std::sync::Arc;

use thiserror::Error;
use timescales_chain::program::{AbortReason, BatchAccount, BatchStatus, MarketAccount};
use timescales_chain::{Level, MarketChain};
use timescales_core::{Decode, EpochId};
use timescales_service::relay::{OpenSnapshot, Relay, RelayConfig, Submission, verify_submission};
use timescales_service::store::StoreError;
use timescales_service::store::node::{EpochPatch, EpochRow, NodeRepo, Phase};

use super::{BundleFacts, ChainObservation, FenceReason, Restored};
use crate::keys::KeyDirectory;
use crate::{Address, VerifiedSubmission};

/// What the chain shows for epoch `e` (the columns).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChainState {
    /// No batch account and `Market.last_committed < e`.
    NoBatch,
    /// No batch account although `Market.last_committed >= e` (reclaimed, or
    /// never ours).
    NoBatchCommitted,
    Committed,
    BeaconRevealed,
    ReceiptPosted,
    Verified,
    Settled,
    Aborted,
}

impl ChainState {
    pub const ALL: [ChainState; 8] = [
        ChainState::NoBatch,
        ChainState::NoBatchCommitted,
        ChainState::Committed,
        ChainState::BeaconRevealed,
        ChainState::ReceiptPosted,
        ChainState::Verified,
        ChainState::Settled,
        ChainState::Aborted,
    ];
}

/// The batch the closed epoch committed, once adopted ("adopt").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Adopted {
    Committed,
    SnapReveal,
    Fetch,
    FetchSettle,
    FetchSettled,
    Aborted,
}

/// One cell of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// "-": the database has no epoch and the chain none beyond it.
    NotApplicable,
    /// The chain is ahead of the database: refuse to start, or abort with
    /// `--accept-chain-ahead`.
    Ahead,
    /// Nothing to do (a scheduled epoch keeps its re-verified bundle).
    Keep,
    /// Terminal here, and the chain reclaimed the batch account.
    KeepReclaimed,
    /// `Relay::restore` the open epoch and resume intake (or close now).
    Restore,
    /// Wait for the in-flight slot.
    WaitInFlight,
    /// The journalled commit: poll it, and re-send the same root if it
    /// expired.
    ResendCommit,
    /// Compare the chain's batch with the closed one. Equal means it was
    /// ours.
    Adopt(Adopted),
    /// Take the snapshot. Reveal once `slot > commit_slot + 2d`.
    Snap,
    SnapReveal,
    SnapFetch,
    SnapFetchSettle,
    Exec,
    Fetch,
    FetchSettle,
    FetchSettled,
    Settle,
    MarkSettled,
    Abort,
    /// Abort. `Superseded` -> fetch, unless the reason is still legal.
    AbortElseFetch,
    AbortElseFetchSettle,
    SupersededFetchSettled,
    MarkAborted,
    Fence,
}

/// The recovery table. `phase` is `None` for an epoch the database does not
/// know. Total: every pair has exactly one action.
pub fn action(phase: Option<Phase>, chain: ChainState) -> Action {
    use Action as A;
    use ChainState as C;
    let Some(phase) = phase else {
        return match chain {
            C::NoBatch => A::NotApplicable,
            _ => A::Ahead,
        };
    };
    match phase {
        Phase::Scheduled => match chain {
            C::NoBatch => A::Keep,
            _ => A::Ahead,
        },
        Phase::Open => match chain {
            C::NoBatch => A::Restore,
            _ => A::Ahead,
        },
        Phase::Closed | Phase::Committing => match chain {
            C::NoBatch if phase == Phase::Closed => A::WaitInFlight,
            C::NoBatch => A::ResendCommit,
            C::NoBatchCommitted => A::Fence,
            C::Committed => A::Adopt(Adopted::Committed),
            C::BeaconRevealed => A::Adopt(Adopted::SnapReveal),
            C::ReceiptPosted => A::Adopt(Adopted::Fetch),
            C::Verified => A::Adopt(Adopted::FetchSettle),
            C::Settled => A::Adopt(Adopted::FetchSettled),
            C::Aborted => A::Adopt(Adopted::Aborted),
        },
        Phase::Committed | Phase::Snapshotted => match chain {
            C::NoBatch | C::NoBatchCommitted => A::Fence,
            C::Committed => A::Snap,
            C::BeaconRevealed => A::SnapReveal,
            C::ReceiptPosted => A::SnapFetch,
            C::Verified => A::SnapFetchSettle,
            C::Settled => A::FetchSettled,
            C::Aborted => A::MarkAborted,
        },
        Phase::Revealed | Phase::Sealed | Phase::Executing => match chain {
            C::NoBatch | C::NoBatchCommitted | C::Committed => A::Fence,
            C::BeaconRevealed => A::Exec,
            C::ReceiptPosted => A::Fetch,
            C::Verified => A::FetchSettle,
            C::Settled => A::FetchSettled,
            C::Aborted => A::MarkAborted,
        },
        Phase::Posted => match chain {
            C::NoBatch | C::NoBatchCommitted | C::Committed | C::BeaconRevealed => A::Fence,
            C::ReceiptPosted | C::Verified => A::Settle,
            C::Settled => A::MarkSettled,
            C::Aborted => A::MarkAborted,
        },
        Phase::Settled => match chain {
            C::NoBatchCommitted => A::KeepReclaimed,
            C::Settled => A::Keep,
            _ => A::Fence,
        },
        Phase::Aborting => match chain {
            C::NoBatch | C::NoBatchCommitted => A::Fence,
            C::Committed | C::BeaconRevealed => A::Abort,
            C::ReceiptPosted => A::AbortElseFetch,
            C::Verified => A::AbortElseFetchSettle,
            C::Settled => A::SupersededFetchSettled,
            C::Aborted => A::MarkAborted,
        },
        Phase::Aborted => match chain {
            C::NoBatchCommitted => A::KeepReclaimed,
            C::Aborted => A::Keep,
            _ => A::Fence,
        },
    }
}

#[derive(Debug, Error)]
pub enum RecoverError {
    #[error(
        "chain is ahead of the database (database up to epoch {db}, chain committed {chain}); \
         restore a newer backup or run with --accept-chain-ahead"
    )]
    ChainAhead { db: u64, chain: u64 },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Chain(#[from] timescales_chain::ChainError),
    #[error("{0}")]
    Invalid(String),
}

/// What start-up recovery of one market needs.
pub struct RecoverInput {
    pub market: Address,
    pub chain: Arc<dyn MarketChain>,
    pub repo: Arc<NodeRepo>,
    pub keys: Arc<KeyDirectory>,
    pub relay_cfg: RelayConfig,
    pub relay_key: Arc<timescales_core::crypto::Keypair>,
    pub cover: Box<dyn Fn() -> Box<dyn timescales_service::relay::CoverSource> + Send + Sync>,
    pub accept_chain_ahead: bool,
    pub now_ms: u64,
}

impl core::fmt::Debug for RecoverInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoverInput")
            .field("market", &bs58::encode(self.market).into_string())
            .finish_non_exhaustive()
    }
}

fn chain_state(batch: Option<&BatchAccount>, market: &MarketAccount, e: u64) -> ChainState {
    match batch {
        Some(b) => b.status.into(),
        None if market.last_committed >= e => ChainState::NoBatchCommitted,
        None => ChainState::NoBatch,
    }
}

/// The abort reason a node that cannot proceed with epoch `e` uses: the
/// relay abort while no beacon input exists, then the timeout the batch's
/// status leads to.
pub fn cannot_proceed_reason(b: &BatchAccount, m: &MarketAccount, slot: u64) -> AbortReason {
    match b.status {
        BatchStatus::Committed if slot < b.commit_slot + u64::from(m.beacon_delay_slots) => {
            AbortReason::Relay
        }
        BatchStatus::Committed => AbortReason::BeaconExpired,
        BatchStatus::BeaconRevealed => AbortReason::ExecTimeout,
        BatchStatus::ReceiptPosted if !m.quorum_met(b.cosign_bitmap) => AbortReason::QuorumTimeout,
        _ => AbortReason::SettleTimeout,
    }
}

/// Runs recovery for one market and returns what its actor starts from.
pub async fn recover(input: RecoverInput) -> Result<Restored, RecoverError> {
    let RecoverInput {
        market,
        chain,
        repo,
        keys,
        relay_cfg,
        relay_key,
        cover,
        accept_chain_ahead,
        now_ms,
    } = input;
    let m = chain.market(Level::Confirmed).await?;
    let slot = chain.slot(Level::Confirmed).await?;
    keys.set_allowed(m.committee_digest, m.prev_committee_digest);
    let db_max = repo.max_epoch(market).await?.unwrap_or(0);
    let mut fenced = None;

    // Epochs the chain committed that the database never saw.
    if m.last_committed > db_max {
        if !accept_chain_ahead {
            return Err(RecoverError::ChainAhead {
                db: db_max,
                chain: m.last_committed,
            });
        }
        for e in db_max + 1..=m.last_committed {
            let batch = chain.batch(e, Level::Confirmed).await?;
            adopt_unknown(&repo, market, e, batch.as_ref(), &m, slot, now_ms).await?;
        }
    }

    for row in repo.non_terminal_epochs(market).await? {
        let e = row.epoch;
        let batch = if row.phase >= Phase::Open || m.last_committed >= e {
            chain.batch(e, Level::Confirmed).await?
        } else {
            None
        };
        let state = chain_state(batch.as_ref(), &m, e);
        match action(Some(row.phase), state) {
            Action::Ahead => {
                if !accept_chain_ahead {
                    return Err(RecoverError::ChainAhead {
                        db: db_max,
                        chain: m.last_committed,
                    });
                }
                // Our open or scheduled epoch was committed by someone else:
                // it is not ours to run. Its intake never resumes.
                match &batch {
                    Some(b) if !b.status.is_terminal() => {
                        let reason = cannot_proceed_reason(b, &m, slot);
                        repo.advance(
                            market,
                            e,
                            Phase::Aborting,
                            EpochPatch {
                                abort_reason: Some(reason as u8),
                                abort_detail: Some("chain ahead of the database".into()),
                                updated_at_ms: Some(now_ms),
                                ..EpochPatch::default()
                            },
                        )
                        .await?;
                    }
                    // Terminal on chain: adopted as the chain has it.
                    Some(b) if b.status == BatchStatus::Settled => {
                        repo.advance(
                            market,
                            e,
                            Phase::Settled,
                            EpochPatch {
                                root: Some(b.root),
                                envelope_count: Some(b.count),
                                terminal_slot: Some(slot),
                                updated_at_ms: Some(now_ms),
                                ..EpochPatch::default()
                            },
                        )
                        .await?;
                    }
                    other => {
                        repo.advance(
                            market,
                            e,
                            Phase::Aborted,
                            EpochPatch {
                                abort_reason: other
                                    .as_ref()
                                    .and_then(|b| b.abort_reason.map(|r| r as u8)),
                                abort_detail: Some("chain ahead of the database".into()),
                                terminal_slot: Some(slot),
                                updated_at_ms: Some(now_ms),
                                ..EpochPatch::default()
                            },
                        )
                        .await?;
                    }
                }
            }
            Action::Adopt(then) => {
                let Some(b) = batch.as_ref() else {
                    continue;
                };
                let ours = row.root == Some(b.root)
                    && row.envelope_count == Some(b.count)
                    && row.terms_digest == Some(b.terms_digest);
                if !ours {
                    tracing::error!(
                        epoch = e,
                        "TimescalesEquivocation: the chain holds another batch"
                    );
                    fenced = Some(FenceReason::Equivocation);
                    break;
                }
                let patch = EpochPatch {
                    commit_slot: Some(b.commit_slot),
                    updated_at_ms: Some(now_ms),
                    ..EpochPatch::default()
                };
                if then == Adopted::Aborted {
                    repo.advance(
                        market,
                        e,
                        Phase::Aborted,
                        EpochPatch {
                            abort_reason: b.abort_reason.map(|r| r as u8),
                            terminal_slot: Some(slot),
                            ..patch
                        },
                    )
                    .await?;
                } else {
                    repo.advance(market, e, Phase::Committed, patch).await?;
                }
            }
            Action::MarkAborted => {
                repo.advance(
                    market,
                    e,
                    Phase::Aborted,
                    EpochPatch {
                        abort_reason: batch.as_ref().and_then(|b| b.abort_reason.map(|r| r as u8)),
                        terminal_slot: Some(slot),
                        updated_at_ms: Some(now_ms),
                        ..EpochPatch::default()
                    },
                )
                .await?;
            }
            Action::Fence => {
                tracing::error!(epoch = e, phase = ?row.phase, ?state, "state divergence");
                fenced = Some(FenceReason::StateDivergence);
                break;
            }
            _ => {}
        }
    }

    let epochs = repo.non_terminal_epochs(market).await?;
    let last_terminal = super::store::last_terminal(&repo, market).await?;
    let mut relay = Relay::new(relay_cfg.clone(), relay_key.clone(), cover());
    let mut open_entries = Vec::new();
    if let Some(open) = epochs.iter().find(|r| r.phase == Phase::Open) {
        let subs = repo.submissions(market, open.epoch).await?;
        let snapshot = OpenSnapshot {
            epoch: EpochId(open.epoch),
            opens_at_ms: open.opens_at_ms.unwrap_or(0),
            cutoff_ms: open.cutoff_ms.unwrap_or(0),
            band: open
                .band
                .ok_or_else(|| RecoverError::Invalid("open epoch without a band".into()))?,
            price_commitment: open.price_commitment.unwrap_or_default(),
            binding: open.binding.unwrap_or_default(),
            submissions: subs
                .iter()
                .filter_map(|s| s.wallet.map(|w| (s.submission.clone(), w)))
                .collect(),
        };
        let cfg = relay_cfg.clone();
        let key = relay_key.clone();
        let cover_source = cover();
        // Re-verifying every accepted submission is CPU work.
        relay =
            tokio::task::spawn_blocking(move || Relay::restore(cfg, key, cover_source, snapshot))
                .await
                .map_err(|e| RecoverError::Invalid(format!("restore task: {e}")))?
                .map_err(|e| RecoverError::Invalid(format!("restoring the open epoch: {e}")))?;
        open_entries = subs
            .into_iter()
            .filter_map(|s| {
                s.wallet
                    .map(|w| (s.commitment, w, s.envelope_digest, s.promise))
            })
            .collect();
    }

    let parked_rows = super::store::all_parked(&repo, market).await?;
    let cfg = relay_cfg.clone();
    let parked = tokio::task::spawn_blocking(move || {
        parked_rows
            .into_iter()
            .filter_map(|row| {
                let sub = Submission::decode_exact(&row.submission).ok()?;
                let inner = verify_submission(&cfg, &sub).ok()?;
                let raw = row.submission.clone();
                Some((row, VerifiedSubmission { raw, inner }))
            })
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|e| RecoverError::Invalid(format!("parked verification: {e}")))?;

    let floor = last_terminal.as_ref().map_or(1, |r| r.epoch + 1);
    let mut bundles = Vec::new();
    let mut served = Vec::new();
    for (e, bytes, was_served) in super::store::bundles_from(&repo, market, floor).await? {
        match keys.verify(e, &bytes) {
            Ok(v) => {
                bundles.push((
                    e,
                    BundleFacts {
                        key_digest: v.key_digest,
                        committee_digest: v.committee_digest,
                        epoch_pk: v.epoch_pk,
                        bytes: v.bytes.clone(),
                    },
                ));
                if was_served {
                    served.push(e);
                }
                let _ = keys.insert(v);
            }
            Err(err) => {
                tracing::warn!(epoch = e, error = %err, "stored key bundle no longer verifies")
            }
        }
    }

    let db_next = epochs
        .iter()
        .filter(|r| r.phase > Phase::Scheduled)
        .map(|r| r.epoch + 1)
        .max()
        .unwrap_or(0);
    let next_epoch = (m.last_committed + 1)
        .max(db_next)
        .max(last_terminal.as_ref().map_or(1, |r| r.epoch + 1));
    let lowest = epochs.first().map(|r| r.epoch);
    let batch = match lowest {
        Some(e) => chain.batch(e, Level::Confirmed).await?,
        None => None,
    };
    Ok(Restored {
        epochs,
        last_terminal,
        relay,
        open_entries,
        parked,
        bundles,
        served,
        next_epoch,
        fenced,
        chain: Some(ChainObservation {
            slot,
            market: m,
            batch,
            relay_lamports: None,
            cranker_lamports: None,
            program: None,
        }),
    })
}

async fn adopt_unknown(
    repo: &NodeRepo,
    market: Address,
    e: u64,
    batch: Option<&BatchAccount>,
    m: &MarketAccount,
    slot: u64,
    now_ms: u64,
) -> Result<(), RecoverError> {
    let mut row = EpochRow {
        market,
        epoch: e,
        phase: Phase::Aborted,
        opens_at_ms: None,
        cutoff_ms: None,
        reference: None,
        band: None,
        price_commitment: None,
        committee_digest: None,
        binding: None,
        terms_digest: batch.map(|b| b.terms_digest),
        announcement: None,
        root: batch.map(|b| b.root),
        envelope_count: batch.map(|b| b.count),
        real_count: None,
        cover_count: None,
        commit_sig: None,
        commit_slot: batch.map(|b| b.commit_slot),
        snapshot_slot: None,
        snapshot_late: false,
        beacon: None,
        reveal_slot: None,
        header: None,
        receipt: None,
        receipt_slot: None,
        artifacts_public: false,
        abort_reason: None,
        abort_detail: Some("adopted from the chain (chain ahead of the database)".into()),
        terminal_slot: None,
        updated_at_ms: now_ms,
    };
    match batch.map(|b| b.status) {
        // Settled without us: the epoch is adopted as it stands. The carried
        // state comes from `recover-state`.
        Some(BatchStatus::Settled) => {
            row.phase = Phase::Settled;
            row.terminal_slot = Some(slot);
        }
        Some(BatchStatus::Aborted) | None => {
            row.abort_reason = batch.and_then(|b| b.abort_reason.map(|r| r as u8));
            row.terminal_slot = Some(slot);
        }
        Some(_) => {
            let b = batch.ok_or_else(|| RecoverError::Invalid("batch vanished".into()))?;
            row.phase = Phase::Aborting;
            row.abort_reason = Some(cannot_proceed_reason(b, m, slot) as u8);
        }
    }
    super::store::adopt_epoch(repo, row).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_total_and_fences_only_impossible_cells() {
        let mut cells = 0;
        for phase in std::iter::once(None).chain(Phase::ALL.into_iter().map(Some)) {
            for c in ChainState::ALL {
                let a = action(phase, c);
                cells += 1;
                // A database epoch the chain has not reached is never
                // "ahead", and an unknown one never fenced.
                if phase.is_none() {
                    assert!(matches!(a, Action::Ahead | Action::NotApplicable));
                }
            }
        }
        assert_eq!(cells, 14 * 8);
        assert_eq!(
            action(Some(Phase::Committing), ChainState::NoBatch),
            Action::ResendCommit
        );
        assert_eq!(
            action(Some(Phase::Closed), ChainState::NoBatch),
            Action::WaitInFlight
        );
        assert_eq!(
            action(Some(Phase::Executing), ChainState::ReceiptPosted),
            Action::Fetch
        );
        assert_eq!(
            action(Some(Phase::Posted), ChainState::BeaconRevealed),
            Action::Fence
        );
        assert_eq!(
            action(Some(Phase::Aborting), ChainState::Settled),
            Action::SupersededFetchSettled
        );
        assert_eq!(
            action(Some(Phase::Settled), ChainState::NoBatchCommitted),
            Action::KeepReclaimed
        );
    }
}
