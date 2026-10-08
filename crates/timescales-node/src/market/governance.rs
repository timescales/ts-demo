//! Governance and chain watching: the Market account (pending
//! change, halt, committee digests), the in-flight batch, the relay and
//! cranker balances and the program's ProgramData (upgrade authority, last
//! deploy slot).
//!
//! The watcher only observes. The actor decides. It publishes
//! `governance.pending` when a change appears or becomes due, applies due
//! between-batches changes before the next commit (`ApplyChange` job,
//! because `CommitBatch` fails with `ChangeDue` otherwise) and publishes
//! `governance.applied` and `program.upgraded`. An applied
//! `SetCommitteeDigest` re-scopes the key directory here: bundles of a
//! committee the chain no longer recognises are dropped and their parked
//! envelopes invalidated. An applied `SetRelay` that moves
//! `Market.relay` away from this node's key drains the market in the actor.
//! No more promises, epochs or commits under the old key until the
//! node restarts with the new one.

use std::sync::Arc;

use timescales_chain::program::loader::{ProgramData, decode_program_data, program_data_address};
use timescales_chain::{Address, Level, MarketChain, SolanaRpc};
use timescales_service::store::node::{NodeRepo, Phase};

use super::{ChainObservation, MarketView};
use crate::keys::KeyDirectory;
use crate::telemetry::NodeMetrics;

/// What one chain poll needs.
pub struct Watch {
    pub market: Address,
    pub program: Address,
    pub chain: Arc<dyn MarketChain>,
    pub rpc: Arc<dyn SolanaRpc>,
    pub relay: Address,
    pub cranker: Address,
    pub keys: Arc<KeyDirectory>,
    pub repo: Arc<NodeRepo>,
    pub metrics: Arc<NodeMetrics>,
}

impl core::fmt::Debug for Watch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Watch")
            .field("market", &bs58::encode(self.market).into_string())
            .finish_non_exhaustive()
    }
}

/// The lowest epoch whose batch is worth reading.
fn watched_epoch(view: &MarketView) -> Option<u64> {
    view.epochs
        .iter()
        .find(|(_, p)| *p >= Phase::Committing)
        .map(|(e, _)| *e)
}

impl Watch {
    async fn program_data(&self) -> Option<ProgramData> {
        let key = program_data_address(&self.program).ok()?;
        let account = self
            .rpc
            .get_account(key, Level::Confirmed, None)
            .await
            .ok()??;
        decode_program_data(&account.data).ok()
    }

    /// One observation, or `None` when the market cannot be read now.
    pub async fn observe(&self, view: &MarketView, with_program: bool) -> Option<ChainObservation> {
        let market = match self.chain.market(Level::Confirmed).await {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(error = %e, "market not observed");
                return None;
            }
        };
        let slot = self.chain.slot(Level::Confirmed).await.ok()?;
        if let Ok(processed) = self.rpc.slot(Level::Processed).await {
            self.metrics
                .chain_slot_lag
                .set(i64::try_from(processed.saturating_sub(slot)).unwrap_or(i64::MAX));
        }
        let batch = match watched_epoch(view) {
            Some(e) => self.chain.batch(e, Level::Confirmed).await.ok().flatten(),
            None => None,
        };
        let (relay_lamports, cranker_lamports) = match self
            .rpc
            .get_multiple_accounts(vec![self.relay, self.cranker], Level::Confirmed, None)
            .await
        {
            Ok((_, accounts)) => {
                let lamports = |i: usize| {
                    accounts
                        .get(i)
                        .map(|a| a.as_ref().map_or(0, |a| a.lamports))
                };
                (lamports(0), lamports(1))
            }
            Err(_) => (None, None),
        };
        if let Some(l) = relay_lamports {
            self.metrics
                .relay_balance_lamports
                .set(i64::try_from(l).unwrap_or(i64::MAX));
        }
        if let Some(l) = cranker_lamports {
            self.metrics
                .cranker_balance_lamports
                .set(i64::try_from(l).unwrap_or(i64::MAX));
        }
        let program = if with_program {
            self.program_data().await
        } else {
            None
        };
        if let Some(p) = program {
            self.metrics
                .program_last_deploy_slot
                .set(i64::try_from(p.last_deploy_slot).unwrap_or(i64::MAX));
        }
        let pending = market.pending.as_ref();
        let labels = self.metrics.market(&self.market);
        self.metrics
            .governance_pending
            .get_or_create(&labels)
            .set(pending.map_or(0, |p| i64::try_from(p.eta_slot).unwrap_or(i64::MAX)));
        let due = pending.is_some_and(|p| p.change.between_batches() && slot >= p.eta_slot);
        self.metrics
            .governance_due
            .get_or_create(&labels)
            .set(i64::from(due));
        Some(ChainObservation {
            slot,
            market,
            batch,
            relay_lamports,
            cranker_lamports,
            program,
        })
    }

    /// Re-scopes the key directory to the committees the chain recognises.
    /// Returns the epochs whose bundles (and parked envelopes) are gone.
    pub async fn rescope_keys(&self, obs: &ChainObservation) -> Vec<u64> {
        let before = self.keys.allowed();
        self.keys.set_allowed(
            obs.market.committee_digest,
            obs.market.prev_committee_digest,
        );
        if self.keys.allowed() == before {
            return Vec::new();
        }
        let gone = self.keys.drop_unrecognised();
        if !gone.is_empty() {
            match self.repo.invalidate_parked(self.market, gone.clone()).await {
                Ok(n) => tracing::warn!(epochs = ?gone, parked = n, "parked envelopes invalidated"),
                Err(e) => tracing::error!(error = %e, "invalidating parked envelopes failed"),
            }
        }
        gone
    }
}
