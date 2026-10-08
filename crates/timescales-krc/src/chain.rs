//! [`RpcKrcChain`]: the member's chain reads over a [`SolanaRpc`], in
//! production a [`QuorumRpc`](timescales_chain::QuorumRpc) whose providers
//! must agree byte for byte.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use timescales_auction::CommittedStatus;
use timescales_chain::program::{BatchAccount, BatchStatus, MarketAccount, batch_pda};
use timescales_chain::{AccountData, Address, ChainError, Level, RpcError, SolanaRpc};
use timescales_core::{EpochId, ExecutorId};
use timescales_executor::tee::{BatchView, ReleaseContext};

use crate::{BoxFuture, KrcChain, KrcError, now_ms};

/// Markets whose confirmed state is cached at most.
const MAX_CACHED_MARKETS: usize = 64;

/// [`KrcChain`] over a [`SolanaRpc`].
///
/// `release_context` reads the Market and the Batch in one
/// `getMultipleAccounts` at the release level (finalized outside profile
/// local), so both come from one slot, and the halt flag from a separate
/// confirmed read: a halt applies as soon as it is confirmed. Confirmed
/// Market reads are cached for `confirmed_cache` (at most 2 s).
/// Every account must be owned by the settlement program and decode as its
/// type. A read the providers dispute is [`KrcError::NotFinal`]. One no
/// provider answers is the RPC error.
pub struct RpcKrcChain {
    rpc: Arc<dyn SolanaRpc>,
    program: Address,
    release_level: Level,
    confirmed_cache: Duration,
    cache: Mutex<HashMap<Address, (Instant, MarketAccount)>>,
    last_success_ms: AtomicU64,
    disagreements: Counter,
    lag_slots: Gauge,
}

impl core::fmt::Debug for RpcKrcChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RpcKrcChain")
            .field("program", &crate::b58(&self.program))
            .field("release_level", &self.release_level)
            .finish_non_exhaustive()
    }
}

impl RpcKrcChain {
    pub fn new(
        rpc: Arc<dyn SolanaRpc>,
        program: Address,
        release_level: Level,
        confirmed_cache: Duration,
    ) -> Self {
        Self {
            rpc,
            program,
            release_level,
            confirmed_cache,
            cache: Mutex::new(HashMap::new()),
            last_success_ms: AtomicU64::new(0),
            disagreements: Counter::default(),
            lag_slots: Gauge::default(),
        }
    }

    /// `timescales_krc_rpc_disagreements_total` and
    /// `timescales_krc_chain_lag_slots`.
    pub fn register_metrics(&self, registry: &mut Registry) {
        registry.register(
            "timescales_krc_rpc_disagreements",
            "Release-critical reads the RPC providers disagreed on",
            self.disagreements.clone(),
        );
        registry.register(
            "timescales_krc_chain_lag_slots",
            "Slots between the confirmed and the release-level view of the last release read",
            self.lag_slots.clone(),
        );
    }

    /// When a chain read last succeeded (ms since the Unix epoch, 0 if
    /// never): the readiness check wants one in the last 30 s.
    pub fn last_success_ms(&self) -> u64 {
        self.last_success_ms.load(Ordering::Relaxed)
    }

    fn rpc_error(&self, e: RpcError) -> KrcError {
        match e {
            RpcError::Disagree => {
                self.disagreements.inc();
                KrcError::NotFinal
            }
            other => KrcError::Rpc(other),
        }
    }

    fn owned<'a>(&self, a: &'a AccountData) -> Result<&'a [u8], KrcError> {
        if a.owner != self.program {
            return Err(
                ChainError::Inconsistent("account not owned by the settlement program").into(),
            );
        }
        Ok(&a.data)
    }

    fn decode_market(
        &self,
        m: Address,
        a: Option<&AccountData>,
    ) -> Result<MarketAccount, KrcError> {
        let a = a.ok_or(KrcError::UnknownMarket(m))?;
        timescales_chain::program::decode_market(self.owned(a)?)
            .map_err(|e| ChainError::Decode(e).into())
    }

    fn decode_batch(
        &self,
        m: Address,
        e: EpochId,
        a: Option<&AccountData>,
    ) -> Result<Option<BatchAccount>, KrcError> {
        let Some(a) = a else { return Ok(None) };
        let b =
            timescales_chain::program::decode_batch(self.owned(a)?).map_err(ChainError::Decode)?;
        if b.market != m || b.epoch != e.0 {
            return Err(
                ChainError::Inconsistent("batch account names another market or epoch").into(),
            );
        }
        Ok(Some(b))
    }

    async fn read_market(
        &self,
        m: Address,
        level: Level,
    ) -> Result<(u64, MarketAccount), KrcError> {
        let a = self
            .rpc
            .get_account(m, level, None)
            .await
            .map_err(|e| self.rpc_error(e))?;
        let market = self.decode_market(m, a.as_ref())?;
        let slot = a.map_or(0, |a| a.context_slot);
        self.last_success_ms.store(now_ms(), Ordering::Relaxed);
        Ok((slot, market))
    }
}

/// The batch as `KeyReleaseMember::decide` sees it.
pub fn batch_view(b: &BatchAccount) -> BatchView {
    let status = match b.status {
        BatchStatus::Committed => CommittedStatus::Committed,
        BatchStatus::BeaconRevealed => CommittedStatus::BeaconRevealed,
        BatchStatus::ReceiptPosted => CommittedStatus::ReceiptPosted,
        BatchStatus::Verified => CommittedStatus::Verified,
        BatchStatus::Settled => CommittedStatus::Settled,
        BatchStatus::Aborted => CommittedStatus::Aborted,
    };
    let revealed = b.status != BatchStatus::Committed;
    let posted = matches!(
        b.status,
        BatchStatus::ReceiptPosted | BatchStatus::Verified | BatchStatus::Settled
    );
    BatchView {
        status,
        root: b.root,
        count: b.count,
        terms_digest: b.terms_digest,
        beacon: revealed.then_some(b.beacon),
        header_digest: posted.then_some(b.header_digest),
        applied_count: b.applied_count,
    }
}

/// The release context of a market and its batch read at one slot. The
/// halt flag comes from `halted` (confirmed).
pub fn release_context(
    market: &MarketAccount,
    batch: Option<&BatchAccount>,
    halted: bool,
) -> ReleaseContext {
    ReleaseContext {
        executors: market
            .executors
            .iter()
            .filter(|k| **k != [0; 32])
            .map(|k| ExecutorId(*k))
            .collect(),
        committee_digest: market.committee_digest,
        prev_committee_digest: market.prev_committee_digest,
        params: market.params,
        last_settled: EpochId(market.last_settled),
        state_root: market.state_root,
        prev_receipt: market.prev_receipt,
        halted,
        batch: batch.map(batch_view),
    }
}

impl KrcChain for RpcKrcChain {
    fn release_context(
        &self,
        m: Address,
        e: EpochId,
    ) -> BoxFuture<'_, Result<ReleaseContext, KrcError>> {
        Box::pin(async move {
            let batch_key = batch_pda(&self.program, &m, e.0)
                .map_err(|e| KrcError::Chain(ChainError::Decode(e)))?
                .0;
            let (slot, accounts) = self
                .rpc
                .get_multiple_accounts(vec![m, batch_key], self.release_level, None)
                .await
                .map_err(|e| self.rpc_error(e))?;
            let [market, batch] = accounts.as_slice() else {
                return Err(
                    ChainError::Inconsistent("getMultipleAccounts returned another count").into(),
                );
            };
            let market = self.decode_market(m, market.as_ref())?;
            let batch = self.decode_batch(m, e, batch.as_ref())?;
            let (confirmed_slot, confirmed) = self.read_market(m, Level::Confirmed).await?;
            self.lag_slots
                .set(i64::try_from(confirmed_slot.saturating_sub(slot)).unwrap_or(i64::MAX));
            Ok(release_context(&market, batch.as_ref(), confirmed.halted))
        })
    }

    fn market(&self, m: Address, level: Level) -> BoxFuture<'_, Result<MarketAccount, KrcError>> {
        Box::pin(async move {
            let cached = level == Level::Confirmed && !self.confirmed_cache.is_zero();
            if cached
                && let Some((at, market)) = self.cache.lock().get(&m)
                && at.elapsed() < self.confirmed_cache
            {
                return Ok(market.clone());
            }
            let (_, market) = self.read_market(m, level).await?;
            if cached {
                let mut cache = self.cache.lock();
                if cache.len() < MAX_CACHED_MARKETS || cache.contains_key(&m) {
                    cache.insert(m, (Instant::now(), market.clone()));
                }
            }
            Ok(market)
        })
    }
}
