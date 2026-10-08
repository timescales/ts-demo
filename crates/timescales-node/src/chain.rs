//! Chain wiring: one `SolanaMarketChain` per market over the
//! node's RPC, all sharing one `TxSender` whose write-ahead journal is the
//! store's `txs` table (`NodeRepo` implements `TxJournal`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use timescales_chain::{
    FeeMode, FeePolicy, Level, MarketChain, MarketChainConfig, SolanaMarketChain, SolanaRpc,
    TxJournal, TxSender,
};
use timescales_service::store::node::NodeRepo;

use crate::Address;
use crate::config::{Commitment, ExecutionConfig, FeeModeConfig, SolanaConfig};

pub fn level(c: Commitment) -> Level {
    match c {
        Commitment::Processed => Level::Processed,
        Commitment::Confirmed => Level::Confirmed,
        Commitment::Finalized => Level::Finalized,
    }
}

pub fn fee_policy(cfg: &SolanaConfig) -> FeePolicy {
    FeePolicy {
        mode: match cfg.priority_fee.mode {
            FeeModeConfig::Fixed => FeeMode::Fixed(cfg.priority_fee.fixed_micro_lamports.0),
            FeeModeConfig::Recent => FeeMode::Recent,
        },
        percentile: cfg.priority_fee.percentile,
        max_micro_lamports: cfg.priority_fee.max_micro_lamports.0,
        cu_margin_pct: cfg.cu_margin_pct,
    }
}

pub fn chain_config(cfg: &SolanaConfig, exec: &ExecutionConfig) -> MarketChainConfig {
    MarketChainConfig {
        max_attempts: cfg.tx_max_attempts.max(1),
        retry_backoff: Duration::from_millis(exec.retry_backoff_ms),
        max_backoff: Duration::from_secs(8),
        poll_interval: Duration::from_millis(cfg.poll_interval_ms),
        max_parallel_txs: usize::try_from(cfg.max_parallel_txs).unwrap_or(16).max(1),
    }
}

/// The sender of every market, journalled in `repo`.
pub fn sender(rpc: Arc<dyn SolanaRpc>, repo: Arc<NodeRepo>, cfg: &SolanaConfig) -> Arc<TxSender> {
    let journal: Arc<dyn TxJournal> = repo;
    Arc::new(TxSender::new(
        rpc,
        fee_policy(cfg),
        journal,
        Duration::from_millis(cfg.poll_interval_ms),
        Duration::from_millis(cfg.confirm_timeout_ms),
    ))
}

/// One adapter per market, sharing `sender`. Every adapter starts its
/// `minContextSlot` at the journal's last landed slot, so a provider that
/// is behind cannot answer with state older than this node acted on.
pub fn markets(
    rpc: Arc<dyn SolanaRpc>,
    sender: Arc<TxSender>,
    program: Address,
    markets: &[Address],
    cfg: MarketChainConfig,
    last_landed: u64,
) -> BTreeMap<Address, Arc<dyn MarketChain>> {
    markets
        .iter()
        .map(|m| {
            let chain = SolanaMarketChain::new(rpc.clone(), sender.clone(), program, *m, cfg);
            chain.observe_from(last_landed);
            (*m, Arc::new(chain) as Arc<dyn MarketChain>)
        })
        .collect()
}
