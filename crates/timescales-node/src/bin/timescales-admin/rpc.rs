//! Cluster access for the commands that read chain state or send
//! transactions: one `HttpRpc`, a `TxSender` with an in-memory journal and
//! the settlement program's id.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use timescales_chain::program::{BatchAccount, Ix, MarketAccount};
use timescales_chain::{
    AccountData, BoxFuture, FeeMode, FeePolicy, HttpRpc, JournalError, Landed, Level,
    MarketChainConfig, SolanaMarketChain, SolanaRpc, TxJournal, TxOp, TxOutcome, TxRecord,
    TxSender, TxSigner,
};

use crate::util::{Key, b58, parse_key};

/// The program id of local and test deployments.
pub(crate) const DEV_PROGRAM_ID: &str = "FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL";
pub(crate) const DEFAULT_RPC: &str = "http://127.0.0.1:8899";

#[derive(Clone, Debug, Args)]
pub(crate) struct ChainArgs {
    /// JSON-RPC endpoint [default: $TIMESCALES_RPC_URL, else
    /// http://127.0.0.1:8899].
    #[arg(long, global = true)]
    pub(crate) rpc: Option<String>,
    /// Settlement program id [default: $TIMESCALES_PROGRAM_ID, else the dev
    /// id FDQq...ytQL].
    #[arg(long, global = true)]
    pub(crate) program: Option<String>,
    /// Compute-unit price in micro-lamports.
    #[arg(long, default_value_t = 0, global = true)]
    pub(crate) priority_fee: u64,
}

impl ChainArgs {
    pub(crate) fn rpc_url(&self) -> String {
        self.rpc
            .clone()
            .or_else(|| std::env::var("TIMESCALES_RPC_URL").ok())
            .unwrap_or_else(|| DEFAULT_RPC.to_owned())
    }

    pub(crate) fn program_id(&self) -> Result<Key> {
        let s = self
            .program
            .clone()
            .or_else(|| std::env::var("TIMESCALES_PROGRAM_ID").ok())
            .unwrap_or_else(|| DEV_PROGRAM_ID.to_owned());
        parse_key(&s).context("--program")
    }

    pub(crate) fn connect(&self) -> Result<Chain> {
        Chain::connect(&self.rpc_url(), self.program_id()?, self.priority_fee)
    }
}

/// Journal of one CLI invocation. Nothing survives the process: an
/// operator re-runs a command after observing chain state, and every
/// command observes before it acts.
#[derive(Debug, Default)]
struct MemoryJournal {
    next: AtomicI64,
    landed: AtomicU64,
}

impl TxJournal for MemoryJournal {
    fn before_send(&self, _rec: TxRecord) -> BoxFuture<'_, Result<i64, JournalError>> {
        let id = self.next.fetch_add(1, Ordering::AcqRel) + 1;
        Box::pin(async move { Ok(id) })
    }

    fn resolved(&self, _id: i64, outcome: TxOutcome) -> BoxFuture<'_, Result<(), JournalError>> {
        if let TxOutcome::Landed { slot } | TxOutcome::Failed { slot, .. } = outcome {
            self.landed.fetch_max(slot, Ordering::AcqRel);
        }
        Box::pin(async { Ok(()) })
    }

    fn pending(&self) -> BoxFuture<'_, Result<Vec<TxRecord>, JournalError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn last_landed_slot(&self) -> BoxFuture<'_, Result<u64, JournalError>> {
        let slot = self.landed.load(Ordering::Acquire);
        Box::pin(async move { Ok(slot) })
    }
}

pub(crate) struct Chain {
    pub(crate) rpc: Arc<dyn SolanaRpc>,
    pub(crate) sender: Arc<TxSender>,
    pub(crate) program: Key,
}

impl Chain {
    pub(crate) fn connect(url: &str, program: Key, priority_fee: u64) -> Result<Self> {
        let rpc: Arc<dyn SolanaRpc> = Arc::new(
            HttpRpc::new(vec![url.to_owned()], Duration::from_secs(15))
                .map_err(|e| anyhow::anyhow!("RPC {url}: {e}"))?,
        );
        let fees = FeePolicy {
            mode: FeeMode::Fixed(priority_fee),
            percentile: 75,
            max_micro_lamports: priority_fee.max(200_000),
            cu_margin_pct: 20,
        };
        let sender = Arc::new(TxSender::new(
            rpc.clone(),
            fees,
            Arc::new(MemoryJournal::default()),
            Duration::from_millis(400),
            Duration::from_secs(60),
        ));
        Ok(Self {
            rpc,
            sender,
            program,
        })
    }

    pub(crate) async fn send(
        &self,
        op: TxOp,
        ixs: Vec<Ix>,
        payer: Arc<dyn TxSigner>,
        extra: Vec<Arc<dyn TxSigner>>,
    ) -> Result<Landed> {
        self.sender
            .send(op, ixs, payer, extra)
            .await
            .map_err(|e| anyhow::anyhow!("{}: {e}", op.as_str()))
    }

    pub(crate) fn market_chain(&self, market: Key) -> SolanaMarketChain {
        SolanaMarketChain::new(
            self.rpc.clone(),
            self.sender.clone(),
            self.program,
            market,
            MarketChainConfig::default(),
        )
    }

    pub(crate) async fn account(&self, key: Key, level: Level) -> Result<Option<AccountData>> {
        Ok(self.rpc.get_account(key, level, None).await?)
    }

    /// The Market account at `market`, owned by the program.
    pub(crate) async fn market(&self, market: Key) -> Result<(MarketAccount, u64)> {
        let acc = self
            .account(market, Level::Confirmed)
            .await?
            .with_context(|| format!("no account at {}", b58(&market)))?;
        if acc.owner != self.program {
            bail!(
                "{} is owned by {}, not the settlement program {}",
                b58(&market),
                b58(&acc.owner),
                b58(&self.program)
            );
        }
        let m = timescales_chain::program::decode_market(&acc.data)
            .map_err(|e| anyhow::anyhow!("{} is not a v2 Market account: {e}", b58(&market)))?;
        Ok((m, acc.context_slot))
    }

    pub(crate) async fn batch(
        &self,
        market: Key,
        epoch: u64,
    ) -> Result<Option<(Key, BatchAccount)>> {
        let (address, _) = timescales_chain::program::batch_pda(&self.program, &market, epoch)?;
        let Some(acc) = self.account(address, Level::Confirmed).await? else {
            return Ok(None);
        };
        if acc.owner != self.program {
            return Ok(None);
        }
        let b = timescales_chain::program::decode_batch(&acc.data)
            .map_err(|e| anyhow::anyhow!("batch {epoch}: {e}"))?;
        Ok(Some((address, b)))
    }

    pub(crate) async fn blockhash(&self) -> Result<[u8; 32]> {
        Ok(self.rpc.latest_blockhash(Level::Finalized).await?.0)
    }

    pub(crate) async fn genesis_hash(&self) -> Result<[u8; 32]> {
        Ok(self.rpc.genesis_hash().await?)
    }
}

/// The blockhash an unsigned transaction is built with: `--blockhash` when
/// given (offline signing flows), else the cluster's latest finalized one.
pub(crate) async fn blockhash_for(args: &ChainArgs, given: Option<&str>) -> Result<[u8; 32]> {
    match given {
        Some(s) => parse_key(s).context("--blockhash"),
        None => args.connect()?.blockhash().await,
    }
}
