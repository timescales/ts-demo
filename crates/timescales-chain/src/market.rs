//! [`SolanaMarketChain`]: every program flow of one market as an
//! idempotent observe-then-act loop.
//!
//! ```text
//! loop {
//!   attempts += 1, past max_attempts => Tx(GaveUp)        every iteration counts
//!   attempts > 1 => sleep(full jitter of backoff x 2^(attempts - 2), <= max_backoff)
//!   observe market + batch at Confirmed, minContextSlot = highest slot seen
//!   done in the observation        => the observed outcome
//!   impossible in the observation  => a typed outcome
//!   send one transaction (TxSender: journal before send, preflight on)
//!     landed => continue (the next observation confirms the effect)
//!     a program error the next observation explains => continue
//!     another program error => ChainError::Program or a typed rejection
//!     expired, unknown or refused by the node => continue
//! }
//! ```
//!
//! The adapter never re-sends after an ambiguous outcome without observing
//! first, and never reads older state than it has seen: every Confirmed
//! read carries the highest slot of any landed transaction or earlier
//! observation as `minContextSlot`, so a failover provider that is behind
//! cannot answer.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::program::errors::{self, ProgramFailure, ProgramKind};
use crate::program::{
    AbortReason, BatchAccount, BatchStatus, ClientError, GovernanceChange, Ix, LAYOUT_VERSION,
    MarketAccount, TRADER_LEN, TRADER_TAG, TimescalesProgramError,
};
use futures::StreamExt;
use rand::Rng;
use timescales_auction::receipts::{ExecutionReceipt, cosign_digest};
use timescales_auction::settlement::SettlementBatch;
use timescales_core::crypto::{Signature, verify_digest};
use timescales_core::{Decode, EpochId, Hash32};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::{
    AbortOutcome, AccountData, Address, BatchPredicate, BoxFuture, ChainError, ChangeOutcome,
    CommitOutcome, CosignOutcome, Filter, Level, MarketChain, PostOutcome, RevealOutcome, RpcError,
    SendOptions, SettleProgress, SettleStage, SolanaRpc, TraderEntry, TraderSnapshot, TxError,
    TxErrorDetail, TxOp, TxSender, TxSigner,
};

/// Slots after `commit_slot + d` in which the beacon can be revealed.
const REVEAL_WINDOW: u64 = 400;
/// Epochs a terminal batch is kept before `ReclaimBatch`.
const BATCH_RETENTION: u64 = 1024;
const SYSTEM_PROGRAM: Address = [0; 32];

/// Program errors after which every operation observes again: the
/// chain moved, and the next observation shows how.
const OBSERVE_AGAIN: [TimescalesProgramError; 4] = [
    TimescalesProgramError::OutOfOrder,
    TimescalesProgramError::WrongStatus,
    TimescalesProgramError::DuplicateLeaf,
    TimescalesProgramError::AlreadyCosigned,
];

/// The chain knobs (`[solana]` and `[execution]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketChainConfig {
    /// Loop iterations per operation, each one counted (`tx_max_attempts`).
    pub max_attempts: u32,
    /// Base of the full-jitter backoff between iterations
    /// (`retry_backoff_ms`).
    pub retry_backoff: Duration,
    /// Longest backoff sleep.
    pub max_backoff: Duration,
    /// Poll interval of [`MarketChain::wait_batch`].
    pub poll_interval: Duration,
    /// Verify or apply transactions in flight at once (`max_parallel_txs`).
    pub max_parallel_txs: usize,
}

impl Default for MarketChainConfig {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            retry_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(8),
            poll_interval: Duration::from_millis(400),
            max_parallel_txs: 16,
        }
    }
}

/// [`MarketChain`] over an `Arc<dyn SolanaRpc>` (a [`QuorumRpc`](crate::QuorumRpc) for
/// release-critical reads), a [`TxSender`] and the `program`
/// builders.
pub struct SolanaMarketChain {
    rpc: Arc<dyn SolanaRpc>,
    sender: Arc<TxSender>,
    program: Address,
    market: Address,
    cfg: MarketChainConfig,
    seen: AtomicU64,
    /// Trader PDAs derived so far. Settlement names the same traders on
    /// every pass of its loop, and a derivation is a hash per bump tried.
    trader_pdas: parking_lot::Mutex<HashMap<Address, Address>>,
}

impl fmt::Debug for SolanaMarketChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolanaMarketChain")
            .field("program", &bs58::encode(self.program).into_string())
            .field("market", &bs58::encode(self.market).into_string())
            .field("cfg", &self.cfg)
            .field("seen", &self.seen)
            .finish_non_exhaustive()
    }
}

/// One consistent read of the market and, optionally, a batch.
struct Observed {
    slot: u64,
    market: MarketAccount,
    batch: Option<BatchAccount>,
}

/// `crate::program::verify_deltas` or `apply_deltas`.
type DeltaBuilder = fn(
    &Address,
    &Address,
    &Address,
    u64,
    &[crate::program::Leaf],
    &mut dyn FnMut(&Address) -> Result<Address, ClientError>,
) -> Result<Ix, ClientError>;

/// What one send means for the loop.
enum Sent {
    Landed(u64),
    /// Did not land (refused, or its blockhash expired): observe again.
    Retry(String),
    /// May have landed (no outcome before the confirmation deadline):
    /// observe again.
    Unknown(String),
    /// A program error the loop cannot explain by observing.
    Program(ProgramFailure),
    /// Any other failure. Returned as is.
    Failed(TxError),
}

/// Counts loop iterations and sleeps between them.
struct Attempts {
    cfg: MarketChainConfig,
    n: u32,
    last: String,
}

impl Attempts {
    fn new(cfg: MarketChainConfig) -> Self {
        Self {
            cfg,
            n: 0,
            last: String::new(),
        }
    }

    async fn next(&mut self) -> Result<(), ChainError> {
        if self.n >= self.cfg.max_attempts {
            return Err(ChainError::Tx(TxError::GaveUp {
                attempts: self.n,
                last: std::mem::take(&mut self.last),
            }));
        }
        self.n += 1;
        if self.n > 1 {
            let doubling = 1u32 << (self.n - 2).min(16);
            let ceiling = self
                .cfg
                .retry_backoff
                .saturating_mul(doubling)
                .min(self.cfg.max_backoff);
            let sleep = rand::thread_rng().gen_range(Duration::ZERO..=ceiling);
            tokio::time::sleep(sleep).await;
        }
        Ok(())
    }

    fn failed(&mut self, why: impl fmt::Display) {
        self.last = why.to_string();
    }
}

/// Errors a later iteration may not see again: RPC failures and provider
/// disagreement.
fn transient(e: &ChainError) -> bool {
    matches!(e, ChainError::Rpc(_) | ChainError::Disagree)
}

fn read_error(e: RpcError) -> ChainError {
    match e {
        RpcError::Disagree => ChainError::Disagree,
        e => ChainError::Rpc(e),
    }
}

fn program_error(f: &ProgramFailure) -> ChainError {
    ChainError::Program {
        ix: f.ix_index,
        program: f.program,
        code: f.code,
        name: f.name.unwrap_or("unknown"),
    }
}

/// The settlement-program error of a failure, if the program itself failed
/// with a known code.
fn settlement_error(f: &ProgramFailure) -> Option<TimescalesProgramError> {
    f.error.filter(|_| f.program == ProgramKind::Settlement)
}

/// The kind of a between-batches change that is due at `slot`: it blocks
/// `CommitBatch` (`ChangeDue`) until applied.
fn due_change(m: &MarketAccount, slot: u64) -> Option<u8> {
    m.pending
        .as_ref()
        .filter(|p| p.change.between_batches() && slot >= p.eta_slot)
        .map(|p| p.change.kind())
}

/// Whether `m` already holds what `change` sets.
fn change_applied(m: &MarketAccount, change: &GovernanceChange) -> bool {
    match change {
        GovernanceChange::SetRelay(k) => m.relay == *k,
        GovernanceChange::SetExecutors { keys, quorum } => {
            m.executors
                .iter()
                .enumerate()
                .all(|(i, slot)| keys.get(i).map_or(*slot == [0; 32], |k| slot == k))
                && m.receipt_quorum == *quorum
        }
        GovernanceChange::SetCommitteeDigest(d) => m.committee_digest == *d,
        GovernanceChange::SetAdmin(k) => m.pending_admin == Some(*k) || m.admin == *k,
        GovernanceChange::SetTimings {
            beacon_delay_slots,
            exec_timeout_slots,
            settle_timeout_slots,
        } => {
            m.beacon_delay_slots == *beacon_delay_slots
                && m.exec_timeout_slots == *exec_timeout_slots
                && m.settle_timeout_slots == *settle_timeout_slots
        }
        GovernanceChange::SetTimelock(slots) => m.timelock_slots == *slots,
    }
}

fn holds(until: BatchPredicate, b: &BatchAccount, m: &MarketAccount) -> bool {
    match until {
        BatchPredicate::Exists => true,
        BatchPredicate::AtLeast(status) => b.status >= status,
        BatchPredicate::Terminal => b.status.is_terminal(),
        BatchPredicate::CosignsAtLeast(n) => {
            (b.cosign_bitmap & m.live_slots()).count_ones() >= u32::from(n)
        }
    }
}

fn progress(tx: &mpsc::Sender<SettleProgress>, stage: SettleStage, done: u32, total: u32) {
    // Progress is informational: a full or closed channel never holds up
    // settlement.
    let _ = tx.try_send(SettleProgress { stage, done, total });
}

impl SolanaMarketChain {
    pub fn new(
        rpc: Arc<dyn SolanaRpc>,
        sender: Arc<TxSender>,
        program: Address,
        market: Address,
        cfg: MarketChainConfig,
    ) -> Self {
        Self {
            rpc,
            sender,
            program,
            market,
            cfg,
            seen: AtomicU64::new(0),
            trader_pdas: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    pub fn program(&self) -> Address {
        self.program
    }

    /// The slot every Confirmed or Processed read of this adapter must have
    /// reached (`minContextSlot`): the highest of its Confirmed
    /// observations, of the transactions its sender saw land (including
    /// those `resolve_pending` resolved at startup) and of
    /// [`observe_from`](Self::observe_from).
    pub fn seen_slot(&self) -> u64 {
        self.seen
            .load(Ordering::Acquire)
            .max(self.sender.last_landed_slot())
    }

    /// Raises [`seen_slot`](Self::seen_slot) to `slot`, for example to the
    /// last landed slot in the node's transaction journal at startup, so a
    /// provider that is behind cannot answer the first reads with state
    /// older than this process already acted on.
    pub fn observe_from(&self, slot: u64) {
        self.saw(slot);
    }

    fn saw(&self, slot: u64) {
        self.seen.fetch_max(slot, Ordering::AcqRel);
    }

    fn min_slot(&self, level: Level) -> Option<u64> {
        // A Finalized read cannot be held to a Confirmed slot: it would fail
        // until finalization catches up.
        let seen = self.seen_slot();
        (level != Level::Finalized && seen > 0).then_some(seen)
    }

    fn batch_key(&self, epoch: u64) -> Result<Address, ChainError> {
        crate::program::batch_pda(&self.program, &self.market, epoch)
            .map(|(k, _)| k)
            .map_err(ChainError::Decode)
    }

    fn decode_market(&self, a: Option<AccountData>) -> Result<MarketAccount, ChainError> {
        let a = a.ok_or(ChainError::Inconsistent("market account not found"))?;
        if a.owner != self.program {
            return Err(ChainError::Inconsistent(
                "market account is not owned by the program",
            ));
        }
        crate::program::decode_market(&a.data).map_err(ChainError::Decode)
    }

    /// `None` for no account, or one closed and handed back to the System
    /// program.
    fn decode_batch(
        &self,
        a: Option<AccountData>,
        epoch: u64,
    ) -> Result<Option<BatchAccount>, ChainError> {
        let Some(a) = a else { return Ok(None) };
        if a.owner == SYSTEM_PROGRAM {
            return Ok(None);
        }
        if a.owner != self.program {
            return Err(ChainError::Inconsistent(
                "batch account is not owned by the program",
            ));
        }
        let b = crate::program::decode_batch(&a.data).map_err(ChainError::Decode)?;
        if b.market != self.market || b.epoch != epoch {
            return Err(ChainError::Inconsistent(
                "batch account names another market or epoch",
            ));
        }
        Ok(Some(b))
    }

    /// The market and, with `epoch`, its batch, in one read at `level`.
    async fn read(&self, epoch: Option<u64>, level: Level) -> Result<Observed, ChainError> {
        let mut keys = vec![self.market];
        if let Some(e) = epoch {
            keys.push(self.batch_key(e)?);
        }
        let (slot, accounts) = self
            .rpc
            .get_multiple_accounts(keys, level, self.min_slot(level))
            .await
            .map_err(read_error)?;
        // A Processed slot is not one the Confirmed view has reached yet, so
        // it must not become the floor of later Confirmed reads.
        if level == Level::Confirmed {
            self.saw(slot);
        }
        let mut accounts = accounts.into_iter();
        let market = self.decode_market(accounts.next().flatten())?;
        let batch = match epoch {
            Some(e) => self.decode_batch(accounts.next().flatten(), e)?,
            None => None,
        };
        Ok(Observed {
            slot,
            market,
            batch,
        })
    }

    /// One observation of the loop. A transient failure counts the attempt
    /// and returns `None`.
    async fn observe(
        &self,
        epoch: Option<u64>,
        attempts: &mut Attempts,
    ) -> Result<Option<Observed>, ChainError> {
        match self.read(epoch, Level::Confirmed).await {
            Ok(o) => Ok(Some(o)),
            Err(e) if transient(&e) => {
                attempts.failed(&e);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Sends one transaction and says what it means for the loop. Program
    /// errors in `observe_again` (besides [`OBSERVE_AGAIN`]) make the loop
    /// observe again.
    async fn send(
        &self,
        epoch: Option<u64>,
        op: TxOp,
        ixs: Vec<Ix>,
        payer: Arc<dyn TxSigner>,
        observe_again: &[TimescalesProgramError],
    ) -> Sent {
        let opts = SendOptions {
            market: self.market,
            epoch,
            op,
            min_slot: self.min_slot(Level::Confirmed),
        };
        let (err, logs, original) = match self.sender.send_with(opts, ixs, payer, vec![]).await {
            Ok(landed) => {
                self.saw(landed.slot);
                return Sent::Landed(landed.slot);
            }
            Err(TxError::Preflight { err, logs }) => {
                let original = TxError::Preflight {
                    err: err.clone(),
                    logs: logs.clone(),
                };
                (err, Some(logs), original)
            }
            Err(TxError::Failed {
                signature,
                slot,
                err,
            }) => {
                self.saw(slot);
                let original = TxError::Failed {
                    signature,
                    slot,
                    err: err.clone(),
                };
                (err, None, original)
            }
            Err(e @ TxError::Timeout { .. }) => return Sent::Unknown(e.to_string()),
            Err(e @ (TxError::Expired { .. } | TxError::Rpc(_))) => {
                return Sent::Retry(e.to_string());
            }
            Err(e) => return Sent::Failed(e),
        };
        self.classify(&err, logs.as_deref(), observe_again, original)
    }

    /// `logs` are those of a preflight or simulation. A transaction that
    /// landed and failed has none.
    fn classify(
        &self,
        err: &TxErrorDetail,
        logs: Option<&[String]>,
        observe_again: &[TimescalesProgramError],
        original: TxError,
    ) -> Sent {
        let out_of_units = logs.map_or_else(|| err.budget_exceeded(), |l| err.out_of_units(l));
        if err.blockhash_not_found() || err.already_processed() || out_of_units {
            return Sent::Retry(err.message.clone());
        }
        let (Some(ix), Some(code)) = (err.ix_index, err.custom) else {
            return Sent::Failed(original);
        };
        let failure = errors::decode(ix, &self.program, code, logs.unwrap_or_default());
        match settlement_error(&failure) {
            Some(e) if OBSERVE_AGAIN.contains(&e) || observe_again.contains(&e) => {
                Sent::Retry(e.to_string())
            }
            _ => Sent::Program(failure),
        }
    }

    async fn committed(
        &self,
        epoch: u64,
        root: Hash32,
        count: u32,
        terms: Hash32,
        payer: Arc<dyn TxSigner>,
    ) -> Result<CommitOutcome, ChainError> {
        use TimescalesProgramError as E;
        let ix = crate::program::commit_batch(
            &self.program,
            &payer.address(),
            &self.market,
            epoch,
            &root,
            count,
            &terms,
        )
        .map_err(ChainError::Decode)?;
        let mut attempts = Attempts::new(self.cfg);
        loop {
            attempts.next().await?;
            let Some(o) = self.observe(Some(epoch), &mut attempts).await? else {
                continue;
            };
            let m = &o.market;
            if let Some(b) = &o.batch {
                return Ok(
                    if (b.root, b.count, b.terms_digest) == (root, count, terms) {
                        CommitOutcome::Committed {
                            slot: b.commit_slot,
                        }
                    } else {
                        CommitOutcome::Equivocation {
                            onchain_root: b.root,
                        }
                    },
                );
            }
            let (last_committed, last_settled) = (m.last_committed, m.last_settled);
            if last_committed.checked_add(1) != Some(epoch) {
                return Ok(CommitOutcome::OutOfOrder {
                    last_committed,
                    last_settled,
                });
            }
            if m.in_flight() {
                return Ok(CommitOutcome::InFlight {
                    last_committed,
                    last_settled,
                });
            }
            if m.halted {
                return Ok(CommitOutcome::Halted);
            }
            if let Some(kind) = due_change(m, o.slot) {
                return Ok(CommitOutcome::ChangeDue { kind });
            }
            let again = [E::InFlight, E::Halted, E::ChangeDue];
            match self
                .send(
                    Some(epoch),
                    TxOp::Commit,
                    vec![ix.clone()],
                    payer.clone(),
                    &again,
                )
                .await
            {
                Sent::Landed(_) => {}
                Sent::Retry(why) | Sent::Unknown(why) => attempts.failed(why),
                Sent::Program(f) => return Err(program_error(&f)),
                Sent::Failed(e) => return Err(ChainError::Tx(e)),
            }
        }
    }

    async fn revealed(
        &self,
        epoch: u64,
        payer: Arc<dyn TxSigner>,
    ) -> Result<RevealOutcome, ChainError> {
        use TimescalesProgramError as E;
        let ix =
            crate::program::reveal_beacon(&self.program, &payer.address(), &self.market, epoch)
                .map_err(ChainError::Decode)?;
        let mut attempts = Attempts::new(self.cfg);
        loop {
            attempts.next().await?;
            let Some(o) = self.observe(Some(epoch), &mut attempts).await? else {
                continue;
            };
            let b = o
                .batch
                .as_ref()
                .ok_or(ChainError::Inconsistent("no batch account for the epoch"))?;
            match b.status {
                BatchStatus::Settled | BatchStatus::Aborted => {
                    return Ok(RevealOutcome::Terminal(b.status));
                }
                BatchStatus::BeaconRevealed
                | BatchStatus::ReceiptPosted
                | BatchStatus::Verified => {
                    return Ok(RevealOutcome::Revealed {
                        beacon: b.beacon,
                        slot: b.reveal_slot,
                    });
                }
                BatchStatus::Committed => {}
            }
            let d = u64::from(o.market.beacon_delay_slots);
            if o.slot > b.commit_slot + d + REVEAL_WINDOW {
                return Ok(RevealOutcome::Expired);
            }
            // Both SlotHashes inputs exist once the slot is past
            // `commit_slot + 2d`.
            let ready = b.commit_slot + 2 * d + 1;
            if o.slot < ready {
                return Ok(RevealOutcome::NotReady {
                    slots_left: ready - o.slot,
                });
            }
            match self
                .send(
                    Some(epoch),
                    TxOp::Reveal,
                    vec![ix.clone()],
                    payer.clone(),
                    &[E::BeaconNotReady],
                )
                .await
            {
                Sent::Landed(_) => {}
                Sent::Retry(why) | Sent::Unknown(why) => attempts.failed(why),
                Sent::Program(f) if settlement_error(&f) == Some(E::BeaconExpired) => {
                    return Ok(RevealOutcome::Expired);
                }
                Sent::Program(f) => return Err(program_error(&f)),
                Sent::Failed(e) => return Err(ChainError::Tx(e)),
            }
        }
    }

    async fn waited(
        &self,
        epoch: u64,
        until: BatchPredicate,
        level: Level,
        deadline: Instant,
    ) -> Result<BatchAccount, ChainError> {
        loop {
            match self.read(Some(epoch), level).await {
                Ok(Observed {
                    market,
                    batch: Some(b),
                    ..
                }) if holds(until, &b, &market) => return Ok(b),
                Ok(_) => {}
                Err(e) if transient(&e) => tracing::debug!(error = %e, "wait_batch read failed"),
                Err(e) => return Err(e),
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(ChainError::Rpc(RpcError::Timeout));
            }
            tokio::time::sleep_until((now + self.cfg.poll_interval).min(deadline)).await;
        }
    }

    async fn posted(
        &self,
        epoch: u64,
        header: [u8; 283],
        receipt: Vec<u8>,
        poster: Arc<dyn TxSigner>,
    ) -> Result<PostOutcome, ChainError> {
        let decoded = ExecutionReceipt::decode_exact(&receipt).map_err(|_| {
            ChainError::Decode(ClientError::InvalidArgument("receipt does not decode"))
        })?;
        let digest = decoded.digest();
        let ixs = vec![
            crate::program::ed25519_verify(&decoded.executor.0, &digest, &decoded.signature.0),
            crate::program::post_receipt(
                &self.program,
                &poster.address(),
                &self.market,
                epoch,
                &header,
                &receipt,
            )
            .map_err(ChainError::Decode)?,
        ];
        let mut sent = false;
        let mut attempts = Attempts::new(self.cfg);
        loop {
            attempts.next().await?;
            let Some(o) = self.observe(Some(epoch), &mut attempts).await? else {
                continue;
            };
            let b = o
                .batch
                .as_ref()
                .ok_or(ChainError::Inconsistent("no batch account for the epoch"))?;
            if b.receipt == digest {
                return Ok(if sent {
                    PostOutcome::Posted {
                        slot: b.receipt_slot,
                    }
                } else {
                    PostOutcome::AlreadyPosted { same_receipt: true }
                });
            }
            match b.status {
                BatchStatus::Committed | BatchStatus::Settled | BatchStatus::Aborted => {
                    return Ok(PostOutcome::WrongStatus(b.status));
                }
                BatchStatus::ReceiptPosted | BatchStatus::Verified => {
                    return Ok(PostOutcome::AlreadyPosted {
                        same_receipt: false,
                    });
                }
                BatchStatus::BeaconRevealed => {}
            }
            match self
                .send(Some(epoch), TxOp::Post, ixs.clone(), poster.clone(), &[])
                .await
            {
                Sent::Landed(_) => sent = true,
                Sent::Unknown(why) => {
                    sent = true;
                    attempts.failed(why);
                }
                Sent::Retry(why) => attempts.failed(why),
                Sent::Program(f) => {
                    return match settlement_error(&f) {
                        Some(e) => Ok(PostOutcome::Rejected(e)),
                        None => Err(program_error(&f)),
                    };
                }
                Sent::Failed(e) => return Err(ChainError::Tx(e)),
            }
        }
    }

    async fn cosigned(
        &self,
        epoch: u64,
        executor: Address,
        signature: [u8; 64],
        payer: Arc<dyn TxSigner>,
    ) -> Result<CosignOutcome, ChainError> {
        let cosign =
            crate::program::cosign_receipt(&self.program, &payer.address(), &self.market, epoch)
                .map_err(ChainError::Decode)?;
        let mut landed = None;
        let mut attempts = Attempts::new(self.cfg);
        loop {
            attempts.next().await?;
            let Some(o) = self.observe(Some(epoch), &mut attempts).await? else {
                continue;
            };
            let b = o
                .batch
                .as_ref()
                .ok_or(ChainError::Inconsistent("no batch account for the epoch"))?;
            let bit = o.market.executor_slot(&executor).map(|i| 1u8 << i);
            let set = bit.is_some_and(|bit| b.cosign_bitmap & bit != 0);
            if set && matches!(b.status, BatchStatus::ReceiptPosted | BatchStatus::Verified) {
                return Ok(match landed {
                    Some(slot) => CosignOutcome::Cosigned { slot },
                    None => CosignOutcome::AlreadyCosigned,
                });
            }
            if b.status != BatchStatus::ReceiptPosted {
                return Ok(CosignOutcome::WrongStatus(b.status));
            }
            let digest = cosign_digest(
                &self.market,
                EpochId(epoch),
                &b.header_digest,
                &b.outcome_digest,
            );
            // A signature over another outcome (or no valid signature at
            // all) cannot co-sign the posted one.
            if verify_digest(&executor, &digest, &Signature(signature)).is_err() {
                return Ok(CosignOutcome::OutcomeMismatch);
            }
            let ixs = vec![
                crate::program::ed25519_verify(&executor, &digest, &signature),
                cosign.clone(),
            ];
            match self
                .send(Some(epoch), TxOp::Cosign, ixs, payer.clone(), &[])
                .await
            {
                Sent::Landed(slot) => landed = Some(slot),
                Sent::Retry(why) | Sent::Unknown(why) => attempts.failed(why),
                Sent::Program(f) => {
                    return match settlement_error(&f) {
                        Some(e) => Ok(CosignOutcome::Rejected(e)),
                        None => Err(program_error(&f)),
                    };
                }
                Sent::Failed(e) => return Err(ChainError::Tx(e)),
            }
        }
    }

    async fn settled(
        &self,
        epoch: u64,
        settlement: Arc<SettlementBatch>,
        payer: Arc<dyn TxSigner>,
        progress_tx: mpsc::Sender<SettleProgress>,
    ) -> Result<u64, ChainError> {
        use TimescalesProgramError as E;
        let leaves = crate::program::leaves(&settlement).map_err(ChainError::Decode)?;
        let payer_key = payer.address();
        let batch_key = self.batch_key(epoch)?;
        let mut closed_at = None;
        let mut attempts = Attempts::new(self.cfg);
        loop {
            attempts.next().await?;
            let Some(o) = self.observe(Some(epoch), &mut attempts).await? else {
                continue;
            };
            let m = &o.market;
            let b = o
                .batch
                .as_ref()
                .ok_or(ChainError::Inconsistent("no batch account for the epoch"))?;
            let total = b.settlement_count;
            let (stage, op, txs) = match b.status {
                BatchStatus::Settled => {
                    progress(&progress_tx, SettleStage::Closing, 1, 1);
                    // The close slot is known from this call's CloseBatch,
                    // or from the market's last progress while no later
                    // batch is committed (the program moves it only on
                    // CommitBatch, CloseBatch and aborts). Otherwise this
                    // observation's slot, which is at or after the close.
                    let still_last = m.last_settled == epoch && m.last_committed == epoch;
                    return Ok(closed_at
                        .or(still_last.then_some(m.last_progress_slot))
                        .unwrap_or(o.slot));
                }
                BatchStatus::Aborted => return Err(ChainError::Inconsistent("batch was aborted")),
                BatchStatus::Committed | BatchStatus::BeaconRevealed => {
                    return Err(ChainError::Inconsistent("batch has no receipt"));
                }
                BatchStatus::ReceiptPosted => {
                    if settlement.root() != b.settlement_root
                        || settlement.deltas.len() != total as usize
                        || settlement.fees.0 != b.fees
                        || settlement.market.0 != m.market_id
                        || settlement.epoch.0 != epoch
                    {
                        return Err(ChainError::Inconsistent(
                            "settlement does not match the posted receipt",
                        ));
                    }
                    if !m.quorum_met(b.cosign_bitmap) {
                        return Err(ChainError::Inconsistent("receipt quorum not met on chain"));
                    }
                    let missing = b.missing_verified();
                    if missing.is_empty() {
                        progress(&progress_tx, SettleStage::Finalizing, 0, 1);
                        let ix = crate::program::finalize(
                            &self.program,
                            &payer_key,
                            &self.market,
                            &batch_key,
                        );
                        (SettleStage::Finalizing, TxOp::Finalize, vec![vec![ix]])
                    } else {
                        progress(
                            &progress_tx,
                            SettleStage::Verifying,
                            b.verified_count,
                            total,
                        );
                        let ixs = self.delta_ixs(
                            &leaves,
                            &missing,
                            &payer_key,
                            epoch,
                            crate::program::verify_deltas_with,
                        )?;
                        (SettleStage::Verifying, TxOp::Verify, ixs)
                    }
                }
                BatchStatus::Verified => {
                    let missing = b.missing_applied();
                    if missing.is_empty() {
                        progress(&progress_tx, SettleStage::Closing, 0, 1);
                        let ix = crate::program::close_batch(
                            &self.program,
                            &payer_key,
                            &self.market,
                            &batch_key,
                        );
                        (SettleStage::Closing, TxOp::Close, vec![vec![ix]])
                    } else {
                        progress(&progress_tx, SettleStage::Applying, b.applied_count, total);
                        let ixs = self.delta_ixs(
                            &leaves,
                            &missing,
                            &payer_key,
                            epoch,
                            crate::program::apply_deltas_with,
                        )?;
                        (SettleStage::Applying, TxOp::Apply, ixs)
                    }
                }
            };
            let again = [E::Incomplete];
            let results: Vec<Sent> = futures::stream::iter(txs)
                .map(|ixs| self.send(Some(epoch), op, ixs, payer.clone(), &again))
                .buffer_unordered(self.cfg.max_parallel_txs.max(1))
                .collect()
                .await;
            for sent in results {
                match sent {
                    Sent::Landed(slot) => {
                        if stage == SettleStage::Closing {
                            closed_at = Some(slot);
                        }
                    }
                    Sent::Retry(why) | Sent::Unknown(why) => attempts.failed(why),
                    Sent::Program(f) => return Err(program_error(&f)),
                    Sent::Failed(e) => return Err(ChainError::Tx(e)),
                }
            }
        }
    }

    /// One `VerifyDeltas` or `ApplyDeltas` instruction per chunk of the
    /// `missing` leaves, chunked by `plan_delta_chunks` (<= 1232 bytes).
    fn delta_ixs(
        &self,
        leaves: &[crate::program::Leaf],
        missing: &[u32],
        payer: &Address,
        epoch: u64,
        build: DeltaBuilder,
    ) -> Result<Vec<Vec<Ix>>, ChainError> {
        let selected: Vec<crate::program::Leaf> = missing
            .iter()
            .map(|&i| {
                leaves
                    .get(i as usize)
                    .cloned()
                    .ok_or(ChainError::Inconsistent(
                        "batch counts more leaves than the settlement has",
                    ))
            })
            .collect::<Result<_, _>>()?;
        let mut pdas = self.trader_pdas.lock();
        let mut trader = |owner: &Address| -> Result<Address, ClientError> {
            if let Some(pda) = pdas.get(owner) {
                return Ok(*pda);
            }
            let pda = crate::program::trader_pda(&self.program, &self.market, owner)?.0;
            pdas.insert(*owner, pda);
            Ok(pda)
        };
        crate::program::plan_delta_chunks(&selected, payer, true)
            .into_iter()
            .map(|range| {
                build(
                    &self.program,
                    payer,
                    &self.market,
                    epoch,
                    &selected[range],
                    &mut trader,
                )
                .map(|ix| vec![ix])
                .map_err(ChainError::Decode)
            })
            .collect()
    }

    async fn aborted(
        &self,
        epoch: u64,
        reason: AbortReason,
        signer: Arc<dyn TxSigner>,
    ) -> Result<AbortOutcome, ChainError> {
        use TimescalesProgramError as E;
        let ix = crate::program::abort_batch(
            &self.program,
            &self.market,
            &self.batch_key(epoch)?,
            &signer.address(),
            reason,
        );
        let mut attempts = Attempts::new(self.cfg);
        loop {
            attempts.next().await?;
            let Some(o) = self.observe(Some(epoch), &mut attempts).await? else {
                continue;
            };
            let m = &o.market;
            let b = o
                .batch
                .as_ref()
                .ok_or(ChainError::Inconsistent("no batch account for the epoch"))?;
            let status = b.status;
            match status {
                BatchStatus::Aborted => {
                    return Ok(AbortOutcome::Aborted {
                        reason: b.abort_reason.unwrap_or(reason),
                    });
                }
                BatchStatus::Settled => return Ok(AbortOutcome::AlreadyTerminal(status)),
                _ => {}
            }
            // After the first apply no reason can abort.
            if b.applied_count > 0 {
                return Ok(AbortOutcome::Superseded(status));
            }
            let d = u64::from(m.beacon_delay_slots);
            let slot = o.slot;
            // `(precondition holds, deadline the slot must pass)`.
            let (applies, deadline) = match reason {
                AbortReason::Admin => (true, None),
                AbortReason::Relay => (
                    status == BatchStatus::Committed && slot < b.commit_slot + d,
                    None,
                ),
                AbortReason::BeaconExpired => (
                    status == BatchStatus::Committed,
                    Some(b.commit_slot + d + REVEAL_WINDOW),
                ),
                AbortReason::ExecTimeout => (
                    status == BatchStatus::BeaconRevealed,
                    Some(b.reveal_slot + m.exec_timeout_slots),
                ),
                AbortReason::SettleTimeout => (
                    matches!(status, BatchStatus::ReceiptPosted | BatchStatus::Verified),
                    Some(b.receipt_slot + m.settle_timeout_slots),
                ),
                AbortReason::QuorumTimeout => (
                    status == BatchStatus::ReceiptPosted && !m.quorum_met(b.cosign_bitmap),
                    Some(b.receipt_slot + m.exec_timeout_slots),
                ),
            };
            if !applies {
                return Ok(AbortOutcome::Superseded(status));
            }
            if let Some(deadline) = deadline.filter(|d| slot <= *d) {
                return Ok(AbortOutcome::NotAllowedYet {
                    slots_left: deadline + 1 - slot,
                });
            }
            // A relay abort that reaches the program after `commit_slot + d`
            // fails `Unauthorised`. The next observation shows it superseded.
            let mut again = vec![E::NotExpired];
            if reason == AbortReason::Relay && signer.address() == m.relay {
                again.push(E::Unauthorised);
            }
            match self
                .send(
                    Some(epoch),
                    TxOp::Abort,
                    vec![ix.clone()],
                    signer.clone(),
                    &again,
                )
                .await
            {
                Sent::Landed(_) => {}
                Sent::Retry(why) | Sent::Unknown(why) => attempts.failed(why),
                Sent::Program(f) => return Err(program_error(&f)),
                Sent::Failed(e) => return Err(ChainError::Tx(e)),
            }
        }
    }

    async fn change_applied(&self, payer: Arc<dyn TxSigner>) -> Result<ChangeOutcome, ChainError> {
        use TimescalesProgramError as E;
        let ix = crate::program::apply_change(&self.program, &payer.address(), &self.market);
        let mut seen: Option<GovernanceChange> = None;
        let mut attempts = Attempts::new(self.cfg);
        loop {
            attempts.next().await?;
            let Some(o) = self.observe(None, &mut attempts).await? else {
                continue;
            };
            let m = &o.market;
            let pending = m.pending.as_ref();
            // The change this call saw pending is gone: applied if the
            // market now holds it, otherwise cancelled.
            if let Some(change) = seen.take_if(|c| pending.is_none_or(|p| p.change != *c))
                && change_applied(m, &change)
            {
                return Ok(ChangeOutcome::Applied {
                    kind: change.kind(),
                });
            }
            let Some(p) = pending else {
                return Ok(ChangeOutcome::NothingDue);
            };
            seen = Some(p.change.clone());
            if o.slot < p.eta_slot {
                return Ok(ChangeOutcome::NotYet {
                    slots_left: p.eta_slot - o.slot,
                });
            }
            if p.change.between_batches() && m.in_flight() {
                return Ok(ChangeOutcome::InFlight);
            }
            let again = [E::Timelocked, E::InFlight, E::NoPendingChange];
            match self
                .send(
                    None,
                    TxOp::ApplyChange,
                    vec![ix.clone()],
                    payer.clone(),
                    &again,
                )
                .await
            {
                Sent::Landed(_) => {}
                Sent::Retry(why) | Sent::Unknown(why) => attempts.failed(why),
                Sent::Program(f) => return Err(program_error(&f)),
                Sent::Failed(e) => return Err(ChainError::Tx(e)),
            }
        }
    }

    async fn reclaimed(&self, epoch: u64, payer: Arc<dyn TxSigner>) -> Result<(), ChainError> {
        let batch_key = self.batch_key(epoch)?;
        let mut attempts = Attempts::new(self.cfg);
        loop {
            attempts.next().await?;
            let Some(o) = self.observe(Some(epoch), &mut attempts).await? else {
                continue;
            };
            let Some(b) = &o.batch else {
                return Ok(());
            };
            if !b.status.is_terminal() {
                return Err(ChainError::Inconsistent("batch is not terminal"));
            }
            if epoch.saturating_add(BATCH_RETENTION) > o.market.last_settled {
                return Err(ChainError::Inconsistent("batch retention not reached"));
            }
            let ix = crate::program::reclaim_batch(
                &self.program,
                &payer.address(),
                &self.market,
                &batch_key,
                &o.market.relay,
            );
            // `InvalidAccount`: the batch was closed (an earlier send of
            // this call landed late) or the relay changed since this
            // observation. The next one shows which.
            match self
                .send(
                    Some(epoch),
                    TxOp::Reclaim,
                    vec![ix],
                    payer.clone(),
                    &[TimescalesProgramError::InvalidAccount],
                )
                .await
            {
                Sent::Landed(_) => {}
                Sent::Retry(why) | Sent::Unknown(why) => attempts.failed(why),
                Sent::Program(f) => return Err(program_error(&f)),
                Sent::Failed(e) => return Err(ChainError::Tx(e)),
            }
        }
    }

    async fn snapshot(&self, min_slot: u64) -> Result<TraderSnapshot, ChainError> {
        let filters = vec![
            Filter::DataSize(TRADER_LEN as u64),
            Filter::Memcmp {
                offset: 0,
                bytes: vec![TRADER_TAG],
            },
            Filter::Memcmp {
                offset: 2,
                bytes: vec![LAYOUT_VERSION],
            },
            Filter::Memcmp {
                offset: 4,
                bytes: self.market.to_vec(),
            },
        ];
        let min_slot = min_slot.max(self.seen_slot());
        let (slot, accounts) = self
            .rpc
            .get_program_accounts(
                self.program,
                filters,
                Some((TraderEntry::SLICE_OFFSET, TraderEntry::SLICE_LEN)),
                Level::Confirmed,
                Some(min_slot),
            )
            .await
            .map_err(read_error)?;
        self.saw(slot);
        let mut traders = accounts
            .iter()
            .map(|(_, d)| TraderEntry::decode_slice(d))
            .collect::<Result<Vec<_>, _>>()
            .map_err(ChainError::Decode)?;
        traders.sort_unstable_by_key(|t| t.owner);
        if traders.windows(2).any(|w| w[0].owner == w[1].owner) {
            return Err(ChainError::Inconsistent(
                "two Trader accounts with one owner",
            ));
        }
        Ok(TraderSnapshot { slot, traders })
    }
}

impl MarketChain for SolanaMarketChain {
    fn address(&self) -> Address {
        self.market
    }

    fn market(&self, level: Level) -> BoxFuture<'_, Result<MarketAccount, ChainError>> {
        Box::pin(async move { Ok(self.read(None, level).await?.market) })
    }

    fn batch(
        &self,
        epoch: u64,
        level: Level,
    ) -> BoxFuture<'_, Result<Option<BatchAccount>, ChainError>> {
        Box::pin(async move { Ok(self.read(Some(epoch), level).await?.batch) })
    }

    fn trader_snapshot(&self, min_slot: u64) -> BoxFuture<'_, Result<TraderSnapshot, ChainError>> {
        Box::pin(self.snapshot(min_slot))
    }

    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, ChainError>> {
        Box::pin(async move { self.rpc.slot(level).await.map_err(read_error) })
    }

    fn ensure_committed(
        &self,
        epoch: u64,
        root: Hash32,
        count: u32,
        terms: Hash32,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<CommitOutcome, ChainError>> {
        Box::pin(self.committed(epoch, root, count, terms, payer))
    }

    fn ensure_revealed(
        &self,
        epoch: u64,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<RevealOutcome, ChainError>> {
        Box::pin(self.revealed(epoch, payer))
    }

    fn wait_batch(
        &self,
        epoch: u64,
        until: BatchPredicate,
        level: Level,
        deadline: Instant,
    ) -> BoxFuture<'_, Result<BatchAccount, ChainError>> {
        Box::pin(self.waited(epoch, until, level, deadline))
    }

    fn ensure_posted(
        &self,
        epoch: u64,
        header: [u8; 283],
        receipt: Vec<u8>,
        poster: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<PostOutcome, ChainError>> {
        Box::pin(self.posted(epoch, header, receipt, poster))
    }

    fn ensure_cosigned(
        &self,
        epoch: u64,
        cosigs: Vec<(Address, [u8; 64])>,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<Vec<CosignOutcome>, ChainError>> {
        Box::pin(async move {
            let mut outcomes = Vec::with_capacity(cosigs.len());
            for (executor, signature) in cosigs {
                outcomes.push(
                    self.cosigned(epoch, executor, signature, payer.clone())
                        .await?,
                );
            }
            Ok(outcomes)
        })
    }

    fn ensure_settled(
        &self,
        epoch: u64,
        settlement: Arc<SettlementBatch>,
        payer: Arc<dyn TxSigner>,
        progress: mpsc::Sender<SettleProgress>,
    ) -> BoxFuture<'_, Result<u64, ChainError>> {
        Box::pin(self.settled(epoch, settlement, payer, progress))
    }

    fn ensure_aborted(
        &self,
        epoch: u64,
        reason: AbortReason,
        signer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<AbortOutcome, ChainError>> {
        Box::pin(self.aborted(epoch, reason, signer))
    }

    fn ensure_change_applied(
        &self,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<ChangeOutcome, ChainError>> {
        Box::pin(self.change_applied(payer))
    }

    fn ensure_reclaimed(
        &self,
        epoch: u64,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<(), ChainError>> {
        Box::pin(self.reclaimed(epoch, payer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_count_every_iteration_and_give_up() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async {
            let cfg = MarketChainConfig {
                max_attempts: 3,
                ..MarketChainConfig::default()
            };
            let mut a = Attempts::new(cfg);
            let start = Instant::now();
            a.next().await.unwrap();
            assert_eq!(Instant::now(), start, "the first iteration does not sleep");
            a.next().await.unwrap();
            a.failed("expired");
            a.next().await.unwrap();
            // Two backoffs of at most 500 ms and 1 s.
            assert!(Instant::now() - start <= Duration::from_millis(1500));
            assert_eq!(
                a.next().await.unwrap_err(),
                ChainError::Tx(TxError::GaveUp {
                    attempts: 3,
                    last: "expired".into()
                })
            );
        });
    }

    #[test]
    fn backoff_is_capped() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async {
            let cfg = MarketChainConfig {
                max_attempts: 40,
                retry_backoff: Duration::from_secs(1),
                max_backoff: Duration::from_secs(2),
                ..MarketChainConfig::default()
            };
            let mut a = Attempts::new(cfg);
            for _ in 0..40 {
                let before = Instant::now();
                a.next().await.unwrap();
                assert!(Instant::now() - before <= Duration::from_secs(2));
            }
        });
    }
}
