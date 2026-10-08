//! [`LiteSvmRpc`]: the settlement program in LiteSVM behind [`SolanaRpc`]
//! (feature `litesvm`, tests only).
//!
//! LiteSVM executes transactions immediately and has one state. This
//! provider adds what the chain adapter needs from a cluster, **emulated**:
//! a slot clock driven by tokio time, Confirmed and Finalized views that lag
//! the processed state by a configured number of slots, blockhashes that
//! expire after a block-height window, signature statuses that move through
//! the commitment levels, preflight and `minContextSlot` checks, the
//! 1232-byte packet limit, and a SlotHashes sysvar rewritten on every new
//! slot. Block height equals the slot (no skipped slots).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use litesvm::LiteSVM;
use parking_lot::Mutex;
use solana_address::Address as SolAddress;
use solana_hash::Hash;
use solana_slot_hashes::SlotHashes;
use solana_transaction::{Transaction, TransactionError};
use timescales_core::crypto::hash_parts;
use tokio::time::Instant;

use crate::wire::{error_detail, first_signature};
use crate::{
    AccountData, Address, BoxFuture, Filter, Level, RpcError, Simulation, SolanaRpc, TxErrorDetail,
    TxStatus,
};

/// Entries of the SlotHashes sysvar.
const SLOT_HASHES: u64 = 512;

/// The settlement program artifact: `TIMESCALES_PROGRAM_SO` resolved against
/// the repository root, by default `target/sbf/timescales_settlement_program.so`
/// as `scripts/build-program.sh` writes it.
pub fn settlement_program_so() -> PathBuf {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rel = std::env::var("TIMESCALES_PROGRAM_SO")
        .unwrap_or_else(|_| "target/sbf/timescales_settlement_program.so".to_owned());
    repo.join(rel)
}

/// How [`LiteSvmRpc`] emulates a cluster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiteSvmConfig {
    /// Slots the Confirmed view lags the processed state.
    pub confirmed_lag: u64,
    /// Slots the Finalized view lags the processed state.
    pub finalized_lag: u64,
    /// Tokio time per slot. With `None` the clock stands still and slots
    /// move only through [`LiteSvmRpc::warp_slot`] and
    /// [`LiteSvmRpc::advance`].
    pub slot_time: Option<Duration>,
    /// Blocks after which a blockhash expires (`lastValidBlockHeight` is
    /// the issuing height plus this).
    pub blockhash_validity: u64,
    pub genesis_hash: [u8; 32],
}

impl Default for LiteSvmConfig {
    fn default() -> Self {
        Self {
            confirmed_lag: 1,
            finalized_lag: 32,
            slot_time: Some(Duration::from_millis(400)),
            blockhash_validity: 150,
            genesis_hash: hash_parts(b"timescales/test/litesvm-genesis", &[]).0,
        }
    }
}

/// The real program `.so` in LiteSVM. Confirmed/Finalized emulated with a
/// finality lag (slots). `warp_slot`, `set_slot_hashes`. See the module
/// documentation for what is emulated.
pub struct LiteSvmRpc {
    cfg: LiteSvmConfig,
    state: Mutex<State>,
}

impl fmt::Debug for LiteSvmRpc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.state.lock();
        f.debug_struct("LiteSvmRpc")
            .field("cfg", &self.cfg)
            .field("slot", &s.slot)
            .field("history", &s.history.len())
            .finish_non_exhaustive()
    }
}

struct State {
    live: LiteSVM,
    /// The processed slot (the live clock).
    slot: u64,
    /// Clock reference: `origin_slot` at `origin`.
    origin: Instant,
    origin_slot: u64,
    /// The state after the last change of every slot that had one, oldest
    /// first. The oldest entry serves every view at or below its slot.
    history: VecDeque<(u64, LiteSVM)>,
    statuses: HashMap<[u8; 64], (u64, Option<TxErrorDetail>)>,
    /// Blockhash -> last valid block height.
    blockhashes: HashMap<[u8; 32], u64>,
    fees: Vec<u64>,
    auto_slot_hashes: bool,
}

impl LiteSvmRpc {
    /// Emulates a cluster over `svm`, which holds the programs and accounts
    /// the test set up. Its clock slot is the starting slot. LiteSVM's own
    /// blockhash check is turned off: this provider checks blockhash
    /// validity itself.
    pub fn new(svm: LiteSVM, cfg: LiteSvmConfig) -> Self {
        let live = svm.with_blockhash_check(false);
        let slot = live.get_sysvar::<solana_clock::Clock>().slot;
        let mut state = State {
            history: VecDeque::from([(slot, live.clone())]),
            live,
            slot,
            origin: Instant::now(),
            origin_slot: slot,
            statuses: HashMap::new(),
            blockhashes: HashMap::new(),
            fees: Vec::new(),
            auto_slot_hashes: true,
        };
        state.write_slot_hashes();
        Self {
            cfg,
            state: Mutex::new(state),
        }
    }

    pub fn config(&self) -> &LiteSvmConfig {
        &self.cfg
    }

    /// The processed slot.
    pub fn current_slot(&self) -> u64 {
        self.tick().slot
    }

    /// Moves the clock forward to `slot` (never back). The clock keeps
    /// running from there.
    pub fn warp_slot(&self, slot: u64) {
        let mut s = self.tick();
        if slot > s.slot {
            s.origin = Instant::now();
            s.origin_slot = slot;
            s.set_slot(slot, &self.cfg);
        }
    }

    pub fn advance(&self, slots: u64) {
        let target = self.current_slot() + slots;
        self.warp_slot(target);
    }

    /// The hash this provider gives `slot` in SlotHashes.
    pub fn slot_hash(slot: u64) -> [u8; 32] {
        hash_parts(b"timescales/test/litesvm-slot", &[&slot.to_le_bytes()]).0
    }

    /// Writes SlotHashes with exactly `entries` and stops rewriting it on
    /// new slots until [`set_auto_slot_hashes`](Self::set_auto_slot_hashes).
    pub fn set_slot_hashes(&self, entries: &[(u64, [u8; 32])]) {
        let mut s = self.tick();
        s.auto_slot_hashes = false;
        let entries: Vec<(u64, Hash)> = entries
            .iter()
            .map(|(slot, h)| (*slot, Hash::new_from_array(*h)))
            .collect();
        s.live.set_sysvar(&SlotHashes::new(&entries));
        s.record(&self.cfg);
    }

    /// With `on`, SlotHashes holds the 512 slots before the current one,
    /// rewritten on every new slot.
    pub fn set_auto_slot_hashes(&self, on: bool) {
        let mut s = self.tick();
        s.auto_slot_hashes = on;
        if on {
            s.write_slot_hashes();
            s.record(&self.cfg);
        }
    }

    /// What `getRecentPrioritizationFees` returns.
    pub fn set_prioritization_fees(&self, fees: Vec<u64>) {
        self.state.lock().fees = fees;
    }

    /// Runs `f` on the processed state, for test setup and inspection. A
    /// change it makes happens at the current slot.
    pub fn with_svm<T>(&self, f: impl FnOnce(&mut LiteSVM) -> T) -> T {
        let mut s = self.tick();
        let out = f(&mut s.live);
        s.record(&self.cfg);
        out
    }

    /// Locks the state and moves the clock to the current time.
    fn tick(&self) -> parking_lot::MutexGuard<'_, State> {
        let mut s = self.state.lock();
        if let Some(slot_time) = self.cfg.slot_time {
            let elapsed = Instant::now().saturating_duration_since(s.origin);
            let slots = elapsed.as_nanos() / slot_time.as_nanos().max(1);
            let target = s
                .origin_slot
                .saturating_add(u64::try_from(slots).unwrap_or(u64::MAX));
            if target > s.slot {
                s.set_slot(target, &self.cfg);
            }
        }
        s
    }

    fn lag(&self, level: Level) -> u64 {
        match level {
            Level::Processed => 0,
            Level::Confirmed => self.cfg.confirmed_lag,
            Level::Finalized => self.cfg.finalized_lag,
        }
    }

    fn check_min_slot(view_slot: u64, min_slot: Option<u64>) -> Result<(), RpcError> {
        match min_slot {
            Some(min_slot) if min_slot > view_slot => Err(RpcError::MinContextSlot { min_slot }),
            _ => Ok(()),
        }
    }
}

impl State {
    fn set_slot(&mut self, slot: u64, cfg: &LiteSvmConfig) {
        self.slot = slot;
        self.live.warp_to_slot(slot);
        if self.auto_slot_hashes {
            self.write_slot_hashes();
        }
        self.prune(cfg);
    }

    /// The 512 slots before the current one, newest first.
    fn write_slot_hashes(&mut self) {
        let entries: Vec<(u64, Hash)> = (self.slot.saturating_sub(SLOT_HASHES)..self.slot)
            .rev()
            .map(|s| (s, Hash::new_from_array(LiteSvmRpc::slot_hash(s))))
            .collect();
        self.live.set_sysvar(&SlotHashes::new(&entries));
    }

    /// Keeps the processed state as the state at the end of this slot.
    fn record(&mut self, cfg: &LiteSvmConfig) {
        match self.history.back_mut() {
            Some((slot, svm)) if *slot == self.slot => *svm = self.live.clone(),
            _ => self.history.push_back((self.slot, self.live.clone())),
        }
        self.prune(cfg);
    }

    /// Drops states no view can reach: everything older than the newest
    /// state at or below the finalized slot.
    fn prune(&mut self, cfg: &LiteSvmConfig) {
        let floor = self.slot.saturating_sub(cfg.finalized_lag);
        while self.history.len() > 1 && self.history[1].0 <= floor {
            self.history.pop_front();
        }
    }

    /// The state a view `lag` slots behind sees, and its slot.
    fn view(&self, lag: u64) -> (u64, &LiteSVM) {
        if lag == 0 {
            return (self.slot, &self.live);
        }
        let at = self.slot.saturating_sub(lag);
        let svm = self
            .history
            .iter()
            .rev()
            .find(|(slot, _)| *slot <= at)
            .or(self.history.front())
            .map_or(&self.live, |(_, svm)| svm);
        (at, svm)
    }

    fn blockhash_valid(&self, blockhash: &[u8; 32]) -> bool {
        self.blockhashes
            .get(blockhash)
            .is_some_and(|last_valid| self.slot <= *last_valid)
    }

    /// A copy of the state at `view_slot` to simulate on: its clock and
    /// SlotHashes are those of that slot.
    fn simulator(&self, lag: u64, sigverify: bool) -> LiteSVM {
        let (at, svm) = self.view(lag);
        let mut sim = svm.clone().with_sigverify(sigverify);
        sim.warp_to_slot(at);
        if self.auto_slot_hashes {
            let entries: Vec<(u64, Hash)> = (at.saturating_sub(SLOT_HASHES)..at)
                .rev()
                .map(|s| (s, Hash::new_from_array(LiteSvmRpc::slot_hash(s))))
                .collect();
            sim.set_sysvar(&SlotHashes::new(&entries));
        } else {
            let id = SolAddress::from(crate::program::SLOT_HASHES_SYSVAR);
            if let Some(hashes) = self.live.get_account(&id) {
                // The live account holds valid SlotHashes data, so the copy
                // is accepted.
                let _ = sim.set_account(id, hashes);
            }
        }
        sim
    }
}

fn account_data(a: solana_account::Account, context_slot: u64) -> Option<AccountData> {
    // A cluster reports an account without lamports as missing.
    (a.lamports > 0).then(|| AccountData {
        owner: a.owner.to_bytes(),
        lamports: a.lamports,
        data: a.data,
        context_slot,
    })
}

fn filters_match(filters: &[Filter], data: &[u8]) -> bool {
    filters.iter().all(|f| match f {
        Filter::DataSize(n) => u64::try_from(data.len()) == Ok(*n),
        Filter::Memcmp { offset, bytes } => usize::try_from(*offset)
            .ok()
            .and_then(|o| data.get(o..o.checked_add(bytes.len())?))
            .is_some_and(|d| d == bytes.as_slice()),
    })
}

fn slice(data: &[u8], slice: Option<(usize, usize)>) -> Vec<u8> {
    match slice {
        None => data.to_vec(),
        Some((offset, length)) => {
            let start = offset.min(data.len());
            let end = offset.saturating_add(length).min(data.len());
            data[start..end].to_vec()
        }
    }
}

fn detail(err: &TransactionError) -> TxErrorDetail {
    match serde_json::to_value(err) {
        Ok(v) => error_detail(&v),
        Err(e) => TxErrorDetail {
            ix_index: None,
            custom: None,
            message: e.to_string(),
        },
    }
}

/// A node refuses a transaction larger than a packet with "invalid params"
/// before looking at it.
fn decode_tx(wire: &[u8]) -> Result<Transaction, RpcError> {
    if wire.len() > crate::program::MAX_TX_SIZE {
        return Err(RpcError::Rpc {
            code: -32602,
            message: format!(
                "transaction too large: {} bytes (max {})",
                wire.len(),
                crate::program::MAX_TX_SIZE
            ),
        });
    }
    bincode::deserialize(wire).map_err(|e| RpcError::Decode(format!("transaction: {e}")))
}

fn preflight(err: TxErrorDetail, logs: Vec<String>) -> RpcError {
    RpcError::Preflight { err, logs }
}

impl SolanaRpc for LiteSvmRpc {
    fn get_account(
        &self,
        key: Address,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AccountData>, RpcError>> {
        Box::pin(async move {
            let s = self.tick();
            let (at, svm) = s.view(self.lag(level));
            Self::check_min_slot(at, min_slot)?;
            Ok(svm
                .get_account(&SolAddress::from(key))
                .and_then(|a| account_data(a, at)))
        })
    }

    fn get_multiple_accounts(
        &self,
        keys: Vec<Address>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<Option<AccountData>>), RpcError>> {
        Box::pin(async move {
            let s = self.tick();
            let (at, svm) = s.view(self.lag(level));
            Self::check_min_slot(at, min_slot)?;
            let accounts = keys
                .iter()
                .map(|k| {
                    svm.get_account(&SolAddress::from(*k))
                        .and_then(|a| account_data(a, at))
                })
                .collect();
            Ok((at, accounts))
        })
    }

    fn get_program_accounts(
        &self,
        program: Address,
        filters: Vec<Filter>,
        data_slice: Option<(usize, usize)>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<(Address, Vec<u8>)>), RpcError>> {
        Box::pin(async move {
            let s = self.tick();
            let (at, svm) = s.view(self.lag(level));
            Self::check_min_slot(at, min_slot)?;
            let mut accounts: Vec<(Address, Vec<u8>)> = svm
                .get_program_accounts(&SolAddress::from(program))
                .into_iter()
                .filter(|(_, a)| a.lamports > 0 && filters_match(&filters, &a.data))
                .map(|(k, a)| (k.to_bytes(), slice(&a.data, data_slice)))
                .collect();
            accounts.sort_unstable();
            Ok((at, accounts))
        })
    }

    fn latest_blockhash(&self, level: Level) -> BoxFuture<'_, Result<([u8; 32], u64), RpcError>> {
        Box::pin(async move {
            let mut s = self.tick();
            let at = s.slot.saturating_sub(self.lag(level));
            let hash = hash_parts(b"timescales/test/litesvm-blockhash", &[&at.to_le_bytes()]).0;
            let last_valid = at + self.cfg.blockhash_validity;
            s.blockhashes.insert(hash, last_valid);
            Ok((hash, last_valid))
        })
    }

    fn send_transaction(
        &self,
        wire: Vec<u8>,
        skip_preflight: bool,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<[u8; 64], RpcError>> {
        Box::pin(async move {
            let tx = decode_tx(&wire)?;
            let signature = first_signature(&wire)
                .ok_or_else(|| RpcError::Decode("transaction without a signature".into()))?;
            let mut s = self.tick();
            // The preflight bank is the Confirmed one, with or without the
            // simulation.
            let lag = self.cfg.confirmed_lag;
            Self::check_min_slot(s.slot.saturating_sub(lag), min_slot)?;
            let dropped = |name: &str| {
                if skip_preflight {
                    Ok(signature)
                } else {
                    Err(preflight(error_detail(&name.into()), vec![]))
                }
            };
            if s.statuses.contains_key(&signature) {
                return dropped("AlreadyProcessed");
            }
            if !s.blockhash_valid(&tx.message.recent_blockhash.to_bytes()) {
                return dropped("BlockhashNotFound");
            }
            if !skip_preflight {
                let sim = s.simulator(lag, s.live.get_sigverify());
                if let Err(f) = sim.simulate_transaction(tx.clone()) {
                    return Err(preflight(detail(&f.err), f.meta.logs));
                }
            }
            match s.live.send_transaction(tx) {
                Ok(_) => {
                    let slot = s.slot;
                    s.statuses.insert(signature, (slot, None));
                    s.record(&self.cfg);
                }
                // An instruction error lands: the fee is charged.
                Err(f) if matches!(f.err, TransactionError::InstructionError(..)) => {
                    let slot = s.slot;
                    s.statuses.insert(signature, (slot, Some(detail(&f.err))));
                    s.record(&self.cfg);
                }
                // Anything else never reaches a block.
                Err(_) => {}
            }
            Ok(signature)
        })
    }

    fn simulate_transaction(&self, wire: Vec<u8>) -> BoxFuture<'_, Result<Simulation, RpcError>> {
        Box::pin(async move {
            let tx = decode_tx(&wire)?;
            let s = self.tick();
            if !s.blockhash_valid(&tx.message.recent_blockhash.to_bytes()) {
                return Ok(Simulation {
                    units: None,
                    logs: vec![],
                    err: Some(error_detail(&"BlockhashNotFound".into())),
                });
            }
            let sim = s.simulator(self.cfg.confirmed_lag, false);
            Ok(match sim.simulate_transaction(tx) {
                Ok(info) => Simulation {
                    units: Some(info.meta.compute_units_consumed),
                    logs: info.meta.logs,
                    err: None,
                },
                Err(f) => Simulation {
                    units: Some(f.meta.compute_units_consumed),
                    logs: f.meta.logs,
                    err: Some(detail(&f.err)),
                },
            })
        })
    }

    fn signature_statuses(
        &self,
        sigs: Vec<[u8; 64]>,
    ) -> BoxFuture<'_, Result<Vec<Option<TxStatus>>, RpcError>> {
        Box::pin(async move {
            let s = self.tick();
            Ok(sigs
                .iter()
                .map(|sig| {
                    s.statuses.get(sig).map(|(slot, err)| {
                        let age = s.slot.saturating_sub(*slot);
                        let level = if age >= self.cfg.finalized_lag {
                            Level::Finalized
                        } else if age >= self.cfg.confirmed_lag {
                            Level::Confirmed
                        } else {
                            Level::Processed
                        };
                        TxStatus {
                            slot: *slot,
                            level,
                            err: err.clone(),
                        }
                    })
                })
                .collect())
        })
    }

    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move { Ok(self.tick().slot.saturating_sub(self.lag(level))) })
    }

    fn block_height(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move { Ok(self.tick().slot.saturating_sub(self.lag(level))) })
    }

    fn genesis_hash(&self) -> BoxFuture<'_, Result<[u8; 32], RpcError>> {
        Box::pin(async move { Ok(self.cfg.genesis_hash) })
    }

    fn recent_prioritization_fees(
        &self,
        _writable: Vec<Address>,
    ) -> BoxFuture<'_, Result<Vec<u64>, RpcError>> {
        Box::pin(async move { Ok(self.state.lock().fees.clone()) })
    }

    fn minimum_balance_for_rent_exemption(
        &self,
        len: usize,
    ) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            Ok(self
                .state
                .lock()
                .live
                .minimum_balance_for_rent_exemption(len))
        })
    }
}
