//! [`FaultyRpc`]: fault injection around any provider (feature `test-util`).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::wire::first_signature;
use crate::{
    AccountData, Address, BoxFuture, Filter, Level, RpcError, Simulation, SolanaRpc, TxStatus,
};

/// The methods of [`SolanaRpc`], to aim faults at and count calls of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RpcMethod {
    GetAccount,
    GetMultipleAccounts,
    GetProgramAccounts,
    LatestBlockhash,
    SendTransaction,
    SimulateTransaction,
    SignatureStatuses,
    Slot,
    BlockHeight,
    GenesisHash,
    RecentPrioritizationFees,
    MinimumBalanceForRentExemption,
}

/// What happens to the next sends.
#[derive(Clone, Debug)]
enum SendFault {
    /// The transaction reaches the cluster, the caller gets the error.
    DropResponse(RpcError),
    /// The caller gets the signature, the cluster never sees the
    /// transaction.
    BlackHole,
}

#[derive(Debug, Default)]
struct Plan {
    sends: VecDeque<SendFault>,
    failures: HashMap<RpcMethod, VecDeque<RpcError>>,
    delays: HashMap<RpcMethod, Duration>,
    disagree: bool,
    stale: bool,
    calls: HashMap<RpcMethod, u64>,
}

/// Wraps a provider and injects faults: drop-response-after-send, delay,
/// errors, disagreement.
///
/// * [`drop_response_after_send`](Self::drop_response_after_send): the
///   transaction is sent, the caller gets an error instead of the signature
///   (a response lost in transit).
/// * [`black_hole_sends`](Self::black_hole_sends): the caller gets the
///   signature, the transaction never reaches the cluster (dropped before a
///   leader. It can only expire).
/// * [`fail_next`](Self::fail_next): calls fail without reaching the
///   provider.
/// * [`delay`](Self::delay): calls wait first.
/// * [`disagree`](Self::disagree): account reads return other bytes than the
///   provider has (the last data byte flipped), and the genesis hash
///   differs.
/// * [`stale`](Self::stale): reads are answered one commitment level lower
///   than asked (Processed as Confirmed, Confirmed as Finalized), so the
///   provider serves older state unless `minContextSlot` stops it.
#[derive(Debug)]
pub struct FaultyRpc<R> {
    inner: Arc<R>,
    plan: Mutex<Plan>,
}

impl<R: SolanaRpc> FaultyRpc<R> {
    pub fn new(inner: Arc<R>) -> Self {
        Self {
            inner,
            plan: Mutex::new(Plan::default()),
        }
    }

    pub fn inner(&self) -> &Arc<R> {
        &self.inner
    }

    /// The next `n` sends reach the provider. Their callers get `err`.
    pub fn drop_response_after_send(&self, n: usize, err: RpcError) {
        let mut plan = self.plan.lock();
        plan.sends
            .extend(std::iter::repeat_n(SendFault::DropResponse(err), n));
    }

    /// The next `n` sends are swallowed: their callers get the signature,
    /// nothing reaches the provider.
    pub fn black_hole_sends(&self, n: usize) {
        let mut plan = self.plan.lock();
        plan.sends
            .extend(std::iter::repeat_n(SendFault::BlackHole, n));
    }

    /// The next `n` calls of `method` fail with `err` without reaching the
    /// provider.
    pub fn fail_next(&self, method: RpcMethod, n: usize, err: RpcError) {
        let mut plan = self.plan.lock();
        plan.failures
            .entry(method)
            .or_default()
            .extend(std::iter::repeat_n(err, n));
    }

    /// Every later call of `method` first waits `delay`. `None` removes it.
    pub fn delay(&self, method: RpcMethod, delay: Option<Duration>) {
        let mut plan = self.plan.lock();
        match delay {
            Some(d) => plan.delays.insert(method, d),
            None => plan.delays.remove(&method),
        };
    }

    pub fn disagree(&self, on: bool) {
        self.plan.lock().disagree = on;
    }

    pub fn stale(&self, on: bool) {
        self.plan.lock().stale = on;
    }

    /// Removes every planned fault. Call counts are kept.
    pub fn clear(&self) {
        let mut plan = self.plan.lock();
        let calls = std::mem::take(&mut plan.calls);
        *plan = Plan {
            calls,
            ..Plan::default()
        };
    }

    /// Calls of `method` so far, including failed ones.
    pub fn calls(&self, method: RpcMethod) -> u64 {
        self.plan.lock().calls.get(&method).copied().unwrap_or(0)
    }

    /// Counts the call, then applies its delay and a planned failure.
    async fn enter(&self, method: RpcMethod) -> Result<(), RpcError> {
        let (delay, failure) = {
            let mut plan = self.plan.lock();
            *plan.calls.entry(method).or_default() += 1;
            let failure = plan.failures.get_mut(&method).and_then(VecDeque::pop_front);
            (plan.delays.get(&method).copied(), failure)
        };
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        failure.map_or(Ok(()), Err)
    }

    fn read_level(&self, level: Level) -> Level {
        if !self.plan.lock().stale {
            return level;
        }
        match level {
            Level::Processed => Level::Confirmed,
            Level::Confirmed | Level::Finalized => Level::Finalized,
        }
    }

    fn disagreeing(&self) -> bool {
        self.plan.lock().disagree
    }
}

fn flip(data: &mut [u8]) {
    if let Some(b) = data.last_mut() {
        *b ^= 1;
    }
}

fn flip_account(a: &mut AccountData) {
    if a.data.is_empty() {
        a.lamports ^= 1;
    } else {
        flip(&mut a.data);
    }
}

impl<R: SolanaRpc> SolanaRpc for FaultyRpc<R> {
    fn get_account(
        &self,
        key: Address,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AccountData>, RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::GetAccount).await?;
            let mut a = self
                .inner
                .get_account(key, self.read_level(level), min_slot)
                .await?;
            if self.disagreeing() {
                a.iter_mut().for_each(flip_account);
            }
            Ok(a)
        })
    }

    fn get_multiple_accounts(
        &self,
        keys: Vec<Address>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<Option<AccountData>>), RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::GetMultipleAccounts).await?;
            let (slot, mut accounts) = self
                .inner
                .get_multiple_accounts(keys, self.read_level(level), min_slot)
                .await?;
            if self.disagreeing() {
                accounts.iter_mut().flatten().for_each(flip_account);
            }
            Ok((slot, accounts))
        })
    }

    fn get_program_accounts(
        &self,
        program: Address,
        filters: Vec<Filter>,
        slice: Option<(usize, usize)>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<(Address, Vec<u8>)>), RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::GetProgramAccounts).await?;
            let (slot, mut accounts) = self
                .inner
                .get_program_accounts(program, filters, slice, self.read_level(level), min_slot)
                .await?;
            if self.disagreeing() {
                accounts.iter_mut().for_each(|(_, d)| flip(d));
            }
            Ok((slot, accounts))
        })
    }

    fn latest_blockhash(&self, level: Level) -> BoxFuture<'_, Result<([u8; 32], u64), RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::LatestBlockhash).await?;
            self.inner.latest_blockhash(level).await
        })
    }

    fn send_transaction(
        &self,
        wire: Vec<u8>,
        skip_preflight: bool,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<[u8; 64], RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::SendTransaction).await?;
            let fault = self.plan.lock().sends.pop_front();
            match fault {
                None => {
                    self.inner
                        .send_transaction(wire, skip_preflight, min_slot)
                        .await
                }
                Some(SendFault::DropResponse(err)) => {
                    self.inner
                        .send_transaction(wire, skip_preflight, min_slot)
                        .await?;
                    Err(err)
                }
                Some(SendFault::BlackHole) => first_signature(&wire)
                    .ok_or_else(|| RpcError::Decode("transaction without a signature".into())),
            }
        })
    }

    fn simulate_transaction(&self, wire: Vec<u8>) -> BoxFuture<'_, Result<Simulation, RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::SimulateTransaction).await?;
            self.inner.simulate_transaction(wire).await
        })
    }

    fn signature_statuses(
        &self,
        sigs: Vec<[u8; 64]>,
    ) -> BoxFuture<'_, Result<Vec<Option<TxStatus>>, RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::SignatureStatuses).await?;
            self.inner.signature_statuses(sigs).await
        })
    }

    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::Slot).await?;
            self.inner.slot(self.read_level(level)).await
        })
    }

    fn block_height(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::BlockHeight).await?;
            self.inner.block_height(self.read_level(level)).await
        })
    }

    fn genesis_hash(&self) -> BoxFuture<'_, Result<[u8; 32], RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::GenesisHash).await?;
            let mut hash = self.inner.genesis_hash().await?;
            if self.disagreeing() {
                flip(&mut hash);
            }
            Ok(hash)
        })
    }

    fn recent_prioritization_fees(
        &self,
        writable: Vec<Address>,
    ) -> BoxFuture<'_, Result<Vec<u64>, RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::RecentPrioritizationFees).await?;
            self.inner.recent_prioritization_fees(writable).await
        })
    }

    fn minimum_balance_for_rent_exemption(
        &self,
        len: usize,
    ) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            self.enter(RpcMethod::MinimumBalanceForRentExemption)
                .await?;
            self.inner.minimum_balance_for_rent_exemption(len).await
        })
    }
}
