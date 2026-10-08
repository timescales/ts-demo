//! [`QuorumRpc`]: release-critical reads from several providers, answered
//! only when enough of them agree byte for byte.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::future::join_all;
use tokio::time::Instant;

use super::ProviderError;
use crate::{
    AccountData, Address, BoxFuture, Filter, Level, RpcError, Simulation, SolanaRpc, TxStatus,
};

/// Reads from >= `agree` providers and returns a result only when they agree
/// (accounts compared byte for byte at a common min_slot, `Disagree`
/// otherwise). Writes go to the first healthy provider.
///
/// * Account reads go to every provider at once. A value returned
///   identically by `agree` providers is the answer, with the lowest of
///   their context slots. Otherwise the providers below the highest slot
///   `agree` of them reached are asked again with that slot as
///   `minContextSlot`, then, while no value has `agree` providers, the ones
///   below each higher slot an answer came from. One provider reporting an
///   inflated slot cannot hold the others to a slot they have not
///   reached. A node refuses a `minContextSlot` it has not reached at once
///   (-32016) rather than wait for it, so a refusal is asked again for a
///   short while ([`with_catch_up`](Self::with_catch_up)). A provider that
///   does not catch up keeps its earlier answer. An answer from below the
///   slot its provider was asked for does not count.
/// * `slot` and `block_height` return the highest value that `agree`
///   providers have reached. `genesis_hash` needs `agree` equal answers.
/// * `signature_statuses` reports a signature's status only when `agree`
///   providers report it with the same slot and error, at the highest
///   commitment level `agree` of them reached. Otherwise the signature reads
///   as not yet seen. Fewer than `agree` providers cannot make a sender
///   believe a transaction landed or failed.
/// * `latest_blockhash`, `send_transaction`, `simulate_transaction`, fees
///   and rent go to one provider, starting with the last one that answered
///   and moving on only after a transport, 429 or 5xx failure.
///   `send_transaction` also moves on when a provider has not reached the
///   caller's slot. Re-sending the same signed transaction to another
///   provider cannot make it land twice, and once a provider may have
///   forwarded it, a later provider's refusal is not reported as one.
pub struct QuorumRpc {
    providers: Vec<Arc<dyn SolanaRpc>>,
    agree: usize,
    preferred: AtomicUsize,
    catch_up: Duration,
    catch_up_poll: Duration,
}

impl fmt::Debug for QuorumRpc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuorumRpc")
            .field("providers", &self.providers.len())
            .field("agree", &self.agree)
            .finish_non_exhaustive()
    }
}

/// An account without its context slot, for comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Content {
    owner: Address,
    lamports: u64,
    data: Vec<u8>,
}

fn content(a: Option<AccountData>) -> Option<Content> {
    a.map(|a| Content {
        owner: a.owner,
        lamports: a.lamports,
        data: a.data,
    })
}

fn account(c: Option<Content>, context_slot: u64) -> Option<AccountData> {
    c.map(|c| AccountData {
        owner: c.owner,
        lamports: c.lamports,
        data: c.data,
        context_slot,
    })
}

type Read<T> = BoxFuture<'static, Result<(u64, T), RpcError>>;

/// An answer from below the slot it was asked for does not count.
fn at_least<T>(
    answer: Result<(u64, T), RpcError>,
    min_slot: Option<u64>,
) -> Result<(u64, T), RpcError> {
    match (answer, min_slot) {
        (Ok((slot, _)), Some(min)) if slot < min => Err(RpcError::Decode(format!(
            "context slot {slot} below the minContextSlot {min} asked for"
        ))),
        (answer, _) => answer,
    }
}

/// Takes the value at least `agree` answers hold, with the lowest of their
/// slots. With several such values (possible only when `agree` is at most
/// half the providers) the one whose lowest slot is highest wins.
fn take_agreed<T: PartialEq>(answers: &mut [Option<(u64, T)>], agree: usize) -> Option<(u64, T)> {
    let mut best: Option<(u64, usize)> = None;
    for (i, answer) in answers.iter().enumerate() {
        let Some((_, value)) = answer else { continue };
        let slots: Vec<u64> = answers
            .iter()
            .flatten()
            .filter(|(_, v)| v == value)
            .map(|(s, _)| *s)
            .collect();
        if slots.len() < agree {
            continue;
        }
        let lowest = slots.into_iter().min()?;
        if best.is_none_or(|(b, _)| lowest > b) {
            best = Some((lowest, i));
        }
    }
    let (slot, i) = best?;
    let (_, value) = answers[i].take()?;
    Some((slot, value))
}

impl QuorumRpc {
    /// How long a provider asked for a slot it has not reached gets to
    /// catch up by default: three slot times.
    pub const CATCH_UP: Duration = Duration::from_millis(1_200);
    /// How often such a provider is asked again meanwhile.
    pub const CATCH_UP_POLL: Duration = Duration::from_millis(200);

    /// `1 <= agree <= providers.len`.
    pub fn new(providers: Vec<Arc<dyn SolanaRpc>>, agree: usize) -> Result<Self, ProviderError> {
        if providers.is_empty() {
            return Err(ProviderError::NoProviders);
        }
        if agree == 0 || agree > providers.len() {
            return Err(ProviderError::Agree {
                agree,
                providers: providers.len(),
            });
        }
        Ok(Self {
            providers,
            agree,
            preferred: AtomicUsize::new(0),
            catch_up: Self::CATCH_UP,
            catch_up_poll: Self::CATCH_UP_POLL,
        })
    }

    /// A provider that refuses a `minContextSlot` it has not reached is
    /// asked again every `poll` (at least 1 ms) until `wait` has passed.
    #[must_use]
    pub fn with_catch_up(mut self, wait: Duration, poll: Duration) -> Self {
        self.catch_up = wait;
        self.catch_up_poll = poll.max(Duration::from_millis(1));
        self
    }

    pub fn agree(&self) -> usize {
        self.agree
    }

    async fn agreed<T, F>(&self, min_slot: Option<u64>, read: F) -> Result<(u64, T), RpcError>
    where
        T: PartialEq,
        F: Fn(Arc<dyn SolanaRpc>, Option<u64>) -> Read<T>,
    {
        let n = self.providers.len();
        let first = join_all(self.providers.iter().map(|p| read(p.clone(), min_slot))).await;
        let mut first_error = None;
        let mut answers: Vec<Option<(u64, T)>> = Vec::with_capacity(n);
        // Providers without an answer that have not reached `min_slot` yet.
        let mut behind = vec![false; n];
        for (i, r) in first.into_iter().enumerate() {
            match at_least(r, min_slot) {
                Ok(answer) => answers.push(Some(answer)),
                Err(e) => {
                    behind[i] = matches!(e, RpcError::MinContextSlot { .. });
                    first_error.get_or_insert(e);
                    answers.push(None);
                }
            }
        }
        // Every round raises the target slot. Providers that move on while
        // they are asked could keep raising it, so the rounds are capped:
        // one for the caller's slot and one per provider.
        let mut target: Option<u64> = None;
        for _ in 0..=n {
            if let Some(found) = take_agreed(&mut answers, self.agree) {
                return Ok(found);
            }
            let mut slots: Vec<u64> = answers.iter().flatten().map(|(s, _)| *s).collect();
            slots.sort_unstable_by(|a, b| b.cmp(a));
            let next = match (slots.get(self.agree - 1).copied(), target) {
                // Too few answers: the providers below the caller's slot
                // get a moment to catch up.
                (None, None) if behind.contains(&true) => min_slot,
                (None, _) => None,
                // The highest slot `agree` providers have reached.
                (Some(reached), None) => Some(reached),
                (Some(reached), Some(t)) if reached > t => Some(reached),
                (Some(_), Some(t)) => slots.into_iter().filter(|s| *s > t).min(),
            };
            let Some(next) = next else { break };
            target = Some(next);
            let ask: Vec<usize> = (0..n)
                .filter(|&i| match &answers[i] {
                    Some((slot, _)) => *slot < next,
                    None => behind[i],
                })
                .collect();
            let again = join_all(ask.iter().map(|&i| self.caught_up(&read, i, next))).await;
            for (i, r) in ask.into_iter().zip(again) {
                // A provider that does not answer keeps its earlier answer.
                if let Ok(answer) = r {
                    answers[i] = Some(answer);
                    behind[i] = false;
                }
            }
        }
        if let Some(found) = take_agreed(&mut answers, self.agree) {
            return Ok(found);
        }
        if answers.iter().flatten().count() < self.agree {
            return Err(first_error.unwrap_or(RpcError::Unavailable));
        }
        Err(RpcError::Disagree)
    }

    /// Asks provider `i` for an answer at `min_slot` or later. Nodes refuse
    /// a `minContextSlot` they have not reached at once rather than wait
    /// for it, so a refusal is asked again until `catch_up` has passed.
    async fn caught_up<T, F>(&self, read: &F, i: usize, min_slot: u64) -> Result<(u64, T), RpcError>
    where
        F: Fn(Arc<dyn SolanaRpc>, Option<u64>) -> Read<T>,
    {
        let deadline = Instant::now() + self.catch_up;
        loop {
            let answer = read(self.providers[i].clone(), Some(min_slot)).await;
            match at_least(answer, Some(min_slot)) {
                Err(RpcError::MinContextSlot { .. })
                    if Instant::now() + self.catch_up_poll <= deadline =>
                {
                    tokio::time::sleep(self.catch_up_poll).await;
                }
                answer => return answer,
            }
        }
    }

    /// The `agree`-th highest of the values the providers return.
    async fn reached<F>(&self, read: F) -> Result<u64, RpcError>
    where
        F: Fn(Arc<dyn SolanaRpc>) -> BoxFuture<'static, Result<u64, RpcError>>,
    {
        let results = join_all(self.providers.iter().map(|p| read(p.clone()))).await;
        let mut first_error = None;
        let mut values: Vec<u64> = results
            .into_iter()
            .filter_map(|r| r.map_err(|e| first_error.get_or_insert(e).clone()).ok())
            .collect();
        values.sort_unstable_by(|a, b| b.cmp(a));
        values
            .get(self.agree - 1)
            .copied()
            .ok_or(first_error.unwrap_or(RpcError::Unavailable))
    }

    async fn one<T, F>(&self, call: F) -> Result<T, RpcError>
    where
        F: Fn(Arc<dyn SolanaRpc>) -> BoxFuture<'static, Result<T, RpcError>>,
    {
        let n = self.providers.len();
        let start = self.preferred.load(Ordering::Relaxed);
        let mut last = RpcError::Unavailable;
        for k in 0..n {
            let i = (start + k) % n;
            match call(self.providers[i].clone()).await {
                Ok(v) => {
                    self.preferred.store(i, Ordering::Relaxed);
                    return Ok(v);
                }
                Err(e) if e.is_transport() || e == RpcError::Unavailable => last = e,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }
}

/// The status at least `agree` of `reported` give with one slot and error,
/// at the highest level `agree` of them reached. With several such groups
/// (possible only when `agree` is at most half the providers) the one at
/// the highest level wins.
fn agreed_status<'a>(
    reported: impl Iterator<Item = &'a Option<TxStatus>>,
    agree: usize,
) -> Option<TxStatus> {
    let seen: Vec<&TxStatus> = reported.flatten().collect();
    seen.iter()
        .filter_map(|s| {
            let mut levels: Vec<Level> = seen
                .iter()
                .filter(|t| t.slot == s.slot && t.err == s.err)
                .map(|t| t.level)
                .collect();
            levels.sort_unstable_by(|a, b| b.cmp(a));
            let level = *levels.get(agree.checked_sub(1)?)?;
            Some(TxStatus {
                slot: s.slot,
                level,
                err: s.err.clone(),
            })
        })
        .max_by_key(|s| s.level)
}

impl SolanaRpc for QuorumRpc {
    fn get_account(
        &self,
        key: Address,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AccountData>, RpcError>> {
        Box::pin(async move {
            let (slot, mut accounts) = self
                .get_multiple_accounts(vec![key], level, min_slot)
                .await?;
            Ok(accounts.pop().flatten().map(|a| AccountData {
                context_slot: slot,
                ..a
            }))
        })
    }

    fn get_multiple_accounts(
        &self,
        keys: Vec<Address>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<Option<AccountData>>), RpcError>> {
        Box::pin(async move {
            let (slot, contents) = self
                .agreed(min_slot, |p, m| {
                    let keys = keys.clone();
                    Box::pin(async move {
                        let (slot, accounts) = p.get_multiple_accounts(keys, level, m).await?;
                        Ok((slot, accounts.into_iter().map(content).collect::<Vec<_>>()))
                    })
                })
                .await?;
            Ok((
                slot,
                contents.into_iter().map(|c| account(c, slot)).collect(),
            ))
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
            self.agreed(min_slot, |p, m| {
                let filters = filters.clone();
                Box::pin(async move {
                    let (slot, mut accounts) = p
                        .get_program_accounts(program, filters, slice, level, m)
                        .await?;
                    // Providers may order the accounts differently.
                    accounts.sort_unstable();
                    Ok((slot, accounts))
                })
            })
            .await
        })
    }

    fn latest_blockhash(&self, level: Level) -> BoxFuture<'_, Result<([u8; 32], u64), RpcError>> {
        Box::pin(async move {
            self.one(|p| Box::pin(async move { p.latest_blockhash(level).await }))
                .await
        })
    }

    fn send_transaction(
        &self,
        wire: Vec<u8>,
        skip_preflight: bool,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<[u8; 64], RpcError>> {
        Box::pin(async move {
            let n = self.providers.len();
            let start = self.preferred.load(Ordering::Relaxed);
            // The latest failure after which the provider may have forwarded
            // the transaction: a later provider's refusal does not mean it
            // was never sent, so the sender has to keep polling.
            let mut ambiguous = None;
            let mut last = RpcError::Unavailable;
            for k in 0..n {
                let i = (start + k) % n;
                let sent = self.providers[i]
                    .send_transaction(wire.clone(), skip_preflight, min_slot)
                    .await;
                match sent {
                    Ok(signature) => {
                        self.preferred.store(i, Ordering::Relaxed);
                        return Ok(signature);
                    }
                    // Not forwarded. Another provider may have reached the
                    // slot already.
                    Err(e @ RpcError::MinContextSlot { .. }) => last = e,
                    Err(e) if e.is_transport() || e == RpcError::Unavailable => {
                        ambiguous = Some(e.clone());
                        last = e;
                    }
                    Err(e) => return Err(ambiguous.unwrap_or(e)),
                }
            }
            Err(ambiguous.unwrap_or(last))
        })
    }

    fn simulate_transaction(&self, wire: Vec<u8>) -> BoxFuture<'_, Result<Simulation, RpcError>> {
        Box::pin(async move {
            self.one(|p| {
                let wire = wire.clone();
                Box::pin(async move { p.simulate_transaction(wire).await })
            })
            .await
        })
    }

    fn signature_statuses(
        &self,
        sigs: Vec<[u8; 64]>,
    ) -> BoxFuture<'_, Result<Vec<Option<TxStatus>>, RpcError>> {
        Box::pin(async move {
            let results = join_all(
                self.providers
                    .iter()
                    .map(|p| p.signature_statuses(sigs.clone())),
            )
            .await;
            let mut first_error = None;
            let mut answers = Vec::new();
            for r in results {
                match r {
                    Ok(statuses) if statuses.len() == sigs.len() => answers.push(statuses),
                    Ok(_) => {
                        first_error.get_or_insert(RpcError::Decode(
                            "another number of statuses than signatures".into(),
                        ));
                    }
                    Err(e) => {
                        first_error.get_or_insert(e);
                    }
                }
            }
            if answers.len() < self.agree {
                return Err(first_error.unwrap_or(RpcError::Unavailable));
            }
            Ok((0..sigs.len())
                .map(|i| agreed_status(answers.iter().map(|a| &a[i]), self.agree))
                .collect())
        })
    }

    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            self.reached(|p| Box::pin(async move { p.slot(level).await }))
                .await
        })
    }

    fn block_height(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            self.reached(|p| Box::pin(async move { p.block_height(level).await }))
                .await
        })
    }

    fn genesis_hash(&self) -> BoxFuture<'_, Result<[u8; 32], RpcError>> {
        Box::pin(async move {
            let (_, hash) = self
                .agreed(None, |p, _| {
                    Box::pin(async move { Ok((0, p.genesis_hash().await?)) })
                })
                .await?;
            Ok(hash)
        })
    }

    fn recent_prioritization_fees(
        &self,
        writable: Vec<Address>,
    ) -> BoxFuture<'_, Result<Vec<u64>, RpcError>> {
        Box::pin(async move {
            self.one(|p| {
                let writable = writable.clone();
                Box::pin(async move { p.recent_prioritization_fees(writable).await })
            })
            .await
        })
    }

    fn minimum_balance_for_rent_exemption(
        &self,
        len: usize,
    ) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            self.one(|p| Box::pin(async move { p.minimum_balance_for_rent_exemption(len).await }))
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use parking_lot::Mutex;

    use super::*;

    /// A provider holding one account. Asked for a `minContextSlot` above
    /// its slot it refuses, as a node does, until it has refused
    /// `catch_up_after` times. Then it has reached that slot.
    struct Fake {
        slot: Mutex<u64>,
        catch_up_after: Mutex<Option<usize>>,
        /// Answers at its own slot whatever slot it is asked for.
        ignores_min_slot: bool,
        data: Vec<u8>,
        /// The account holds these bytes from this slot on.
        later: Option<(u64, Vec<u8>)>,
        failures: Mutex<Vec<RpcError>>,
        status: Option<TxStatus>,
        /// Lists program accounts in the opposite order.
        reversed: bool,
        calls: Mutex<Vec<&'static str>>,
    }

    impl Fake {
        fn new(slot: u64, data: &[u8]) -> Self {
            Self {
                slot: Mutex::new(slot),
                catch_up_after: Mutex::new(None),
                ignores_min_slot: false,
                data: data.to_vec(),
                later: None,
                failures: Mutex::new(vec![]),
                status: None,
                reversed: false,
                calls: Mutex::new(vec![]),
            }
        }

        fn changing(slot: u64, data: &[u8], from: u64, later: &[u8]) -> Self {
            Self {
                later: Some((from, later.to_vec())),
                ..Self::new(slot, data)
            }
        }

        fn catching_up_after(self, refusals: usize) -> Self {
            *self.catch_up_after.lock() = Some(refusals);
            self
        }

        fn enter(&self, method: &'static str) -> Result<(), RpcError> {
            self.calls.lock().push(method);
            self.failures.lock().pop().map_or(Ok(()), Err)
        }

        fn at(&self, min_slot: Option<u64>) -> Result<u64, RpcError> {
            let mut slot = self.slot.lock();
            match min_slot {
                Some(min) if min > *slot && !self.ignores_min_slot => {
                    let mut left = self.catch_up_after.lock();
                    match left.as_mut() {
                        Some(0) => *slot = min,
                        Some(n) => {
                            *n -= 1;
                            return Err(RpcError::MinContextSlot { min_slot: min });
                        }
                        None => return Err(RpcError::MinContextSlot { min_slot: min }),
                    }
                }
                _ => {}
            }
            Ok(*slot)
        }

        fn data_at(&self, slot: u64) -> Vec<u8> {
            match &self.later {
                Some((from, later)) if slot >= *from => later.clone(),
                _ => self.data.clone(),
            }
        }

        fn calls(&self, method: &str) -> usize {
            self.calls.lock().iter().filter(|m| **m == method).count()
        }
    }

    impl SolanaRpc for Fake {
        fn get_account(
            &self,
            _key: Address,
            _level: Level,
            _min_slot: Option<u64>,
        ) -> BoxFuture<'_, Result<Option<AccountData>, RpcError>> {
            unreachable!("QuorumRpc reads single accounts through get_multiple_accounts")
        }

        fn get_multiple_accounts(
            &self,
            keys: Vec<Address>,
            _level: Level,
            min_slot: Option<u64>,
        ) -> BoxFuture<'_, Result<(u64, Vec<Option<AccountData>>), RpcError>> {
            Box::pin(async move {
                self.enter("get_multiple_accounts")?;
                let slot = self.at(min_slot)?;
                let accounts = keys
                    .iter()
                    .map(|k| {
                        (k[0] == 1).then(|| AccountData {
                            owner: [9; 32],
                            lamports: 5,
                            data: self.data_at(slot),
                            context_slot: slot,
                        })
                    })
                    .collect();
                Ok((slot, accounts))
            })
        }

        fn get_program_accounts(
            &self,
            _program: Address,
            _filters: Vec<Filter>,
            _slice: Option<(usize, usize)>,
            _level: Level,
            min_slot: Option<u64>,
        ) -> BoxFuture<'_, Result<(u64, Vec<(Address, Vec<u8>)>), RpcError>> {
            Box::pin(async move {
                self.enter("get_program_accounts")?;
                let slot = self.at(min_slot)?;
                let mut accounts = vec![([2; 32], self.data_at(slot)), ([1; 32], vec![7])];
                if self.reversed {
                    accounts.reverse();
                }
                Ok((slot, accounts))
            })
        }

        fn latest_blockhash(
            &self,
            _level: Level,
        ) -> BoxFuture<'_, Result<([u8; 32], u64), RpcError>> {
            Box::pin(async move {
                self.enter("latest_blockhash")?;
                Ok(([self.data[0]; 32], 1))
            })
        }

        fn send_transaction(
            &self,
            _wire: Vec<u8>,
            _skip_preflight: bool,
            _min_slot: Option<u64>,
        ) -> BoxFuture<'_, Result<[u8; 64], RpcError>> {
            Box::pin(async move {
                self.enter("send_transaction")?;
                Ok([self.data[0]; 64])
            })
        }

        fn simulate_transaction(
            &self,
            _wire: Vec<u8>,
        ) -> BoxFuture<'_, Result<Simulation, RpcError>> {
            unreachable!()
        }

        fn signature_statuses(
            &self,
            sigs: Vec<[u8; 64]>,
        ) -> BoxFuture<'_, Result<Vec<Option<TxStatus>>, RpcError>> {
            Box::pin(async move {
                self.enter("signature_statuses")?;
                Ok(sigs.iter().map(|_| self.status.clone()).collect())
            })
        }

        fn slot(&self, _level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
            Box::pin(async move {
                self.enter("slot")?;
                Ok(*self.slot.lock())
            })
        }

        fn block_height(&self, _level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
            unreachable!()
        }

        fn genesis_hash(&self) -> BoxFuture<'_, Result<[u8; 32], RpcError>> {
            Box::pin(async move {
                self.enter("genesis_hash")?;
                Ok([self.data[0]; 32])
            })
        }

        fn recent_prioritization_fees(
            &self,
            _writable: Vec<Address>,
        ) -> BoxFuture<'_, Result<Vec<u64>, RpcError>> {
            unreachable!()
        }

        fn minimum_balance_for_rent_exemption(
            &self,
            _len: usize,
        ) -> BoxFuture<'_, Result<u64, RpcError>> {
            unreachable!()
        }
    }

    fn quorum(fakes: &[Arc<Fake>], agree: usize) -> QuorumRpc {
        let providers = fakes
            .iter()
            .map(|f| f.clone() as Arc<dyn SolanaRpc>)
            .collect();
        QuorumRpc::new(providers, agree).unwrap()
    }

    /// With the clock paused: waiting for a provider to catch up takes no
    /// real time.
    fn block_on<T>(f: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn construction_bounds() {
        assert_eq!(
            QuorumRpc::new(vec![], 1).unwrap_err(),
            ProviderError::NoProviders
        );
        let one: Vec<Arc<dyn SolanaRpc>> = vec![Arc::new(Fake::new(1, &[1]))];
        assert_eq!(
            QuorumRpc::new(one.clone(), 2).unwrap_err(),
            ProviderError::Agree {
                agree: 2,
                providers: 1
            }
        );
        assert!(QuorumRpc::new(one.clone(), 0).is_err());
        assert_eq!(QuorumRpc::new(one, 1).unwrap().agree(), 1);
    }

    fn account_data(q: &QuorumRpc, min_slot: Option<u64>) -> Result<(u64, Vec<u8>), RpcError> {
        let (slot, accounts) =
            block_on(q.get_multiple_accounts(vec![[1; 32]], Level::Confirmed, min_slot))?;
        let data = accounts.into_iter().next().flatten().map(|a| a.data);
        Ok((slot, data.unwrap()))
    }

    #[test]
    fn identical_bytes_agree_at_the_lowest_of_their_slots() {
        let fakes = [Arc::new(Fake::new(10, &[4])), Arc::new(Fake::new(11, &[4]))];
        let q = quorum(&fakes, 2);
        let (slot, accounts) =
            block_on(q.get_multiple_accounts(vec![[1; 32], [0; 32]], Level::Confirmed, Some(8)))
                .unwrap();
        assert_eq!(slot, 10);
        assert_eq!(
            accounts,
            vec![
                Some(AccountData {
                    owner: [9; 32],
                    lamports: 5,
                    data: vec![4],
                    context_slot: 10,
                }),
                None
            ]
        );
        assert_eq!(fakes[0].calls("get_multiple_accounts"), 1);
        assert_eq!(fakes[1].calls("get_multiple_accounts"), 1);
        let single = block_on(q.get_account([1; 32], Level::Confirmed, None)).unwrap();
        assert_eq!(single.map(|a| a.context_slot), Some(10));
        // A provider repeating the bytes cannot raise the slot.
        let fakes = [
            Arc::new(Fake::new(10, &[4])),
            Arc::new(Fake::new(1000, &[4])),
        ];
        assert_eq!(account_data(&quorum(&fakes, 2), None), Ok((10, vec![4])));
    }

    #[test]
    fn a_provider_behind_is_asked_again_at_the_slot_the_other_reached() {
        // The account changed at slot 12. The provider at slot 10 has
        // reached 12 by the time it is asked for it.
        let fakes = [
            Arc::new(Fake::changing(10, &[4], 12, &[5]).catching_up_after(0)),
            Arc::new(Fake::new(12, &[5])),
        ];
        assert_eq!(account_data(&quorum(&fakes, 2), Some(8)), Ok((12, vec![5])));
        assert_eq!(fakes[0].calls("get_multiple_accounts"), 2);
        assert_eq!(fakes[1].calls("get_multiple_accounts"), 1);
    }

    #[test]
    fn one_inflated_slot_cannot_hold_back_agreeing_providers() {
        // Two of three. The third reports slot 1000, which nobody else has
        // reached. The first is one slot behind a change.
        let fakes = [
            Arc::new(Fake::changing(10, &[4], 11, &[5]).catching_up_after(0)),
            Arc::new(Fake::new(11, &[5])),
            Arc::new(Fake::new(1000, &[6])),
        ];
        assert_eq!(account_data(&quorum(&fakes, 2), None), Ok((11, vec![5])));
        assert_eq!(fakes[0].calls("get_multiple_accounts"), 2);
        assert_eq!(fakes[1].calls("get_multiple_accounts"), 1);
        assert_eq!(fakes[2].calls("get_multiple_accounts"), 1);
        // With the same bytes on both, nobody is asked again.
        let fakes = [
            Arc::new(Fake::new(10, &[4])),
            Arc::new(Fake::new(12, &[4])),
            Arc::new(Fake::new(1000, &[6])),
        ];
        assert_eq!(account_data(&quorum(&fakes, 2), None), Ok((10, vec![4])));
        for f in &fakes {
            assert_eq!(f.calls("get_multiple_accounts"), 1);
        }
    }

    #[test]
    fn a_provider_that_catches_up_after_a_delay_counts() {
        let fakes = [
            Arc::new(Fake::changing(10, &[4], 11, &[5]).catching_up_after(2)),
            Arc::new(Fake::new(11, &[5])),
        ];
        let q = quorum(&fakes, 2);
        block_on(async {
            let start = Instant::now();
            let (slot, accounts) = q
                .get_multiple_accounts(vec![[1; 32]], Level::Confirmed, None)
                .await
                .unwrap();
            assert_eq!(
                (slot, accounts[0].as_ref().unwrap().data.clone()),
                (11, vec![5])
            );
            let waited = start.elapsed();
            assert!(waited >= QuorumRpc::CATCH_UP_POLL * 2, "{waited:?}");
            assert!(waited < QuorumRpc::CATCH_UP_POLL * 3, "{waited:?}");
        });
        // The first answer, two refusals and the answer at slot 11.
        assert_eq!(fakes[0].calls("get_multiple_accounts"), 4);

        // Below the caller's own slot: too few answers until it catches up.
        let fakes = [
            Arc::new(Fake::new(10, &[4]).catching_up_after(1)),
            Arc::new(Fake::new(12, &[4])),
        ];
        assert_eq!(
            account_data(&quorum(&fakes, 2), Some(12)),
            Ok((12, vec![4]))
        );
        assert_eq!(fakes[0].calls("get_multiple_accounts"), 2);
    }

    #[test]
    fn other_bytes_or_a_provider_that_cannot_catch_up_disagree() {
        let fakes = [Arc::new(Fake::new(12, &[4])), Arc::new(Fake::new(12, &[5]))];
        assert_eq!(
            account_data(&quorum(&fakes, 2), None),
            Err(RpcError::Disagree)
        );
        // Refuses slot 11 for good: asked again for a bounded time only.
        let fakes = [
            Arc::new(Fake::changing(10, &[4], 11, &[5])),
            Arc::new(Fake::new(11, &[5])),
        ];
        let q = quorum(&fakes, 2);
        block_on(async {
            let start = Instant::now();
            assert_eq!(
                q.get_multiple_accounts(vec![[1; 32]], Level::Confirmed, None)
                    .await,
                Err(RpcError::Disagree)
            );
            let waited = start.elapsed();
            assert!(waited >= QuorumRpc::CATCH_UP, "{waited:?}");
            assert!(
                waited < QuorumRpc::CATCH_UP + QuorumRpc::CATCH_UP_POLL,
                "{waited:?}"
            );
        });
        let q = quorum(&fakes, 2).with_catch_up(Duration::ZERO, Duration::ZERO);
        let calls = fakes[0].calls("get_multiple_accounts");
        assert_eq!(account_data(&q, None), Err(RpcError::Disagree));
        assert_eq!(fakes[0].calls("get_multiple_accounts"), calls + 2);
        // Too few providers reach the caller's slot.
        assert!(matches!(
            account_data(&q, Some(11)),
            Err(RpcError::MinContextSlot { min_slot: 11 })
        ));
    }

    #[test]
    fn answers_below_the_slot_asked_for_do_not_count() {
        let liar = || {
            let mut f = Fake::new(5, &[4]);
            f.ignores_min_slot = true;
            Arc::new(f)
        };
        let fakes = [liar(), Arc::new(Fake::new(12, &[4]))];
        assert!(matches!(
            account_data(&quorum(&fakes, 2), Some(8)),
            Err(RpcError::Decode(_))
        ));
        let fakes = [
            liar(),
            Arc::new(Fake::new(12, &[4])),
            Arc::new(Fake::new(13, &[4])),
        ];
        assert_eq!(account_data(&quorum(&fakes, 2), Some(8)), Ok((12, vec![4])));
    }

    #[test]
    fn agreement_of_some_providers_is_enough() {
        let fakes = [
            Arc::new(Fake::new(12, &[5])),
            Arc::new(Fake::new(12, &[4])),
            Arc::new(Fake::new(12, &[4])),
        ];
        let (_, accounts) = block_on(quorum(&fakes, 2).get_multiple_accounts(
            vec![[1; 32]],
            Level::Confirmed,
            None,
        ))
        .unwrap();
        assert_eq!(accounts[0].as_ref().map(|a| a.data.clone()), Some(vec![4]));
        // Program accounts are compared as sets: the providers list them in
        // different orders.
        let mut reversed = Fake::new(12, &[4]);
        reversed.reversed = true;
        let fakes = [Arc::new(reversed), Arc::new(Fake::new(13, &[4]))];
        let q = quorum(&fakes, 2);
        let (slot, accounts) =
            block_on(q.get_program_accounts([0; 32], vec![], None, Level::Confirmed, None))
                .unwrap();
        assert_eq!(slot, 12);
        assert_eq!(accounts, vec![([1; 32], vec![7]), ([2; 32], vec![4])]);
    }

    #[test]
    fn too_few_answers_return_the_first_error() {
        let fakes = [Arc::new(Fake::new(12, &[4])), Arc::new(Fake::new(12, &[4]))];
        fakes[1].failures.lock().push(RpcError::Timeout);
        assert_eq!(
            block_on(quorum(&fakes, 2).get_multiple_accounts(
                vec![[1; 32]],
                Level::Confirmed,
                None
            )),
            Err(RpcError::Timeout)
        );
        fakes[0].failures.lock().push(RpcError::Http(502));
        assert_eq!(
            block_on(quorum(&fakes, 1).genesis_hash()),
            Ok([4; 32]),
            "one answer is enough for a quorum of one"
        );
    }

    #[test]
    fn slot_is_the_highest_value_enough_providers_reached() {
        let fakes = [
            Arc::new(Fake::new(30, &[4])),
            Arc::new(Fake::new(10, &[4])),
            Arc::new(Fake::new(20, &[4])),
        ];
        assert_eq!(block_on(quorum(&fakes, 1).slot(Level::Confirmed)), Ok(30));
        assert_eq!(block_on(quorum(&fakes, 2).slot(Level::Confirmed)), Ok(20));
        assert_eq!(block_on(quorum(&fakes, 3).slot(Level::Confirmed)), Ok(10));
        fakes[0].failures.lock().push(RpcError::Timeout);
        assert_eq!(block_on(quorum(&fakes, 2).slot(Level::Confirmed)), Ok(10));
    }

    #[test]
    fn genesis_hashes_must_agree() {
        let fakes = [Arc::new(Fake::new(1, &[4])), Arc::new(Fake::new(1, &[5]))];
        assert_eq!(
            block_on(quorum(&fakes, 2).genesis_hash()),
            Err(RpcError::Disagree)
        );
    }

    #[test]
    fn writes_move_on_only_after_endpoint_failures() {
        let fakes = [Arc::new(Fake::new(1, &[4])), Arc::new(Fake::new(1, &[5]))];
        let q = quorum(&fakes, 2);
        fakes[0].failures.lock().push(RpcError::Http(503));
        assert_eq!(
            block_on(q.send_transaction(vec![], false, None)),
            Ok([5; 64])
        );
        // The provider that answered stays the first one asked.
        assert_eq!(
            block_on(q.latest_blockhash(Level::Confirmed)),
            Ok(([5; 32], 1))
        );
        assert_eq!(fakes[0].calls("latest_blockhash"), 0);
        // A JSON-RPC error is an answer: no other provider is asked.
        fakes[1].failures.lock().push(RpcError::Rpc {
            code: -32002,
            message: "simulation failed".into(),
        });
        assert!(matches!(
            block_on(q.send_transaction(vec![], false, None)),
            Err(RpcError::Rpc { code: -32002, .. })
        ));
        assert_eq!(fakes[0].calls("send_transaction"), 1);
        fakes[1].failures.lock().push(RpcError::Timeout);
        fakes[0]
            .failures
            .lock()
            .push(RpcError::Transport("refused".into()));
        assert_eq!(
            block_on(q.send_transaction(vec![], false, None)),
            Err(RpcError::Transport("refused".into())),
            "every provider failed: the last failure"
        );
    }

    #[test]
    fn a_refusal_after_an_ambiguous_send_is_not_reported() {
        let fakes = [Arc::new(Fake::new(1, &[4])), Arc::new(Fake::new(1, &[5]))];
        let q = quorum(&fakes, 2);
        // The first provider may have forwarded the transaction before it
        // timed out. The second, behind, no longer knows the blockhash.
        fakes[0].failures.lock().push(RpcError::Timeout);
        fakes[1].failures.lock().push(RpcError::Rpc {
            code: -32002,
            message: "Blockhash not found".into(),
        });
        let sent = block_on(q.send_transaction(vec![], false, None));
        assert_eq!(sent, Err(RpcError::Timeout));
        assert!(!sent.unwrap_err().refused_send());
        assert_eq!(fakes[1].calls("send_transaction"), 1);
    }

    #[test]
    fn a_provider_behind_the_callers_slot_passes_a_send_on() {
        let fakes = [Arc::new(Fake::new(1, &[4])), Arc::new(Fake::new(1, &[5]))];
        let q = quorum(&fakes, 2);
        fakes[0]
            .failures
            .lock()
            .push(RpcError::MinContextSlot { min_slot: 9 });
        assert_eq!(
            block_on(q.send_transaction(vec![], false, Some(9))),
            Ok([5; 64])
        );
        // The provider that took it is asked first from now on.
        assert_eq!(
            block_on(q.send_transaction(vec![], false, Some(9))),
            Ok([5; 64])
        );
        assert_eq!(fakes[0].calls("send_transaction"), 1);
        // Nobody has reached the slot: the transaction was not forwarded.
        for f in &fakes {
            f.failures
                .lock()
                .push(RpcError::MinContextSlot { min_slot: 9 });
        }
        let sent = block_on(q.send_transaction(vec![], false, Some(9)));
        assert_eq!(sent, Err(RpcError::MinContextSlot { min_slot: 9 }));
        assert!(sent.unwrap_err().refused_send());
    }

    #[test]
    fn statuses_need_agreeing_providers() {
        let status = |level, err: Option<u32>| {
            Some(TxStatus {
                slot: 3,
                level,
                err: err.map(|code| crate::TxErrorDetail {
                    ix_index: Some(0),
                    custom: Some(code),
                    message: format!("{code}"),
                }),
            })
        };
        let fake = |s: Option<TxStatus>| {
            let mut f = Fake::new(1, &[4]);
            f.status = s;
            Arc::new(f)
        };
        // Two report it: at the level both reached.
        let fakes = [
            fake(status(Level::Processed, None)),
            fake(status(Level::Finalized, None)),
            fake(None),
        ];
        assert_eq!(
            block_on(quorum(&fakes, 2).signature_statuses(vec![[1; 64], [2; 64]])),
            Ok(vec![
                status(Level::Processed, None),
                status(Level::Processed, None)
            ])
        );
        assert_eq!(
            block_on(quorum(&fakes, 1).signature_statuses(vec![[1; 64]])),
            Ok(vec![status(Level::Finalized, None)]),
            "a quorum of one takes the highest level"
        );
        assert_eq!(
            block_on(quorum(&fakes, 3).signature_statuses(vec![[1; 64]])),
            Ok(vec![None])
        );
        // One provider claiming a failure is not enough.
        let fakes = [
            fake(status(Level::Confirmed, Some(6014))),
            fake(status(Level::Confirmed, None)),
            fake(None),
        ];
        assert_eq!(
            block_on(quorum(&fakes, 2).signature_statuses(vec![[1; 64]])),
            Ok(vec![None])
        );
        for f in &fakes[..2] {
            f.failures.lock().push(RpcError::Timeout);
        }
        assert_eq!(
            block_on(quorum(&fakes, 2).signature_statuses(vec![[1; 64]])),
            Err(RpcError::Timeout)
        );
    }
}
