//! Intake: session -> decode and signature verification on
//! the bounded verification pool -> submission checks -> bans ->
//! eligibility -> quota -> the market actor, which applies the epoch window,
//! capacity, fair share and deduplication and answers with promises or
//! relay-signed refusals. A batched request (one order's open and parked
//! epochs) is one actor command, so its items see one consistent state.
//!
//! Eligibility needs a Trader account whose available value - quote plus
//! base valued at the open band's low tick, reservations subtracted -
//! reaches `min_available_value_quote`. The per-epoch quota scales with it:
//! `min(max_envelopes_per_wallet_per_epoch, floor(value /
//! min_value_per_envelope_quote))`. Balances come from the last snapshot or,
//! on a miss, from one account read at the client's `min_context_slot`
//! (cached 30 s).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use timescales_chain::{Level, SolanaRpc, TraderEntry, TraderSnapshot};
use timescales_core::{Decode, MarketParams};
use timescales_service::api::{
    DecodeFailedDetails, DecodeReason, ErrorCode, ProblemDetails, U64, WalletNotEligibleDetails,
};
use timescales_service::relay::{RelayConfig, RelayError, Submission, verify_submission};
use timescales_service::store::node::NodeRepo;
use tokio::sync::{Semaphore, watch};

use crate::clock::Clock;
use crate::config::QuotaConfig;
use crate::market::runtime::MarketHandle;
use crate::market::{Cmd, IntakeItem, MarketView, Reply};
use crate::sessions::Sessions;
use crate::{Address, SessionRef, SubmitError, VerifiedSubmission};
use timescales_service::api::SubmitResult;

/// Account reads on a cache miss are reused this long.
const MISS_TTL_MS: u64 = 30_000;
/// Most looked-up (not snapshot) rows the eligibility cache keeps. Any client
/// can make the node look up a fresh wallet, so past this the lookup is still
/// answered but not cached.
const MAX_LOOKUP_ROWS: usize = 65_536;

/// How long a request waits for a verification slot before OVERLOADED.
const VERIFY_WAIT: Duration = Duration::from_secs(2);

/// Why a wallet may not trade in a market.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ineligible {
    NoTraderAccount,
    Insufficient {
        min: u64,
    },
    /// The chain could not be read.
    Unavailable(String),
}

/// What an eligible wallet may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    /// Envelopes per epoch, parked ones included.
    pub per_epoch: u32,
    pub available_value: u128,
}

#[derive(Clone, Copy, Debug)]
struct Cached {
    entry: Option<TraderEntry>,
    slot: u64,
    at_ms: u64,
    from_snapshot: bool,
}

struct EligibilityMarket {
    params: MarketParams,
    quota: QuotaConfig,
    view: watch::Receiver<MarketView>,
}

/// The eligibility cache: snapshot rows plus a bounded set of looked-up rows.
#[derive(Default)]
struct RowCache {
    rows: HashMap<(Address, Address), Cached>,
    /// Rows with `from_snapshot == false`.
    lookups: usize,
}

impl RowCache {
    fn get(&self, key: &(Address, Address)) -> Option<Cached> {
        self.rows.get(key).copied()
    }

    fn insert(&mut self, key: (Address, Address), row: Cached) {
        let added = usize::from(!row.from_snapshot);
        match self.rows.insert(key, row) {
            Some(old) if !old.from_snapshot => self.lookups = self.lookups - 1 + added,
            _ => self.lookups += added,
        }
    }

    fn retain(&mut self, mut keep: impl FnMut(&(Address, Address), &Cached) -> bool) {
        self.rows.retain(|k, c| keep(k, c));
        self.lookups = self.rows.values().filter(|c| !c.from_snapshot).count();
    }

    /// Caches a looked-up row. Expired lookups are swept once there are
    /// [`MAX_LOOKUP_ROWS`] of them. If they are all still fresh the new row is
    /// not cached. Snapshot rows are never evicted here.
    fn remember(&mut self, key: (Address, Address), row: Cached, now: u64) {
        let replaces_lookup = self.rows.get(&key).is_some_and(|c| !c.from_snapshot);
        if !replaces_lookup && self.lookups >= MAX_LOOKUP_ROWS {
            self.retain(|_, c| c.from_snapshot || now < c.at_ms.saturating_add(MISS_TTL_MS));
            if self.lookups >= MAX_LOOKUP_ROWS {
                return;
            }
        }
        self.insert(key, row);
    }
}

/// Eligibility and quotas of every market (the TraderCache).
pub struct Eligibility {
    program: Address,
    rpc: Arc<dyn SolanaRpc>,
    clock: Arc<dyn Clock>,
    markets: RwLock<BTreeMap<Address, EligibilityMarket>>,
    cache: Mutex<RowCache>,
}

impl core::fmt::Debug for Eligibility {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Eligibility").finish_non_exhaustive()
    }
}

impl Eligibility {
    pub fn new(program: Address, rpc: Arc<dyn SolanaRpc>, clock: Arc<dyn Clock>) -> Self {
        Self {
            program,
            rpc,
            clock,
            markets: RwLock::new(BTreeMap::new()),
            cache: Mutex::new(RowCache::default()),
        }
    }

    pub fn register(
        &self,
        market: Address,
        params: MarketParams,
        quota: QuotaConfig,
        view: watch::Receiver<MarketView>,
    ) {
        self.markets.write().insert(
            market,
            EligibilityMarket {
                params,
                quota,
                view,
            },
        );
    }

    /// Replaces the market's cached balances with a snapshot's.
    pub fn seed(&self, market: Address, snapshot: &TraderSnapshot) {
        let now = self.clock.now_ms();
        let mut cache = self.cache.lock();
        cache.retain(|(m, _), c| *m != market || !c.from_snapshot);
        for t in &snapshot.traders {
            cache.insert(
                (market, t.owner),
                Cached {
                    entry: Some(*t),
                    slot: snapshot.slot,
                    at_ms: now,
                    from_snapshot: true,
                },
            );
        }
    }

    async fn entry(
        &self,
        market: Address,
        wallet: Address,
        min_slot: Option<u64>,
    ) -> Result<Option<TraderEntry>, Ineligible> {
        let now = self.clock.now_ms();
        if let Some(c) = self.cache.lock().get(&(market, wallet)) {
            let fresh = c.from_snapshot || now < c.at_ms.saturating_add(MISS_TTL_MS);
            if fresh && min_slot.is_none_or(|s| c.slot >= s) {
                return Ok(c.entry);
            }
        }
        let pda = timescales_chain::program::trader_pda(&self.program, &market, &wallet)
            .map_err(|e| Ineligible::Unavailable(e.to_string()))?
            .0;
        let (slot, accounts) = self
            .rpc
            .get_multiple_accounts(vec![pda], Level::Confirmed, min_slot)
            .await
            .map_err(|e| Ineligible::Unavailable(e.to_string()))?;
        let entry = match accounts.into_iter().next().flatten() {
            Some(a)
                if a.owner == self.program
                    && a.data.len() == timescales_chain::program::TRADER_LEN =>
            {
                let decoded = timescales_chain::program::decode_trader(&a.data)
                    .map_err(|e| Ineligible::Unavailable(e.to_string()))?;
                if decoded.market != market || decoded.owner != wallet {
                    None
                } else {
                    let slice = &a.data[TraderEntry::SLICE_OFFSET
                        ..TraderEntry::SLICE_OFFSET + TraderEntry::SLICE_LEN];
                    TraderEntry::decode_slice(slice).ok()
                }
            }
            _ => None,
        };
        self.cache.lock().remember(
            (market, wallet),
            Cached {
                entry,
                slot,
                at_ms: now,
                from_snapshot: false,
            },
            now,
        );
        Ok(entry)
    }

    /// Whether `wallet` may trade in `market` now, and its quota.
    pub async fn check(
        &self,
        market: Address,
        wallet: Address,
        min_slot: Option<u64>,
    ) -> Result<Quota, Ineligible> {
        let (params, quota, view) = {
            let markets = self.markets.read();
            let m = markets
                .get(&market)
                .ok_or_else(|| Ineligible::Unavailable("unknown market".into()))?;
            (m.params, m.quota.clone(), m.view.borrow().clone())
        };
        let entry = self.entry(market, wallet, min_slot).await?;
        let min = quota.min_available_value_quote.0;
        let Some(entry) = entry else {
            return Err(if quota.require_trader_account {
                Ineligible::NoTraderAccount
            } else {
                Ineligible::Insufficient { min }
            });
        };
        let value = available_value(&params, &entry, view.next_epoch, view.band.map(|b| b.lo.0));
        if value < u128::from(min) {
            return Err(Ineligible::Insufficient { min });
        }
        let per_value = value / u128::from(quota.min_value_per_envelope_quote.0.max(1));
        let per_epoch = u32::try_from(per_value)
            .unwrap_or(u32::MAX)
            .min(quota.max_envelopes_per_wallet_per_epoch);
        Ok(Quota {
            per_epoch,
            available_value: value,
        })
    }
}

/// Quote plus base valued at `lo_tick` (available balances for batch
/// `epoch`), in quote atoms. Without an open band only the quote counts.
pub fn available_value(
    params: &MarketParams,
    entry: &TraderEntry,
    epoch: u64,
    lo_tick: Option<u64>,
) -> u128 {
    let (base, quote) = entry.available(epoch);
    let lots = u128::from(base) / u128::from(params.base_lot_size.max(1));
    let per_lot = u128::from(lo_tick.unwrap_or(0)).saturating_mul(u128::from(params.tick_size));
    u128::from(quote).saturating_add(lots.saturating_mul(per_lot))
}

fn plain(code: ErrorCode) -> SubmitError {
    SubmitError {
        code,
        details: serde_json::Value::Null,
        retry_after_ms: None,
        refusal: None,
    }
}

fn not_eligible(details: WalletNotEligibleDetails) -> SubmitError {
    SubmitError {
        code: ErrorCode::WalletNotEligible,
        details: ProblemDetails::WalletNotEligible(details).to_value(),
        retry_after_ms: None,
        refusal: None,
    }
}

fn overloaded() -> SubmitError {
    let mut e = plain(ErrorCode::Overloaded);
    e.retry_after_ms = Some(1_000);
    e
}

fn relay_refusal(e: &RelayError) -> SubmitError {
    plain(match e {
        RelayError::BadSignature | RelayError::Unauthorised => ErrorCode::BadSignature,
        RelayError::MaskedNotAllowed | RelayError::EncodingMismatch => {
            ErrorCode::MaskedNotSupported
        }
        // verify_submission's only auction error is a wrong market.
        RelayError::Auction(_) => ErrorCode::WrongMarket,
        RelayError::UnsupportedVersion(_) => ErrorCode::VersionUnsupported,
        _ => ErrorCode::BadRequest,
    })
}

/// Decodes `raw` exactly and runs the relay's stateless checks on it,
/// signature included. Blocking: call it on the verification pool.
pub fn verify_raw(
    cfg: &RelayConfig,
    raw: &[u8],
) -> Result<timescales_service::relay::VerifiedSubmission, SubmitError> {
    let sub = Submission::decode_exact(raw).map_err(|e| SubmitError {
        code: ErrorCode::DecodeFailed,
        details: ProblemDetails::DecodeFailed(DecodeFailedDetails {
            reason: DecodeReason::from(&e),
        })
        .to_value(),
        retry_after_ms: None,
        refusal: None,
    })?;
    verify_submission(cfg, &sub).map_err(|e| relay_refusal(&e))
}

/// The bounded verification pool: submission signatures are checked
/// on the blocking pool, at most `permits` requests at a time, and a request
/// that waits longer than two seconds for a slot is OVERLOADED.
#[derive(Clone, Debug)]
pub struct Verifier {
    permits: Arc<Semaphore>,
    wait: Duration,
}

impl Verifier {
    pub fn new(permits: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(permits.max(1))),
            wait: VERIFY_WAIT,
        }
    }

    /// Verifies every `raw` of one request, in order, on one blocking task.
    pub async fn verify(
        &self,
        cfg: &RelayConfig,
        raws: Vec<Vec<u8>>,
    ) -> Vec<Result<timescales_service::relay::VerifiedSubmission, SubmitError>> {
        let n = raws.len();
        let permit =
            match tokio::time::timeout(self.wait, self.permits.clone().acquire_owned()).await {
                Ok(Ok(p)) => p,
                _ => return vec![Err(overloaded()); n],
            };
        let cfg = cfg.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            raws.iter()
                .map(|raw| verify_raw(&cfg, raw))
                .collect::<Vec<_>>()
        })
        .await;
        joined.unwrap_or_else(|_| vec![Err(plain(ErrorCode::Internal)); n])
    }
}

/// The submission path of every market.
pub struct Intake {
    markets: BTreeMap<Address, (MarketHandle, RelayConfig)>,
    verifier: Verifier,
    sessions: Arc<Sessions>,
    eligibility: Arc<Eligibility>,
    repo: Arc<NodeRepo>,
    clock: Arc<dyn Clock>,
    reply_timeout: Duration,
}

impl core::fmt::Debug for Intake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Intake")
            .field("markets", &self.markets.len())
            .finish_non_exhaustive()
    }
}

impl Intake {
    pub fn new(
        markets: BTreeMap<Address, (MarketHandle, RelayConfig)>,
        verifier: Verifier,
        sessions: Arc<Sessions>,
        eligibility: Arc<Eligibility>,
        repo: Arc<NodeRepo>,
        clock: Arc<dyn Clock>,
        reply_timeout: Duration,
    ) -> Self {
        Self {
            markets,
            verifier,
            sessions,
            eligibility,
            repo,
            clock,
            reply_timeout,
        }
    }

    /// Decodes and verifies one submission of market `m` on the pool, for
    /// the API layer to build a [`VerifiedSubmission`] from request bytes.
    pub async fn verify(
        &self,
        m: Address,
        raw: Vec<u8>,
    ) -> Result<VerifiedSubmission, SubmitError> {
        let Some((_, cfg)) = self.markets.get(&m) else {
            return Err(plain(ErrorCode::MarketUnknown));
        };
        let inner = self
            .verifier
            .verify(cfg, vec![raw.clone()])
            .await
            .pop()
            .unwrap_or_else(|| Err(plain(ErrorCode::Internal)))?;
        Ok(VerifiedSubmission { raw, inner })
    }

    /// One request's submissions, in order, with one result each. Every
    /// item's bytes are decoded and its signature verified here, whatever
    /// the caller already checked.
    pub async fn submit(
        &self,
        m: Address,
        items: Vec<VerifiedSubmission>,
        session: SessionRef,
    ) -> Vec<Result<SubmitResult, SubmitError>> {
        let n = items.len();
        let all = |code: ErrorCode| vec![Err(plain(code)); n];
        let Some((handle, cfg)) = self.markets.get(&m) else {
            return all(ErrorCode::MarketUnknown);
        };
        let params = &cfg.params;
        let row = match self.sessions.active(session.session_key).await {
            Ok(row) => row,
            Err(code) => return all(code),
        };
        if row.wallet != session.wallet {
            return all(ErrorCode::SessionUnknown);
        }
        if row.market.is_some_and(|sm| sm != m) {
            return all(ErrorCode::WrongMarket);
        }
        let raws = items.iter().map(|i| i.raw.clone()).collect();
        let verified = self.verifier.verify(cfg, raws).await;
        let now = self.clock.now_ms();
        let mut results: Vec<Option<Result<SubmitResult, SubmitError>>> = vec![None; n];
        let mut accepted = Vec::new();
        let mut positions = Vec::new();
        for (i, (item, checked)) in items.into_iter().zip(verified).enumerate() {
            let checked = match checked {
                Ok(c) if c == item.inner => c,
                Ok(_) => {
                    results[i] = Some(Err(plain(ErrorCode::BadRequest)));
                    continue;
                }
                Err(e) => {
                    results[i] = Some(Err(e));
                    continue;
                }
            };
            let item = VerifiedSubmission {
                raw: item.raw,
                inner: checked,
            };
            let sub = &item.inner.submission;
            let env = &sub.envelope;
            let refusal = if sub.trader.0 != session.session_key {
                Some(ErrorCode::BadSignature)
            } else if sub.masked.is_some() {
                Some(ErrorCode::MaskedNotSupported)
            } else if env.market != params.market {
                Some(ErrorCode::WrongMarket)
            } else if env.version != timescales_core::PROTOCOL_VERSION {
                Some(ErrorCode::VersionUnsupported)
            } else if env.digest() != item.inner.envelope_digest {
                Some(ErrorCode::BadRequest)
            } else {
                None
            };
            match refusal {
                Some(code) => results[i] = Some(Err(plain(code))),
                None => {
                    positions.push(i);
                    accepted.push(IntakeItem {
                        sub: item,
                        received_at_ms: now,
                    });
                }
            }
        }
        if !accepted.is_empty() {
            let epoch = handle.view.borrow().next_epoch;
            let gate = match crate::market::store::banned_until(
                &self.repo,
                m,
                session.wallet,
                epoch,
            )
            .await
            {
                Ok(Some(until)) => Some(not_eligible(WalletNotEligibleDetails::Banned {
                    until_epoch: U64(until),
                })),
                Ok(None) => None,
                Err(_) => Some(plain(ErrorCode::Internal)),
            };
            let quota = match gate {
                Some(err) => Err(err),
                None => match self.eligibility.check(m, session.wallet, None).await {
                    Ok(q) => Ok(q),
                    Err(Ineligible::NoTraderAccount) => {
                        Err(not_eligible(WalletNotEligibleDetails::NoTraderAccount))
                    }
                    Err(Ineligible::Insufficient { min }) => Err(not_eligible(
                        WalletNotEligibleDetails::InsufficientAvailable {
                            min_available_value_quote: U64(min),
                        },
                    )),
                    Err(Ineligible::Unavailable(_)) => Err(plain(ErrorCode::MarketUnavailable)),
                },
            };
            let answers = match quota {
                Err(err) => vec![Err(err); accepted.len()],
                Ok(q) => self.send(handle, accepted, session, q.per_epoch).await,
            };
            for (i, r) in positions.into_iter().zip(answers) {
                results[i] = Some(r);
            }
        }
        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(plain(ErrorCode::Internal))))
            .collect()
    }

    async fn send(
        &self,
        handle: &MarketHandle,
        items: Vec<IntakeItem>,
        session: SessionRef,
        quota: u32,
    ) -> Vec<Result<SubmitResult, SubmitError>> {
        let n = items.len();
        let (request, rx) = handle.replies.register();
        let cmd = Cmd::Submit {
            request,
            items,
            session,
            quota,
        };
        if handle.tx.try_send(cmd).is_err() {
            handle.replies.cancel(request);
            return vec![Err(overloaded()); n];
        }
        match tokio::time::timeout(self.reply_timeout, rx).await {
            Ok(Ok(Reply::Submit { results, .. })) => results,
            _ => {
                handle.replies.cancel(request);
                vec![Err(overloaded()); n]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use timescales_core::{CommitmentScheme, FeeBps, FlowMode, MarketId, Rationing};

    fn params() -> MarketParams {
        MarketParams {
            market: MarketId(1),
            base_lot_size: 10,
            tick_size: 5,
            band_half_width: 16,
            max_order_lots_log2: 20,
            max_orders_per_trader: 8,
            max_batch_envelopes: 1024,
            max_order_lifetime: 8,
            maker_fee: FeeBps(0),
            taker_fee: FeeBps(10),
            flow: FlowMode::DualFlow,
            rationing: Rationing::ProRata,
            commitment_scheme: CommitmentScheme::Sha256,
        }
    }

    fn entry(base: u64, quote: u64) -> TraderEntry {
        TraderEntry {
            owner: [1; 32],
            base,
            quote,
            requested_base: 0,
            requested_quote: 0,
            request_epoch: 0,
            last_leaf_epoch: 0,
            last_change_slot: 0,
            floor_epoch: 0,
            floor_base: 0,
            floor_quote: 0,
        }
    }

    #[test]
    fn lookup_rows_stay_bounded() {
        let miss = |at_ms| Cached {
            entry: None,
            slot: 1,
            at_ms,
            from_snapshot: false,
        };
        let key = |i: usize| {
            ([1; 32], {
                let mut w = [0u8; 32];
                w[..8].copy_from_slice(&(i as u64).to_le_bytes());
                w
            })
        };
        let mut cache = RowCache::default();
        cache.insert(
            ([1; 32], [0xff; 32]),
            Cached {
                entry: None,
                slot: 1,
                at_ms: 0,
                from_snapshot: true,
            },
        );
        let mut now = 0;
        for i in 0..3 * MAX_LOOKUP_ROWS {
            if i % 1000 == 0 {
                now += 1_000;
            }
            cache.remember(key(i), miss(now), now);
            assert!(cache.rows.len() <= MAX_LOOKUP_ROWS + 1);
        }
        assert!(
            cache.rows.contains_key(&([1; 32], [0xff; 32])),
            "snapshot rows survive"
        );
    }

    #[test]
    fn value_counts_base_at_the_low_tick() {
        let p = params();
        // 100 base atoms = 10 lots, at tick 7 x 5 quote atoms per lot.
        assert_eq!(
            available_value(&p, &entry(100, 1_000), 3, Some(7)),
            1_000 + 350
        );
        assert_eq!(available_value(&p, &entry(100, 1_000), 3, None), 1_000);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_verification_pool_is_overloaded_after_two_seconds() {
        let v = Verifier::new(1);
        let held = v.permits.clone().acquire_owned().await.unwrap();
        let cfg = RelayConfig {
            params: params(),
            market_address: [7; 32],
            padding: timescales_service::relay::Padding::None,
            allow_masked: false,
            max_real: 8,
            carry_p: 0.0,
        };
        let started = tokio::time::Instant::now();
        let r = v.verify(&cfg, vec![vec![0; 3], vec![0; 3]]).await;
        assert!(started.elapsed() >= VERIFY_WAIT);
        assert_eq!(r.len(), 2);
        for e in r {
            let e = e.unwrap_err();
            assert_eq!(e.code, ErrorCode::Overloaded);
            assert_eq!(e.retry_after_ms, Some(1_000));
        }
        drop(held);
        let r = v.verify(&cfg, vec![vec![0; 3]]).await;
        assert_eq!(r[0].clone().unwrap_err().code, ErrorCode::DecodeFailed);
    }

    #[test]
    fn reservations_count_against_value() {
        let p = params();
        let mut t = entry(0, 1_000);
        t.requested_quote = 400;
        t.request_epoch = 2;
        // Epoch 2 itself may still use it. Epoch 3 may not.
        assert_eq!(available_value(&p, &t, 2, None), 1_000);
        assert_eq!(available_value(&p, &t, 3, None), 600);
    }
}
