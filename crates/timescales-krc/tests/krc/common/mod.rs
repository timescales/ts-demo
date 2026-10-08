//! Test world for the member and dealer suites: a market on a chain the
//! test writes directly, committees, a test dealer and a test enclave.
//!
//! With the features `litesvm` and `test-util` the chain is LiteSVM behind
//! two `FaultyRpc` providers and a `QuorumRpc` that needs both to agree, so
//! the member reads through the same commitment emulation and agreement
//! rules as against a cluster. Without them it is an in-memory map behind
//! the same `QuorumRpc`. Market and Batch accounts are written as the
//! program lays them out (`encode_market`, `encode_batch`, checked against
//! the chain crate's decoders), so tests can put a batch in any state
//! directly instead of driving the program there.
//!
//! The quote verifier is a test double (`TestVerifier`, evidence =
//! measurement || report data): the members' verifier and policy plumbing is
//! what is under test, not quote verification.

#![allow(dead_code, unreachable_pub)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use timescales_auction::{BatchHeader, epoch_binding, terms_digest};
use timescales_chain::program::{BATCH_LEN, BatchAccount, BatchStatus, MARKET_LEN, MarketAccount};
use timescales_chain::{Address, QuorumRpc, SolanaRpc};
use timescales_core::crypto::threshold::{FeldmanDealing, ScalarShare, x25519_public};
use timescales_core::crypto::{Keypair, SealSecret, Zeroizing, hash};
use timescales_core::{
    CommitmentScheme, Encode, EpochId, ExecutorId, FeeBps, FlowMode, HEADER_VERSION_ENVELOPE_BOUND,
    Hash32, MarketId, MarketParams, PriceBand, Rationing, Tick,
};
use timescales_executor::attestation::{
    AttestationError, Evidence, ExecutorAttestationV2, Measurement, Platform, QuoteVerifier,
    TcbStatus, VerifiedReport,
};
use timescales_executor::policy::AttestationPolicy;
use timescales_executor::tee::KeyReleaseRequest;
use timescales_krc::config::{ChainConfig, MarketEntry, MemberConfig, PolicyConfig};
use timescales_krc::member::{Member, MemberKeys};
use timescales_krc::{KrcChain, RpcKrcChain};
use timescales_service::store::member::MemberRepo;
use timescales_service::store::{RatchetSealer, Schema, Store, StoreOptions};
use timescales_service::wire::{
    CommitteeDescription, CommitteeMember, EpochKeyAnnouncement, KeyScheme, ShareDelivery,
};
use timescales_service::{LogFormat, Profile, TelemetryConfig};

pub const PROGRAM: &str = "FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL";
pub const MARKET_ID: u64 = 7;
pub const MEASUREMENT: Measurement = Measurement(Hash32([0x3e; 32]));

pub fn program() -> Address {
    timescales_chain::program::decode_base58(PROGRAM).unwrap()
}

pub fn market_address() -> Address {
    hash(b"test/krc/market", &[]).0
}

pub fn b58(key: &[u8; 32]) -> String {
    bs58::encode(key).into_string()
}

// ---- accounts ----

pub fn params() -> MarketParams {
    MarketParams {
        market: MarketId(MARKET_ID),
        base_lot_size: 1,
        tick_size: 1,
        band_half_width: 16,
        max_order_lots_log2: 40,
        max_orders_per_trader: 8,
        max_batch_envelopes: 1024,
        max_order_lifetime: 16,
        maker_fee: FeeBps(0),
        taker_fee: FeeBps(10),
        flow: FlowMode::DualFlow,
        rationing: Rationing::ProRata,
        commitment_scheme: CommitmentScheme::Sha256,
    }
}

pub fn market_account(committee_digest: Hash32, executors: &[Address]) -> MarketAccount {
    let mut slots = [[0u8; 32]; 8];
    for (slot, e) in slots.iter_mut().zip(executors) {
        *slot = *e;
    }
    MarketAccount {
        bump: 255,
        layout_version: timescales_chain::program::LAYOUT_VERSION,
        halted: false,
        market_id: MARKET_ID,
        creator: [1; 32],
        admin: [2; 32],
        pending_admin: None,
        relay: [3; 32],
        base_mint: [4; 32],
        quote_mint: [5; 32],
        base_vault: [6; 32],
        quote_vault: [7; 32],
        params: params(),
        params_digest: Hash32([8; 32]),
        committee_digest,
        executor_count: u8::try_from(executors.len()).unwrap(),
        receipt_quorum: 1,
        executors: slots,
        beacon_delay_slots: 4,
        timelock_slots: 20,
        exec_timeout_slots: 150,
        settle_timeout_slots: 1500,
        last_committed: 0,
        last_settled: 0,
        last_progress_slot: 0,
        fees_accrued: 0,
        fees_claimed: 0,
        prev_receipt: Hash32([0x9a; 32]),
        state_root: Hash32([0x5b; 32]),
        pending: None,
        salt: [0x5a; 32],
        prev_committee_digest: Hash32::ZERO,
    }
}

/// The on-chain layout of a Market account without a pending change.
pub fn encode_market(m: &MarketAccount) -> Vec<u8> {
    assert!(
        m.pending.is_none(),
        "encode_market writes no pending change"
    );
    let mut d = vec![
        timescales_chain::program::MARKET_TAG,
        m.bump,
        m.layout_version,
        u8::from(m.halted),
    ];
    d.extend_from_slice(&m.market_id.to_le_bytes());
    for k in [
        &m.creator,
        &m.admin,
        &m.pending_admin.unwrap_or([0; 32]),
        &m.relay,
    ] {
        d.extend_from_slice(k);
    }
    for k in [&m.base_mint, &m.quote_mint, &m.base_vault, &m.quote_vault] {
        d.extend_from_slice(k);
    }
    d.extend_from_slice(&m.params.to_bytes());
    d.extend_from_slice(m.params_digest.as_bytes());
    d.extend_from_slice(m.committee_digest.as_bytes());
    d.push(m.executor_count);
    d.push(m.receipt_quorum);
    for e in &m.executors {
        d.extend_from_slice(e);
    }
    d.extend_from_slice(&m.beacon_delay_slots.to_le_bytes());
    for v in [
        m.timelock_slots,
        m.exec_timeout_slots,
        m.settle_timeout_slots,
        m.last_committed,
        m.last_settled,
        m.last_progress_slot,
        m.fees_accrued,
        m.fees_claimed,
    ] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(m.prev_receipt.as_bytes());
    d.extend_from_slice(m.state_root.as_bytes());
    // Pending change: kind 0, eta, length, payload (all zero).
    d.resize(MARKET_LEN - 64, 0);
    d.extend_from_slice(&m.salt);
    d.extend_from_slice(m.prev_committee_digest.as_bytes());
    assert_eq!(d.len(), MARKET_LEN);
    d
}

pub fn batch_account(epoch: u64, status: BatchStatus) -> BatchAccount {
    BatchAccount {
        bump: 254,
        layout_version: timescales_chain::program::LAYOUT_VERSION,
        status,
        abort_reason: None,
        cosign_count: 0,
        cosign_bitmap: 0,
        market: market_address(),
        epoch,
        root: hash(b"test/krc/root", &epoch.to_le_bytes()),
        count: 16,
        terms_digest: Hash32::ZERO,
        commit_slot: 100,
        beacon_slot_a: 104,
        beacon_slot_b: 108,
        beacon: hash(b"test/krc/beacon", &epoch.to_le_bytes()),
        reveal_slot: 110,
        receipt_slot: 0,
        header_digest: Hash32::ZERO,
        receipt: Hash32::ZERO,
        outcome_digest: Hash32::ZERO,
        next_state_root: Hash32::ZERO,
        settlement_root: Hash32::ZERO,
        settlement_count: 0,
        fees: 0,
        verified_count: 0,
        applied_count: 0,
        sum_base: 0,
        sum_quote: 0,
        verified: [0; 128],
        applied: [0; 128],
    }
}

/// The on-chain layout of a Batch account.
pub fn encode_batch(b: &BatchAccount) -> Vec<u8> {
    let mut d = vec![
        timescales_chain::program::BATCH_TAG,
        b.bump,
        b.layout_version,
        b.status as u8,
        b.abort_reason.map_or(0, |r| r as u8),
        b.cosign_count,
        b.cosign_bitmap,
        0,
    ];
    d.extend_from_slice(&b.market);
    d.extend_from_slice(&b.epoch.to_le_bytes());
    d.extend_from_slice(b.root.as_bytes());
    d.extend_from_slice(&b.count.to_le_bytes());
    d.extend_from_slice(b.terms_digest.as_bytes());
    for v in [b.commit_slot, b.beacon_slot_a, b.beacon_slot_b] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(b.beacon.as_bytes());
    for v in [b.reveal_slot, b.receipt_slot] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    for h in [
        b.header_digest,
        b.receipt,
        b.outcome_digest,
        b.next_state_root,
        b.settlement_root,
    ] {
        d.extend_from_slice(h.as_bytes());
    }
    d.extend_from_slice(&b.settlement_count.to_le_bytes());
    d.extend_from_slice(&b.fees.to_le_bytes());
    d.extend_from_slice(&b.verified_count.to_le_bytes());
    d.extend_from_slice(&b.applied_count.to_le_bytes());
    d.extend_from_slice(&b.sum_base.to_le_bytes());
    d.extend_from_slice(&b.sum_quote.to_le_bytes());
    d.extend_from_slice(&b.verified);
    d.extend_from_slice(&b.applied);
    d.extend_from_slice(&[0; 32]);
    assert_eq!(d.len(), BATCH_LEN);
    d
}

pub fn batch_key(epoch: u64) -> Address {
    timescales_chain::program::batch_pda(&program(), &market_address(), epoch)
        .unwrap()
        .0
}

// ---- chain ----

#[cfg(all(feature = "litesvm", feature = "test-util"))]
mod backend {
    use super::*;
    use timescales_chain::{FaultyRpc, LiteSvmConfig, LiteSvmRpc, RpcError, RpcMethod};

    pub const FINALIZED_LAG: u64 = 4;

    /// LiteSVM with sysvars and the settlement program, behind two
    /// providers. This crate has no dependency on `litesvm` or the Solana
    /// account types, so values of those types are only ever obtained from
    /// `LiteSvmRpc` and LiteSVM themselves (by inference, never named).
    pub struct Backend {
        pub svm: Arc<LiteSvmRpc>,
        pub providers: [Arc<FaultyRpc<LiteSvmRpc>>; 2],
    }

    fn fresh<S: Default>(_: fn(S, LiteSvmConfig) -> LiteSvmRpc) -> S {
        S::default()
    }

    impl Backend {
        pub fn new() -> Self {
            let cfg = LiteSvmConfig {
                confirmed_lag: 1,
                finalized_lag: FINALIZED_LAG,
                slot_time: None,
                ..LiteSvmConfig::default()
            };
            let mut svm = fresh(LiteSvmRpc::new).with_sysvars().with_builtins();
            let so = timescales_chain::settlement_program_so();
            assert!(
                so.is_file(),
                "settlement program not found at {}; run scripts/build-program.sh",
                so.display()
            );
            svm.add_program_from_file(program(), &so).unwrap();
            svm.warp_to_slot(1_000);
            let svm = Arc::new(LiteSvmRpc::new(svm, cfg));
            let providers = [
                Arc::new(FaultyRpc::new(Arc::clone(&svm))),
                Arc::new(FaultyRpc::new(Arc::clone(&svm))),
            ];
            Self { svm, providers }
        }

        pub fn providers(&self) -> Vec<Arc<dyn SolanaRpc>> {
            self.providers
                .iter()
                .map(|p| Arc::clone(p) as Arc<dyn SolanaRpc>)
                .collect()
        }

        /// Writes a program-owned account at the current slot, then moves
        /// the clock past the finalized lag.
        pub fn put(&self, key: Address, data: Vec<u8>) {
            let clock = timescales_chain::program::decode_base58(
                "SysvarC1ock11111111111111111111111111111111",
            )
            .unwrap();
            self.svm.with_svm(|svm| {
                // An existing account gives a value of the account type.
                let mut account = svm.get_account(&clock.into()).unwrap();
                account.lamports = if data.is_empty() { 0 } else { 1_000_000_000 };
                account.data = data;
                account.owner = program().into();
                account.executable = false;
                svm.set_account(key.into(), account).unwrap();
            });
            self.svm.advance(FINALIZED_LAG + 1);
        }

        pub fn disagree(&self, on: bool) {
            self.providers[1].disagree(on);
        }

        pub fn fail_reads(&self, n: usize) {
            for p in &self.providers {
                p.fail_next(RpcMethod::GetAccount, n, RpcError::Unavailable);
                p.fail_next(RpcMethod::GetMultipleAccounts, n, RpcError::Unavailable);
            }
        }

        pub fn name() -> &'static str {
            "litesvm"
        }
    }
}

#[cfg(not(all(feature = "litesvm", feature = "test-util")))]
mod backend {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use parking_lot::Mutex;
    use timescales_chain::{AccountData, BoxFuture, Filter, Level, RpcError, Simulation, TxStatus};

    use super::*;

    type Accounts = Arc<Mutex<HashMap<Address, Vec<u8>>>>;

    /// One provider over the shared accounts. `flip` makes it return other
    /// bytes, as a lying or forked provider would.
    pub struct MapRpc {
        accounts: Accounts,
        flip: AtomicBool,
        fail: AtomicUsize,
    }

    impl MapRpc {
        fn read(&self, key: &Address) -> Result<Option<AccountData>, RpcError> {
            if self
                .fail
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(RpcError::Unavailable);
            }
            let flip = self.flip.load(Ordering::SeqCst);
            Ok(self.accounts.lock().get(key).cloned().map(|mut data| {
                if flip && let Some(last) = data.last_mut() {
                    *last ^= 1;
                }
                AccountData {
                    owner: program(),
                    lamports: 1,
                    data,
                    context_slot: 1_000,
                }
            }))
        }
    }

    fn unsupported<T: Send + 'static>() -> BoxFuture<'static, Result<T, RpcError>> {
        Box::pin(async { Err(RpcError::Unavailable) })
    }

    impl SolanaRpc for MapRpc {
        fn get_account(
            &self,
            key: Address,
            _: Level,
            _: Option<u64>,
        ) -> BoxFuture<'_, Result<Option<AccountData>, RpcError>> {
            Box::pin(async move { self.read(&key) })
        }
        fn get_multiple_accounts(
            &self,
            keys: Vec<Address>,
            _: Level,
            _: Option<u64>,
        ) -> BoxFuture<'_, Result<(u64, Vec<Option<AccountData>>), RpcError>> {
            Box::pin(async move {
                let accounts = keys
                    .iter()
                    .map(|k| self.read(k))
                    .collect::<Result<_, _>>()?;
                Ok((1_000, accounts))
            })
        }
        fn get_program_accounts(
            &self,
            _: Address,
            _: Vec<Filter>,
            _: Option<(usize, usize)>,
            _: Level,
            _: Option<u64>,
        ) -> BoxFuture<'_, Result<(u64, Vec<(Address, Vec<u8>)>), RpcError>> {
            unsupported()
        }
        fn latest_blockhash(&self, _: Level) -> BoxFuture<'_, Result<([u8; 32], u64), RpcError>> {
            unsupported()
        }
        fn send_transaction(
            &self,
            _: Vec<u8>,
            _: bool,
            _: Option<u64>,
        ) -> BoxFuture<'_, Result<[u8; 64], RpcError>> {
            unsupported()
        }
        fn simulate_transaction(&self, _: Vec<u8>) -> BoxFuture<'_, Result<Simulation, RpcError>> {
            unsupported()
        }
        fn signature_statuses(
            &self,
            _: Vec<[u8; 64]>,
        ) -> BoxFuture<'_, Result<Vec<Option<TxStatus>>, RpcError>> {
            unsupported()
        }
        fn slot(&self, _: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
            Box::pin(async { Ok(1_000) })
        }
        fn block_height(&self, _: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
            Box::pin(async { Ok(1_000) })
        }
        fn genesis_hash(&self) -> BoxFuture<'_, Result<[u8; 32], RpcError>> {
            Box::pin(async { Ok([0x6e; 32]) })
        }
        fn recent_prioritization_fees(
            &self,
            _: Vec<Address>,
        ) -> BoxFuture<'_, Result<Vec<u64>, RpcError>> {
            unsupported()
        }
        fn minimum_balance_for_rent_exemption(
            &self,
            _: usize,
        ) -> BoxFuture<'_, Result<u64, RpcError>> {
            unsupported()
        }
    }

    pub struct Backend {
        accounts: Accounts,
        providers: [Arc<MapRpc>; 2],
    }

    impl Backend {
        pub fn new() -> Self {
            let accounts = Accounts::default();
            let provider = || {
                Arc::new(MapRpc {
                    accounts: Arc::clone(&accounts),
                    flip: AtomicBool::new(false),
                    fail: AtomicUsize::new(0),
                })
            };
            let providers = [provider(), provider()];
            Self {
                accounts,
                providers,
            }
        }

        pub fn providers(&self) -> Vec<Arc<dyn SolanaRpc>> {
            self.providers
                .iter()
                .map(|p| Arc::clone(p) as Arc<dyn SolanaRpc>)
                .collect()
        }

        pub fn put(&self, key: Address, data: Vec<u8>) {
            let mut accounts = self.accounts.lock();
            if data.is_empty() {
                accounts.remove(&key);
            } else {
                accounts.insert(key, data);
            }
        }

        pub fn disagree(&self, on: bool) {
            self.providers[1].flip.store(on, Ordering::SeqCst);
        }

        pub fn fail_reads(&self, n: usize) {
            for p in &self.providers {
                p.fail.store(n, Ordering::SeqCst);
            }
        }

        pub fn name() -> &'static str {
            "in-memory"
        }
    }
}

pub use backend::Backend;

/// The chain a test controls: the Market and its Batch accounts.
pub struct Chain {
    pub backend: Backend,
    pub rpc: Arc<dyn SolanaRpc>,
    pub market: parking_lot::Mutex<MarketAccount>,
}

impl Chain {
    pub fn new(market: MarketAccount) -> Self {
        let backend = Backend::new();
        let rpc: Arc<dyn SolanaRpc> = Arc::new(
            QuorumRpc::new(backend.providers(), 2)
                .unwrap()
                .with_catch_up(Duration::ZERO, Duration::from_millis(1)),
        );
        backend.put(market_address(), encode_market(&market));
        Self {
            backend,
            rpc,
            market: parking_lot::Mutex::new(market),
        }
    }

    /// A member's chain view: finalized release reads, no confirmed cache
    /// (tests change the chain between calls).
    pub fn krc(&self) -> Arc<RpcKrcChain> {
        self.krc_cached(Duration::ZERO)
    }

    pub fn krc_cached(&self, confirmed_cache: Duration) -> Arc<RpcKrcChain> {
        Arc::new(RpcKrcChain::new(
            Arc::clone(&self.rpc),
            program(),
            timescales_chain::Level::Finalized,
            confirmed_cache,
        ))
    }

    pub fn update_market(&self, f: impl FnOnce(&mut MarketAccount)) {
        let mut m = self.market.lock();
        f(&mut m);
        self.backend.put(market_address(), encode_market(&m));
    }

    pub fn put_batch(&self, b: &BatchAccount) {
        self.backend.put(batch_key(b.epoch), encode_batch(b));
    }

    pub fn remove_batch(&self, epoch: u64) {
        self.backend.put(batch_key(epoch), Vec::new());
    }
}

// ---- committees ----

/// Committee keys. Member `i`'s keys depend only on `(key_set, i)`, so two
/// committees with the same key set share members.
pub struct Committee {
    pub desc: CommitteeDescription,
    pub identities: Vec<Keypair>,
    pub transports: Vec<SealSecret>,
}

pub fn member_identity(key_set: u8, index: u8) -> Keypair {
    Keypair::from_seed(hash(b"test/krc/identity", &[key_set, index]).0)
}

pub fn member_transport(key_set: u8, index: u8) -> SealSecret {
    SealSecret::from_bytes(hash(b"test/krc/transport", &[key_set, index]).0)
}

pub fn committee(market: Address, n: u8, t: u8, key_set: u8) -> Committee {
    let identities: Vec<Keypair> = (1..=n).map(|i| member_identity(key_set, i)).collect();
    let transports: Vec<SealSecret> = (1..=n).map(|i| member_transport(key_set, i)).collect();
    let desc = CommitteeDescription {
        version: CommitteeDescription::VERSION,
        market,
        threshold: t,
        members: (1..=n)
            .map(|i| CommitteeMember {
                index: i,
                identity: identities[usize::from(i - 1)].public(),
                transport: transports[usize::from(i - 1)].public(),
            })
            .collect(),
    };
    desc.validate().unwrap();
    Committee {
        desc,
        identities,
        transports,
    }
}

impl Committee {
    pub fn digest(&self) -> Hash32 {
        self.desc.digest()
    }

    pub fn write(&self, path: &Path) {
        std::fs::write(path, self.desc.to_bytes()).unwrap();
    }
}

pub fn dealer_key() -> Keypair {
    Keypair::from_seed(hash(b"test/krc/dealer", &[]).0)
}

/// A test dealing: the announcement, one delivery per member and the
/// plaintext shares (for checks only, the real dealer never keeps them).
pub struct TestDealing {
    pub announcement: EpochKeyAnnouncement,
    pub deliveries: Vec<ShareDelivery>,
    pub shares: Vec<ScalarShare>,
}

pub fn deal(c: &Committee, epoch: u64) -> TestDealing {
    let n = u8::try_from(c.desc.members.len()).unwrap();
    let (secret, commitments, shares) =
        FeldmanDealing::try_new(&mut OsRng, c.desc.threshold, n).unwrap();
    let announcement = EpochKeyAnnouncement {
        version: EpochKeyAnnouncement::VERSION,
        market: c.desc.market,
        epoch: EpochId(epoch),
        committee_digest: c.digest(),
        scheme: KeyScheme::FeldmanEd25519,
        epoch_pk: x25519_public(&secret),
        commitments,
    };
    let deliveries = shares
        .iter()
        .map(|s| {
            ShareDelivery::seal(
                &mut OsRng,
                announcement.clone(),
                c.desc.member(s.index).unwrap(),
                s,
            )
            .unwrap()
        })
        .collect();
    TestDealing {
        announcement,
        deliveries,
        shares,
    }
}

// ---- members ----

/// Accepts simulated-platform evidence `measurement32 || report_data64`.
#[derive(Debug)]
pub struct TestVerifier;

impl QuoteVerifier for TestVerifier {
    fn verify(&self, e: &Evidence) -> Result<VerifiedReport, AttestationError> {
        if e.platform != Platform::Simulated {
            return Err(AttestationError::UnsupportedPlatform(e.platform));
        }
        let (m, data) = e
            .quote
            .split_at_checked(32)
            .ok_or(AttestationError::Malformed("short quote"))?;
        let report_data: [u8; 64] = data
            .try_into()
            .map_err(|_| AttestationError::Malformed("report data"))?;
        Ok(VerifiedReport {
            platform: Platform::Simulated,
            measurement: Measurement(Hash32(m.try_into().unwrap())),
            tcb: TcbStatus::UpToDate,
            debug: false,
            report_data,
            platform_id: Hash32::ZERO,
            td: None,
        })
    }
}

pub fn evidence(measurement: Measurement, report_data: [u8; 64]) -> Evidence {
    let mut quote = measurement.0.0.to_vec();
    quote.extend_from_slice(&report_data);
    Evidence {
        platform: Platform::Simulated,
        quote,
    }
}

pub fn test_policy() -> AttestationPolicy {
    AttestationPolicy::strict([Platform::Simulated], [MEASUREMENT])
}

pub fn telemetry() -> TelemetryConfig {
    TelemetryConfig {
        log_format: LogFormat::Pretty,
        log_filter: "info".into(),
        otlp_endpoint: String::new(),
        service_name: None,
    }
}

pub fn chain_config() -> ChainConfig {
    ChainConfig {
        cluster: "localnet".into(),
        genesis_hash: b58(&[0x6e; 32]),
        program_id: PROGRAM.into(),
        rpc_urls: vec![
            "http://127.0.0.1:8899".into(),
            "http://127.0.0.1:8898".into(),
        ],
        rpc_agree: 2,
        release_commitment: Some("finalized".into()),
        confirmed_cache_ms: Some(0),
        rpc_timeout_ms: 5000,
    }
}

pub fn member_config(dir: &Path, index: u8, committee_file: PathBuf) -> MemberConfig {
    MemberConfig {
        profile: Profile::Local,
        index,
        listen: "127.0.0.1:0".into(),
        ops_listen: "127.0.0.1:0".into(),
        data_dir: dir.join("data"),
        identity_key: dir.join("identity.hex"),
        transport_key: dir.join("transport.hex"),
        kek_file: dir.join("kek.keys"),
        kek_ratchet_epochs: 64,
        shares_dir: dir.join("shares"),
        dealer_keys: vec![hex::encode(dealer_key().public())],
        skew_ms: 30_000,
        nonce_ttl_ms: 60_000,
        max_nonces_per_epoch_executor: 16,
        max_outstanding_nonces: 4096,
        max_releases_per_epoch: 8,
        per_caller_rps: 1000,
        per_caller_burst: 1000,
        prune_interval_ms: 10_000,
        audit_retention_days: 90,
        markets: vec![MarketEntry {
            address: b58(&market_address()),
            committee_file,
        }],
        tls: None,
        chain: chain_config(),
        policy: PolicyConfig {
            platforms: vec!["simulated".into()],
            measurements: vec![MEASUREMENT.0.to_hex()],
            allow_debug: false,
            min_tcb: "up_to_date".into(),
            simulated_vendor_root: Some("00".repeat(32)),
            tdx_collateral_file: None,
            tdx_mr_config_id: String::new(),
            tdx_td_attributes_mask: String::new(),
            tdx_xfam: String::new(),
        },
        telemetry: telemetry(),
    }
}

/// The two database files of a member under `dir`.
pub fn member_repo(dir: &Path, at_rest: &Arc<RatchetSealer>) -> MemberRepo {
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::create_dir_all(dir.join("shares")).unwrap();
    let member = Store::open(
        &dir.join("data/member.sqlite"),
        Schema::Member,
        StoreOptions::default(),
    )
    .unwrap();
    let shares = Store::open(
        &dir.join("shares/shares.sqlite"),
        Schema::MemberShares,
        StoreOptions {
            secure_delete: true,
            ..StoreOptions::default()
        },
    )
    .unwrap();
    MemberRepo::new(member, shares, Arc::clone(at_rest))
}

pub fn at_rest(dir: &Path) -> Arc<RatchetSealer> {
    let path = dir.join("kek.keys");
    Arc::new(if path.exists() {
        RatchetSealer::load(&path).unwrap()
    } else {
        RatchetSealer::create(
            &path,
            0,
            Zeroizing::new(hash(b"test/krc/kek", dir.as_os_str().as_encoded_bytes()).0),
        )
        .unwrap()
    })
}

/// Member `index` of `committee` (key set `key_set`), with its files in
/// `dir`. Opening the same `dir` again is a restart.
pub fn open_member(dir: &Path, cfg: MemberConfig, key_set: u8, chain: Arc<dyn KrcChain>) -> Member {
    let index = cfg.index;
    let at_rest = at_rest(dir);
    let repo = member_repo(dir, &at_rest);
    Member::new(
        cfg,
        MemberKeys {
            identity: member_identity(key_set, index),
            transport: member_transport(key_set, index),
            at_rest,
        },
        repo,
        chain,
        Arc::new(TestVerifier),
        test_policy(),
    )
    .unwrap()
}

// ---- enclave ----

pub struct Enclave {
    pub executor: Keypair,
    pub seal: SealSecret,
}

impl Enclave {
    pub fn new(seed: u8) -> Self {
        Self {
            executor: Keypair::from_seed(hash(b"test/krc/executor", &[seed]).0),
            seal: SealSecret::from_bytes(hash(b"test/krc/seal", &[seed]).0),
        }
    }

    pub fn id(&self) -> ExecutorId {
        ExecutorId(self.executor.public())
    }
}

pub fn band() -> PriceBand {
    PriceBand {
        lo: Tick(90),
        hi: Tick(110),
        reference: Tick(100),
    }
}

pub const PRICE_COMMITMENT: Hash32 = Hash32([0x9c; 32]);

/// The epoch binding a relay commits for this announcement and committee.
pub fn binding(announcement: &EpochKeyAnnouncement) -> Hash32 {
    epoch_binding(
        &PRICE_COMMITMENT,
        &announcement.digest(),
        &announcement.committee_digest,
    )
}

/// The batch a relay commits for `announcement`, beacon revealed.
pub fn revealed_batch(announcement: &EpochKeyAnnouncement) -> BatchAccount {
    let mut b = batch_account(announcement.epoch.0, BatchStatus::BeaconRevealed);
    b.terms_digest = terms_digest(&band(), &binding(announcement));
    b
}

/// The version 2 header of `batch` on top of `market`.
pub fn header(market: &MarketAccount, batch: &BatchAccount, balances_root: Hash32) -> BatchHeader {
    BatchHeader {
        version: HEADER_VERSION_ENVELOPE_BOUND,
        market: MarketId(market.market_id),
        epoch: EpochId(batch.epoch),
        params: market.params,
        band: band(),
        price_commitment: Hash32::ZERO,
        envelope_count: batch.count,
        batch_root: batch.root,
        beacon: batch.beacon,
        prior_state_root: market.state_root,
        balances_root,
        prev_receipt: market.prev_receipt,
    }
}

/// A release request of `enclave` for `header` (whose binding is set from
/// `announcement`), carrying `nonce` in the slot of member `index` of an
/// `n`-member committee, attested with `measurement`.
#[allow(clippy::too_many_arguments)]
pub fn release_request(
    enclave: &Enclave,
    mut header: BatchHeader,
    announcement: &EpochKeyAnnouncement,
    index: u8,
    n: u8,
    nonce: Hash32,
    measurement: Measurement,
) -> KeyReleaseRequest {
    header.price_commitment = binding(announcement);
    let mut nonces = vec![Hash32::ZERO; usize::from(n)];
    nonces[usize::from(index - 1)] = nonce;
    let mut attestation = ExecutorAttestationV2 {
        executor: enclave.id(),
        seal_key: enclave.seal.public(),
        header_digest: header.digest(),
        nonces,
        committee_digest: announcement.committee_digest,
        evidence: Evidence {
            platform: Platform::Simulated,
            quote: Vec::new(),
        },
    };
    attestation.evidence = evidence(measurement, attestation.expected_report_data());
    KeyReleaseRequest {
        header,
        price_commitment: PRICE_COMMITMENT,
        attestation,
    }
}

/// Opens a released share as the enclave does: `index || scalar`.
pub fn open_released(
    enclave: &Enclave,
    header: &BatchHeader,
    share: &timescales_executor::tee::SealedShare,
) -> Zeroizing<Vec<u8>> {
    let mut info = b"key-release".to_vec();
    header.market.encode(&mut info);
    header.epoch.encode(&mut info);
    timescales_core::crypto::open(
        &enclave.seal,
        &share.sealed.ephemeral,
        &info,
        header.digest().as_bytes(),
        &share.sealed.ciphertext,
    )
    .unwrap()
}

/// Every occurrence of `needle` in the files under `dir`.
pub fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path)
                && bytes.windows(needle.len()).any(|w| w == needle)
            {
                found.push(path);
            }
        }
    }
    found
}
