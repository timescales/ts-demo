//! Test world for the enclave suites: the settlement program in LiteSVM, a
//! market initialised through the program, enclave services booted on the
//! simulated platform behind real HTTP listeners, and key-release members
//! behind real HTTP listeners.
//!
//! The members are stand-ins written here: this crate has no dependency on
//! `timescales-krc`.
//! Each one is the release core `KeyReleaseMember` of
//! the executor tee module, the decision every KRC member makes, behind
//! `/krc/v1/challenge` and `/krc/v1/release` with the member service's wire
//! behaviour: prefix-first `SignedEnvelope` requests, member-signed
//! answers, refusals as `ReleaseResponse` tag 1. Its release context is
//! read from the same LiteSVM chain at finalized.
//!
//! The dealer is the test itself: it deals Feldman shares, has the members
//! sign acks and stores each share in its member's core directly.
//!
//! LiteSVM, the Solana account and address types are never named (this
//! crate does not depend on them): values of those types come from
//! `LiteSvmRpc` and LiteSVM by inference.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::result_large_err
)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use rand_core::{OsRng, RngCore};
use timescales_auction::collateral::BalanceSheet;
use timescales_auction::{BatchHeader, batch_leaves, epoch_binding, terms_digest};
use timescales_chain::program::{
    BatchAccount, BatchStatus, InitMarketArgs, MarketAccount, TOKEN_PROGRAM,
};
use timescales_chain::{
    Address, BatchPredicate, CommitOutcome, FaultyRpc, FeeMode, FeePolicy, FileSigner, Level,
    LiteSvmConfig, LiteSvmRpc, MarketChain, MarketChainConfig, QuorumRpc, RevealOutcome,
    SolanaMarketChain, SolanaRpc, TxOp, TxSender, TxSigner,
};
use timescales_core::crypto::threshold::{FeldmanDealing, ScalarShare, edwards_u};
use timescales_core::crypto::{Hasher, Keypair, SealSecret, Signature, Zeroizing, domain, hash};
use timescales_core::intent::{
    IntentBody, PrivateIntent, SealedEnvelope, commit_body, signed_message,
};
use timescales_core::{
    CommitmentScheme, Decode, Encode, EpochId, ExecutorId, FeeBps, FlowMode, Hash32, Lots,
    MarketId, MarketParams, Order, OrderKind, Rationing, Role, Side, Tick, TraderId,
};
use timescales_enclave::config::{EnclaveChain, EnclaveMarket, PlatformKind, PriorityFee};
use timescales_enclave::{EnclaveConfig, EnclaveService, TxLog, keygen_simulated, router};
use timescales_executor::ExecutionBatch;
use timescales_executor::attestation::Platform;
use timescales_executor::attestation::simulated::SimulatedQuoteVerifier;
use timescales_executor::policy::AttestationPolicy;
use timescales_executor::tee::{
    BatchView, HeldAnnouncement, KeyReleaseMember, KeyReleaseRequest, ReleaseContext,
    program_measurement,
};
use timescales_service::wire::{
    ChainId, ChallengeRequest, ChallengeResponse, CommitteeDescription, CommitteeMember,
    EpochKeyAck, EpochKeyAnnouncement, EpochKeyBundle, ErrorResponse, ExecutePosted, ExecuteReady,
    ExecuteRequest, GrantMethod, GrantRecord, KeyScheme, MessageKind, Provenance, ProvenanceEntry,
    PublishRequest, ReleaseRefusal, ReleaseResponse, ReplayGuard, SESSION_STATEMENT, SessionGrant,
    render_session_message,
};
use timescales_service::{
    ClientError, EnvelopeAuth, HttpLimits, LogFormat, Profile, SignedClient, TelemetryConfig,
    VerifiedEnvelope, sealed_response, sealed_response_with_status,
};

/// The dev program id. LiteSVM runs the program under it.
pub const PROGRAM: &str = "FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL";
pub const SLOT: Duration = Duration::from_millis(50);
pub const FINALIZED_LAG: u64 = 4;
pub const BEACON_DELAY: u16 = 4;
pub const DOMAIN: &str = "localhost:4173";
pub const REFERENCE: Tick = Tick(100);
pub const VENDOR_SEED: [u8; 32] = [0x5e; 32];
pub const THRESHOLD: u8 = 2;
pub const MEMBERS: u8 = 3;

pub fn program() -> Address {
    timescales_chain::program::decode_base58(PROGRAM).unwrap()
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn key(label: &[u8], i: u64) -> Keypair {
    Keypair::from_seed(hash(label, &i.to_le_bytes()).0)
}

/// A Solana signer for an Ed25519 keypair.
pub fn signer(kp: &Keypair) -> Arc<dyn TxSigner> {
    let mut bytes = Zeroizing::new([0u8; 64]);
    bytes[..32].copy_from_slice(kp.seed().as_slice());
    bytes[32..].copy_from_slice(&kp.public());
    Arc::new(FileSigner::from_bytes(bytes).unwrap())
}

fn fresh<S: Default>(_: fn(S, LiteSvmConfig) -> LiteSvmRpc) -> S {
    S::default()
}

/// Writes an account at the current slot: `owner`, `lamports`, `data`.
/// A value of LiteSVM's account type is obtained from an existing account.
pub fn put_account(svm: &LiteSvmRpc, key: Address, owner: Address, lamports: u64, data: Vec<u8>) {
    let clock =
        timescales_chain::program::decode_base58("SysvarC1ock11111111111111111111111111111111")
            .unwrap();
    svm.with_svm(|svm| {
        let mut account = svm.get_account(&clock.into()).unwrap();
        account.lamports = lamports;
        account.data = data;
        account.owner = owner.into();
        account.executable = false;
        svm.set_account(key.into(), account).unwrap();
    });
}

fn mint_data() -> Vec<u8> {
    let mut d = vec![0u8; timescales_chain::program::spl::MINT_LEN];
    d[44] = 6;
    d[45] = 1;
    d
}

fn token_account_data(mint: &Address, owner: &Address) -> Vec<u8> {
    let mut d = vec![0u8; timescales_chain::program::spl::TOKEN_ACCOUNT_LEN];
    d[..32].copy_from_slice(mint);
    d[32..64].copy_from_slice(owner);
    d[108] = 1;
    d
}

/// The on-chain layout of a Trader account.
pub fn trader_data(market: &Address, owner: &Address, bump: u8, base: u64, quote: u64) -> Vec<u8> {
    let mut d = vec![
        timescales_chain::program::TRADER_TAG,
        bump,
        timescales_chain::program::LAYOUT_VERSION,
        0,
    ];
    d.extend_from_slice(market);
    d.extend_from_slice(owner);
    // base, quote, requested x2, request_epoch, last_leaf_epoch,
    // last_change_slot, floor epoch, floor x2.
    for v in [base, quote, 0, 0, 0, 0, 0, 0, 0, 0] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(d.len(), timescales_chain::program::TRADER_LEN);
    d
}

pub fn params(market_id: u64) -> MarketParams {
    MarketParams {
        market: MarketId(market_id),
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

// ---- members ----

pub struct MemberState {
    pub index: u8,
    pub identity: Keypair,
    pub core: KeyReleaseMember,
    chain: Arc<SolanaMarketChain>,
    market_id: u64,
    auth: EnvelopeAuth,
    pub challenges: AtomicU64,
    pub releases: AtomicU64,
}

/// The router state of a member stand-in.
#[derive(Clone)]
struct MemberApp(Arc<MemberState>);

impl FromRef<MemberApp> for EnvelopeAuth {
    fn from_ref(s: &MemberApp) -> Self {
        s.0.auth.clone()
    }
}

fn batch_view(b: &BatchAccount) -> BatchView {
    use timescales_auction::CommittedStatus as C;
    let status = match b.status {
        BatchStatus::Committed => C::Committed,
        BatchStatus::BeaconRevealed => C::BeaconRevealed,
        BatchStatus::ReceiptPosted => C::ReceiptPosted,
        BatchStatus::Verified => C::Verified,
        BatchStatus::Settled => C::Settled,
        BatchStatus::Aborted => C::Aborted,
    };
    let posted = matches!(
        b.status,
        BatchStatus::ReceiptPosted | BatchStatus::Verified | BatchStatus::Settled
    );
    BatchView {
        status,
        root: b.root,
        count: b.count,
        terms_digest: b.terms_digest,
        beacon: (b.status != BatchStatus::Committed).then_some(b.beacon),
        header_digest: posted.then_some(b.header_digest),
        applied_count: b.applied_count,
    }
}

impl MemberState {
    fn sealed(&self, kind: MessageKind, to: [u8; 32], body: Vec<u8>) -> Response {
        sealed_response(kind, &self.identity, to, now_ms(), body)
    }

    fn refuse(&self, status: StatusCode, to: [u8; 32], code: ReleaseRefusal) -> Response {
        sealed_response_with_status(
            status,
            MessageKind::ReleaseResponse,
            &self.identity,
            to,
            now_ms(),
            ReleaseResponse::refused(code, &format!("{code:?}")).to_bytes(),
        )
    }

    /// One read of the chain state a release depends on: Market and Batch
    /// at finalized, the halt flag at confirmed.
    async fn context(&self, epoch: u64) -> Option<ReleaseContext> {
        let m = self.chain.market(Level::Finalized).await.ok()?;
        let b = self.chain.batch(epoch, Level::Finalized).await.ok()?;
        let halted = self.chain.market(Level::Confirmed).await.ok()?.halted;
        Some(ReleaseContext {
            executors: m
                .executors
                .iter()
                .filter(|k| **k != [0; 32])
                .map(|k| ExecutorId(*k))
                .collect(),
            committee_digest: m.committee_digest,
            prev_committee_digest: m.prev_committee_digest,
            params: m.params,
            last_settled: EpochId(m.last_settled),
            state_root: m.state_root,
            prev_receipt: m.prev_receipt,
            halted,
            batch: b.as_ref().map(batch_view),
        })
    }
}

async fn member_challenge(
    State(MemberApp(s)): State<MemberApp>,
    env: VerifiedEnvelope,
) -> Response {
    s.challenges.fetch_add(1, Ordering::SeqCst);
    let Ok(r) = ChallengeRequest::decode_exact(&env.body) else {
        return s.refuse(
            StatusCode::BAD_REQUEST,
            env.sender,
            ReleaseRefusal::BadRequest,
        );
    };
    if r.executor.0 != env.sender {
        return s.refuse(
            StatusCode::FORBIDDEN,
            env.sender,
            ReleaseRefusal::Unauthenticated,
        );
    }
    match s
        .core
        .issue_nonce(MarketId(s.market_id), r.epoch, r.executor)
    {
        Ok(nonce) => s.sealed(
            MessageKind::ChallengeResponse,
            env.sender,
            ChallengeResponse {
                member: s.index,
                market: r.market,
                epoch: r.epoch,
                nonce,
                expires_at_ms: now_ms() + 60_000,
            }
            .to_bytes(),
        ),
        Err(e) => s.refuse(StatusCode::CONFLICT, env.sender, ReleaseRefusal::from(&e)),
    }
}

async fn member_release(State(MemberApp(s)): State<MemberApp>, env: VerifiedEnvelope) -> Response {
    s.releases.fetch_add(1, Ordering::SeqCst);
    let response = match KeyReleaseRequest::decode_exact(&env.body) {
        Err(_) => ReleaseResponse::refused(ReleaseRefusal::BadRequest, "decode"),
        Ok(r) if r.attestation.executor.0 != env.sender => {
            ReleaseResponse::refused(ReleaseRefusal::Unauthenticated, "sender")
        }
        Ok(r) => match s.context(r.header.epoch.0).await {
            None => ReleaseResponse::refused(ReleaseRefusal::NotFinal, "chain read"),
            Some(ctx) => match s.core.decide(&r, &ctx) {
                Ok(share) => ReleaseResponse::Share(share),
                Err(e) => ReleaseResponse::refused(ReleaseRefusal::from(&e), &e.to_string()),
            },
        },
    };
    s.sealed(
        MessageKind::ReleaseResponse,
        env.sender,
        response.to_bytes(),
    )
}

pub struct Member {
    pub url: String,
    pub state: Arc<MemberState>,
}

impl Member {
    pub fn challenges(&self) -> u64 {
        self.state.challenges.load(Ordering::SeqCst)
    }

    pub fn releases(&self) -> u64 {
        self.state.releases.load(Ordering::SeqCst)
    }
}

pub async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

// ---- enclaves ----

pub struct TestEnclave {
    pub svc: Arc<EnclaveService>,
    pub url: String,
    pub client: SignedClient,
    /// Its two RPC providers. Its market chain needs both to agree.
    pub providers: [Arc<FaultyRpc<LiteSvmRpc>>; 2],
    pub log: Arc<TxLog>,
    pub fee_payer: Arc<dyn TxSigner>,
}

pub type Refusal = (u16, ErrorResponse);

fn refusal(e: ClientError) -> Refusal {
    match e {
        ClientError::Refused { status, envelope } => {
            assert_eq!(envelope.kind, MessageKind::ErrorResponse);
            (status, ErrorResponse::decode_exact(&envelope.body).unwrap())
        }
        other => panic!("expected a signed refusal, got {other:?}"),
    }
}

impl TestEnclave {
    pub fn executor(&self) -> ExecutorId {
        self.svc.executor()
    }

    /// `POST /enclave/v1/execute` as the node. The raw response body on
    /// success.
    pub async fn execute_raw(&self, req: &ExecuteRequest) -> Result<Vec<u8>, Refusal> {
        let env = self
            .client
            .call(
                &format!("{}/enclave/v1/execute", self.url),
                MessageKind::ExecuteRequest,
                req.to_bytes(),
            )
            .await
            .map_err(refusal)?;
        assert_eq!(env.kind, MessageKind::ExecuteReady);
        Ok(env.body)
    }

    pub async fn execute(&self, req: &ExecuteRequest) -> Result<ExecuteReady, Refusal> {
        self.execute_raw(req)
            .await
            .map(|b| ExecuteReady::decode_exact(&b).unwrap())
    }

    pub async fn publish(&self, req: &PublishRequest) -> Result<ExecutePosted, Refusal> {
        let env = self
            .client
            .call(
                &format!("{}/enclave/v1/publish", self.url),
                MessageKind::PublishRequest,
                req.to_bytes(),
            )
            .await
            .map_err(refusal)?;
        assert_eq!(env.kind, MessageKind::ExecutePosted);
        Ok(ExecutePosted::decode_exact(&env.body).unwrap())
    }

    pub fn fault_both(&self, f: impl Fn(&FaultyRpc<LiteSvmRpc>)) {
        for p in &self.providers {
            f(p);
        }
    }
}

// ---- traders ----

pub struct TestTrader {
    pub wallet_seed: [u8; 32],
    pub wallet: Keypair,
    pub session: Keypair,
    pub grant: GrantRecord,
}

impl TestTrader {
    pub fn id(&self) -> TraderId {
        TraderId(self.wallet.public())
    }
}

/// An order of one envelope.
#[derive(Clone, Copy, Debug)]
pub struct OrderSpec {
    pub trader: usize,
    pub side: Side,
    pub role: Role,
    pub limit: u64,
    pub qty: u64,
    /// The session that submits it, when not the trader's own.
    pub via: Option<usize>,
}

impl OrderSpec {
    pub fn new(trader: usize, side: Side, role: Role, limit: u64, qty: u64) -> Self {
        Self {
            trader,
            side,
            role,
            limit,
            qty,
            via: None,
        }
    }
}

/// Two traders whose orders cross in both books.
pub fn crossing_orders() -> Vec<OrderSpec> {
    vec![
        OrderSpec::new(0, Side::Buy, Role::Maker, 105, 10),
        OrderSpec::new(1, Side::Sell, Role::Taker, 95, 10),
        OrderSpec::new(1, Side::Sell, Role::Maker, 95, 10),
        OrderSpec::new(0, Side::Buy, Role::Taker, 105, 10),
    ]
}

// ---- the world ----

#[derive(Clone, Debug)]
pub struct Options {
    pub enclaves: usize,
    /// Registered executors whose keys the test holds (not enclaves).
    pub extra_executors: usize,
    pub quorum: u8,
    pub post_deadline_ms: u64,
    pub reveal_backstop_slots: u64,
    pub settle_backstop_after_ms: u64,
    /// Rotate the market to another committee digest after it is set up,
    /// so the test committee is the market's previous one.
    pub rotate_committee: bool,
    /// A member that holds a share inconsistent with the commitments.
    pub bad_member: Option<u8>,
    pub traders: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            enclaves: 1,
            extra_executors: 0,
            quorum: 1,
            post_deadline_ms: 20_000,
            reveal_backstop_slots: 1_000_000,
            settle_backstop_after_ms: 60_000,
            rotate_committee: false,
            bad_member: None,
            traders: 2,
        }
    }
}

pub struct World {
    pub opts: Options,
    pub svm: Arc<LiteSvmRpc>,
    pub chain: Arc<SolanaMarketChain>,
    pub sender: Arc<TxSender>,
    pub market: Address,
    pub market_id: u64,
    pub params: MarketParams,
    pub admin: Arc<dyn TxSigner>,
    pub relay: Arc<dyn TxSigner>,
    pub cranker: Arc<dyn TxSigner>,
    pub committee: CommitteeDescription,
    pub member_keys: Vec<Keypair>,
    pub members: Vec<Member>,
    pub enclaves: Vec<TestEnclave>,
    pub extra: Vec<Keypair>,
    pub node: Arc<Keypair>,
    pub traders: Vec<TestTrader>,
    pub dir: tempfile::TempDir,
}

/// What `World::epoch` built.
pub struct Epoch {
    pub epoch: u64,
    pub req: ExecuteRequest,
    pub header: BatchHeader,
    pub commit_slot: u64,
}

impl Epoch {
    pub fn header_digest(&self) -> Hash32 {
        self.header.digest()
    }

    /// The request with the node's balance sheet edited and the header
    /// committing to the edited sheet, as a node that lies consistently
    /// would send it.
    pub fn with_sheet(&self, edit: impl FnOnce(&mut BalanceSheet)) -> ExecuteRequest {
        let mut req = self.req.clone();
        edit(&mut req.batch.balances);
        req.batch.header.balances_root = req.batch.balances.root();
        req
    }

    pub fn publish(&self, market: Address, cosigs: Vec<(ExecutorId, Signature)>) -> PublishRequest {
        PublishRequest {
            market,
            epoch: EpochId(self.epoch),
            header_digest: self.header_digest(),
            cosigs,
        }
    }
}

/// How `World::epoch` builds the request.
pub struct EpochSpec {
    pub orders: Vec<OrderSpec>,
    pub covers: usize,
    pub reveal: bool,
    /// Feed the enclave a committee and bundle of members the market does
    /// not know, with a header bound to them.
    pub forged_committee: bool,
    /// Provenance entries replaced by a grant that fails the domain rule.
    pub foreign_domain: Vec<usize>,
}

impl Default for EpochSpec {
    fn default() -> Self {
        Self {
            orders: crossing_orders(),
            covers: 1,
            reveal: true,
            forged_committee: false,
            foreign_domain: Vec::new(),
        }
    }
}

fn grant(wallet_seed: &[u8; 32], session: &Keypair, market: Address, domain: &str) -> GrantRecord {
    let wallet = Keypair::from_seed(*wallet_seed);
    let now = now_ms();
    let g = SessionGrant {
        domain: domain.to_owned(),
        wallet: wallet.public(),
        statement: SESSION_STATEMENT.to_owned(),
        uri: format!("http://{domain}"),
        chain_id: ChainId::Localnet,
        nonce: [7; 16],
        issued_at_ms: now - now % 1000,
        expires_at_ms: now - now % 1000 + 3_600_000,
        not_before_ms: None,
        session_key: session.public(),
        program: program(),
        market: Some(market),
    };
    let text = render_session_message(&g);
    let signature = Signature(timescales_enclave::testing::sign_message(
        wallet_seed,
        text.as_bytes(),
    ));
    GrantRecord {
        text,
        signature,
        method: GrantMethod::SignIn,
    }
}

/// The digest a session key signs to submit an envelope.
pub fn submission_digest(env: &SealedEnvelope, session_key: &[u8; 32]) -> Hash32 {
    Hasher::new(domain::RELAY_SUBMISSION)
        .chain(&env.to_bytes())
        .chain(session_key)
        .finalize()
}

/// A dealt epoch key under `committee`, with acks of every member.
struct Dealt {
    bundle: EpochKeyBundle,
    shares: Vec<ScalarShare>,
}

fn deal(committee: &CommitteeDescription, identities: &[Keypair], epoch: u64) -> Dealt {
    let (_secret, commitments, shares) =
        FeldmanDealing::new(&mut OsRng, committee.threshold, MEMBERS);
    let ann = EpochKeyAnnouncement {
        version: EpochKeyAnnouncement::VERSION,
        market: committee.market,
        epoch: EpochId(epoch),
        committee_digest: committee.digest(),
        scheme: KeyScheme::FeldmanEd25519,
        epoch_pk: edwards_u(&commitments[0]).unwrap(),
        commitments,
    };
    let acks = identities
        .iter()
        .enumerate()
        .map(|(i, id)| {
            EpochKeyAck::sign(
                u8::try_from(i + 1).unwrap(),
                &ann.digest(),
                Hash32([0x9d; 32]),
                id,
            )
        })
        .collect();
    Dealt {
        bundle: EpochKeyBundle {
            announcement: ann,
            acks,
        },
        shares,
    }
}

fn committee_of(market: Address, identities: &[Keypair], label: &[u8]) -> CommitteeDescription {
    CommitteeDescription {
        version: CommitteeDescription::VERSION,
        market,
        threshold: THRESHOLD,
        members: identities
            .iter()
            .enumerate()
            .map(|(i, id)| CommitteeMember {
                index: u8::try_from(i + 1).unwrap(),
                identity: id.public(),
                transport: SealSecret::from_bytes(hash(label, &[u8::try_from(i).unwrap()]).0)
                    .public(),
            })
            .collect(),
    }
}

/// A placed order's sealed envelope.
fn seal_order(
    params: &MarketParams,
    epoch: u64,
    epoch_pk: &[u8; 32],
    trader: &TestTrader,
    o: &OrderSpec,
    nonce: u64,
) -> SealedEnvelope {
    let order = Order {
        market: params.market,
        trader: trader.id(),
        nonce,
        side: o.side,
        role: o.role,
        kind: OrderKind::Limit,
        limit: Tick(o.limit),
        quantity: Lots(o.qty),
        valid_from: EpochId(epoch),
        expires_at: EpochId(epoch),
    };
    // The salt type is not nameable here: obtain it by decoding.
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let mut bytes = IntentBody::Place(order).to_bytes();
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&[0; 64]);
    let unsigned = PrivateIntent::decode_exact(&bytes).unwrap();
    let c = commit_body(params.commitment_scheme, &unsigned.body, &unsigned.salt).unwrap();
    let intent = PrivateIntent {
        signature: trader.wallet.sign_message(&signed_message(&c)),
        ..unsigned
    };
    SealedEnvelope::seal(
        &mut OsRng,
        params.market,
        EpochId(epoch),
        epoch_pk,
        c,
        &intent,
    )
    .unwrap()
}

fn cover(params: &MarketParams, epoch: u64, epoch_pk: &[u8; 32]) -> SealedEnvelope {
    let (intent, c) = PrivateIntent::noop(&mut OsRng, params.commitment_scheme).unwrap();
    SealedEnvelope::seal(
        &mut OsRng,
        params.market,
        EpochId(epoch),
        epoch_pk,
        c,
        &intent,
    )
    .unwrap()
}

impl World {
    pub async fn new(opts: Options) -> World {
        timescales_service::tls::install_default_provider();
        let dir = tempfile::tempdir().unwrap();
        let program = program();
        let so = timescales_chain::settlement_program_so();
        assert!(
            so.is_file(),
            "settlement program not found at {}; run scripts/build-program.sh",
            so.display()
        );
        let mut svm = fresh(LiteSvmRpc::new)
            .with_mainnet_features()
            .with_builtins()
            .with_sysvars()
            .with_feature_accounts()
            .with_default_programs()
            .with_precompiles()
            .with_sigverify(true);
        svm.add_program_from_file(program, &so).unwrap();
        svm.warp_to_slot(1_000);
        let svm = Arc::new(LiteSvmRpc::new(
            svm,
            LiteSvmConfig {
                confirmed_lag: 1,
                finalized_lag: FINALIZED_LAG,
                slot_time: Some(SLOT),
                blockhash_validity: 300,
                ..LiteSvmConfig::default()
            },
        ));
        let genesis = svm.config().genesis_hash;

        let mut seq = 0u64;
        let mut funded = |svm: &LiteSvmRpc| {
            seq += 1;
            let kp = key(b"test/enclave/wallet", seq);
            put_account(svm, kp.public(), [0; 32], 100_000_000_000, vec![]);
            kp
        };
        let creator = funded(&svm);
        let admin = funded(&svm);
        let relay = funded(&svm);
        let cranker = funded(&svm);
        let payers: Vec<Keypair> = (0..opts.enclaves).map(|_| funded(&svm)).collect();

        let salt = [0x5a; 32];
        let market_id =
            timescales_chain::program::derive_market_id(&program, &creator.public(), &salt);
        let market = timescales_chain::program::market_pda(&program, market_id)
            .unwrap()
            .0;
        let params = params(market_id);
        let base_mint = hash(b"test/base-mint", &[]).0;
        let quote_mint = hash(b"test/quote-mint", &[]).0;
        let base_vault = hash(b"test/base-vault", &[]).0;
        let quote_vault = hash(b"test/quote-vault", &[]).0;
        for (k, d) in [
            (base_mint, mint_data()),
            (quote_mint, mint_data()),
            (base_vault, token_account_data(&base_mint, &market)),
            (quote_vault, token_account_data(&quote_mint, &market)),
        ] {
            put_account(&svm, k, TOKEN_PROGRAM, 1_000_000_000, d);
        }

        // The harness reads and writes through its own provider.
        let harness: Arc<dyn SolanaRpc> =
            Arc::new(QuorumRpc::new(vec![Arc::clone(&svm) as Arc<dyn SolanaRpc>], 1).unwrap());
        let fees = FeePolicy {
            mode: FeeMode::Fixed(1_000),
            percentile: 75,
            max_micro_lamports: 200_000,
            cu_margin_pct: 20,
        };
        let chain_cfg = MarketChainConfig {
            max_attempts: 12,
            retry_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(1),
            poll_interval: SLOT,
            max_parallel_txs: 4,
        };
        let sender = Arc::new(TxSender::new(
            Arc::clone(&harness),
            fees,
            Arc::new(TxLog::new()),
            SLOT,
            Duration::from_secs(30),
        ));
        let chain = Arc::new(SolanaMarketChain::new(
            harness,
            Arc::clone(&sender),
            program,
            market,
            chain_cfg,
        ));

        // Committee and members.
        let member_keys: Vec<Keypair> = (1..=u64::from(MEMBERS))
            .map(|i| key(b"test/enclave/member", i))
            .collect();
        let committee = committee_of(market, &member_keys, b"test/enclave/transport");
        let committee_file = dir.path().join("committee.bin");
        std::fs::write(&committee_file, committee.to_bytes()).unwrap();
        let vendor =
            timescales_executor::attestation::simulated::SimulatedVendor::from_seed(VENDOR_SEED, 0);
        let mut members = Vec::new();
        for (i, id) in member_keys.iter().enumerate() {
            let index = u8::try_from(i + 1).unwrap();
            let verifier = Arc::new(SimulatedQuoteVerifier::from_root(vendor.root_key(), 0));
            let policy = AttestationPolicy::strict([Platform::Simulated], [program_measurement()]);
            let core = KeyReleaseMember::new(index, verifier, policy).unwrap();
            let identity = Keypair::from_seed(*id.seed());
            let auth = EnvelopeAuth {
                me: identity.public(),
                allowed: Arc::new(|_: &[u8; 32], kind: MessageKind| {
                    matches!(
                        kind,
                        MessageKind::ChallengeRequest | MessageKind::ReleaseRequest
                    )
                }),
                replay: Arc::new(ReplayGuard::new(10_000, 60_000)),
                skew_ms: 30_000,
                now_ms: Arc::new(now_ms),
            };
            let state = Arc::new(MemberState {
                index,
                identity,
                core,
                chain: Arc::clone(&chain),
                market_id,
                auth,
                challenges: AtomicU64::new(0),
                releases: AtomicU64::new(0),
            });
            let app = Router::new()
                .route("/krc/v1/challenge", post(member_challenge))
                .route("/krc/v1/release", post(member_release))
                .with_state(MemberApp(Arc::clone(&state)));
            let addr = serve(app).await;
            members.push(Member {
                url: format!("http://{addr}"),
                state,
            });
        }

        // Enclaves, booted before the market so it can register them.
        let vendor_seed = dir.path().join("vendor.hex");
        write_private(&vendor_seed, hex::encode(VENDOR_SEED).as_bytes());
        let node = Arc::new(key(b"test/enclave/node", 0));
        let mut enclaves = Vec::new();
        for (i, payer_kp) in payers.iter().enumerate() {
            let key_file = dir.path().join(format!("enclave-{i}.keys"));
            keygen_simulated(&vendor_seed, &key_file).unwrap();
            let cfg = EnclaveConfig {
                profile: Profile::Local,
                listen: "127.0.0.1:0".into(),
                ops_listen: "127.0.0.1:0".into(),
                platform: PlatformKind::Simulated,
                simulated_key_file: Some(key_file),
                simulated_vendor_seed: Some(vendor_seed.clone()),
                tdx_configfs_root: None,
                fee_payer_keypair: PathBuf::from("unused-fee-payer.json"),
                node_keys: vec![hex::encode(node.public())],
                member_urls: members.iter().map(|m| m.url.clone()).collect(),
                member_timeout_ms: 10_000,
                post_deadline_ms: opts.post_deadline_ms,
                settle_backstop_after_ms: opts.settle_backstop_after_ms,
                reveal_backstop_slots: opts.reveal_backstop_slots,
                allow_sign_message_grants: false,
                max_concurrent_executions: 2,
                max_body_bytes: 16 * 1024 * 1024,
                result_cache_entries: 32,
                markets: vec![EnclaveMarket {
                    address: bs58::encode(market).into_string(),
                    committee_file: committee_file.clone(),
                    session_domains: vec![DOMAIN.into()],
                }],
                tls: None,
                chain: EnclaveChain {
                    cluster: "localnet".into(),
                    genesis_hash: bs58::encode(genesis).into_string(),
                    program_id: PROGRAM.into(),
                    rpc_urls: vec!["http://127.0.0.1:1".into(), "http://127.0.0.1:2".into()],
                    rpc_agree: 2,
                    rpc_timeout_ms: 5_000,
                    poll_interval_ms: 50,
                    priority_fee: PriorityFee {
                        mode: "fixed".into(),
                        fixed_micro_lamports: "1000".into(),
                        percentile: 75,
                        max_micro_lamports: "200000".into(),
                    },
                },
                telemetry: TelemetryConfig {
                    log_format: LogFormat::Pretty,
                    log_filter: "info".into(),
                    otlp_endpoint: String::new(),
                    service_name: None,
                },
            };
            let providers = [
                Arc::new(FaultyRpc::new(Arc::clone(&svm))),
                Arc::new(FaultyRpc::new(Arc::clone(&svm))),
            ];
            let rpc: Arc<dyn SolanaRpc> = Arc::new(
                QuorumRpc::new(
                    providers
                        .iter()
                        .map(|p| Arc::clone(p) as Arc<dyn SolanaRpc>)
                        .collect(),
                    2,
                )
                .unwrap(),
            );
            let log = Arc::new(TxLog::new());
            let enclave_sender = Arc::new(TxSender::new(
                Arc::clone(&rpc),
                fees,
                Arc::clone(&log) as Arc<dyn timescales_chain::TxJournal>,
                SLOT,
                Duration::from_secs(30),
            ));
            let enclave_chain: Arc<dyn MarketChain> = Arc::new(SolanaMarketChain::new(
                rpc,
                enclave_sender,
                program,
                market,
                chain_cfg,
            ));
            let fee_payer = signer(payer_kp);
            let svc = Arc::new(
                EnclaveService::boot(
                    cfg,
                    BTreeMap::from([(market, enclave_chain)]),
                    Arc::clone(&fee_payer),
                )
                .unwrap()
                .with_tx_log(Arc::clone(&log)),
            );
            let limits = HttpLimits {
                max_body_bytes: 16 * 1024 * 1024 + 4096,
                request_timeout: Duration::from_secs(10),
                max_concurrency: 64,
                per_caller_rps: 5,
                per_caller_burst: 5,
            };
            let addr = serve(router(Arc::clone(&svc), limits)).await;
            let client = SignedClient::new(
                Arc::clone(&node) as Arc<dyn timescales_service::wire::EnvelopeSigner>,
                svc.executor().0,
                None,
                Duration::from_secs(120),
            )
            .unwrap();
            enclaves.push(TestEnclave {
                svc,
                url: format!("http://{addr}"),
                client,
                providers,
                log,
                fee_payer,
            });
        }
        let extra: Vec<Keypair> = (0..opts.extra_executors)
            .map(|i| key(b"test/enclave/extra-executor", u64::try_from(i).unwrap()))
            .collect();

        let admin = signer(&admin);
        let relay = signer(&relay);
        let cranker = signer(&cranker);
        let creator = signer(&creator);
        let mut executors: Vec<Address> = enclaves.iter().map(|e| e.executor().0).collect();
        executors.extend(extra.iter().map(Keypair::public));
        let args = InitMarketArgs {
            salt,
            admin: admin.address(),
            relay: relay.address(),
            params,
            committee_digest: committee.digest(),
            beacon_delay_slots: BEACON_DELAY,
            timelock_slots: 20,
            exec_timeout_slots: 100_000,
            settle_timeout_slots: 200_000,
            receipt_quorum: opts.quorum,
            executors,
        };
        let init = timescales_chain::program::init_market(
            &program,
            &creator.address(),
            &base_mint,
            &quote_mint,
            &base_vault,
            &quote_vault,
            &args,
        )
        .unwrap();
        sender
            .send(TxOp::Admin, vec![init], creator, vec![])
            .await
            .unwrap();

        // Traders with deposited balances, written in the program's layout.
        let traders: Vec<TestTrader> = (0..opts.traders)
            .map(|i| {
                let wallet_seed = hash(b"test/enclave/trader", &[u8::try_from(i).unwrap()]).0;
                let session = key(b"test/enclave/session", u64::try_from(i).unwrap());
                let grant = grant(&wallet_seed, &session, market, DOMAIN);
                TestTrader {
                    wallet_seed,
                    wallet: Keypair::from_seed(wallet_seed),
                    session,
                    grant,
                }
            })
            .collect();
        for t in &traders {
            let (pda, bump) =
                timescales_chain::program::trader_pda(&program, &market, &t.wallet.public())
                    .unwrap();
            put_account(
                &svm,
                pda,
                program,
                10_000_000,
                trader_data(
                    &market,
                    &t.wallet.public(),
                    bump,
                    1_000_000_000,
                    1_000_000_000_000,
                ),
            );
        }

        let mut world = World {
            opts,
            svm,
            chain,
            sender,
            market,
            market_id,
            params,
            admin,
            relay,
            cranker,
            committee,
            member_keys,
            members,
            enclaves,
            extra,
            node,
            traders,
            dir,
        };
        world.wait_slots(FINALIZED_LAG + 1).await;
        world.check_market().await;
        world
    }

    async fn check_market(&mut self) {
        if self.opts.rotate_committee {
            self.rotate_committee().await;
        }
        let m = self.market_account().await;
        if self.opts.rotate_committee {
            assert_eq!(m.prev_committee_digest, self.committee.digest());
            assert_ne!(m.committee_digest, self.committee.digest());
        } else {
            assert_eq!(m.committee_digest, self.committee.digest());
        }
        assert_eq!(m.receipt_quorum, self.opts.quorum);
    }

    /// A graceful rotation to another committee: proposed by the admin,
    /// applied after the timelock.
    async fn rotate_committee(&self) {
        let change = timescales_chain::program::GovernanceChange::SetCommitteeDigest(hash(
            b"test/enclave/next-committee",
            &[],
        ));
        let ix = timescales_chain::program::propose_change(
            &program(),
            &self.admin.address(),
            &self.market,
            &change,
        )
        .unwrap();
        self.sender
            .send(TxOp::Admin, vec![ix], Arc::clone(&self.admin), vec![])
            .await
            .unwrap();
        loop {
            match self
                .chain
                .ensure_change_applied(Arc::clone(&self.cranker))
                .await
                .unwrap()
            {
                timescales_chain::ChangeOutcome::NotYet { slots_left } => {
                    self.wait_slots(slots_left).await;
                }
                timescales_chain::ChangeOutcome::Applied { .. } => break,
                other => panic!("apply change: {other:?}"),
            }
        }
        self.wait_slots(FINALIZED_LAG + 1).await;
    }

    pub async fn market_account(&self) -> MarketAccount {
        self.chain.market(Level::Confirmed).await.unwrap()
    }

    pub async fn batch(&self, epoch: u64) -> Option<BatchAccount> {
        self.chain.batch(epoch, Level::Confirmed).await.unwrap()
    }

    pub async fn wait_slots(&self, slots: u64) {
        let target = self.svm.current_slot() + slots;
        while self.svm.current_slot() < target {
            tokio::time::sleep(SLOT).await;
        }
    }

    /// Reveals the beacon of `epoch` through the harness, waiting out
    /// `NotReady`, then waits until finalized reads show it.
    pub async fn reveal(&self, epoch: u64) {
        loop {
            match self
                .chain
                .ensure_revealed(epoch, Arc::clone(&self.cranker))
                .await
                .unwrap()
            {
                RevealOutcome::NotReady { slots_left } => self.wait_slots(slots_left).await,
                RevealOutcome::Revealed { .. } => break,
                other => panic!("reveal: {other:?}"),
            }
        }
        self.wait_finalized(epoch, BatchStatus::BeaconRevealed)
            .await;
    }

    pub async fn wait_finalized(&self, epoch: u64, status: BatchStatus) {
        self.chain
            .wait_batch(
                epoch,
                BatchPredicate::AtLeast(status),
                Level::Finalized,
                tokio::time::Instant::now() + Duration::from_secs(30),
            )
            .await
            .unwrap();
    }

    /// Deals a key for `epoch`, seals the orders, commits the batch as the
    /// relay, reveals the beacon (unless `spec.reveal` is false) and builds
    /// the node's `ExecuteRequest`.
    pub async fn epoch(&self, epoch: u64, spec: EpochSpec) -> Epoch {
        let dealt = deal(&self.committee, &self.member_keys, epoch);
        let ann = &dealt.bundle.announcement;
        let announcement = HeldAnnouncement {
            digest: ann.digest(),
            committee_digest: self.committee.digest(),
        };
        for (m, share) in self.members.iter().zip(dealt.shares.iter()) {
            let share = if Some(m.state.index) == self.opts.bad_member {
                // Inconsistent with the commitments.
                ScalarShare::from_bytes(m.state.index, &[1; 32]).unwrap()
            } else {
                share.clone()
            };
            m.state
                .core
                .store_dealt_share(
                    MarketId(self.market_id),
                    EpochId(epoch),
                    share,
                    announcement,
                )
                .unwrap();
        }

        // Envelopes and who submitted them.
        let mut envelopes = Vec::new();
        let mut entries = Vec::new();
        let grants: Vec<GrantRecord> = self.traders.iter().map(|t| t.grant.clone()).collect();
        let mut grants_out = grants.clone();
        for (n, o) in spec.orders.iter().enumerate() {
            let trader = &self.traders[o.trader];
            let env = seal_order(
                &self.params,
                epoch,
                &ann.epoch_pk,
                trader,
                o,
                u64::try_from(n).unwrap() + 1,
            );
            let via = o.via.unwrap_or(o.trader);
            let mut grant_index = u32::try_from(via).unwrap();
            if spec.foreign_domain.contains(&n) {
                let other = grant(
                    &trader.wallet_seed,
                    &trader.session,
                    self.market,
                    "phish.example",
                );
                grants_out.push(other);
                grant_index = u32::try_from(grants_out.len() - 1).unwrap();
            }
            let session = &self.traders[via].session;
            entries.push(ProvenanceEntry {
                grant: grant_index,
                session_signature: session.sign_digest(&submission_digest(&env, &session.public())),
            });
            envelopes.push(env);
        }
        for _ in 0..spec.covers {
            envelopes.push(cover(&self.params, epoch, &ann.epoch_pk));
            entries.push(ProvenanceEntry {
                grant: ProvenanceEntry::NO_GRANT,
                session_signature: Signature([0; 64]),
            });
        }

        // The relay commits root, count and terms.
        let price_commitment = hash(b"test/enclave/price-commitment", &epoch.to_le_bytes());
        let band = self.params.band(REFERENCE).unwrap();
        let binding = epoch_binding(&price_commitment, &ann.digest(), &self.committee.digest());
        let leaves = batch_leaves(&envelopes);
        let m = self.market_account().await;
        let draft = BatchHeader::assemble_v2(
            self.params,
            EpochId(epoch),
            band,
            binding,
            &leaves,
            Hash32::ZERO,
            m.state_root,
            Hash32::ZERO,
            m.prev_receipt,
        );
        let committed = self
            .chain
            .ensure_committed(
                epoch,
                draft.batch_root,
                draft.envelope_count,
                terms_digest(&band, &binding),
                Arc::clone(&self.relay),
            )
            .await
            .unwrap();
        let CommitOutcome::Committed { slot: commit_slot } = committed else {
            panic!("commit: {committed:?}");
        };
        let snapshot = self.chain.trader_snapshot(commit_slot).await.unwrap();
        let sheet = snapshot.balance_sheet(epoch);
        let beacon = if spec.reveal {
            self.reveal(epoch).await;
            self.batch(epoch).await.unwrap().beacon
        } else {
            Hash32::ZERO
        };

        let (committee, bundle, binding) = if spec.forged_committee {
            let fake: Vec<Keypair> = (1..=u64::from(MEMBERS))
                .map(|i| key(b"test/enclave/fake-member", i))
                .collect();
            let committee = committee_of(self.market, &fake, b"test/enclave/fake-transport");
            let forged = deal(&committee, &fake, epoch);
            let binding = epoch_binding(
                &price_commitment,
                &forged.bundle.announcement.digest(),
                &committee.digest(),
            );
            (committee, forged.bundle, binding)
        } else {
            (self.committee.clone(), dealt.bundle.clone(), binding)
        };
        let header = BatchHeader::assemble_v2(
            self.params,
            EpochId(epoch),
            band,
            binding,
            &leaves,
            beacon,
            m.state_root,
            sheet.root(),
            m.prev_receipt,
        );
        let req = ExecuteRequest {
            version: ExecuteRequest::VERSION,
            market: self.market,
            commit_slot,
            batch: ExecutionBatch {
                header,
                envelopes,
                masked: Vec::new(),
                balances: sheet,
                prior_state: Default::default(),
            },
            bundle,
            committee,
            price_commitment,
            provenance: Provenance {
                grants: grants_out,
                entries,
            },
        };
        Epoch {
            epoch,
            req,
            header,
            commit_slot,
        }
    }

    /// Signs a co-signature with a registered extra executor key.
    pub fn extra_cosign(
        &self,
        i: usize,
        epoch: u64,
        header: &Hash32,
        outcome: &Hash32,
    ) -> (ExecutorId, Signature) {
        let k = &self.extra[i];
        let digest = timescales_auction::receipts::cosign_digest(
            &self.market,
            EpochId(epoch),
            header,
            outcome,
        );
        (ExecutorId(k.public()), k.sign_digest(&digest))
    }

    pub fn challenges(&self) -> u64 {
        self.members.iter().map(Member::challenges).sum()
    }

    pub fn releases(&self) -> u64 {
        self.members.iter().map(Member::releases).sum()
    }

    /// Removes a registered executor at once (admin).
    pub async fn remove_executor(&self, key: &Address) {
        let ix = timescales_chain::program::remove_executor(
            &program(),
            &self.admin.address(),
            &self.market,
            key,
        );
        self.sender
            .send(TxOp::Admin, vec![ix], Arc::clone(&self.admin), vec![])
            .await
            .unwrap();
        self.wait_slots(2).await;
    }
}

/// `GET path` over plain HTTP/1.1. The status and the body.
pub async fn http_get(base: &str, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = base.trim_start_matches("http://");
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, body.to_owned())
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(bytes).unwrap();
}
