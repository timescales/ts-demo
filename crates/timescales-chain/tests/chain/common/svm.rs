//! A market on the real settlement program, run by `LiteSvmRpc` behind a
//! `FaultyRpc`, with the adapter under test on top. Test setup (market,
//! traders, governance) goes through the same `TxSender`. Headers,
//! receipts and co-signatures are built the way an enclave builds them.

use std::sync::Arc;
use std::time::Duration;

use litesvm::LiteSVM;
use parking_lot::Mutex;
use solana_account::Account;
use solana_address::Address as SolAddress;
use solana_keypair::Keypair;
use timescales_auction::receipts::{
    BackendKind, ExecutionOutcome, ExecutionReceipt, cosign_digest,
};
use timescales_auction::settlement::{AccountDelta, SettlementBatch};
use timescales_chain::program::{
    BatchAccount, GovernanceChange, InitMarketArgs, Ix, MarketAccount, Side, TOKEN_PROGRAM,
};
use timescales_chain::{
    Address, BoxFuture, FaultyRpc, FeeMode, FeePolicy, FileSigner, JournalError, Landed, Level,
    LiteSvmConfig, LiteSvmRpc, MarketChainConfig, RevealOutcome, RpcMethod, SolanaMarketChain,
    TxJournal, TxOp, TxOutcome, TxRecord, TxSender, TxSigner,
};
use timescales_core::crypto::{Keypair as ExecutorKey, domain, hash, hash_parts};
use timescales_core::{
    CommitmentScheme, Encode, EpochId, ExecutorId, FeeBps, FlowMode, Hash32, MarketId,
    MarketParams, PROTOCOL_VERSION, QuoteAtoms, Rationing, TraderId,
};
use zeroize::Zeroizing;

/// The dev program id. LiteSVM runs the program under it.
pub const PROGRAM: &str = "FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL";
pub const START_SLOT: u64 = 1_000;
/// Header bytes 63..119: the reference band and the epoch binding. The
/// program only hashes them into the terms digest.
pub const BAND: [u8; 24] = [7; 24];
pub const BINDING: [u8; 32] = [0xb1; 32];
pub const SLOT_TIME: Duration = Duration::from_millis(400);

pub fn program() -> Address {
    timescales_chain::program::decode_base58(PROGRAM).unwrap()
}

/// `H(EPOCH_TERMS, band || binding)`, the terms digest every commit uses.
pub fn terms() -> Hash32 {
    hash_parts(domain::EPOCH_TERMS, &[&BAND, &BINDING])
}

pub fn root(epoch: u64) -> Hash32 {
    hash(b"test/batch-root", &epoch.to_le_bytes())
}

pub fn next_state_root(epoch: u64) -> Hash32 {
    hash(b"test/state-root", &epoch.to_le_bytes())
}

/// One journalled transaction.
#[derive(Clone, Debug)]
pub struct Row {
    pub record: TxRecord,
    pub outcome: Option<TxOutcome>,
    /// `sendTransaction` calls the provider had seen when the row was
    /// written.
    pub sends_before: u64,
}

/// An in-memory `TxJournal` that also notes how many sends reached the
/// provider before each row was written.
pub struct Journal {
    rows: Mutex<Vec<Row>>,
    faulty: Arc<FaultyRpc<LiteSvmRpc>>,
    refuse: Mutex<bool>,
}

impl Journal {
    pub fn new(faulty: Arc<FaultyRpc<LiteSvmRpc>>) -> Self {
        Self {
            rows: Mutex::new(Vec::new()),
            faulty,
            refuse: Mutex::new(false),
        }
    }

    pub fn rows(&self) -> Vec<Row> {
        self.rows.lock().clone()
    }

    /// Rows of `op` written after the first `skip` rows.
    pub fn ops_since(&self, skip: usize, op: TxOp) -> Vec<Row> {
        self.rows()
            .into_iter()
            .skip(skip)
            .filter(|r| r.record.op == op)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.rows.lock().len()
    }

    /// The next `before_send` fails, as a store that cannot write would.
    pub fn refuse_next(&self) {
        *self.refuse.lock() = true;
    }
}

impl TxJournal for Journal {
    fn before_send(&self, rec: TxRecord) -> BoxFuture<'_, Result<i64, JournalError>> {
        Box::pin(async move {
            if std::mem::take(&mut *self.refuse.lock()) {
                return Err(JournalError("disk full".into()));
            }
            let sends_before = self.faulty.calls(RpcMethod::SendTransaction);
            let mut rows = self.rows.lock();
            let id = i64::try_from(rows.len()).unwrap() + 1;
            rows.push(Row {
                record: TxRecord {
                    id: Some(id),
                    ..rec
                },
                outcome: None,
                sends_before,
            });
            Ok(id)
        })
    }

    fn resolved(&self, id: i64, outcome: TxOutcome) -> BoxFuture<'_, Result<(), JournalError>> {
        Box::pin(async move {
            let mut rows = self.rows.lock();
            let row = rows
                .iter_mut()
                .find(|r| r.record.id == Some(id))
                .ok_or_else(|| JournalError(format!("no row {id}")))?;
            row.outcome = Some(outcome);
            Ok(())
        })
    }

    fn pending(&self) -> BoxFuture<'_, Result<Vec<TxRecord>, JournalError>> {
        Box::pin(async move {
            Ok(self
                .rows
                .lock()
                .iter()
                .filter(|r| r.outcome.is_none())
                .map(|r| r.record.clone())
                .collect())
        })
    }

    fn last_landed_slot(&self) -> BoxFuture<'_, Result<u64, JournalError>> {
        Box::pin(async move {
            Ok(self
                .rows
                .lock()
                .iter()
                .filter_map(|r| match r.outcome {
                    Some(TxOutcome::Landed { slot } | TxOutcome::Failed { slot, .. }) => Some(slot),
                    _ => None,
                })
                .max()
                .unwrap_or(0))
        })
    }
}

/// Market configuration (bounds, `localnet` build).
#[derive(Clone, Debug)]
pub struct Setup {
    pub executors: usize,
    pub quorum: u8,
    pub beacon_delay: u16,
    pub exec_timeout: u64,
    pub settle_timeout: u64,
    pub timelock: u64,
    pub cluster: LiteSvmConfig,
    pub chain: MarketChainConfig,
    pub fees: FeePolicy,
    pub confirm_timeout: Duration,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            executors: 3,
            quorum: 2,
            beacon_delay: 4,
            exec_timeout: 150,
            settle_timeout: 1_500,
            timelock: 20,
            cluster: LiteSvmConfig {
                confirmed_lag: 1,
                finalized_lag: 32,
                slot_time: Some(SLOT_TIME),
                blockhash_validity: 40,
                ..LiteSvmConfig::default()
            },
            chain: MarketChainConfig {
                max_attempts: 12,
                ..MarketChainConfig::default()
            },
            fees: FeePolicy {
                mode: FeeMode::Fixed(1_000),
                percentile: 75,
                max_micro_lamports: 200_000,
                cu_margin_pct: 20,
            },
            confirm_timeout: Duration::from_secs(30),
        }
    }
}

pub fn signer(kp: &Keypair) -> Arc<dyn TxSigner> {
    Arc::new(FileSigner::from_bytes(Zeroizing::new(kp.to_bytes())).unwrap())
}

fn key(seed: u64) -> Keypair {
    Keypair::new_from_array(hash(b"test/keypair", &seed.to_le_bytes()).0)
}

/// A wallet with an open, funded Trader account.
#[derive(Clone)]
pub struct Trader {
    pub signer: Arc<dyn TxSigner>,
    pub base_ata: Address,
    pub quote_ata: Address,
}

impl Trader {
    pub fn id(&self) -> Address {
        self.signer.address()
    }
}

pub struct Net {
    pub setup: Setup,
    pub svm: Arc<LiteSvmRpc>,
    pub faulty: Arc<FaultyRpc<LiteSvmRpc>>,
    pub journal: Arc<Journal>,
    pub sender: Arc<TxSender>,
    pub chain: SolanaMarketChain,
    pub program: Address,
    pub market: Address,
    pub market_id: u64,
    pub params: MarketParams,
    pub creator: Arc<dyn TxSigner>,
    pub admin: Arc<dyn TxSigner>,
    pub relay: Arc<dyn TxSigner>,
    pub cranker: Arc<dyn TxSigner>,
    pub executors: Vec<ExecutorKey>,
    /// One fee payer per executor's enclave.
    pub posters: Vec<Arc<dyn TxSigner>>,
    pub base_mint: Address,
    pub quote_mint: Address,
    pub base_vault: Address,
    pub quote_vault: Address,
    seq: Mutex<u64>,
}

fn mint_account() -> Account {
    let mut d = vec![0u8; timescales_chain::program::spl::MINT_LEN];
    d[44] = 6;
    d[45] = 1;
    Account {
        lamports: 1_000_000_000,
        data: d,
        owner: SolAddress::from(TOKEN_PROGRAM),
        executable: false,
        rent_epoch: 0,
    }
}

fn token_account(mint: &Address, owner: &Address, amount: u64) -> Account {
    let mut d = vec![0u8; timescales_chain::program::spl::TOKEN_ACCOUNT_LEN];
    d[..32].copy_from_slice(mint);
    d[32..64].copy_from_slice(owner);
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    Account {
        lamports: 1_000_000_000,
        data: d,
        owner: SolAddress::from(TOKEN_PROGRAM),
        executable: false,
        rent_epoch: 0,
    }
}

fn wallet_account(lamports: u64) -> Account {
    Account {
        lamports,
        data: vec![],
        owner: SolAddress::default(),
        executable: false,
        rent_epoch: 0,
    }
}

impl Net {
    /// A market initialised with `setup`, behind a fault-free `FaultyRpc`.
    pub async fn new(setup: Setup) -> Self {
        let so = timescales_chain::settlement_program_so();
        assert!(
            so.is_file(),
            "settlement program not found at {}; run scripts/build-program.sh",
            so.display()
        );
        let program = program();
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(SolAddress::from(program), &so)
            .unwrap();
        svm.warp_to_slot(START_SLOT);

        let mut seq = 0;
        let mut funded = |svm: &mut LiteSVM| {
            seq += 1;
            let kp = key(seq);
            svm.set_account(
                SolAddress::from(signer(&kp).address()),
                wallet_account(100_000_000_000),
            )
            .unwrap();
            signer(&kp)
        };
        let creator = funded(&mut svm);
        let admin = funded(&mut svm);
        let relay = funded(&mut svm);
        let cranker = funded(&mut svm);
        let posters: Vec<_> = (0..setup.executors).map(|_| funded(&mut svm)).collect();
        let executors: Vec<ExecutorKey> = (0..setup.executors)
            .map(|i| ExecutorKey::from_seed([0x40 + u8::try_from(i).unwrap(); 32]))
            .collect();

        let salt = [0x5a; 32];
        let market_id =
            timescales_chain::program::derive_market_id(&program, &creator.address(), &salt);
        let market = timescales_chain::program::market_pda(&program, market_id)
            .unwrap()
            .0;
        let base_mint = hash(b"test/base-mint", &[]).0;
        let quote_mint = hash(b"test/quote-mint", &[]).0;
        let base_vault = hash(b"test/base-vault", &[]).0;
        let quote_vault = hash(b"test/quote-vault", &[]).0;
        for (k, a) in [
            (base_mint, mint_account()),
            (quote_mint, mint_account()),
            (base_vault, token_account(&base_mint, &market, 0)),
            (quote_vault, token_account(&quote_mint, &market, 0)),
        ] {
            svm.set_account(SolAddress::from(k), a).unwrap();
        }

        let svm = Arc::new(LiteSvmRpc::new(svm, setup.cluster.clone()));
        let faulty = Arc::new(FaultyRpc::new(svm.clone()));
        let journal = Arc::new(Journal::new(faulty.clone()));
        let sender = Arc::new(TxSender::new(
            faulty.clone(),
            setup.fees,
            journal.clone(),
            SLOT_TIME,
            setup.confirm_timeout,
        ));
        let chain =
            SolanaMarketChain::new(faulty.clone(), sender.clone(), program, market, setup.chain);
        let params = MarketParams {
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
        };
        let net = Net {
            setup: setup.clone(),
            svm,
            faulty,
            journal,
            sender,
            chain,
            program,
            market,
            market_id,
            params,
            creator,
            admin,
            relay,
            cranker,
            executors,
            posters,
            base_mint,
            quote_mint,
            base_vault,
            quote_vault,
            seq: Mutex::new(seq),
        };
        let args = InitMarketArgs {
            salt,
            admin: net.admin.address(),
            relay: net.relay.address(),
            params,
            committee_digest: Hash32([0xc0; 32]),
            beacon_delay_slots: setup.beacon_delay,
            timelock_slots: setup.timelock,
            exec_timeout_slots: setup.exec_timeout,
            settle_timeout_slots: setup.settle_timeout,
            receipt_quorum: setup.quorum,
            executors: net.executors.iter().map(|k| k.public()).collect(),
        };
        let init = timescales_chain::program::init_market(
            &program,
            &net.creator.address(),
            &base_mint,
            &quote_mint,
            &base_vault,
            &quote_vault,
            &args,
        )
        .unwrap();
        net.send(vec![init], &net.creator.clone()).await;
        net
    }

    /// Sends setup instructions through the sender under test.
    pub async fn send(&self, ixs: Vec<Ix>, payer: &Arc<dyn TxSigner>) -> Landed {
        self.sender
            .send(TxOp::Admin, ixs, payer.clone(), vec![])
            .await
            .unwrap()
    }

    /// A funded wallet, once the Confirmed view has it.
    pub async fn wallet(&self) -> Arc<dyn TxSigner> {
        let s = self.unconfirmed_wallet();
        self.wait_slots(self.setup.cluster.confirmed_lag).await;
        s
    }

    fn unconfirmed_wallet(&self) -> Arc<dyn TxSigner> {
        let s = {
            let mut seq = self.seq.lock();
            *seq += 1;
            signer(&key(*seq))
        };
        self.set_account(&s.address(), wallet_account(10_000_000_000));
        s
    }

    /// A wallet holding `base` and `quote` tokens, with a Trader account
    /// and everything deposited.
    pub async fn trader(&self, base: u64, quote: u64) -> Trader {
        let s = self.unconfirmed_wallet();
        let owner = s.address();
        let base_ata = hash(b"test/base-ata", &owner).0;
        let quote_ata = hash(b"test/quote-ata", &owner).0;
        self.svm.with_svm(|svm| {
            svm.set_account(
                SolAddress::from(base_ata),
                token_account(&self.base_mint, &owner, base),
            )
            .unwrap();
            svm.set_account(
                SolAddress::from(quote_ata),
                token_account(&self.quote_mint, &owner, quote),
            )
            .unwrap();
        });
        self.wait_slots(self.setup.cluster.confirmed_lag).await;
        let mut ixs = vec![
            timescales_chain::program::open_trader(&self.program, &owner, &self.market).unwrap(),
        ];
        for (side, amount, source, vault) in [
            (Side::Base, base, base_ata, self.base_vault),
            (Side::Quote, quote, quote_ata, self.quote_vault),
        ] {
            if amount > 0 {
                ixs.push(
                    timescales_chain::program::deposit(
                        &self.program,
                        &owner,
                        &self.market,
                        &source,
                        &vault,
                        side,
                        amount,
                    )
                    .unwrap(),
                );
            }
        }
        self.send(ixs, &s).await;
        Trader {
            signer: s,
            base_ata,
            quote_ata,
        }
    }

    pub async fn market_account(&self) -> MarketAccount {
        use timescales_chain::MarketChain;
        self.chain.market(Level::Confirmed).await.unwrap()
    }

    pub async fn batch_account(&self, epoch: u64) -> BatchAccount {
        use timescales_chain::MarketChain;
        self.chain
            .batch(epoch, Level::Confirmed)
            .await
            .unwrap()
            .expect("batch account")
    }

    /// The live (processed) account, read past every emulated lag.
    pub fn account(&self, key: &Address) -> Option<Account> {
        self.svm
            .with_svm(|svm| svm.get_account(&SolAddress::from(*key)))
    }

    pub fn set_account(&self, key: &Address, account: Account) {
        self.svm
            .with_svm(|svm| svm.set_account(SolAddress::from(*key), account).unwrap());
    }

    pub fn batch_key(&self, epoch: u64) -> Address {
        timescales_chain::program::batch_pda(&self.program, &self.market, epoch)
            .unwrap()
            .0
    }

    /// Waits (tokio time) until `slot` is the processed slot.
    pub async fn until_slot(&self, slot: u64) {
        while self.svm.current_slot() < slot {
            tokio::time::sleep(SLOT_TIME).await;
        }
    }

    /// Waits `slots` slots of tokio time.
    pub async fn wait_slots(&self, slots: u64) {
        let target = self.svm.current_slot() + slots;
        self.until_slot(target).await;
    }

    /// `ensure_revealed` until the beacon is in, waiting out `NotReady`.
    pub async fn reveal(&self, epoch: u64) -> RevealOutcome {
        use timescales_chain::MarketChain;
        loop {
            match self
                .chain
                .ensure_revealed(epoch, self.cranker.clone())
                .await
                .unwrap()
            {
                RevealOutcome::NotReady { slots_left } => self.wait_slots(slots_left).await,
                other => return other,
            }
        }
    }

    /// The settlement of `epoch` with `deltas` (sorted by trader as
    /// `settle` produces them) and `fees`.
    pub fn settlement(
        &self,
        epoch: u64,
        deltas: &[(Address, i64, i64)],
        fees: u64,
    ) -> SettlementBatch {
        let mut deltas: Vec<AccountDelta> = deltas
            .iter()
            .map(|(t, base, quote)| AccountDelta {
                trader: TraderId(*t),
                base: *base,
                quote: *quote,
            })
            .collect();
        deltas.sort_by_key(|d| d.trader);
        SettlementBatch {
            market: MarketId(self.market_id),
            epoch: EpochId(epoch),
            deltas,
            fees: QuoteAtoms(fees),
        }
    }

    /// The v2 header (PostReceipt) of a revealed batch.
    pub fn header(&self, b: &BatchAccount, m: &MarketAccount) -> [u8; 283] {
        let mut h = vec![2u8];
        h.extend_from_slice(&self.market_id.to_le_bytes());
        h.extend_from_slice(&b.epoch.to_le_bytes());
        h.extend_from_slice(&self.params.to_bytes());
        h.extend_from_slice(&BAND);
        h.extend_from_slice(&BINDING);
        h.extend_from_slice(&b.count.to_le_bytes());
        h.extend_from_slice(b.root.as_bytes());
        h.extend_from_slice(b.beacon.as_bytes());
        h.extend_from_slice(m.state_root.as_bytes());
        h.extend_from_slice(&[0xba; 32]);
        h.extend_from_slice(m.prev_receipt.as_bytes());
        h.try_into().unwrap()
    }

    /// Executor `executor`'s signed receipt over `header` and `s`.
    pub fn receipt(
        &self,
        executor: &ExecutorKey,
        header: &[u8; 283],
        s: &SettlementBatch,
    ) -> Vec<u8> {
        let outcome = ExecutionOutcome {
            market: MarketId(self.market_id),
            epoch: s.epoch,
            header_digest: hash(domain::BATCH_HEADER, header),
            clearing: vec![],
            fill_count: 0,
            fills_root: Hash32([0xf1; 32]),
            cancelled_root: Hash32([0xca; 32]),
            next_state_root: next_state_root(s.epoch.0),
            settlement_count: u32::try_from(s.deltas.len()).unwrap(),
            settlement_root: s.root(),
            fees: s.fees,
        };
        let id = ExecutorId(executor.public());
        let (attestation, proof, trace) = (Hash32([0xa7; 32]), Hash32::ZERO, Hash32([0x7e; 32]));
        let digest = ExecutionReceipt::signing_digest(
            &outcome,
            BackendKind::Tee,
            &id,
            &attestation,
            &proof,
            &trace,
        );
        ExecutionReceipt {
            version: PROTOCOL_VERSION,
            outcome,
            backend: BackendKind::Tee,
            executor: id,
            attestation,
            proof,
            trace,
            signature: executor.sign_digest(&digest),
        }
        .to_bytes()
    }

    /// Header and receipt of executor `i` for the revealed `epoch`.
    pub async fn post_args(
        &self,
        epoch: u64,
        i: usize,
        s: &SettlementBatch,
    ) -> ([u8; 283], Vec<u8>) {
        let b = self.batch_account(epoch).await;
        let m = self.market_account().await;
        let header = self.header(&b, &m);
        let receipt = self.receipt(&self.executors[i], &header, s);
        (header, receipt)
    }

    /// Executor `i`'s co-signature of the posted receipt of `epoch`.
    pub async fn cosignature(&self, epoch: u64, i: usize) -> (Address, [u8; 64]) {
        let b = self.batch_account(epoch).await;
        let digest = cosign_digest(
            &self.market,
            EpochId(epoch),
            &b.header_digest,
            &b.outcome_digest,
        );
        let key = &self.executors[i];
        (key.public(), key.sign_digest(&digest).0)
    }

    /// Proposes `change` as the admin.
    pub async fn propose(&self, change: &GovernanceChange) {
        let ix = timescales_chain::program::propose_change(
            &self.program,
            &self.admin.address(),
            &self.market,
            change,
        )
        .unwrap();
        self.send(vec![ix], &self.admin.clone()).await;
    }

    pub async fn set_halted(&self, halted: bool) {
        let ix = timescales_chain::program::set_halted(
            &self.program,
            &self.admin.address(),
            &self.market,
            halted,
        );
        self.send(vec![ix], &self.admin.clone()).await;
    }

    /// `sendTransaction` calls so far.
    pub fn sends(&self) -> u64 {
        self.faulty.calls(RpcMethod::SendTransaction)
    }
}
