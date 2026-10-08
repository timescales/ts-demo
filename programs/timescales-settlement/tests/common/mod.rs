//! Shared LiteSVM harness for the v2 program suites.
//!
//! Instruction data, headers and receipts are built here by hand from the
//! layouts (not with the chain crate), and signed
//! with `ed25519-dalek`. Hashes use the core crate's domain tags, so a
//! tag or layout drift between the program and the off-chain crates fails
//! these tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::{InstructionError, Transaction, TransactionError};
use timescales_core::crypto::{domain, hash_parts};
use timescales_core::merkle::MerkleTree;

pub use timescales_settlement_program::error::TimescalesError as E;

pub const START_SLOT: u64 = 1_000;
pub const BAND: [u8; 24] = {
    let mut b = [0u8; 24];
    b[0] = 90;
    b[8] = 110;
    b[16] = 100;
    b
};
pub const BINDING: [u8; 32] = [0xb1; 32];
pub const BACKEND_TEE: u8 = 1;

pub fn h(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    hash_parts(tag, parts).0
}

pub fn terms() -> [u8; 32] {
    h(domain::EPOCH_TERMS, &[&BAND, &BINDING])
}

/// The program artifact: `TIMESCALES_PROGRAM_SO` resolved against the
/// repository root, by default the `scripts/build-program.sh` output. A
/// missing file fails the test.
pub fn program_so() -> PathBuf {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rel = std::env::var("TIMESCALES_PROGRAM_SO")
        .unwrap_or_else(|_| "target/sbf/timescales_settlement_program.so".to_owned());
    let path = repo.join(rel);
    assert!(
        path.is_file(),
        "settlement program not found at {}; run scripts/build-program.sh",
        path.display()
    );
    path
}

pub fn addr(b: [u8; 32]) -> Address {
    Address::from(b)
}

pub fn program_id() -> Address {
    addr(timescales_settlement_program::ID.to_bytes())
}

pub fn token_program() -> Address {
    addr(timescales_settlement_program::cpi::TOKEN_PROGRAM.to_bytes())
}

pub fn system_program() -> Address {
    Address::default()
}

pub fn slot_hashes_id() -> Address {
    addr(solana_program::sysvar::slot_hashes::ID.to_bytes())
}

pub fn instructions_id() -> Address {
    addr(solana_program::sysvar::instructions::ID.to_bytes())
}

pub fn ed25519_program() -> Address {
    addr(solana_program::ed25519_program::ID.to_bytes())
}

pub fn pda(seeds: &[&[u8]]) -> Address {
    let (k, _) = solana_program::pubkey::Pubkey::find_program_address(
        seeds,
        &timescales_settlement_program::ID,
    );
    addr(k.to_bytes())
}

pub fn market_pda(id: u64) -> Address {
    pda(&[b"market", &id.to_le_bytes()])
}

pub fn derive_market_id(creator: &Address, salt: &[u8; 32]) -> u64 {
    let d = h(
        domain::MARKET_ID,
        &[program_id().as_ref(), creator.as_ref(), salt],
    );
    u64::from_le_bytes(d[..8].try_into().expect("8 bytes"))
}

pub fn w(a: Address, signer: bool) -> AccountMeta {
    AccountMeta::new(a, signer)
}

pub fn ro(a: Address, signer: bool) -> AccountMeta {
    AccountMeta::new_readonly(a, signer)
}

pub fn ix(data: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts,
        data,
    }
}

/// The Ed25519 precompile instruction with everything inline.
pub fn ed25519_ix(public: &[u8; 32], message: &[u8; 32], sig: &[u8; 64]) -> Instruction {
    const PK: u16 = 16;
    const SIG: u16 = PK + 32;
    const MSG: u16 = SIG + 64;
    let mut d = vec![1u8, 0];
    for v in [SIG, u16::MAX, PK, u16::MAX, MSG, 32, u16::MAX] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(public);
    d.extend_from_slice(sig);
    d.extend_from_slice(message);
    Instruction {
        program_id: ed25519_program(),
        accounts: vec![],
        data: d,
    }
}

pub fn sign(key: &SigningKey, msg: &[u8; 32]) -> [u8; 64] {
    key.sign(msg).to_bytes()
}

pub fn executor_key(i: usize) -> SigningKey {
    SigningKey::from_bytes(&[0x40 + i as u8; 32])
}

pub fn executor_id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// Exact serialized size of a legacy transaction.
pub fn legacy_tx_size(ixs: &[Instruction], payer: &Address, signers: usize) -> usize {
    fn shortvec(n: usize) -> usize {
        match n {
            0..=0x7f => 1,
            0x80..=0x3fff => 2,
            _ => 3,
        }
    }
    let msg = Message::new(ixs, Some(payer));
    let keys = msg.account_keys.len();
    let body: usize = msg
        .instructions
        .iter()
        .map(|i| {
            1 + shortvec(i.accounts.len())
                + i.accounts.len()
                + shortvec(i.data.len())
                + i.data.len()
        })
        .sum();
    assert_eq!(usize::from(msg.header.num_required_signatures), signers);
    shortvec(signers)
        + 64 * signers
        + 3
        + shortvec(keys)
        + 32 * keys
        + 32
        + shortvec(msg.instructions.len())
        + body
}

/// A failed transaction: the custom error code of the failing instruction,
/// if it was one.
#[derive(Debug)]
pub struct Failure {
    pub index: Option<u8>,
    pub code: Option<u32>,
    pub err: String,
    pub logs: Vec<String>,
}

pub type TxResult = Result<u64, Failure>;

#[track_caller]
pub fn fails(r: TxResult, e: E) {
    match r {
        Ok(_) => panic!("expected {e:?}, transaction succeeded"),
        Err(f) => assert_eq!(
            f.code,
            Some(e.code()),
            "expected {e:?} ({}), got {} {:?}",
            e.code(),
            f.err,
            f.code.and_then(E::from_code)
        ),
    }
}

#[track_caller]
pub fn ok(r: TxResult) -> u64 {
    match r {
        Ok(cu) => cu,
        Err(f) => panic!(
            "transaction failed: {} {:?}\n{}",
            f.err,
            f.code.and_then(E::from_code),
            f.logs.join("\n")
        ),
    }
}

pub fn mint_account() -> Account {
    let mut d = vec![0u8; 82];
    d[44] = 6;
    d[45] = 1;
    Account {
        lamports: 1_000_000_000,
        data: d,
        owner: token_program(),
        executable: false,
        rent_epoch: 0,
    }
}

pub fn token_account(mint: &Address, owner: &Address, amount: u64) -> Account {
    let mut d = vec![0u8; 165];
    d[..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    Account {
        lamports: 1_000_000_000,
        data: d,
        owner: token_program(),
        executable: false,
        rent_epoch: 0,
    }
}

pub fn u64_at(d: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(d[off..off + 8].try_into().expect("8 bytes"))
}

pub fn u32_at(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(d[off..off + 4].try_into().expect("4 bytes"))
}

pub fn key_at(d: &[u8], off: usize) -> [u8; 32] {
    d[off..off + 32].try_into().expect("32 bytes")
}

/// Market fields the suites read (offsets).
#[derive(Clone, Debug)]
pub struct MarketView {
    pub halted: bool,
    pub admin: [u8; 32],
    pub pending_admin: [u8; 32],
    pub relay: [u8; 32],
    pub committee_digest: [u8; 32],
    pub executor_count: u8,
    pub receipt_quorum: u8,
    pub executors: Vec<[u8; 32]>,
    pub beacon_delay: u16,
    pub timelock: u64,
    pub exec_timeout: u64,
    pub settle_timeout: u64,
    pub last_committed: u64,
    pub last_settled: u64,
    pub last_progress_slot: u64,
    pub fees_accrued: u64,
    pub fees_claimed: u64,
    pub prev_receipt: [u8; 32],
    pub state_root: [u8; 32],
    pub pending_kind: u8,
    pub pending_eta: u64,
    pub salt: [u8; 32],
    pub prev_committee_digest: [u8; 32],
}

impl MarketView {
    pub fn decode(d: &[u8]) -> Self {
        assert_eq!(d.len(), 1103);
        assert_eq!((d[0], d[2]), (0x21, 2));
        MarketView {
            halted: d[3] & 1 == 1,
            admin: key_at(d, 44),
            pending_admin: key_at(d, 76),
            relay: key_at(d, 108),
            committee_digest: key_at(d, 346),
            executor_count: d[378],
            receipt_quorum: d[379],
            executors: (0..8).map(|i| key_at(d, 380 + 32 * i)).collect(),
            beacon_delay: u16::from_le_bytes([d[636], d[637]]),
            timelock: u64_at(d, 638),
            exec_timeout: u64_at(d, 646),
            settle_timeout: u64_at(d, 654),
            last_committed: u64_at(d, 662),
            last_settled: u64_at(d, 670),
            last_progress_slot: u64_at(d, 678),
            fees_accrued: u64_at(d, 686),
            fees_claimed: u64_at(d, 694),
            prev_receipt: key_at(d, 702),
            state_root: key_at(d, 734),
            pending_kind: d[766],
            pending_eta: u64_at(d, 767),
            salt: key_at(d, 1039),
            prev_committee_digest: key_at(d, 1071),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraderView {
    pub base: u64,
    pub quote: u64,
    pub requested_base: u64,
    pub requested_quote: u64,
    pub request_epoch: u64,
    pub last_leaf_epoch: u64,
    pub last_change_slot: u64,
    pub floor_epoch: u64,
    pub floor_base: u64,
    pub floor_quote: u64,
}

impl TraderView {
    pub fn decode(d: &[u8]) -> Self {
        assert_eq!(d.len(), 148);
        assert_eq!((d[0], d[2]), (0x22, 2));
        TraderView {
            base: u64_at(d, 68),
            quote: u64_at(d, 76),
            requested_base: u64_at(d, 84),
            requested_quote: u64_at(d, 92),
            request_epoch: u64_at(d, 100),
            last_leaf_epoch: u64_at(d, 108),
            last_change_slot: u64_at(d, 116),
            floor_epoch: u64_at(d, 124),
            floor_base: u64_at(d, 132),
            floor_quote: u64_at(d, 140),
        }
    }

    ///  `available(t, e)`.
    pub fn available(&self, epoch: u64) -> (u64, u64) {
        if epoch > self.request_epoch {
            (
                self.base - self.requested_base.min(self.base),
                self.quote - self.requested_quote.min(self.quote),
            )
        } else {
            (self.base, self.quote)
        }
    }
}

#[derive(Clone, Debug)]
pub struct BatchView {
    pub status: u8,
    pub abort_reason: u8,
    pub cosign_count: u8,
    pub cosign_bitmap: u8,
    pub epoch: u64,
    pub root: [u8; 32],
    pub count: u32,
    pub commit_slot: u64,
    pub beacon_slot_a: u64,
    pub beacon_slot_b: u64,
    pub beacon: [u8; 32],
    pub reveal_slot: u64,
    pub receipt_slot: u64,
    pub header_digest: [u8; 32],
    pub receipt: [u8; 32],
    pub outcome_digest: [u8; 32],
    pub next_state_root: [u8; 32],
    pub settlement_count: u32,
    pub fees: u64,
    pub verified_count: u32,
    pub applied_count: u32,
}

pub const COMMITTED: u8 = 1;
pub const REVEALED: u8 = 2;
pub const POSTED: u8 = 3;
pub const VERIFIED: u8 = 4;
pub const SETTLED: u8 = 5;
pub const ABORTED: u8 = 6;

impl BatchView {
    pub fn decode(d: &[u8]) -> Self {
        assert_eq!(d.len(), 688);
        assert_eq!((d[0], d[2]), (0x23, 2));
        BatchView {
            status: d[3],
            abort_reason: d[4],
            cosign_count: d[5],
            cosign_bitmap: d[6],
            epoch: u64_at(d, 40),
            root: key_at(d, 48),
            count: u32_at(d, 80),
            commit_slot: u64_at(d, 116),
            beacon_slot_a: u64_at(d, 124),
            beacon_slot_b: u64_at(d, 132),
            beacon: key_at(d, 140),
            reveal_slot: u64_at(d, 172),
            receipt_slot: u64_at(d, 180),
            header_digest: key_at(d, 188),
            receipt: key_at(d, 220),
            outcome_digest: key_at(d, 252),
            next_state_root: key_at(d, 284),
            settlement_count: u32_at(d, 348),
            fees: u64_at(d, 352),
            verified_count: u32_at(d, 360),
            applied_count: u32_at(d, 364),
        }
    }
}

/// A batch's settlement deltas (`trader || base i64 || quote i64`) and fees.
#[derive(Clone, Debug, Default)]
pub struct Settlement {
    pub leaves: Vec<[u8; 48]>,
    pub fees: u64,
}

impl Settlement {
    pub fn new(deltas: &[(Address, i64, i64)], fees: u64) -> Self {
        let leaves = deltas
            .iter()
            .map(|(owner, base, quote)| {
                let mut b = [0u8; 48];
                b[..32].copy_from_slice(owner.as_ref());
                b[32..40].copy_from_slice(&base.to_le_bytes());
                b[40..].copy_from_slice(&quote.to_le_bytes());
                b
            })
            .collect();
        Settlement { leaves, fees }
    }

    pub fn tree(&self) -> MerkleTree {
        MerkleTree::from_data(&self.leaves)
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree().root().0
    }

    pub fn owner(&self, i: usize) -> Address {
        addr(key_at(&self.leaves[i], 0))
    }

    /// `index u32 || trader32 || base i64 || quote i64 || p u8 || path32xp`.
    pub fn encode_leaf(&self, i: usize) -> Vec<u8> {
        let proof = self.tree().proof(i).expect("leaf in range");
        let mut d = (i as u32).to_le_bytes().to_vec();
        d.extend_from_slice(&self.leaves[i]);
        d.push(proof.path.len() as u8);
        for p in &proof.path {
            d.extend_from_slice(p.as_bytes());
        }
        d
    }
}

/// A receipt being prepared for `PostReceipt`: header bytes and the
/// receipt without its signature. Tests mutate either before posting.
#[derive(Clone, Debug)]
pub struct Post {
    pub header: Vec<u8>,
    /// Receipt bytes without the trailing 64-byte signature.
    pub body: Vec<u8>,
    pub signer: usize,
}

impl Post {
    pub fn header_digest(&self) -> [u8; 32] {
        h(domain::BATCH_HEADER, &[&self.header])
    }

    /// Re-binds the receipt to the (possibly mutated) header.
    pub fn rebind(&mut self) {
        let d = self.header_digest();
        self.body[17..49].copy_from_slice(&d);
    }

    pub fn digest(&self) -> [u8; 32] {
        h(domain::RECEIPT, &[&self.body])
    }

    pub fn outcome_digest(&self) -> [u8; 32] {
        let end = self.body.len() - 129;
        h(domain::OUTCOME, &[&self.body[1..end]])
    }

    /// Offset of field `at` (in the k = 0 layout) for this receipt.
    pub fn off(&self, at: usize) -> usize {
        at + (self.body.len() - 326)
    }
}

pub struct TraderAcc {
    pub kp: Keypair,
    pub pda: Address,
    pub base_ata: Address,
    pub quote_ata: Address,
}

impl TraderAcc {
    pub fn owner(&self) -> Address {
        self.kp.pubkey()
    }
}

#[derive(Clone, Debug)]
pub struct Cfg {
    pub beacon_delay: u16,
    pub timelock: u64,
    pub exec_timeout: u64,
    pub settle_timeout: u64,
    pub quorum: u8,
    pub executors: usize,
    pub max_envelopes: u32,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            beacon_delay: 4,
            timelock: 20,
            exec_timeout: 150,
            settle_timeout: 1_500,
            quorum: 1,
            executors: 1,
            max_envelopes: 1024,
        }
    }
}

/// Every `InitMarket` argument, so tests can corrupt any of them.
#[derive(Clone, Debug)]
pub struct InitArgs {
    pub market_id: u64,
    pub salt: [u8; 32],
    pub admin: [u8; 32],
    pub relay: [u8; 32],
    pub params: [u8; 46],
    pub committee_digest: [u8; 32],
    pub beacon_delay: u16,
    pub timelock: u64,
    pub exec_timeout: u64,
    pub settle_timeout: u64,
    pub quorum: u8,
    pub executors: Vec<[u8; 32]>,
}

impl InitArgs {
    pub fn data(&self) -> Vec<u8> {
        let mut d = vec![0u8];
        d.extend_from_slice(&self.market_id.to_le_bytes());
        d.extend_from_slice(&self.salt);
        d.extend_from_slice(&self.admin);
        d.extend_from_slice(&self.relay);
        d.extend_from_slice(&self.params);
        d.extend_from_slice(&self.committee_digest);
        d.extend_from_slice(&self.beacon_delay.to_le_bytes());
        d.extend_from_slice(&self.timelock.to_le_bytes());
        d.extend_from_slice(&self.exec_timeout.to_le_bytes());
        d.extend_from_slice(&self.settle_timeout.to_le_bytes());
        d.push(self.quorum);
        d.push(self.executors.len() as u8);
        for e in &self.executors {
            d.extend_from_slice(e);
        }
        d
    }
}

/// `MarketParams` bytes, encoded by the core crate.
pub fn params_bytes(market_id: u64, max_envelopes: u32) -> [u8; 46] {
    use timescales_core::*;
    let p = MarketParams {
        market: MarketId(market_id),
        base_lot_size: 1,
        tick_size: 1,
        band_half_width: 16,
        max_order_lots_log2: 40,
        max_orders_per_trader: 8,
        max_batch_envelopes: max_envelopes,
        max_order_lifetime: 16,
        maker_fee: FeeBps(0),
        taker_fee: FeeBps(10),
        flow: FlowMode::DualFlow,
        rationing: Rationing::ProRata,
        commitment_scheme: CommitmentScheme::Sha256,
    };
    p.to_bytes().try_into().expect("46-byte params")
}

pub struct Env {
    pub svm: LiteSVM,
    pub creator: Keypair,
    pub admin: Keypair,
    pub relay: Keypair,
    pub cranker: Keypair,
    pub salt: [u8; 32],
    pub market_id: u64,
    pub market: Address,
    pub base_mint: Address,
    pub quote_mint: Address,
    pub base_vault: Address,
    pub quote_vault: Address,
    pub executors: Vec<SigningKey>,
    pub committee: [u8; 32],
    pub cfg: Cfg,
    pub params: [u8; 46],
    /// Keys handed out so far (see `funded`).
    pub seq: u64,
}

/// Keys are derived from a per-chain counter, so every run (and every
/// recorded compute-unit figure, which depends on PDA bump searches) is
/// reproducible.
fn funded(svm: &mut LiteSVM, seq: &mut u64) -> Keypair {
    *seq += 1;
    let kp = Keypair::new_from_array(h(b"test/keypair", &[&seq.to_le_bytes()]));
    svm.airdrop(&kp.pubkey(), 100_000_000_000).expect("airdrop");
    kp
}

impl Env {
    pub fn new(cfg: Cfg) -> Self {
        let mut env = Self::bare(cfg);
        let args = env.init_args();
        let creator = env.creator.insecure_clone();
        ok(env.init_market(&args, &creator));
        env
    }

    /// Everything but `InitMarket`: program, keys, mints and vaults owned by
    /// the derived market PDA.
    pub fn bare(cfg: Cfg) -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(program_id(), program_so())
            .expect("load program");
        svm.warp_to_slot(START_SLOT);
        let mut seq = 0;
        let creator = funded(&mut svm, &mut seq);
        let admin = funded(&mut svm, &mut seq);
        let relay = funded(&mut svm, &mut seq);
        let cranker = funded(&mut svm, &mut seq);
        let salt = [0x5a; 32];
        let market_id = derive_market_id(&creator.pubkey(), &salt);
        let market = market_pda(market_id);
        let (base_mint, quote_mint) = (Address::new_unique(), Address::new_unique());
        let (base_vault, quote_vault) = (Address::new_unique(), Address::new_unique());
        svm.set_account(base_mint, mint_account()).expect("mint");
        svm.set_account(quote_mint, mint_account()).expect("mint");
        svm.set_account(base_vault, token_account(&base_mint, &market, 0))
            .expect("vault");
        svm.set_account(quote_vault, token_account(&quote_mint, &market, 0))
            .expect("vault");
        let executors = (0..cfg.executors).map(executor_key).collect();
        let params = params_bytes(market_id, cfg.max_envelopes);
        Env {
            svm,
            creator,
            admin,
            relay,
            cranker,
            salt,
            market_id,
            market,
            base_mint,
            quote_mint,
            base_vault,
            quote_vault,
            executors,
            committee: [0xc0; 32],
            cfg,
            params,
            seq,
        }
    }

    /// An independent copy of the whole chain state and keys.
    pub fn fork(&self) -> Env {
        Env {
            svm: self.svm.clone(),
            creator: self.creator.insecure_clone(),
            admin: self.admin.insecure_clone(),
            relay: self.relay.insecure_clone(),
            cranker: self.cranker.insecure_clone(),
            salt: self.salt,
            market_id: self.market_id,
            market: self.market,
            base_mint: self.base_mint,
            quote_mint: self.quote_mint,
            base_vault: self.base_vault,
            quote_vault: self.quote_vault,
            executors: self.executors.clone(),
            committee: self.committee,
            cfg: self.cfg.clone(),
            params: self.params,
            seq: self.seq,
        }
    }

    pub fn init_args(&self) -> InitArgs {
        InitArgs {
            market_id: self.market_id,
            salt: self.salt,
            admin: self.admin.pubkey().to_bytes(),
            relay: self.relay.pubkey().to_bytes(),
            params: self.params,
            committee_digest: self.committee,
            beacon_delay: self.cfg.beacon_delay,
            timelock: self.cfg.timelock,
            exec_timeout: self.cfg.exec_timeout,
            settle_timeout: self.cfg.settle_timeout,
            quorum: self.cfg.quorum,
            executors: self.executors.iter().map(executor_id).collect(),
        }
    }

    pub fn init_market_ix(&self, args: &InitArgs, creator: &Address) -> Instruction {
        self.init_market_ix_with(args, creator, self.base_vault, self.quote_vault)
    }

    pub fn init_market_ix_with(
        &self,
        args: &InitArgs,
        creator: &Address,
        base_vault: Address,
        quote_vault: Address,
    ) -> Instruction {
        ix(
            args.data(),
            vec![
                w(*creator, true),
                w(market_pda(args.market_id), false),
                ro(self.base_mint, false),
                ro(self.quote_mint, false),
                ro(base_vault, false),
                ro(quote_vault, false),
                ro(system_program(), false),
            ],
        )
    }

    pub fn init_market(&mut self, args: &InitArgs, creator: &Keypair) -> TxResult {
        let ixn = self.init_market_ix(args, &creator.pubkey());
        self.send(&[ixn], &[creator])
    }

    pub fn send(&mut self, ixs: &[Instruction], signers: &[&Keypair]) -> TxResult {
        let payer = signers[0].pubkey();
        let msg = Message::new(ixs, Some(&payer));
        let tx = Transaction::new(signers, msg, self.svm.latest_blockhash());
        let r = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        match r {
            Ok(m) => Ok(m.compute_units_consumed),
            Err(f) => {
                let (index, code) = match &f.err {
                    TransactionError::InstructionError(i, InstructionError::Custom(c)) => {
                        (Some(*i), Some(*c))
                    }
                    TransactionError::InstructionError(i, _) => (Some(*i), None),
                    _ => (None, None),
                };
                Err(Failure {
                    index,
                    code,
                    err: format!("{:?}", f.err),
                    logs: f.meta.logs,
                })
            }
        }
    }

    /// Sends with the cranker as fee payer and signer.
    pub fn crank(&mut self, ixs: &[Instruction]) -> TxResult {
        let c = self.cranker.insecure_clone();
        self.send(ixs, &[&c])
    }

    pub fn slot(&self) -> u64 {
        let clock = addr(solana_program::sysvar::clock::ID.to_bytes());
        u64_at(&self.account(&clock).expect("clock").data, 0)
    }

    pub fn warp(&mut self, slot: u64) {
        self.svm.warp_to_slot(slot);
    }

    pub fn advance(&mut self, slots: u64) {
        let s = self.slot() + slots;
        self.warp(s);
    }

    pub fn funded(&mut self) -> Keypair {
        funded(&mut self.svm, &mut self.seq)
    }

    pub fn account(&self, a: &Address) -> Option<Account> {
        self.svm.get_account(a)
    }

    pub fn market_view(&self) -> MarketView {
        MarketView::decode(&self.account(&self.market).expect("market").data)
    }

    pub fn trader_pda(&self, owner: &Address) -> Address {
        pda(&[b"trader", self.market.as_ref(), owner.as_ref()])
    }

    pub fn trader_view(&self, owner: &Address) -> TraderView {
        TraderView::decode(&self.account(&self.trader_pda(owner)).expect("trader").data)
    }

    pub fn batch_pda(&self, epoch: u64) -> Address {
        pda(&[b"batch", self.market.as_ref(), &epoch.to_le_bytes()])
    }

    pub fn batch_view(&self, epoch: u64) -> BatchView {
        BatchView::decode(&self.account(&self.batch_pda(epoch)).expect("batch").data)
    }

    pub fn token_amount(&self, a: &Address) -> u64 {
        u64_at(&self.account(a).expect("token account").data, 64)
    }

    /// Overwrites part of a program account's data (to reach states that
    /// honest flows cannot, for defence-in-depth checks).
    pub fn poke(&mut self, a: &Address, off: usize, bytes: &[u8]) {
        let mut acc = self.account(a).expect("account");
        acc.data[off..off + bytes.len()].copy_from_slice(bytes);
        self.svm.set_account(*a, acc).expect("set account");
    }

    // ----- instruction builders -----

    pub fn open_trader_ix(&self, owner: &Address) -> Instruction {
        ix(
            vec![1],
            vec![
                w(*owner, true),
                ro(self.market, false),
                w(self.trader_pda(owner), false),
                ro(system_program(), false),
            ],
        )
    }

    pub fn deposit_ix(&self, t: &TraderAcc, quote: bool, amount: u64) -> Instruction {
        let mut d = vec![2, u8::from(quote)];
        d.extend_from_slice(&amount.to_le_bytes());
        let (src, vault) = if quote {
            (t.quote_ata, self.quote_vault)
        } else {
            (t.base_ata, self.base_vault)
        };
        ix(
            d,
            vec![
                ro(t.owner(), true),
                ro(self.market, false),
                w(t.pda, false),
                w(src, false),
                w(vault, false),
                ro(token_program(), false),
            ],
        )
    }

    pub fn request_withdraw_ix(&self, t: &TraderAcc, base: u64, quote: u64) -> Instruction {
        let mut d = vec![3];
        d.extend_from_slice(&base.to_le_bytes());
        d.extend_from_slice(&quote.to_le_bytes());
        ix(
            d,
            vec![ro(t.owner(), true), ro(self.market, false), w(t.pda, false)],
        )
    }

    pub fn cancel_request_ix(&self, t: &TraderAcc) -> Instruction {
        ix(
            vec![14],
            vec![ro(t.owner(), true), ro(self.market, false), w(t.pda, false)],
        )
    }

    pub fn withdraw_ix(&self, t: &TraderAcc, quote: bool) -> Instruction {
        let (dest, vault) = if quote {
            (t.quote_ata, self.quote_vault)
        } else {
            (t.base_ata, self.base_vault)
        };
        ix(
            vec![4, u8::from(quote)],
            vec![
                ro(t.owner(), true),
                ro(self.market, false),
                w(t.pda, false),
                w(vault, false),
                w(dest, false),
                ro(token_program(), false),
            ],
        )
    }

    pub fn close_trader_ix(&self, t: &TraderAcc) -> Instruction {
        ix(
            vec![23],
            vec![w(t.owner(), true), ro(self.market, false), w(t.pda, false)],
        )
    }

    pub fn commit_ix(
        &self,
        epoch: u64,
        root: &[u8; 32],
        count: u32,
        terms: &[u8; 32],
    ) -> Instruction {
        let mut d = vec![5];
        d.extend_from_slice(&epoch.to_le_bytes());
        d.extend_from_slice(root);
        d.extend_from_slice(&count.to_le_bytes());
        d.extend_from_slice(terms);
        ix(
            d,
            vec![
                w(self.relay.pubkey(), true),
                w(self.market, false),
                w(self.batch_pda(epoch), false),
                ro(system_program(), false),
            ],
        )
    }

    pub fn reveal_ix(&self, epoch: u64) -> Instruction {
        ix(
            vec![12],
            vec![
                ro(self.cranker.pubkey(), true),
                ro(self.market, false),
                w(self.batch_pda(epoch), false),
                ro(slot_hashes_id(), false),
            ],
        )
    }

    pub fn post_ix(&self, epoch: u64, header: &[u8], receipt: &[u8]) -> Instruction {
        let mut d = vec![6];
        d.extend_from_slice(&(header.len() as u16).to_le_bytes());
        d.extend_from_slice(header);
        d.extend_from_slice(&(receipt.len() as u16).to_le_bytes());
        d.extend_from_slice(receipt);
        ix(
            d,
            vec![
                ro(self.cranker.pubkey(), true),
                ro(self.market, false),
                w(self.batch_pda(epoch), false),
                ro(instructions_id(), false),
            ],
        )
    }

    pub fn cosign_ix(&self, epoch: u64) -> Instruction {
        ix(
            vec![13],
            vec![
                ro(self.cranker.pubkey(), true),
                ro(self.market, false),
                w(self.batch_pda(epoch), false),
                ro(instructions_id(), false),
            ],
        )
    }

    fn deltas_ix(&self, tag: u8, epoch: u64, s: &Settlement, idx: &[usize]) -> Instruction {
        let mut d = vec![tag, idx.len() as u8];
        let mut metas = vec![
            ro(self.cranker.pubkey(), true),
            ro(self.market, false),
            w(self.batch_pda(epoch), false),
        ];
        for &i in idx {
            d.extend_from_slice(&s.encode_leaf(i));
            metas.push(w(self.trader_pda(&s.owner(i)), false));
        }
        ix(d, metas)
    }

    pub fn verify_ix(&self, epoch: u64, s: &Settlement, idx: &[usize]) -> Instruction {
        self.deltas_ix(7, epoch, s, idx)
    }

    pub fn apply_ix(&self, epoch: u64, s: &Settlement, idx: &[usize]) -> Instruction {
        self.deltas_ix(9, epoch, s, idx)
    }

    fn batch_ix(&self, tag: u8, epoch: u64, market_writable: bool) -> Instruction {
        ix(
            vec![tag],
            vec![
                ro(self.cranker.pubkey(), true),
                if market_writable {
                    w(self.market, false)
                } else {
                    ro(self.market, false)
                },
                w(self.batch_pda(epoch), false),
            ],
        )
    }

    pub fn finalize_ix(&self, epoch: u64) -> Instruction {
        self.batch_ix(8, epoch, false)
    }

    pub fn close_batch_ix(&self, epoch: u64) -> Instruction {
        self.batch_ix(10, epoch, true)
    }

    pub fn abort_ix(&self, epoch: u64, signer: &Address, reason: u8) -> Instruction {
        ix(
            vec![11, reason],
            vec![
                ro(*signer, true),
                w(self.market, false),
                w(self.batch_pda(epoch), false),
            ],
        )
    }

    pub fn reclaim_ix(&self, epoch: u64, relay: &Address) -> Instruction {
        ix(
            vec![22],
            vec![
                ro(self.cranker.pubkey(), true),
                ro(self.market, false),
                w(self.batch_pda(epoch), false),
                w(*relay, false),
            ],
        )
    }

    fn admin_ix(&self, data: Vec<u8>, signer: &Address) -> Instruction {
        ix(data, vec![ro(*signer, true), w(self.market, false)])
    }

    pub fn set_halted_ix(&self, signer: &Address, halted: bool) -> Instruction {
        self.admin_ix(vec![15, u8::from(halted)], signer)
    }

    pub fn propose_ix(&self, signer: &Address, kind: u8, payload: &[u8]) -> Instruction {
        let mut d = vec![16, kind];
        d.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        d.extend_from_slice(payload);
        self.admin_ix(d, signer)
    }

    pub fn apply_change_ix(&self, signer: &Address) -> Instruction {
        self.admin_ix(vec![17], signer)
    }

    pub fn cancel_change_ix(&self, signer: &Address) -> Instruction {
        self.admin_ix(vec![18], signer)
    }

    pub fn accept_admin_ix(&self, signer: &Address) -> Instruction {
        self.admin_ix(vec![19], signer)
    }

    pub fn remove_executor_ix(&self, signer: &Address, key: &[u8; 32]) -> Instruction {
        let mut d = vec![20];
        d.extend_from_slice(key);
        self.admin_ix(d, signer)
    }

    pub fn claim_fees_ix(&self, signer: &Address, dest: &Address, amount: u64) -> Instruction {
        let mut d = vec![21];
        d.extend_from_slice(&amount.to_le_bytes());
        ix(
            d,
            vec![
                ro(*signer, true),
                w(self.market, false),
                w(self.quote_vault, false),
                w(*dest, false),
                ro(token_program(), false),
            ],
        )
    }

    // ----- flows -----

    /// A funded wallet with an open Trader account and `base`/`quote`
    /// deposited.
    pub fn trader(&mut self, base: u64, quote: u64) -> TraderAcc {
        let t = self.wallet(base, quote);
        let open = self.open_trader_ix(&t.owner());
        let kp = t.kp.insecure_clone();
        ok(self.send(&[open], &[&kp]));
        if base > 0 {
            let d = self.deposit_ix(&t, false, base);
            ok(self.send(&[d], &[&kp]));
        }
        if quote > 0 {
            let d = self.deposit_ix(&t, true, quote);
            ok(self.send(&[d], &[&kp]));
        }
        t
    }

    /// A funded wallet holding `base` and `quote` tokens, without a Trader
    /// account.
    pub fn wallet(&mut self, base: u64, quote: u64) -> TraderAcc {
        let kp = self.funded();
        let owner = kp.pubkey();
        let (base_ata, quote_ata) = (Address::new_unique(), Address::new_unique());
        self.svm
            .set_account(base_ata, token_account(&self.base_mint, &owner, base))
            .expect("ata");
        self.svm
            .set_account(quote_ata, token_account(&self.quote_mint, &owner, quote))
            .expect("ata");
        TraderAcc {
            pda: self.trader_pda(&owner),
            kp,
            base_ata,
            quote_ata,
        }
    }

    pub fn commit(&mut self, epoch: u64, root: &[u8; 32], count: u32) -> TxResult {
        let c = self.commit_ix(epoch, root, count, &terms());
        let relay = self.relay.insecure_clone();
        self.send(&[c], &[&relay])
    }

    /// Commits `s`'s epoch with a root derived from the epoch (the program
    /// never opens it) and `count = max(1, deltas)`.
    pub fn commit_for(&mut self, epoch: u64, s: &Settlement) -> TxResult {
        let root = h(b"test/batch-root", &[&epoch.to_le_bytes()]);
        self.commit(epoch, &root, s.leaves.len().max(1) as u32)
    }

    /// Writes the SlotHashes sysvar: one entry per slot in `slots`
    /// (descending), hash = H("test/slot", slot).
    pub fn set_slot_hashes(&mut self, slots: &[u64]) {
        let mut sorted = slots.to_vec();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        sorted.dedup();
        assert!(sorted.len() <= 512);
        let mut d = (sorted.len() as u64).to_le_bytes().to_vec();
        for s in &sorted {
            d.extend_from_slice(&s.to_le_bytes());
            d.extend_from_slice(&slot_hash(*s));
        }
        d.resize(8 + 512 * 40, 0);
        self.svm
            .set_account(
                slot_hashes_id(),
                Account {
                    lamports: 1_000_000_000,
                    data: d,
                    owner: addr(solana_program::sysvar::ID.to_bytes()),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .expect("slot hashes");
    }

    /// SlotHashes as a cluster would hold it at the current slot: every
    /// slot from the current one back 512 slots.
    pub fn fill_slot_hashes(&mut self) {
        let now = self.slot();
        let slots: Vec<u64> = (now.saturating_sub(511)..=now).collect();
        self.set_slot_hashes(&slots);
    }

    /// Moves past `commit_slot + 2d`, fills SlotHashes and reveals.
    pub fn reveal(&mut self, epoch: u64) -> TxResult {
        let b = self.batch_view(epoch);
        let target = b.commit_slot + 2 * u64::from(self.cfg.beacon_delay) + 1;
        if self.slot() < target {
            self.warp(target);
        }
        self.fill_slot_hashes();
        let r = self.reveal_ix(epoch);
        self.crank(&[r])
    }

    /// A correct header and receipt for the committed, revealed `epoch`.
    pub fn prepare(&self, epoch: u64, s: &Settlement) -> Post {
        let m = self.market_view();
        let b = self.batch_view(epoch);
        let mut header = vec![2u8];
        header.extend_from_slice(&self.market_id.to_le_bytes());
        header.extend_from_slice(&epoch.to_le_bytes());
        header.extend_from_slice(&self.params);
        header.extend_from_slice(&BAND);
        header.extend_from_slice(&BINDING);
        header.extend_from_slice(&b.count.to_le_bytes());
        header.extend_from_slice(&b.root);
        header.extend_from_slice(&b.beacon);
        header.extend_from_slice(&m.state_root);
        header.extend_from_slice(&[0xba; 32]);
        header.extend_from_slice(&m.prev_receipt);
        assert_eq!(header.len(), 283);

        let mut post = Post {
            header,
            body: Vec::new(),
            signer: 0,
        };
        let mut r = vec![1u8];
        r.extend_from_slice(&self.market_id.to_le_bytes());
        r.extend_from_slice(&epoch.to_le_bytes());
        r.extend_from_slice(&post.header_digest());
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&(s.leaves.len() as u32).to_le_bytes());
        r.extend_from_slice(&[0xf1; 32]);
        r.extend_from_slice(&[0xca; 32]);
        r.extend_from_slice(&next_state_root(epoch));
        r.extend_from_slice(&(s.leaves.len() as u32).to_le_bytes());
        r.extend_from_slice(&s.root());
        r.extend_from_slice(&s.fees.to_le_bytes());
        r.push(BACKEND_TEE);
        r.extend_from_slice(&executor_id(&self.executors[0]));
        r.extend_from_slice(&[0xa7; 32]);
        r.extend_from_slice(&[0; 32]);
        r.extend_from_slice(&[0x7e; 32]);
        assert_eq!(r.len(), 326);
        post.body = r;
        post
    }

    /// Re-signs as executor `i` (also writes its key into the receipt).
    pub fn set_poster(&self, post: &mut Post, i: usize) {
        post.signer = i;
        let off = post.off(198);
        let key = executor_id(&self.executors_or_extra(i));
        post.body[off..off + 32].copy_from_slice(&key);
    }

    /// Executor keys beyond the registered ones are unknown executors.
    pub fn executors_or_extra(&self, i: usize) -> SigningKey {
        self.executors
            .get(i)
            .cloned()
            .unwrap_or_else(|| executor_key(i))
    }

    /// The receipt with the poster's signature appended.
    pub fn signed_receipt(&self, post: &Post) -> Vec<u8> {
        let key = self.executors_or_extra(post.signer);
        let mut receipt = post.body.clone();
        receipt.extend_from_slice(&sign(&key, &post.digest()));
        receipt
    }

    pub fn post_ixs(&self, epoch: u64, post: &Post) -> Vec<Instruction> {
        let key = self.executors_or_extra(post.signer);
        let digest = post.digest();
        let sig = sign(&key, &digest);
        let mut receipt = post.body.clone();
        receipt.extend_from_slice(&sig);
        vec![
            ed25519_ix(&executor_id(&key), &digest, &sig),
            self.post_ix(epoch, &post.header, &receipt),
        ]
    }

    pub fn post(&mut self, epoch: u64, post: &Post) -> TxResult {
        let ixs = self.post_ixs(epoch, post);
        self.crank(&ixs)
    }

    pub fn cosign_digest(&self, epoch: u64) -> [u8; 32] {
        let b = self.batch_view(epoch);
        h(
            domain::RECEIPT_COSIGN,
            &[
                self.market.as_ref(),
                &epoch.to_le_bytes(),
                &b.header_digest,
                &b.outcome_digest,
            ],
        )
    }

    pub fn cosign_ixs(&self, epoch: u64, key: &SigningKey, digest: &[u8; 32]) -> Vec<Instruction> {
        let sig = sign(key, digest);
        vec![
            ed25519_ix(&executor_id(key), digest, &sig),
            self.cosign_ix(epoch),
        ]
    }

    pub fn cosign(&mut self, epoch: u64, i: usize) -> TxResult {
        let digest = self.cosign_digest(epoch);
        let key = self.executors_or_extra(i);
        let ixs = self.cosign_ixs(epoch, &key, &digest);
        self.crank(&ixs)
    }

    pub fn verify(&mut self, epoch: u64, s: &Settlement, idx: &[usize]) -> TxResult {
        let v = self.verify_ix(epoch, s, idx);
        self.crank(&[v])
    }

    pub fn apply(&mut self, epoch: u64, s: &Settlement, idx: &[usize]) -> TxResult {
        let a = self.apply_ix(epoch, s, idx);
        self.crank(&[a])
    }

    pub fn finalize(&mut self, epoch: u64) -> TxResult {
        let f = self.finalize_ix(epoch);
        self.crank(&[f])
    }

    pub fn close_batch(&mut self, epoch: u64) -> TxResult {
        let c = self.close_batch_ix(epoch);
        self.crank(&[c])
    }

    pub fn abort(&mut self, epoch: u64, signer: &Keypair, reason: u8) -> TxResult {
        let a = self.abort_ix(epoch, &signer.pubkey(), reason);
        let c = self.cranker.insecure_clone();
        self.send(&[a], &[&c, signer])
    }

    /// Commit, reveal, post and gather the quorum's co-signatures.
    pub fn post_with_quorum(&mut self, epoch: u64, s: &Settlement) {
        ok(self.commit_for(epoch, s));
        ok(self.reveal(epoch));
        let post = self.prepare(epoch, s);
        ok(self.post(epoch, &post));
        for i in 1..usize::from(self.cfg.quorum) {
            ok(self.cosign(epoch, i));
        }
    }

    pub fn verify_all(&mut self, epoch: u64, s: &Settlement) {
        let idx: Vec<usize> = (0..s.leaves.len()).collect();
        for chunk in idx.chunks(3) {
            ok(self.verify(epoch, s, chunk));
        }
    }

    pub fn apply_all(&mut self, epoch: u64, s: &Settlement) {
        let idx: Vec<usize> = (0..s.leaves.len()).collect();
        for chunk in idx.chunks(3) {
            ok(self.apply(epoch, s, chunk));
        }
    }

    /// Verify, finalize, apply and close a posted batch.
    pub fn settle(&mut self, epoch: u64, s: &Settlement) {
        self.verify_all(epoch, s);
        ok(self.finalize(epoch));
        self.apply_all(epoch, s);
        ok(self.close_batch(epoch));
    }

    pub fn run_epoch(&mut self, epoch: u64, s: &Settlement) {
        self.post_with_quorum(epoch, s);
        self.settle(epoch, s);
    }

    /// Commits `epoch` and aborts it as the relay right away.
    pub fn skip_epoch(&mut self, epoch: u64) {
        ok(self.commit_for(epoch, &Settlement::default()));
        let relay = self.relay.insecure_clone();
        ok(self.abort(epoch, &relay, 2));
    }

    pub fn admin_send(&mut self, ixn: Instruction) -> TxResult {
        let a = self.admin.insecure_clone();
        self.send(&[ixn], &[&a])
    }
}

pub fn slot_hash(slot: u64) -> [u8; 32] {
    h(b"test/slot", &[&slot.to_le_bytes()])
}

pub fn next_state_root(epoch: u64) -> [u8; 32] {
    h(b"test/state", &[&epoch.to_le_bytes()])
}
