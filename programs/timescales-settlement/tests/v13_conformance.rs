//! V13 conformance: the chain crate against the program artifact.
//!
//! Every one of the 24 instructions is built by the chain crate, sent to
//! the program in LiteSVM and must succeed. The crate's decoders must read
//! back what the program wrote. Its addresses must match `solana-program`'s
//! derivations and what the Token, associated token account and loader
//! programs create. Its transaction sizes must match message compilation.
//! And its error attribution must name the failing program from the logs
//! the runtime produced. The other suites build instructions by hand
//! (`common`), so the two encodings are also compared byte for byte.

mod common;

use std::collections::BTreeSet;
use std::str::FromStr;

use common::*;
use litesvm::LiteSVM;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program::pubkey::Pubkey;
use solana_signer::Signer;
use timescales_auction::settlement::{AccountDelta, SettlementBatch};
use timescales_chain::program::errors::ProgramKind;
use timescales_chain::program::{self as ts, AbortReason, BatchStatus, GovernanceChange, Side};
use timescales_core::{
    Decode, Encode, EpochId, Hash32, MarketId, MarketParams, QuoteAtoms, TraderId,
};

fn key(a: &Address) -> ts::Key {
    a.to_bytes()
}

fn addr(k: &ts::Key) -> Address {
    Address::from(*k)
}

fn program() -> ts::Key {
    key(&program_id())
}

fn sdk(ix: &ts::Ix) -> Instruction {
    Instruction {
        program_id: addr(&ix.program),
        accounts: ix
            .accounts
            .iter()
            .map(|m| AccountMeta {
                pubkey: addr(&m.key),
                is_signer: m.signer,
                is_writable: m.writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

fn keypair(label: &[u8]) -> Keypair {
    Keypair::new_from_array(h(b"v13/keypair", &[label]))
}

fn budgeted(ixs: Vec<ts::Ix>) -> Vec<ts::Ix> {
    let mut all = vec![
        ts::compute_budget::set_limit(400_000),
        ts::compute_budget::set_price(1_000),
    ];
    all.extend(ixs);
    all
}

/// An `Env` whose transactions are all built by the chain crate.
struct Run {
    env: Env,
    /// Tags of settlement-program instructions that succeeded.
    tags: BTreeSet<u8>,
}

impl Run {
    fn new(cfg: Cfg) -> Self {
        Run {
            env: Env::bare(cfg),
            tags: BTreeSet::new(),
        }
    }

    fn market(&self) -> ts::Key {
        key(&self.env.market)
    }

    fn batch(&self, epoch: u64) -> ts::Key {
        ts::batch_pda(&program(), &self.market(), epoch).unwrap().0
    }

    /// Sends `ixs` signed by `signers`, the first paying. The size computed
    /// by the chain crate must equal the size of the message
    /// `solana-message` compiles, and fit one packet.
    fn send(&mut self, ixs: &[ts::Ix], signers: &[&Keypair]) -> TxResult {
        let payer = signers[0].pubkey();
        let sdk_ixs: Vec<Instruction> = ixs.iter().map(sdk).collect();
        let size = ts::legacy_tx_size(ixs, &key(&payer), signers.len());
        assert_eq!(size, legacy_tx_size(&sdk_ixs, &payer, signers.len()));
        assert!(size <= ts::MAX_TX_SIZE, "{size} bytes");
        let r = self.env.send(&sdk_ixs, signers);
        if r.is_ok() {
            for ix in ixs.iter().filter(|ix| ix.program == program()) {
                self.tags.insert(ix.data[0]);
            }
        }
        r
    }

    fn crank(&mut self, ixs: &[ts::Ix]) -> TxResult {
        let cranker = self.env.cranker.insecure_clone();
        self.send(ixs, &[&cranker])
    }

    fn market_account(&self) -> ts::MarketAccount {
        let a = self.env.account(&self.env.market).expect("market");
        assert_eq!(a.owner, program_id());
        let m = ts::decode_market(&a.data).unwrap();
        check_market_view(&m, &MarketView::decode(&a.data));
        m
    }

    fn trader_account(&self, owner: &ts::Key) -> ts::TraderAccount {
        let a = self
            .env
            .account(&self.env.trader_pda(&addr(owner)))
            .expect("trader");
        assert_eq!(a.owner, program_id());
        let t = ts::decode_trader(&a.data).unwrap();
        let ours = TraderView {
            base: t.base,
            quote: t.quote,
            requested_base: t.requested_base,
            requested_quote: t.requested_quote,
            request_epoch: t.request_epoch,
            last_leaf_epoch: t.last_leaf_epoch,
            last_change_slot: t.last_change_slot,
            floor_epoch: t.floor_epoch,
            floor_base: t.floor_base,
            floor_quote: t.floor_quote,
        };
        assert_eq!(ours, TraderView::decode(&a.data));
        assert_eq!((t.market, t.owner), (self.market(), *owner));
        t
    }

    fn batch_account(&self, epoch: u64) -> ts::BatchAccount {
        let a = self.env.account(&addr(&self.batch(epoch))).expect("batch");
        assert_eq!(a.owner, program_id());
        let b = ts::decode_batch(&a.data).unwrap();
        let v = BatchView::decode(&a.data);
        let reason = b.abort_reason.map_or(0, |r| r as u8);
        assert_eq!(
            [b.status as u8, reason, b.cosign_count, b.cosign_bitmap],
            [v.status, v.abort_reason, v.cosign_count, v.cosign_bitmap]
        );
        assert_eq!(
            [
                b.epoch,
                b.commit_slot,
                b.beacon_slot_a,
                b.beacon_slot_b,
                b.reveal_slot,
                b.receipt_slot,
                b.fees
            ],
            [
                v.epoch,
                v.commit_slot,
                v.beacon_slot_a,
                v.beacon_slot_b,
                v.reveal_slot,
                v.receipt_slot,
                v.fees
            ]
        );
        assert_eq!(
            [
                b.root,
                b.beacon,
                b.header_digest,
                b.receipt,
                b.outcome_digest,
                b.next_state_root
            ]
            .map(|h| h.0),
            [
                v.root,
                v.beacon,
                v.header_digest,
                v.receipt,
                v.outcome_digest,
                v.next_state_root
            ]
        );
        assert_eq!(
            [
                b.count,
                b.settlement_count,
                b.verified_count,
                b.applied_count
            ],
            [
                v.count,
                v.settlement_count,
                v.verified_count,
                v.applied_count
            ]
        );
        assert_eq!(b.market, self.market());
        b
    }
}

fn check_market_view(m: &ts::MarketAccount, v: &MarketView) {
    assert_eq!(m.layout_version, 2);
    assert_eq!(m.halted, v.halted);
    let pending_admin = m.pending_admin.unwrap_or([0; 32]);
    assert_eq!(
        [
            m.admin,
            pending_admin,
            m.relay,
            m.committee_digest.0,
            m.salt
        ],
        [
            v.admin,
            v.pending_admin,
            v.relay,
            v.committee_digest,
            v.salt
        ]
    );
    assert_eq!(
        [m.prev_receipt, m.state_root, m.prev_committee_digest].map(|h| h.0),
        [v.prev_receipt, v.state_root, v.prev_committee_digest]
    );
    assert_eq!(
        [m.executor_count, m.receipt_quorum],
        [v.executor_count, v.receipt_quorum]
    );
    assert_eq!(m.executors.to_vec(), v.executors);
    assert_eq!(m.beacon_delay_slots, v.beacon_delay);
    assert_eq!(
        [
            m.timelock_slots,
            m.exec_timeout_slots,
            m.settle_timeout_slots,
            m.last_committed
        ],
        [
            v.timelock,
            v.exec_timeout,
            v.settle_timeout,
            v.last_committed
        ]
    );
    assert_eq!(
        [
            m.last_settled,
            m.last_progress_slot,
            m.fees_accrued,
            m.fees_claimed
        ],
        [
            v.last_settled,
            v.last_progress_slot,
            v.fees_accrued,
            v.fees_claimed
        ]
    );
    let pending = m.pending.as_ref();
    assert_eq!(pending.map_or(0, |p| p.change.kind()), v.pending_kind);
    if let Some(p) = pending {
        assert_eq!(p.eta_slot, v.pending_eta);
    }
}

struct Wallet {
    kp: Keypair,
    owner: ts::Key,
    base_ata: ts::Key,
    quote_ata: ts::Key,
}

/// Mints (the base mint with a freeze authority), the market's vaults as
/// associated token accounts of the market PDA, all created through the
/// Token and associated token account programs.
fn bootstrap_tokens(run: &mut Run) {
    let creator = run.env.creator.insecure_clone();
    let payer = key(&creator.pubkey());
    let freeze_authority = key(&run.env.admin.pubkey());
    let rent = run
        .env
        .svm
        .minimum_balance_for_rent_exemption(ts::spl::MINT_LEN);
    let market = run.market();
    let mut mints = Vec::new();
    for (label, freeze) in [
        (&b"base"[..], Some(&freeze_authority)),
        (&b"quote"[..], None),
    ] {
        let mint = keypair(label);
        let m = key(&mint.pubkey());
        let ixs = [
            ts::system::create_account(&payer, &m, rent, 82, &ts::TOKEN_PROGRAM),
            ts::spl::initialize_mint2(&m, &payer, freeze, 6),
        ];
        ok(run.send(&ixs, &[&creator, &mint]));
        let decoded = ts::spl::decode_mint(&run.env.account(&mint.pubkey()).unwrap().data).unwrap();
        assert_eq!(
            decoded,
            ts::spl::Mint {
                mint_authority: Some(payer),
                supply: 0,
                decimals: 6,
                freeze_authority: freeze.copied(),
            }
        );
        // The vault: created by the associated token account program, which
        // refuses an address other than the one it derives.
        let vault = ts::associated_token_address(&market, &m);
        ok(run.send(
            &[ts::spl::create_ata_idempotent(&payer, &market, &m)],
            &[&creator],
        ));
        let data = run.env.account(&addr(&vault)).expect("vault").data;
        assert_eq!((&data[..32], &data[32..64]), (&m[..], &market[..]));
        // Idempotent.
        ok(run.send(
            &[ts::spl::create_ata_idempotent(&payer, &market, &m)],
            &[&creator],
        ));
        mints.push((mint.pubkey(), addr(&vault)));
    }
    (run.env.base_mint, run.env.base_vault) = mints[0];
    (run.env.quote_mint, run.env.quote_vault) = mints[1];
}

/// A funded wallet with associated token accounts holding `base` and
/// `quote`, minted by the creator.
fn wallet(run: &mut Run, base: u64, quote: u64) -> Wallet {
    let kp = run.env.funded();
    let owner = key(&kp.pubkey());
    let (base_mint, quote_mint) = (key(&run.env.base_mint), key(&run.env.quote_mint));
    let ixs = [
        ts::spl::create_ata_idempotent(&owner, &owner, &base_mint),
        ts::spl::create_ata_idempotent(&owner, &owner, &quote_mint),
    ];
    ok(run.send(&ixs, &[&kp]));
    let w = Wallet {
        owner,
        base_ata: ts::associated_token_address(&owner, &base_mint),
        quote_ata: ts::associated_token_address(&owner, &quote_mint),
        kp,
    };
    let creator = run.env.creator.insecure_clone();
    let authority = key(&creator.pubkey());
    let ixs = [
        ts::spl::mint_to(&base_mint, &w.base_ata, &authority, base),
        ts::spl::mint_to(&quote_mint, &w.quote_ata, &authority, quote),
    ];
    ok(run.send(&ixs, &[&creator]));
    assert_eq!(run.env.token_amount(&addr(&w.base_ata)), base);
    assert_eq!(run.env.token_amount(&addr(&w.quote_ata)), quote);
    w
}

fn init_args(env: &Env) -> ts::InitMarketArgs {
    ts::InitMarketArgs {
        salt: env.salt,
        admin: key(&env.admin.pubkey()),
        relay: key(&env.relay.pubkey()),
        params: MarketParams::decode_exact(&env.params).unwrap(),
        committee_digest: Hash32(env.committee),
        beacon_delay_slots: env.cfg.beacon_delay,
        timelock_slots: env.cfg.timelock,
        exec_timeout_slots: env.cfg.exec_timeout,
        settle_timeout_slots: env.cfg.settle_timeout,
        receipt_quorum: env.cfg.quorum,
        executors: env.executors.iter().map(executor_id).collect(),
    }
}

fn init_market(run: &mut Run) {
    let env = &run.env;
    let creator = env.creator.insecure_clone();
    let ix = ts::init_market(
        &program(),
        &key(&creator.pubkey()),
        &key(&env.base_mint),
        &key(&env.quote_mint),
        &key(&env.base_vault),
        &key(&env.quote_vault),
        &init_args(env),
    )
    .unwrap();
    // The same bytes as the hand-built instruction of the other suites.
    assert_eq!(
        sdk(&ix),
        env.init_market_ix(&env.init_args(), &creator.pubkey())
    );
    ok(run.send(&[ix], &[&creator]));
}

fn open_and_deposit(run: &mut Run, w: &Wallet, base: u64, quote: u64) {
    let (p, m) = (program(), run.market());
    let mut ixs = vec![ts::open_trader(&p, &w.owner, &m).unwrap()];
    let (base_vault, quote_vault) = (key(&run.env.base_vault), key(&run.env.quote_vault));
    if base > 0 {
        ixs.push(
            ts::deposit(&p, &w.owner, &m, &w.base_ata, &base_vault, Side::Base, base).unwrap(),
        );
    }
    if quote > 0 {
        ixs.push(
            ts::deposit(
                &p,
                &w.owner,
                &m,
                &w.quote_ata,
                &quote_vault,
                Side::Quote,
                quote,
            )
            .unwrap(),
        );
    }
    let kp = w.kp.insecure_clone();
    ok(run.send(&ixs, &[&kp]));
}

/// The SDK settlement batch and the hand-built `Settlement` of the other
/// suites over the same deltas: one tree, one root.
fn settlement(
    market_id: u64,
    epoch: u64,
    deltas: &[(&Wallet, i64, i64)],
    fees: u64,
) -> (SettlementBatch, Settlement) {
    let batch = SettlementBatch {
        market: MarketId(market_id),
        epoch: EpochId(epoch),
        deltas: deltas
            .iter()
            .map(|(w, base, quote)| AccountDelta {
                trader: TraderId(w.owner),
                base: *base,
                quote: *quote,
            })
            .collect(),
        fees: QuoteAtoms(fees),
    };
    let s = Settlement::new(
        &deltas
            .iter()
            .map(|(w, base, quote)| (addr(&w.owner), *base, *quote))
            .collect::<Vec<_>>(),
        fees,
    );
    assert_eq!(batch.root().0, s.root());
    (batch, s)
}

fn commit(run: &mut Run, epoch: u64, count: u32) {
    let root = Hash32(h(b"test/batch-root", &[&epoch.to_le_bytes()]));
    let relay = run.env.relay.insecure_clone();
    let ix = ts::commit_batch(
        &program(),
        &key(&relay.pubkey()),
        &run.market(),
        epoch,
        &root,
        count,
        &Hash32(terms()),
    )
    .unwrap();
    assert_eq!(sdk(&ix), run.env.commit_ix(epoch, &root.0, count, &terms()));
    ok(run.send(&[ix], &[&relay]));
    let b = run.batch_account(epoch);
    assert_eq!(b.status, BatchStatus::Committed);
    assert_eq!((b.root, b.count, b.terms_digest.0), (root, count, terms()));
    assert_eq!(b.commit_slot, run.env.slot());
}

/// Reveal, post with the compute-budget instructions in front of the
/// Ed25519 instruction, and gather the quorum's co-signatures.
fn reveal_post_cosign(run: &mut Run, epoch: u64, s: &Settlement) {
    let (p, m) = (program(), run.market());
    let cranker = key(&run.env.cranker.pubkey());
    let target = run.batch_account(epoch).commit_slot + 2 * u64::from(run.env.cfg.beacon_delay) + 1;
    run.env.warp(target);
    run.env.fill_slot_hashes();
    let reveal = ts::reveal_beacon(&p, &cranker, &m, epoch).unwrap();
    assert_eq!(sdk(&reveal), run.env.reveal_ix(epoch));
    ok(run.crank(&[reveal]));
    let b = run.batch_account(epoch);
    assert_eq!(b.status, BatchStatus::BeaconRevealed);
    assert_eq!(b.reveal_slot, target);
    assert_ne!(b.beacon, Hash32::ZERO);

    let post = run.env.prepare(epoch, s);
    let receipt = run.env.signed_receipt(&post);
    let poster = &run.env.executors[0];
    let digest = post.digest();
    let pre = ts::ed25519_verify(
        &executor_id(poster),
        &Hash32(digest),
        &sign(poster, &digest),
    );
    let ix = ts::post_receipt(&p, &cranker, &m, epoch, &post.header, &receipt).unwrap();
    assert_eq!(
        vec![sdk(&pre), sdk(&ix)],
        run.env.post_ixs(epoch, &post),
        "post instructions"
    );
    ok(run.crank(&budgeted(vec![pre, ix])));
    let b = run.batch_account(epoch);
    assert_eq!(b.status, BatchStatus::ReceiptPosted);
    assert_eq!(
        (b.header_digest.0, b.receipt.0),
        (post.header_digest(), digest)
    );
    assert_eq!((b.cosign_count, b.cosign_bitmap), (1, 1));

    let digest = run.env.cosign_digest(epoch);
    for i in 1..usize::from(run.env.cfg.quorum) {
        let signer = run.env.executors[i].clone();
        let pre = ts::ed25519_verify(
            &executor_id(&signer),
            &Hash32(digest),
            &sign(&signer, &digest),
        );
        let ix = ts::cosign_receipt(&p, &cranker, &m, epoch).unwrap();
        assert_eq!(
            vec![sdk(&pre), sdk(&ix)],
            run.env.cosign_ixs(epoch, &signer, &digest)
        );
        ok(run.crank(&budgeted(vec![pre, ix])));
    }
    let b = run.batch_account(epoch);
    assert!(run.market_account().quorum_met(b.cosign_bitmap));
}

/// Verify, finalize, apply and close in the planner's chunks.
fn settle(run: &mut Run, epoch: u64, batch: &SettlementBatch, s: &Settlement) {
    let (p, m) = (program(), run.market());
    let cranker = key(&run.env.cranker.pubkey());
    let leaves = ts::leaves(batch).unwrap();
    let chunks = ts::plan_delta_chunks(&leaves, &cranker, true);
    let all: Vec<u32> = (0..u32::try_from(leaves.len()).unwrap()).collect();
    assert_eq!(run.batch_account(epoch).missing_verified(), all);
    for range in &chunks {
        let chunk = &leaves[range.clone()];
        let ix = ts::verify_deltas(&p, &cranker, &m, epoch, chunk).unwrap();
        let idx: Vec<usize> = range.clone().collect();
        assert_eq!(sdk(&ix), run.env.verify_ix(epoch, s, &idx));
        ok(run.crank(&budgeted(vec![ix])));
    }
    let b = run.batch_account(epoch);
    assert!(b.missing_verified().is_empty());
    assert_eq!(b.missing_applied(), all);
    let batch_key = run.batch(epoch);
    let fin = ts::finalize(&p, &cranker, &m, &batch_key);
    assert_eq!(sdk(&fin), run.env.finalize_ix(epoch));
    ok(run.crank(&[fin]));
    assert_eq!(run.batch_account(epoch).status, BatchStatus::Verified);
    for range in &chunks {
        let chunk = &leaves[range.clone()];
        let ix = ts::apply_deltas(&p, &cranker, &m, epoch, chunk).unwrap();
        let idx: Vec<usize> = range.clone().collect();
        assert_eq!(sdk(&ix), run.env.apply_ix(epoch, s, &idx));
        ok(run.crank(&budgeted(vec![ix])));
    }
    assert!(run.batch_account(epoch).missing_applied().is_empty());
    let close = ts::close_batch(&p, &cranker, &m, &batch_key);
    assert_eq!(sdk(&close), run.env.close_batch_ix(epoch));
    ok(run.crank(&[close]));
    let b = run.batch_account(epoch);
    assert_eq!(b.status, BatchStatus::Settled);
    let market = run.market_account();
    assert_eq!(market.last_settled, epoch);
    assert_eq!(market.prev_receipt, b.receipt);
    assert_eq!(market.state_root.0, next_state_root(epoch));
}

/// Commits `epoch` and aborts it as the relay before the beacon delay.
fn relay_abort(run: &mut Run, epoch: u64) {
    let relay = run.env.relay.insecure_clone();
    let (p, m, batch) = (program(), run.market(), run.batch(epoch));
    let root = Hash32(h(b"test/batch-root", &[&epoch.to_le_bytes()]));
    let commit = ts::commit_batch(
        &p,
        &key(&relay.pubkey()),
        &m,
        epoch,
        &root,
        1,
        &Hash32(terms()),
    )
    .unwrap();
    let abort = ts::abort_batch(&p, &m, &batch, &key(&relay.pubkey()), AbortReason::Relay);
    ok(run.send(&[commit], &[&relay]));
    ok(run.send(&[abort], &[&relay]));
}

fn propose_and_apply(run: &mut Run, change: GovernanceChange) -> ts::MarketAccount {
    let admin = run.env.admin.insecure_clone();
    let (p, m) = (program(), run.market());
    let ix = ts::propose_change(&p, &key(&admin.pubkey()), &m, &change).unwrap();
    assert_eq!(
        sdk(&ix),
        run.env
            .propose_ix(&admin.pubkey(), change.kind(), &change.payload().unwrap())
    );
    ok(run.send(&[ix], &[&admin]));
    let pending = run.market_account().pending.expect("pending change");
    assert_eq!(pending.change, change);
    assert_eq!(
        pending.eta_slot,
        run.env.slot() + run.market_account().timelock_slots
    );
    run.env.warp(pending.eta_slot);
    let cranker = key(&run.env.cranker.pubkey());
    let apply = ts::apply_change(&p, &cranker, &m);
    assert_eq!(
        sdk(&apply),
        run.env.apply_change_ix(&run.env.cranker.pubkey())
    );
    ok(run.crank(&[apply]));
    let market = run.market_account();
    assert_eq!(market.pending, None);
    market
}

#[test]
fn every_tag_runs_on_the_program() {
    let mut run = Run::new(Cfg {
        executors: 3,
        quorum: 2,
        ..Cfg::default()
    });
    let (p, m) = (program(), run.market());
    bootstrap_tokens(&mut run);
    init_market(&mut run);
    let market = run.market_account();
    assert_eq!(market.market_id, run.env.market_id);
    assert_eq!(market.creator, key(&run.env.creator.pubkey()));
    assert_eq!(market.params.to_bytes(), run.env.params.to_vec());
    assert_eq!(
        market.params_digest.0,
        h(timescales_core::crypto::domain::MARKET_PARAMS, &[&run.env.params])
    );
    assert_eq!(market.state_root, ts::EMPTY_STATE_ROOT);
    assert_eq!(
        (market.base_vault, market.quote_vault),
        (key(&run.env.base_vault), key(&run.env.quote_vault))
    );
    assert_eq!(market.vault(Side::Quote), key(&run.env.quote_vault));
    assert_eq!(market.live_slots(), 0b111);

    let a = wallet(&mut run, 1_000, 10_000);
    let b = wallet(&mut run, 2_000, 5_000);
    let c = wallet(&mut run, 0, 0);
    open_and_deposit(&mut run, &a, 1_000, 10_000);
    open_and_deposit(&mut run, &b, 2_000, 5_000);
    open_and_deposit(&mut run, &c, 0, 0);
    assert_eq!(run.env.token_amount(&run.env.quote_vault), 15_000);
    let ta = run.trader_account(&a.owner);
    assert_eq!(
        (ta.base, ta.quote, ta.last_change_slot),
        (1_000, 10_000, run.env.slot())
    );

    // Epoch 1: a buys 10 base from b for 100 quote and pays a fee of 1.
    let (batch, s) = settlement(run.env.market_id, 1, &[(&a, 10, -101), (&b, -10, 100)], 1);
    commit(&mut run, 1, 2);
    reveal_post_cosign(&mut run, 1, &s);
    settle(&mut run, 1, &batch, &s);
    let ta = run.trader_account(&a.owner);
    assert_eq!((ta.base, ta.quote, ta.last_leaf_epoch), (1_010, 9_899, 1));
    let tb = run.trader_account(&b.owner);
    assert_eq!((tb.base, tb.quote), (1_990, 5_100));
    assert_eq!(run.market_account().fees_accrued, 1);

    // Fee claim into a token account made with InitializeAccount3.
    let admin = run.env.admin.insecure_clone();
    let dest = keypair(b"fee destination");
    let rent = run
        .env
        .svm
        .minimum_balance_for_rent_exemption(ts::spl::TOKEN_ACCOUNT_LEN);
    let (admin_key, dest_key) = (key(&admin.pubkey()), key(&dest.pubkey()));
    let ixs = [
        ts::system::create_account(&admin_key, &dest_key, rent, 165, &ts::TOKEN_PROGRAM),
        ts::spl::initialize_account3(&dest_key, &key(&run.env.quote_mint), &admin_key),
    ];
    ok(run.send(&ixs, &[&admin, &dest]));
    let claim = ts::claim_fees(&p, &admin_key, &m, &key(&run.env.quote_vault), &dest_key, 1);
    assert_eq!(
        sdk(&claim),
        run.env.claim_fees_ix(&admin.pubkey(), &dest.pubkey(), 1)
    );
    ok(run.send(&[claim], &[&admin]));
    assert_eq!(run.env.token_amount(&dest.pubkey()), 1);
    assert_eq!(run.market_account().unclaimed_fees(), 0);

    // Epoch 2: committed, then aborted by the relay before the beacon.
    relay_abort(&mut run, 2);
    let b2 = run.batch_account(2);
    assert_eq!(
        (b2.status, b2.abort_reason),
        (BatchStatus::Aborted, Some(AbortReason::Relay))
    );
    assert!(!run.market_account().in_flight());

    // Withdrawal requests: request, cancel, request again, withdraw.
    let ak = a.kp.insecure_clone();
    let req = ts::request_withdraw(&p, &a.owner, &m, 5, 0).unwrap();
    ok(run.send(&[req], &[&ak]));
    let ta = run.trader_account(&a.owner);
    assert_eq!((ta.requested_base, ta.request_epoch), (5, 2));
    let cancel = ts::cancel_withdraw_request(&p, &a.owner, &m).unwrap();
    ok(run.send(&[cancel], &[&ak]));
    assert_eq!(run.trader_account(&a.owner).requested_base, 0);
    let req = ts::request_withdraw(&p, &a.owner, &m, 0, 899).unwrap();
    ok(run.send(&[req], &[&ak]));
    assert_eq!(
        ts::available(&run.trader_account(&a.owner), 3),
        (1_010, 9_000)
    );
    let wd = ts::withdraw(
        &p,
        &a.owner,
        &m,
        &key(&run.env.quote_vault),
        &a.quote_ata,
        Side::Quote,
    )
    .unwrap();
    ok(run.send(&[wd], &[&ak]));
    let ta = run.trader_account(&a.owner);
    assert_eq!((ta.quote, ta.requested_quote), (9_000, 0));
    assert_eq!(run.env.token_amount(&addr(&a.quote_ata)), 899);

    // Governance: halt, every change kind, cancel, two-step admin, removal.
    let halt = ts::set_halted(&p, &admin_key, &m, true);
    assert_eq!(sdk(&halt), run.env.set_halted_ix(&admin.pubkey(), true));
    ok(run.send(&[halt], &[&admin]));
    assert!(run.market_account().halted);
    ok(run.send(&[ts::set_halted(&p, &admin_key, &m, false)], &[&admin]));
    assert!(!run.market_account().halted);

    let market = propose_and_apply(&mut run, GovernanceChange::SetTimelock(30));
    assert_eq!(market.timelock_slots, 30);
    let old_committee = market.committee_digest;
    let market = propose_and_apply(
        &mut run,
        GovernanceChange::SetCommitteeDigest(Hash32([0xc1; 32])),
    );
    assert_eq!(market.committee_digest, Hash32([0xc1; 32]));
    assert_eq!(market.prev_committee_digest, old_committee);
    let market = propose_and_apply(
        &mut run,
        GovernanceChange::SetTimings {
            beacon_delay_slots: 8,
            exec_timeout_slots: 750,
            settle_timeout_slots: 9_000,
        },
    );
    assert_eq!(
        (
            market.beacon_delay_slots,
            market.exec_timeout_slots,
            market.settle_timeout_slots
        ),
        (8, 750, 9_000)
    );
    let mut keys: Vec<ts::Key> = run.env.executors.iter().map(executor_id).collect();
    keys.push(executor_id(&executor_key(3)));
    let market = propose_and_apply(
        &mut run,
        GovernanceChange::SetExecutors {
            keys: keys.clone(),
            quorum: 3,
        },
    );
    assert_eq!((market.executor_count, market.receipt_quorum), (4, 3));
    assert_eq!(market.executors[..4], keys[..]);
    let relay = run.env.relay.pubkey();
    let market = propose_and_apply(&mut run, GovernanceChange::SetRelay(key(&relay)));
    assert_eq!(market.relay, key(&relay));

    let proposal =
        ts::propose_change(&p, &admin_key, &m, &GovernanceChange::SetRelay([9; 32])).unwrap();
    ok(run.send(&[proposal], &[&admin]));
    let cancel = ts::cancel_change(&p, &admin_key, &m);
    assert_eq!(sdk(&cancel), run.env.cancel_change_ix(&admin.pubkey()));
    ok(run.send(&[cancel], &[&admin]));
    assert_eq!(run.market_account().pending, None);

    let next_admin = run.env.funded();
    let next = key(&next_admin.pubkey());
    let market = propose_and_apply(&mut run, GovernanceChange::SetAdmin(next));
    assert_eq!(market.pending_admin, Some(next));
    let accept = ts::accept_admin(&p, &next, &m);
    assert_eq!(sdk(&accept), run.env.accept_admin_ix(&next_admin.pubkey()));
    ok(run.send(&[accept], &[&next_admin]));
    let market = run.market_account();
    assert_eq!((market.admin, market.pending_admin), (next, None));
    let remove = ts::remove_executor(&p, &next, &m, &keys[3]);
    assert_eq!(
        sdk(&remove),
        run.env.remove_executor_ix(&next_admin.pubkey(), &keys[3])
    );
    ok(run.send(&[remove], &[&next_admin]));
    let market = run.market_account();
    assert_eq!((market.executor_count, market.executors[3]), (3, [0; 32]));
    assert_eq!(market.executor_slot(&keys[3]), None);

    // An empty account closes and returns its rent.
    let ck = c.kp.insecure_clone();
    let close = ts::close_trader(&p, &c.owner, &m).unwrap();
    ok(run.send(&[close], &[&ck]));
    assert!(run
        .env
        .account(&run.env.trader_pda(&addr(&c.owner)))
        .is_none_or(|acc| acc.lamports == 0));

    // Retention: 1024 more terminal epochs, then epoch 1's rent goes back
    // to the relay.
    for epoch in 3..=1026 {
        relay_abort(&mut run, epoch);
    }
    assert_eq!(run.market_account().last_settled, 1026);
    let relay_key = key(&relay);
    let before = run.env.account(&relay).expect("relay").lamports;
    let batch1 = run.batch(1);
    let rent1 = run.env.account(&addr(&batch1)).expect("batch").lamports;
    let cranker = key(&run.env.cranker.pubkey());
    let reclaim = ts::reclaim_batch(&p, &cranker, &m, &batch1, &relay_key);
    assert_eq!(sdk(&reclaim), run.env.reclaim_ix(1, &relay));
    ok(run.crank(&[reclaim]));
    assert_eq!(
        run.env.account(&relay).expect("relay").lamports,
        before + rent1
    );
    assert!(run
        .env
        .account(&addr(&batch1))
        .is_none_or(|acc| acc.lamports == 0));

    assert_eq!(run.tags, (0..=23).collect::<BTreeSet<u8>>(), "tags sent");
}

#[test]
fn builders_match_the_hand_built_instructions() {
    let mut env = Env::new(Cfg {
        executors: 3,
        quorum: 2,
        ..Cfg::default()
    });
    let (p, m) = (program(), key(&env.market));
    let t = env.wallet(7, 8);
    let owner = key(&t.owner());
    let (base_vault, quote_vault) = (key(&env.base_vault), key(&env.quote_vault));
    let mut checks: Vec<(ts::Ix, Instruction)> = vec![
        (
            ts::open_trader(&p, &owner, &m).unwrap(),
            env.open_trader_ix(&t.owner()),
        ),
        (
            ts::deposit(
                &p,
                &owner,
                &m,
                &key(&t.base_ata),
                &base_vault,
                Side::Base,
                7,
            )
            .unwrap(),
            env.deposit_ix(&t, false, 7),
        ),
        (
            ts::deposit(
                &p,
                &owner,
                &m,
                &key(&t.quote_ata),
                &quote_vault,
                Side::Quote,
                8,
            )
            .unwrap(),
            env.deposit_ix(&t, true, 8),
        ),
        (
            ts::request_withdraw(&p, &owner, &m, 3, 4).unwrap(),
            env.request_withdraw_ix(&t, 3, 4),
        ),
        (
            ts::cancel_withdraw_request(&p, &owner, &m).unwrap(),
            env.cancel_request_ix(&t),
        ),
        (
            ts::withdraw(&p, &owner, &m, &base_vault, &key(&t.base_ata), Side::Base).unwrap(),
            env.withdraw_ix(&t, false),
        ),
        (
            ts::withdraw(
                &p,
                &owner,
                &m,
                &quote_vault,
                &key(&t.quote_ata),
                Side::Quote,
            )
            .unwrap(),
            env.withdraw_ix(&t, true),
        ),
        (
            ts::close_trader(&p, &owner, &m).unwrap(),
            env.close_trader_ix(&t),
        ),
    ];
    let admin = env.admin.pubkey();
    let batch = |epoch: u64| key(&env.batch_pda(epoch));
    for (reason, byte) in [
        (AbortReason::Admin, 1u8),
        (AbortReason::Relay, 2),
        (AbortReason::BeaconExpired, 3),
        (AbortReason::ExecTimeout, 4),
        (AbortReason::SettleTimeout, 5),
        (AbortReason::QuorumTimeout, 6),
    ] {
        checks.push((
            ts::abort_batch(&p, &m, &batch(4), &key(&admin), reason),
            env.abort_ix(4, &admin, byte),
        ));
    }
    for change in [
        GovernanceChange::SetRelay([1; 32]),
        GovernanceChange::SetExecutors {
            keys: vec![[2; 32], [3; 32]],
            quorum: 1,
        },
        GovernanceChange::SetCommitteeDigest(Hash32([4; 32])),
        GovernanceChange::SetAdmin([5; 32]),
        GovernanceChange::SetTimings {
            beacon_delay_slots: 4,
            exec_timeout_slots: 150,
            settle_timeout_slots: 300,
        },
        GovernanceChange::SetTimelock(20),
    ] {
        checks.push((
            ts::propose_change(&p, &key(&admin), &m, &change).unwrap(),
            env.propose_ix(&admin, change.kind(), &change.payload().unwrap()),
        ));
    }
    for (ix, hand) in &checks {
        assert_eq!(&sdk(ix), hand, "tag {}", ix.data[0]);
    }

    // And they run: open the account and deposit on both sides.
    let tk = t.kp.insecure_clone();
    for (ix, _) in checks.iter().take(3) {
        ok(env.send(&[sdk(ix)], &[&tk]));
    }
    let view = env.trader_view(&t.owner());
    assert_eq!((view.base, view.quote), (7, 8));
}

fn loader() -> Pubkey {
    Pubkey::from_str("BPFLoaderUpgradeab1e11111111111111111111111").unwrap()
}

#[test]
fn addresses_match_solana() {
    let p = program();
    let id = Pubkey::new_from_array(p);
    for i in 0..200u64 {
        let market_id = i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let (k, bump) = Pubkey::find_program_address(&[b"market", &market_id.to_le_bytes()], &id);
        assert_eq!(ts::market_pda(&p, market_id).unwrap(), (k.to_bytes(), bump));
        let market = k.to_bytes();
        let owner = h(b"v13/owner", &[&i.to_le_bytes()]);
        let (k, bump) = Pubkey::find_program_address(&[b"trader", &market, &owner], &id);
        assert_eq!(
            ts::trader_pda(&p, &market, &owner).unwrap(),
            (k.to_bytes(), bump)
        );
        let (k, bump) = Pubkey::find_program_address(&[b"batch", &market, &i.to_le_bytes()], &id);
        assert_eq!(ts::batch_pda(&p, &market, i).unwrap(), (k.to_bytes(), bump));
        let mint = h(b"v13/mint", &[&i.to_le_bytes()]);
        let ata_program = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let token = timescales_settlement_program::cpi::TOKEN_PROGRAM;
        let (k, _) = Pubkey::find_program_address(&[&owner, token.as_ref(), &mint], &ata_program);
        assert_eq!(ts::associated_token_address(&owner, &mint), k.to_bytes());
        // The derived market id is the one the program accepts.
        let creator = Address::from(owner);
        let salt = h(b"v13/salt", &[&i.to_le_bytes()]);
        assert_eq!(
            ts::derive_market_id(&p, &owner, &salt),
            derive_market_id(&creator, &salt)
        );
    }

    // Well-known ids against solana-program's own constants.
    for (ours, theirs) in [
        (
            ts::TOKEN_PROGRAM,
            timescales_settlement_program::cpi::TOKEN_PROGRAM,
        ),
        (
            ts::SYSTEM_PROGRAM,
            Pubkey::from_str("11111111111111111111111111111111").unwrap(),
        ),
        (ts::ED25519_PROGRAM, solana_program::ed25519_program::ID),
        (
            ts::INSTRUCTIONS_SYSVAR,
            solana_program::sysvar::instructions::ID,
        ),
        (
            ts::SLOT_HASHES_SYSVAR,
            solana_program::sysvar::slot_hashes::ID,
        ),
        (ts::BPF_LOADER_UPGRADEABLE, loader()),
        (
            ts::COMPUTE_BUDGET_PROGRAM,
            Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap(),
        ),
        (
            ts::ASSOCIATED_TOKEN_PROGRAM,
            Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap(),
        ),
    ] {
        assert_eq!(ours, theirs.to_bytes(), "{theirs}");
    }

    // The program's ProgramData account, written by LiteSVM with the
    // loader's own serialization when it loads the artifact.
    let mut svm = LiteSVM::new();
    let clock = addr(&solana_program::sysvar::clock::ID.to_bytes());
    let load_slot = u64_at(&svm.get_account(&clock).expect("clock").data, 0);
    svm.add_program_from_file(program_id(), program_so())
        .expect("load program");
    let data_address = ts::loader::program_data_address(&p).unwrap();
    let (expected, _) = Pubkey::find_program_address(&[&p], &loader());
    assert_eq!(data_address, expected.to_bytes());
    let account = svm.get_account(&addr(&data_address)).expect("ProgramData");
    let program_data = ts::loader::decode_program_data(&account.data).unwrap();
    assert_eq!(
        program_data,
        ts::loader::ProgramData {
            last_deploy_slot: load_slot,
            upgrade_authority: None,
        }
    );
    let program_account = svm.get_account(&program_id()).expect("program");
    assert!(ts::loader::decode_program_data(&program_account.data).is_err());
}

#[test]
fn failures_are_attributed_from_the_runtime_logs() {
    let mut run = Run::new(Cfg::default());
    bootstrap_tokens(&mut run);
    init_market(&mut run);
    let (p, m) = (program(), run.market());

    // The settlement program itself, behind the compute-budget
    // instructions: CommitBatch out of order.
    let relay = run.env.relay.insecure_clone();
    let root = Hash32([7; 32]);
    let commit = ts::commit_batch(&p, &key(&relay.pubkey()), &m, 5, &root, 1, &root).unwrap();
    let f = run.send(&budgeted(vec![commit]), &[&relay]).unwrap_err();
    let failure = ts::errors::decode(f.index.unwrap(), &p, f.code.unwrap(), &f.logs);
    assert_eq!(
        failure,
        ts::errors::ProgramFailure {
            ix_index: 2,
            program: ProgramKind::Settlement,
            code: E::OutOfOrder.code(),
            name: Some("OutOfOrder"),
            error: Some(ts::TimescalesProgramError::OutOfOrder),
        }
    );

    // A Token CPI: a deposit larger than the source holds.
    let w = wallet(&mut run, 10, 0);
    let wk = w.kp.insecure_clone();
    ok(run.send(&[ts::open_trader(&p, &w.owner, &m).unwrap()], &[&wk]));
    let vault = key(&run.env.base_vault);
    let deposit = ts::deposit(&p, &w.owner, &m, &w.base_ata, &vault, Side::Base, 11).unwrap();
    let f = run.send(&[deposit], &[&wk]).unwrap_err();
    let failure = ts::errors::decode(f.index.unwrap(), &p, f.code.unwrap(), &f.logs);
    assert_eq!(
        (
            failure.ix_index,
            failure.program,
            failure.name,
            failure.error
        ),
        (0, ProgramKind::Token, Some("InsufficientFunds"), None),
        "{:#?}",
        f.logs
    );

    // A System CPI: OpenTrader from a wallet that can pay the fee and stays
    // rent-exempt itself, but cannot pay the Trader account's rent.
    let poor = keypair(b"poor");
    let lamports = run.env.svm.minimum_balance_for_rent_exemption(0) + 100_000;
    assert!(
        lamports
            < run
                .env
                .svm
                .minimum_balance_for_rent_exemption(ts::TRADER_LEN)
    );
    run.env.svm.airdrop(&poor.pubkey(), lamports).unwrap();
    let open = ts::open_trader(&p, &key(&poor.pubkey()), &m).unwrap();
    let f = run.send(&[open], &[&poor]).unwrap_err();
    let failure = ts::errors::decode(f.index.unwrap(), &p, f.code.unwrap(), &f.logs);
    assert_eq!(
        (
            failure.ix_index,
            failure.program,
            failure.name,
            failure.error
        ),
        (
            0,
            ProgramKind::System,
            Some("ResultWithNegativeLamports"),
            None
        ),
        "{:#?}",
        f.logs
    );

    // The same codes without logs: only a settlement code is attributed.
    let blind = ts::errors::decode(0, &p, E::OutOfOrder.code(), &[]);
    assert_eq!(blind.program, ProgramKind::Settlement);
    assert_eq!(
        ts::errors::decode(0, &p, 1, &[]).program,
        ProgramKind::Other
    );
}

/// A batch of 65 settlement leaves (audit paths of 7 hashes) settles in
/// the planner's chunks of 3 with the compute-budget instructions, every
/// transaction within one packet.
#[test]
fn planned_chunks_settle_a_large_batch() {
    let mut run = Run::new(Cfg::default());
    bootstrap_tokens(&mut run);
    init_market(&mut run);
    let wallets: Vec<Wallet> = (0..65)
        .map(|_| {
            let w = wallet(&mut run, 100, 100);
            open_and_deposit(&mut run, &w, 100, 100);
            w
        })
        .collect();
    // Alternate buyers and sellers, so base and quote both conserve. The
    // odd one out keeps a zero delta.
    let mut deltas: Vec<(&Wallet, i64, i64)> = wallets
        .iter()
        .enumerate()
        .map(|(i, w)| match i % 2 {
            0 if i + 1 < wallets.len() => (w, 3, -30),
            1 => (w, -3, 30),
            _ => (w, 0, 0),
        })
        .collect();
    deltas.sort_by_key(|(w, _, _)| w.owner);
    let (batch, s) = settlement(run.env.market_id, 1, &deltas, 0);
    let leaves = ts::leaves(&batch).unwrap();
    assert!(leaves[..64].iter().all(|l| l.path.len() == 7));
    let cranker = key(&run.env.cranker.pubkey());
    let chunks = ts::plan_delta_chunks(&leaves, &cranker, true);
    assert_eq!(chunks[0].len(), 3);
    assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), 65);
    commit(&mut run, 1, 65);
    reveal_post_cosign(&mut run, 1, &s);
    settle(&mut run, 1, &batch, &s);
    for (w, base, quote) in &deltas {
        let t = run.trader_account(&w.owner);
        assert_eq!(
            (i128::from(t.base), i128::from(t.quote)),
            (100 + i128::from(*base), 100 + i128::from(*quote))
        );
    }
}

/// The floor the program records at the first change to a Trader account
/// while a batch is in flight is `available` for that batch,
/// the value the enclave's balance check compares the sheet with. A request
/// made before the commit is reserved for the batch. Cancelling it after the
/// commit captures the floor.
#[test]
fn the_recorded_floor_is_available_at_the_commit() {
    let mut run = Run::new(Cfg::default());
    bootstrap_tokens(&mut run);
    init_market(&mut run);
    let (p, m) = (program(), run.market());
    let w = wallet(&mut run, 100, 100);
    open_and_deposit(&mut run, &w, 100, 100);
    let wk = w.kp.insecure_clone();
    let request = ts::request_withdraw(&p, &w.owner, &m, 5, 7).unwrap();
    ok(run.send(&[request], &[&wk]));
    commit(&mut run, 1, 1);
    let before = run.trader_account(&w.owner);
    assert_eq!((before.request_epoch, before.floor_epoch), (0, 0));
    assert_eq!(ts::available(&before, 1), (95, 93));

    let cancel = ts::cancel_withdraw_request(&p, &w.owner, &m).unwrap();
    ok(run.send(&[cancel], &[&wk]));
    let after = run.trader_account(&w.owner);
    assert_eq!(after.floor_epoch, 1);
    assert_eq!(
        (after.floor_base, after.floor_quote),
        ts::available(&before, 1)
    );
    assert_eq!(after.last_change_slot, run.env.slot());
    // Available never decreases while the batch is in flight.
    assert_eq!(ts::available(&after, 1), (100, 100));
}
