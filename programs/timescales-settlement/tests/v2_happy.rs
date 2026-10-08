//! Happy path across epochs: init, open, deposit, commit, reveal, post,
//! verify, finalize, apply, close. The state-root and receipt chains.
//! Withdrawals. Fee claims. Reclaim after retention.

mod common;

use common::*;
use solana_signer::Signer;
use timescales_core::crypto::domain;
use timescales_core::{EpochId, Hash32};

#[test]
fn init_market_writes_every_field() {
    let env = Env::new(Cfg {
        executors: 3,
        quorum: 2,
        ..Cfg::default()
    });
    let d = env.account(&env.market).expect("market").data;
    let m = MarketView::decode(&d);
    assert_eq!(u64_at(&d, 4), env.market_id);
    assert_eq!(key_at(&d, 12), env.creator.pubkey().to_bytes());
    assert_eq!(m.admin, env.admin.pubkey().to_bytes());
    assert_eq!(m.pending_admin, [0; 32]);
    assert_eq!(m.relay, env.relay.pubkey().to_bytes());
    assert_eq!(key_at(&d, 140), env.base_mint.to_bytes());
    assert_eq!(key_at(&d, 172), env.quote_mint.to_bytes());
    assert_eq!(key_at(&d, 204), env.base_vault.to_bytes());
    assert_eq!(key_at(&d, 236), env.quote_vault.to_bytes());
    assert_eq!(&d[268..314], &env.params);
    assert_eq!(key_at(&d, 314), h(domain::MARKET_PARAMS, &[&env.params]));
    assert_eq!(m.committee_digest, env.committee);
    assert_eq!((m.executor_count, m.receipt_quorum), (3, 2));
    for (i, k) in env.executors.iter().enumerate() {
        assert_eq!(m.executors[i], executor_id(k));
    }
    assert!(m.executors[3..].iter().all(|k| *k == [0; 32]));
    assert_eq!(
        (m.beacon_delay, m.timelock, m.exec_timeout, m.settle_timeout),
        (4, 20, 150, 1_500)
    );
    assert_eq!((m.last_committed, m.last_settled), (0, 0));
    assert_eq!(m.last_progress_slot, START_SLOT);
    assert_eq!((m.fees_accrued, m.fees_claimed), (0, 0));
    assert_eq!(m.prev_receipt, [0; 32]);
    assert_eq!(m.state_root, timescales_core::merkle::empty_root().0);
    assert_eq!(m.pending_kind, 0);
    assert_eq!(m.salt, env.salt);
    assert_eq!(m.prev_committee_digest, [0; 32]);
    assert!(!m.halted);
    assert_eq!(d[2], 2, "layout version");
    // The PDA is ["market", id] and the id is derived, not chosen.
    assert_eq!(env.market, market_pda(env.market_id));
}

#[test]
fn three_epochs_settle_and_chain() {
    let mut env = Env::new(Cfg::default());
    let a = env.trader(1_000, 50_000);
    let b = env.trader(2_000, 10_000);
    let c = env.trader(0, 7_000);
    let vault_quote = env.token_amount(&env.quote_vault);
    assert_eq!(vault_quote, 67_000);

    // Epoch 1: a buys 100 base from b for 1,000 quote and pays a 10 fee.
    let s1 = Settlement::new(&[(a.owner(), 100, -1_010), (b.owner(), -100, 1_000)], 10);
    env.post_with_quorum(1, &s1);
    let posted = env.batch_view(1);
    assert_eq!(posted.status, POSTED);
    assert_eq!((posted.cosign_count, posted.cosign_bitmap), (1, 1));
    env.settle(1, &s1);
    let b1 = env.batch_view(1);
    assert_eq!(b1.status, SETTLED);
    assert_eq!((b1.verified_count, b1.applied_count), (2, 2));
    let m = env.market_view();
    assert_eq!((m.last_committed, m.last_settled), (1, 1));
    assert_eq!(m.prev_receipt, b1.receipt);
    assert_eq!(m.state_root, next_state_root(1));
    assert_eq!(m.fees_accrued, 10);
    assert_eq!(
        (
            env.trader_view(&a.owner()).base,
            env.trader_view(&a.owner()).quote
        ),
        (1_100, 48_990)
    );
    assert_eq!(
        (
            env.trader_view(&b.owner()).base,
            env.trader_view(&b.owner()).quote
        ),
        (1_900, 11_000)
    );

    // Epoch 2 executes against epoch 1's state root and receipt.
    let s2 = Settlement::new(
        &[
            (a.owner(), -50, 495),
            (b.owner(), 0, 0),
            (c.owner(), 50, -500),
        ],
        5,
    );
    ok(env.commit_for(2, &s2));
    ok(env.reveal(2));
    let post = env.prepare(2, &s2);
    assert_eq!(&post.header[251..283], &b1.receipt);
    assert_eq!(&post.header[187..219], &next_state_root(1));
    ok(env.post(2, &post));
    let b2 = env.batch_view(2);
    assert_eq!(b2.header_digest, post.header_digest());
    assert_eq!(b2.receipt, post.digest());
    assert_eq!(b2.outcome_digest, post.outcome_digest());
    assert_eq!(b2.next_state_root, next_state_root(2));
    env.settle(2, &s2);

    // Epoch 3 has no deltas at all.
    let s3 = Settlement::default();
    env.run_epoch(3, &s3);
    let m = env.market_view();
    assert_eq!((m.last_committed, m.last_settled), (3, 3));
    assert_eq!(m.state_root, next_state_root(3));
    assert_eq!(m.prev_receipt, env.batch_view(3).receipt);
    assert_eq!(m.fees_accrued, 15);

    // Conservation: the quote vault backs every balance plus unclaimed fees.
    let total_quote: u64 = [&a, &b, &c]
        .iter()
        .map(|t| env.trader_view(&t.owner()).quote)
        .sum();
    assert_eq!(total_quote + m.fees_accrued - m.fees_claimed, vault_quote);

    // Fee claim moves exactly the claimed amount out of the vault.
    let dest = env.wallet(0, 0);
    let claim = env.claim_fees_ix(&env.admin.pubkey(), &dest.quote_ata, 15);
    ok(env.admin_send(claim));
    assert_eq!(env.token_amount(&dest.quote_ata), 15);
    assert_eq!(env.market_view().fees_claimed, 15);
    let over = env.claim_fees_ix(&env.admin.pubkey(), &dest.quote_ata, 1);
    fails(env.admin_send(over), E::Insolvent);

    // Withdraw with nothing in flight: unlocked at once.
    let req = env.request_withdraw_ix(&c, 50, 6_500);
    ok(env.send(&[req], &[&c.kp]));
    let wd = env.withdraw_ix(&c, true);
    ok(env.send(&[wd], &[&c.kp]));
    let wd = env.withdraw_ix(&c, false);
    ok(env.send(&[wd], &[&c.kp]));
    let t = env.trader_view(&c.owner());
    assert_eq!(
        (t.base, t.quote, t.requested_base, t.requested_quote),
        (0, 0, 0, 0)
    );
    assert_eq!(env.token_amount(&c.base_ata), 50);
    assert_eq!(env.token_amount(&c.quote_ata), 6_500);
    let wd = env.withdraw_ix(&c, true);
    fails(env.send(&[wd], &[&c.kp]), E::NothingToWithdraw);

    // The emptied account closes and returns its rent to the owner.
    let before = env.svm.get_balance(&c.owner()).expect("owner");
    let rent = env.account(&c.pda).expect("trader").lamports;
    let close = env.close_trader_ix(&c);
    ok(env.send(&[close], &[&c.kp]));
    assert!(env.account(&c.pda).is_none());
    assert_eq!(
        env.svm.get_balance(&c.owner()).expect("owner"),
        before + rent - 5_000
    );
}

#[test]
fn beacon_and_cosign_digest_match_the_off_chain_crates() {
    let mut env = Env::new(Cfg {
        executors: 2,
        quorum: 2,
        ..Cfg::default()
    });
    let a = env.trader(10, 10);
    let s = Settlement::new(&[(a.owner(), 0, 0)], 0);
    ok(env.commit_for(1, &s));
    ok(env.reveal(1));
    let b = env.batch_view(1);
    let d = u64::from(env.cfg.beacon_delay);
    assert_eq!(b.beacon_slot_a, b.commit_slot + d);
    assert_eq!(b.beacon_slot_b, b.commit_slot + 2 * d);
    let expected = timescales_auction::beacon_v2(
        &env.market.to_bytes(),
        EpochId(1),
        &Hash32(b.root),
        b.count,
        (b.beacon_slot_a, Hash32(slot_hash(b.beacon_slot_a))),
        (b.beacon_slot_b, Hash32(slot_hash(b.beacon_slot_b))),
    );
    assert_eq!(b.beacon, expected.0);
    assert_eq!(b.reveal_slot, env.slot());

    let post = env.prepare(1, &s);
    ok(env.post(1, &post));
    let b = env.batch_view(1);
    let expected = timescales_auction::receipts::cosign_digest(
        &env.market.to_bytes(),
        EpochId(1),
        &Hash32(b.header_digest),
        &Hash32(b.outcome_digest),
    );
    assert_eq!(env.cosign_digest(1), expected.0);
    ok(env.cosign(1, 1));
    assert_eq!(env.batch_view(1).cosign_bitmap, 0b11);
    env.settle(1, &s);
}

#[test]
fn terms_digest_matches_the_off_chain_crate() {
    use timescales_core::{Decode, PriceBand};
    let band = PriceBand::decode_exact(&BAND).expect("band");
    assert_eq!(
        timescales_auction::terms_digest(&band, &Hash32(BINDING)).0,
        terms()
    );
}

#[test]
fn reclaim_after_retention() {
    let mut env = Env::new(Cfg::default());
    let s = Settlement::default();
    env.run_epoch(1, &s);
    for e in 2..=1024 {
        env.skip_epoch(e);
    }
    assert_eq!(env.market_view().last_settled, 1024);
    let relay = env.relay.pubkey();
    let r = env.reclaim_ix(1, &relay);
    fails(env.crank(&[r]), E::RetentionNotReached);
    let wrong = env.reclaim_ix(1, &env.cranker.pubkey());
    env.skip_epoch(1025);
    fails(env.crank(&[wrong]), E::InvalidAccount);
    let rent = env.account(&env.batch_pda(1)).expect("batch").lamports;
    let before = env.svm.get_balance(&relay).expect("relay");
    let r = env.reclaim_ix(1, &relay);
    ok(env.crank(&[r]));
    assert!(env.account(&env.batch_pda(1)).is_none());
    assert_eq!(env.svm.get_balance(&relay).expect("relay"), before + rent);
    // Aborted batches are reclaimable too, and an in-flight one never is.
    let r = env.reclaim_ix(2, &relay);
    fails(env.crank(&[r]), E::RetentionNotReached);
    ok(env.commit_for(1026, &s));
    let r = env.reclaim_ix(1026, &relay);
    fails(env.crank(&[r]), E::WrongStatus);
}
