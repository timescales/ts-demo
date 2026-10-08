use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::p2p::Network;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_auction::collateral::Balance;
use timescales_auction::{ChainView, CommittedBatch, InMemoryChain, batch_leaves, terms_digest};
use timescales_core::identity::TraderKey;
use timescales_core::intent::{Cancel, ENVELOPE_LEN, MaskedBody, PrivateIntent};
use timescales_core::*;
use timescales_executor::{KeyProvider, LocalKeySchedule};

use super::*;

fn params() -> MarketParams {
    MarketParams {
        market: MarketId(1),
        base_lot_size: 1,
        tick_size: 1,
        band_half_width: 4,
        max_order_lots_log2: 16,
        max_orders_per_trader: 8,
        max_batch_envelopes: 1024,
        max_order_lifetime: 2,
        maker_fee: FeeBps(0),
        taker_fee: FeeBps(0),
        flow: FlowMode::SingleBook,
        rationing: Rationing::Lottery,
        commitment_scheme: CommitmentScheme::Sha256,
    }
}

const MARKET: [u8; 32] = [0x4d; 32];
const PC: Hash32 = Hash32([0xc1; 32]);
const BINDING: Hash32 = Hash32([0xb1; 32]);
const W1: [u8; 32] = [0xa1; 32];
const W2: [u8; 32] = [0xa2; 32];

struct Env {
    keys: Arc<LocalKeySchedule>,
    chain: Arc<InMemoryChain>,
}

fn env() -> Env {
    Env {
        keys: Arc::new(LocalKeySchedule::new([9; 32])),
        chain: Arc::new(InMemoryChain::new([0x5a; 32])),
    }
}

fn config(padding: Padding) -> RelayConfig {
    RelayConfig {
        params: params(),
        market_address: MARKET,
        padding,
        allow_masked: false,
        max_real: params().max_batch_envelopes,
        carry_p: 0.0,
    }
}

fn cover(env: &Env) -> Box<EpochKeyCover<LocalKeySchedule>> {
    Box::new(EpochKeyCover {
        keys: env.keys.clone(),
        params: params(),
        masked: false,
    })
}

fn relay_key() -> Arc<Keypair> {
    Arc::new(Keypair::from_seed([0x7e; 32]))
}

fn window(epoch: u64, opens_at_ms: u64, cutoff_ms: u64) -> AuctionEpoch {
    AuctionEpoch {
        epoch: EpochId(epoch),
        opens_at_ms,
        cutoff_ms,
    }
}

/// A seeded relay with epoch 1 open for header v1 (the simulation path).
fn relay(env: &Env, ack: AckPolicy, padding: Padding, seed: u64) -> Relay {
    let mut r = Relay::new_seeded(
        config(padding),
        Arc::new(Keypair::from_seed([seed as u8; 32])),
        env.chain.clone(),
        cover(env),
        [seed as u8; 32],
    )
    .with_ack(ack);
    r.open_epoch(window(1, 0, 100), Tick(50), Hash32::ZERO)
        .unwrap();
    r
}

/// An OS-seeded relay with epoch 1 open for header v2.
fn relay_v2(env: &Env, padding: Padding) -> Relay {
    let mut r = Relay::new(config(padding), relay_key(), cover(env));
    r.open_epoch_v2(window(1, 0, 100), Tick(50), PC, BINDING)
        .unwrap();
    r
}

/// A signed placement for `epoch` and its commitment.
fn intent(trader: &TraderKey, nonce: u64, epoch: u64) -> (PrivateIntent, OrderCommitment) {
    let mut rng = ChaCha20Rng::seed_from_u64(nonce);
    let o = Order {
        market: MarketId(1),
        trader: trader.id(),
        nonce,
        side: Side::Buy,
        role: Role::Taker,
        kind: OrderKind::Limit,
        limit: Tick(50),
        quantity: Lots(1),
        valid_from: EpochId(epoch),
        expires_at: EpochId(epoch),
    };
    PrivateIntent::place(&mut rng, trader, CommitmentScheme::Sha256, o).unwrap()
}

/// `pi` sealed to the epoch key. `seed` picks the ephemeral key.
fn seal(
    env: &Env,
    epoch: u64,
    c: OrderCommitment,
    pi: &PrivateIntent,
    seed: u64,
) -> SealedEnvelope {
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x5ea1);
    let pk = env.keys.epoch_public(MarketId(1), EpochId(epoch)).unwrap();
    SealedEnvelope::seal(&mut rng, MarketId(1), EpochId(epoch), &pk, c, pi).unwrap()
}

fn submission_for(env: &Env, trader: &TraderKey, nonce: u64, epoch: u64) -> Submission {
    let (pi, c) = intent(trader, nonce, epoch);
    Submission::sign(trader, seal(env, epoch, c, &pi, nonce), None)
}

fn submission(env: &Env, trader: &TraderKey, nonce: u64) -> Submission {
    submission_for(env, trader, nonce, 1)
}

fn verified(s: &Submission) -> VerifiedSubmission {
    verify_submission(&config(Padding::None), s).unwrap()
}

fn sheet(trader: &TraderKey) -> BalanceSheet {
    let mut b = BalanceSheet::default();
    b.set(
        trader.id(),
        Balance {
            base: BaseAtoms(10),
            quote: QuoteAtoms(500),
        },
    );
    b
}

fn prior() -> OrderStateTable {
    let mut t = OrderStateTable::default();
    t.apply(EpochId(0), 2, [(OrderCommitment([7; 32]), Lots(1))], []);
    t
}

#[test]
fn pads_to_bucket_with_indistinguishable_cover() {
    let env = env();
    let mut r = relay(
        &env,
        AckPolicy::Immediate,
        Padding::PowerOfTwo { min: 8 },
        1,
    );
    let t = TraderKey::from_seed([1; 32]);
    for n in 0..5 {
        assert!(r.submit(10, submission(&env, &t, n)).unwrap().is_some());
    }
    let s = r
        .seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO,
        )
        .unwrap();
    assert_eq!((s.real, s.cover, s.batch.envelopes.len()), (5, 3, 8));
    assert!(
        s.batch
            .envelopes
            .iter()
            .all(|e| e.to_bytes().len() == ENVELOPE_LEN)
    );
    assert_eq!(
        env.chain.committed_root(MarketId(1), EpochId(1)),
        Some(s.batch.header.batch_root)
    );
    assert_eq!(
        s.batch.header.beacon,
        env.chain.beacon(MarketId(1), EpochId(1)).unwrap()
    );
}

#[test]
fn acks_at_cutoff_are_released_together() {
    let env = env();
    let mut r = relay(&env, AckPolicy::AtCutoff, Padding::None, 2);
    let t = TraderKey::from_seed([1; 32]);
    assert!(r.submit(10, submission(&env, &t, 1)).unwrap().is_none());
    assert!(r.submit(20, submission(&env, &t, 2)).unwrap().is_none());
    let s = r
        .seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO,
        )
        .unwrap();
    assert_eq!(s.promises.len(), 2);
    assert!(s.promises.iter().all(InclusionPromise::verify));
}

#[test]
fn window_and_authentication_enforced() {
    let env = env();
    let mut r = relay(&env, AckPolicy::Immediate, Padding::None, 3);
    let t = TraderKey::from_seed([1; 32]);
    assert!(matches!(
        r.submit(100, submission(&env, &t, 1)),
        Err(RelayError::Auction(AuctionError::AfterCutoff { .. }))
    ));
    let mut s = submission(&env, &t, 2);
    s.signature.0[0] ^= 1;
    assert_eq!(r.submit(10, s), Err(RelayError::BadSignature));

    let mut reg = Registry::default();
    reg.insert(TraderKey::from_seed([2; 32]).id(), ());
    r.set_allowlist(Some(reg));
    assert_eq!(
        r.submit(10, submission(&env, &t, 3)),
        Err(RelayError::Unauthorised)
    );
    assert!(
        r.seal(
            50,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO
        )
        .is_err(),
        "no seal before cutoff"
    );
}

#[test]
#[allow(deprecated)]
fn v1_exclusion_is_provable_for_its_own_batch() {
    let env = env();
    let mut r = relay(&env, AckPolicy::Immediate, Padding::None, 4);
    let t = TraderKey::from_seed([1; 32]);
    let p = r.submit(10, submission(&env, &t, 1)).unwrap().unwrap();
    let kept = submission(&env, &t, 2).envelope.commitment;
    // A dishonest relay commits a set without the promised envelope.
    let root = batch_root(&[kept]);
    assert!(prove_exclusion(&p, &[kept], &root));
    assert!(prove_exclusion_for(
        &p,
        MarketId(1),
        EpochId(1),
        &[kept],
        &root
    ));
    let both = [kept, p.commitment];
    assert!(!prove_exclusion_for(
        &p,
        MarketId(1),
        EpochId(1),
        &both,
        &batch_root(&both)
    ));
    // The same root read for another batch proves nothing, which the
    // deprecated check cannot tell.
    assert!(!prove_exclusion_for(
        &p,
        MarketId(1),
        EpochId(2),
        &[kept],
        &root
    ));
    assert!(!prove_exclusion_for(
        &p,
        MarketId(2),
        EpochId(1),
        &[kept],
        &root
    ));
    let mut forged = p;
    forged.signature.0[0] ^= 1;
    assert!(!prove_exclusion_for(
        &forged,
        MarketId(1),
        EpochId(1),
        &[kept],
        &root
    ));
}

#[tokio::test]
async fn replicas_converge_after_partition_and_cannot_equivocate() {
    let env = env();
    let net = Network::new(7);
    let mut a =
        relay(&env, AckPolicy::Immediate, Padding::None, 5).with_peers(net.endpoint(1).unwrap());
    let mut b =
        relay(&env, AckPolicy::Immediate, Padding::None, 6).with_peers(net.endpoint(2).unwrap());
    let t = TraderKey::from_seed([1; 32]);

    net.partition(vec![[1].into(), [2].into()]);
    a.submit(10, submission(&env, &t, 1)).unwrap();
    b.submit(10, submission(&env, &t, 2)).unwrap();
    assert_eq!((a.absorb_gossip(11), b.absorb_gossip(11)), (0, 0));

    net.heal();
    a.anti_entropy();
    b.anti_entropy();
    assert_eq!((a.absorb_gossip(20), b.absorb_gossip(20)), (1, 1));
    assert_eq!((a.len(), b.len()), (2, 2));
    let sa = a
        .seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO,
        )
        .unwrap();
    // Same set, same root: the second commit is idempotent.
    let sb = b
        .seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO,
        )
        .unwrap();
    assert_eq!(sa.batch.header.batch_root, sb.batch.header.batch_root);

    // A partition that lasts through the cutoff yields different sets. Only
    // the first root to reach the chain is accepted.
    let env2 = Env {
        keys: env.keys.clone(),
        chain: Arc::new(InMemoryChain::new([0x5a; 32])),
    };
    let net2 = Network::new(8);
    let mut c =
        relay(&env2, AckPolicy::Immediate, Padding::None, 7).with_peers(net2.endpoint(1).unwrap());
    let mut d =
        relay(&env2, AckPolicy::Immediate, Padding::None, 8).with_peers(net2.endpoint(2).unwrap());
    net2.partition(vec![[1].into(), [2].into()]);
    c.submit(10, submission(&env2, &t, 3)).unwrap();
    d.submit(10, submission(&env2, &t, 4)).unwrap();
    assert!(
        c.seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO
        )
        .is_ok()
    );
    assert!(matches!(
        d.seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO
        ),
        Err(RelayError::Commit(CommitError::Equivocation))
    ));
}

/// Header v1 differential: on the same cover RNG stream, close and
/// assemble produce the batch the legacy seal produces, apart from the
/// envelope-bound header fields.
#[test]
fn close_assemble_equals_seal() {
    let env = env();
    let t = TraderKey::from_seed([1; 32]);
    let subs: Vec<Submission> = (0..5).map(|n| submission(&env, &t, n)).collect();
    let (balances, prior, prev) = (sheet(&t), prior(), Hash32([0x9e; 32]));
    let seeded = |chain: &Arc<InMemoryChain>| {
        let mut r = Relay::new_seeded(
            config(Padding::PowerOfTwo { min: 8 }),
            relay_key(),
            chain.clone(),
            cover(&env),
            [3; 32],
        );
        r.open_epoch_v2(window(1, 0, 100), Tick(50), PC, BINDING)
            .unwrap();
        for s in &subs {
            r.submit(10, s.clone()).unwrap();
        }
        r
    };

    let sealed = seeded(&env.chain)
        .seal(100, balances.clone(), prior.clone(), prev)
        .unwrap();
    let v1 = sealed.batch.header;

    let untouched = Arc::new(InMemoryChain::new([0x5a; 32]));
    let mut r = seeded(&untouched);
    let closed = r.close(100).unwrap().clone();
    let assembled = closed
        .assemble(v1.beacon, balances.clone(), prior.clone(), prev)
        .unwrap();
    let v2 = assembled.batch.header;

    assert_eq!(assembled.batch.envelopes, sealed.batch.envelopes);
    assert_eq!((assembled.real, assembled.cover), (5, 3));
    assert_eq!((sealed.real, sealed.cover), (5, 3));
    assert_eq!(assembled.batch.balances, sealed.batch.balances);
    assert_eq!(assembled.batch.prior_state, sealed.batch.prior_state);
    assert!(assembled.batch.masked.is_empty() && sealed.batch.masked.is_empty());

    // The header v1 rebuilt from the closed batch is the sealed one.
    let commitments: Vec<OrderCommitment> = closed.envelopes.iter().map(|e| e.commitment).collect();
    let rebuilt = BatchHeader::assemble(
        params(),
        EpochId(1),
        closed.band,
        PC,
        &commitments,
        v1.beacon,
        prior.root(),
        balances.root(),
        prev,
    );
    assert_eq!(rebuilt.to_bytes(), v1.to_bytes());

    // Header v2 differs exactly in the version, the binding and the root.
    assert_eq!((v1.version, v2.version), (1, 2));
    assert_eq!(v2.price_commitment, BINDING);
    assert_eq!(
        v2.batch_root,
        batch_root_v2(&batch_leaves(&sealed.batch.envelopes))
    );
    let mut v2_as_v1 = v2;
    v2_as_v1.version = v1.version;
    v2_as_v1.price_commitment = v1.price_commitment;
    v2_as_v1.batch_root = v1.batch_root;
    assert_eq!(v2_as_v1, v1);
    // Closing commits nothing. The node does.
    assert_eq!(untouched.committed_root(MarketId(1), EpochId(1)), None);
}

/// Counts fresh cover envelopes.
struct Counting {
    inner: EpochKeyCover<LocalKeySchedule>,
    calls: Arc<AtomicUsize>,
}

impl CoverSource for Counting {
    fn cover(
        &self,
        market: MarketId,
        epoch: EpochId,
        rng: &mut ChaCha20Rng,
    ) -> Result<(SealedEnvelope, Option<MaskedIntent>), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.cover(market, epoch, rng)
    }
}

#[test]
fn close_idempotent() {
    let env = env();
    let calls = Arc::new(AtomicUsize::new(0));
    let counting = Box::new(Counting {
        inner: EpochKeyCover {
            keys: env.keys.clone(),
            params: params(),
            masked: false,
        },
        calls: calls.clone(),
    });
    let mut r = Relay::new(config(Padding::Fixed(8)), relay_key(), counting);
    r.open_epoch_v2(window(1, 0, 100), Tick(50), PC, BINDING)
        .unwrap();
    let t = TraderKey::from_seed([1; 32]);
    let subs: Vec<Submission> = (0..3).map(|n| submission(&env, &t, n)).collect();
    let promises: Vec<InclusionPromiseV2> = subs
        .iter()
        .map(|s| r.submit_verified(10, verified(s), W1).unwrap())
        .collect();

    assert!(matches!(
        r.close(99),
        Err(RelayError::Auction(AuctionError::InvalidTransition { .. }))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let first = r.close(100).unwrap().clone();
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    let again = r.close(250).unwrap().clone();
    assert_eq!(again, first, "byte-identical batch");
    assert_eq!(calls.load(Ordering::SeqCst), 5, "cover is drawn once");

    assert_eq!((first.real, first.cover, first.envelopes.len()), (3, 5, 8));
    assert_eq!(first.leaves, batch_leaves(&first.envelopes));
    assert_eq!(first.root, batch_root_v2(&first.leaves));
    assert_eq!(first.submitters[..3], [W1; 3]);
    assert!(first.submitters[3..].iter().all(|w| *w == [0; 32]));
    assert_eq!(
        (
            first.market_address,
            first.epoch,
            first.params,
            first.price_commitment,
            first.binding
        ),
        (MARKET, EpochId(1), params(), PC, BINDING)
    );
    assert_eq!(first.band, params().band(Tick(50)).unwrap());
    assert_eq!((first.opens_at_ms, first.cutoff_ms), (0, 100));
    for (s, p) in subs.iter().zip(&promises) {
        assert_eq!(p.envelope_digest, s.envelope.digest());
        assert!(first.leaves.contains(&p.leaf()));
    }

    // Closed means closed, whatever the clock says.
    let late = submission(&env, &t, 9);
    let closed = RelayError::Auction(AuctionError::InvalidTransition { from: "Closed" });
    assert_eq!(
        r.submit_verified(50, verified(&late), W1),
        Err(closed.clone())
    );
    assert_eq!(r.submit(50, late), Err(closed));
    // Re-delivering an accepted submission still yields its promise.
    assert_eq!(
        r.submit_verified(50, verified(&subs[0]), W1),
        Ok(promises[0])
    );
}

#[test]
fn take_closed_frees_slot() {
    let env = env();
    let mut r = relay_v2(&env, Padding::PowerOfTwo { min: 4 });
    let t = TraderKey::from_seed([1; 32]);
    assert_eq!(r.take_closed(), Err(RelayError::NotClosed));
    // Nothing was taken: the epoch is still open.
    r.submit_verified(10, verified(&submission(&env, &t, 1)), W1)
        .unwrap();

    let closed = r.close(100).unwrap().clone();
    assert_eq!(
        r.open_epoch_v2(window(2, 100, 200), Tick(50), PC, BINDING),
        Err(RelayError::EpochOpen),
        "a closed batch still holds the slot"
    );
    assert_eq!(r.take_closed(), Ok(closed));
    assert_eq!(r.take_closed(), Err(RelayError::NotClosed));
    assert_eq!(r.close(100).unwrap_err(), RelayError::NoEpoch);
    assert!(r.is_empty());

    r.open_epoch_v2(window(2, 100, 200), Tick(51), PC, BINDING)
        .unwrap();
    let p = r
        .submit_verified(150, verified(&submission_for(&env, &t, 2, 2)), W1)
        .unwrap();
    assert_eq!(p.epoch, EpochId(2));
    assert_eq!(r.len(), 1);
}

#[test]
fn open_epoch_refuses_overwrite() {
    let env = env();
    let mut r = relay(&env, AckPolicy::Immediate, Padding::None, 9);
    let t = TraderKey::from_seed([1; 32]);
    r.submit(10, submission(&env, &t, 1)).unwrap();
    assert_eq!(
        r.open_epoch(window(1, 0, 100), Tick(50), Hash32::ZERO),
        Err(RelayError::EpochOpen)
    );
    assert_eq!(
        r.open_epoch(window(2, 100, 200), Tick(60), Hash32::ZERO),
        Err(RelayError::EpochOpen)
    );
    assert_eq!(
        r.open_epoch_v2(window(2, 100, 200), Tick(60), PC, BINDING),
        Err(RelayError::EpochOpen)
    );
    // The open epoch is untouched and keeps accepting.
    assert_eq!(r.len(), 1);
    r.submit(20, submission(&env, &t, 2)).unwrap();
    let sealed = r
        .seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO,
        )
        .unwrap();
    assert_eq!((sealed.real, sealed.batch.header.epoch), (2, EpochId(1)));
    // Sealing consumed the epoch, so the next one opens.
    r.open_epoch(window(2, 100, 200), Tick(60), Hash32::ZERO)
        .unwrap();
}

#[test]
fn open_epoch_checks_its_inputs() {
    let env = env();
    let mut r = Relay::new(config(Padding::None), relay_key(), cover(&env));
    assert_eq!(
        r.open_epoch_v2(window(1, 100, 100), Tick(50), PC, BINDING),
        Err(RelayError::Auction(AuctionError::EmptyWindow {
            opens_at_ms: 100,
            cutoff_ms: 100
        }))
    );
    assert!(matches!(
        r.open_epoch_v2(window(1, 0, 100), Tick(4), PC, BINDING),
        Err(RelayError::Band(_))
    ));
    for p in [-0.1, 1.5, f64::NAN] {
        let mut cfg = config(Padding::None);
        cfg.carry_p = p;
        let mut bad = Relay::new(cfg, relay_key(), cover(&env));
        assert!(matches!(
            bad.open_epoch_v2(window(1, 0, 100), Tick(50), PC, BINDING),
            Err(RelayError::Cover(_))
        ));
    }
    let mut cfg = config(Padding::None);
    cfg.params.max_order_lots_log2 = 0;
    let mut invalid = Relay::new(cfg, relay_key(), cover(&env));
    assert!(matches!(
        invalid.open_epoch_v2(window(1, 0, 100), Tick(50), PC, BINDING),
        Err(RelayError::Band(_))
    ));
    // Refusals leave nothing open.
    r.open_epoch_v2(window(1, 0, 100), Tick(50), PC, BINDING)
        .unwrap();
}

#[test]
fn restore_rederives_promises() {
    let env = env();
    let mut live = relay_v2(&env, Padding::PowerOfTwo { min: 4 });
    let a = TraderKey::from_seed([1; 32]);
    let b = TraderKey::from_seed([2; 32]);
    let accepted = [
        (submission(&env, &a, 1), W1),
        (submission(&env, &a, 2), W1),
        (submission(&env, &b, 3), W2),
    ];
    let promises: Vec<InclusionPromiseV2> = accepted
        .iter()
        .map(|(s, w)| live.submit_verified(10, verified(s), *w).unwrap())
        .collect();

    let snapshot = OpenSnapshot {
        epoch: EpochId(1),
        opens_at_ms: 0,
        cutoff_ms: 100,
        band: params().band(Tick(50)).unwrap(),
        price_commitment: PC,
        binding: BINDING,
        submissions: accepted.iter().map(|(s, w)| (s.to_bytes(), *w)).collect(),
    };
    assert!(snapshot.submissions.iter().all(|(b, _)| b.len() == 386));
    let restore = |s: OpenSnapshot| {
        Relay::restore(
            config(Padding::PowerOfTwo { min: 4 }),
            relay_key(),
            cover(&env),
            s,
        )
    };
    let mut restored = restore(snapshot.clone()).unwrap();
    assert_eq!(restored.len(), 3);
    for ((s, w), p) in accepted.iter().zip(&promises) {
        let again = restored.submit_verified(20, verified(s), *w).unwrap();
        assert_eq!(again, *p);
        assert_eq!(again.signature.0, p.signature.0, "byte for byte");
    }
    // Intake resumes where it stopped.
    restored
        .submit_verified(30, verified(&submission(&env, &b, 4)), W2)
        .unwrap();
    let real = |c: &ClosedBatch| -> BTreeSet<BatchLeaf> {
        c.envelopes
            .iter()
            .zip(&c.submitters)
            .filter(|(_, w)| **w != [0; 32])
            .map(|(e, _)| BatchLeaf::of(e))
            .collect()
    };
    let before = real(live.close(100).unwrap());
    let after = restored.close(100).unwrap();
    assert_eq!(after.real, 4);
    assert!(before.is_subset(&real(after)));

    // A row that no longer verifies fails the restore, naming the row.
    let mut tampered = snapshot.clone();
    tampered.submissions[1].0[330] ^= 1;
    assert!(matches!(
        restore(tampered),
        Err(RelayError::Restore(m)) if m.starts_with("#1:")
    ));
    let mut truncated = snapshot.clone();
    truncated.submissions[0].0.pop();
    assert!(matches!(
        restore(truncated),
        Err(RelayError::Restore(m)) if m.starts_with("#0:")
    ));
    // The same commitment from the same wallet with other bytes.
    let (pi, c) = intent(&a, 1, 1);
    let mut conflicting = snapshot.clone();
    conflicting.submissions.push((
        Submission::sign(&a, seal(&env, 1, c, &pi, 77), None).to_bytes(),
        W1,
    ));
    assert!(matches!(
        restore(conflicting),
        Err(RelayError::Restore(m)) if m.starts_with("#3:")
    ));
    let mut other_band = snapshot.clone();
    other_band.band.hi = Tick(55);
    assert!(matches!(restore(other_band), Err(RelayError::Band(_))));
}

#[test]
fn dedup_per_wallet() {
    let env = env();
    let mut r = relay_v2(&env, Padding::None);
    let a = TraderKey::from_seed([1; 32]);
    let session_b = TraderKey::from_seed([2; 32]);
    let (pi, c) = intent(&a, 1, 1);
    let e1 = seal(&env, 1, c, &pi, 100);
    let e2 = seal(&env, 1, c, &pi, 200);
    assert_ne!(e1.digest(), e2.digest());

    let p1 = r
        .submit_verified(10, verified(&Submission::sign(&a, e1.clone(), None)), W1)
        .unwrap();
    assert_eq!(
        r.submit_verified(11, verified(&Submission::sign(&a, e2.clone(), None)), W1),
        Err(RelayError::DuplicateForSubmitter)
    );
    assert_eq!(
        r.submit_verified(12, verified(&Submission::sign(&a, e1.clone(), None)), W1),
        Ok(p1),
        "identical bytes return the original promise"
    );

    // Another wallet can neither keep W1's envelope out by using its
    // commitment first, nor submit W1's exact envelope as its own.
    let p2 = r
        .submit_verified(
            13,
            verified(&Submission::sign(&session_b, e2.clone(), None)),
            W2,
        )
        .unwrap();
    assert_eq!(p2.commitment, p1.commitment);
    assert_ne!(p2.envelope_digest, p1.envelope_digest);
    let copy = verified(&Submission::sign(&session_b, e1.clone(), None));
    assert_eq!(
        r.submit_verified(14, copy.clone(), W2),
        Err(RelayError::DuplicateForSubmitter)
    );
    assert_eq!(
        r.submit_verified(14, copy, [0xa3; 32]),
        Err(RelayError::Auction(AuctionError::Duplicate)),
        "the same leaf is in the batch once"
    );
    assert_eq!(r.len(), 2);

    let closed = r.close(100).unwrap();
    assert_eq!(closed.envelopes, vec![e1.clone(), e2.clone()]);
    assert_eq!(closed.submitters, vec![W1, W2]);
    assert!(closed.leaves.contains(&p1.leaf()) && closed.leaves.contains(&p2.leaf()));

    // Header v1 intake keeps one envelope per commitment.
    let mut v1 = relay(&env, AckPolicy::Immediate, Padding::None, 11);
    v1.submit(10, Submission::sign(&a, e1, None)).unwrap();
    assert_eq!(
        v1.submit(10, Submission::sign(&session_b, e2, None)),
        Err(RelayError::Auction(AuctionError::Duplicate))
    );
}

#[test]
fn substitution_detected() {
    let env = env();
    let mut r = relay_v2(&env, Padding::PowerOfTwo { min: 4 });
    let a = TraderKey::from_seed([1; 32]);
    let (pi, c) = intent(&a, 1, 1);
    let p = r
        .submit_verified(
            10,
            verified(&Submission::sign(&a, seal(&env, 1, c, &pi, 100), None)),
            W1,
        )
        .unwrap();
    r.submit_verified(10, verified(&submission(&env, &a, 2)), W1)
        .unwrap();
    r.close(100).unwrap();
    let closed = r.take_closed().unwrap();
    let count = closed.real + closed.cover;
    assert!(!prove_exclusion_v2(
        &p,
        &closed.leaves,
        &MARKET,
        EpochId(1),
        &closed.root,
        count
    ));

    // The relay commits another envelope under the trader's commitment.
    let garbage = BatchLeaf::of(&seal(&env, 1, c, &pi, 300));
    let mut swapped: Vec<BatchLeaf> = closed
        .leaves
        .iter()
        .map(|l| if *l == p.leaf() { garbage } else { *l })
        .collect();
    swapped.sort_unstable();
    let root = batch_root_v2(&swapped);
    assert!(swapped.iter().any(|l| l.commitment == p.commitment));
    assert!(prove_exclusion_v2(
        &p,
        &swapped,
        &MARKET,
        EpochId(1),
        &root,
        count
    ));
    // Dropping the envelope is caught the same way.
    let dropped: Vec<BatchLeaf> = closed
        .leaves
        .iter()
        .copied()
        .filter(|l| *l != p.leaf())
        .collect();
    assert!(prove_exclusion_v2(
        &p,
        &dropped,
        &MARKET,
        EpochId(1),
        &batch_root_v2(&dropped),
        count - 1
    ));
    // The leaves must be the committed ones: root and count as on chain.
    assert!(!prove_exclusion_v2(
        &p,
        &swapped,
        &MARKET,
        EpochId(1),
        &closed.root,
        count
    ));
    assert!(!prove_exclusion_v2(
        &p,
        &swapped,
        &MARKET,
        EpochId(1),
        &root,
        count + 1
    ));
    // A promise for the garbage envelope was never signed.
    let mut forged = p;
    forged.envelope_digest = garbage.envelope_digest;
    assert!(!prove_exclusion_v2(
        &forged,
        &closed.leaves,
        &MARKET,
        EpochId(1),
        &closed.root,
        count
    ));
}

#[test]
fn prove_exclusion_v2_wrong_epoch() {
    let env = env();
    let mut r = relay_v2(&env, Padding::None);
    let a = TraderKey::from_seed([1; 32]);
    let p = r
        .submit_verified(10, verified(&submission(&env, &a, 1)), W1)
        .unwrap();
    r.submit_verified(10, verified(&submission(&env, &a, 2)), W1)
        .unwrap();
    r.close(100).unwrap();
    let e1 = r.take_closed().unwrap();
    r.open_epoch_v2(window(2, 100, 200), Tick(50), PC, BINDING)
        .unwrap();
    r.submit_verified(150, verified(&submission_for(&env, &a, 3, 2)), W1)
        .unwrap();
    r.close(200).unwrap();
    let e2 = r.take_closed().unwrap();
    let (n1, n2) = (e1.real + e1.cover, e2.real + e2.cover);

    assert!(!prove_exclusion_v2(
        &p,
        &e1.leaves,
        &MARKET,
        EpochId(1),
        &e1.root,
        n1
    ));
    // Epoch 2's batch lacks the leaf, but the promise is for epoch 1.
    assert!(!e2.leaves.contains(&p.leaf()));
    assert!(!prove_exclusion_v2(
        &p,
        &e2.leaves,
        &MARKET,
        EpochId(2),
        &e2.root,
        n2
    ));
    assert!(!prove_exclusion_v2(
        &p,
        &e1.leaves,
        &[0x4e; 32],
        EpochId(1),
        &e1.root,
        n1
    ));
    // For contrast, the right batch without the leaf is evidence.
    let without: Vec<BatchLeaf> = e1
        .leaves
        .iter()
        .copied()
        .filter(|l| *l != p.leaf())
        .collect();
    assert!(prove_exclusion_v2(
        &p,
        &without,
        &MARKET,
        EpochId(1),
        &batch_root_v2(&without),
        n1 - 1
    ));
}

#[test]
fn cover_rng_not_seeded() {
    let env = env();
    let t = TraderKey::from_seed([1; 32]);
    let subs: Vec<Submission> = (0..3).map(|n| submission(&env, &t, n)).collect();
    let cover_of = |mut r: Relay| -> Vec<OrderCommitment> {
        r.open_epoch_v2(window(1, 0, 100), Tick(50), PC, BINDING)
            .unwrap();
        for s in &subs {
            r.submit_verified(10, verified(s), W1).unwrap();
        }
        let c = r.close(100).unwrap();
        c.envelopes[c.real as usize..]
            .iter()
            .map(|e| e.commitment)
            .collect()
    };
    let os = || Relay::new(config(Padding::Fixed(16)), relay_key(), cover(&env));
    let (x, y) = (cover_of(os()), cover_of(os()));
    assert_eq!((x.len(), y.len()), (13, 13));
    assert!(
        x.iter().all(|c| !y.contains(c)),
        "same inputs, independent cover"
    );

    // What a seeded relay gives away: its cover replays exactly.
    let seeded = || {
        Relay::new_seeded(
            config(Padding::Fixed(16)),
            relay_key(),
            env.chain.clone(),
            cover(&env),
            [7; 32],
        )
    };
    assert_eq!(cover_of(seeded()), cover_of(seeded()));
}

/// Fails the first commit after it landed, as a lost RPC response would.
struct LostResponse {
    chain: InMemoryChain,
    lost: AtomicBool,
}

impl ChainView for LostResponse {
    fn committed_batch(&self, m: MarketId, e: EpochId) -> Option<CommittedBatch> {
        self.chain.committed_batch(m, e)
    }
}

impl BatchCommitter for LostResponse {
    fn commit_root(
        &self,
        m: MarketId,
        e: EpochId,
        root: Hash32,
        count: u32,
    ) -> Result<Hash32, CommitError> {
        let beacon = self.chain.commit_root(m, e, root, count)?;
        if self.lost.swap(true, Ordering::SeqCst) {
            Ok(beacon)
        } else {
            Err(CommitError::Unavailable)
        }
    }
}

/// a retried seal commits the root that already landed
/// instead of padding again and equivocating.
#[test]
fn seal_retry_commits_the_same_root() {
    let env = env();
    let chain = Arc::new(LostResponse {
        chain: InMemoryChain::new([0x5a; 32]),
        lost: AtomicBool::new(false),
    });
    let mut r = Relay::new_seeded(
        config(Padding::PowerOfTwo { min: 8 }),
        relay_key(),
        chain.clone(),
        cover(&env),
        [4; 32],
    );
    r.open_epoch(window(1, 0, 100), Tick(50), Hash32::ZERO)
        .unwrap();
    let t = TraderKey::from_seed([1; 32]);
    r.submit(10, submission(&env, &t, 1)).unwrap();
    let seal = |r: &mut Relay| {
        r.seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO,
        )
    };
    assert!(matches!(
        seal(&mut r),
        Err(RelayError::Commit(CommitError::Unavailable))
    ));
    let landed = chain.committed_root(MarketId(1), EpochId(1)).unwrap();
    let sealed = seal(&mut r).unwrap();
    assert_eq!(sealed.batch.header.batch_root, landed);
    assert_eq!(sealed.batch.envelopes.len(), 8);
}

#[test]
fn header_v2_needs_a_binding_and_no_masked_encodings() {
    let env = env();
    let t = TraderKey::from_seed([1; 32]);
    let mut v1 = relay(&env, AckPolicy::Immediate, Padding::None, 12);
    v1.submit(10, submission(&env, &t, 1)).unwrap();
    assert_eq!(v1.close(100).unwrap_err(), RelayError::Unbound);
    assert_eq!(v1.take_closed(), Err(RelayError::NotClosed));
    assert!(
        v1.seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO
        )
        .is_ok()
    );

    let mut cfg = config(Padding::None);
    cfg.allow_masked = true;
    let mut r = Relay::new(cfg.clone(), relay_key(), cover(&env));
    r.open_epoch_v2(window(1, 0, 100), Tick(50), PC, BINDING)
        .unwrap();
    let plain = submission(&env, &t, 2);
    let masked = MaskedIntent::noop(MarketId(1), EpochId(1), plain.envelope.commitment);
    let with_masked = Submission::sign(&t, plain.envelope, Some(masked));
    let v = verify_submission(&cfg, &with_masked).unwrap();
    assert_eq!(
        r.submit_verified(10, v, W1),
        Err(RelayError::MaskedNotAllowed)
    );
    r.submit(10, with_masked).unwrap();
    assert_eq!(r.close(100).unwrap_err(), RelayError::MaskedNotAllowed);
}

/// CommitBatch refuses `count = 0`, so an idle header v2 epoch closes
/// to one cover envelope whatever the padding. The header v1 path keeps the
/// configured padding.
#[test]
fn idle_v2_epochs_close_to_one_cover_envelope() {
    let env = env();
    for padding in [Padding::None, Padding::Fixed(0)] {
        let mut r = relay_v2(&env, padding);
        let closed = r.close(100).unwrap().clone();
        assert_eq!((closed.real, closed.cover), (0, 1), "{padding:?}");
        assert_eq!(closed.submitters, vec![[0; 32]]);
        assert_eq!(closed.leaves, batch_leaves(&closed.envelopes));
        let assembled = closed
            .assemble(
                Hash32([0xbe; 32]),
                BalanceSheet::default(),
                OrderStateTable::default(),
                Hash32::ZERO,
            )
            .unwrap();
        assert_eq!(assembled.batch.header.envelope_count, 1);
    }

    let mut v1 = relay(&env, AckPolicy::Immediate, Padding::None, 13);
    let sealed = v1
        .seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO,
        )
        .unwrap();
    assert!(sealed.batch.envelopes.is_empty());
}

#[test]
fn verify_submission_checks() {
    let env = env();
    let t = TraderKey::from_seed([1; 32]);
    let other = TraderKey::from_seed([2; 32]);
    let s = submission(&env, &t, 1);
    let ok = verify_submission(&config(Padding::None), &s).unwrap();
    assert_eq!(ok.envelope_digest, s.envelope.digest());
    assert_eq!(ok.submission, s);

    let mut bad = s.clone();
    bad.signature.0[1] ^= 1;
    assert_eq!(
        verify_submission(&config(Padding::None), &bad),
        Err(RelayError::BadSignature)
    );
    let mut other_market = s.envelope.clone();
    other_market.market = MarketId(2);
    assert_eq!(
        verify_submission(
            &config(Padding::None),
            &Submission::sign(&t, other_market, None)
        ),
        Err(RelayError::Auction(AuctionError::WrongMarket {
            expected: MarketId(1),
            got: MarketId(2)
        }))
    );
    let mut v9 = s.envelope.clone();
    v9.version = 9;
    assert_eq!(
        verify_submission(&config(Padding::None), &Submission::sign(&t, v9, None)),
        Err(RelayError::UnsupportedVersion(9))
    );

    // Masked encodings: refused unless allowed, then bound to the envelope
    // and to the signer.
    let c = s.envelope.commitment;
    let cancel = |k: &TraderKey| {
        MaskedIntent::sign(
            k,
            MarketId(1),
            EpochId(1),
            c,
            MaskedBody::Cancel(Cancel {
                market: MarketId(1),
                trader: k.id(),
                nonce: 5,
                target: OrderCommitment([3; 32]),
                epoch: EpochId(1),
            }),
        )
    };
    let with = |m: MaskedIntent| Submission::sign(&t, s.envelope.clone(), Some(m));
    let check = |sub: &Submission, allow: bool| {
        let mut cfg = config(Padding::None);
        cfg.allow_masked = allow;
        verify_submission(&cfg, sub).map(|v| v.envelope_digest)
    };
    assert_eq!(
        check(&with(cancel(&t)), false),
        Err(RelayError::MaskedNotAllowed)
    );
    assert_eq!(check(&with(cancel(&t)), true), Ok(s.envelope.digest()));
    assert_eq!(
        check(&with(MaskedIntent::noop(MarketId(1), EpochId(1), c)), true),
        Ok(s.envelope.digest())
    );
    assert_eq!(
        check(&with(cancel(&other)), true),
        Err(RelayError::Unauthorised)
    );
    let mut forged = cancel(&t);
    forged.signature.0[0] ^= 1;
    assert_eq!(check(&with(forged), true), Err(RelayError::BadSignature));
    let mut elsewhere = cancel(&t);
    elsewhere.epoch = EpochId(2);
    assert_eq!(
        check(&with(elsewhere), true),
        Err(RelayError::EncodingMismatch)
    );
}

#[test]
fn submit_verified_enforces_window_epoch_capacity_and_allowlist() {
    let env = env();
    let t = TraderKey::from_seed([1; 32]);
    let mut none = Relay::new(config(Padding::None), relay_key(), cover(&env));
    assert_eq!(
        none.submit_verified(10, verified(&submission(&env, &t, 1)), W1),
        Err(RelayError::NoEpoch)
    );

    let mut cfg = config(Padding::None);
    cfg.max_real = 2;
    let mut r = Relay::new(cfg, relay_key(), cover(&env));
    r.open_epoch_v2(window(1, 50, 100), Tick(50), PC, BINDING)
        .unwrap();
    assert_eq!(
        r.submit_verified(49, verified(&submission(&env, &t, 1)), W1),
        Err(RelayError::Auction(AuctionError::BeforeOpen))
    );
    assert!(matches!(
        r.submit_verified(100, verified(&submission(&env, &t, 1)), W1),
        Err(RelayError::Auction(AuctionError::AfterCutoff { .. }))
    ));
    assert!(matches!(
        r.submit_verified(60, verified(&submission_for(&env, &t, 1, 2)), W1),
        Err(RelayError::Auction(AuctionError::WrongEpoch { .. }))
    ));
    r.submit_verified(60, verified(&submission(&env, &t, 1)), W1)
        .unwrap();
    r.submit_verified(60, verified(&submission(&env, &t, 2)), W1)
        .unwrap();
    assert_eq!(
        r.submit_verified(60, verified(&submission(&env, &t, 3)), W1),
        Err(RelayError::Auction(AuctionError::Full))
    );

    let mut gated = relay_v2(&env, Padding::None);
    let mut reg = Registry::default();
    reg.insert(TraderId(W2), ());
    gated.set_allowlist(Some(reg));
    assert_eq!(
        gated.submit_verified(10, verified(&submission(&env, &t, 1)), W1),
        Err(RelayError::Unauthorised)
    );
    // The allowlist names wallets, not the session key that signed.
    gated
        .submit_verified(10, verified(&submission(&env, &t, 1)), W2)
        .unwrap();
}

/// `VerifiedSubmission` has public fields. A digest that is not its
/// envelope's would make the relay promise a leaf it never includes.
#[test]
fn submit_verified_refuses_a_digest_that_is_not_the_envelopes() {
    let env = env();
    let mut r = relay_v2(&env, Padding::None);
    let t = TraderKey::from_seed([1; 32]);
    let mut v = verified(&submission(&env, &t, 1));
    v.envelope_digest.0[0] ^= 1;
    assert_eq!(
        r.submit_verified(10, v.clone(), W1),
        Err(RelayError::DigestMismatch)
    );
    assert!(r.is_empty());

    v.envelope_digest.0[0] ^= 1;
    let p = r.submit_verified(10, v.clone(), W1).unwrap();
    assert_eq!(p.envelope_digest, v.submission.envelope.digest());
    // A re-delivery carrying another digest is not taken for the original.
    v.envelope_digest.0[1] ^= 1;
    assert_eq!(
        r.submit_verified(11, v, W1),
        Err(RelayError::DigestMismatch)
    );
}

#[test]
fn assemble_checks_the_closed_batch() {
    let env = env();
    let mut r = relay_v2(&env, Padding::PowerOfTwo { min: 4 });
    let t = TraderKey::from_seed([1; 32]);
    r.submit_verified(10, verified(&submission(&env, &t, 1)), W1)
        .unwrap();
    r.close(100).unwrap();
    let closed = r.take_closed().unwrap();
    let beacon = Hash32([0xbe; 32]);
    let assemble = |c: &ClosedBatch| c.assemble(beacon, sheet(&t), prior(), Hash32([0x9e; 32]));

    let ok = assemble(&closed).unwrap();
    let h = ok.batch.header;
    assert_eq!(h.version, HEADER_VERSION_ENVELOPE_BOUND);
    assert_eq!(&h.to_bytes()[87..119], BINDING.as_bytes());
    assert_eq!(
        (h.epoch, h.envelope_count, h.batch_root, h.beacon),
        (EpochId(1), 4, closed.root, beacon)
    );
    assert_eq!(
        (h.prior_state_root, h.balances_root, h.prev_receipt),
        (prior().root(), sheet(&t).root(), Hash32([0x9e; 32]))
    );
    assert_eq!(
        terms_digest(&h.band, &h.price_commitment),
        terms_digest(&params().band(Tick(50)).unwrap(), &BINDING)
    );
    assert_eq!(ok.batch.envelopes, closed.envelopes);
    assert!(ok.batch.masked.is_empty() && ok.promises.is_empty());
    assert_eq!((ok.real, ok.cover), (1, 3));

    let mismatch = RelayError::Auction(AuctionError::HeaderMismatch);
    let mut swapped = closed.clone();
    swapped.envelopes[0] = submission(&env, &t, 2).envelope;
    assert_eq!(assemble(&swapped).unwrap_err(), mismatch);
    let mut root = closed.clone();
    root.root.0[0] ^= 1;
    assert_eq!(assemble(&root).unwrap_err(), mismatch);
    let mut leaves = closed.clone();
    leaves.leaves.pop();
    assert_eq!(assemble(&leaves).unwrap_err(), mismatch);
    let mut counts = closed.clone();
    counts.cover += 1;
    assert_eq!(assemble(&counts).unwrap_err(), mismatch);
    let mut submitters = closed.clone();
    submitters.submitters.pop();
    assert_eq!(assemble(&submitters).unwrap_err(), mismatch);
    let mut band = closed.clone();
    band.band.lo = Tick(1);
    assert!(matches!(assemble(&band), Err(RelayError::Band(_))));
    let mut epoch = closed.clone();
    epoch.epoch = EpochId(2);
    assert!(matches!(
        assemble(&epoch),
        Err(RelayError::Auction(AuctionError::WrongEpoch { .. }))
    ));
}

/// Persisted params are not validated by decoding. Deriving a band from
/// `max_order_lots_log2 = 64` would shift a u64 by 64, so restore and
/// assemble validate first and refuse.
#[test]
fn invalid_params_are_refused_before_a_band_is_derived() {
    let env = env();
    let mut cfg = config(Padding::None);
    cfg.params.max_order_lots_log2 = 64;
    let snapshot = OpenSnapshot {
        epoch: EpochId(1),
        opens_at_ms: 0,
        cutoff_ms: 100,
        band: params().band(Tick(50)).unwrap(),
        price_commitment: PC,
        binding: BINDING,
        submissions: Vec::new(),
    };
    assert!(matches!(
        Relay::restore(cfg, relay_key(), cover(&env), snapshot),
        Err(RelayError::Band(_))
    ));

    let mut r = relay_v2(&env, Padding::Fixed(2));
    r.close(100).unwrap();
    let mut closed = r.take_closed().unwrap();
    closed.params.max_order_lots_log2 = 64;
    assert!(matches!(
        closed.assemble(
            Hash32([0xbe; 32]),
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO
        ),
        Err(RelayError::Band(_))
    ));
}

#[test]
fn refusals_are_signed_over_the_wire_layout() {
    let env = env();
    let r = relay_v2(&env, Padding::None);
    let d = Hash32([0xd0; 32]);
    let refusal = r.refusal(EpochId(3), d, 2, 123_456);
    assert_eq!(
        (
            refusal.market,
            refusal.epoch,
            refusal.envelope_digest,
            refusal.code,
            refusal.at_ms,
            refusal.relay
        ),
        (MARKET, EpochId(3), d, 2, 123_456, r.public_key())
    );
    // The signature covers the 113 bytes before it.
    let mut bytes = MARKET.to_vec();
    bytes.extend_from_slice(&3u64.to_le_bytes());
    bytes.extend_from_slice(d.as_bytes());
    bytes.push(2);
    bytes.extend_from_slice(&123_456u64.to_le_bytes());
    bytes.extend_from_slice(&r.public_key());
    assert_eq!(bytes.len(), 113);
    let digest = timescales_core::crypto::hash(domain::RELAY_REFUSAL, &bytes);
    assert!(verify_digest(&refusal.relay, &digest, &refusal.signature).is_ok());
    // Computed independently (Python hashlib) for a fixed relay key.
    let fixed = RelayRefusal {
        relay: [0xee; 32],
        ..refusal
    };
    assert_eq!(
        refusal_digest(&fixed).to_hex(),
        "877e3d7e12cf7362f285a40afaa897eee788f2003cfe774d4173fbd49d60064a"
    );
    let mut other = refusal;
    other.code = 3;
    assert!(verify_digest(&other.relay, &refusal_digest(&other), &other.signature).is_err());
}

#[test]
fn promise_digests_match_the_reference_values() {
    let c = OrderCommitment([0xc0; 32]);
    let d = Hash32([0xd0; 32]);
    // Computed independently (Python hashlib) from the wire layouts.
    assert_eq!(
        InclusionPromiseV2::digest(&MARKET, EpochId(1), &c, &d).to_hex(),
        "52eb0d3e8fa3907bf5998e7d839a8d2e785a21c3359e8e7d8e697edad93683ed"
    );
    assert_eq!(
        InclusionPromise::digest(MarketId(1), EpochId(1), &c).to_hex(),
        "4be882b71008c4eb39b1d346839b11488fe3b9764d2a0a5896800434e4d53a61"
    );

    let key = Keypair::from_seed([0x7e; 32]);
    let p = InclusionPromiseV2::sign(&key, MARKET, EpochId(1), c, d);
    assert!(p.verify());
    assert_eq!((p.relay, p.market), (key.public(), MARKET));
    assert_eq!(
        p.leaf(),
        BatchLeaf {
            commitment: c,
            envelope_digest: d
        }
    );
    let tweaks: [fn(&mut InclusionPromiseV2); 5] = [
        |p| p.market[0] ^= 1,
        |p| p.epoch = EpochId(2),
        |p| p.commitment.0[0] ^= 1,
        |p| p.envelope_digest.0[0] ^= 1,
        |p| p.relay = Keypair::from_seed([1; 32]).public(),
    ];
    for tweak in tweaks {
        let mut q = p;
        tweak(&mut q);
        assert!(!q.verify());
    }
}

#[test]
fn closing_moves_to_a_blocking_thread() {
    fn send<T: Send>() {}
    send::<Relay>();
    send::<ClosedBatch>();

    let env = env();
    let mut r = relay_v2(&env, Padding::Fixed(4));
    let closed = std::thread::spawn(move || r.close(100).cloned())
        .join()
        .unwrap()
        .unwrap();
    assert_eq!(closed.envelopes.len(), 4);
}

/// Every `RelayError` variant, and every `CommitError` variant the
/// relay passes on, comes out of a relay path below. The matches have no
/// wildcard arm, so a new variant does not compile until it is named here,
/// and the comparison then fails until a case produces it.
#[test]
fn every_error_variant_is_produced() {
    fn relay_variant(e: &RelayError) -> &'static str {
        match e {
            RelayError::Unauthorised => "Unauthorised",
            RelayError::BadSignature => "BadSignature",
            RelayError::EncodingMismatch => "EncodingMismatch",
            RelayError::NoEpoch => "NoEpoch",
            RelayError::Auction(_) => "Auction",
            RelayError::Commit(_) => "Commit",
            RelayError::Band(_) => "Band",
            RelayError::Cover(_) => "Cover",
            RelayError::MaskedNotAllowed => "MaskedNotAllowed",
            RelayError::EpochOpen => "EpochOpen",
            RelayError::DuplicateForSubmitter => "DuplicateForSubmitter",
            RelayError::NotClosed => "NotClosed",
            RelayError::Restore(_) => "Restore",
            RelayError::UnsupportedVersion(_) => "UnsupportedVersion",
            RelayError::Unbound => "Unbound",
            RelayError::DigestMismatch => "DigestMismatch",
        }
    }
    const RELAY: [&str; 16] = [
        "Unauthorised",
        "BadSignature",
        "EncodingMismatch",
        "NoEpoch",
        "Auction",
        "Commit",
        "Band",
        "Cover",
        "MaskedNotAllowed",
        "EpochOpen",
        "DuplicateForSubmitter",
        "NotClosed",
        "Restore",
        "UnsupportedVersion",
        "Unbound",
        "DigestMismatch",
    ];
    fn commit_variant(e: &CommitError) -> &'static str {
        match e {
            CommitError::Equivocation => "Equivocation",
            CommitError::OutOfOrder => "OutOfOrder",
            CommitError::Unavailable => "Unavailable",
        }
    }
    const COMMIT: [&str; 3] = ["Equivocation", "OutOfOrder", "Unavailable"];

    // `shared` and `later` are separate chains for the commit failures.
    let (env, shared, later) = (env(), env(), env());
    let t = TraderKey::from_seed([1; 32]);
    let s = submission(&env, &t, 1);
    let plain = config(Padding::None);
    let mut masked_ok = config(Padding::None);
    masked_ok.allow_masked = true;
    let mut errors = Vec::new();

    // Stateless intake checks.
    let mut forged = s.clone();
    forged.signature.0[0] ^= 1;
    errors.push(verify_submission(&plain, &forged).unwrap_err());
    let noop = |epoch| MaskedIntent::noop(MarketId(1), EpochId(epoch), s.envelope.commitment);
    let with_masked = |epoch| Submission::sign(&t, s.envelope.clone(), Some(noop(epoch)));
    errors.push(verify_submission(&plain, &with_masked(1)).unwrap_err());
    errors.push(verify_submission(&masked_ok, &with_masked(2)).unwrap_err());
    let mut v9 = s.envelope.clone();
    v9.version = 9;
    errors.push(verify_submission(&plain, &Submission::sign(&t, v9, None)).unwrap_err());

    // Opening.
    let mut r = relay_v2(&env, Padding::None);
    errors.push(
        r.open_epoch_v2(window(2, 100, 200), Tick(50), PC, BINDING)
            .unwrap_err(),
    );
    let mut fresh = Relay::new(plain.clone(), relay_key(), cover(&env));
    errors.push(
        fresh
            .open_epoch_v2(window(1, 0, 100), Tick(4), PC, BINDING)
            .unwrap_err(),
    );
    let mut bad_carry = plain.clone();
    bad_carry.carry_p = 1.5;
    errors.push(
        Relay::new(bad_carry, relay_key(), cover(&env))
            .open_epoch_v2(window(1, 0, 100), Tick(50), PC, BINDING)
            .unwrap_err(),
    );

    // Intake.
    errors.push(fresh.submit_verified(10, verified(&s), W1).unwrap_err());
    errors.push(fresh.take_closed().unwrap_err());
    let mut wrong_digest = verified(&s);
    wrong_digest.envelope_digest.0[0] ^= 1;
    errors.push(r.submit_verified(10, wrong_digest, W1).unwrap_err());
    errors.push(r.submit_verified(100, verified(&s), W1).unwrap_err());
    r.submit_verified(10, verified(&s), W1).unwrap();
    let (pi, c) = intent(&t, 1, 1);
    let resealed = Submission::sign(&t, seal(&env, 1, c, &pi, 99), None);
    errors.push(r.submit_verified(10, verified(&resealed), W1).unwrap_err());
    let mut gated = relay_v2(&env, Padding::None);
    let mut wallets = Registry::default();
    wallets.insert(TraderId(W2), ());
    gated.set_allowlist(Some(wallets));
    errors.push(gated.submit_verified(10, verified(&s), W1).unwrap_err());

    // Restore.
    let mut row = s.to_bytes();
    row[330] ^= 1;
    let snapshot = OpenSnapshot {
        epoch: EpochId(1),
        opens_at_ms: 0,
        cutoff_ms: 100,
        band: params().band(Tick(50)).unwrap(),
        price_commitment: PC,
        binding: BINDING,
        submissions: vec![(row, W1)],
    };
    errors.push(Relay::restore(plain.clone(), relay_key(), cover(&env), snapshot).unwrap_err());

    // Closing an epoch opened for header v1, and the v1 commit path.
    fresh
        .open_epoch(window(1, 0, 100), Tick(50), Hash32::ZERO)
        .unwrap();
    errors.push(fresh.close(100).unwrap_err());
    let seal_v1 = |r: &mut Relay| {
        r.seal(
            100,
            BalanceSheet::default(),
            OrderStateTable::default(),
            Hash32::ZERO,
        )
    };
    errors.push(seal_v1(&mut fresh).unwrap_err());
    let mut first = relay(&shared, AckPolicy::Immediate, Padding::None, 14);
    let mut second = relay(&shared, AckPolicy::Immediate, Padding::None, 15);
    first.submit(10, submission(&shared, &t, 2)).unwrap();
    second.submit(10, submission(&shared, &t, 3)).unwrap();
    seal_v1(&mut first).unwrap();
    errors.push(seal_v1(&mut second).unwrap_err());
    assert!(
        later
            .chain
            .commit(MarketId(1), EpochId(2), Hash32([2; 32]), 1)
    );
    let mut behind = relay(&later, AckPolicy::Immediate, Padding::None, 16);
    errors.push(seal_v1(&mut behind).unwrap_err());

    let produced: BTreeSet<&str> = errors.iter().map(relay_variant).collect();
    assert_eq!(produced, RELAY.into_iter().collect::<BTreeSet<_>>());
    let commits: BTreeSet<&str> = errors
        .iter()
        .filter_map(|e| match e {
            RelayError::Commit(c) => Some(commit_variant(c)),
            _ => None,
        })
        .collect();
    assert_eq!(commits, COMMIT.into_iter().collect::<BTreeSet<_>>());
}
