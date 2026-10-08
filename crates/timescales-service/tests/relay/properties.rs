//! Randomized model checks of the relay: close then assemble equals
//! the legacy seal on the same RNG stream, repeated closes are identical,
//! intake deduplicates on (commitment, wallet) and on the leaf, and
//! exclusion evidence catches every omission and substitution. Each check
//! runs a fixed set of seeded cases, so failures reproduce.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use timescales_auction::collateral::BalanceSheet;
use timescales_auction::orderbook::OrderStateTable;
use timescales_auction::{
    AuctionEpoch, AuctionError, BatchHeader, BatchLeaf, InMemoryChain, batch_root_v2,
};
use timescales_core::crypto::Keypair;
use timescales_core::identity::TraderKey;
use timescales_core::intent::{PrivateIntent, SealedEnvelope};
use timescales_core::{
    CommitmentScheme, EpochId, FeeBps, FlowMode, Hash32, Lots, MarketId, MarketParams, Order,
    OrderCommitment, OrderKind, Rationing, Role, Side, Tick,
};
use timescales_executor::{KeyProvider, LocalKeySchedule};
use timescales_service::relay::{
    ClosedBatch, EpochKeyCover, InclusionPromiseV2, Padding, Relay, RelayConfig, RelayError,
    Submission, VerifiedSubmission, prove_exclusion_v2, verify_submission,
};

const CASES: u64 = 24;
const MARKET: [u8; 32] = [0x4d; 32];
const BINDING: Hash32 = Hash32([0xb1; 32]);

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

fn config(padding: Padding) -> RelayConfig {
    RelayConfig {
        params: params(),
        market_address: MARKET,
        padding,
        allow_masked: false,
        max_real: 1024,
        carry_p: 0.0,
    }
}

struct World {
    keys: Arc<LocalKeySchedule>,
    traders: Vec<TraderKey>,
}

impl World {
    fn new() -> Self {
        Self {
            keys: Arc::new(LocalKeySchedule::new([9; 32])),
            traders: (1..=3u8).map(|i| TraderKey::from_seed([i; 32])).collect(),
        }
    }

    fn cover(&self) -> Box<EpochKeyCover<LocalKeySchedule>> {
        Box::new(EpochKeyCover {
            keys: self.keys.clone(),
            params: params(),
            masked: false,
        })
    }

    /// A placement by trader `t` for epoch 1.
    fn intent(&self, t: usize, nonce: u64) -> (PrivateIntent, OrderCommitment) {
        let trader = &self.traders[t];
        let mut rng = ChaCha20Rng::seed_from_u64(nonce);
        let o = Order {
            market: MarketId(1),
            trader: trader.id(),
            nonce,
            side: if nonce.is_multiple_of(2) {
                Side::Buy
            } else {
                Side::Sell
            },
            role: Role::Taker,
            kind: OrderKind::Limit,
            limit: Tick(50),
            quantity: Lots(1 + nonce % 5),
            valid_from: EpochId(1),
            expires_at: EpochId(1),
        };
        PrivateIntent::place(&mut rng, trader, CommitmentScheme::Sha256, o).unwrap()
    }

    fn seal(&self, c: OrderCommitment, pi: &PrivateIntent, seed: u64) -> SealedEnvelope {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let pk = self.keys.epoch_public(MarketId(1), EpochId(1)).unwrap();
        SealedEnvelope::seal(&mut rng, MarketId(1), EpochId(1), &pk, c, pi).unwrap()
    }

    fn submission(&self, t: usize, nonce: u64, seal_seed: u64) -> Submission {
        let (pi, c) = self.intent(t, nonce);
        Submission::sign(&self.traders[t], self.seal(c, &pi, seal_seed), None)
    }
}

fn verified(s: &Submission) -> VerifiedSubmission {
    verify_submission(&config(Padding::None), s).unwrap()
}

fn window() -> AuctionEpoch {
    AuctionEpoch {
        epoch: EpochId(1),
        opens_at_ms: 0,
        cutoff_ms: 100,
    }
}

fn random_padding(rng: &mut ChaCha20Rng, real: usize) -> Padding {
    match rng.gen_range(0..3) {
        0 => Padding::None,
        1 => Padding::PowerOfTwo {
            min: rng.gen_range(1..20),
        },
        _ => Padding::Fixed(real as u32 + rng.gen_range(0..10)),
    }
}

#[test]
fn close_then_assemble_equals_seal_on_the_same_stream() {
    let w = World::new();
    for case in 0..CASES {
        let mut rng = ChaCha20Rng::seed_from_u64(case);
        let real = rng.gen_range(0..12usize);
        let subs: Vec<Submission> = (0..real)
            .map(|i| w.submission(rng.gen_range(0..3), 1_000 * case + i as u64, rng.r#gen()))
            .collect();
        let padding = random_padding(&mut rng, real);
        let seed: [u8; 32] = rng.r#gen();
        let prev = Hash32(rng.r#gen());
        let relay = |chain: Arc<InMemoryChain>| {
            let mut r = Relay::new_seeded(
                config(padding),
                Arc::new(Keypair::from_seed([0x7e; 32])),
                chain,
                w.cover(),
                seed,
            );
            r.open_epoch_v2(window(), Tick(50), Hash32([0xc1; 32]), BINDING)
                .unwrap();
            for s in &subs {
                r.submit(10, s.clone()).unwrap();
            }
            r
        };

        let sealed = relay(Arc::new(InMemoryChain::new([0x5a; 32])))
            .seal(
                100,
                BalanceSheet::default(),
                OrderStateTable::default(),
                prev,
            )
            .unwrap();
        let mut r = relay(Arc::new(InMemoryChain::new([0x5a; 32])));
        let closed = r.close(100).unwrap().clone();
        assert_eq!(
            &closed,
            r.close(100 + rng.gen_range(0..1_000)).unwrap(),
            "case {case}: repeated close"
        );
        let v1 = sealed.batch.header;
        let assembled = closed
            .assemble(
                v1.beacon,
                BalanceSheet::default(),
                OrderStateTable::default(),
                prev,
            )
            .unwrap();

        assert_eq!(
            assembled.batch.envelopes, sealed.batch.envelopes,
            "case {case}"
        );
        assert_eq!(
            (assembled.real, assembled.cover),
            (sealed.real, sealed.cover)
        );
        assert_eq!(assembled.real, real);
        // An epoch opened for header v2 never closes empty.
        assert_eq!(
            assembled.batch.envelopes.len(),
            padding.target(real).max(1),
            "case {case}"
        );
        let commitments: Vec<OrderCommitment> =
            closed.envelopes.iter().map(|e| e.commitment).collect();
        let rebuilt = BatchHeader::assemble(
            params(),
            EpochId(1),
            closed.band,
            Hash32([0xc1; 32]),
            &commitments,
            v1.beacon,
            OrderStateTable::default().root(),
            BalanceSheet::default().root(),
            prev,
        );
        assert_eq!(rebuilt, v1, "case {case}");
        let mut v2 = assembled.batch.header;
        assert_eq!((v2.version, v2.price_commitment), (2, BINDING));
        assert_eq!(v2.batch_root, closed.root);
        v2.version = v1.version;
        v2.price_commitment = v1.price_commitment;
        v2.batch_root = v1.batch_root;
        assert_eq!(v2, v1, "case {case}");
    }
}

/// The relay against a model of the intake rules.
#[test]
fn intake_dedups_on_commitment_and_wallet() {
    let w = World::new();
    let wallets = [[0xa1; 32], [0xa2; 32], [0xa3; 32]];
    for case in 0..CASES {
        let mut rng = ChaCha20Rng::seed_from_u64(100 + case);
        // Three orders, each sealed three ways.
        let intents: Vec<(PrivateIntent, OrderCommitment)> = (0..3)
            .map(|i| w.intent(i, 7_000 * case + i as u64))
            .collect();
        let envelopes: Vec<Vec<SealedEnvelope>> = intents
            .iter()
            .map(|(pi, c)| (0..3).map(|k| w.seal(*c, pi, 31 * case + k)).collect())
            .collect();
        let mut r = Relay::new(
            config(Padding::None),
            Arc::new(Keypair::from_seed([0x7e; 32])),
            w.cover(),
        );
        r.open_epoch_v2(window(), Tick(50), Hash32::ZERO, BINDING)
            .unwrap();

        let mut by_wallet: BTreeMap<(OrderCommitment, [u8; 32]), InclusionPromiseV2> =
            BTreeMap::new();
        let mut leaves: BTreeSet<BatchLeaf> = BTreeSet::new();
        for _ in 0..30 {
            let (i, k, wi) = (
                rng.gen_range(0..3),
                rng.gen_range(0..3),
                rng.gen_range(0..3),
            );
            let env = envelopes[i][k].clone();
            let leaf = BatchLeaf::of(&env);
            // Any session key may carry the envelope. The wallet is what counts.
            let signer = &w.traders[rng.gen_range(0..3)];
            let got = r.submit_verified(
                10,
                verified(&Submission::sign(signer, env, None)),
                wallets[wi],
            );
            let key = (leaf.commitment, wallets[wi]);
            match by_wallet.get(&key) {
                Some(p) if p.leaf() == leaf => assert_eq!(got, Ok(*p)),
                Some(_) => assert_eq!(got, Err(RelayError::DuplicateForSubmitter)),
                None if leaves.contains(&leaf) => {
                    assert_eq!(got, Err(RelayError::Auction(AuctionError::Duplicate)))
                }
                None => {
                    let p = got.unwrap();
                    assert!(p.verify());
                    assert_eq!(p.leaf(), leaf);
                    by_wallet.insert(key, p);
                    leaves.insert(leaf);
                }
            }
        }

        let closed = r.close(100).unwrap();
        assert_eq!(
            closed.leaves,
            leaves.iter().copied().collect::<Vec<_>>(),
            "case {case}"
        );
        for ((c, wallet), p) in &by_wallet {
            let at = closed
                .envelopes
                .iter()
                .position(|e| BatchLeaf::of(e) == p.leaf())
                .unwrap();
            assert_eq!(
                (closed.envelopes[at].commitment, closed.submitters[at]),
                (*c, *wallet)
            );
        }
    }
}

/// Every accepted envelope's promise is evidence against any committed set
/// that lacks its exact leaf, and against nothing else.
#[test]
fn evidence_catches_every_omission_and_substitution() {
    let w = World::new();
    for case in 0..CASES {
        let mut rng = ChaCha20Rng::seed_from_u64(200 + case);
        let mut r = Relay::new(
            config(Padding::PowerOfTwo { min: 4 }),
            Arc::new(Keypair::from_seed([0x7e; 32])),
            w.cover(),
        );
        r.open_epoch_v2(window(), Tick(50), Hash32::ZERO, BINDING)
            .unwrap();
        let n = rng.gen_range(1..8usize);
        let accepted: Vec<(InclusionPromiseV2, PrivateIntent)> = (0..n)
            .map(|i| {
                let t = rng.gen_range(0..3);
                let (pi, c) = w.intent(t, 9_000 * case + i as u64);
                let s = Submission::sign(&w.traders[t], w.seal(c, &pi, rng.r#gen()), None);
                (r.submit_verified(10, verified(&s), [0xa1; 32]).unwrap(), pi)
            })
            .collect();
        r.close(100).unwrap();
        let closed: ClosedBatch = r.take_closed().unwrap();
        let count = closed.real + closed.cover;
        let evidence = |p: &InclusionPromiseV2, leaves: &[BatchLeaf], epoch: u64| {
            prove_exclusion_v2(
                p,
                leaves,
                &MARKET,
                EpochId(epoch),
                &batch_root_v2(leaves),
                leaves.len() as u32,
            )
        };

        for (p, pi) in &accepted {
            assert!(!prove_exclusion_v2(
                p,
                &closed.leaves,
                &MARKET,
                EpochId(1),
                &closed.root,
                count
            ));
            let omitted: Vec<BatchLeaf> = closed
                .leaves
                .iter()
                .copied()
                .filter(|l| *l != p.leaf())
                .collect();
            assert!(evidence(p, &omitted, 1), "case {case}: omission");
            assert!(!evidence(p, &omitted, 2), "case {case}: other epoch");
            let substitute = BatchLeaf::of(&w.seal(p.commitment, pi, rng.r#gen()));
            let substituted: Vec<BatchLeaf> = closed
                .leaves
                .iter()
                .map(|l| if *l == p.leaf() { substitute } else { *l })
                .collect();
            assert!(evidence(p, &substituted, 1), "case {case}: substitution");
        }
    }
}
