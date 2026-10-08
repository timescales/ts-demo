// Floats only format timings for display.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_possible_truncation,
    clippy::unwrap_used
)]

//! Micro-benchmarks for the hot paths (criterion).

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use rand::SeedableRng;
use timescales_auction::clearing::{Curves, clear};
use timescales_auction::matching::match_book;
use timescales_auction::orderbook::BookOrder;
use timescales_core::crypto::SealSecret;
use timescales_core::merkle::MerkleTree;
use timescales_core::*;
use timescales_executor::LocalKeySchedule;
use timescales_executor::mpc::{Engine, Fp, LtCircuit};
use timescales_executor::workload::{WorkloadConfig, default_params, generate};

fn book(n: usize, k: u32) -> (PriceBand, Vec<BookOrder>) {
    use rand::Rng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
    let band = PriceBand {
        lo: Tick(1000),
        hi: Tick(1000 + u64::from(k) - 1),
        reference: Tick(1000 + u64::from(k / 2)),
    };
    let orders = (0..n)
        .map(|i| BookOrder {
            commitment: OrderCommitment([u8::try_from(i % 256).unwrap_or(0); 32]),
            trader: TraderId([u8::try_from(i % 200).unwrap_or(0); 32]),
            side: if rng.gen_bool(0.5) {
                Side::Buy
            } else {
                Side::Sell
            },
            role: Role::Taker,
            slot: Some(rng.gen_range(0..k)),
            quantity: Lots(rng.gen_range(1..100)),
        })
        .collect();
    (band, orders)
}

fn matching(c: &mut Criterion) {
    let mut g = c.benchmark_group("match_book");
    for n in [1_000usize, 10_000, 100_000] {
        let (band, orders) = book(n, 65);
        g.bench_with_input(BenchmarkId::from_parameter(n), &orders, |b, o| {
            b.iter(|| match_book(&band, Rationing::Lottery, black_box(o)))
        });
    }
    g.finish();
    let (band, orders) = book(10_000, 65);
    c.bench_function("clear_curves_10k", |b| {
        b.iter(|| {
            let cv =
                Curves::build(65, orders.iter().map(|o| (o.side, o.slot, o.quantity.0))).unwrap();
            clear(&cv, &band)
        })
    });
}

fn envelopes(c: &mut Criterion) {
    let keys = LocalKeySchedule::new([1; 32]);
    let w = generate(
        &WorkloadConfig::new(
            default_params(FlowMode::DualFlow, CommitmentScheme::Sha256),
            64,
            1,
        ),
        &keys,
    );
    let sk: SealSecret =
        timescales_executor::KeyProvider::epoch_secret(&keys, MarketId(1), EpochId(1)).unwrap();
    let env = w.batch.envelopes[0].clone();
    c.bench_function("envelope_open", |b| {
        b.iter(|| black_box(&env).open(&sk, CommitmentScheme::Sha256))
    });
    let leaves: Vec<Vec<u8>> = (0..10_000u64).map(|i| i.to_le_bytes().to_vec()).collect();
    c.bench_function("merkle_root_10k", |b| {
        b.iter(|| MerkleTree::from_data(black_box(&leaves)).root())
    });
}

fn mpc(c: &mut Criterion) {
    let mut g = c.benchmark_group("mpc_ge_1k");
    for circuit in [LtCircuit::Ripple, LtCircuit::LogDepth] {
        g.bench_function(format!("{circuit:?}"), |b| {
            b.iter(|| {
                let mut e = Engine::new(3, true, circuit, 1);
                let t = TraderId([0; 32]);
                let (off, m) = e.dealer().input_masks(t, 2000);
                let s = e.dealer().take_masks(&t, off, 2000).unwrap();
                let d: Vec<Fp> = (0..2000u64)
                    .zip(&m)
                    .map(|(x, r)| Fp::from_u64(x * 7919 % 1_000_003) - *r)
                    .collect();
                let x = e.add_public(&s, &d);
                let (a, bb) = (x.slice(0, 1000), x.slice(1000, 1000));
                e.ge(&a, &bb, 42).unwrap()
            })
        });
    }
    g.finish();
}

fn poseidon(c: &mut Criterion) {
    let o = Order {
        market: MarketId(1),
        trader: TraderId([3; 32]),
        nonce: 1,
        side: Side::Buy,
        role: Role::Taker,
        kind: OrderKind::Limit,
        limit: Tick(100),
        quantity: Lots(5),
        valid_from: EpochId(1),
        expires_at: EpochId(1),
    };
    let salt = timescales_core::commitment::Salt([9; 32]);
    c.bench_function("commit_sha256", |b| {
        b.iter(|| timescales_core::commitment::commit_sha256(black_box(&o), &salt))
    });
    c.bench_function("commit_poseidon", |b| {
        b.iter(|| timescales_core::commitment::poseidon::commit(black_box(&o), &salt))
    });
}

criterion_group!(benches, matching, envelopes, mpc, poseidon);
criterion_main!(benches);
