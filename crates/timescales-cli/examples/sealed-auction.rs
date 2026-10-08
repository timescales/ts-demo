// Floats only format timings for display.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_possible_truncation,
    clippy::unwrap_used
)]

//! Sealed-bid issuance: one seller (the issuer) offers a fixed size at a
//! reserve price. Bidders submit sealed limit bids. The batch clears at a
//! single price, bids above it fill completely, bids at it share the rest
//! pro rata, and bids below it are never revealed.

use std::sync::Arc;

use anyhow::{Result, ensure};
use rand::SeedableRng;
use timescales_auction::collateral::{Balance, BalanceSheet};
use timescales_auction::orderbook::OrderStateTable;
use timescales_core::identity::{ExecutorKey, TraderKey};
use timescales_core::intent::{PrivateIntent, SealedEnvelope};
use timescales_core::*;
use timescales_executor::workload::{beacon, build_batch, default_params};
use timescales_executor::{ConfidentialExecutor, KeyProvider, LocalKeySchedule, ReferenceExecutor};

#[tokio::main]
async fn main() -> Result<()> {
    let mut params = default_params(FlowMode::SingleBook, CommitmentScheme::Sha256);
    params.band_half_width = 10;
    params.rationing = Rationing::ProRata;
    let epoch = EpochId(1);
    let reference = Tick(100);
    let keys = LocalKeySchedule::new([0x5e; 32]);
    let pk = keys.epoch_public(params.market, epoch)?;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);

    let issuer = TraderKey::from_seed([1; 32]);
    // (limit tick, lots) per bidder.
    let bids = [
        (108, 3_000),
        (105, 2_500),
        (103, 4_000),
        (103, 2_000),
        (101, 3_000),
        (96, 5_000),
    ];
    let bidders: Vec<TraderKey> = (0..bids.len())
        .map(|i| TraderKey::from_seed([10 + i as u8; 32]))
        .collect();

    let order = |t: &TraderKey, side, limit: u64, q, nonce| Order {
        market: params.market,
        trader: t.id(),
        nonce,
        side,
        role: Role::Taker,
        kind: OrderKind::Limit,
        limit: Tick(limit),
        quantity: Lots(q),
        valid_from: epoch,
        expires_at: epoch,
    };
    let mut intents = vec![order(&issuer, Side::Sell, 100, 10_000, 0)];
    for (i, (l, q)) in bids.iter().enumerate() {
        intents.push(order(&bidders[i], Side::Buy, *l, *q, 0));
    }
    let mut envelopes = Vec::new();
    let mut balances = BalanceSheet::default();
    let all_keys: Vec<&TraderKey> = std::iter::once(&issuer).chain(bidders.iter()).collect();
    for (o, k) in intents.iter().zip(&all_keys) {
        let (pi, c) = PrivateIntent::place(&mut rng, k, params.commitment_scheme, *o)?;
        envelopes.push(SealedEnvelope::seal(
            &mut rng,
            params.market,
            epoch,
            &pk,
            c,
            &pi,
        )?);
        balances.set(
            k.id(),
            Balance {
                base: BaseAtoms(1 << 40),
                quote: QuoteAtoms(1 << 50),
            },
        );
    }
    let batch = build_batch(
        params,
        epoch,
        reference,
        envelopes,
        balances,
        OrderStateTable::default(),
        beacon(1, epoch),
    );
    let exec = ReferenceExecutor::new(
        Arc::new(LocalKeySchedule::new([0x5e; 32])),
        ExecutorKey::from_seed([2; 32]),
    );
    let r = exec.execute(batch).await?;
    let c = r.receipt.outcome.clearing[0];
    println!(
        "clearing price: tick {}, volume {} lots (issuer offered 10000 at reserve 100)",
        c.tick.0, c.volume.0
    );
    for (i, (l, q)) in bids.iter().enumerate() {
        let f = r
            .artifacts
            .fills
            .iter()
            .find(|f| f.trader == bidders[i].id())
            .map_or(0, |f| f.quantity.0);
        println!("  bidder {i}: bid {q:>5} @ {l:>3} -> filled {f:>5}");
    }
    ensure!(
        r.artifacts.fills.iter().all(|f| f.tick == c.tick),
        "uniform price"
    );
    ensure!(c.volume.0 == 10_000, "issue fully placed");
    let losers = bids
        .iter()
        .zip(&bidders)
        .filter(|((l, _), _)| Tick(*l) < c.tick);
    for (_, k) in losers {
        ensure!(
            r.artifacts.fills.iter().all(|f| f.trader != k.id()),
            "bids below the price never appear in the receipt"
        );
    }
    r.artifacts.settlement.check_conservation()?;
    println!(
        "receipt {} conserves base and quote; losing bids appear nowhere on the record",
        r.receipt.digest()
    );
    Ok(())
}
