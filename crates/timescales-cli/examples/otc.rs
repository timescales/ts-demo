// Floats only format timings for display.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_possible_truncation,
    clippy::unwrap_used
)]

//! OTC block trade through the MPC committee: a large maker offer, a few
//! taker bids and some background flow. No machine ever holds the orders
//! in plaintext. The committee opens only the fills.

use std::sync::Arc;

use anyhow::{Result, ensure};
use rand::SeedableRng;
use timescales_auction::collateral::{Balance, BalanceSheet};
use timescales_auction::orderbook::OrderStateTable;
use timescales_core::identity::{ExecutorKey, TraderKey};
use timescales_core::intent::{PrivateIntent, SealedEnvelope};
use timescales_core::*;
use timescales_executor::mpc::{
    Layout, MpcCommittee, MpcConfig, MpcExecutor, NetworkModel, mask_order,
};
use timescales_executor::workload::{beacon, build_batch, default_params};
use timescales_executor::{ConfidentialExecutor, KeyProvider, LocalKeySchedule, ReferenceExecutor};

#[tokio::main]
async fn main() -> Result<()> {
    let mut params = default_params(FlowMode::DualFlow, CommitmentScheme::Sha256);
    params.band_half_width = 8;
    let epoch = EpochId(1);
    let reference = Tick(10_000);
    let keys = LocalKeySchedule::new([0x07; 32]);
    let pk = keys.epoch_public(params.market, epoch)?;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(2);
    let committee = MpcCommittee::new(
        MpcConfig {
            parties: 3,
            ..MpcConfig::default()
        },
        ExecutorKey::from_seed([3; 32]),
    );

    // (role, side, limit, lots)
    let flow = [
        (Role::Maker, Side::Sell, 10_002, 50_000), // block offer
        (Role::Taker, Side::Buy, 10_004, 20_000),
        (Role::Taker, Side::Buy, 10_003, 15_000),
        (Role::Taker, Side::Buy, 10_001, 30_000),
        (Role::Maker, Side::Buy, 9_998, 5_000),
        (Role::Taker, Side::Sell, 9_997, 2_000),
    ];
    let band = params.band(reference)?;
    let layout = Layout::new(&band, params.max_order_lots_log2);
    let mut envelopes = Vec::new();
    let mut masked = Vec::new();
    let mut balances = BalanceSheet::default();
    let mut source = &committee;
    for (i, (role, side, limit, q)) in flow.iter().enumerate() {
        let k = TraderKey::from_seed([40 + i as u8; 32]);
        let o = Order {
            market: params.market,
            trader: k.id(),
            nonce: 0,
            side: *side,
            role: *role,
            kind: OrderKind::Limit,
            limit: Tick(*limit),
            quantity: Lots(*q),
            valid_from: epoch,
            expires_at: epoch,
        };
        let (pi, c) = PrivateIntent::place(&mut rng, &k, params.commitment_scheme, o)?;
        envelopes.push(SealedEnvelope::seal(
            &mut rng,
            params.market,
            epoch,
            &pk,
            c,
            &pi,
        )?);
        masked.push(mask_order(&mut source, &k, &o, c, &band, &layout, epoch));
        balances.set(
            k.id(),
            Balance {
                base: BaseAtoms(1 << 50),
                quote: QuoteAtoms(1 << 60),
            },
        );
    }
    let mut batch = build_batch(
        params,
        epoch,
        reference,
        envelopes,
        balances,
        OrderStateTable::default(),
        beacon(2, epoch),
    );
    batch.masked = masked;

    let committee = Arc::new(committee);
    let mpc = MpcExecutor::new(committee.clone())
        .execute(batch.clone())
        .await?;
    let reference_result = ReferenceExecutor::new(Arc::new(keys), ExecutorKey::from_seed([4; 32]))
        .execute(batch)
        .await?;
    ensure!(
        mpc.receipt.outcome == reference_result.receipt.outcome,
        "MPC and reference agree"
    );
    for c in &mpc.receipt.outcome.clearing {
        println!("{:?}: tick {} volume {}", c.book, c.tick.0, c.volume.0);
    }
    for f in &mpc.artifacts.fills {
        println!(
            "  fill {:?} {:?} {} lots @ {}",
            f.role, f.side, f.quantity.0, f.tick.0
        );
    }
    let rep = committee.last_report().expect("report");
    println!(
        "committee: {} parties, {} rounds, {:.1} MB per party, {} secure comparisons; est. online {:.0} ms (LAN) / {:.1} s (WAN)",
        rep.parties,
        rep.meter.rounds,
        rep.meter.bytes_per_party(rep.parties) as f64 / 1e6,
        rep.meter.comparisons,
        rep.online_latency(&NetworkModel::LAN).as_secs_f64() * 1e3,
        rep.online_latency(&NetworkModel::WAN).as_secs_f64()
    );
    Ok(())
}
