// Floats only format timings for display.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_possible_truncation,
    clippy::unwrap_used
)]

//! Tokenised fund: subscriptions and redemptions clear in a narrow collar
//! around the NAV published by two fund administrators. The NAV reaches the
//! auction as a TLS-attested claim. The batch result comes with a Groth16
//! proof so an auditor can check it without seeing any investor's order.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, ensure};
use rand::SeedableRng;
use timescales_auction::collateral::{Balance, BalanceSheet};
use timescales_auction::orderbook::OrderStateTable;
use timescales_core::crypto::Keypair;
use timescales_core::identity::{ExecutorKey, TraderKey};
use timescales_core::intent::{PrivateIntent, SealedEnvelope};
use timescales_core::oracle::{OracleConfig, Source, price_commitment};
use timescales_core::tls_proof::{Notary, Transcript, Trust};
use timescales_core::*;
use timescales_executor::prover::Keys;
use timescales_executor::verifier::{ProofBundle, decode_vk, verify_bundle};
use timescales_executor::workload::{beacon, build_batch, default_params};
use timescales_executor::zk::{Groth16Prover, shape_for};
use timescales_executor::{ConfidentialExecutor, KeyProvider, LocalKeySchedule, ReferenceExecutor};

#[tokio::main]
async fn main() -> Result<()> {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(3);
    // NAV with 4 decimals. One tick = 0.0001 of a share's NAV.
    let notary = Notary::new(Keypair::generate(&mut rng));
    let admins: Vec<Source> = (1..=2)
        .map(|i| Source {
            id: i,
            server: format!("nav{i}.fund-admin.test"),
            field: "nav".into(),
            decimals: 4,
            atoms_per_unit: 1,
        })
        .collect();
    let oracle = OracleConfig {
        market: MarketId(1),
        tick_size: 1,
        sources: admins.clone(),
        min_sources: 2,
        max_spread_ticks: 5,
        trust: Trust {
            notaries: [notary.public_key()].into(),
            servers: admins.iter().map(|s| s.server.clone()).collect(),
            max_age_secs: 3600,
        },
    };
    let presentations: Vec<_> = admins
        .iter()
        .zip(["101.2345", "101.2347"])
        .map(|(s, nav)| {
            let body = format!(r#"{{"fund":"TSCL-RWA-1","nav":"{nav}","holders":"redacted"}}"#);
            let (att, open) = notary.notarize(
                &mut rng,
                Transcript {
                    server_name: s.server.clone(),
                    time: 50,
                    sent: b"GET /nav".to_vec(),
                    received: body.into_bytes(),
                },
            )?;
            Ok((s.id, open.disclose_received(&att, 16..48)))
        })
        .collect::<Result<_>>()?;
    let pc = price_commitment(&oracle, EpochId(1), &presentations, 60)?;
    println!(
        "attested NAV tick {} from {} administrators",
        pc.reference.0,
        pc.observations.len()
    );

    let mut params = default_params(FlowMode::SingleBook, CommitmentScheme::PoseidonBn254);
    params.band_half_width = 4;
    params.max_order_lots_log2 = 16;
    params.max_batch_envelopes = 16;
    let epoch = EpochId(1);
    let keys = LocalKeySchedule::new([0x88; 32]);
    let pk = keys.epoch_public(params.market, epoch)?;
    // Subscriptions (buys) and redemptions (sells), limits in ticks.
    let book = [
        (Side::Buy, 1_012_349, 400),
        (Side::Buy, 1_012_347, 250),
        (Side::Buy, 1_012_343, 100),
        (Side::Sell, 1_012_345, 300),
        (Side::Sell, 1_012_346, 200),
        (Side::Sell, 1_012_350, 500),
    ];
    let mut envelopes = Vec::new();
    let mut balances = BalanceSheet::default();
    for (i, (side, limit, q)) in book.iter().enumerate() {
        let k = TraderKey::from_seed([60 + i as u8; 32]);
        let o = Order {
            market: params.market,
            trader: k.id(),
            nonce: 0,
            side: *side,
            role: Role::Taker,
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
        balances.set(
            k.id(),
            Balance {
                base: BaseAtoms(1 << 40),
                quote: QuoteAtoms(1 << 62),
            },
        );
    }
    let mut batch = build_batch(
        params,
        epoch,
        pc.reference,
        envelopes,
        balances,
        OrderStateTable::default(),
        beacon(3, epoch),
    );
    batch.header.price_commitment = pc.digest();

    let shape = shape_for(&batch.header, 8);
    let t = Instant::now();
    let pkeys = Arc::new(Keys::setup(shape, &mut rng)?);
    println!(
        "circuit: {} constraints, setup {:.1} s (local, experiment only)",
        timescales_executor::prover::constraint_count(shape)?,
        t.elapsed().as_secs_f64()
    );
    let exec = ReferenceExecutor::new(Arc::new(keys), ExecutorKey::from_seed([5; 32]))
        .with_prover(Arc::new(Groth16Prover::new(pkeys.clone())));
    let r = exec.execute(batch.clone()).await?;
    let c = r.receipt.outcome.clearing[0];
    println!(
        "cleared {} shares at tick {} (band {}..{})",
        c.volume.0, c.tick.0, batch.header.band.lo.0, batch.header.band.hi.0
    );
    println!(
        "proving took {:.0} ms",
        r.metrics.stage("prove").unwrap_or_default().as_secs_f64() * 1e3
    );

    // The auditor's check uses only public data.
    let bundle = ProofBundle::from_bytes(&r.proof.as_ref().expect("proof").bytes)?;
    let commitments: Vec<_> = batch.envelopes.iter().map(|e| e.commitment).collect();
    let t = Instant::now();
    verify_bundle(
        &decode_vk(&pkeys.vk_bytes())?,
        &bundle,
        &batch.header,
        &commitments,
        &batch.prior_state,
        &r.artifacts,
        &r.receipt.outcome.clearing,
    )?;
    println!(
        "auditor verified the proof in {:.1} ms; proof is {} bytes",
        t.elapsed().as_secs_f64() * 1e3,
        bundle.proof.len()
    );
    ensure!(
        r.receipt.proof == bundle.digest(),
        "receipt commits to the proof"
    );
    Ok(())
}
