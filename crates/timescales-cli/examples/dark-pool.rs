// Floats only format timings for display.
#![allow(
    clippy::float_arithmetic,
    clippy::cast_possible_truncation,
    clippy::unwrap_used
)]

//! A dark pool epoch seen from each seat at the table.
//!
//! The relay sees ciphertext and who sent it. The chain sees a root, a
//! padded count and later the fills. The TEE operator's host sees nothing
//! it can decrypt: the epoch key is released only to the attested enclave,
//! and only after the root is on chain. Traders learn their own fills.

use std::sync::Arc;

use anyhow::{Result, ensure};
use rand::{RngCore, SeedableRng};
use timescales_auction::{AuctionEpoch, ChainView};
use timescales_core::crypto::Keypair;
use timescales_core::*;
use timescales_executor::ConfidentialExecutor;
use timescales_executor::tee::LocalTeeDeployment;
use timescales_executor::workload::{WorkloadConfig, default_params, generate, trader_key};
use timescales_service::relay::{
    AckPolicy, EpochKeyCover, Padding, Relay, RelayConfig, Submission,
};

#[tokio::main]
async fn main() -> Result<()> {
    let mut params = default_params(FlowMode::DualFlow, CommitmentScheme::Sha256);
    params.band_half_width = 8;
    let epoch = EpochId(1);
    let dep = LocalTeeDeployment::new(5, 3, 7);
    dep.prepare_epoch(params.market, epoch);

    let mut cfg = WorkloadConfig::new(params, 150, 7);
    cfg.traders = 50;
    let w = generate(&cfg, dep.keys.as_ref());
    let keys: std::collections::BTreeMap<_, _> = (0..cfg.traders)
        .map(|i| trader_key(cfg.seed, i))
        .map(|k| (k.id(), k))
        .collect();

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
    let cover = Box::new(EpochKeyCover {
        keys: dep.keys.clone(),
        params,
        masked: false,
    });
    let mut cover_seed = [0u8; 32];
    rng.fill_bytes(&mut cover_seed);
    let mut relay = Relay::new_seeded(
        RelayConfig {
            params,
            market_address: [0x4d; 32],
            padding: Padding::PowerOfTwo { min: 64 },
            allow_masked: false,
            max_real: params.max_batch_envelopes,
            carry_p: 0.0,
        },
        Arc::new(Keypair::generate(&mut rng)),
        dep.chain.clone(),
        cover,
        cover_seed,
    )
    .with_ack(AckPolicy::AtCutoff);
    relay.open_epoch(
        AuctionEpoch {
            epoch,
            opens_at_ms: 0,
            cutoff_ms: 200,
        },
        cfg.reference,
        Hash32::ZERO,
    )?;
    for (i, ((pi, _), env)) in w.intents.iter().zip(&w.batch.envelopes).enumerate() {
        if let Some(t) = pi.body.trader() {
            relay.submit(
                i as u64 % 200,
                Submission::sign(&keys[&t], env.clone(), None),
            )?;
        }
    }
    let sealed = relay.seal(
        200,
        w.batch.balances.clone(),
        w.batch.prior_state.clone(),
        Hash32::ZERO,
    )?;
    let b = &sealed.batch;

    println!(
        "relay: {} submissions from {} traders, all {} bytes",
        sealed.real,
        keys.len(),
        timescales_core::intent::ENVELOPE_LEN
    );
    println!(
        "chain: root {} for epoch {}, {} envelopes published ({} real, {} cover)",
        b.header.batch_root,
        epoch.0,
        b.envelopes.len(),
        sealed.real,
        sealed.cover
    );
    ensure!(dep.chain.committed_root(params.market, epoch) == Some(b.header.batch_root));
    println!(
        "acknowledgements released together at cutoff: {}",
        sealed.promises.len()
    );

    let r = dep.executor.execute(b.clone()).await?;
    println!(
        "TEE: receipt {} signed by enclave key {}, attestation {}",
        r.receipt.digest(),
        r.receipt.executor,
        r.receipt.attestation
    );
    for c in &r.receipt.outcome.clearing {
        println!("  {:?}: tick {} volume {}", c.book, c.tick.0, c.volume.0);
    }
    let filled: std::collections::BTreeSet<_> =
        r.artifacts.fills.iter().map(|f| f.commitment).collect();
    let unfilled = b
        .envelopes
        .iter()
        .filter(|e| !filled.contains(&e.commitment))
        .count();
    println!(
        "public after settlement: {} fills; {} envelopes (incl. cover) reveal nothing beyond their commitment",
        r.artifacts.fills.len(),
        unfilled
    );
    r.artifacts.settlement.check_conservation()?;
    r.artifacts.settlement.apply(&b.balances)?;
    Ok(())
}
