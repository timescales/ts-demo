//! Multi-epoch dark pool, every component in one process:
//!
//! oracle (TLS-attested prices) -> relay (padding, delayed acks, root
//! commit) -> scheduler (TEE first, MPC committee as fallback) -> receipt
//! checks -> settlement against carried balances and order state.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rand::{RngCore, SeedableRng};
use timescales_auction::orderbook::OrderStateTable;
use timescales_auction::receipts::BackendKind;
use timescales_auction::{AuctionEpoch, ChainView};
use timescales_core::crypto::Keypair;
use timescales_core::identity::ExecutorKey;
use timescales_core::intent::MaskedIntent;
use timescales_core::oracle::{OracleConfig, Source, price_commitment};
use timescales_core::tls_proof::{Notary, Transcript, Trust};
use timescales_core::{CommitmentScheme, EpochId, FlowMode, Hash32};
use timescales_executor::ExecutionBatch;
use timescales_executor::mpc::{MpcCommittee, MpcConfig, MpcExecutor};
use timescales_executor::policy::{ExecutionPolicy, ProofMode};
use timescales_executor::scheduler::{Backend, Scheduler};
use timescales_executor::tee::{EnclaveFault, LocalTeeDeployment};
use timescales_executor::workload::{
    WorkloadConfig, attach_masked, default_params, generate, trader_key,
};
use timescales_service::relay::{
    AckPolicy, EpochKeyCover, Padding, Relay, RelayConfig, Submission,
};

const INTERVAL_MS: u64 = 250;

/// The demo has no market account. Promises v2 would bind this address.
const DEMO_MARKET_ADDRESS: [u8; 32] = [0x4d; 32];

pub(crate) async fn run(
    epochs: u64,
    orders: usize,
    traders: usize,
    fail_tee_at: Option<u64>,
) -> Result<()> {
    let mut params = default_params(FlowMode::DualFlow, CommitmentScheme::Sha256);
    params.band_half_width = 16;
    let market = params.market;

    // Executors and key custody.
    let dep = LocalTeeDeployment::new(5, 3, 0xd3);
    let committee = Arc::new(MpcCommittee::new(
        MpcConfig::default(),
        ExecutorKey::from_seed([3; 32]),
    ));
    let LocalTeeDeployment {
        chain,
        keys,
        executor,
        members,
        ..
    } = dep;
    let tee = Arc::new(executor);
    let policy = ExecutionPolicy {
        backends: vec![BackendKind::Tee, BackendKind::Mpc],
        proof: ProofMode::None,
        attempts_per_backend: 1,
        attempt_timeout: Duration::from_secs(120),
        mpc_max_batch: 4096,
    };
    let scheduler: Scheduler<timescales_executor::tee::PublishedEpochKeys> = Scheduler::new(
        policy,
        vec![
            Backend::Tee(tee.clone()),
            Backend::Mpc(MpcExecutor::new(committee.clone())),
        ],
    );

    // Oracle: three sources behind one notary.
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(9);
    let notary = Notary::new(Keypair::generate(&mut rng));
    let sources: Vec<Source> = (1..=3)
        .map(|i| Source {
            id: i,
            server: format!("feed{i}.example.test"),
            field: "price".into(),
            decimals: 2,
            atoms_per_unit: 1,
        })
        .collect();
    let oracle = OracleConfig {
        market,
        tick_size: 1,
        sources: sources.clone(),
        min_sources: 2,
        max_spread_ticks: 200,
        trust: Trust {
            notaries: [notary.public_key()].into(),
            servers: sources.iter().map(|s| s.server.clone()).collect(),
            max_age_secs: 60,
        },
    };

    let cover = Box::new(EpochKeyCover {
        keys: keys.clone(),
        params,
        masked: true,
    });
    let relay_cfg = RelayConfig {
        params,
        market_address: DEMO_MARKET_ADDRESS,
        padding: Padding::PowerOfTwo { min: 64 },
        allow_masked: true,
        max_real: params.max_batch_envelopes,
        carry_p: 0.0,
    };
    let mut cover_seed = [0u8; 32];
    rng.fill_bytes(&mut cover_seed);
    let mut relay = Relay::new_seeded(
        relay_cfg,
        Arc::new(Keypair::generate(&mut rng)),
        chain.clone(),
        cover,
        cover_seed,
    )
    .with_ack(AckPolicy::AtCutoff);

    let mut balances = None;
    let mut state = OrderStateTable::default();
    let mut prev_receipt = Hash32::ZERO;
    let mut expired = 0;
    println!(
        "{:>5} {:>8} {:>10} {:>9} {:>6} {:>22} {:>22} {:>8} {:>9}",
        "epoch",
        "ref",
        "env(real)",
        "accepted",
        "fills",
        "maker-ask/taker-bid",
        "maker-bid/taker-ask",
        "backend",
        "exec ms"
    );
    for e in 1..=epochs {
        let epoch = EpochId(e);
        keys_for(&members, &keys, market, epoch, &mut rng)?;

        // Reference price from attested feeds. Drifts a little per epoch.
        let now = 1_000 + e;
        let mid = 10_000 + 7 * e;
        let presentations: Vec<_> = sources
            .iter()
            .enumerate()
            .map(|(k, s)| {
                let px = format!("{}.{:02}", (mid + k as u64) / 100, (mid + k as u64) % 100);
                let body = format!(r#"{{"symbol":"TSCL/USD","price":"{px}","account":"hidden"}}"#);
                let (att, open) = notary
                    .notarize(
                        &mut rng,
                        Transcript {
                            server_name: s.server.clone(),
                            time: now,
                            sent: b"GET /px".to_vec(),
                            received: body.into_bytes(),
                        },
                    )
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok((s.id, open.try_disclose_received(&att, 20..50)?))
            })
            .collect::<Result<_>>()?;
        let pc = price_commitment(&oracle, epoch, &presentations, now).context("oracle")?;
        let timing = AuctionEpoch {
            epoch,
            opens_at_ms: 0,
            cutoff_ms: INTERVAL_MS,
        };
        relay.open_epoch(timing, pc.reference, pc.digest())?;

        // Traders: same population every epoch, new orders.
        let mut cfg = WorkloadConfig::new(params, orders, 0xd3);
        cfg.traders = traders;
        cfg.epoch = epoch;
        cfg.reference = pc.reference;
        let mut w = generate(&cfg, keys.as_ref());
        attach_masked(&mut w, &committee);
        let balances_now = balances
            .get_or_insert_with(|| w.batch.balances.clone())
            .clone();
        let tkeys: std::collections::BTreeMap<_, _> = (0..traders)
            .map(|i| trader_key(cfg.seed, i))
            .map(|k| (k.id(), k))
            .collect();
        for (i, env) in w.batch.envelopes.iter().enumerate() {
            let masked: MaskedIntent = w.batch.masked[i].clone();
            let Some(t) = masked.trader() else {
                // Cover traffic from the generator: submit as the relay would.
                continue;
            };
            relay.submit(
                10 + i as u64 % 200,
                Submission::sign(&tkeys[&t], env.clone(), Some(masked)),
            )?;
        }

        let sealed = relay.seal(
            INTERVAL_MS,
            balances_now.clone(),
            state.clone(),
            prev_receipt,
        )?;
        if chain.committed_root(market, epoch) != Some(sealed.batch.header.batch_root) {
            bail!("relay did not commit the root it sealed");
        }
        if fail_tee_at == Some(e) {
            tee.set_fault(EnclaveFault::CrashAfterKeyRelease);
        }
        let batch: ExecutionBatch = sealed.batch;
        let t = Instant::now();
        let s = scheduler
            .run(batch.clone())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        // One crash leaves the TEE's circuit closed (it opens after
        // `unhealthy_after` consecutive failures), so the next epoch goes
        // back to the TEE without any reset.
        tee.set_fault(EnclaveFault::None);

        let r = &s.result;
        r.artifacts.check_against(&r.receipt.outcome)?;
        balances = Some(r.artifacts.settlement.apply(&balances_now)?);
        state.apply(
            epoch,
            params.max_order_lifetime,
            r.artifacts.fills.iter().map(|f| (f.commitment, f.quantity)),
            r.artifacts.cancelled.iter().copied(),
        );
        if state.root() != r.receipt.outcome.next_state_root {
            bail!("carried state diverged from the receipt");
        }
        prev_receipt = r.receipt.digest();
        // The epoch is terminal: drop its mask blocks that no MPC run
        // consumed (every block, when the TEE executed it).
        expired += committee
            .expire_masks(epoch)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let book = |i: usize| {
            r.receipt
                .outcome
                .clearing
                .get(i)
                .map_or_else(String::new, |c| format!("{} x {}", c.tick.0, c.volume.0))
        };
        println!(
            "{:>5} {:>8} {:>10} {:>9} {:>6} {:>22} {:>22} {:>8} {:>9.1}",
            e,
            pc.reference.0,
            format!("{}({})", batch.envelopes.len(), sealed.real),
            r.metrics.accepted,
            r.artifacts.fills.len(),
            book(0),
            book(1),
            format!("{:?}", s.backend),
            ms
        );
    }
    println!(
        "settled {epochs} epochs, {expired} unused mask blocks expired, final receipt {}",
        prev_receipt.to_hex()
    );
    Ok(())
}

fn keys_for(
    members: &[Arc<timescales_executor::tee::KeyReleaseMember>],
    keys: &timescales_executor::tee::PublishedEpochKeys,
    market: timescales_core::MarketId,
    epoch: EpochId,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<()> {
    let dealer = timescales_executor::tee::EpochKeyDealer {
        threshold: 3,
        members: u8::try_from(members.len()).unwrap_or(5),
    };
    let dealt = dealer.deal(rng)?;
    for (m, s) in members.iter().zip(dealt.shares) {
        m.store_share(market, epoch, s)?;
    }
    keys.publish(market, epoch, dealt.public);
    Ok(())
}
