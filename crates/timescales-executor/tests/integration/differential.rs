//! Differential testing across backends (hypothesis H3).
//!
//! For random markets and order flow, every backend that supports the
//! market must produce the same `ExecutionOutcome` and artifacts as the
//! reference executor. A failure here is a bug in a backend or in the
//! specification, never an acceptable result.

use std::sync::Arc;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use timescales_core::crypto::SealSecret;
use timescales_core::identity::ExecutorKey;
use timescales_core::{CommitmentScheme, EpochId, FlowMode, MarketId, Rationing};
use timescales_executor::mpc::{MpcCommittee, MpcConfig, MpcExecutor};
use timescales_executor::tee::LocalTeeDeployment;
use timescales_executor::workload::{
    Funding, WorkloadConfig, attach_masked, default_params, generate,
};
use timescales_executor::{ConfidentialExecutor, ExecutorError, KeyProvider, ReferenceExecutor};

struct OneKey(SealSecret);

impl KeyProvider for OneKey {
    fn epoch_public(&self, _: MarketId, _: EpochId) -> Result<[u8; 32], ExecutorError> {
        Ok(self.0.public())
    }
    fn epoch_secret(&self, _: MarketId, _: EpochId) -> Result<SealSecret, ExecutorError> {
        Ok(SealSecret::from_bytes(self.0.to_bytes()))
    }
}

fn random_config(rng: &mut ChaCha20Rng, seed: u64) -> WorkloadConfig {
    let flow = if rng.gen_bool(0.5) {
        FlowMode::DualFlow
    } else {
        FlowMode::SingleBook
    };
    let mut p = default_params(flow, CommitmentScheme::Sha256);
    p.band_half_width = rng.gen_range(2..8);
    p.max_orders_per_trader = rng.gen_range(2..6);
    p.maker_fee = timescales_core::FeeBps(rng.gen_range(0..20));
    p.taker_fee = timescales_core::FeeBps(rng.gen_range(0..40));
    let n = rng.gen_range(10..70);
    let mut cfg = WorkloadConfig::new(p, n, seed);
    cfg.traders = rng.gen_range(3..(n / 2).max(4));
    cfg.max_quantity = rng.gen_range(1..30);
    cfg.cancel_pct = rng.gen_range(0..10);
    cfg.noop_pct = rng.gen_range(0..10);
    cfg.market_order_pct = rng.gen_range(0..20);
    cfg.out_of_band_pct = rng.gen_range(0..30);
    cfg.funding = if rng.gen_bool(0.5) {
        Funding::Rich
    } else {
        Funding::Tight(rng.gen_range(10..90))
    };
    // Mix one- and two-sided traders so self-trade prevention stays exercised.
    cfg.one_sided = rng.gen_bool(0.5);
    cfg
}

#[tokio::test(flavor = "multi_thread")]
async fn reference_tee_and_mpc_agree_on_random_batches() {
    let cases: u64 = std::env::var("TIMESCALES_DIFF_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let mut rng = ChaCha20Rng::seed_from_u64(0xd1ff);
    let mut traded = 0;
    for seed in 0..cases {
        let cfg = random_config(&mut rng, seed);
        let dep = LocalTeeDeployment::new(3, 2, seed);
        let sk = dep.prepare_epoch_with_secret(cfg.params.market, cfg.epoch);
        let mut w = generate(&cfg, dep.keys.as_ref());
        let committee = Arc::new(MpcCommittee::new(
            MpcConfig {
                dealer_seed: Some(ChaCha20Rng::seed_from_u64(seed).get_seed()),
                ..MpcConfig::default()
            },
            ExecutorKey::from_seed([2; 32]),
        ));
        attach_masked(&mut w, &committee);
        dep.commit(&w.batch.header);

        let r = ReferenceExecutor::new(Arc::new(OneKey(sk)), ExecutorKey::from_seed([1; 32]))
            .execute(w.batch.clone())
            .await
            .unwrap_or_else(|e| panic!("reference failed on case {seed}: {e}"));
        let t = dep
            .executor
            .execute(w.batch.clone())
            .await
            .unwrap_or_else(|e| panic!("tee failed on case {seed}: {e}"));
        let m = MpcExecutor::new(committee)
            .execute(w.batch.clone())
            .await
            .unwrap_or_else(|e| panic!("mpc failed on case {seed}: {e}"));

        assert_eq!(
            r.receipt.outcome, t.receipt.outcome,
            "TEE diverged on case {seed}: {cfg:?}"
        );
        assert_eq!(
            r.receipt.outcome, m.receipt.outcome,
            "MPC diverged on case {seed}: {cfg:?}"
        );
        assert_eq!(
            r.artifacts, m.artifacts,
            "MPC artifacts diverged on case {seed}"
        );
        traded += usize::from(!r.artifacts.fills.is_empty());
    }
    assert!(
        traded as u64 * 2 >= cases,
        "too few cases traded ({traded}/{cases}); generator is not exercising matching"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pro_rata_markets_agree_between_reference_and_tee() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x9a7a);
    for seed in 0..8u64 {
        let mut cfg = random_config(&mut rng, 100 + seed);
        cfg.params.rationing = Rationing::ProRata;
        let dep = LocalTeeDeployment::new(3, 2, seed);
        let sk = dep.prepare_epoch_with_secret(cfg.params.market, cfg.epoch);
        let w = generate(&cfg, dep.keys.as_ref());
        dep.commit(&w.batch.header);
        let r = ReferenceExecutor::new(Arc::new(OneKey(sk)), ExecutorKey::from_seed([1; 32]))
            .execute(w.batch.clone())
            .await
            .unwrap();
        let t = dep.executor.execute(w.batch.clone()).await.unwrap();
        assert_eq!(r.receipt.outcome, t.receipt.outcome);
    }
}
