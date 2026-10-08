//! Deterministic synthetic order flow.
//!
//! Everything is a function of [`WorkloadConfig`] (including its seed), so a
//! benchmark or failing test can be reproduced exactly. Per-order randomness
//! comes from a ChaCha20 stream indexed by the order's position, which keeps
//! generation parallel without making it nondeterministic.
//!
//! The distributions are deliberately simple and are *not* a model of real
//! order flow: limits are uniform around the reference tick (with some mass
//! outside the band), quantities are uniform, sides and roles are fair coins.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use crate::mpc::{Layout, MpcCommittee, mask_order};
use crate::{ExecutionBatch, KeyProvider};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use timescales_auction::BatchHeader;
use timescales_auction::collateral::{Balance, BalanceSheet};
use timescales_auction::orderbook::OrderStateTable;
use timescales_core::crypto::{Hasher, domain};
use timescales_core::identity::TraderKey;
use timescales_core::intent::{
    Cancel, IntentBody, MaskedBody, MaskedIntent, PrivateIntent, SealedEnvelope,
};
use timescales_core::{
    BaseAtoms, CommitmentScheme, EpochId, FeeBps, FlowMode, Hash32, Lots, MarketId, MarketParams,
    Order, OrderCommitment, OrderKind, QuoteAtoms, Rationing, Role, Side, Tick,
};

/// Market used by tests, benchmarks and the demos unless they say otherwise.
pub fn default_params(flow: FlowMode, scheme: CommitmentScheme) -> MarketParams {
    MarketParams {
        market: MarketId(1),
        base_lot_size: 1_000,
        tick_size: 100,
        band_half_width: 32,
        max_order_lots_log2: 20,
        max_orders_per_trader: 1024,
        max_batch_envelopes: 1 << 21,
        max_order_lifetime: 8,
        maker_fee: FeeBps(1),
        taker_fee: FeeBps(5),
        flow,
        rationing: Rationing::Lottery,
        commitment_scheme: scheme,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Funding {
    /// Every trader can afford every order.
    Rich,
    /// Roughly this percentage of traders is funded for only a few orders.
    Tight(u8),
}

#[derive(Clone, Debug)]
pub struct WorkloadConfig {
    pub params: MarketParams,
    pub epoch: EpochId,
    pub reference: Tick,
    pub orders: usize,
    pub traders: usize,
    pub seed: u64,
    /// Percentages of the intent stream.
    pub market_order_pct: u8,
    pub cancel_pct: u8,
    pub noop_pct: u8,
    /// Percentage of limit orders priced outside the band.
    pub out_of_band_pct: u8,
    pub max_quantity: u64,
    pub funding: Funding,
    /// Each trader always buys or always sells. Two-sided traders run into
    /// self-trade prevention, which then rejects most of their orders. That
    /// is useful for tests of the rule and unrepresentative for benchmarks.
    pub one_sided: bool,
}

impl WorkloadConfig {
    pub fn new(params: MarketParams, orders: usize, seed: u64) -> Self {
        Self {
            params,
            epoch: EpochId(1),
            reference: Tick(10_000),
            orders,
            traders: (orders / 4).max(2),
            seed,
            market_order_pct: 5,
            cancel_pct: 2,
            noop_pct: 0,
            out_of_band_pct: 5,
            max_quantity: 100,
            funding: Funding::Rich,
            one_sided: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Place,
    Cancel,
    Noop,
}

/// Generated plaintext and the batch built from it.
#[derive(Debug)]
pub struct Workload {
    pub config: WorkloadConfig,
    /// Plaintext intents, index-aligned with `batch.envelopes`.
    pub intents: Vec<(PrivateIntent, OrderCommitment)>,
    pub batch: ExecutionBatch,
}

fn stream(seed: u64, i: usize) -> ChaCha20Rng {
    let mut r = ChaCha20Rng::seed_from_u64(seed);
    r.set_stream(i as u64);
    r
}

pub fn trader_key(seed: u64, i: usize) -> TraderKey {
    let h = Hasher::new(b"timescales/workload/trader")
        .chain(&seed.to_le_bytes())
        .chain(&(i as u64).to_le_bytes())
        .finalize();
    TraderKey::from_seed(h.0)
}

pub fn beacon(seed: u64, epoch: EpochId) -> Hash32 {
    Hasher::new(domain::BATCH_SEED)
        .chain(b"workload-beacon")
        .chain(&seed.to_le_bytes())
        .chain(&epoch.0.to_le_bytes())
        .finalize()
}

fn random_order(
    cfg: &WorkloadConfig,
    index: usize,
    trader: &TraderKey,
    nonce: u64,
    rng: &mut ChaCha20Rng,
) -> Order {
    let w = i64::from(cfg.params.band_half_width);
    let coin = rng.gen_bool(0.5);
    let side = match (cfg.one_sided, index.is_multiple_of(2), coin) {
        (true, true, _) | (false, _, true) => Side::Buy,
        _ => Side::Sell,
    };
    let role = if rng.gen_bool(0.5) {
        Role::Maker
    } else {
        Role::Taker
    };
    let market = rng.gen_range(0..100u8) < cfg.market_order_pct;
    let reach = if rng.gen_range(0..100u8) < cfg.out_of_band_pct {
        w + 1 + w / 2
    } else {
        w
    };
    let offset = rng.gen_range(-reach..=reach);
    let limit = Tick(cfg.reference.0.saturating_add_signed(offset));
    let q = rng.gen_range(1..=cfg.max_quantity.min(cfg.params.max_order_lots()));
    Order {
        market: cfg.params.market,
        trader: trader.id(),
        nonce,
        side,
        role,
        kind: if market {
            OrderKind::Market
        } else {
            OrderKind::Limit
        },
        limit: if market { Tick::ZERO } else { limit },
        quantity: Lots(q),
        valid_from: cfg.epoch,
        expires_at: cfg.epoch,
    }
}

/// Generate intents and seal them to `keys`' epoch key.
pub fn generate<K: KeyProvider>(cfg: &WorkloadConfig, keys: &K) -> Workload {
    let traders: Vec<TraderKey> = (0..cfg.traders)
        .into_par_iter()
        .map(|i| trader_key(cfg.seed, i))
        .collect();
    // Traders depend on the seed only. Order flow also on the epoch, so a
    // multi-epoch run has the same population trading different orders.
    let oseed = cfg.seed.wrapping_add(
        cfg.epoch
            .0
            .wrapping_sub(1)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15),
    );
    let scheme = cfg.params.commitment_scheme;
    let kinds: Vec<Kind> = (0..cfg.orders)
        .map(|i| {
            let mut r = stream(oseed ^ 0x6b69_6e64, i);
            let x = r.gen_range(0..100u8);
            if x < cfg.noop_pct {
                Kind::Noop
            } else if x < cfg.noop_pct.saturating_add(cfg.cancel_pct) && i > 0 {
                Kind::Cancel
            } else {
                Kind::Place
            }
        })
        .collect();

    // Pass 1: placements and cover traffic.
    let mut intents: Vec<Option<(PrivateIntent, OrderCommitment, usize)>> = (0..cfg.orders)
        .into_par_iter()
        .map(|i| {
            let mut rng = stream(oseed, i);
            match kinds[i] {
                Kind::Place => {
                    let t = rng.gen_range(0..traders.len());
                    let o = random_order(cfg, t, &traders[t], i as u64, &mut rng);
                    let (pi, c) = PrivateIntent::place(&mut rng, &traders[t], scheme, o)
                        .expect("valid signer");
                    Some((pi, c, t))
                }
                Kind::Noop => {
                    let (pi, c) = PrivateIntent::noop(&mut rng, scheme).expect("noop");
                    Some((pi, c, usize::MAX))
                }
                Kind::Cancel => None,
            }
        })
        .collect();

    // Pass 2: cancels of earlier placements by their owner.
    let places: Vec<usize> = (0..cfg.orders)
        .filter(|&i| kinds[i] == Kind::Place)
        .collect();
    for i in 0..cfg.orders {
        if kinds[i] != Kind::Cancel {
            continue;
        }
        let mut rng = stream(oseed ^ 0x6361_6e63, i);
        let n_earlier = places.partition_point(|&j| j < i);
        let entry = if let Some(&j) = places[..n_earlier].get(rng.gen_range(0..n_earlier.max(1))) {
            let (_, target, t) = intents[j].expect("placement present");
            let c = Cancel {
                market: cfg.params.market,
                trader: traders[t].id(),
                nonce: i as u64,
                target,
                epoch: cfg.epoch,
            };
            let (pi, cc) =
                PrivateIntent::cancel(&mut rng, &traders[t], scheme, c).expect("valid signer");
            (pi, cc, t)
        } else {
            let (pi, c) = PrivateIntent::noop(&mut rng, scheme).expect("noop");
            (pi, c, usize::MAX)
        };
        intents[i] = Some(entry);
    }
    let intents: Vec<(PrivateIntent, OrderCommitment)> = intents
        .into_iter()
        .map(|x| x.map(|(p, c, _)| (p, c)).expect("every slot filled"))
        .collect();

    let epoch_pk = keys
        .epoch_public(cfg.params.market, cfg.epoch)
        .expect("epoch key");
    let envelopes: Vec<SealedEnvelope> = intents
        .par_iter()
        .enumerate()
        .map(|(i, (pi, c))| {
            let mut rng = stream(oseed ^ 0x7365_616c, i);
            SealedEnvelope::seal(&mut rng, cfg.params.market, cfg.epoch, &epoch_pk, *c, pi)
                .expect("seal")
        })
        .collect();

    let balances = funding(cfg, &traders);
    let prior = OrderStateTable::default();
    let batch = build_batch(
        cfg.params,
        cfg.epoch,
        cfg.reference,
        envelopes,
        balances,
        prior,
        beacon(cfg.seed, cfg.epoch),
    );
    Workload {
        config: cfg.clone(),
        intents,
        batch,
    }
}

fn funding(cfg: &WorkloadConfig, traders: &[TraderKey]) -> BalanceSheet {
    traders
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let b = match cfg.funding {
                Funding::Rich => Balance {
                    base: BaseAtoms(1 << 60),
                    quote: QuoteAtoms(1 << 60),
                },
                Funding::Tight(pct) => {
                    let mut r = stream(cfg.seed ^ 0x6675_6e64, i);
                    if r.gen_range(0..100u8) < pct {
                        let lot_price = cfg.reference.0 * cfg.params.tick_size;
                        Balance {
                            base: BaseAtoms(
                                r.gen_range(0..4 * cfg.max_quantity) * cfg.params.base_lot_size,
                            ),
                            quote: QuoteAtoms(r.gen_range(0..4 * cfg.max_quantity) * lot_price),
                        }
                    } else {
                        Balance {
                            base: BaseAtoms(1 << 60),
                            quote: QuoteAtoms(1 << 60),
                        }
                    }
                }
            };
            (t.id(), b)
        })
        .collect()
}

/// Assemble a batch whose header is consistent with its inputs.
pub fn build_batch(
    params: MarketParams,
    epoch: EpochId,
    reference: Tick,
    envelopes: Vec<SealedEnvelope>,
    balances: BalanceSheet,
    prior: OrderStateTable,
    beacon: Hash32,
) -> ExecutionBatch {
    let band = params
        .band(reference)
        .expect("reference compatible with params");
    let commitments: Vec<OrderCommitment> = envelopes.iter().map(|e| e.commitment).collect();
    let header = BatchHeader::assemble(
        params,
        epoch,
        band,
        Hash32::ZERO,
        &commitments,
        beacon,
        prior.root(),
        balances.root(),
        Hash32::ZERO,
    );
    ExecutionBatch {
        header,
        envelopes,
        masked: Vec::new(),
        balances,
        prior_state: prior,
    }
}

/// Attach the masked (MPC) encoding of the same intents to the batch, with
/// masks issued by `committee`. Commitments and order match the sealed
/// envelopes, so either backend can execute the batch.
pub fn attach_masked(w: &mut Workload, committee: &MpcCommittee) {
    let cfg = &w.config;
    let keys: std::collections::BTreeMap<_, _> = (0..cfg.traders)
        .map(|i| trader_key(cfg.seed, i))
        .map(|k| (k.id(), k))
        .collect();
    let band = w.batch.header.band;
    let layout = Layout::new(&band, cfg.params.max_order_lots_log2);
    let mut source = committee;
    w.batch.masked = w
        .intents
        .iter()
        .map(|(pi, c)| match pi.body {
            IntentBody::Place(o) => mask_order(
                &mut source,
                &keys[&o.trader],
                &o,
                *c,
                &band,
                &layout,
                cfg.epoch,
            ),
            IntentBody::Cancel(x) => MaskedIntent::sign(
                &keys[&x.trader],
                cfg.params.market,
                cfg.epoch,
                *c,
                MaskedBody::Cancel(x),
            ),
            IntentBody::Noop => MaskedIntent::noop(cfg.params.market, cfg.epoch, *c),
        })
        .collect();
}

/// Configuration of the version 1 vectors: workload seed 42, eight
/// intents, single book, band of seven ticks. Returns the workload config,
/// the epoch-key schedule seed and the executor key seed.
pub fn vector_config() -> (WorkloadConfig, [u8; 32], [u8; 32]) {
    let mut params = default_params(FlowMode::SingleBook, CommitmentScheme::Sha256);
    params.band_half_width = 3;
    let mut cfg = WorkloadConfig::new(params, 8, 42);
    cfg.traders = 4;
    cfg.max_quantity = 9;
    (cfg, [0x11; 32], [0x22; 32])
}
