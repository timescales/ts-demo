//! Carried cover: recurrence across epochs, its lifetime bound, and
//! the export/import round trip the node persists under its KEK.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_auction::{AuctionEpoch, InMemoryChain};
use timescales_core::crypto::Keypair;
use timescales_core::identity::TraderKey;
use timescales_core::intent::{CIPHERTEXT_LEN, IntentBody, MaskedBody, SealedEnvelope};
use timescales_core::{
    CommitmentScheme, EpochId, FeeBps, FlowMode, Hash32, MarketId, MarketParams, OrderCommitment,
    PROTOCOL_VERSION, Rationing, Tick,
};
use timescales_executor::{KeyProvider, LocalKeySchedule};
use timescales_service::relay::{
    CarryingCover, ClosedBatch, CoverSource, EpochKeyCover, Padding, Relay, RelayConfig,
    Submission, verify_submission,
};

const M: MarketId = MarketId(1);

fn params() -> MarketParams {
    MarketParams {
        market: M,
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

fn keys() -> Arc<LocalKeySchedule> {
    Arc::new(LocalKeySchedule::new([9; 32]))
}

fn config(carry_p: f64) -> RelayConfig {
    RelayConfig {
        params: params(),
        market_address: [0x4d; 32],
        padding: Padding::Fixed(4),
        allow_masked: false,
        max_real: 1024,
        carry_p,
    }
}

fn window(epoch: u64) -> AuctionEpoch {
    AuctionEpoch {
        epoch: EpochId(epoch),
        opens_at_ms: 100 * epoch,
        cutoff_ms: 100 * (epoch + 1),
    }
}

/// What the executor would find inside.
fn opens(keys: &LocalKeySchedule, env: &SealedEnvelope) -> IntentBody {
    let sk = keys.epoch_secret(M, env.epoch).unwrap();
    env.open(&sk, CommitmentScheme::Sha256).unwrap().body
}

fn commitments(c: &ClosedBatch) -> BTreeSet<OrderCommitment> {
    c.envelopes.iter().map(|e| e.commitment).collect()
}

#[test]
fn cover_carry_round_trip() {
    let keys = keys();
    let a = CarryingCover::new(keys.clone(), params(), false);
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let first: Vec<SealedEnvelope> = (0..4)
        .map(|_| a.cover(M, EpochId(1), &mut rng).unwrap().0)
        .collect();
    let used: BTreeSet<OrderCommitment> = first.iter().map(|e| e.commitment).collect();
    let exported = a.export();
    assert_eq!(
        exported.iter().map(|(c, _)| *c).collect::<BTreeSet<_>>(),
        used
    );
    assert!(exported.iter().all(|(_, record)| record.len() == 114));

    // A restarted node imports what it persisted and carries on from there.
    let b = CarryingCover::new(keys.clone(), params(), false);
    b.import(exported.clone()).unwrap();
    assert_eq!(b.export(), exported);
    for epoch in [2, 3] {
        let mut carried = BTreeSet::new();
        while let Some((env, masked)) = b.carry(M, EpochId(epoch), &mut rng).unwrap() {
            assert!(masked.is_none());
            assert_eq!(env.epoch, EpochId(epoch));
            assert_eq!(opens(&keys, &env), IntentBody::Noop);
            let earlier = first
                .iter()
                .find(|e| e.commitment == env.commitment)
                .unwrap();
            assert_ne!(env.ephemeral, earlier.ephemeral, "sealed afresh");
            assert!(carried.insert(env.commitment), "once per epoch");
        }
        assert_eq!(carried, used, "epoch {epoch}");
    }
    // With max_order_lifetime 2 a commitment appears in at most three
    // consecutive epochs, so nothing is left to carry into the fourth.
    assert!(b.export().is_empty());
    assert!(b.carry(M, EpochId(4), &mut rng).unwrap().is_none());
}

#[test]
fn import_checks_every_record_before_keeping_any() {
    let keys = keys();
    let a = CarryingCover::new(keys.clone(), params(), false);
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for _ in 0..2 {
        a.cover(M, EpochId(1), &mut rng).unwrap();
    }
    let good = a.export();
    let (c0, r0) = good[0].clone();
    let (c1, _) = good[1].clone();

    let mut version = r0.clone();
    version[0] = 2;
    let mut later_first = r0.clone();
    later_first[1..9].copy_from_slice(&5u64.to_le_bytes());
    let mut signed = r0.clone();
    signed[17 + 1 + 32] = 1;
    let bad = [
        (c1, r0.clone()),
        (c0, r0[..r0.len() - 1].to_vec()),
        (c0, [r0.clone(), vec![0]].concat()),
        (c0, version),
        (c0, later_first),
        (c0, signed),
    ];
    let b = CarryingCover::new(keys, params(), false);
    for (c, record) in bad {
        assert!(b.import(vec![good[1].clone(), (c, record)]).is_err());
        assert!(b.export().is_empty(), "nothing kept from a refused import");
    }
    b.import(good.clone()).unwrap();
    assert_eq!(b.export(), good);
}

#[test]
fn masked_markets_get_masked_no_ops() {
    let keys = keys();
    let cover = CarryingCover::new(keys, params(), true);
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let (env, masked) = cover.cover(M, EpochId(1), &mut rng).unwrap();
    let masked = masked.unwrap();
    assert_eq!(masked.commitment, env.commitment);
    assert_eq!(masked.body, MaskedBody::Noop);
    let (again, masked) = cover.carry(M, EpochId(2), &mut rng).unwrap().unwrap();
    assert_eq!(again.commitment, env.commitment);
    assert_eq!(masked.unwrap().epoch, EpochId(2));
}

/// With `carry_p = 1` every cover slot reuses a no-op of the previous
/// epoch while the run lasts. Then cover starts over.
#[test]
fn relay_carries_cover_for_at_most_an_order_lifetime() {
    let keys = keys();
    let mut r = Relay::new(
        config(1.0),
        Arc::new(Keypair::from_seed([0x7e; 32])),
        Box::new(CarryingCover::new(keys.clone(), params(), false)),
    );
    let mut batches = Vec::new();
    for e in 1..=4u64 {
        r.open_epoch_v2(window(e), Tick(50), Hash32::ZERO, Hash32([0xb1; 32]))
            .unwrap();
        r.close(100 * (e + 1)).unwrap();
        let c = r.take_closed().unwrap();
        assert_eq!((c.real, c.cover), (0, 4));
        assert!(
            c.envelopes
                .iter()
                .all(|env| opens(&keys, env) == IntentBody::Noop)
        );
        batches.push(c);
    }
    assert_eq!(commitments(&batches[0]), commitments(&batches[1]));
    assert_eq!(commitments(&batches[1]), commitments(&batches[2]));
    assert!(commitments(&batches[3]).is_disjoint(&commitments(&batches[2])));
    // Same commitments, new envelopes.
    assert!(
        batches[0]
            .leaves
            .iter()
            .all(|l| !batches[1].leaves.contains(l))
    );
}

/// Somebody submits an envelope under a commitment that was cover last
/// epoch. The relay then does not carry that no-op into the same batch.
#[test]
fn carried_cover_never_repeats_a_submitted_commitment() {
    let keys = keys();
    let mut r = Relay::new(
        config(1.0),
        Arc::new(Keypair::from_seed([0x7e; 32])),
        Box::new(CarryingCover::new(keys, params(), false)),
    );
    r.open_epoch_v2(window(1), Tick(50), Hash32::ZERO, Hash32([0xb1; 32]))
        .unwrap();
    r.close(200).unwrap();
    let first = r.take_closed().unwrap();
    let target = first.envelopes[0].commitment;

    r.open_epoch_v2(window(2), Tick(50), Hash32::ZERO, Hash32([0xb1; 32]))
        .unwrap();
    let probe = SealedEnvelope {
        version: PROTOCOL_VERSION,
        market: M,
        epoch: EpochId(2),
        commitment: target,
        ephemeral: [1; 32],
        ciphertext: [0; CIPHERTEXT_LEN],
    };
    let s = Submission::sign(&TraderKey::from_seed([5; 32]), probe, None);
    r.submit_verified(
        250,
        verify_submission(&config(1.0), &s).unwrap(),
        [0xa5; 32],
    )
    .unwrap();
    r.close(300).unwrap();
    let second = r.take_closed().unwrap();
    assert_eq!((second.real, second.cover), (1, 3));
    assert_eq!(
        second
            .envelopes
            .iter()
            .filter(|e| e.commitment == target)
            .count(),
        1
    );
}

/// Carrying is opt-in: without it, `CarryingCover` draws exactly what
/// `EpochKeyCover` draws from the same stream.
#[test]
fn carrying_cover_without_carry_is_plain_cover() {
    let keys = keys();
    let batch = |cover: Box<dyn CoverSource>| {
        let mut r = Relay::new_seeded(
            config(0.0),
            Arc::new(Keypair::from_seed([0x7e; 32])),
            Arc::new(InMemoryChain::new([0x5a; 32])),
            cover,
            [8; 32],
        );
        r.open_epoch_v2(window(1), Tick(50), Hash32::ZERO, Hash32([0xb1; 32]))
            .unwrap();
        r.close(200).unwrap().clone()
    };
    let plain = batch(Box::new(EpochKeyCover {
        keys: keys.clone(),
        params: params(),
        masked: false,
    }));
    let carrying = batch(Box::new(CarryingCover::new(keys, params(), false)));
    assert_eq!(plain, carrying);
}

/// A source that keeps no carried set (`EpochKeyCover`) uses the provided
/// `carry`, `export` and `import`: the relay asks it to carry for every slot
/// and falls back to fresh cover.
#[test]
fn sources_without_a_carried_set_give_fresh_cover() {
    let keys = keys();
    let plain = EpochKeyCover {
        keys: keys.clone(),
        params: params(),
        masked: false,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    plain.cover(M, EpochId(1), &mut rng).unwrap();
    assert!(plain.carry(M, EpochId(2), &mut rng).unwrap().is_none());
    assert!(plain.export().is_empty());
    let record = CarryingCover::new(keys.clone(), params(), false);
    record.cover(M, EpochId(1), &mut rng).unwrap();
    plain.import(record.export()).unwrap();
    assert!(plain.export().is_empty());

    let mut r = Relay::new(
        config(1.0),
        Arc::new(Keypair::from_seed([0x7e; 32])),
        Box::new(plain),
    );
    let mut seen = BTreeSet::new();
    for e in 1..=2u64 {
        r.open_epoch_v2(window(e), Tick(50), Hash32::ZERO, Hash32([0xb1; 32]))
            .unwrap();
        r.close(100 * (e + 1)).unwrap();
        let c = r.take_closed().unwrap();
        assert_eq!((c.real, c.cover), (0, 4));
        assert!(
            c.envelopes
                .iter()
                .all(|env| opens(&keys, env) == IntentBody::Noop)
        );
        for env in &c.envelopes {
            assert!(seen.insert(env.commitment), "fresh every epoch");
        }
    }
}
