//! The plaintext pipeline on version 1 and version 2 headers: header
//! checks, the order seed, provenance admission and the list of envelopes
//! that did not authenticate.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_auction::collateral::{Balance, BalanceSheet};
use timescales_auction::orderbook::{Disposition, OrderStateTable, RejectReason};
use timescales_auction::{BatchHeader, BatchLeaf, batch_leaves, canonical_order, epoch_seed};
use timescales_core::crypto::{EpochSecret, ScalarSealSecret, SealSecret};
use timescales_core::identity::{ExecutorKey, TraderKey};
use timescales_core::intent::{Cancel, PrivateIntent, SealedEnvelope};
use timescales_core::{
    BaseAtoms, CommitmentScheme, EpochId, FeeBps, FlowMode, Hash32, Lots, MarketId, MarketParams,
    Order, OrderCommitment, OrderKind, QuoteAtoms, Rationing, Role, Side, Tick, TraderId,
};
use timescales_executor::{
    ExecutionBatch, ExecutionMetrics, ExecutorError, KeyProvider, LocalKeySchedule,
    ReferenceExecutor, check_header, check_header_commitments, execute_opened, open_envelopes,
    order_seed, spawn_blocking,
};

const EPOCH: EpochId = EpochId(5);
const REFERENCE: Tick = Tick(100);
const ADDRESS: [u8; 32] = [0xad; 32];

fn params() -> MarketParams {
    let p = MarketParams {
        market: MarketId(7),
        base_lot_size: 1_000,
        tick_size: 100,
        band_half_width: 3,
        max_order_lots_log2: 20,
        max_orders_per_trader: 4,
        max_batch_envelopes: 1024,
        max_order_lifetime: 8,
        maker_fee: FeeBps(5),
        taker_fee: FeeBps(10),
        flow: FlowMode::SingleBook,
        rationing: Rationing::Lottery,
        commitment_scheme: CommitmentScheme::Sha256,
    };
    p.validate().unwrap();
    p
}

fn trader(i: u8) -> TraderKey {
    TraderKey::from_seed([i; 32])
}

fn order(t: &TraderKey, nonce: u64, side: Side, limit: u64, qty: u64) -> Order {
    Order {
        market: params().market,
        trader: t.id(),
        nonce,
        side,
        role: Role::Taker,
        kind: OrderKind::Limit,
        limit: Tick(limit),
        quantity: Lots(qty),
        valid_from: EPOCH,
        expires_at: EPOCH,
    }
}

/// Envelopes for: a buy by trader 1, a sell by trader 2, a cancel by
/// trader 3, cover, and a sell by trader 4, who has no funds.
struct Flow {
    envelopes: Vec<SealedEnvelope>,
    traders: Vec<Option<TraderId>>,
    balances: BalanceSheet,
}

fn flow(rng: &mut ChaCha20Rng, pk: &[u8; 32]) -> Flow {
    let p = params();
    let s = p.commitment_scheme;
    let intents: Vec<(PrivateIntent, OrderCommitment)> = vec![
        PrivateIntent::place(rng, &trader(1), s, order(&trader(1), 1, Side::Buy, 101, 5)).unwrap(),
        PrivateIntent::place(rng, &trader(2), s, order(&trader(2), 1, Side::Sell, 99, 5)).unwrap(),
        PrivateIntent::cancel(
            rng,
            &trader(3),
            s,
            Cancel {
                market: p.market,
                trader: trader(3).id(),
                nonce: 9,
                target: OrderCommitment([3; 32]),
                epoch: EPOCH,
            },
        )
        .unwrap(),
        PrivateIntent::noop(rng, s).unwrap(),
        PrivateIntent::place(rng, &trader(4), s, order(&trader(4), 1, Side::Sell, 98, 2)).unwrap(),
    ];
    let envelopes = intents
        .iter()
        .map(|(pi, c)| SealedEnvelope::seal(rng, p.market, EPOCH, pk, *c, pi).unwrap())
        .collect();
    let funded = Balance {
        base: BaseAtoms(1 << 40),
        quote: QuoteAtoms(1 << 40),
    };
    Flow {
        envelopes,
        traders: vec![
            Some(trader(1).id()),
            Some(trader(2).id()),
            Some(trader(3).id()),
            None,
            Some(trader(4).id()),
        ],
        balances: (1..=3).map(|i| (trader(i).id(), funded)).collect(),
    }
}

fn batch(version: u8, envelopes: Vec<SealedEnvelope>, balances: BalanceSheet) -> ExecutionBatch {
    let p = params();
    let band = p.band(REFERENCE).unwrap();
    let prior = OrderStateTable::default();
    let header = if version == 1 {
        let commitments: Vec<_> = envelopes.iter().map(|e| e.commitment).collect();
        BatchHeader::assemble(
            p,
            EPOCH,
            band,
            Hash32([0x9c; 32]),
            &commitments,
            Hash32([0xbe; 32]),
            prior.root(),
            balances.root(),
            Hash32::ZERO,
        )
    } else {
        BatchHeader::assemble_v2(
            p,
            EPOCH,
            band,
            Hash32([0xb1; 32]),
            &batch_leaves(&envelopes),
            Hash32([0xbe; 32]),
            prior.root(),
            balances.root(),
            Hash32::ZERO,
        )
    };
    ExecutionBatch {
        header,
        envelopes,
        masked: Vec::new(),
        balances,
        prior_state: prior,
    }
}

fn dev_key(seed: u8) -> SealSecret {
    SealSecret::from_bytes([seed; 32])
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(17)
}

#[test]
fn version_2_root_binds_the_envelope_bytes() {
    let key = dev_key(1);
    let f = flow(&mut rng(), &key.public());
    let b = batch(2, f.envelopes.clone(), f.balances.clone());
    assert!(check_header(&b.header, &b.envelopes, &b.balances, &b.prior_state).is_ok());

    // The same commitment in a different envelope (a substituted payload)
    // changes the leaf and so the root.
    let mut swapped = b.envelopes.clone();
    let (pi, _) = PrivateIntent::noop(&mut rng(), params().commitment_scheme).unwrap();
    let substitute = SealedEnvelope::seal(
        &mut rng(),
        params().market,
        EPOCH,
        &key.public(),
        swapped[0].commitment,
        &pi,
    )
    .unwrap();
    assert_ne!(BatchLeaf::of(&substitute), BatchLeaf::of(&swapped[0]));
    swapped[0] = substitute;
    assert_eq!(
        check_header(&b.header, &swapped, &b.balances, &b.prior_state),
        Err(ExecutorError::BadHeader("batch root"))
    );

    // A version 2 header over the version 1 root does not pass.
    let v1 = batch(1, f.envelopes.clone(), f.balances.clone());
    let mut forged = b.header;
    forged.batch_root = v1.header.batch_root;
    assert_eq!(
        check_header(&forged, &b.envelopes, &b.balances, &b.prior_state),
        Err(ExecutorError::BadHeader("batch root"))
    );
    // Commitments alone cannot check a version 2 header.
    let commitments: Vec<_> = b.envelopes.iter().map(|e| e.commitment).collect();
    assert!(matches!(
        check_header_commitments(&b.header, &commitments, &b.balances, &b.prior_state),
        Err(ExecutorError::BadHeader(_))
    ));
}

#[test]
fn unknown_versions_and_foreign_markets_are_refused() {
    let f = flow(&mut rng(), &dev_key(1).public());
    let b = batch(2, f.envelopes, f.balances);
    let mut h = b.header;
    h.version = 3;
    assert_eq!(
        check_header(&h, &b.envelopes, &b.balances, &b.prior_state),
        Err(ExecutorError::BadHeader("header version"))
    );
    let mut h = b.header;
    h.market = MarketId(8);
    assert_eq!(
        check_header(&h, &b.envelopes, &b.balances, &b.prior_state),
        Err(ExecutorError::BadHeader("market"))
    );
    let mut h = b.header;
    h.envelope_count += 1;
    assert_eq!(
        check_header(&h, &b.envelopes, &b.balances, &b.prior_state),
        Err(ExecutorError::BadHeader("envelope count"))
    );
}

#[test]
fn order_seed_of_version_2_needs_the_epoch_secret_and_the_address() {
    let key = dev_key(1);
    let f = flow(&mut rng(), &key.public());
    let v1 = batch(1, f.envelopes.clone(), f.balances.clone());
    let v2 = batch(2, f.envelopes, f.balances);
    let dev = EpochSecret::Dev(dev_key(1));
    // Version 1 ignores both.
    assert_eq!(order_seed(&v1.header, &dev, &ADDRESS), v1.header.seed());
    assert_eq!(order_seed(&v1.header, &dev, &[0; 32]), v1.header.seed());

    let expected = v2
        .header
        .seed_v2(&epoch_seed(&key.to_bytes(), &ADDRESS, EPOCH));
    assert_eq!(order_seed(&v2.header, &dev, &ADDRESS), expected);
    assert_ne!(expected, v2.header.seed());
    assert_ne!(order_seed(&v2.header, &dev, &[0; 32]), expected);
    assert_ne!(
        order_seed(&v2.header, &EpochSecret::Dev(dev_key(2)), &ADDRESS),
        expected
    );
    // A threshold secret mixes in its scalar.
    let scalar = ScalarSealSecret::from_x25519(&key);
    let threshold_seed =
        v2.header
            .seed_v2(&epoch_seed(&scalar.scalar().to_bytes(), &ADDRESS, EPOCH));
    assert_eq!(
        order_seed(&v2.header, &EpochSecret::Threshold(scalar), &ADDRESS),
        threshold_seed
    );
}

#[test]
fn version_2_executes_in_the_order_of_the_secret_seed() {
    let key = dev_key(1);
    let f = flow(&mut rng(), &key.public());
    let b = batch(2, f.envelopes, f.balances);
    let secret = EpochSecret::Threshold(ScalarSealSecret::from_x25519(&key));
    let band = check_header(&b.header, &b.envelopes, &b.balances, &b.prior_state).unwrap();
    let seed = order_seed(&b.header, &secret, &ADDRESS);
    let opened = open_envelopes(&secret, params().commitment_scheme, &b.envelopes);
    let plain =
        execute_opened(&b, &band, &seed, opened, None, ExecutionMetrics::default()).unwrap();
    let expected: Vec<_> = canonical_order(&seed, &b.envelopes)
        .into_iter()
        .map(|(i, _)| b.envelopes[i].commitment)
        .collect();
    let got: Vec<_> = plain.candidates.iter().map(|c| c.commitment).collect();
    assert_eq!(got, expected);
    assert!(plain.artifacts.fills.len() >= 2, "the buy and a sell trade");
}

#[test]
fn provenance_rejects_intents_their_trader_did_not_submit() {
    let key = dev_key(1);
    let f = flow(&mut rng(), &key.public());
    let b = batch(1, f.envelopes, f.balances);
    let secret = EpochSecret::Dev(dev_key(1));
    let band = check_header(&b.header, &b.envelopes, &b.balances, &b.prior_state).unwrap();
    let seed = order_seed(&b.header, &secret, &ADDRESS);
    let run = |admission: Option<&[Option<TraderId>]>| {
        let opened = open_envelopes(&secret, params().commitment_scheme, &b.envelopes);
        execute_opened(
            &b,
            &band,
            &seed,
            opened,
            admission,
            ExecutionMetrics::default(),
        )
        .unwrap()
    };
    let disposition = |plain: &timescales_executor::PlainExecution, i: usize| {
        plain
            .validated
            .dispositions
            .iter()
            .find(|(c, _)| *c == b.envelopes[i].commitment)
            .map(|(_, d)| *d)
            .unwrap()
    };

    // Everyone submitted their own intents: only trader 4's unfunded sell is
    // rejected, for collateral, which is not an authentication failure.
    let honest = run(Some(&f.traders));
    assert!(honest.metrics.unauthenticated.is_empty());
    assert_eq!(
        disposition(&honest, 4),
        Disposition::Rejected(RejectReason::InsufficientCollateral)
    );
    assert_eq!(honest.outcome, run(None).outcome);

    // Trader 1's buy submitted under trader 2's grant, trader 3's cancel
    // submitted as cover: both rejected like bad signatures. Cover passes
    // whatever the admission says.
    let mut admission = f.traders.clone();
    admission[0] = Some(trader(2).id());
    admission[2] = None;
    admission[3] = Some(trader(1).id());
    let plain = run(Some(&admission));
    assert_eq!(plain.metrics.unauthenticated, vec![0, 2]);
    for i in [0, 2] {
        assert_eq!(
            disposition(&plain, i),
            Disposition::Rejected(RejectReason::BadSignature)
        );
    }
    assert_eq!(disposition(&plain, 3), Disposition::Noop);
    assert!(plain.artifacts.fills.is_empty(), "the only buy was refused");
}

#[test]
fn envelopes_that_do_not_open_are_unauthenticated() {
    let key = dev_key(1);
    let mut f = flow(&mut rng(), &key.public());
    // Sealed to another key, and a flipped ciphertext bit.
    let (pi, c) = PrivateIntent::place(
        &mut rng(),
        &trader(5),
        params().commitment_scheme,
        order(&trader(5), 1, Side::Buy, 100, 1),
    )
    .unwrap();
    f.envelopes.push(
        SealedEnvelope::seal(
            &mut rng(),
            params().market,
            EPOCH,
            &dev_key(9).public(),
            c,
            &pi,
        )
        .unwrap(),
    );
    f.envelopes[1].ciphertext[0] ^= 1;
    let b = batch(1, f.envelopes, f.balances);
    let secret = EpochSecret::Dev(dev_key(1));
    let band = check_header(&b.header, &b.envelopes, &b.balances, &b.prior_state).unwrap();
    let opened = open_envelopes(&secret, params().commitment_scheme, &b.envelopes);
    let plain = execute_opened(
        &b,
        &band,
        &b.header.seed(),
        opened,
        None,
        ExecutionMetrics::default(),
    )
    .unwrap();
    assert_eq!(plain.metrics.unauthenticated, vec![1, 5]);
}

#[test]
fn mismatched_lengths_are_errors() {
    let f = flow(&mut rng(), &dev_key(1).public());
    let b = batch(1, f.envelopes, f.balances);
    let secret = EpochSecret::Dev(dev_key(1));
    let band = check_header(&b.header, &b.envelopes, &b.balances, &b.prior_state).unwrap();
    let mut opened = open_envelopes(&secret, params().commitment_scheme, &b.envelopes);
    let short = vec![None; b.envelopes.len() - 1];
    assert!(matches!(
        execute_opened(
            &b,
            &band,
            &b.header.seed(),
            open_envelopes(&secret, params().commitment_scheme, &b.envelopes),
            Some(&short),
            ExecutionMetrics::default()
        ),
        Err(ExecutorError::Execution(_))
    ));
    opened.pop();
    assert!(matches!(
        execute_opened(
            &b,
            &band,
            &b.header.seed(),
            opened,
            None,
            ExecutionMetrics::default()
        ),
        Err(ExecutorError::Execution(_))
    ));
}

/// A key provider holding one epoch secret in threshold form, like an
/// enclave after reconstruction.
struct ThresholdKey(SealSecret);

impl KeyProvider for ThresholdKey {
    fn epoch_public(&self, _: MarketId, _: EpochId) -> Result<[u8; 32], ExecutorError> {
        Ok(self.0.public())
    }
    fn epoch_secret(&self, _: MarketId, _: EpochId) -> Result<SealSecret, ExecutorError> {
        Ok(SealSecret::from_bytes(self.0.to_bytes()))
    }
    fn epoch_key(&self, _: MarketId, _: EpochId) -> Result<EpochSecret, ExecutorError> {
        Ok(EpochSecret::Threshold(ScalarSealSecret::from_x25519(
            &self.0,
        )))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reference_executor_needs_the_address_for_version_2() {
    let key = dev_key(1);
    let f = flow(&mut rng(), &key.public());
    let b = Arc::new(batch(2, f.envelopes, f.balances));
    let exec = || {
        ReferenceExecutor::new(
            Arc::new(ThresholdKey(dev_key(1))),
            ExecutorKey::from_seed([2; 32]),
        )
    };
    assert!(matches!(
        exec().execute_shared(Arc::clone(&b)).await,
        Err(ExecutorError::KeyUnavailable(_))
    ));
    let here = exec()
        .with_market_address(ADDRESS)
        .execute_shared(Arc::clone(&b))
        .await
        .unwrap();
    let elsewhere = exec()
        .with_market_address([0xae; 32])
        .execute_shared(Arc::clone(&b))
        .await
        .unwrap();
    here.receipt.verify_signature().unwrap();
    // The canonical order is part of the trace, and the seed differs.
    assert_ne!(here.receipt.trace, elsewhere.receipt.trace);
    let blocking = exec()
        .with_market_address(ADDRESS)
        .execute_admitted(&b, None)
        .unwrap();
    assert_eq!(blocking.receipt.outcome, here.receipt.outcome);
    assert!(blocking.metrics.unauthenticated.is_empty());
}

#[test]
fn local_key_schedule_hands_out_dev_keys_and_no_commitments() {
    let keys = LocalKeySchedule::new([3; 32]);
    let m = MarketId(1);
    let pk = keys.epoch_public(m, EPOCH).unwrap();
    assert_eq!(keys.epoch_secret(m, EPOCH).unwrap().public(), pk);
    assert!(
        matches!(keys.epoch_key(m, EPOCH).unwrap(), EpochSecret::Dev(ref s) if s.public() == pk)
    );
    assert_ne!(keys.epoch_public(m, EpochId(6)).unwrap(), pk);
    assert!(keys.epoch_commitments(m, EPOCH).unwrap().is_empty());
    assert_eq!(format!("{keys:?}"), "LocalKeySchedule(..)");
}

#[tokio::test]
async fn blocking_tasks_report_panics_as_execution_errors() {
    assert_eq!(spawn_blocking(|| Ok(7)).await, Ok(7));
    let r: Result<(), ExecutorError> = spawn_blocking(|| panic!("boom")).await;
    assert!(matches!(r, Err(ExecutorError::Execution(_))));
}
