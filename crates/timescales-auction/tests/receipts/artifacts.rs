//! `check_against`, `check_settlement` and the co-signature digest.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_auction::receipts::{
    BackendKind, ExecutionArtifacts, ExecutionOutcome, ExecutionReceipt, MAX_CLEARING_PRICES,
    ReceiptError, commitments_root, cosign_digest, fills_root,
};
use timescales_auction::settlement::{AccountDelta, SettlementBatch, settle};
use timescales_core::crypto::{Hasher, domain};
use timescales_core::identity::ExecutorKey;
use timescales_core::{
    BookId, ClearingPrice, CommitmentScheme, Decode, Encode, EpochId, FeeBps, Fill, FlowMode,
    Hash32, Lots, MAX_SETTLEMENT_DELTAS, MarketId, MarketParams, OrderCommitment, QuoteAtoms,
    Rationing, Role, Side, Tick, TraderId,
};

fn params() -> MarketParams {
    MarketParams {
        market: MarketId(1),
        base_lot_size: 1_000,
        tick_size: 7,
        band_half_width: 5,
        max_order_lots_log2: 20,
        max_orders_per_trader: 8,
        max_batch_envelopes: 1024,
        max_order_lifetime: 1,
        maker_fee: FeeBps(2),
        taker_fee: FeeBps(25),
        flow: FlowMode::SingleBook,
        rationing: Rationing::Lottery,
        commitment_scheme: CommitmentScheme::Sha256,
    }
}

fn fill(t: u8, side: Side, role: Role, q: u64) -> Fill {
    Fill {
        commitment: OrderCommitment([t; 32]),
        trader: TraderId([t; 32]),
        book: BookId::Single,
        side,
        role,
        quantity: Lots(q),
        tick: Tick(100),
    }
}

/// Artifacts of a small trade and the outcome that commits to them.
fn executed() -> (ExecutionArtifacts, ExecutionOutcome) {
    let fills = vec![
        fill(1, Side::Sell, Role::Maker, 3),
        fill(2, Side::Buy, Role::Taker, 2),
        fill(3, Side::Buy, Role::Taker, 1),
    ];
    let settlement = settle(&params(), EpochId(9), &fills).expect("settles");
    let artifacts = ExecutionArtifacts {
        fills,
        cancelled: vec![OrderCommitment([8; 32])],
        settlement,
    };
    let outcome = outcome_for(&artifacts);
    (artifacts, outcome)
}

fn outcome_for(a: &ExecutionArtifacts) -> ExecutionOutcome {
    ExecutionOutcome {
        market: MarketId(1),
        epoch: EpochId(9),
        header_digest: Hash32([5; 32]),
        clearing: vec![ClearingPrice {
            book: BookId::Single,
            tick: Tick(100),
            volume: Lots(3),
        }],
        fill_count: u32::try_from(a.fills.len()).expect("small"),
        fills_root: fills_root(&a.fills),
        cancelled_root: commitments_root(&a.cancelled),
        next_state_root: Hash32::ZERO,
        settlement_count: u32::try_from(a.settlement.deltas.len()).expect("small"),
        settlement_root: a.settlement.root(),
        fees: a.settlement.fees,
    }
}

#[test]
fn honest_artifacts_pass_both_checks() {
    let (a, o) = executed();
    assert_eq!(a.check_against(&o), Ok(()));
    assert_eq!(a.check_settlement(&params(), EpochId(9)), Ok(()));
}

#[test]
fn check_against_enforces_program_limits() {
    let (a, o) = executed();
    let mut many_books = o.clone();
    let price = many_books.clearing[0];
    many_books.clearing = vec![price; MAX_CLEARING_PRICES + 1];
    assert_eq!(
        a.check_against(&many_books),
        Err(ReceiptError::Limit("clearing prices"))
    );
    let mut two = o.clone();
    two.clearing = vec![price; MAX_CLEARING_PRICES];
    assert_eq!(a.check_against(&two), Ok(()));

    let mut many_deltas = o;
    many_deltas.settlement_count = MAX_SETTLEMENT_DELTAS + 1;
    assert_eq!(
        a.check_against(&many_deltas),
        Err(ReceiptError::Limit("settlement deltas"))
    );
}

#[test]
fn check_against_binds_the_settlement_to_the_batch() {
    let (a, o) = executed();
    for (market, epoch) in [(MarketId(2), EpochId(9)), (MarketId(1), EpochId(8))] {
        let mut moved = a.clone();
        moved.settlement.market = market;
        moved.settlement.epoch = epoch;
        // The roots do not cover market and epoch. The explicit check does.
        assert_eq!(moved.settlement.root(), a.settlement.root());
        assert_eq!(
            moved.check_against(&o),
            Err(ReceiptError::Mismatch("settlement batch"))
        );
    }
}

#[test]
fn check_against_refuses_non_canonical_settlements() {
    let (mut a, _) = executed();
    // A batch that conserves both assets but lists one trader twice. Its
    // outcome commits to it faithfully.
    let t = TraderId([4; 32]);
    a.settlement = SettlementBatch {
        market: MarketId(1),
        epoch: EpochId(9),
        deltas: vec![
            AccountDelta {
                trader: t,
                base: -5,
                quote: 7,
            },
            AccountDelta {
                trader: t,
                base: 5,
                quote: -7,
            },
        ],
        fees: QuoteAtoms(0),
    };
    let o = outcome_for(&a);
    assert_eq!(
        a.check_against(&o),
        Err(ReceiptError::Mismatch("settlement order"))
    );
}

#[test]
fn check_settlement_recomputes_from_the_fills() {
    let (a, o) = executed();
    // Fills changed together with their root: check_against cannot tell,
    // the recomputation can.
    let mut more = a.clone();
    more.fills[1].quantity = Lots(3);
    more.fills[0].quantity = Lots(4);
    let o2 = ExecutionOutcome {
        fills_root: fills_root(&more.fills),
        ..o.clone()
    };
    assert_eq!(more.check_against(&o2), Ok(()));
    assert_eq!(
        more.check_settlement(&params(), EpochId(9)),
        Err(ReceiptError::Mismatch("settlement of the fills"))
    );

    // Deltas moved between traders while conserving: only the
    // recomputation notices.
    let mut moved = a.clone();
    moved.settlement.deltas[1].quote -= 1;
    moved.settlement.deltas[2].quote += 1;
    assert_eq!(moved.settlement.check_conservation(), Ok(()));
    assert_eq!(moved.check_against(&outcome_for(&moved)), Ok(()));
    assert!(moved.check_settlement(&params(), EpochId(9)).is_err());

    // Other fees, another market or another epoch.
    let mut fees = params();
    fees.taker_fee = FeeBps(30);
    assert!(a.check_settlement(&fees, EpochId(9)).is_err());
    let mut market = params();
    market.market = MarketId(2);
    assert!(a.check_settlement(&market, EpochId(9)).is_err());
    assert!(a.check_settlement(&params(), EpochId(10)).is_err());

    // Fills that cannot be settled at all.
    let mut huge = a;
    huge.fills[0].quantity = Lots(u64::MAX);
    assert!(huge.check_settlement(&params(), EpochId(9)).is_err());
}

/// `H(RECEIPT_COSIGN, market32 || epoch u64 || header digest || outcome
/// digest)`, checked against a digest computed independently (Python
/// `hashlib`) for fixed inputs.
#[test]
fn cosign_digest_known_answer() {
    let d = cosign_digest(
        &[0x11; 32],
        EpochId(7),
        &Hash32([0x22; 32]),
        &Hash32([0x33; 32]),
    );
    assert_eq!(
        Some(d),
        Hash32::from_hex("19d6ca120941525b11ce0c5fc671c0965d287ff9515d80f0833bacdbef78df8e")
    );
    let mut framed = vec![0x11; 32];
    framed.extend_from_slice(&7u64.to_le_bytes());
    framed.extend_from_slice(&[0x22; 32]);
    framed.extend_from_slice(&[0x33; 32]);
    assert_eq!(
        d,
        Hasher::new(domain::RECEIPT_COSIGN)
            .chain(&framed)
            .finalize()
    );
}

#[test]
fn cosign_digest_binds_every_input() {
    let base = cosign_digest(&[1; 32], EpochId(2), &Hash32([3; 32]), &Hash32([4; 32]));
    let variants = [
        cosign_digest(&[9; 32], EpochId(2), &Hash32([3; 32]), &Hash32([4; 32])),
        cosign_digest(&[1; 32], EpochId(3), &Hash32([3; 32]), &Hash32([4; 32])),
        cosign_digest(&[1; 32], EpochId(2), &Hash32([9; 32]), &Hash32([4; 32])),
        cosign_digest(&[1; 32], EpochId(2), &Hash32([3; 32]), &Hash32([9; 32])),
        // Header and outcome swapped.
        cosign_digest(&[1; 32], EpochId(2), &Hash32([4; 32]), &Hash32([3; 32])),
    ];
    for v in variants {
        assert_ne!(v, base);
    }
    // Distinct from the receipt's own signing digest domain.
    assert_ne!(
        base,
        Hasher::new(domain::RECEIPT)
            .chain(&[1; 32])
            .chain(&2u64.to_le_bytes())
            .chain(&[3; 32])
            .chain(&[4; 32])
            .finalize()
    );
}

#[test]
fn minimum_encoded_lengths() {
    let (a, mut o) = executed();
    o.clearing.clear();
    assert_eq!(o.to_bytes().len(), ExecutionOutcome::MIN_ENCODED_LEN);
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let key = ExecutorKey::generate(&mut rng);
    let r = ExecutionReceipt::sign(
        &key,
        o,
        BackendKind::Tee,
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
    );
    assert_eq!(r.to_bytes().len(), ExecutionReceipt::MIN_ENCODED_LEN);
    let empty = ExecutionArtifacts {
        fills: Vec::new(),
        cancelled: Vec::new(),
        settlement: SettlementBatch {
            market: MarketId(1),
            epoch: EpochId(9),
            deltas: Vec::new(),
            fees: QuoteAtoms(0),
        },
    };
    assert_eq!(empty.to_bytes().len(), ExecutionArtifacts::MIN_ENCODED_LEN);
    assert_eq!(ExecutionArtifacts::decode_exact(&a.to_bytes()), Ok(a));
}

#[test]
fn every_receipt_error_is_produced() {
    // Exhaustive on purpose: a new variant must be produced here.
    fn variant(e: &ReceiptError) -> usize {
        match e {
            ReceiptError::BadSignature => 0,
            ReceiptError::Mismatch(_) => 1,
            ReceiptError::Version(_) => 2,
            ReceiptError::Limit(_) => 3,
        }
    }
    let (a, o) = executed();
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let key = ExecutorKey::generate(&mut rng);
    let r = ExecutionReceipt::sign(
        &key,
        o.clone(),
        BackendKind::Reference,
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
    );
    let mut forged = r.clone();
    forged.signature.0[0] ^= 1;
    let mut v2 = r;
    v2.version = 2;
    let mut wide = o.clone();
    wide.settlement_count = MAX_SETTLEMENT_DELTAS + 1;
    let errors = [
        forged.verify_signature(),
        a.check_settlement(&params(), EpochId(1)),
        v2.verify_signature(),
        a.check_against(&wide),
    ];
    let seen: Vec<usize> = errors
        .iter()
        .map(|e| variant(e.as_ref().unwrap_err()))
        .collect();
    assert_eq!(seen, [0, 1, 2, 3]);
}
