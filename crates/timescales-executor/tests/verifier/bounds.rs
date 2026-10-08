//! Untrusted bundles cannot make the verifier allocate for a capacity the
//! key was not built for, and receipt-supplied clearing ticks cannot
//! underflow. Every `VerifyError` variant, `Invalid` included, is reachable
//! without the prover.

use ark_bn254::g1::{G1_GENERATOR_X, G1_GENERATOR_Y};
use ark_bn254::g2::{G2_GENERATOR_X, G2_GENERATOR_Y};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_groth16::{Proof, VerifyingKey};
use timescales_auction::BatchHeader;
use timescales_auction::orderbook::OrderStateTable;
use timescales_auction::receipts::ExecutionArtifacts;
use timescales_core::{
    BookId, ClearingPrice, CommitmentScheme, Decode, EpochId, FeeBps, FlowMode, Hash32, Lots,
    MarketId, MarketParams, OrderCommitment, Rationing, Tick,
};
use timescales_executor::verifier::{
    CircuitShape, MAX_CAPACITY, ProofBundle, ShapedVerifyingKey, VerifyError, encode_proof,
    entries_from_public, verify_bundle,
};

fn params() -> MarketParams {
    MarketParams {
        market: MarketId(1),
        base_lot_size: 1,
        tick_size: 1,
        band_half_width: 2,
        max_order_lots_log2: 8,
        max_orders_per_trader: 4,
        max_batch_envelopes: 16,
        max_order_lifetime: 1,
        maker_fee: FeeBps(0),
        taker_fee: FeeBps(0),
        flow: FlowMode::SingleBook,
        rationing: Rationing::Lottery,
        commitment_scheme: CommitmentScheme::PoseidonBn254,
    }
}

fn header() -> BatchHeader {
    let p = params();
    BatchHeader::assemble(
        p,
        EpochId(1),
        p.band(Tick(100)).expect("band"),
        Hash32::ZERO,
        &[],
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
    )
}

/// Shape that fits `header`.
fn shape(capacity: usize) -> CircuitShape {
    CircuitShape {
        capacity,
        ticks: 5,
        qty_bits: 8,
        flow: FlowMode::SingleBook,
    }
}

/// Fills, cancels and settlement all empty: `u32 0 || u32 0 || market ||
/// epoch || u32 0 || fees`.
fn no_artifacts() -> ExecutionArtifacts {
    let mut b = vec![0u8; 8];
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&[0u8; 4 + 8]);
    ExecutionArtifacts::decode_exact(&b).expect("empty artifacts")
}

/// A structurally fitting key for a single-book shape. It proves nothing.
fn key(public_inputs: usize) -> VerifyingKey<Bn254> {
    VerifyingKey {
        gamma_abc_g1: vec![G1Affine::default(); public_inputs + 1],
        ..VerifyingKey::default()
    }
}

fn bundle(shape: CircuitShape) -> ProofBundle {
    ProofBundle {
        shape,
        admitted: Vec::new(),
        proof: vec![0u8; 128],
    }
}

fn bundle_bytes(capacity: u32, flags: &[u8]) -> Vec<u8> {
    let mut b = capacity.to_le_bytes().to_vec();
    b.extend_from_slice(&5u32.to_le_bytes());
    b.extend_from_slice(&[8, 0]);
    b.extend_from_slice(&u32::try_from(flags.len()).expect("few").to_le_bytes());
    b.extend_from_slice(flags);
    b.extend_from_slice(&[0u8; 128]);
    b
}

#[test]
fn from_bytes_bounds_the_capacity() {
    let max = u32::try_from(MAX_CAPACITY).expect("fits");
    let b = ProofBundle::from_bytes(&bundle_bytes(max, &[1, 0])).expect("at the bound");
    assert_eq!(b.shape.capacity, MAX_CAPACITY);
    assert_eq!(ProofBundle::from_bytes(&b.to_bytes()), Ok(b));
    for capacity in [max + 1, u32::MAX] {
        assert_eq!(
            ProofBundle::from_bytes(&bundle_bytes(capacity, &[])),
            Err(VerifyError::Malformed("bundle"))
        );
    }
    // More flags than capacity, and flags other than 0 or 1.
    assert!(ProofBundle::from_bytes(&bundle_bytes(1, &[0, 1])).is_err());
    assert!(ProofBundle::from_bytes(&bundle_bytes(4, &[2])).is_err());
}

#[test]
fn shaped_key_refuses_other_shapes_before_allocating() {
    let k = ShapedVerifyingKey::new(shape(8), key(4)).expect("fits");
    assert_eq!(k.shape(), &shape(8));
    assert_eq!(k.vk(), &key(4));
    let artifacts = no_artifacts();
    let prior = OrderStateTable::default();
    // A capacity no allocation could satisfy: refused before entries are
    // built for it.
    let wide = bundle(shape(1 << 40));
    assert_eq!(
        k.verify(&wide, &header(), &[], &prior, &artifacts, &[]),
        Err(VerifyError::Shape("bundle shape differs from the key's"))
    );
    let mut other = shape(8);
    other.qty_bits = 9;
    assert_eq!(
        k.verify(&bundle(other), &header(), &[], &prior, &artifacts, &[]),
        Err(VerifyError::Shape("bundle shape differs from the key's"))
    );
}

#[test]
fn shaped_key_must_fit_its_shape() {
    // Single book: transcript, lo, one (slot, volume) pair.
    assert!(ShapedVerifyingKey::new(shape(8), key(4)).is_ok());
    assert_eq!(
        ShapedVerifyingKey::new(shape(8), key(6)).map(|_| ()),
        Err(VerifyError::Malformed(
            "verifying key does not fit the shape"
        ))
    );
    let mut dual = shape(8);
    dual.flow = FlowMode::DualFlow;
    assert!(ShapedVerifyingKey::new(dual, key(6)).is_ok());
    assert_eq!(
        ShapedVerifyingKey::new(shape(MAX_CAPACITY + 1), key(4)).map(|_| ()),
        Err(VerifyError::Shape("capacity"))
    );
    assert!(matches!(
        ShapedVerifyingKey::from_bytes(shape(8), &[1, 2, 3]),
        Err(VerifyError::Malformed(_))
    ));
}

#[test]
fn verify_bundle_bounds_the_capacity_without_the_key() {
    let artifacts = no_artifacts();
    let prior = OrderStateTable::default();
    assert_eq!(
        verify_bundle(
            &key(4),
            &bundle(shape(1 << 40)),
            &header(),
            &[],
            &prior,
            &artifacts,
            &[]
        ),
        Err(VerifyError::Shape("capacity"))
    );
    assert_eq!(
        entries_from_public(&header(), &[], &prior, &[], &artifacts, MAX_CAPACITY + 1),
        Err(VerifyError::Shape("capacity"))
    );
}

#[test]
fn clearing_ticks_outside_the_band_are_refused() {
    let h = header();
    let artifacts = no_artifacts();
    let prior = OrderStateTable::default();
    for tick in [h.band.lo.0 - 1, 0, h.band.lo.0 + (1 << 33)] {
        let clearing = [ClearingPrice {
            book: BookId::Single,
            tick: Tick(tick),
            volume: Lots(1),
        }];
        assert_eq!(
            verify_bundle(
                &key(4),
                &bundle(shape(1)),
                &h,
                &[],
                &prior,
                &artifacts,
                &clearing
            ),
            Err(VerifyError::Shape("clearing tick outside the band"))
        );
    }
}

#[test]
fn commitments_must_be_field_elements() {
    let prior = OrderStateTable::default();
    assert_eq!(
        entries_from_public(
            &header(),
            &[OrderCommitment([0xff; 32])],
            &prior,
            &[true],
            &no_artifacts(),
            4,
        ),
        Err(VerifyError::Commitment)
    );
}

/// A well-formed proof that fails the pairing check against `key(4)`, whose
/// elements are all the identity: `e(A, B) = e != 1`.
fn false_proof() -> Vec<u8> {
    encode_proof(&Proof::<Bn254> {
        a: G1Affine::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y),
        b: G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y),
        c: G1Affine::default(),
    })
}

#[test]
fn every_verify_error_is_produced() {
    // Exhaustive on purpose: a new variant must be produced here.
    fn variant(e: &VerifyError) -> usize {
        match e {
            VerifyError::Invalid => 0,
            VerifyError::Malformed(_) => 1,
            VerifyError::Shape(_) => 2,
            VerifyError::Commitment => 3,
        }
    }
    let h = header();
    let artifacts = no_artifacts();
    let prior = OrderStateTable::default();
    let clearing = [ClearingPrice {
        book: BookId::Single,
        tick: Tick(h.band.lo.0 + 1),
        volume: Lots(0),
    }];
    let wrong = ProofBundle {
        proof: false_proof(),
        ..bundle(shape(1))
    };
    let errors = [
        verify_bundle(&key(4), &wrong, &h, &[], &prior, &artifacts, &clearing),
        ProofBundle::from_bytes(&[]).map(|_| ()),
        entries_from_public(&h, &[], &prior, &[true], &artifacts, 4).map(|_| ()),
        entries_from_public(
            &h,
            &[OrderCommitment([0xff; 32])],
            &prior,
            &[true],
            &artifacts,
            4,
        )
        .map(|_| ()),
    ];
    let seen: Vec<usize> = errors
        .iter()
        .map(|e| variant(e.as_ref().expect_err("every case fails")))
        .collect();
    assert_eq!(seen, [0, 1, 2, 3]);
}
