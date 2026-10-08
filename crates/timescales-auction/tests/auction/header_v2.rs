//! Envelope-bound batches: leaves, roots, header v2, binding, terms
//! and seeds. The pinned digests were computed independently (Python
//! hashlib) from the layouts and.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use proptest::prelude::*;
use timescales_auction::{
    BatchHeader, BatchLeaf, batch_leaves, batch_root, batch_root_v2, epoch_binding, epoch_seed,
    terms_digest,
};
use timescales_core::crypto::{domain, hash};
use timescales_core::intent::{CIPHERTEXT_LEN, SealedEnvelope};
use timescales_core::merkle::MerkleTree;
use timescales_core::{
    CommitmentScheme, Decode, DecodeError, Encode, EpochId, FeeBps, FlowMode,
    HEADER_VERSION_ENVELOPE_BOUND, Hash32, MarketId, MarketParams, OrderCommitment,
    PROTOCOL_VERSION, PriceBand, Rationing, Tick,
};

fn params() -> MarketParams {
    MarketParams {
        market: MarketId(1),
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

fn leaf(c: u8, d: u8) -> BatchLeaf {
    BatchLeaf {
        commitment: OrderCommitment([c; 32]),
        envelope_digest: Hash32([d; 32]),
    }
}

fn envelope(c: u8, tweak: u8) -> SealedEnvelope {
    let mut ciphertext = [0u8; CIPHERTEXT_LEN];
    ciphertext[0] = tweak;
    SealedEnvelope {
        version: PROTOCOL_VERSION,
        market: MarketId(1),
        epoch: EpochId(7),
        commitment: OrderCommitment([c; 32]),
        ephemeral: [c; 32],
        ciphertext,
    }
}

fn header_v2(leaves: &[BatchLeaf]) -> BatchHeader {
    let p = params();
    BatchHeader::assemble_v2(
        p,
        EpochId(7),
        p.band(Tick(50)).unwrap(),
        Hash32([0xb1; 32]),
        leaves,
        Hash32([0xbe; 32]),
        Hash32([0x5a; 32]),
        Hash32([0xba; 32]),
        Hash32([0x9e; 32]),
    )
}

#[test]
fn root_v2_is_the_merkle_root_of_sorted_leaf_bytes() {
    let leaves = [leaf(3, 9), leaf(1, 8), leaf(1, 7)];
    let root = batch_root_v2(&leaves);
    let sorted = [leaf(1, 7), leaf(1, 8), leaf(3, 9)].map(|l| l.to_bytes());
    assert_eq!(root, MerkleTree::from_data(&sorted).root());
    assert_eq!(
        root.to_hex(),
        "08f22ed9002f25313d2f995636911b2d47893fe3a6910bb487146fd1bcb16570"
    );

    for perm in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let shuffled = perm.map(|i| leaves[i]);
        assert_eq!(batch_root_v2(&shuffled), root);
    }
    // A substituted envelope is a different leaf, so a different root.
    assert_ne!(batch_root_v2(&[leaf(3, 9), leaf(1, 8), leaf(1, 6)]), root);
    // Dropping a leaf that shares its commitment with another changes it too.
    assert_ne!(batch_root_v2(&[leaf(3, 9), leaf(1, 8)]), root);
}

#[test]
fn leaves_of_envelopes_are_sorted_and_bind_every_byte() {
    let envs = [envelope(5, 0), envelope(2, 0), envelope(5, 1)];
    let leaves = batch_leaves(&envs);
    assert_eq!(leaves.len(), 3);
    assert!(leaves.windows(2).all(|w| w[0].to_bytes() < w[1].to_bytes()));
    for e in &envs {
        let l = BatchLeaf::of(e);
        assert_eq!(l.commitment, e.commitment);
        assert_eq!(l.envelope_digest, e.digest());
        assert_eq!(
            l.envelope_digest,
            hash(domain::ENVELOPE_COMMITMENT, &e.to_bytes())
        );
        assert!(leaves.contains(&l));
        assert_eq!(BatchLeaf::from_bytes(&l.to_bytes()), l);
    }
    // Same commitment, one ciphertext byte apart: two distinct leaves.
    assert_ne!(BatchLeaf::of(&envs[0]), BatchLeaf::of(&envs[2]));
}

proptest! {
    #[test]
    fn root_v2_ignores_arrival_order(
        (arrived, shuffled) in prop::collection::vec(any::<([u8; 32], [u8; 32])>(), 0..40)
            .prop_flat_map(|v| (Just(v.clone()), Just(v).prop_shuffle()))
    ) {
        let leaves = |v: Vec<([u8; 32], [u8; 32])>| -> Vec<BatchLeaf> {
            v.into_iter()
                .map(|(c, d)| BatchLeaf { commitment: OrderCommitment(c), envelope_digest: Hash32(d) })
                .collect()
        };
        prop_assert_eq!(batch_root_v2(&leaves(shuffled)), batch_root_v2(&leaves(arrived)));
    }

    #[test]
    fn leaf_order_is_byte_order(a in any::<[u8; 32]>(), b in any::<[u8; 32]>(),
                                c in any::<[u8; 32]>(), d in any::<[u8; 32]>()) {
        let x = BatchLeaf { commitment: OrderCommitment(a), envelope_digest: Hash32(b) };
        let y = BatchLeaf { commitment: OrderCommitment(c), envelope_digest: Hash32(d) };
        prop_assert_eq!(x.cmp(&y), x.to_bytes().cmp(&y.to_bytes()));
    }
}

#[test]
fn header_v2_carries_the_binding_where_the_program_reads_terms() {
    let leaves = [leaf(3, 9), leaf(1, 8)];
    let h = header_v2(&leaves);
    let bytes = h.to_bytes();
    assert_eq!(bytes.len(), 283);
    assert_eq!(bytes[0], HEADER_VERSION_ENVELOPE_BOUND);
    assert_eq!(&bytes[87..119], &[0xb1; 32]);
    assert_eq!(h.envelope_count, 2);
    assert_eq!(&bytes[119..123], &2u32.to_le_bytes());
    assert_eq!(h.batch_root, batch_root_v2(&leaves));
    assert_eq!(&bytes[123..155], h.batch_root.as_bytes());
    assert_eq!(&bytes[155..187], &[0xbe; 32]);
    assert_eq!(&bytes[187..219], &[0x5a; 32]);
    assert_eq!(&bytes[219..251], &[0xba; 32]);
    assert_eq!(&bytes[251..283], &[0x9e; 32]);
    // PostReceipt checks H(EPOCH_TERMS, header[63..119]) against the
    // committed terms_digest.
    assert_eq!(
        terms_digest(&h.band, &h.price_commitment),
        hash(domain::EPOCH_TERMS, &bytes[63..119])
    );
}

#[test]
fn header_decode_accepts_versions_one_and_two_only() {
    let v2 = header_v2(&[leaf(1, 1)]);
    assert_eq!(BatchHeader::decode_exact(&v2.to_bytes()), Ok(v2));

    let p = params();
    let v1 = BatchHeader::assemble(
        p,
        EpochId(7),
        p.band(Tick(50)).unwrap(),
        Hash32([0xb1; 32]),
        &[OrderCommitment([1; 32])],
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
    );
    assert_eq!(v1.version, PROTOCOL_VERSION);
    assert_eq!(v1.batch_root, batch_root(&[OrderCommitment([1; 32])]));
    assert_eq!(BatchHeader::decode_exact(&v1.to_bytes()), Ok(v1));

    for version in [0u8, 3, 0xff] {
        let mut b = v2.to_bytes();
        b[0] = version;
        assert_eq!(
            BatchHeader::decode_exact(&b),
            Err(DecodeError::InvalidValue("BatchHeader.version"))
        );
    }
    let mut other_market = v2.to_bytes();
    other_market[1] ^= 1;
    assert_eq!(
        BatchHeader::decode_exact(&other_market),
        Err(DecodeError::InvalidValue("BatchHeader.market"))
    );
    let mut long = v2.to_bytes();
    long.push(0);
    assert_eq!(
        BatchHeader::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
}

#[test]
fn binding_terms_and_seeds_match_the_reference_values() {
    let binding = epoch_binding(&Hash32([1; 32]), &Hash32([2; 32]), &Hash32([3; 32]));
    assert_eq!(
        binding.to_hex(),
        "a145b4d6cfb00546adf4123ed404f9ac3bde0a2b721aca9f4be0f535bc68e7f4"
    );
    // The three inputs are not interchangeable.
    assert_ne!(
        epoch_binding(&Hash32([2; 32]), &Hash32([1; 32]), &Hash32([3; 32])),
        binding
    );

    let band = PriceBand {
        lo: Tick(46),
        hi: Tick(54),
        reference: Tick(50),
    };
    assert_eq!(params().band(Tick(50)), Ok(band));
    assert_eq!(
        terms_digest(&band, &binding).to_hex(),
        "9529391ccc05bdab29550c12ff6da4ece02c61b1c1e1ae08a1ccbce030b65c15"
    );

    let market = [0x11; 32];
    let seed = epoch_seed(&[0x5e; 32], &market, EpochId(7));
    assert_eq!(
        seed.to_hex(),
        "8c5adb3f8edea966f79234cf44d7675facd8425c5d8fb4ca52982bb0c0f3d940"
    );
    assert_ne!(epoch_seed(&[0x5f; 32], &market, EpochId(7)), seed);
    assert_ne!(epoch_seed(&[0x5e; 32], &[0x12; 32], EpochId(7)), seed);
    assert_ne!(epoch_seed(&[0x5e; 32], &market, EpochId(8)), seed);

    let mut h = header_v2(&[leaf(1, 1)]);
    h.batch_root = Hash32([0x22; 32]);
    h.beacon = Hash32::from_hex("8d91f6c654fb8a994d3e83a432232e551740c911cacf99d5989a247a8fe0ee3c")
        .unwrap();
    assert_eq!(
        h.seed_v2(&seed).to_hex(),
        "733ca89cd6a889faf933b9db0e27913a7eeef79673a9c8089acd279cd7c55545"
    );
    assert_eq!(
        h.seed().to_hex(),
        "0c86d2fd22490ba3bbda403670a77dcbae84cffa701a526cd63c8241876a7c78"
    );
    assert_ne!(h.seed_v2(&Hash32([0; 32])), h.seed_v2(&seed));
}
