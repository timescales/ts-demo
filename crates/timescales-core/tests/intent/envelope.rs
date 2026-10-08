//! Envelope digests, the threshold opening path and the minimum encoded
//! lengths of the intent types.

use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_core::commitment::CommitmentError;
use timescales_core::crypto::threshold::{FeldmanDealing, lagrange_combine, x25519_public};
use timescales_core::crypto::{
    CryptoError, EpochSecret, ScalarSealSecret, SealSecret, domain, hash,
};
use timescales_core::identity::TraderKey;
use timescales_core::intent::{
    Cancel, ENVELOPE_LEN, IntentError, MaskedIntent, PLAINTEXT_LEN, PrivateIntent, SealedEnvelope,
};
use timescales_core::{
    CommitmentScheme, Decode, Encode, EpochId, Hash32, Lots, MarketId, Order, OrderCommitment,
    OrderKind, Role, Side, Tick,
};

fn order(key: &TraderKey, nonce: u64, limit: u64, quantity: u64) -> Order {
    Order {
        market: MarketId(1),
        trader: key.id(),
        nonce,
        side: Side::Buy,
        role: Role::Taker,
        kind: OrderKind::Limit,
        limit: Tick(limit),
        quantity: Lots(quantity),
        valid_from: EpochId(5),
        expires_at: EpochId(5),
    }
}

fn sealed(
    rng: &mut ChaCha20Rng,
    epoch_pk: &[u8; 32],
    intent: &PrivateIntent,
    c: OrderCommitment,
) -> SealedEnvelope {
    SealedEnvelope::seal(rng, MarketId(1), EpochId(5), epoch_pk, c, intent).expect("seal")
}

fn hex_strings<'a>(doc: &'a str, key: &str) -> Vec<&'a str> {
    let needle = format!("\"{key}\": \"");
    doc.match_indices(needle.as_str())
        .map(|(at, _)| {
            let start = at + needle.len();
            &doc[start..start + doc[start..].find('"').expect("closing quote")]
        })
        .collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

#[test]
fn envelope_digest_binds_every_byte() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let key = TraderKey::generate(&mut rng);
    let ek = SealSecret::generate(&mut rng);
    let (intent, c) = PrivateIntent::place(
        &mut rng,
        &key,
        CommitmentScheme::Sha256,
        order(&key, 1, 100, 2),
    )
    .unwrap();
    let env = sealed(&mut rng, &ek.public(), &intent, c);
    let bytes = env.to_bytes();
    for i in [0, 1, 9, 17, 48, 49, 80, 81, ENVELOPE_LEN - 1] {
        let mut changed = bytes.clone();
        changed[i] ^= 1;
        assert_ne!(hash(domain::ENVELOPE_COMMITMENT, &changed), env.digest());
    }
    // A fresh seal of the same intent is a different envelope.
    assert_ne!(
        sealed(&mut rng, &ek.public(), &intent, c).digest(),
        env.digest()
    );
}

#[test]
fn open_with_dev_secret_matches_open() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let key = TraderKey::generate(&mut rng);
    let ek = SealSecret::generate(&mut rng);
    let (intent, c) = PrivateIntent::place(
        &mut rng,
        &key,
        CommitmentScheme::Sha256,
        order(&key, 1, 100, 2),
    )
    .unwrap();
    let env = sealed(&mut rng, &ek.public(), &intent, c);
    let opened = env.open(&ek, CommitmentScheme::Sha256).unwrap();
    let dev = EpochSecret::Dev(SealSecret::from_bytes(ek.to_bytes()));
    assert_eq!(env.open_with(&dev, CommitmentScheme::Sha256), Ok(opened));
    assert_eq!(opened, intent);
}

#[test]
fn open_with_threshold_secret() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let (_, _, shares) = FeldmanDealing::new(&mut rng, 2, 3);
    let s = lagrange_combine(&shares[1..]);
    let epoch_pk = x25519_public(&s);
    let secret = EpochSecret::Threshold(ScalarSealSecret::from_scalar(*s));

    let key = TraderKey::generate(&mut rng);
    let (intent, c) = PrivateIntent::place(
        &mut rng,
        &key,
        CommitmentScheme::Sha256,
        order(&key, 1, 100, 2),
    )
    .unwrap();
    let env = sealed(&mut rng, &epoch_pk, &intent, c);
    assert_eq!(env.open_with(&secret, CommitmentScheme::Sha256), Ok(intent));

    // Cancels and cover open the same way.
    let cancel = Cancel {
        market: MarketId(1),
        trader: key.id(),
        nonce: 2,
        target: c,
        epoch: EpochId(5),
    };
    let (ci, cc) = PrivateIntent::cancel(&mut rng, &key, CommitmentScheme::Sha256, cancel).unwrap();
    let env = sealed(&mut rng, &epoch_pk, &ci, cc);
    assert_eq!(env.open_with(&secret, CommitmentScheme::Sha256), Ok(ci));
    let (ni, nc) = PrivateIntent::noop(&mut rng, CommitmentScheme::Sha256).unwrap();
    let env = sealed(&mut rng, &epoch_pk, &ni, nc);
    assert_eq!(env.open_with(&secret, CommitmentScheme::Sha256), Ok(ni));

    // Another epoch's secret cannot open it.
    let (other, _, _) = FeldmanDealing::new(&mut rng, 2, 3);
    let other = EpochSecret::Threshold(ScalarSealSecret::from_scalar(*other));
    assert_eq!(
        env.open_with(&other, CommitmentScheme::Sha256),
        Err(IntentError::Crypto(CryptoError::Aead))
    );
}

#[test]
fn open_with_threshold_refuses_a_small_order_ephemeral_key() {
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let (s, _, _) = FeldmanDealing::new(&mut rng, 1, 1);
    let secret = EpochSecret::Threshold(ScalarSealSecret::from_scalar(*s));
    let (ni, nc) = PrivateIntent::noop(&mut rng, CommitmentScheme::Sha256).unwrap();
    let mut env = sealed(&mut rng, &secret.public(), &ni, nc);
    // u = 1 is a point of order 4.
    env.ephemeral = [0u8; 32];
    env.ephemeral[0] = 1;
    assert_eq!(
        env.open_with(&secret, CommitmentScheme::Sha256),
        Err(IntentError::Crypto(CryptoError::InvalidPublicKey))
    );
}

#[test]
fn minimum_encoded_lengths_are_the_shortest_encodings() {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let ek = SealSecret::generate(&mut rng);
    let (ni, nc) = PrivateIntent::noop(&mut rng, CommitmentScheme::Sha256).unwrap();
    assert_eq!(ni.to_bytes().len(), PrivateIntent::MIN_ENCODED_LEN);
    let env = sealed(&mut rng, &ek.public(), &ni, nc);
    assert_eq!(env.to_bytes().len(), SealedEnvelope::MIN_ENCODED_LEN);
    let masked = MaskedIntent::noop(MarketId(1), EpochId(5), nc);
    assert_eq!(masked.to_bytes().len(), MaskedIntent::MIN_ENCODED_LEN);
    let cancel = Cancel {
        market: MarketId(1),
        trader: TraderKey::generate(&mut rng).id(),
        nonce: 0,
        target: nc,
        epoch: EpochId(5),
    };
    assert_eq!(cancel.to_bytes().len(), Cancel::MIN_ENCODED_LEN);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// On whole envelopes: 10,000 honestly sealed 289-byte envelopes
    /// (place, cancel and cover) open to the same intent through the
    /// threshold path and through the standard X25519 path for the same
    /// public key.
    #[test]
    fn threshold_open_with_equals_open(
        k in any::<[u8; 32]>(),
        seed in any::<u64>(),
        nonce in any::<u64>(),
        limit in 1u64..1_000_000,
        quantity in 0u64..1_000_000,
        kind in 0u8..3,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let standard = SealSecret::from_bytes(k);
        let threshold = EpochSecret::Threshold(ScalarSealSecret::from_x25519(&standard));
        prop_assert_eq!(threshold.public(), standard.public());

        let key = TraderKey::generate(&mut rng);
        let (intent, c) = match kind {
            0 => PrivateIntent::place(&mut rng, &key, CommitmentScheme::Sha256, order(&key, nonce, limit, quantity)),
            1 => PrivateIntent::cancel(&mut rng, &key, CommitmentScheme::Sha256, Cancel {
                market: MarketId(1),
                trader: key.id(),
                nonce,
                target: OrderCommitment([7; 32]),
                epoch: EpochId(5),
            }),
            _ => PrivateIntent::noop(&mut rng, CommitmentScheme::Sha256),
        }
        .unwrap();
        let env = sealed(&mut rng, &standard.public(), &intent, c);
        let a = env.open(&standard, CommitmentScheme::Sha256);
        let t = env.open_with(&threshold, CommitmentScheme::Sha256);
        prop_assert_eq!(a, Ok(intent));
        prop_assert_eq!(t, Ok(intent));
    }
}

/// An envelope around an arbitrary 192-byte plaintext, built with the
/// envelope's key-derivation info and header AAD.
fn envelope_around(
    rng: &mut ChaCha20Rng,
    epoch_pk: &[u8; 32],
    commitment: OrderCommitment,
    plaintext: &[u8; PLAINTEXT_LEN],
) -> SealedEnvelope {
    let (market, epoch) = (MarketId(1), EpochId(5));
    let mut info = b"envelope".to_vec();
    market.encode(&mut info);
    epoch.encode(&mut info);
    let mut aad = vec![1u8];
    market.encode(&mut aad);
    epoch.encode(&mut aad);
    commitment.encode(&mut aad);
    let b = timescales_core::crypto::seal(rng, epoch_pk, &info, &aad, plaintext).expect("seal");
    SealedEnvelope {
        version: 1,
        market,
        epoch,
        commitment,
        ephemeral: b.ephemeral,
        ciphertext: b.ciphertext.try_into().expect("fixed length"),
    }
}

#[test]
fn every_intent_error_is_produced() {
    // Exhaustive on purpose: a new variant must be produced here.
    fn variant(e: &IntentError) -> usize {
        match e {
            IntentError::UnsupportedVersion(_) => 0,
            IntentError::Crypto(_) => 1,
            IntentError::Malformed(_) => 2,
            IntentError::Commitment(_) => 3,
            IntentError::CommitmentMismatch => 4,
            IntentError::BadSignature => 5,
            IntentError::WrongSigner => 6,
        }
    }
    let mut rng = ChaCha20Rng::seed_from_u64(6);
    let key = TraderKey::generate(&mut rng);
    let ek = SealSecret::generate(&mut rng);
    let scheme = CommitmentScheme::Sha256;
    let (intent, c) = PrivateIntent::place(&mut rng, &key, scheme, order(&key, 1, 100, 2)).unwrap();
    let env = sealed(&mut rng, &ek.public(), &intent, c);
    let mut seen = Vec::new();

    let mut v2 = env.clone();
    v2.version = 2;
    seen.push(v2.open(&ek, scheme).unwrap_err());
    let mut moved = env.clone();
    moved.epoch = EpochId(6);
    seen.push(moved.open(&ek, scheme).unwrap_err());

    let mut padded = [0u8; PLAINTEXT_LEN];
    let encoded = intent.to_bytes();
    padded[..encoded.len()].copy_from_slice(&encoded);
    padded[PLAINTEXT_LEN - 1] = 1;
    let bad_padding = envelope_around(&mut rng, &ek.public(), c, &padded);
    let e = bad_padding.open(&ek, scheme).unwrap_err();
    assert!(matches!(&e, IntentError::Malformed(_)), "{e:?}");
    seen.push(e);

    // Poseidon is a feature of the core crate. Without it, a
    // Poseidon commitment cannot be recomputed and the scheme is reported.
    // With it (feature unification in workspace runs) the variant cannot
    // occur at all.
    let poseidon = CommitmentScheme::PoseidonBn254;
    let poseidon_compiled =
        match timescales_core::intent::commit_body(poseidon, &intent.body, &intent.salt) {
            Ok(_) => true,
            Err(e) => {
                assert_eq!(
                    e,
                    IntentError::Commitment(CommitmentError::UnsupportedScheme(poseidon))
                );
                assert_eq!(env.open(&ek, poseidon), Err(e.clone()));
                seen.push(e);
                false
            }
        };

    let wrong = sealed(&mut rng, &ek.public(), &intent, OrderCommitment([1; 32]));
    seen.push(wrong.open(&ek, scheme).unwrap_err());
    let mut forged = intent;
    forged.signature.0[5] ^= 1;
    seen.push(
        sealed(&mut rng, &ek.public(), &forged, c)
            .open(&ek, scheme)
            .unwrap_err(),
    );
    let other = TraderKey::generate(&mut rng);
    seen.push(PrivateIntent::place(&mut rng, &other, scheme, order(&key, 2, 100, 2)).unwrap_err());

    let variants: Vec<usize> = seen.iter().map(variant).collect();
    let expected: Vec<usize> = (0..7).filter(|v| *v != 3 || !poseidon_compiled).collect();
    assert_eq!(variants, expected);
}
