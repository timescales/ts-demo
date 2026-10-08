//! `MaskedIntent::verify_signature`: what relays and the MPC path accept.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_core::crypto::Signature;
use timescales_core::identity::TraderKey;
use timescales_core::intent::{
    Cancel, FieldBytes, IntentError, MaskedBody, MaskedIntent, MaskedPlace,
};
use timescales_core::{Decode, Encode, EpochId, MarketId, OrderCommitment};

fn place(key: &TraderKey) -> MaskedBody {
    MaskedBody::Place(MaskedPlace {
        trader: key.id(),
        nonce: 9,
        valid_from: EpochId(4),
        expires_at: EpochId(6),
        mask_offset: 128,
        values: (0..8).map(|v| FieldBytes(v * 0x1_0000_0001)).collect(),
    })
}

fn signed(key: &TraderKey, body: MaskedBody) -> MaskedIntent {
    MaskedIntent::sign(key, MarketId(3), EpochId(5), OrderCommitment([1; 32]), body)
}

#[test]
fn signed_place_and_cancel_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let key = TraderKey::generate(&mut rng);
    let m = signed(&key, place(&key));
    assert_eq!(m.verify_signature(), Ok(()));
    assert_eq!(m.trader(), Some(key.id()));
    let cancel = MaskedBody::Cancel(Cancel {
        market: MarketId(3),
        trader: key.id(),
        nonce: 10,
        target: OrderCommitment([1; 32]),
        epoch: EpochId(5),
    });
    assert_eq!(signed(&key, cancel).verify_signature(), Ok(()));
    // The encoding round-trips with the signature intact.
    let decoded = MaskedIntent::decode_exact(&m.to_bytes()).unwrap();
    assert_eq!(decoded.verify_signature(), Ok(()));
}

#[test]
fn every_signed_field_is_bound() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let key = TraderKey::generate(&mut rng);
    let m = signed(&key, place(&key));
    let tampered: [fn(&mut MaskedIntent); 5] = [
        |m| m.market = MarketId(4),
        |m| m.epoch = EpochId(6),
        |m| m.commitment = OrderCommitment([2; 32]),
        |m| {
            if let MaskedBody::Place(p) = &mut m.body {
                p.values[3] = FieldBytes(1);
            }
        },
        |m| m.signature.0[0] ^= 1,
    ];
    for change in tampered {
        let mut t = m.clone();
        change(&mut t);
        assert_eq!(t.verify_signature(), Err(IntentError::BadSignature));
    }
}

#[test]
fn signature_must_come_from_the_named_trader() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let key = TraderKey::generate(&mut rng);
    let other = TraderKey::generate(&mut rng);
    // Signed by `other` while the body names `key`.
    let m = signed(&other, place(&key));
    assert_eq!(m.verify_signature(), Err(IntentError::BadSignature));
}

#[test]
fn cover_carries_the_zero_signature() {
    let noop = MaskedIntent::noop(MarketId(3), EpochId(5), OrderCommitment([1; 32]));
    assert_eq!(noop.trader(), None);
    assert_eq!(noop.verify_signature(), Ok(()));
    let mut forged = noop.clone();
    forged.signature = Signature([7; 64]);
    assert_eq!(forged.verify_signature(), Err(IntentError::BadSignature));
}
