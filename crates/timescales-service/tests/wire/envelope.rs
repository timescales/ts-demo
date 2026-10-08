use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use timescales_core::crypto::{Hasher, Keypair, domain};
use timescales_core::{Decode, DecodeError, Encode, Hash32};
use timescales_executor::attestation::{Evidence, Measurement, Platform};
use timescales_executor::tee::{Enclave, Quoter};
use timescales_service::wire::{
    EnvelopePrefix, EnvelopeSigner, MessageKind, PREFIX_LEN, ReplayGuard, SignedEnvelope,
    WIRE_VERSION, WireError,
};

use crate::common::{keypair, rng};

const NOW: u64 = 1_800_000_000_000;
const SKEW: u64 = 30_000;

fn me() -> [u8; 32] {
    keypair(2).public()
}

fn only(sender: [u8; 32]) -> impl Fn(&[u8; 32], MessageKind) -> bool {
    move |s, _| *s == sender
}

fn sealed(kind: MessageKind, body: &[u8]) -> SignedEnvelope {
    SignedEnvelope::seal(kind, &keypair(1), me(), NOW, &mut rng(3), body.to_vec())
}

fn prefix_of(bytes: &[u8]) -> [u8; PREFIX_LEN] {
    bytes[..PREFIX_LEN].try_into().unwrap()
}

#[test]
fn sealed_envelopes_open_for_their_audience() {
    let env = sealed(MessageKind::ChallengeRequest, b"challenge");
    assert_eq!(env.version, WIRE_VERSION);
    assert_eq!(env.sender, keypair(1).public());
    assert_eq!(env.issued_at_ms, NOW);
    let body = env
        .open(&me(), &only(keypair(1).public()), NOW + 5, SKEW)
        .unwrap();
    assert_eq!(body, b"challenge");
}

#[test]
fn the_signature_covers_prefix_and_body_under_the_rpc_domain() {
    let env = sealed(MessageKind::EpochKeyAck, b"ack");
    let bytes = env.to_bytes();
    let signed = &bytes[..bytes.len() - 64];
    assert_eq!(signed, env.bytes_before_sig());
    let digest = Hasher::new(domain::RPC_ENVELOPE).chain(signed).finalize();
    timescales_core::crypto::verify_digest(&env.sender, &digest, &env.signature).unwrap();
}

#[test]
fn layout_is_the_94_byte_prefix_then_body_then_signature() {
    let env = sealed(MessageKind::ReleaseResponse, b"xyz");
    let bytes = env.to_bytes();
    assert_eq!(bytes.len(), PREFIX_LEN + 3 + 64);
    assert_eq!(bytes[0], WIRE_VERSION);
    assert_eq!(bytes[1], MessageKind::ReleaseResponse as u8);
    assert_eq!(&bytes[2..34], &env.sender);
    assert_eq!(&bytes[34..66], &env.audience);
    assert_eq!(&bytes[66..74], &NOW.to_le_bytes());
    assert_eq!(&bytes[74..90], &env.nonce);
    assert_eq!(&bytes[90..94], &3u32.to_le_bytes());
    assert_eq!(&bytes[94..97], b"xyz");
    assert_eq!(&bytes[97..], &env.signature.0);
    assert_eq!(SignedEnvelope::MIN_ENCODED_LEN, PREFIX_LEN + 64);
}

#[test]
fn encoding_round_trips_whole_and_in_two_reads() {
    let env = sealed(MessageKind::ShareDelivery, &[7; 700]);
    let bytes = env.to_bytes();
    assert_eq!(SignedEnvelope::decode_exact(&bytes).unwrap(), env);

    let prefix = EnvelopePrefix::check(&prefix_of(&bytes), &me(), &only(env.sender)).unwrap();
    assert_eq!(prefix, env.prefix());
    assert_eq!(prefix.to_bytes(), prefix_of(&bytes));
    let rest = &bytes[PREFIX_LEN..];
    assert_eq!(SignedEnvelope::from_prefix(&prefix, rest).unwrap(), env);
    assert!(matches!(
        SignedEnvelope::from_prefix(&prefix, &rest[1..]),
        Err(WireError::Decode(DecodeError::UnexpectedEof { .. }))
    ));
    let mut longer = rest.to_vec();
    longer.push(0);
    assert!(matches!(
        SignedEnvelope::from_prefix(&prefix, &longer),
        Err(WireError::Decode(DecodeError::TrailingBytes(1)))
    ));
}

#[test]
fn an_oversized_length_is_refused_from_the_prefix_alone() {
    let mut env = sealed(MessageKind::PublishRequest, b"");
    env.body = vec![0; MessageKind::PublishRequest.max_body() + 1];
    let prefix = env.prefix().to_bytes();
    // Only the 94 prefix bytes exist: the check never needs the body.
    assert!(matches!(
        EnvelopePrefix::check(&prefix, &me(), &|_, _| true),
        Err(WireError::TooLarge {
            len: 1025,
            max: 1024
        })
    ));
    assert_eq!(
        SignedEnvelope::decode_exact(&prefix),
        Err(DecodeError::LengthExceeded {
            len: 1025,
            max: 1024
        })
    );
    let mut huge = prefix;
    huge[90..94].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        EnvelopePrefix::parse(&huge),
        Err(WireError::TooLarge { len: u32::MAX, .. })
    ));
}

#[test]
fn every_kind_takes_exactly_its_largest_body() {
    for kind in MessageKind::ALL {
        let max = kind.max_body();
        let mut env = sealed(kind, b"");
        env.body = vec![0; max];
        assert!(EnvelopePrefix::parse(&env.prefix().to_bytes()).is_ok());
        env.body.push(0);
        assert!(
            matches!(
                EnvelopePrefix::parse(&env.prefix().to_bytes()),
                Err(WireError::TooLarge { .. })
            ),
            "{kind:?}"
        );
        assert_eq!(kind.max_envelope_len(), 158 + max);
    }
}

#[test]
fn the_empty_kind_carries_nothing() {
    let env = sealed(MessageKind::Empty, b"");
    assert_eq!(env.open(&me(), &only(env.sender), NOW, SKEW).unwrap(), b"");
    let env = sealed(MessageKind::Empty, b"x");
    assert!(matches!(
        env.open(&me(), &only(env.sender), NOW, SKEW),
        Err(WireError::TooLarge { len: 1, max: 0 })
    ));
}

#[test]
fn another_audience_is_refused() {
    let env = SignedEnvelope::seal(
        MessageKind::ReleaseRequest,
        &keypair(1),
        keypair(9).public(),
        NOW,
        &mut rng(1),
        b"req".to_vec(),
    );
    let allowed = only(env.sender);
    assert!(matches!(
        env.open(&me(), &allowed, NOW, SKEW),
        Err(WireError::Audience)
    ));
    assert!(matches!(
        EnvelopePrefix::check(&env.prefix().to_bytes(), &me(), &allowed),
        Err(WireError::Audience)
    ));
}

#[test]
fn senders_are_allowed_per_kind() {
    let env = sealed(MessageKind::ExecuteRequest, b"batch");
    let node = env.sender;
    let policy = move |s: &[u8; 32], k: MessageKind| *s == node && k == MessageKind::ExecuteRequest;
    assert!(env.open(&me(), &policy, NOW, SKEW).is_ok());
    let other = sealed(MessageKind::PublishRequest, b"publish");
    assert!(matches!(
        other.open(&me(), &policy, NOW, SKEW),
        Err(WireError::Sender)
    ));
    let stranger = SignedEnvelope::seal(
        MessageKind::ExecuteRequest,
        &keypair(5),
        me(),
        NOW,
        &mut rng(2),
        b"batch".to_vec(),
    );
    assert!(matches!(
        stranger.open(&me(), &policy, NOW, SKEW),
        Err(WireError::Sender)
    ));
    assert!(matches!(
        EnvelopePrefix::check(&stranger.prefix().to_bytes(), &me(), &policy),
        Err(WireError::Sender)
    ));
}

#[test]
fn unknown_versions_and_kinds_are_refused() {
    let env = sealed(MessageKind::EpochKeyAck, b"a");
    for v in [0u8, 2, 255] {
        let mut p = env.prefix().to_bytes();
        p[0] = v;
        assert!(matches!(EnvelopePrefix::parse(&p), Err(WireError::Version(x)) if x == v));
        let mut bytes = env.to_bytes();
        bytes[0] = v;
        assert_eq!(
            SignedEnvelope::decode_exact(&bytes),
            Err(DecodeError::InvalidValue("SignedEnvelope.version"))
        );
        let mut e = env.clone();
        e.version = v;
        assert!(matches!(
            e.open(&me(), &|_, _| true, NOW, SKEW),
            Err(WireError::Version(x)) if x == v
        ));
    }
    for k in [0u8, 16, 255] {
        let mut p = env.prefix().to_bytes();
        p[1] = k;
        assert!(matches!(EnvelopePrefix::parse(&p), Err(WireError::Kind(x)) if x == k));
        let mut bytes = env.to_bytes();
        bytes[1] = k;
        assert_eq!(
            SignedEnvelope::decode_exact(&bytes),
            Err(DecodeError::InvalidTag {
                ty: "MessageKind",
                tag: k
            })
        );
    }
}

#[test]
fn clock_skew_is_bounded_both_ways() {
    let env = sealed(MessageKind::ChallengeResponse, b"n");
    let allowed = only(env.sender);
    assert!(env.open(&me(), &allowed, NOW + SKEW, SKEW).is_ok());
    assert!(env.open(&me(), &allowed, NOW - SKEW, SKEW).is_ok());
    assert!(matches!(
        env.open(&me(), &allowed, NOW + SKEW + 1, SKEW),
        Err(WireError::Skew {
            now_ms,
            issued_at_ms: NOW
        }) if now_ms == NOW + SKEW + 1
    ));
    assert!(matches!(
        env.open(&me(), &allowed, NOW - SKEW - 1, SKEW),
        Err(WireError::Skew { .. })
    ));
}

#[test]
fn any_change_breaks_the_signature() {
    let env = sealed(MessageKind::ReleaseRequest, b"release me");
    let allowed = |_: &[u8; 32], _: MessageKind| true;
    let mut body = env.clone();
    body.body[0] ^= 1;
    let mut nonce = env.clone();
    nonce.nonce[3] ^= 1;
    let mut kind = env.clone();
    kind.kind = MessageKind::ExecuteRequest;
    let mut time = env.clone();
    time.issued_at_ms += 1;
    let mut sender = env.clone();
    sender.sender = keypair(7).public();
    let mut sig = env.clone();
    sig.signature.0[10] ^= 1;
    for (what, e) in [
        ("body", body),
        ("nonce", nonce),
        ("kind", kind),
        ("time", time),
        ("sender", sender),
        ("signature", sig),
    ] {
        assert!(
            matches!(
                e.open(&me(), &allowed, NOW, SKEW),
                Err(WireError::BadSignature)
            ),
            "{what}"
        );
    }
}

#[test]
fn trailing_and_missing_bytes_are_refused() {
    let env = sealed(MessageKind::AnnouncementQuery, &[1; 40]);
    let mut bytes = env.to_bytes();
    bytes.push(0);
    assert_eq!(
        SignedEnvelope::decode_exact(&bytes),
        Err(DecodeError::TrailingBytes(1))
    );
    bytes.truncate(bytes.len() - 2);
    assert!(matches!(
        SignedEnvelope::decode_exact(&bytes),
        Err(DecodeError::UnexpectedEof { .. })
    ));
    assert!(matches!(
        SignedEnvelope::decode_exact(&bytes[..50]),
        Err(DecodeError::UnexpectedEof { .. })
    ));
}

struct NoQuotes;

impl Quoter for NoQuotes {
    fn quote(&self, _: Measurement, _: bool, _: [u8; 64]) -> Evidence {
        Evidence {
            platform: Platform::Simulated,
            quote: Vec::new(),
        }
    }
}

#[test]
fn enclaves_seal_with_their_executor_key() {
    let enclave = Enclave::boot(Arc::new(NoQuotes), Measurement(Hash32::ZERO), false);
    let env = SignedEnvelope::seal(
        MessageKind::ReleaseRequest,
        &enclave,
        me(),
        NOW,
        &mut rng(4),
        b"attested".to_vec(),
    );
    assert_eq!(env.sender, enclave.executor_id().0);
    assert_eq!(env.sender, EnvelopeSigner::public(&enclave));
    let executor = enclave.executor_id().0;
    assert!(env.open(&me(), &only(executor), NOW, SKEW).is_ok());
}

#[test]
fn nonces_are_fresh_per_envelope() {
    let mut r = rng(8);
    let k = keypair(1);
    let a = SignedEnvelope::seal(MessageKind::Empty, &k, me(), NOW, &mut r, Vec::new());
    let b = SignedEnvelope::seal(MessageKind::Empty, &k, me(), NOW, &mut r, Vec::new());
    assert_ne!(a.nonce, b.nonce);
}

#[test]
fn the_replay_guard_refuses_repeats_and_accepts_fresh_nonces() {
    let g = ReplayGuard::new(16, 2 * SKEW);
    let a = keypair(1).public();
    let b = keypair(2).public();
    g.check_and_insert(&a, &[1; 16], NOW, NOW).unwrap();
    assert!(matches!(
        g.check_and_insert(&a, &[1; 16], NOW, NOW + 1),
        Err(WireError::Replay)
    ));
    // The same nonce with another issue time is still a replay.
    assert!(matches!(
        g.check_and_insert(&a, &[1; 16], NOW + 5, NOW + 5),
        Err(WireError::Replay)
    ));
    g.check_and_insert(&a, &[2; 16], NOW, NOW).unwrap();
    g.check_and_insert(&b, &[1; 16], NOW, NOW).unwrap();
    assert_eq!(g.len(), 3);
    assert!(!g.is_empty());
}

#[test]
fn a_full_replay_guard_fails_closed_without_evicting() {
    let g = ReplayGuard::new(3, 2 * SKEW);
    let a = keypair(1).public();
    for n in 0..3u8 {
        g.check_and_insert(&a, &[n; 16], NOW, NOW).unwrap();
    }
    assert!(matches!(
        g.check_and_insert(&a, &[9; 16], NOW, NOW),
        Err(WireError::ReplayGuardFull)
    ));
    // Live entries are still remembered.
    for n in 0..3u8 {
        assert!(matches!(
            g.check_and_insert(&a, &[n; 16], NOW, NOW + 1),
            Err(WireError::Replay)
        ));
    }
    // Once they expire, capacity returns.
    let later = NOW + 2 * SKEW + 1;
    g.check_and_insert(&a, &[9; 16], later, later).unwrap();
    assert_eq!(g.len(), 1);
}

#[test]
fn the_replay_guard_only_tracks_its_window() {
    let window = 2 * SKEW;
    let g = ReplayGuard::new(16, window);
    let a = keypair(1).public();
    assert!(matches!(
        g.check_and_insert(&a, &[1; 16], NOW - window - 1, NOW),
        Err(WireError::Skew { .. })
    ));
    assert!(matches!(
        g.check_and_insert(&a, &[1; 16], NOW + window + 1, NOW),
        Err(WireError::Skew { .. })
    ));
    assert!(g.is_empty());
    // An entry is remembered for as long as it could be accepted again.
    g.check_and_insert(&a, &[1; 16], NOW - window, NOW).unwrap();
    assert!(matches!(
        g.check_and_insert(&a, &[1; 16], NOW - window, NOW),
        Err(WireError::Replay)
    ));
}

#[test]
fn concurrent_inserts_of_one_nonce_admit_exactly_one() {
    let g = Arc::new(ReplayGuard::new(1024, 2 * SKEW));
    let admitted = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let g = Arc::clone(&g);
            let admitted = Arc::clone(&admitted);
            std::thread::spawn(move || {
                for n in 0..64u8 {
                    if g.check_and_insert(&[7; 32], &[n; 16], NOW, NOW).is_ok() {
                        admitted.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(admitted.load(Ordering::Relaxed), 64);
    assert_eq!(g.len(), 64);
}

#[test]
fn keypairs_sign_envelopes_under_the_rpc_domain() {
    let k = Keypair::from_seed([4; 32]);
    let sig = k.sign_envelope(b"bytes");
    let d = Hasher::new(domain::RPC_ENVELOPE).chain(b"bytes").finalize();
    timescales_core::crypto::verify_digest(&EnvelopeSigner::public(&k), &d, &sig).unwrap();
}
