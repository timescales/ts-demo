//! Every `WireError` variant comes out of the public API. The name
//! table is an exhaustive match, so a new variant does not compile until it
//! is listed here and produced below.

use std::collections::BTreeSet;

use timescales_core::{DecodeError, Encode, Hash32};
use timescales_service::wire::{
    ChainId, EnvelopePrefix, EpochKeyAnnouncement, GrantExpectations, KeyScheme, MessageKind,
    ReplayGuard, SessionGrant, SignedEnvelope, WireError, check_session_nonce, issue_session_nonce,
    parse_session_message,
};

use crate::common::{Committee, Dealing, keypair, policy_statement, rng};

const NOW: u64 = 1_800_000_000_000;
const SKEW: u64 = 30_000;

fn name(e: &WireError) -> &'static str {
    match e {
        WireError::Decode(_) => "Decode",
        WireError::Version(_) => "Version",
        WireError::Kind(_) => "Kind",
        WireError::BadSignature => "BadSignature",
        WireError::Audience => "Audience",
        WireError::Sender => "Sender",
        WireError::TooLarge { .. } => "TooLarge",
        WireError::Skew { .. } => "Skew",
        WireError::Replay => "Replay",
        WireError::ReplayGuardFull => "ReplayGuardFull",
        WireError::Threshold { .. } => "Threshold",
        WireError::UnknownMember(_) => "UnknownMember",
        WireError::CommitteeMismatch => "CommitteeMismatch",
        WireError::Committee(_) => "Committee",
        WireError::Scheme => "Scheme",
        WireError::BadPoint(_) => "BadPoint",
        WireError::Template(_) => "Template",
        WireError::Expired => "Expired",
        WireError::Nonce => "Nonce",
        WireError::Policy(_) => "Policy",
    }
}

const ALL: [&str; 20] = [
    "Decode",
    "Version",
    "Kind",
    "BadSignature",
    "Audience",
    "Sender",
    "TooLarge",
    "Skew",
    "Replay",
    "ReplayGuardFull",
    "Threshold",
    "UnknownMember",
    "CommitteeMismatch",
    "Committee",
    "Scheme",
    "BadPoint",
    "Template",
    "Expired",
    "Nonce",
    "Policy",
];

fn envelope_errors() -> Vec<WireError> {
    let me = keypair(2).public();
    let sender = keypair(1);
    let env = SignedEnvelope::seal(
        MessageKind::ChallengeRequest,
        &sender,
        me,
        NOW,
        &mut rng(1),
        b"challenge".to_vec(),
    );
    let anyone = |_: &[u8; 32], _: MessageKind| true;
    let prefix = env.prefix().to_bytes();

    let mut version = prefix;
    version[0] = 9;
    let mut kind = prefix;
    kind[1] = 0;
    let mut too_large = prefix;
    too_large[90..94].copy_from_slice(&257u32.to_le_bytes());
    let mut tampered = env.clone();
    tampered.body[0] ^= 1;
    let truncated = env.to_bytes();

    let guard = ReplayGuard::new(1, 2 * SKEW);
    let first = guard.check_and_insert(&env.sender, &env.nonce, NOW, NOW);
    assert!(first.is_ok());

    vec![
        SignedEnvelope::from_prefix(&env.prefix(), &truncated[95..]).unwrap_err(),
        EnvelopePrefix::parse(&version).unwrap_err(),
        EnvelopePrefix::parse(&kind).unwrap_err(),
        EnvelopePrefix::parse(&too_large).unwrap_err(),
        tampered.open(&me, &anyone, NOW, SKEW).unwrap_err(),
        env.open(&[7; 32], &anyone, NOW, SKEW).unwrap_err(),
        env.open(&me, &|_, _| false, NOW, SKEW).unwrap_err(),
        env.open(&me, &anyone, NOW + SKEW + 1, SKEW).unwrap_err(),
        guard
            .check_and_insert(&env.sender, &env.nonce, NOW, NOW)
            .unwrap_err(),
        guard
            .check_and_insert(&env.sender, &[1; 16], NOW, NOW)
            .unwrap_err(),
    ]
}

fn key_errors() -> Vec<WireError> {
    let committee = Committee::new(2, 3);
    let ann = Dealing::new(3, 2).announcement(&committee.desc);
    let digests = [committee.desc.digest()];

    let one_ack = committee.bundle(&ann, &[1]);
    let mut stranger = committee.bundle(&ann, &[1, 2]);
    stranger.acks[1].member = 9;
    let mut invalid = committee.desc.clone();
    invalid.threshold = 0;
    let dev = EpochKeyAnnouncement {
        scheme: KeyScheme::DevX25519,
        commitments: Vec::new(),
        ..ann.clone()
    };
    let mut off_curve = ann.clone();
    off_curve.commitments[1] = [0; 32];
    off_curve.commitments[1][0] = 2;
    let mut odd_platforms = policy_statement(1, committee.desc.digest());
    odd_platforms.platforms = 0x80;

    vec![
        one_ack
            .verify(&committee.desc, &digests, false)
            .unwrap_err(),
        stranger
            .verify(&committee.desc, &digests, false)
            .unwrap_err(),
        one_ack
            .verify(&committee.desc, &[Hash32([1; 32])], false)
            .unwrap_err(),
        invalid.validate().unwrap_err(),
        dev.check_structure(2, false).unwrap_err(),
        off_curve.check_structure(2, false).unwrap_err(),
        odd_platforms
            .sign(committee.identity(1))
            .verify(&committee.identity(1).public())
            .unwrap_err(),
    ]
}

fn session_errors() -> Vec<WireError> {
    let key = [3u8; 32];
    let nonce = issue_session_nonce(&key, NOW, &mut rng(2));
    let mut forged = nonce;
    forged[15] ^= 1;
    let grant = SessionGrant {
        domain: "app.timescales.example".into(),
        wallet: [1; 32],
        statement: String::new(),
        uri: "https://app.timescales.example".into(),
        chain_id: ChainId::Devnet,
        nonce,
        issued_at_ms: NOW,
        expires_at_ms: NOW + 1_000,
        not_before_ms: None,
        session_key: [2; 32],
        program: [3; 32],
        market: None,
    };
    let domains = ["app.timescales.example".to_owned()];
    let expect = GrantExpectations {
        domains: &domains,
        uri: "https://app.timescales.example",
        chain_id: ChainId::Devnet,
        program: [3; 32],
        now_ms: NOW + 1_000,
        max_ttl_ms: 60_000,
    };
    vec![
        parse_session_message("not a sign-in message").unwrap_err(),
        check_session_nonce(&key, &nonce, NOW + 600_000, 300_000).unwrap_err(),
        check_session_nonce(&key, &forged, NOW, 300_000).unwrap_err(),
        grant.check(&expect).unwrap_err(),
    ]
}

#[test]
fn every_wire_error_variant_is_produced() {
    let errors: Vec<WireError> = envelope_errors()
        .into_iter()
        .chain(key_errors())
        .chain(session_errors())
        .collect();
    let produced: BTreeSet<&str> = errors.iter().map(name).collect();
    assert_eq!(produced, ALL.into_iter().collect::<BTreeSet<_>>());
    for e in &errors {
        assert!(!e.to_string().is_empty(), "{e:?}");
    }
}

#[test]
fn each_case_gives_the_expected_variant() {
    let names: Vec<&str> = envelope_errors().iter().map(name).collect();
    assert_eq!(
        names,
        [
            "Decode",
            "Version",
            "Kind",
            "TooLarge",
            "BadSignature",
            "Audience",
            "Sender",
            "Skew",
            "Replay",
            "ReplayGuardFull",
        ]
    );
    let names: Vec<&str> = key_errors().iter().map(name).collect();
    assert_eq!(
        names,
        [
            "Threshold",
            "UnknownMember",
            "CommitteeMismatch",
            "Committee",
            "Scheme",
            "BadPoint",
            "Policy",
        ]
    );
    let names: Vec<&str> = session_errors().iter().map(name).collect();
    assert_eq!(names, ["Template", "Expired", "Nonce", "Expired"]);
}

#[test]
fn decode_errors_convert_into_wire_errors() {
    let e: WireError = DecodeError::TrailingBytes(3).into();
    assert!(matches!(
        e,
        WireError::Decode(DecodeError::TrailingBytes(3))
    ));
    assert_eq!(e.to_string(), "decode: 3 trailing bytes after value");
    let e = WireError::TooLarge { len: 9, max: 8 };
    assert_eq!(e.to_string(), "body of 9 bytes exceeds 8");
    let e = WireError::Threshold { got: 1, need: 2 };
    assert_eq!(e.to_string(), "1 of 2 required acknowledgements");
}
