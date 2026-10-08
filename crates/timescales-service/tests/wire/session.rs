use proptest::prelude::*;
use sha2::{Digest, Sha256};
use timescales_core::crypto::{Hasher, Keypair, domain};
use timescales_service::wire::{
    ChainId, GrantExpectations, MAX_SESSION_TEXT_BYTES, SESSION_STATEMENT, SessionAuthorization,
    SessionGrant, WireError, check_session_nonce, issue_session_nonce, parse_session_message,
    render_session_message, session_request_digest,
};

use crate::common::{keypair, rng};

fn b58(bytes: [u8; 32]) -> String {
    bs58::encode(bytes).into_string()
}

/// 2026-10-07T12:00:00.123Z
const ISSUED: u64 = 1_791_374_400_123;
const HOUR: u64 = 3_600_000;

fn grant() -> SessionGrant {
    SessionGrant {
        domain: "app.timescales.example".into(),
        wallet: [1; 32],
        statement: SESSION_STATEMENT.into(),
        uri: "https://app.timescales.example".into(),
        chain_id: ChainId::Devnet,
        nonce: hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap(),
        issued_at_ms: ISSUED,
        expires_at_ms: ISSUED + 12 * HOUR,
        not_before_ms: None,
        session_key: [0xab; 32],
        program: [2; 32],
        market: Some([3; 32]),
    }
}

/// The SDK's canonical test text (`test/session-text.test.ts`).
fn canonical() -> String {
    [
        "app.timescales.example wants you to sign in with your Solana account:".to_owned(),
        b58([1; 32]),
        String::new(),
        SESSION_STATEMENT.to_owned(),
        String::new(),
        "URI: https://app.timescales.example".to_owned(),
        "Version: 1".to_owned(),
        "Chain ID: devnet".to_owned(),
        "Nonce: 00112233445566778899aabbccddeeff".to_owned(),
        "Issued At: 2026-10-07T12:00:00.123Z".to_owned(),
        "Expiration Time: 2026-10-08T00:00:00.123Z".to_owned(),
        "Resources:".to_owned(),
        format!("- timescales:session:{}", "ab".repeat(32)),
        format!("- timescales:program:{}", b58([2; 32])),
        format!("- timescales:market:{}", b58([3; 32])),
    ]
    .join("\n")
}

/// Replaces one whole line of the canonical text (`None` removes it).
fn with_line(from: &str, to: Option<&str>) -> String {
    let text = canonical();
    let mut lines: Vec<&str> = text.split('\n').collect();
    let i = lines.iter().position(|l| *l == from).unwrap();
    match to {
        Some(t) => lines[i] = t,
        None => {
            lines.remove(i);
        }
    }
    lines.join("\n")
}

#[test]
fn the_statement_is_the_one_wallets_are_asked_to_show() {
    assert_eq!(
        SESSION_STATEMENT,
        "Authorize a Timescales trading session. This key can submit encrypted orders for this \
         wallet. Timescales executes only orders this wallet signs. It cannot sign orders or move \
         funds."
    );
}

#[test]
fn rendering_matches_the_sdk_text_byte_for_byte() {
    assert_eq!(render_session_message(&grant()), canonical());
    assert!(!canonical().ends_with('\n'));
}

#[test]
fn an_all_markets_grant_has_no_market_line() {
    let g = SessionGrant {
        market: None,
        ..grant()
    };
    let text = render_session_message(&g);
    let full = canonical();
    let lines: Vec<&str> = full.split('\n').collect();
    assert_eq!(text, lines[..lines.len() - 1].join("\n"));
    assert_eq!(parse_session_message(&text).unwrap(), g);
}

#[test]
fn the_canonical_text_round_trips() {
    assert_eq!(parse_session_message(&canonical()).unwrap(), grant());
    assert_eq!(
        render_session_message(&parse_session_message(&canonical()).unwrap()),
        canonical()
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn random_grants_round_trip(
        wallet in any::<[u8; 32]>(),
        program in any::<[u8; 32]>(),
        market in proptest::option::of(any::<[u8; 32]>()),
        nonce in any::<[u8; 16]>(),
        session_key in any::<[u8; 32]>(),
        issued_at_ms in 946_684_800_000u64..7_258_118_400_000,
        ttl in 1u64..=24 * HOUR,
        chain in 0u8..3,
        port in proptest::option::of(1u32..=65_535),
    ) {
        let g = SessionGrant {
            domain: port.map_or_else(|| "localhost".to_owned(), |p| format!("localhost:{p}")),
            wallet,
            statement: SESSION_STATEMENT.into(),
            uri: "http://localhost:5173".into(),
            chain_id: [ChainId::Localnet, ChainId::Devnet, ChainId::Mainnet][usize::from(chain)],
            nonce,
            issued_at_ms,
            expires_at_ms: issued_at_ms + ttl,
            not_before_ms: None,
            session_key,
            program,
            market,
        };
        prop_assert_eq!(parse_session_message(&render_session_message(&g)).unwrap(), g);
    }

    #[test]
    fn arbitrary_text_never_panics(text in "\\PC{0,300}") {
        let _ = parse_session_message(&text);
    }

    #[test]
    fn mutated_grants_never_panic_and_accepted_ones_round_trip(
        at in 0usize..2000,
        byte in any::<u8>(),
    ) {
        let mut bytes = canonical().into_bytes();
        let at = at % bytes.len();
        bytes[at] = byte;
        if let Ok(text) = String::from_utf8(bytes)
            && let Ok(g) = parse_session_message(&text)
        {
            let again = parse_session_message(&render_session_message(&g)).unwrap();
            prop_assert_eq!(again, g);
        }
    }
}

#[test]
fn wallet_formatted_variants_with_the_same_fields_are_accepted() {
    let variants: Vec<(&str, String)> = vec![
        (
            "EIP-4361 blank lines without a statement",
            canonical().replace(&format!("\n{SESSION_STATEMENT}\n"), "\n"),
        ),
        (
            "no statement at all",
            canonical().replace(&format!("{SESSION_STATEMENT}\n\n"), ""),
        ),
        (
            "a +00:00 offset",
            with_line(
                "Issued At: 2026-10-07T12:00:00.123Z",
                Some("Issued At: 2026-10-07T12:00:00.123+00:00"),
            ),
        ),
        (
            "another offset",
            with_line(
                "Issued At: 2026-10-07T12:00:00.123Z",
                Some("Issued At: 2026-10-07T14:30:00.123+02:30"),
            ),
        ),
        (
            "a negative offset",
            with_line(
                "Issued At: 2026-10-07T12:00:00.123Z",
                Some("Issued At: 2026-10-07T07:00:00.123-05:00"),
            ),
        ),
        (
            "microsecond digits",
            with_line(
                "Issued At: 2026-10-07T12:00:00.123Z",
                Some("Issued At: 2026-10-07T12:00:00.123000Z"),
            ),
        ),
        (
            "lowercase t and z",
            with_line(
                "Issued At: 2026-10-07T12:00:00.123Z",
                Some("Issued At: 2026-10-07t12:00:00.123z"),
            ),
        ),
        (
            "a solana:-prefixed chain id",
            with_line("Chain ID: devnet", Some("Chain ID: solana:devnet")),
        ),
        (
            "a Request ID",
            with_line(
                "Expiration Time: 2026-10-08T00:00:00.123Z",
                Some("Expiration Time: 2026-10-08T00:00:00.123Z\nRequest ID: abc-123"),
            ),
        ),
        (
            "reordered resources",
            canonical().replace(
                &format!(
                    "- timescales:session:{}\n- timescales:program:{}",
                    "ab".repeat(32),
                    b58([2; 32])
                ),
                &format!(
                    "- timescales:program:{}\n- timescales:session:{}",
                    b58([2; 32]),
                    "ab".repeat(32)
                ),
            ),
        ),
        (
            "the market first",
            canonical().replace(
                &format!(
                    "- timescales:session:{}\n- timescales:program:{}\n- timescales:market:{}",
                    "ab".repeat(32),
                    b58([2; 32]),
                    b58([3; 32])
                ),
                &format!(
                    "- timescales:market:{}\n- timescales:session:{}\n- timescales:program:{}",
                    b58([3; 32]),
                    "ab".repeat(32),
                    b58([2; 32])
                ),
            ),
        ),
    ];
    let expected = grant();
    for (name, text) in variants {
        assert_ne!(text, canonical(), "{name}: the variant must differ");
        let parsed = parse_session_message(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            parsed.statement == expected.statement || parsed.statement.is_empty(),
            "{name}"
        );
        assert_eq!(
            SessionGrant {
                statement: expected.statement.clone(),
                ..parsed
            },
            expected,
            "{name}"
        );
    }
}

#[test]
fn whole_second_times_read_as_whole_seconds() {
    let text = with_line(
        "Issued At: 2026-10-07T12:00:00.123Z",
        Some("Issued At: 2026-10-07T12:00:00Z"),
    );
    assert_eq!(
        parse_session_message(&text).unwrap().issued_at_ms,
        ISSUED - 123
    );
}

#[test]
fn texts_outside_the_abnf_or_the_template_are_refused() {
    let session_line = format!("- timescales:session:{}", "ab".repeat(32));
    let program_line = format!("- timescales:program:{}", b58([2; 32]));
    let negatives: Vec<(&str, String)> = vec![
        ("CRLF line endings", canonical().replace('\n', "\r\n")),
        ("a trailing newline", format!("{}\n", canonical())),
        (
            "Not Before",
            with_line(
                "Expiration Time: 2026-10-08T00:00:00.123Z",
                Some("Expiration Time: 2026-10-08T00:00:00.123Z\nNot Before: 2026-10-07T12:00:00Z"),
            ),
        ),
        ("version 2", with_line("Version: 1", Some("Version: 2"))),
        (
            "an unknown resource",
            format!("{}\n- https://evil.example/", canonical()),
        ),
        (
            "a repeated resource",
            format!("{}\n{program_line}", canonical()),
        ),
        (
            "a repeated market",
            format!("{}\n- timescales:market:{}", canonical(), b58([4; 32])),
        ),
        ("a missing session resource", with_line(&session_line, None)),
        ("a missing program resource", with_line(&program_line, None)),
        (
            "an uppercase session key",
            with_line(
                &session_line,
                Some(&format!("- timescales:session:{}", "AB".repeat(32))),
            ),
        ),
        (
            "a short session key",
            with_line(
                &session_line,
                Some(&format!("- timescales:session:{}", "ab".repeat(31))),
            ),
        ),
        (
            "out-of-order fields",
            canonical().replace(
                "URI: https://app.timescales.example\nVersion: 1",
                "Version: 1\nURI: https://app.timescales.example",
            ),
        ),
        (
            "a repeated field",
            with_line("Version: 1", Some("Version: 1\nVersion: 1")),
        ),
        ("an empty field", with_line("Version: 1", Some("Version: "))),
        (
            "a missing nonce",
            with_line("Nonce: 00112233445566778899aabbccddeeff", None),
        ),
        (
            "a short nonce",
            with_line(
                "Nonce: 00112233445566778899aabbccddeeff",
                Some("Nonce: 0011223344556677"),
            ),
        ),
        (
            "an uppercase nonce",
            with_line(
                "Nonce: 00112233445566778899aabbccddeeff",
                Some("Nonce: 00112233445566778899AABBCCDDEEFF"),
            ),
        ),
        (
            "an unknown chain",
            with_line("Chain ID: devnet", Some("Chain ID: testnet")),
        ),
        (
            "a missing URI",
            with_line("URI: https://app.timescales.example", None),
        ),
        (
            "a URI without a scheme",
            with_line(
                "URI: https://app.timescales.example",
                Some("URI: app.timescales.example"),
            ),
        ),
        (
            "an invalid address",
            canonical().replace(&b58([1; 32]), "0OIl"),
        ),
        (
            "a non-canonical address",
            canonical().replace(&b58([1; 32]), &format!("1{}", b58([1; 32]))),
        ),
        (
            "a short address",
            canonical().replace(&b58([1; 32]), &bs58::encode([1u8; 31]).into_string()),
        ),
        (
            "sub-millisecond precision",
            with_line(
                "Issued At: 2026-10-07T12:00:00.123Z",
                Some("Issued At: 2026-10-07T12:00:00.1234Z"),
            ),
        ),
        (
            "an impossible date",
            with_line(
                "Issued At: 2026-10-07T12:00:00.123Z",
                Some("Issued At: 2026-02-30T12:00:00.123Z"),
            ),
        ),
        (
            "a leap second",
            with_line(
                "Issued At: 2026-10-07T12:00:00.123Z",
                Some("Issued At: 2026-12-31T23:59:60Z"),
            ),
        ),
        (
            "expiry before issuance",
            with_line(
                "Expiration Time: 2026-10-08T00:00:00.123Z",
                Some("Expiration Time: 2026-10-07T00:00:00Z"),
            ),
        ),
        (
            "expiry equal to issuance",
            with_line(
                "Expiration Time: 2026-10-08T00:00:00.123Z",
                Some("Expiration Time: 2026-10-07T12:00:00.123Z"),
            ),
        ),
        (
            "a wrong header",
            canonical().replace(
                "wants you to sign in with your Solana account:",
                "wants you to sign in with your Ethereum account:",
            ),
        ),
        (
            "a domain with a path",
            canonical().replace(
                "app.timescales.example wants",
                "app.timescales.example/x wants",
            ),
        ),
        (
            "a missing blank line after the address",
            canonical().replacen(
                &format!("{}\n\n", b58([1; 32])),
                &format!("{}\n", b58([1; 32])),
                1,
            ),
        ),
        (
            "a missing blank line after the statement",
            canonical().replace(
                &format!("{SESSION_STATEMENT}\n\n"),
                &format!("{SESSION_STATEMENT}\n"),
            ),
        ),
        (
            "an unknown line",
            with_line("Version: 1", Some("Version: 1\nColor: blue")),
        ),
        ("an empty resource", format!("{}\n- ", canonical())),
        (
            "text over 1024 bytes",
            canonical().replace(SESSION_STATEMENT, &"x".repeat(MAX_SESSION_TEXT_BYTES)),
        ),
        ("an empty message", String::new()),
        (
            "only the header",
            canonical().split('\n').next().unwrap().to_owned(),
        ),
        (
            "nothing after the address",
            canonical()
                .split('\n')
                .take(2)
                .collect::<Vec<_>>()
                .join("\n"),
        ),
    ];
    for (name, text) in negatives {
        assert!(
            matches!(parse_session_message(&text), Err(WireError::Template(_))),
            "{name} was accepted"
        );
    }
}

#[test]
fn a_not_before_grant_renders_but_is_never_accepted() {
    let g = SessionGrant {
        not_before_ms: Some(ISSUED + HOUR),
        ..grant()
    };
    let text = render_session_message(&g);
    assert!(text.contains("\nNot Before: 2026-10-07T13:00:00.123Z\nResources:"));
    assert!(parse_session_message(&text).is_err());
    assert!(matches!(
        check_at(&g, ISSUED + 2 * HOUR),
        Err(WireError::Template("Not Before is not supported"))
    ));
}

fn check_at(g: &SessionGrant, now_ms: u64) -> Result<(), WireError> {
    let domains = [
        "app.timescales.example".to_owned(),
        "localhost:4173".to_owned(),
    ];
    g.check(&GrantExpectations {
        domains: &domains,
        uri: "https://app.timescales.example",
        chain_id: ChainId::Devnet,
        program: [2; 32],
        now_ms,
        max_ttl_ms: 24 * HOUR,
    })
}

#[test]
fn grants_are_checked_against_the_deployment() {
    let now = ISSUED + 1;
    assert!(check_at(&grant(), now).is_ok());
    let unstated = SessionGrant {
        statement: String::new(),
        ..grant()
    };
    assert!(check_at(&unstated, now).is_ok());

    let elsewhere = SessionGrant {
        domain: "evil.example".into(),
        ..grant()
    };
    assert!(matches!(
        check_at(&elsewhere, now),
        Err(WireError::Audience)
    ));
    let case = SessionGrant {
        domain: "App.Timescales.Example".into(),
        ..grant()
    };
    assert!(matches!(check_at(&case, now), Err(WireError::Audience)));
    for (what, g) in [
        (
            "uri",
            SessionGrant {
                uri: "https://evil.example".into(),
                ..grant()
            },
        ),
        (
            "chain",
            SessionGrant {
                chain_id: ChainId::Mainnet,
                ..grant()
            },
        ),
        (
            "program",
            SessionGrant {
                program: [9; 32],
                ..grant()
            },
        ),
        (
            "statement",
            SessionGrant {
                statement: "Sign in to win a prize".into(),
                ..grant()
            },
        ),
        (
            "expiry",
            SessionGrant {
                expires_at_ms: ISSUED,
                ..grant()
            },
        ),
    ] {
        assert!(
            matches!(check_at(&g, now), Err(WireError::Template(_))),
            "{what}"
        );
    }
}

#[test]
fn grant_lifetimes_are_bounded_and_expire() {
    let ttl = 24 * HOUR;
    let longest = SessionGrant {
        expires_at_ms: ISSUED + ttl,
        ..grant()
    };
    assert!(check_at(&longest, ISSUED).is_ok());
    let too_long = SessionGrant {
        expires_at_ms: ISSUED + ttl + 1,
        ..grant()
    };
    assert!(matches!(
        check_at(&too_long, ISSUED),
        Err(WireError::Policy(_))
    ));
    // Dated in the future, a grant still cannot outlive the limit from now.
    let future = SessionGrant {
        issued_at_ms: ISSUED + 10 * HOUR,
        expires_at_ms: ISSUED + 30 * HOUR,
        ..grant()
    };
    assert!(matches!(
        check_at(&future, ISSUED),
        Err(WireError::Policy(_))
    ));

    let g = grant();
    assert!(check_at(&g, g.expires_at_ms - 1).is_ok());
    assert!(matches!(
        check_at(&g, g.expires_at_ms),
        Err(WireError::Expired)
    ));
    assert!(matches!(
        check_at(&g, g.expires_at_ms + HOUR),
        Err(WireError::Expired)
    ));
}

#[test]
fn chain_ids_have_one_text_each() {
    for c in [ChainId::Localnet, ChainId::Devnet, ChainId::Mainnet] {
        assert_eq!(ChainId::parse(c.as_str()), Some(c));
        assert_eq!(ChainId::parse(&format!("solana:{}", c.as_str())), Some(c));
    }
    assert_eq!(ChainId::Mainnet.as_str(), "mainnet");
    assert_eq!(ChainId::parse("mainnet-beta"), None);
    assert_eq!(ChainId::parse("solana:solana:devnet"), None);
    assert_eq!(ChainId::parse("Devnet"), None);
}

#[test]
fn request_digests_bind_method_path_time_and_body() {
    let d = session_request_digest("POST", "/v1/markets/x/submissions?batch=1", 1_234, b"{}");
    let expected = Hasher::new(domain::SESSION)
        .chain(b"request")
        .chain(b"POST")
        .chain(&[0])
        .chain(b"/v1/markets/x/submissions?batch=1")
        .chain(&[0])
        .chain(&1_234u64.to_le_bytes())
        .chain(&Sha256::digest(b"{}"))
        .finalize();
    assert_eq!(d, expected);
    let others = [
        session_request_digest("GET", "/v1/markets/x/submissions?batch=1", 1_234, b"{}"),
        session_request_digest("POST", "/v1/markets/x/submissions?batch=2", 1_234, b"{}"),
        session_request_digest("POST", "/v1/markets/x/submissions?batch=1", 1_235, b"{}"),
        session_request_digest("POST", "/v1/markets/x/submissions?batch=1", 1_234, b"{ }"),
        session_request_digest("POS", "T/v1/markets/x/submissions?batch=1", 1_234, b"{}"),
    ];
    for o in others {
        assert_ne!(o, d);
    }
}

#[test]
fn session_authorizations_render_parse_and_verify() {
    let key = keypair(30);
    let a = SessionAuthorization::sign(
        &key,
        "DELETE",
        "/v1/sessions/current",
        1_791_000_000_000,
        b"",
    );
    let header = a.render();
    assert_eq!(
        header,
        format!(
            "TimescalesSession {}.1791000000000.{}",
            hex::encode(key.public()),
            hex::encode(a.signature.0)
        )
    );
    let parsed = SessionAuthorization::parse(&header).unwrap();
    assert_eq!(parsed, a);
    assert!(
        parsed
            .verify(
                "DELETE",
                "/v1/sessions/current",
                b"",
                1_791_000_010_000,
                30_000
            )
            .is_ok()
    );
    assert!(matches!(
        parsed.verify(
            "DELETE",
            "/v1/sessions/current",
            b"",
            1_791_000_030_001,
            30_000
        ),
        Err(WireError::Skew { .. })
    ));
    assert!(matches!(
        parsed.verify(
            "DELETE",
            "/v1/sessions/current",
            b"",
            1_790_999_969_999,
            30_000
        ),
        Err(WireError::Skew { .. })
    ));
    assert!(matches!(
        parsed.verify(
            "GET",
            "/v1/sessions/current",
            b"",
            1_791_000_000_000,
            30_000
        ),
        Err(WireError::BadSignature)
    ));
    assert!(matches!(
        parsed.verify(
            "DELETE",
            "/v1/sessions/current",
            b"x",
            1_791_000_000_000,
            30_000
        ),
        Err(WireError::BadSignature)
    ));
    let zero = SessionAuthorization::sign(&key, "GET", "/", 0, b"");
    assert_eq!(SessionAuthorization::parse(&zero.render()).unwrap(), zero);
}

#[test]
fn malformed_authorization_headers_are_refused() {
    let a = SessionAuthorization::sign(&keypair(30), "GET", "/v1/sessions/current", 77, b"");
    let pk = hex::encode(a.session_key);
    let sig = hex::encode(a.signature.0);
    for header in [
        String::new(),
        format!("Bearer {pk}.77.{sig}"),
        format!("timescalessession {pk}.77.{sig}"),
        format!("TimescalesSession  {pk}.77.{sig}"),
        format!("TimescalesSession {pk}.077.{sig}"),
        format!("TimescalesSession {pk}.+77.{sig}"),
        format!("TimescalesSession {pk}..{sig}"),
        format!("TimescalesSession {pk}.18446744073709551616.{sig}"),
        format!("TimescalesSession {pk}.77"),
        format!("TimescalesSession {pk}.77.{sig}.1"),
        format!("TimescalesSession {}.77.{sig}", pk.to_uppercase()),
        format!("TimescalesSession {}.77.{sig}", &pk[2..]),
        format!("TimescalesSession {pk}.77.{}", &sig[..126]),
        format!("TimescalesSession {pk}.77.{}g", &sig[..127]),
    ] {
        assert!(
            matches!(
                SessionAuthorization::parse(&header),
                Err(WireError::Template(_))
            ),
            "{header}"
        );
    }
    let max = format!("TimescalesSession {pk}.18446744073709551615.{sig}");
    assert_eq!(SessionAuthorization::parse(&max).unwrap().ts_ms, u64::MAX);
}

#[test]
fn fresh_session_nonces_check_out() {
    let key = [5u8; 32];
    let now = 1_791_374_400_500;
    let nonce = issue_session_nonce(&key, now, &mut rng(1));
    assert_eq!(&nonce[..4], &(1_791_374_400u32).to_le_bytes());
    assert!(check_session_nonce(&key, &nonce, now, 300_000).is_ok());
    // The TTL counts from the issuing second.
    assert!(check_session_nonce(&key, &nonce, 1_791_374_400_000 + 300_000, 300_000).is_ok());
    assert!(matches!(
        check_session_nonce(&key, &nonce, 1_791_374_400_000 + 300_001, 300_000),
        Err(WireError::Expired)
    ));
    let other = issue_session_nonce(&key, now, &mut rng(2));
    assert_ne!(other, nonce);
    // A nonce is what a grant carries.
    let g = SessionGrant { nonce, ..grant() };
    assert_eq!(
        parse_session_message(&render_session_message(&g))
            .unwrap()
            .nonce,
        nonce
    );
}

#[test]
fn forged_and_future_session_nonces_are_refused() {
    let key = [5u8; 32];
    let now = 1_791_374_400_500;
    let nonce = issue_session_nonce(&key, now, &mut rng(1));
    assert!(matches!(
        check_session_nonce(&[6; 32], &nonce, now, 300_000),
        Err(WireError::Nonce)
    ));
    for at in 0..16 {
        let mut forged = nonce;
        forged[at] ^= 1;
        assert!(
            matches!(
                check_session_nonce(&key, &forged, now, 300_000),
                Err(WireError::Nonce)
            ),
            "byte {at}"
        );
    }
    // A forged MAC is refused whatever its age.
    let mut stale = nonce;
    stale[15] ^= 1;
    assert!(matches!(
        check_session_nonce(&key, &stale, now + 10 * 300_000, 300_000),
        Err(WireError::Nonce)
    ));
    let early = issue_session_nonce(&key, now + 5_000, &mut rng(3));
    assert!(matches!(
        check_session_nonce(&key, &early, now, 300_000),
        Err(WireError::Nonce)
    ));
}

#[test]
fn session_keys_sign_like_any_keypair() {
    let key = Keypair::from_seed([1; 32]);
    let a = SessionAuthorization::sign(&key, "GET", "/v1/sessions/current", 5, b"");
    assert_eq!(a.session_key, key.public());
    timescales_core::crypto::verify_digest(
        &key.public(),
        &session_request_digest("GET", "/v1/sessions/current", 5, b""),
        &a.signature,
    )
    .unwrap();
}
