//! Configuration loading, profiles and the start-up refusals.

use std::cell::RefCell;

use serde::Deserialize;
use timescales_service::{
    BuildInfo, ConfigError, ConfigIssue, LogFormat, MAINNET_BETA_GENESIS_HASH, Profile,
    TelemetryConfig, TlsConfig, Validate, check_cluster_profile, load_config, refuse_simulation,
};

use crate::common::write_file;

/// Base58 as Solana writes genesis hashes.
fn b58(s: &str) -> [u8; 32] {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out = [0u8; 32];
    for c in s.bytes() {
        let mut carry = u32::try_from(ALPHABET.iter().position(|a| *a == c).unwrap()).unwrap();
        for byte in out.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        assert_eq!(carry, 0, "{s} does not fit 32 bytes");
    }
    out
}

const DEVNET: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const TESTNET: &str = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";

#[test]
fn mainnet_genesis_refuses_non_production() {
    assert_eq!(
        MAINNET_BETA_GENESIS_HASH,
        b58("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d")
    );
    for profile in [Profile::Local, Profile::Devnet] {
        match check_cluster_profile(profile, &MAINNET_BETA_GENESIS_HASH) {
            Err(ConfigError::MainnetNonProduction(p)) => assert_eq!(p, profile),
            other => panic!("{profile:?} on mainnet-beta: {other:?}"),
        }
    }
    assert!(check_cluster_profile(Profile::Production, &MAINNET_BETA_GENESIS_HASH).is_ok());
    for other in [b58(DEVNET), b58(TESTNET), [0; 32]] {
        for profile in [Profile::Local, Profile::Devnet, Profile::Production] {
            assert!(check_cluster_profile(profile, &other).is_ok());
        }
    }
}

#[test]
fn production_refuses_simulation_builds() {
    let clean = BuildInfo {
        version: "0.1.0",
        git_sha: "abc",
        simulation: false,
        sim_platform: false,
    };
    for build in [
        BuildInfo {
            simulation: true,
            ..clean
        },
        BuildInfo {
            sim_platform: true,
            ..clean
        },
    ] {
        assert!(matches!(
            refuse_simulation(Profile::Production, &build),
            Err(ConfigError::SimulationBuild)
        ));
        assert!(refuse_simulation(Profile::Local, &build).is_ok());
        assert!(refuse_simulation(Profile::Devnet, &build).is_ok());
    }
    assert!(refuse_simulation(Profile::Production, &clean).is_ok());
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestConfig {
    service: Section,
    telemetry: TelemetryConfig,
    #[serde(default)]
    tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    profile: Profile,
    listen: String,
}

thread_local! {
    /// The profile each validation on this test's thread ran under.
    static VALIDATED: RefCell<Vec<Profile>> = const { RefCell::new(Vec::new()) };
}

fn last_validated() -> Option<Profile> {
    VALIDATED.with(|v| v.borrow().last().copied())
}

impl Validate for TestConfig {
    fn validate(&self, profile: Profile) -> Result<(), Vec<ConfigIssue>> {
        VALIDATED.with(|v| v.borrow_mut().push(profile));
        let mut issues = Vec::new();
        if profile == Profile::Production {
            if self.telemetry.log_format != LogFormat::Json {
                issues.push(ConfigIssue::new(
                    "telemetry.log_format",
                    "must be json in production",
                ));
            }
            if self.tls.is_none() {
                issues.push(ConfigIssue::new(
                    "tls",
                    "mutual TLS is required in production",
                ));
            }
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }
}

const GOOD: &str = r#"
[service]
profile = "local"
listen = "127.0.0.1:9000"

[telemetry]
log_format = "pretty"
log_filter = "info"
"#;

fn write(dir: &std::path::Path, text: &str) -> std::path::PathBuf {
    write_file(dir, "service.toml", text.as_bytes(), 0o644)
}

#[test]
fn load_config_parses_validates_and_overrides_the_profile() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), GOOD);
    let cfg: TestConfig = load_config(&path, None).unwrap();
    assert_eq!(cfg.service.profile, Profile::Local);
    assert_eq!(cfg.service.listen, "127.0.0.1:9000");
    assert_eq!(cfg.telemetry.otlp_endpoint, "");
    assert_eq!(last_validated(), Some(Profile::Local));

    // An override is what the configuration is validated under, and what
    // it says afterwards.
    let cfg: TestConfig = load_config(&path, Some(Profile::Devnet)).unwrap();
    assert_eq!(cfg.service.profile, Profile::Devnet);
    assert_eq!(last_validated(), Some(Profile::Devnet));

    match load_config::<TestConfig>(&path, Some(Profile::Production)) {
        Err(ConfigError::Invalid(issues)) => {
            let fields: Vec<_> = issues.iter().map(|i| i.field.as_str()).collect();
            assert_eq!(fields, ["telemetry.log_format", "tls"]);
            let message = ConfigError::Invalid(issues).to_string();
            assert!(
                message.starts_with("2 configuration issue(s): telemetry.log_format: must be json"),
                "{message}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn unknown_fields_and_missing_profiles_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let unknown = write(dir.path(), &format!("{GOOD}\n[service.extra]\nx = 1\n"));
    match load_config::<TestConfig>(&unknown, None) {
        Err(ConfigError::Parse { message, .. }) => assert!(message.contains("extra"), "{message}"),
        other => panic!("{other:?}"),
    }
    let typo = write(dir.path(), &GOOD.replace("log_filter", "log_filtr"));
    match load_config::<TestConfig>(&typo, None) {
        // Line and column are reported when nothing was overridden.
        Err(ConfigError::Parse { message, .. }) => {
            assert!(
                message.contains("log_filtr") && message.contains("line"),
                "{message}"
            )
        }
        other => panic!("{other:?}"),
    }
    match load_config::<TestConfig>(&typo, Some(Profile::Local)) {
        Err(ConfigError::Parse { message, .. }) => {
            assert!(message.contains("log_filtr"), "{message}")
        }
        other => panic!("{other:?}"),
    }

    let no_profile = write(dir.path(), &GOOD.replace("profile = \"local\"\n", ""));
    match load_config::<TestConfig>(&no_profile, None) {
        Err(ConfigError::Invalid(issues)) => assert_eq!(issues[0].field, "profile"),
        other => panic!("{other:?}"),
    }
    // The override supplies the profile, but the type still requires the
    // field, so the file must name one.
    assert!(matches!(
        load_config::<TestConfig>(&no_profile, Some(Profile::Local)),
        Err(ConfigError::Parse { .. })
    ));
    let bad_profile = write(dir.path(), &GOOD.replace("\"local\"", "\"staging\""));
    match load_config::<TestConfig>(&bad_profile, None) {
        Err(ConfigError::Invalid(issues)) => assert_eq!(issues[0].field, "service.profile"),
        other => panic!("{other:?}"),
    }

    assert!(matches!(
        load_config::<TestConfig>(&dir.path().join("missing.toml"), None),
        Err(ConfigError::Io { .. })
    ));
    let big = write(
        dir.path(),
        &format!("{GOOD}\n#{}\n", "x".repeat(1024 * 1024)),
    );
    assert!(matches!(
        load_config::<TestConfig>(&big, None),
        Err(ConfigError::Parse { .. })
    ));
    let broken = write(dir.path(), "[service\nprofile = 1");
    assert!(matches!(
        load_config::<TestConfig>(&broken, None),
        Err(ConfigError::Parse { .. })
    ));
}

#[test]
fn tls_pins_are_written_in_hex() {
    let dir = tempfile::tempdir().unwrap();
    let pin = "ab".repeat(32);
    let text = format!(
        "{GOOD}\n[tls]\ncert_file = \"/etc/svc.crt\"\nkey_file = \"/etc/svc.key\"\npeer_spki_sha256 = [\"{pin}\", \"{}\"]\n",
        "CD".repeat(32)
    );
    let cfg: TestConfig = load_config(&write(dir.path(), &text), None).unwrap();
    let tls = cfg.tls.unwrap();
    assert_eq!(tls.peer_spki_sha256, vec![[0xab; 32], [0xcd; 32]]);
    assert_eq!(tls.cert_file, std::path::Path::new("/etc/svc.crt"));

    let empty = format!("{GOOD}\n[tls]\ncert_file = \"a\"\nkey_file = \"b\"\n");
    let cfg: TestConfig = load_config(&write(dir.path(), &empty), None).unwrap();
    assert!(cfg.tls.unwrap().peer_spki_sha256.is_empty());

    for bad in [
        "\"abcd\"".to_owned(),
        format!("\"{}\"", "zz".repeat(32)),
        "[1, 2]".to_owned(),
    ] {
        let text = format!(
            "{GOOD}\n[tls]\ncert_file = \"a\"\nkey_file = \"b\"\npeer_spki_sha256 = [{bad}]\n"
        );
        assert!(
            matches!(
                load_config::<TestConfig>(&write(dir.path(), &text), None),
                Err(ConfigError::Parse { .. })
            ),
            "{bad}"
        );
    }
}
