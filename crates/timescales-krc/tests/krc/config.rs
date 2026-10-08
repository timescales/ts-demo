//! Configuration files: the production fixtures pass `config-check
//! --offline`, and every rule refuses what it should.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use timescales_core::Encode;
use timescales_core::crypto::{Keypair, SealSecret, hash};
use timescales_krc::config::{DealerFile, MemberFile};
use timescales_krc::service::{AnyConfig, file_issues, load_any};
use timescales_service::wire::{CommitteeDescription, CommitteeMember};
use timescales_service::{ConfigError, Profile, load_config};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/krc/data")
}

/// The committee of the production fixtures: five members, threshold 3,
/// keys derived from fixed labels (no secret of any deployment).
fn fixture_committee() -> CommitteeDescription {
    let market = hash(b"timescales/test/fixture-market", &[]).0;
    CommitteeDescription {
        version: CommitteeDescription::VERSION,
        market,
        threshold: 3,
        members: (1..=5u8)
            .map(|i| CommitteeMember {
                index: i,
                identity: Keypair::from_seed(hash(b"timescales/test/fixture-identity", &[i]).0)
                    .public(),
                transport: SealSecret::from_bytes(
                    hash(b"timescales/test/fixture-transport", &[i]).0,
                )
                .public(),
            })
            .collect(),
    }
}

#[test]
fn the_committee_fixture_is_what_its_generator_writes() {
    let committee = fixture_committee();
    committee.validate().unwrap();
    let path = fixtures().join("committee-production.bin");
    if std::env::var_os("TIMESCALES_KRC_WRITE_FIXTURES").is_some() {
        std::fs::write(&path, committee.to_bytes()).unwrap();
        println!("market {}", bs58::encode(committee.market).into_string());
        println!(
            "dealer {}",
            hex::encode(
                Keypair::from_seed(hash(b"timescales/test/fixture-dealer", &[]).0).public()
            )
        );
    }
    assert_eq!(std::fs::read(path).unwrap(), committee.to_bytes());
}

fn load_member_file(text: &str, profile: Option<Profile>) -> Result<MemberFile, ConfigError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("member.toml");
    std::fs::write(&path, text).unwrap();
    load_config::<MemberFile>(&path, profile)
}

fn load_dealer_file(text: &str, profile: Option<Profile>) -> Result<DealerFile, ConfigError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dealer.toml");
    std::fs::write(&path, text).unwrap();
    load_config::<DealerFile>(&path, profile)
}

fn issues(r: Result<impl std::fmt::Debug, ConfigError>) -> Vec<String> {
    match r {
        Err(ConfigError::Invalid(issues)) => issues.iter().map(ToString::to_string).collect(),
        other => panic!("expected configuration issues, got {other:?}"),
    }
}

fn edit(text: &str, f: impl FnOnce(&mut toml::Table)) -> String {
    let mut t: toml::Table = toml::from_str(text).unwrap();
    f(&mut t);
    toml::to_string(&t).unwrap()
}

fn table<'a>(t: &'a mut toml::Table, path: &[&str]) -> &'a mut toml::Table {
    path.iter().fold(t, |t, k| t[*k].as_table_mut().unwrap())
}

fn member_fixture() -> String {
    std::fs::read_to_string(fixtures().join("member.production.toml")).unwrap()
}

fn dealer_fixture() -> String {
    std::fs::read_to_string(fixtures().join("dealer.production.toml")).unwrap()
}

#[test]
fn the_production_fixtures_pass_the_offline_check() {
    for name in ["member.production.toml", "dealer.production.toml"] {
        let cfg = load_any(&fixtures().join(name), None).unwrap();
        assert!(
            file_issues(&cfg).is_empty(),
            "{name}: {:?}",
            file_issues(&cfg)
        );
        match cfg {
            AnyConfig::Member(m) => {
                assert_eq!(m.profile, Profile::Production);
                // Relative paths resolve against the file's directory.
                assert_eq!(
                    m.markets[0].committee_file,
                    fixtures().join("committee-production.bin")
                );
            }
            AnyConfig::Dealer(d) => assert_eq!(d.profile, Profile::Production),
        }
    }
}

#[test]
fn production_refuses_an_unsafe_member() {
    let text = edit(&member_fixture(), |t| {
        let m = table(t, &["member"]);
        m.remove("tls");
        m["shares_dir"] = "/var/lib/timescales-krc/shares".into();
        let chain = table(t, &["member", "chain"]);
        chain["rpc_urls"] = toml::Value::Array(vec!["http://127.0.0.1:8899".into()]);
        chain["rpc_agree"] = 1.into();
        chain["release_commitment"] = "confirmed".into();
        let policy = table(t, &["member", "policy"]);
        policy["allow_debug"] = true.into();
        policy["min_tcb"] = "out_of_date".into();
        policy["tdx_mr_config_id"] = "".into();
        policy["tdx_xfam"] = "".into();
        policy["tdx_td_attributes_mask"] = "".into();
        table(t, &["member", "telemetry"])["log_format"] = "pretty".into();
    });
    let found = issues(load_member_file(&text, None));
    for expected in [
        "member.tls: mutual TLS is required in production",
        "member.shares_dir:",
        "member.chain.rpc_urls[0]: must be https in production",
        "member.chain.rpc_urls: production needs at least 2 independent providers",
        "member.chain.rpc_agree: production needs at least 2 agreeing providers",
        "member.chain.release_commitment:",
        "member.policy: debug enclaves are not accepted under the production profile",
        "member.policy: minimum TCB OutOfDate is below sw_hardening_needed",
        "member.policy: no MRCONFIGID pin",
        "member.policy: no XFAM pin",
        "member.policy: no TD attributes rule",
        "member.telemetry.log_format: must be json in production",
    ] {
        assert!(
            found.iter().any(|i| i.starts_with(expected)),
            "missing {expected:?} in {found:#?}"
        );
    }
}

#[test]
fn production_refuses_the_simulated_platform() {
    let text = edit(&member_fixture(), |t| {
        let policy = table(t, &["member", "policy"]);
        policy["platforms"] = toml::Value::Array(vec!["simulated".into(), "intel_tdx".into()]);
        policy.insert("simulated_vendor_root".into(), "11".repeat(32).into());
    });
    let found = issues(load_member_file(&text, None));
    assert!(
        found.iter().any(|i| i
            == "member.policy: the simulated platform is not accepted under the production profile"),
        "{found:#?}"
    );
}

#[test]
fn a_local_profile_allows_what_production_refuses() {
    let text = edit(&member_fixture(), |t| {
        let chain = table(t, &["member", "chain"]);
        chain["cluster"] = "localnet".into();
        chain["genesis_hash"] = bs58::encode([0x6e; 32]).into_string().into();
        chain["rpc_urls"] = toml::Value::Array(vec!["http://127.0.0.1:8899".into()]);
        chain["rpc_agree"] = 1.into();
        chain["release_commitment"] = "confirmed".into();
        table(t, &["member"]).remove("tls");
        table(t, &["member", "telemetry"])["log_format"] = "pretty".into();
    });
    assert!(load_member_file(&text, Some(Profile::Local)).is_ok());
    // "confirmed" is for local only.
    let found = issues(load_member_file(&text, Some(Profile::Devnet)));
    assert!(
        found
            .iter()
            .any(|i| i.starts_with("member.chain.release_commitment")),
        "{found:#?}"
    );
}

#[test]
fn mainnet_refuses_every_profile_but_production() {
    let found = issues(load_member_file(&member_fixture(), Some(Profile::Devnet)));
    assert!(
        found
            .iter()
            .any(|i| i.starts_with("member.chain.genesis_hash: mainnet-beta refuses")),
        "{found:#?}"
    );
}

#[test]
fn unknown_fields_and_malformed_values_are_refused() {
    let text = edit(&member_fixture(), |t| {
        table(t, &["member"]).insert("shares_backup".into(), true.into());
    });
    assert!(matches!(
        load_member_file(&text, None),
        Err(ConfigError::Parse { .. })
    ));
    let text = edit(&member_fixture(), |t| {
        let m = table(t, &["member"]);
        m["index"] = 0.into();
        m["dealer_keys"] = toml::Value::Array(vec!["beef".into()]);
        m["max_releases_per_epoch"] = 9.into();
        table(t, &["member", "policy"])["measurements"] = toml::Value::Array(vec!["xyz".into()]);
    });
    let found = issues(load_member_file(&text, None));
    for expected in [
        "member.index: must be 1..=16",
        "member.dealer_keys[0]: expected 64 hex digits",
        "member.max_releases_per_epoch: must be 1..=8",
        "member.policy.measurements[0]: expected 64 hex digits",
    ] {
        assert!(
            found.iter().any(|i| i == expected),
            "missing {expected:?} in {found:#?}"
        );
    }
}

#[test]
fn production_refuses_an_unsafe_dealer() {
    let text = edit(&dealer_fixture(), |t| {
        let d = table(t, &["dealer"]);
        d.remove("tls");
        d["node_url"] = "http://10.0.0.5:8081".into();
        d["lookahead_epochs"] = 1.into();
        d["member_urls"] = toml::Value::Array(vec!["http://10.0.0.6:8095".into()]);
    });
    let found = issues(load_dealer_file(&text, None));
    for expected in [
        "dealer.tls: mutual TLS is required in production",
        "dealer.node_url: must be https in production",
        "dealer.member_urls[0]: must be https in production",
        "dealer.lookahead_epochs:",
    ] {
        assert!(
            found.iter().any(|i| i.starts_with(expected)),
            "missing {expected:?} in {found:#?}"
        );
    }
}

#[test]
fn the_dealer_needs_one_url_per_committee_member() {
    let text = edit(&dealer_fixture(), |t| {
        let d = table(t, &["dealer"]);
        d["member_urls"] = toml::Value::Array(vec!["https://m1.krc.example".into()]);
        table(t, &["dealer"])["market"].as_array_mut().unwrap()[0]
            .as_table_mut()
            .unwrap()["committee_file"] = fixtures()
            .join("committee-production.bin")
            .to_string_lossy()
            .into_owned()
            .into();
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dealer.toml");
    std::fs::write(&path, text).unwrap();
    let cfg = load_any(&path, None).unwrap();
    let found = file_issues(&cfg);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].field, "dealer.member_urls");
}

#[tokio::test]
async fn a_member_with_tls_configured_does_not_serve_plaintext() {
    let text = edit(&member_fixture(), |t| {
        let chain = table(t, &["member", "chain"]);
        chain["cluster"] = "devnet".into();
        chain["genesis_hash"] = bs58::encode([0x6e; 32]).into_string().into();
    });
    let cfg = load_member_file(&text, Some(Profile::Devnet))
        .unwrap()
        .member;
    let err = timescales_krc::service::run_member(cfg, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("cannot serve mutual TLS"),
        "{err:#}"
    );
}
