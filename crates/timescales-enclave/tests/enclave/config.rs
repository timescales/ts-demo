//! Configuration files: the production fixture passes `config-check
//! --offline`, and every rule refuses what it should.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use timescales_core::Encode;
use timescales_core::crypto::{Keypair, SealSecret, hash};
use timescales_enclave::EnclaveFile;
use timescales_enclave::run::load;
use timescales_service::wire::{CommitteeDescription, CommitteeMember};
use timescales_service::{ConfigError, Profile, load_config};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/enclave/data")
}

/// The committee of the production fixture: five members, threshold 3,
/// keys derived from fixed labels (no secret of any deployment).
fn fixture_committee() -> CommitteeDescription {
    let market = hash(b"timescales/test/enclave-fixture-market", &[]).0;
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
    if std::env::var_os("TIMESCALES_ENCLAVE_WRITE_FIXTURES").is_some() {
        std::fs::write(&path, committee.to_bytes()).unwrap();
        println!("market {}", bs58::encode(committee.market).into_string());
    }
    assert_eq!(std::fs::read(path).unwrap(), committee.to_bytes());
}

#[test]
fn the_production_fixture_passes_the_offline_check() {
    let cfg = load(&fixtures().join("enclave.production.toml"), None).unwrap();
    assert_eq!(cfg.profile, Profile::Production);
    assert!(cfg.file_issues().is_empty(), "{:?}", cfg.file_issues());
    // Relative paths resolve against the file.
    assert_eq!(
        cfg.markets[0].committee_file,
        fixtures().join("committee-production.bin")
    );
    assert_eq!(cfg.market_addresses(), vec![fixture_committee().market]);
}

fn fixture_text() -> String {
    std::fs::read_to_string(fixtures().join("enclave.production.toml")).unwrap()
}

fn edit(text: &str, f: impl FnOnce(&mut toml::Table)) -> String {
    let mut t: toml::Table = toml::from_str(text).unwrap();
    f(t.get_mut("enclave").unwrap().as_table_mut().unwrap());
    toml::to_string(&t).unwrap()
}

fn issues_of(text: &str, profile: Option<Profile>) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("enclave.toml");
    std::fs::write(&path, text).unwrap();
    match load_config::<EnclaveFile>(&path, profile) {
        Err(ConfigError::Invalid(issues)) => issues.iter().map(ToString::to_string).collect(),
        Ok(_) => Vec::new(),
        Err(other) => panic!("{other}"),
    }
}

fn has(issues: &[String], field: &str) -> bool {
    issues.iter().any(|i| i.starts_with(&format!("{field}:")))
}

#[test]
fn production_refuses_the_simulated_platform_and_weak_links() {
    let text = edit(&fixture_text(), |t| {
        t.insert("platform".into(), "simulated".into());
        t.insert("simulated_key_file".into(), "keys.bin".into());
        t.insert("simulated_vendor_seed".into(), "vendor.hex".into());
        t.insert("allow_sign_message_grants".into(), true.into());
        t.insert(
            "member_urls".into(),
            toml::Value::Array(vec!["http://member-1.internal:8095".into()]),
        );
        t.remove("tls");
        let chain = t.get_mut("chain").unwrap().as_table_mut().unwrap();
        chain.insert("rpc_agree".into(), 1.into());
        chain.insert(
            "rpc_urls".into(),
            toml::Value::Array(vec!["https://rpc-one.example.org".into()]),
        );
    });
    let issues = issues_of(&text, None);
    for field in [
        "enclave.platform",
        "enclave.allow_sign_message_grants",
        "enclave.member_urls[0]",
        "enclave.tls",
        "enclave.chain.rpc_agree",
        "enclave.chain.rpc_urls",
    ] {
        assert!(has(&issues, field), "{field} not refused: {issues:?}");
    }
    // The same file is acceptable for a local stack except for mainnet.
    let local = edit(&text, |t| {
        let chain = t.get_mut("chain").unwrap().as_table_mut().unwrap();
        chain.insert("cluster".into(), "localnet".into());
        chain.insert(
            "genesis_hash".into(),
            bs58::encode([1u8; 32]).into_string().into(),
        );
    });
    assert!(issues_of(&local, Some(Profile::Local)).is_empty());
    // A non-production profile on mainnet-beta's genesis is refused.
    let issues = issues_of(&text, Some(Profile::Devnet));
    assert!(has(&issues, "enclave.chain.genesis_hash"), "{issues:?}");
}

#[test]
fn malformed_values_and_unknown_fields_are_refused() {
    let text = edit(&fixture_text(), |t| {
        t.insert("node_keys".into(), toml::Value::Array(vec!["zz".into()]));
        t.insert("listen".into(), "8090".into());
        t.insert("post_deadline_ms".into(), 0.into());
        t.insert("max_body_bytes".into(), 10.into());
        t.insert("tdx_configfs_root".into(), "".into());
        let fee = t
            .get_mut("chain")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .get_mut("priority_fee")
            .unwrap()
            .as_table_mut()
            .unwrap();
        fee.insert("mode".into(), "dynamic".into());
        fee.insert("max_micro_lamports".into(), "-1".into());
    });
    let issues = issues_of(&text, None);
    for field in [
        "enclave.node_keys[0]",
        "enclave.listen",
        "enclave.post_deadline_ms",
        "enclave.max_body_bytes",
        "enclave.tdx_configfs_root",
        "enclave.chain.priority_fee.mode",
        "enclave.chain.priority_fee.max_micro_lamports",
    ] {
        assert!(has(&issues, field), "{field} not refused: {issues:?}");
    }
    let unknown = edit(&fixture_text(), |t| {
        t.insert("max_executions".into(), 3.into());
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("enclave.toml");
    std::fs::write(&path, unknown).unwrap();
    assert!(matches!(
        load_config::<EnclaveFile>(&path, None),
        Err(ConfigError::Parse { .. })
    ));
}

#[test]
fn file_checks_need_one_member_url_per_member() {
    let mut cfg = load(&fixtures().join("enclave.production.toml"), None).unwrap();
    cfg.member_urls.pop();
    let issues = cfg.file_issues();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].field, "enclave.member_urls");
    cfg.markets[0].committee_file = fixtures().join("missing.bin");
    assert!(
        cfg.file_issues()
            .iter()
            .any(|i| i.field == "enclave.market[0].committee_file")
    );
}

/// A build with the simulated platform never boots under the production
/// profile, whatever the file says.
#[cfg(feature = "sim-platform")]
#[test]
fn a_sim_platform_build_refuses_to_boot_in_production() {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use timescales_chain::{FileSigner, TxSigner};
    use timescales_core::crypto::Zeroizing;
    use timescales_enclave::{EnclaveError, EnclaveService};

    let cfg = load(&fixtures().join("enclave.production.toml"), None).unwrap();
    let kp = Keypair::from_seed([3; 32]);
    let mut bytes = Zeroizing::new([0u8; 64]);
    bytes[..32].copy_from_slice(kp.seed().as_slice());
    bytes[32..].copy_from_slice(&kp.public());
    let payer: Arc<dyn TxSigner> = Arc::new(FileSigner::from_bytes(bytes).unwrap());
    let err = EnclaveService::boot(cfg, BTreeMap::new(), payer).unwrap_err();
    assert!(
        matches!(err, EnclaveError::Config(ConfigError::SimulationBuild)),
        "{err}"
    );
}

#[tokio::test]
async fn run_refuses_plaintext_when_mutual_tls_is_configured() {
    let cfg = load(&fixtures().join("enclave.production.toml"), None).unwrap();
    let err = timescales_enclave::run::run(cfg, std::future::pending())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("refusing to listen in plaintext"), "{err}");
}
