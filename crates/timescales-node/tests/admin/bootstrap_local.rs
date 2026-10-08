//! `timescales-admin` against a local validator: keygen, market id,
//! committee, bootstrap-local (twice: it is idempotent for a salt), inspect,
//! and every governance action signed and unsigned.
//!
//! Needs `scripts/e2e/up.sh --validator-only`. Ignored unless asked for:
//!
//! ```text
//! scripts/e2e/up.sh --validator-only && TIMESCALES_E2E=1 cargo test --locked \
//!   -p timescales-node --test admin -- --ignored && scripts/e2e/down.sh
//! ```

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use base64::Engine;
use serde_json::Value;
use timescales_chain::{
    BoxFuture, CommitOutcome, FeeMode, FeePolicy, FileSigner, HttpRpc, JournalError, Level,
    MarketChain, MarketChainConfig, SolanaMarketChain, SolanaRpc, TxJournal, TxOutcome, TxRecord,
    TxSender, TxSigner,
};
use timescales_core::Hash32;

/// The relay's side of a commit, which no admin command sends.
#[derive(Default)]
struct Journal(AtomicI64);

impl TxJournal for Journal {
    fn before_send(&self, _rec: TxRecord) -> BoxFuture<'_, Result<i64, JournalError>> {
        let id = self.0.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move { Ok(id) })
    }
    fn resolved(&self, _id: i64, _o: TxOutcome) -> BoxFuture<'_, Result<(), JournalError>> {
        Box::pin(async { Ok(()) })
    }
    fn pending(&self) -> BoxFuture<'_, Result<Vec<TxRecord>, JournalError>> {
        Box::pin(async { Ok(vec![]) })
    }
    fn last_landed_slot(&self) -> BoxFuture<'_, Result<u64, JournalError>> {
        Box::pin(async { Ok(0) })
    }
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rpc_url() -> String {
    std::env::var("TIMESCALES_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_owned())
}

fn funder() -> PathBuf {
    std::env::var_os("TIMESCALES_FUNDER_KEYPAIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo().join("target/e2e/ledger/faucet-keypair.json"))
}

/// Runs the CLI and returns its JSON output. Panics with stderr on failure.
fn admin(args: &[&str]) -> Value {
    let out = admin_raw(args);
    assert!(
        out.status.success(),
        "timescales-admin {args:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{args:?}: {e}: {}", String::from_utf8_lossy(&out.stdout)))
}

fn admin_raw(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_timescales-admin"))
        .current_dir(repo())
        .args(args)
        .args(chain_args(args))
        .output()
        .unwrap()
}

/// `--rpc` for the subcommands that talk to the cluster.
fn chain_args(args: &[&str]) -> Vec<String> {
    let offline = matches!(args.first(), Some(&"keygen" | &"committee"))
        || args.starts_with(&["market", "id"]);
    if offline {
        vec![]
    } else {
        vec!["--rpc".to_owned(), rpc_url()]
    }
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn signer(path: &Path) -> FileSigner {
    let bytes = timescales_service::keys::solana_keypair_bytes(path).unwrap();
    FileSigner::from_bytes(bytes).unwrap()
}

/// Polls `inspect market` until `f` holds.
fn wait_market(market: &str, what: &str, f: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..120 {
        let m = admin(&["inspect", "market", "--market", market]);
        if f(&m) {
            return m;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("market never reached: {what}");
}

/// Polls `inspect market` until the market account exists.
fn wait_market_exists(market: &str) -> Value {
    for _ in 0..120 {
        let out = admin_raw(&["inspect", "market", "--market", market]);
        if out.status.success() {
            return serde_json::from_slice(&out.stdout).unwrap();
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("market {market} was never created");
}

/// Applies the pending change once its timelock has passed.
fn apply_when_due(market: &str, cranker: &str) -> Value {
    for _ in 0..120 {
        let out = admin(&[
            "governance",
            "apply",
            "--market",
            market,
            "--signer",
            cranker,
        ]);
        if out["outcome"].get("applied").is_some() {
            return out;
        }
        assert!(
            out["outcome"].get("not_yet").is_some(),
            "unexpected apply outcome {out}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("the pending change never became due");
}

#[test]
#[ignore = "needs a local validator: scripts/e2e/up.sh --validator-only, then TIMESCALES_E2E=1"]
fn bootstrap_and_govern_a_local_market() {
    if std::env::var("TIMESCALES_E2E").as_deref() != Ok("1") {
        eprintln!("skipped: set TIMESCALES_E2E=1 with a validator from scripts/e2e/up.sh");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let secrets = dir.join("secrets");
    let sec = |name: &str| secrets.join(name).to_str().unwrap().to_owned();

    //
    let keys = admin(&[
        "keygen",
        "--profile",
        "local",
        "--out",
        secrets.to_str().unwrap(),
    ]);
    assert_eq!(keys["label"], "INSECURE-LOCAL");
    let salt = hex::encode(rand_salt());
    let id = admin(&[
        "market",
        "id",
        "--creator",
        s(&keys["admin"]),
        "--salt",
        &salt,
    ]);
    let market = s(&id["address"]).to_owned();
    let committee = dir.join("committee.bin");
    let built = admin(&[
        "committee",
        "build",
        "--market",
        &market,
        "--threshold",
        "2",
        "--members",
        &sec("members.toml"),
        "--out",
        committee.to_str().unwrap(),
    ]);
    let digest = admin(&["committee", "digest", "--file", committee.to_str().unwrap()]);
    assert_eq!(built["digest"], digest["digest"]);

    // twice: the second run finds the market and changes nothing.
    let env_path = dir.join("env.json");
    let boot = |out: &Path| {
        admin(&[
            "bootstrap-local",
            "--secrets",
            secrets.to_str().unwrap(),
            "--salt",
            &salt,
            "--committee",
            committee.to_str().unwrap(),
            "--market-config",
            "config/markets/local-dual.json",
            "--funder",
            funder().to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
    };
    let env = boot(&env_path);
    let again = boot(&dir.join("env-again.json"));
    assert_eq!(env["market"], again["market"]);
    assert_eq!(env["mints"], again["mints"]);
    let written: Value =
        serde_json::from_str(&std::fs::read_to_string(&env_path).unwrap()).unwrap();
    assert_eq!(written, env);
    assert_eq!(env["market"]["address"], market.as_str());
    assert_eq!(env["market"]["market_id"], id["market_id"]);

    let m = admin(&["inspect", "market", "--market", &market]);
    assert_eq!(m["market_id"], id["market_id"]);
    assert_eq!(m["admin"], keys["admin"]);
    assert_eq!(m["relay"], keys["relay"]);
    assert_eq!(m["committee_digest"], built["digest"]);
    assert_eq!(m["receipt_quorum"], 2);
    assert_eq!(m["halted"], false);
    assert_eq!(m["pending"], Value::Null);
    assert_eq!(m["last_committed"], "0");
    let executors: Vec<&str> = m["executors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| s(&e["key"]))
        .collect();
    let expected: Vec<&str> = keys["enclaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| s(&e["executor_b58"]))
        .collect();
    assert_eq!(executors, expected);
    assert_eq!(m["params"]["flow"], "dual");
    assert_eq!(m["params"]["max_batch_envelopes"], 1024);
    assert_eq!(m["params"]["market"].to_string(), s(&id["market_id"]));
    for side in ["base", "quote"] {
        assert_eq!(m[side]["decimals"], 6);
        assert_eq!(m[side]["mint_authority"], keys["admin"]);
        assert_eq!(m[side]["freeze_authority"], Value::Null);
        assert_eq!(m[side]["vault_amount"], "0");
    }
    assert_eq!(m["timelock_slots"], "20");

    // The traders' SOL and tokens, read straight from the cluster.
    let rpc = HttpRpc::new(vec![rpc_url()], Duration::from_secs(10)).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for t in env["traders"].as_array().unwrap() {
        let owner = timescales_chain::program::decode_base58(s(&t["owner"])).unwrap();
        let acc = rt
            .block_on(rpc.get_account(owner, Level::Confirmed, None))
            .unwrap()
            .unwrap();
        assert!(acc.lamports >= 10_000_000_000, "{t}");
        for (ata, atoms) in [
            ("base_ata", 1_000_000_000u64),
            ("quote_ata", 1_000_000_000_000),
        ] {
            let key = timescales_chain::program::decode_base58(s(&t[ata])).unwrap();
            let a = rt
                .block_on(rpc.get_account(key, Level::Confirmed, None))
                .unwrap()
                .unwrap();
            assert_eq!(
                u64::from_le_bytes(a.data[64..72].try_into().unwrap()),
                atoms
            );
        }
    }
    let traders = admin(&["inspect", "traders", "--market", &market]);
    assert_eq!(traders["traders"], serde_json::json!([]));
    let program = admin(&["inspect", "program"]);
    assert_eq!(
        program["program"],
        "FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL"
    );
    let no_batch = admin_raw(&["inspect", "epoch", "--market", &market, "--epoch", "1"]);
    assert!(!no_batch.status.success());

    let admin_kp = sec("admin.json");
    let cranker = sec("cranker.json");

    // Epoch 1: the relay commits a batch. `crank reveal` reveals its beacon
    // once both target slots exist. An admin abort voids it. Reclaiming is
    // refused before the retention period.
    let rpc_arc: Arc<dyn SolanaRpc> =
        Arc::new(HttpRpc::new(vec![rpc_url()], Duration::from_secs(10)).unwrap());
    let sender = Arc::new(TxSender::new(
        rpc_arc.clone(),
        FeePolicy {
            mode: FeeMode::Fixed(0),
            percentile: 75,
            max_micro_lamports: 0,
            cu_margin_pct: 20,
        },
        Arc::new(Journal::default()),
        Duration::from_millis(400),
        Duration::from_secs(60),
    ));
    let program =
        timescales_chain::program::decode_base58("FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL")
            .unwrap();
    let market_key = timescales_chain::program::decode_base58(&market).unwrap();
    let chain = SolanaMarketChain::new(
        rpc_arc,
        sender,
        program,
        market_key,
        MarketChainConfig::default(),
    );
    let relay: Arc<dyn TxSigner> = Arc::new(signer(Path::new(&sec("relay.json"))));
    let committed = rt
        .block_on(chain.ensure_committed(1, Hash32([0x11; 32]), 1, Hash32([0x22; 32]), relay))
        .unwrap();
    assert!(
        matches!(committed, CommitOutcome::Committed { .. }),
        "{committed:?}"
    );
    assert_eq!(
        admin(&["inspect", "epoch", "--market", &market, "--epoch", "1"])["status"],
        "Committed"
    );
    let mut revealed = Value::Null;
    for _ in 0..60 {
        let out = admin(&[
            "crank", "reveal", "--market", &market, "--epoch", "1", "--payer", &cranker,
        ]);
        if out.get("revealed").is_some() {
            revealed = out;
            break;
        }
        assert!(out.get("not_ready").is_some(), "{out}");
        std::thread::sleep(Duration::from_millis(500));
    }
    let batch = admin(&["inspect", "epoch", "--market", &market, "--epoch", "1"]);
    assert_eq!(batch["status"], "BeaconRevealed");
    assert_eq!(batch["beacon"], revealed["revealed"]["beacon"]);
    let aborted = admin(&[
        "crank", "abort", "--market", &market, "--epoch", "1", "--reason", "admin", "--signer",
        &admin_kp,
    ]);
    assert_eq!(aborted["aborted"], "Admin");
    let batch = admin(&["inspect", "epoch", "--market", &market, "--epoch", "1"]);
    assert_eq!(
        (&batch["status"], &batch["abort_reason"]),
        (&serde_json::json!("Aborted"), &serde_json::json!("Admin"))
    );
    let m = admin(&["inspect", "market", "--market", &market]);
    assert_eq!((s(&m["last_committed"]), s(&m["last_settled"])), ("1", "1"));
    let again = admin(&[
        "crank", "abort", "--market", &market, "--epoch", "1", "--reason", "admin", "--signer",
        &admin_kp,
    ]);
    // Idempotent: the batch is already aborted, with the reason it has.
    assert_eq!(again["aborted"], "Admin");
    let reclaim = admin_raw(&[
        "crank", "reclaim", "--market", &market, "--epoch", "1", "--payer", &cranker,
    ]);
    assert!(
        !reclaim.status.success(),
        "a batch inside the retention period cannot be reclaimed"
    );

    // `market init --unsigned` for a second market on the same mints, signed
    // here by the creator and sent raw.
    let salt2 = hex::encode(rand_salt());
    let id2 = admin(&[
        "market",
        "id",
        "--creator",
        s(&keys["admin"]),
        "--salt",
        &salt2,
    ]);
    let committee2 = dir.join("committee-2.bin");
    admin(&[
        "committee",
        "build",
        "--market",
        s(&id2["address"]),
        "--threshold",
        "2",
        "--members",
        &sec("members.toml"),
        "--out",
        committee2.to_str().unwrap(),
    ]);
    let init = admin(&[
        "market",
        "init",
        "--unsigned",
        "--creator",
        s(&keys["admin"]),
        "--salt",
        &salt2,
        "--admin",
        s(&keys["admin"]),
        "--relay",
        s(&keys["relay"]),
        "--params",
        "config/markets/local-dual.json",
        "--committee",
        committee2.to_str().unwrap(),
        "--base-mint",
        s(&env["mints"]["base"]["address"]),
        "--quote-mint",
        s(&env["mints"]["quote"]["address"]),
        "--executor",
        expected[0],
        "--executor",
        expected[1],
        "--receipt-quorum",
        "2",
        "--timings",
        "local",
    ]);
    assert_eq!(init["market"]["address"], id2["address"]);
    let message = base64::engine::general_purpose::STANDARD
        .decode(s(&init["message_base64"]))
        .unwrap();
    let mut wire = vec![1u8];
    wire.extend_from_slice(&signer(Path::new(&admin_kp)).sign(&message));
    wire.extend_from_slice(&message);
    rt.block_on(rpc.send_transaction(wire, false, None))
        .unwrap();
    let m2 = wait_market_exists(s(&id2["address"]));
    assert_eq!(m2["market_id"], id2["market_id"]);
    assert_eq!(m2["executors"].as_array().unwrap().len(), 2);
    assert_eq!(m2["base"]["vault_amount"], "0");

    // An unsigned proposal, signed here as a multisig would and sent raw.
    let unsigned = admin(&[
        "governance",
        "propose",
        "--market",
        &market,
        "--unsigned",
        "set-timelock",
        "--slots",
        "30",
    ]);
    assert_eq!(unsigned["signers"], serde_json::json!([keys["admin"]]));
    let message = base64::engine::general_purpose::STANDARD
        .decode(s(&unsigned["message_base64"]))
        .unwrap();
    let sig = signer(Path::new(&admin_kp)).sign(&message);
    let mut wire = vec![1u8];
    wire.extend_from_slice(&sig);
    wire.extend_from_slice(&message);
    let tx = base64::engine::general_purpose::STANDARD
        .decode(s(&unsigned["transaction_base64"]))
        .unwrap();
    assert_eq!(tx[65..], message[..]);
    rt.block_on(rpc.send_transaction(wire, false, None))
        .unwrap();
    let m = wait_market(&market, "the unsigned proposal", |m| {
        !m["pending"].is_null()
    });
    assert_eq!(m["pending"]["change"]["kind"], "set_timelock");
    let busy = admin_raw(&[
        "governance",
        "propose",
        "--market",
        &market,
        "--signer",
        &admin_kp,
        "set-timelock",
        "--slots",
        "40",
    ]);
    assert!(!busy.status.success(), "a second proposal must wait");
    admin(&[
        "governance",
        "cancel",
        "--market",
        &market,
        "--signer",
        &admin_kp,
    ]);
    let m = admin(&["inspect", "market", "--market", &market]);
    assert_eq!(m["pending"], Value::Null);

    // A timelocked change, applied by anyone once due.
    let new_relay = bs58::encode(signer(Path::new(&sec("trader-4.json"))).address()).into_string();
    admin(&[
        "governance",
        "propose",
        "--market",
        &market,
        "--signer",
        &admin_kp,
        "set-relay",
        "--relay",
        &new_relay,
    ]);
    let applied = apply_when_due(&market, &cranker);
    assert_eq!(applied["outcome"]["applied"], 1);
    let m = admin(&["inspect", "market", "--market", &market]);
    assert_eq!(m["relay"], new_relay.as_str());
    assert_eq!(m["pending"], Value::Null);

    // The committee digest moves to prev_committee_digest.
    admin(&[
        "governance",
        "propose",
        "--market",
        &market,
        "--signer",
        &admin_kp,
        "set-committee-digest",
        "--digest",
        &"ab".repeat(32),
    ]);
    apply_when_due(&market, &cranker);
    let m = admin(&["inspect", "market", "--market", &market]);
    assert_eq!(m["committee_digest"], "ab".repeat(32));
    assert_eq!(m["prev_committee_digest"], built["digest"]);

    // Timings and timelock.
    admin(&[
        "governance",
        "propose",
        "--market",
        &market,
        "--signer",
        &admin_kp,
        "set-timings",
        "--beacon-delay",
        "5",
        "--exec-timeout",
        "160",
        "--settle-timeout",
        "1600",
    ]);
    apply_when_due(&market, &cranker);
    admin(&[
        "governance",
        "propose",
        "--market",
        &market,
        "--signer",
        &admin_kp,
        "set-timelock",
        "--slots",
        "10",
    ]);
    apply_when_due(&market, &cranker);
    let m = admin(&["inspect", "market", "--market", &market]);
    assert_eq!(
        (
            &m["beacon_delay_slots"],
            s(&m["exec_timeout_slots"]),
            s(&m["settle_timeout_slots"])
        ),
        (&serde_json::json!(5), "160", "1600")
    );
    assert_eq!(m["timelock_slots"], "10");

    // Executors: the whole set, then an immediate removal.
    admin(&[
        "governance",
        "propose",
        "--market",
        &market,
        "--signer",
        &admin_kp,
        "set-executors",
        "--executor",
        expected[0],
        "--executor",
        expected[1],
        "--executor",
        expected[2],
        "--quorum",
        "1",
    ]);
    apply_when_due(&market, &cranker);
    let removed = admin(&[
        "governance",
        "remove-executor",
        "--market",
        &market,
        "--signer",
        &admin_kp,
        "--executor",
        expected[2],
    ]);
    assert!(removed.get("warning").is_none());
    let m = admin(&["inspect", "market", "--market", &market]);
    assert_eq!(m["executors"].as_array().unwrap().len(), 2);
    assert_eq!(m["receipt_quorum"], 1);

    // Halt and resume are immediate.
    admin(&[
        "governance",
        "halt",
        "--market",
        &market,
        "--signer",
        &admin_kp,
    ]);
    assert_eq!(
        admin(&["inspect", "market", "--market", &market])["halted"],
        true
    );
    admin(&[
        "governance",
        "halt",
        "--off",
        "--market",
        &market,
        "--signer",
        &admin_kp,
    ]);
    assert_eq!(
        admin(&["inspect", "market", "--market", &market])["halted"],
        false
    );

    // Nothing to claim yet.
    let claim = admin_raw(&[
        "governance",
        "claim-fees",
        "--market",
        &market,
        "--signer",
        &admin_kp,
        "--amount",
        "all",
        "--dest",
        s(&env["traders"][0]["quote_ata"]),
    ]);
    assert!(!claim.status.success());

    // Two-step admin handover, last: the old admin cannot act after it.
    let new_admin = sec("trader-1.json");
    let new_admin_key = s(&env["traders"][0]["owner"]).to_owned();
    admin(&[
        "governance",
        "propose",
        "--market",
        &market,
        "--signer",
        &admin_kp,
        "set-admin",
        "--admin",
        &new_admin_key,
    ]);
    apply_when_due(&market, &cranker);
    let m = admin(&["inspect", "market", "--market", &market]);
    assert_eq!(m["pending_admin"], new_admin_key.as_str());
    let wrong = admin_raw(&[
        "governance",
        "accept",
        "--market",
        &market,
        "--signer",
        &admin_kp,
    ]);
    assert!(!wrong.status.success(), "only the pending admin may accept");
    admin(&[
        "governance",
        "accept",
        "--market",
        &market,
        "--signer",
        &new_admin,
    ]);
    let m = admin(&["inspect", "market", "--market", &market]);
    assert_eq!(m["admin"], new_admin_key.as_str());
    assert_eq!(m["pending_admin"], Value::Null);
}

fn rand_salt() -> [u8; 32] {
    use rand_core::RngCore;
    let mut s = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut s);
    s
}
