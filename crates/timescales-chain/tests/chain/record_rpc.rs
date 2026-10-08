//! Records the responses `contract.rs` replays from a real
//! `solana-test-validator` into `tests/chain/data/rpc/validator.json`. Both
//! tests are ignored. Recording is a manual step:
//!
//! ```text
//! scripts/build-program.sh
//! TIMESCALES_RECORD_DIR=<dir> cargo test -p timescales-chain --test record_rpc \
//!     -- --ignored --exact write_validator_accounts      # prints the validator command
//! solana-test-validator...                               # as printed, in another shell
//! TIMESCALES_RECORD_RPC=http://127.0.0.1:18899 cargo test -p timescales-chain \
//!     --test record_rpc -- --ignored --exact record_validator_responses
//! ```
//!
//! The validator runs the settlement program under the dev program id and
//! holds the Trader accounts of `common::accounts` at genesis.

#![allow(clippy::unwrap_used)]

use super::common;

use std::path::Path;
use std::time::Duration;

use common::accounts::{self, b58};
use common::http;
use serde_json::{Map, Value, json};
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use timescales_chain::program::Ix;

const MISSING: [u8; 32] = [0x5e; 32];

#[test]
#[ignore = "manual: writes the validator's preloaded accounts (see the module documentation)"]
fn write_validator_accounts() {
    let dir = std::env::var("TIMESCALES_RECORD_DIR").expect("TIMESCALES_RECORD_DIR");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let so = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/sbf/timescales_settlement_program.so")
        .canonicalize()
        .expect("run scripts/build-program.sh first");
    let mut cmd = format!(
        "solana-test-validator --reset --quiet --ledger {} --rpc-port 18899 --faucet-port 19900 \
         --gossip-port 18000 --dynamic-port-range 18001-18030 --bpf-program {} {}",
        dir.join("ledger").display(),
        accounts::PROGRAM,
        so.display()
    );
    for (i, f) in accounts::traders().iter().enumerate() {
        let file = dir.join(format!("trader-{i}.json"));
        std::fs::write(
            &file,
            serde_json::to_vec_pretty(&accounts::account_file(f)).unwrap(),
        )
        .unwrap();
        cmd.push_str(&format!(
            " --account {} {}",
            b58(&f.address),
            file.display()
        ));
    }
    println!("{cmd}");
}

fn sdk(ix: &Ix) -> Instruction {
    Instruction {
        program_id: Address::from(ix.program),
        accounts: ix
            .accounts
            .iter()
            .map(|m| AccountMeta {
                pubkey: Address::from(m.key),
                is_signer: m.signer,
                is_writable: m.writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

/// `[1 signature] || message`, signed by `payer` alone.
fn wire(ixs: &[Ix], payer: &Keypair, blockhash: &[u8; 32]) -> Vec<u8> {
    let ixs: Vec<Instruction> = ixs.iter().map(sdk).collect();
    let message = Message::new_with_blockhash(
        &ixs,
        Some(&payer.pubkey()),
        &Hash::new_from_array(*blockhash),
    );
    let bytes = bincode::serialize(&message).unwrap();
    let mut w = vec![1u8];
    w.extend_from_slice(payer.sign_message(&bytes).as_ref());
    w.extend_from_slice(&bytes);
    w
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

struct Recorder {
    url: String,
    exchanges: Map<String, Value>,
}

impl Recorder {
    async fn call(&self, method: &str, params: &Value) -> Value {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let (status, body) = http::post(
            &self.url,
            &serde_json::to_vec(&req).unwrap(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap()
    }

    async fn record(&mut self, name: &str, method: &str, params: Value) -> Value {
        let response = self.call(method, &params).await;
        self.exchanges.insert(
            name.to_owned(),
            json!({"request": {"method": method, "params": params}, "response": response}),
        );
        response
    }

    async fn blockhash(&self) -> [u8; 32] {
        let r = self
            .call("getLatestBlockhash", &json!([{"commitment": "confirmed"}]))
            .await;
        timescales_chain::program::decode_base58(
            r["result"]["value"]["blockhash"].as_str().unwrap(),
        )
        .unwrap()
    }

    /// Polls until `sig` reaches `level` (or any level with `None`).
    async fn wait(&self, sig: &str, level: Option<&str>) {
        for _ in 0..240 {
            let r = self
                .call(
                    "getSignatureStatuses",
                    &json!([[sig], {"searchTransactionHistory": true}]),
                )
                .await;
            let status = &r["result"]["value"][0];
            let reached = match level {
                None => !status.is_null(),
                Some(l) => status["confirmationStatus"] == l,
            };
            if reached {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("{sig} did not reach {level:?}");
    }
}

#[tokio::test]
#[ignore = "manual: needs a local solana-test-validator (see the module documentation)"]
async fn record_validator_responses() {
    let url = std::env::var("TIMESCALES_RECORD_RPC").expect("TIMESCALES_RECORD_RPC");
    let mut r = Recorder {
        url,
        exchanges: Map::new(),
    };
    let traders = accounts::traders();
    let (a, b) = (b58(&traders[0].address), b58(&traders[1].address));
    let confirmed = json!({"encoding": "base64", "commitment": "confirmed"});

    let version = r.call("getVersion", &json!([])).await["result"].clone();
    r.record(
        "getAccountInfo/present",
        "getAccountInfo",
        json!([a, confirmed]),
    )
    .await;
    r.record(
        "getAccountInfo/missing",
        "getAccountInfo",
        json!([b58(&MISSING), confirmed]),
    )
    .await;
    r.record(
        "getAccountInfo/minContextSlot",
        "getAccountInfo",
        json!([a, {"encoding": "base64", "commitment": "confirmed", "minContextSlot": 1_000_000_000_000u64}]),
    )
    .await;
    r.record(
        "getMultipleAccounts",
        "getMultipleAccounts",
        json!([[a, b58(&MISSING), b], confirmed]),
    )
    .await;
    r.record(
        "getProgramAccounts/traders",
        "getProgramAccounts",
        json!([accounts::PROGRAM, {
            "encoding": "base64",
            "commitment": "confirmed",
            "withContext": true,
            "filters": [
                {"dataSize": 148},
                {"memcmp": {"offset": 0, "bytes": b64(&[0x22]), "encoding": "base64"}},
                {"memcmp": {"offset": 2, "bytes": b64(&[2]), "encoding": "base64"}},
                {"memcmp": {"offset": 4, "bytes": b64(&accounts::market()), "encoding": "base64"}},
            ],
            "dataSlice": {"offset": 36, "length": 112},
        }]),
    )
    .await;
    r.record(
        "getLatestBlockhash",
        "getLatestBlockhash",
        json!([{"commitment": "confirmed"}]),
    )
    .await;
    r.record("getSlot", "getSlot", json!([{"commitment": "confirmed"}]))
        .await;
    r.record(
        "getBlockHeight",
        "getBlockHeight",
        json!([{"commitment": "confirmed"}]),
    )
    .await;
    r.record("getGenesisHash", "getGenesisHash", json!([]))
        .await;
    r.record(
        "getRecentPrioritizationFees",
        "getRecentPrioritizationFees",
        json!([[a]]),
    )
    .await;
    r.record(
        "getMinimumBalanceForRentExemption",
        "getMinimumBalanceForRentExemption",
        json!([148]),
    )
    .await;

    // A funded payer for the transactions.
    let payer = Keypair::new_from_array([0x9a; 32]);
    let payer_key = payer.pubkey().to_bytes();
    let airdrop = r
        .call(
            "requestAirdrop",
            &json!([b58(&payer_key), 10_000_000_000u64]),
        )
        .await;
    r.wait(airdrop["result"].as_str().unwrap(), Some("finalized"))
        .await;

    let budget = |price| {
        vec![
            timescales_chain::program::compute_budget::set_limit(200_000),
            timescales_chain::program::compute_budget::set_price(price),
        ]
    };
    let mut transfer = budget(1);
    transfer.push(timescales_chain::program::system::transfer(
        &payer_key,
        &accounts::owner(0x77),
        1_000_000,
    ));
    // Unknown tag: the program refuses it with InvalidInstruction (6001).
    let bad_ix = Ix {
        program: accounts::program(),
        accounts: vec![],
        data: vec![99],
    };
    let bad = |price| {
        let mut ixs = budget(price);
        ixs.push(bad_ix.clone());
        ixs
    };
    let sim = json!({"encoding": "base64", "sigVerify": false, "replaceRecentBlockhash": false, "commitment": "confirmed"});
    let send = |skip: bool| json!({"encoding": "base64", "skipPreflight": skip, "preflightCommitment": "confirmed"});

    let blockhash = r.blockhash().await;
    r.record(
        "simulateTransaction/ok",
        "simulateTransaction",
        json!([b64(&wire(&transfer, &payer, &blockhash)), sim]),
    )
    .await;
    r.record(
        "simulateTransaction/err",
        "simulateTransaction",
        json!([b64(&wire(&bad(1), &payer, &blockhash)), sim]),
    )
    .await;
    r.record(
        "sendTransaction/preflight",
        "sendTransaction",
        json!([b64(&wire(&bad(2), &payer, &blockhash)), send(false)]),
    )
    .await;
    r.record(
        "sendTransaction/blockhashNotFound",
        "sendTransaction",
        json!([b64(&wire(&transfer, &payer, &[7; 32])), send(false)]),
    )
    .await;
    let ok = r
        .record(
            "sendTransaction/ok",
            "sendTransaction",
            json!([b64(&wire(&transfer, &payer, &blockhash)), send(false)]),
        )
        .await;
    let failed = r
        .record(
            "sendTransaction/skipPreflight",
            "sendTransaction",
            json!([b64(&wire(&bad(3), &payer, &blockhash)), send(true)]),
        )
        .await;
    let (ok, failed) = (
        ok["result"].as_str().unwrap().to_owned(),
        failed["result"].as_str().unwrap().to_owned(),
    );
    r.wait(&ok, Some("finalized")).await;
    r.wait(&failed, Some("finalized")).await;
    let unknown = b58(&[0x11; 64]);
    r.record(
        "getSignatureStatuses",
        "getSignatureStatuses",
        json!([[ok, failed, unknown], {"searchTransactionHistory": true}]),
    )
    .await;

    let fixture = json!({
        "recorded_from": "solana-test-validator (see tests/record_rpc.rs)",
        "version": version,
        "exchanges": r.exchanges,
    });
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/chain/data/rpc/validator.json");
    let mut text = serde_json::to_string_pretty(&fixture).unwrap();
    text.push('\n');
    std::fs::write(&path, text).unwrap();
    println!("wrote {}", path.display());
}
