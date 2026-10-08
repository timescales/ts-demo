//! The `SolanaRpc` contract: `HttpRpc` and `MinimalRpc` against
//! one stub JSON-RPC server. Successful answers and JSON-RPC errors are
//! responses recorded from `solana-test-validator` (Agave 3.1.10) in
//! `tests/chain/data/rpc/validator.json` (see `record_rpc.rs`). HTTP failures,
//! malformed bodies and slow answers are synthetic. Every test runs for each
//! client this build has, and checks the client's answer against values
//! derived from the fixture, plus the request it sent.
//!
//! `MinimalRpc` runs twice: over its production `ReqwestTransport` (reqwest
//! is built with `rustls-no-provider`, so the suite installs ring first, as
//! the services do at start) and over a plain TCP HTTP/1.1 transport.

#![cfg(any(feature = "rpc-client", feature = "rpc-minimal"))]
#![allow(clippy::unwrap_used)]

use super::common;

use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::accounts::{self, b58};
use common::stub::{Reply, Stub};
use serde_json::{Value, json};
use timescales_chain::program::decode_base58;
use timescales_chain::{
    AccountData, Filter, Level, RpcError, RpcErrorCount, SolanaRpc, TxErrorDetail, TxStatus,
};

static FIXTURE: LazyLock<Value> =
    LazyLock::new(|| serde_json::from_str(include_str!("data/rpc/validator.json")).unwrap());

fn exchange(name: &str) -> &'static Value {
    let e = &FIXTURE["exchanges"][name];
    assert!(e.is_object(), "no recorded exchange {name}");
    e
}

fn recorded(name: &str) -> Reply {
    Reply::Rpc(exchange(name)["response"].clone())
}

fn result(name: &str) -> &'static Value {
    &exchange(name)["response"]["result"]
}

fn context_slot(name: &str) -> u64 {
    result(name)["context"]["slot"].as_u64().unwrap()
}

/// The transaction a recorded `sendTransaction` or `simulateTransaction`
/// carried.
fn recorded_wire(name: &str) -> Vec<u8> {
    BASE64
        .decode(exchange(name)["request"]["params"][0].as_str().unwrap())
        .unwrap()
}

fn key(s: &str) -> [u8; 32] {
    decode_base58(s).unwrap()
}

const TIMEOUT: Duration = Duration::from_millis(1500);

#[cfg(feature = "rpc-minimal")]
struct TcpTransport;

#[cfg(feature = "rpc-minimal")]
impl timescales_chain::HttpTransport for TcpTransport {
    fn post(
        &self,
        url: String,
        body: Vec<u8>,
    ) -> timescales_chain::BoxFuture<'_, Result<timescales_chain::HttpReply, RpcError>> {
        Box::pin(async move {
            match common::http::post(&url, &body, TIMEOUT).await {
                Ok((status, body)) => Ok(timescales_chain::HttpReply { status, body }),
                Err(common::http::Error::Timeout) => Err(RpcError::Timeout),
                Err(common::http::Error::Transport(e)) => Err(RpcError::Transport(e)),
            }
        })
    }
}

/// Installs the process-wide rustls provider reqwest needs to build a
/// client. A second install fails harmlessly.
#[cfg(feature = "rpc-minimal")]
fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// One client under test.
enum Client {
    #[cfg(feature = "rpc-client")]
    Http(timescales_chain::HttpRpc),
    #[cfg(feature = "rpc-minimal")]
    Reqwest(timescales_chain::MinimalRpc),
    #[cfg(feature = "rpc-minimal")]
    Minimal(timescales_chain::MinimalRpc),
}

impl Client {
    /// Every client of this build, each over `urls`.
    #[allow(
        clippy::vec_init_then_push,
        reason = "each client is behind its own feature"
    )]
    fn all(urls: &[String]) -> Vec<Client> {
        let mut clients = Vec::new();
        #[cfg(feature = "rpc-client")]
        clients.push(Client::Http(
            timescales_chain::HttpRpc::new(urls.to_vec(), TIMEOUT).unwrap(),
        ));
        #[cfg(feature = "rpc-minimal")]
        {
            install_ring();
            clients.push(Client::Reqwest(
                timescales_chain::MinimalRpc::new(urls.to_vec(), TIMEOUT).unwrap(),
            ));
        }
        #[cfg(feature = "rpc-minimal")]
        clients.push(Client::Minimal(
            timescales_chain::MinimalRpc::with_transport(
                urls.to_vec(),
                std::sync::Arc::new(TcpTransport),
            )
            .unwrap(),
        ));
        clients
    }

    fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "rpc-client")]
            Client::Http(_) => "HttpRpc",
            #[cfg(feature = "rpc-minimal")]
            Client::Reqwest(_) => "MinimalRpc over reqwest",
            #[cfg(feature = "rpc-minimal")]
            Client::Minimal(_) => "MinimalRpc",
        }
    }

    fn rpc(&self) -> &dyn SolanaRpc {
        match self {
            #[cfg(feature = "rpc-client")]
            Client::Http(c) => c,
            #[cfg(feature = "rpc-minimal")]
            Client::Reqwest(c) | Client::Minimal(c) => c,
        }
    }

    fn current_url(&self) -> usize {
        match self {
            #[cfg(feature = "rpc-client")]
            Client::Http(c) => c.current_url(),
            #[cfg(feature = "rpc-minimal")]
            Client::Reqwest(c) | Client::Minimal(c) => c.current_url(),
        }
    }

    fn error_counts(&self) -> Vec<RpcErrorCount> {
        match self {
            #[cfg(feature = "rpc-client")]
            Client::Http(c) => c.error_counts(),
            #[cfg(feature = "rpc-minimal")]
            Client::Reqwest(c) | Client::Minimal(c) => c.error_counts(),
        }
    }

    /// HTTP requests one call makes when every answer is 429:
    /// `solana-rpc-client` retries 429 five times itself.
    fn requests_per_rate_limited_call(&self) -> usize {
        match self {
            #[cfg(feature = "rpc-client")]
            Client::Http(_) => 6,
            #[cfg(feature = "rpc-minimal")]
            Client::Reqwest(_) | Client::Minimal(_) => 1,
        }
    }
}

/// Runs `test` once per client, each against a fresh stub.
async fn for_each_client<F, Fut>(test: F)
where
    F: Fn(Stub, Client) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let kinds = Client::all(&["http://unused".to_owned()]).len();
    for i in 0..kinds {
        let stub = Stub::start().await;
        let client = Client::all(std::slice::from_ref(&stub.url)).swap_remove(i);
        test(stub, client).await;
    }
}

/// A config object's field, with `null` and absence alike.
fn field<'a>(config: &'a Value, name: &str) -> Option<&'a Value> {
    config.get(name).filter(|v| !v.is_null())
}

fn account(fixture: &accounts::Fixture, context_slot: u64) -> AccountData {
    AccountData {
        owner: accounts::program(),
        lamports: fixture.lamports,
        data: fixture.data.clone(),
        context_slot,
    }
}

#[tokio::test]
async fn get_account_reads_recorded_accounts() {
    for_each_client(|stub, client| async move {
        let traders = accounts::traders();
        stub.reply("getAccountInfo", recorded("getAccountInfo/present"));
        stub.reply("getAccountInfo", recorded("getAccountInfo/missing"));
        let rpc = client.rpc();
        let got = rpc
            .get_account(traders[0].address, Level::Confirmed, None)
            .await
            .unwrap();
        let slot = context_slot("getAccountInfo/present");
        assert_eq!(got, Some(account(&traders[0], slot)), "{}", client.name());
        assert_eq!(
            rpc.get_account([0x5e; 32], Level::Finalized, None)
                .await
                .unwrap(),
            None,
            "{}",
            client.name()
        );
        let params = stub.params("getAccountInfo");
        assert_eq!(params[0][0], b58(&traders[0].address));
        assert_eq!(field(&params[0][1], "encoding"), Some(&json!("base64")));
        assert_eq!(
            field(&params[0][1], "commitment"),
            Some(&json!("confirmed"))
        );
        assert_eq!(field(&params[0][1], "minContextSlot"), None);
        assert_eq!(
            field(&params[1][1], "commitment"),
            Some(&json!("finalized"))
        );
    })
    .await;
}

#[tokio::test]
async fn min_context_slot_not_reached() {
    for_each_client(|stub, client| async move {
        stub.reply("getAccountInfo", recorded("getAccountInfo/minContextSlot"));
        let min_slot = 1_000_000_000_000;
        let err = client
            .rpc()
            .get_account([1; 32], Level::Confirmed, Some(min_slot))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            RpcError::MinContextSlot { min_slot },
            "{}",
            client.name()
        );
        let params = stub.params("getAccountInfo");
        assert_eq!(
            field(&params[0][1], "minContextSlot"),
            Some(&json!(min_slot))
        );
    })
    .await;
}

#[tokio::test]
async fn get_multiple_accounts_keeps_order_and_context() {
    for_each_client(|stub, client| async move {
        let traders = accounts::traders();
        stub.reply("getMultipleAccounts", recorded("getMultipleAccounts"));
        let keys = vec![traders[0].address, [0x5e; 32], traders[1].address];
        let got = client
            .rpc()
            .get_multiple_accounts(keys.clone(), Level::Confirmed, Some(5))
            .await
            .unwrap();
        let slot = context_slot("getMultipleAccounts");
        assert_eq!(
            got,
            (
                slot,
                vec![
                    Some(account(&traders[0], slot)),
                    None,
                    Some(account(&traders[1], slot))
                ]
            ),
            "{}",
            client.name()
        );
        let params = stub.params("getMultipleAccounts");
        let sent: Vec<String> = keys.iter().map(|k| b58(k)).collect();
        assert_eq!(params[0][0], json!(sent));
        assert_eq!(field(&params[0][1], "minContextSlot"), Some(&json!(5)));
        assert_eq!(field(&params[0][1], "encoding"), Some(&json!("base64")));
    })
    .await;
}

#[tokio::test]
async fn get_program_accounts_filters_and_slices() {
    for_each_client(|stub, client| async move {
        let traders = accounts::traders();
        stub.reply("getProgramAccounts", recorded("getProgramAccounts/traders"));
        let filters = vec![
            Filter::DataSize(148),
            Filter::Memcmp {
                offset: 0,
                bytes: vec![0x22],
            },
            Filter::Memcmp {
                offset: 2,
                bytes: vec![2],
            },
            Filter::Memcmp {
                offset: 4,
                bytes: accounts::market().to_vec(),
            },
        ];
        let (slot, mut got) = client
            .rpc()
            .get_program_accounts(
                accounts::program(),
                filters,
                Some((36, 112)),
                Level::Confirmed,
                Some(9),
            )
            .await
            .unwrap();
        got.sort();
        // The validator applied the filters: the other market's trader is
        // not in the answer.
        let mut expected: Vec<([u8; 32], Vec<u8>)> = traders[..2]
            .iter()
            .map(|t| (t.address, t.data[36..148].to_vec()))
            .collect();
        expected.sort();
        assert_eq!(slot, context_slot("getProgramAccounts/traders"));
        assert_eq!(got, expected, "{}", client.name());

        let sent = &stub.params("getProgramAccounts")[0];
        assert_eq!(sent[0], accounts::PROGRAM);
        let recorded_config = &exchange("getProgramAccounts/traders")["request"]["params"][1];
        for name in ["encoding", "commitment", "withContext", "dataSlice"] {
            assert_eq!(
                field(&sent[1], name),
                field(recorded_config, name),
                "{} {name}",
                client.name()
            );
        }
        assert_eq!(field(&sent[1], "minContextSlot"), Some(&json!(9)));
        // Filters as the validator understood them: same kinds, offsets and
        // decoded bytes.
        let normalized = |filters: &Value| -> Vec<(String, u64, Vec<u8>)> {
            filters
                .as_array()
                .unwrap()
                .iter()
                .map(|f| match f.get("dataSize") {
                    Some(n) => ("dataSize".into(), n.as_u64().unwrap(), vec![]),
                    None => {
                        let m = &f["memcmp"];
                        assert_eq!(m["encoding"], "base64");
                        (
                            "memcmp".into(),
                            m["offset"].as_u64().unwrap(),
                            BASE64.decode(m["bytes"].as_str().unwrap()).unwrap(),
                        )
                    }
                })
                .collect()
        };
        assert_eq!(
            normalized(&sent[1]["filters"]),
            normalized(&recorded_config["filters"])
        );
    })
    .await;
}

#[tokio::test]
async fn latest_blockhash_and_counters() {
    for_each_client(|stub, client| async move {
        for name in [
            "getLatestBlockhash",
            "getSlot",
            "getBlockHeight",
            "getGenesisHash",
            "getRecentPrioritizationFees",
            "getMinimumBalanceForRentExemption",
        ] {
            stub.reply(name, recorded(name));
        }
        let rpc = client.rpc();
        let value = &result("getLatestBlockhash")["value"];
        assert_eq!(
            rpc.latest_blockhash(Level::Confirmed).await.unwrap(),
            (
                key(value["blockhash"].as_str().unwrap()),
                value["lastValidBlockHeight"].as_u64().unwrap()
            )
        );
        assert_eq!(
            rpc.slot(Level::Confirmed).await.unwrap(),
            result("getSlot").as_u64().unwrap()
        );
        assert_eq!(
            rpc.block_height(Level::Confirmed).await.unwrap(),
            result("getBlockHeight").as_u64().unwrap()
        );
        assert_eq!(
            rpc.genesis_hash().await.unwrap(),
            key(result("getGenesisHash").as_str().unwrap())
        );
        let fees: Vec<u64> = result("getRecentPrioritizationFees")
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["prioritizationFee"].as_u64().unwrap())
            .collect();
        assert_eq!(
            rpc.recent_prioritization_fees(vec![accounts::traders()[0].address])
                .await
                .unwrap(),
            fees
        );
        assert_eq!(
            rpc.minimum_balance_for_rent_exemption(148).await.unwrap(),
            result("getMinimumBalanceForRentExemption")
                .as_u64()
                .unwrap()
        );
        for (method, commitment) in [
            ("getLatestBlockhash", "confirmed"),
            ("getSlot", "confirmed"),
            ("getBlockHeight", "confirmed"),
        ] {
            assert_eq!(
                field(&stub.params(method)[0][0], "commitment"),
                Some(&json!(commitment)),
                "{} {method}",
                client.name()
            );
        }
        assert_eq!(
            stub.params("getRecentPrioritizationFees")[0][0],
            json!([b58(&accounts::traders()[0].address)])
        );
        assert_eq!(stub.params("getMinimumBalanceForRentExemption")[0][0], 148);
    })
    .await;
}

#[tokio::test]
async fn send_transaction_returns_its_signature() {
    for_each_client(|stub, client| async move {
        stub.reply("sendTransaction", recorded("sendTransaction/ok"));
        let wire = recorded_wire("sendTransaction/ok");
        let sig = client
            .rpc()
            .send_transaction(wire.clone(), false, Some(3))
            .await
            .unwrap();
        let expected: [u8; 64] = bs58::decode(result("sendTransaction/ok").as_str().unwrap())
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(sig, expected, "{}", client.name());
        assert_eq!(sig[..], wire[1..65]);
        let sent = &stub.params("sendTransaction")[0];
        assert_eq!(BASE64.decode(sent[0].as_str().unwrap()).unwrap(), wire);
        assert_eq!(field(&sent[1], "encoding"), Some(&json!("base64")));
        assert_eq!(field(&sent[1], "skipPreflight"), Some(&json!(false)));
        assert_eq!(
            field(&sent[1], "preflightCommitment"),
            Some(&json!("confirmed"))
        );
        assert_eq!(field(&sent[1], "minContextSlot"), Some(&json!(3)));
    })
    .await;
}

#[tokio::test]
async fn a_signature_of_another_transaction_is_refused() {
    for_each_client(|stub, client| async move {
        stub.reply("sendTransaction", recorded("sendTransaction/ok"));
        let other = recorded_wire("sendTransaction/skipPreflight");
        let err = client
            .rpc()
            .send_transaction(other, true, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, RpcError::Decode(_)),
            "{} {err:?}",
            client.name()
        );
    })
    .await;
}

fn logs(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn preflight_failures_carry_the_program_error_and_logs() {
    for_each_client(|stub, client| async move {
        stub.reply("sendTransaction", recorded("sendTransaction/preflight"));
        stub.reply(
            "sendTransaction",
            recorded("sendTransaction/blockhashNotFound"),
        );
        let rpc = client.rpc();
        let err = rpc
            .send_transaction(recorded_wire("sendTransaction/preflight"), false, None)
            .await
            .unwrap_err();
        let data = &exchange("sendTransaction/preflight")["response"]["error"]["data"];
        assert_eq!(
            err,
            RpcError::Preflight {
                err: TxErrorDetail {
                    ix_index: Some(2),
                    custom: Some(6001),
                    message: r#"{"InstructionError":[2,{"Custom":6001}]}"#.into(),
                },
                logs: logs(&data["logs"]),
            },
            "{}",
            client.name()
        );
        assert!(err.refused_send());
        let err = rpc
            .send_transaction(
                recorded_wire("sendTransaction/blockhashNotFound"),
                false,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            RpcError::Preflight {
                err: TxErrorDetail {
                    ix_index: None,
                    custom: None,
                    message: "BlockhashNotFound".into(),
                },
                logs: vec![],
            },
            "{}",
            client.name()
        );
    })
    .await;
}

#[tokio::test]
async fn simulations_report_units_logs_and_errors() {
    for_each_client(|stub, client| async move {
        stub.reply("simulateTransaction", recorded("simulateTransaction/ok"));
        stub.reply("simulateTransaction", recorded("simulateTransaction/err"));
        let rpc = client.rpc();
        let ok = rpc
            .simulate_transaction(recorded_wire("simulateTransaction/ok"))
            .await
            .unwrap();
        let value = &result("simulateTransaction/ok")["value"];
        assert_eq!(ok.units, value["unitsConsumed"].as_u64());
        assert!(ok.units.is_some());
        assert_eq!(ok.logs, logs(&value["logs"]));
        assert_eq!(ok.err, None, "{}", client.name());
        let err = rpc
            .simulate_transaction(recorded_wire("simulateTransaction/err"))
            .await
            .unwrap();
        let value = &result("simulateTransaction/err")["value"];
        assert_eq!(err.logs, logs(&value["logs"]));
        assert_eq!(
            err.err,
            Some(TxErrorDetail {
                ix_index: Some(2),
                custom: Some(6001),
                message: r#"{"InstructionError":[2,{"Custom":6001}]}"#.into(),
            }),
            "{}",
            client.name()
        );
        let sent = &stub.params("simulateTransaction")[0][1];
        assert_eq!(field(sent, "sigVerify"), Some(&json!(false)));
        assert_eq!(field(sent, "replaceRecentBlockhash"), Some(&json!(false)));
        assert_eq!(field(sent, "commitment"), Some(&json!("confirmed")));
        assert_eq!(field(sent, "encoding"), Some(&json!("base64")));
    })
    .await;
}

#[tokio::test]
async fn signature_statuses_in_order() {
    for_each_client(|stub, client| async move {
        stub.reply("getSignatureStatuses", recorded("getSignatureStatuses"));
        let names = exchange("getSignatureStatuses")["request"]["params"][0]
            .as_array()
            .unwrap();
        let sigs: Vec<[u8; 64]> = names
            .iter()
            .map(|s| {
                bs58::decode(s.as_str().unwrap())
                    .into_vec()
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect();
        let got = client.rpc().signature_statuses(sigs).await.unwrap();
        let values = result("getSignatureStatuses")["value"].as_array().unwrap();
        let slot = |i: usize| values[i]["slot"].as_u64().unwrap();
        assert_eq!(
            got,
            vec![
                Some(TxStatus {
                    slot: slot(0),
                    level: Level::Finalized,
                    err: None,
                }),
                Some(TxStatus {
                    slot: slot(1),
                    level: Level::Finalized,
                    err: Some(TxErrorDetail {
                        ix_index: Some(2),
                        custom: Some(6001),
                        message: r#"{"InstructionError":[2,{"Custom":6001}]}"#.into(),
                    }),
                }),
                None,
            ],
            "{}",
            client.name()
        );
        let sent = &stub.params("getSignatureStatuses")[0];
        assert_eq!(&sent[0], &json!(names));
        assert_eq!(
            field(&sent[1], "searchTransactionHistory"),
            Some(&json!(true))
        );
    })
    .await;
}

#[tokio::test]
async fn endpoint_failures_map_to_errors() {
    for_each_client(|stub, client| async move {
        let n = client.requests_per_rate_limited_call();
        for _ in 0..n {
            stub.reply("getSlot", Reply::Status(429));
        }
        stub.reply("getSlot", Reply::Status(503));
        stub.reply("getSlot", Reply::Raw(b"<html>bad gateway</html>".to_vec()));
        stub.reply(
            "getSlot",
            Reply::Slow(Duration::from_secs(5), Box::new(recorded("getSlot"))),
        );
        let rpc = client.rpc();
        assert_eq!(rpc.slot(Level::Confirmed).await, Err(RpcError::RateLimited));
        assert_eq!(rpc.slot(Level::Confirmed).await, Err(RpcError::Http(503)));
        assert!(
            matches!(rpc.slot(Level::Confirmed).await, Err(RpcError::Decode(_))),
            "{}",
            client.name()
        );
        assert_eq!(
            rpc.slot(Level::Confirmed).await,
            Err(RpcError::Timeout),
            "{}",
            client.name()
        );
        assert_eq!(stub.params("getSlot").len(), n + 3);
    })
    .await;
}

#[cfg(feature = "rpc-minimal")]
#[tokio::test]
async fn reqwest_refuses_a_response_over_its_size_cap() {
    use timescales_chain::{HttpTransport, MinimalRpc, ReqwestTransport};

    install_ring();
    let stub = Stub::start().await;
    let reply = serde_json::to_vec(&exchange("getSlot")["response"]).unwrap();
    let transport = ReqwestTransport::new(TIMEOUT, reply.len()).unwrap();
    stub.reply("getSlot", Reply::Raw(reply.clone()));
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"getSlot"}"#.to_vec();
    let got = transport
        .post(stub.url.clone(), body.clone())
        .await
        .unwrap();
    assert_eq!((got.status, got.body), (200, reply.clone()));

    let tight = MinimalRpc::with_transport(
        vec![stub.url.clone()],
        std::sync::Arc::new(ReqwestTransport::new(TIMEOUT, reply.len() - 1).unwrap()),
    )
    .unwrap();
    stub.reply("getSlot", Reply::Raw(reply));
    let err = tight.slot(Level::Confirmed).await.unwrap_err();
    assert!(
        matches!(&err, RpcError::Decode(m) if m.contains("larger than")),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_unreachable_endpoint_is_a_transport_error() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    for client in Client::all(&[format!("http://127.0.0.1:{port}")]) {
        let err = client.rpc().slot(Level::Confirmed).await.unwrap_err();
        assert!(
            matches!(err, RpcError::Transport(_)),
            "{} {err:?}",
            client.name()
        );
        assert!(err.is_transport());
    }
}

async fn failover_after(failure: Reply, per_call: impl Fn(&Client) -> usize) {
    let kinds = Client::all(&["http://unused".to_owned()]).len();
    for i in 0..kinds {
        let (a, b) = (Stub::start().await, Stub::start().await);
        let client = Client::all(&[a.url.clone(), b.url.clone()]).swap_remove(i);
        let per_call = per_call(&client);
        for _ in 0..3 * per_call {
            a.reply_any(failure.clone());
        }
        b.reply("getSlot", recorded("getSlot"));
        let rpc = client.rpc();
        for _ in 0..3 {
            assert!(rpc.slot(Level::Confirmed).await.is_err());
        }
        assert_eq!(client.current_url(), 1, "{}", client.name());
        assert_eq!(
            rpc.slot(Level::Confirmed).await.unwrap(),
            result("getSlot").as_u64().unwrap()
        );
        assert_eq!(a.requests().len(), 3 * per_call, "{}", client.name());
        assert_eq!(b.requests().len(), 1);
        let counted: u64 = client
            .error_counts()
            .iter()
            .filter(|c| c.url_index == 0)
            .map(|c| c.count)
            .sum();
        assert_eq!(counted, 3);
    }
}

#[tokio::test]
async fn three_5xx_answers_fail_over() {
    failover_after(Reply::Status(503), |_| 1).await;
}

#[tokio::test]
async fn three_rate_limited_calls_fail_over() {
    failover_after(Reply::Status(429), Client::requests_per_rate_limited_call).await;
}

#[tokio::test]
async fn json_rpc_errors_do_not_fail_over() {
    let kinds = Client::all(&["http://unused".to_owned()]).len();
    for i in 0..kinds {
        let (a, b) = (Stub::start().await, Stub::start().await);
        let client = Client::all(&[a.url.clone(), b.url.clone()]).swap_remove(i);
        for _ in 0..4 {
            a.reply("getAccountInfo", recorded("getAccountInfo/minContextSlot"));
        }
        a.reply("getSlot", Reply::Status(503));
        a.reply("getSlot", Reply::Status(503));
        a.reply("getAccountInfo", recorded("getAccountInfo/minContextSlot"));
        a.reply("getSlot", Reply::Status(503));
        a.reply("getSlot", recorded("getSlot"));
        let rpc = client.rpc();
        for _ in 0..4 {
            assert!(matches!(
                rpc.get_account([1; 32], Level::Confirmed, Some(u64::MAX))
                    .await,
                Err(RpcError::MinContextSlot { .. })
            ));
        }
        // Two endpoint failures, an answer, one more failure: never three
        // in a row.
        assert!(rpc.slot(Level::Confirmed).await.is_err());
        assert!(rpc.slot(Level::Confirmed).await.is_err());
        assert!(
            rpc.get_account([1; 32], Level::Confirmed, Some(u64::MAX))
                .await
                .is_err()
        );
        assert!(rpc.slot(Level::Confirmed).await.is_err());
        assert_eq!(client.current_url(), 0, "{}", client.name());
        assert!(rpc.slot(Level::Confirmed).await.is_ok());
        assert!(b.requests().is_empty());
    }
}
