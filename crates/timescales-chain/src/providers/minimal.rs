//! [`MinimalRpc`]: hand-written JSON-RPC 2.0 for exactly the methods of
//! [`SolanaRpc`], the enclave's client. It uses no Solana client crate,
//! so the enclave's TCB holds a few hundred lines of request building and
//! response parsing instead of the `solana-rpc-client` tree.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Map, Value, json};

use super::ProviderError;
use super::codes::{MIN_CONTEXT_SLOT_NOT_REACHED, PREFLIGHT_FAILURE};
use super::failover::{Failover, RpcErrorCount};
use crate::wire::{error_detail, first_signature};
use crate::{
    AccountData, Address, BoxFuture, Filter, Level, RpcError, Simulation, SolanaRpc, TxStatus,
};

/// One HTTP exchange: the status and the whole body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// POSTs a JSON body. The seam between [`MinimalRpc`]'s JSON-RPC layer and
/// an HTTP client. [`ReqwestTransport`] is the production one.
pub trait HttpTransport: Send + Sync + 'static {
    fn post(&self, url: String, body: Vec<u8>) -> BoxFuture<'_, Result<HttpReply, RpcError>>;
}

/// reqwest with a request timeout and a cap on the response size.
#[derive(Clone, Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
    max_body: usize,
}

impl ReqwestTransport {
    /// A client with `timeout` per request. reqwest is built with
    /// `rustls-no-provider`, so the process must install a rustls
    /// `CryptoProvider` before calling this (for example
    /// `rustls::crypto::ring::default_provider.install_default`).
    /// Without one reqwest panics while building the client.
    pub fn new(timeout: Duration, max_body: usize) -> Result<Self, ProviderError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| ProviderError::Client(e.to_string()))?;
        Ok(Self::with_client(client, max_body))
    }

    /// Uses a client built by the caller (for example with pinned roots).
    pub fn with_client(client: reqwest::Client, max_body: usize) -> Self {
        Self { client, max_body }
    }
}

impl HttpTransport for ReqwestTransport {
    fn post(&self, url: String, body: Vec<u8>) -> BoxFuture<'_, Result<HttpReply, RpcError>> {
        Box::pin(async move {
            let mut response = self
                .client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .map_err(reqwest_error)?;
            let status = response.status().as_u16();
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(reqwest_error)? {
                if body.len() + chunk.len() > self.max_body {
                    return Err(RpcError::Decode(format!(
                        "response larger than {} bytes",
                        self.max_body
                    )));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(HttpReply { status, body })
        })
    }
}

fn reqwest_error(e: reqwest::Error) -> RpcError {
    if e.is_timeout() {
        RpcError::Timeout
    } else {
        RpcError::Transport(e.to_string())
    }
}

/// Hand-written JSON-RPC over [`HttpTransport`] (reqwest by default), for
/// the methods of [`SolanaRpc`] only. The enclave's client. Fails over to
/// the next URL after three consecutive transport, 429 or 5xx failures.
pub struct MinimalRpc {
    failover: Failover,
    transport: Arc<dyn HttpTransport>,
    next_id: AtomicU64,
}

impl fmt::Debug for MinimalRpc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MinimalRpc")
            .field("failover", &self.failover)
            .finish_non_exhaustive()
    }
}

impl MinimalRpc {
    /// Response size cap of [`MinimalRpc::new`]: a `getProgramAccounts`
    /// snapshot answers about 360 bytes of JSON per trader (measured on the
    /// recorded validator response), so 36 MB at 10^5 traders.
    pub const MAX_RESPONSE_BYTES: usize = 64 << 20;

    /// reqwest with `timeout` per request. See [`ReqwestTransport::new`] for
    /// the TLS provider it needs.
    pub fn new(urls: Vec<String>, timeout: Duration) -> Result<Self, ProviderError> {
        let transport = ReqwestTransport::new(timeout, Self::MAX_RESPONSE_BYTES)?;
        Self::with_transport(urls, Arc::new(transport))
    }

    pub fn with_transport(
        urls: Vec<String>,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            failover: Failover::new(urls)?,
            transport,
            next_id: AtomicU64::new(1),
        })
    }

    /// Index of the URL calls currently go to.
    pub fn current_url(&self) -> usize {
        self.failover.current().0
    }

    pub fn error_counts(&self) -> Vec<RpcErrorCount> {
        self.failover.error_counts()
    }

    async fn call(
        &self,
        method: &'static str,
        params: Value,
        min_slot: Option<u64>,
    ) -> Result<Value, RpcError> {
        let (index, url) = self.failover.current();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let body = serde_json::to_vec(&request).map_err(|e| RpcError::Decode(e.to_string()))?;
        let result = match self.transport.post(url.to_owned(), body).await {
            Ok(reply) => parse_reply(&reply, id, min_slot),
            Err(e) => Err(e),
        };
        self.failover.record(index, &result);
        result
    }
}

fn parse_reply(reply: &HttpReply, id: u64, min_slot: Option<u64>) -> Result<Value, RpcError> {
    match reply.status {
        200..=299 => {}
        429 => return Err(RpcError::RateLimited),
        status => return Err(RpcError::Http(status)),
    }
    let mut v: Value =
        serde_json::from_slice(&reply.body).map_err(|e| RpcError::Decode(e.to_string()))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| decode("response is not a JSON object"))?;
    if obj.get("id").and_then(Value::as_u64) != Some(id) {
        return Err(decode("response id does not match the request"));
    }
    if let Some(err) = obj.get("error") {
        return Err(rpc_error(err, min_slot));
    }
    obj.remove("result")
        .ok_or_else(|| decode("response has neither a result nor an error"))
}

fn rpc_error(err: &Value, min_slot: Option<u64>) -> RpcError {
    let Some(code) = err.get("code").and_then(Value::as_i64) else {
        return decode("error object without a code");
    };
    let message = err
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    match (code, min_slot) {
        (MIN_CONTEXT_SLOT_NOT_REACHED, Some(min_slot)) => RpcError::MinContextSlot { min_slot },
        (PREFLIGHT_FAILURE, _) => {
            let data = err.get("data");
            match data.and_then(|d| d.get("err")).filter(|e| !e.is_null()) {
                Some(e) => RpcError::Preflight {
                    err: error_detail(e),
                    logs: strings(data.and_then(|d| d.get("logs"))),
                },
                None => RpcError::Rpc { code, message },
            }
        }
        _ => RpcError::Rpc { code, message },
    }
}

fn decode(what: &str) -> RpcError {
    RpcError::Decode(what.to_owned())
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn b58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

fn key(v: &Value) -> Result<Address, RpcError> {
    let s = v
        .as_str()
        .ok_or_else(|| decode("address is not a string"))?;
    let mut out = [0u8; 32];
    match bs58::decode(s).onto(&mut out) {
        Ok(32) => Ok(out),
        _ => Err(decode("address is not 32 bytes of base58")),
    }
}

fn u64_of(v: &Value, what: &'static str) -> Result<u64, RpcError> {
    v.as_u64()
        .ok_or_else(|| RpcError::Decode(format!("{what} is not an unsigned integer")))
}

/// `{"commitment": level, "minContextSlot": min_slot}` plus `extra`.
fn config(level: Level, min_slot: Option<u64>, extra: Value) -> Value {
    let mut m = Map::new();
    m.insert("commitment".into(), level.as_str().into());
    if let Some(slot) = min_slot {
        m.insert("minContextSlot".into(), slot.into());
    }
    if let Value::Object(extra) = extra {
        m.extend(extra);
    }
    Value::Object(m)
}

/// `{"context": {"slot": n}, "value": v}` -> `(n, v)`.
fn with_context(mut v: Value) -> Result<(u64, Value), RpcError> {
    let slot = u64_of(&v["context"]["slot"], "context slot")?;
    let value = v
        .get_mut("value")
        .map(Value::take)
        .ok_or_else(|| decode("response without a value"))?;
    Ok((slot, value))
}

/// An account in `base64` encoding, or `None` for `null`.
fn account(v: &Value, context_slot: u64) -> Result<Option<AccountData>, RpcError> {
    if v.is_null() {
        return Ok(None);
    }
    Ok(Some(AccountData {
        owner: key(&v["owner"])?,
        lamports: u64_of(&v["lamports"], "lamports")?,
        data: account_data(&v["data"])?,
        context_slot,
    }))
}

/// `["<base64>", "base64"]`.
fn account_data(v: &Value) -> Result<Vec<u8>, RpcError> {
    match v.as_array().map(Vec::as_slice) {
        Some([Value::String(data), Value::String(encoding)]) if encoding == "base64" => BASE64
            .decode(data)
            .map_err(|_| decode("account data is not base64")),
        _ => Err(decode("account data is not [data, \"base64\"]")),
    }
}

fn filter(f: &Filter) -> Value {
    match f {
        Filter::DataSize(n) => json!({"dataSize": n}),
        Filter::Memcmp { offset, bytes } => {
            json!({"memcmp": {"offset": offset, "bytes": BASE64.encode(bytes), "encoding": "base64"}})
        }
    }
}

fn level_of(status: &Value) -> Level {
    match status["confirmationStatus"].as_str() {
        Some("finalized") => Level::Finalized,
        Some("confirmed") => Level::Confirmed,
        Some(_) => Level::Processed,
        // Nodes without `confirmationStatus` report a rooted status as
        // `confirmations: null`.
        None if status["confirmations"].is_null() => Level::Finalized,
        None => Level::Processed,
    }
}

fn tx_status(v: &Value) -> Result<Option<TxStatus>, RpcError> {
    if v.is_null() {
        return Ok(None);
    }
    let err = v.get("err").filter(|e| !e.is_null()).map(error_detail);
    Ok(Some(TxStatus {
        slot: u64_of(&v["slot"], "status slot")?,
        level: level_of(v),
        err,
    }))
}

impl SolanaRpc for MinimalRpc {
    fn get_account(
        &self,
        key: Address,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AccountData>, RpcError>> {
        Box::pin(async move {
            let params = json!([
                b58(&key),
                config(level, min_slot, json!({"encoding": "base64"}))
            ]);
            let (slot, value) = with_context(self.call("getAccountInfo", params, min_slot).await?)?;
            account(&value, slot)
        })
    }

    fn get_multiple_accounts(
        &self,
        keys: Vec<Address>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<Option<AccountData>>), RpcError>> {
        Box::pin(async move {
            let keys: Vec<String> = keys.iter().map(|k| b58(k)).collect();
            let n = keys.len();
            let params = json!([keys, config(level, min_slot, json!({"encoding": "base64"}))]);
            let (slot, value) =
                with_context(self.call("getMultipleAccounts", params, min_slot).await?)?;
            let accounts = value
                .as_array()
                .filter(|a| a.len() == n)
                .ok_or_else(|| decode("getMultipleAccounts returned another number of accounts"))?;
            let accounts = accounts
                .iter()
                .map(|a| account(a, slot))
                .collect::<Result<_, _>>()?;
            Ok((slot, accounts))
        })
    }

    fn get_program_accounts(
        &self,
        program: Address,
        filters: Vec<Filter>,
        slice: Option<(usize, usize)>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<(Address, Vec<u8>)>), RpcError>> {
        Box::pin(async move {
            let mut extra = json!({
                "encoding": "base64",
                "withContext": true,
                "filters": filters.iter().map(filter).collect::<Vec<_>>(),
            });
            if let Some((offset, length)) = slice {
                extra["dataSlice"] = json!({"offset": offset, "length": length});
            }
            let params = json!([b58(&program), config(level, min_slot, extra)]);
            let (slot, value) =
                with_context(self.call("getProgramAccounts", params, min_slot).await?)?;
            let keyed = value
                .as_array()
                .ok_or_else(|| decode("getProgramAccounts value is not an array"))?;
            let accounts = keyed
                .iter()
                .map(|k| Ok((key(&k["pubkey"])?, account_data(&k["account"]["data"])?)))
                .collect::<Result<_, RpcError>>()?;
            Ok((slot, accounts))
        })
    }

    fn latest_blockhash(&self, level: Level) -> BoxFuture<'_, Result<([u8; 32], u64), RpcError>> {
        Box::pin(async move {
            let params = json!([config(level, None, Value::Null)]);
            let (_, value) = with_context(self.call("getLatestBlockhash", params, None).await?)?;
            Ok((
                key(&value["blockhash"])?,
                u64_of(&value["lastValidBlockHeight"], "lastValidBlockHeight")?,
            ))
        })
    }

    fn send_transaction(
        &self,
        wire: Vec<u8>,
        skip_preflight: bool,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<[u8; 64], RpcError>> {
        Box::pin(async move {
            let expected =
                first_signature(&wire).ok_or_else(|| decode("transaction without a signature"))?;
            let mut cfg = json!({
                "encoding": "base64",
                "skipPreflight": skip_preflight,
                "preflightCommitment": Level::Confirmed.as_str(),
            });
            if let Some(slot) = min_slot {
                cfg["minContextSlot"] = slot.into();
            }
            let params = json!([BASE64.encode(&wire), cfg]);
            let result = self.call("sendTransaction", params, min_slot).await?;
            let mut signature = [0u8; 64];
            let decoded = result
                .as_str()
                .map(|s| bs58::decode(s).onto(&mut signature));
            if !matches!(decoded, Some(Ok(64))) {
                return Err(decode("signature is not 64 bytes of base58"));
            }
            if signature != expected {
                return Err(decode("node returned the signature of another transaction"));
            }
            Ok(signature)
        })
    }

    fn simulate_transaction(&self, wire: Vec<u8>) -> BoxFuture<'_, Result<Simulation, RpcError>> {
        Box::pin(async move {
            let cfg = config(
                Level::Confirmed,
                None,
                json!({"encoding": "base64", "sigVerify": false, "replaceRecentBlockhash": false}),
            );
            let params = json!([BASE64.encode(&wire), cfg]);
            let (_, value) = with_context(self.call("simulateTransaction", params, None).await?)?;
            Ok(Simulation {
                units: value["unitsConsumed"].as_u64(),
                logs: strings(value.get("logs")),
                err: value.get("err").filter(|e| !e.is_null()).map(error_detail),
            })
        })
    }

    fn signature_statuses(
        &self,
        sigs: Vec<[u8; 64]>,
    ) -> BoxFuture<'_, Result<Vec<Option<TxStatus>>, RpcError>> {
        Box::pin(async move {
            let n = sigs.len();
            let sigs: Vec<String> = sigs.iter().map(|s| b58(s)).collect();
            // As in `HttpRpc`: without the history search, a signature that
            // left the status cache reads as never seen.
            let params = json!([sigs, {"searchTransactionHistory": true}]);
            let (_, value) = with_context(self.call("getSignatureStatuses", params, None).await?)?;
            value
                .as_array()
                .filter(|a| a.len() == n)
                .ok_or_else(|| decode("getSignatureStatuses returned another number of statuses"))?
                .iter()
                .map(tx_status)
                .collect()
        })
    }

    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            let params = json!([config(level, None, Value::Null)]);
            u64_of(&self.call("getSlot", params, None).await?, "slot")
        })
    }

    fn block_height(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            let params = json!([config(level, None, Value::Null)]);
            u64_of(
                &self.call("getBlockHeight", params, None).await?,
                "block height",
            )
        })
    }

    fn genesis_hash(&self) -> BoxFuture<'_, Result<[u8; 32], RpcError>> {
        Box::pin(async move { key(&self.call("getGenesisHash", json!([]), None).await?) })
    }

    fn recent_prioritization_fees(
        &self,
        writable: Vec<Address>,
    ) -> BoxFuture<'_, Result<Vec<u64>, RpcError>> {
        Box::pin(async move {
            let keys: Vec<String> = writable.iter().map(|k| b58(k)).collect();
            let result = self
                .call("getRecentPrioritizationFees", json!([keys]), None)
                .await?;
            result
                .as_array()
                .ok_or_else(|| decode("prioritization fees are not an array"))?
                .iter()
                .map(|f| u64_of(&f["prioritizationFee"], "prioritizationFee"))
                .collect()
        })
    }

    fn minimum_balance_for_rent_exemption(
        &self,
        len: usize,
    ) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            let result = self
                .call("getMinimumBalanceForRentExemption", json!([len]), None)
                .await?;
            u64_of(&result, "rent")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: Value) -> HttpReply {
        HttpReply {
            status,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    #[test]
    fn status_codes_map_to_endpoint_errors() {
        let ok = json!({"jsonrpc": "2.0", "id": 1, "result": 5});
        assert_eq!(parse_reply(&reply(200, ok.clone()), 1, None), Ok(json!(5)));
        assert_eq!(
            parse_reply(&reply(429, ok.clone()), 1, None),
            Err(RpcError::RateLimited)
        );
        assert_eq!(
            parse_reply(&reply(503, ok.clone()), 1, None),
            Err(RpcError::Http(503))
        );
        assert!(matches!(
            parse_reply(&reply(200, ok), 2, None),
            Err(RpcError::Decode(_))
        ));
        let not_json = HttpReply {
            status: 200,
            body: b"<html>".to_vec(),
        };
        assert!(matches!(
            parse_reply(&not_json, 1, None),
            Err(RpcError::Decode(_))
        ));
    }

    #[test]
    fn json_rpc_errors() {
        let min_slot = json!({"code": -32016, "message": "Minimum context slot has not been reached", "data": {"contextSlot": 3}});
        assert_eq!(
            rpc_error(&min_slot, Some(9)),
            RpcError::MinContextSlot { min_slot: 9 }
        );
        assert!(matches!(
            rpc_error(&min_slot, None),
            RpcError::Rpc { code: -32016, .. }
        ));
        let preflight = json!({"code": -32002, "message": "Transaction simulation failed",
            "data": {"err": {"InstructionError": [1, {"Custom": 6003}]}, "logs": ["a", "b"]}});
        assert_eq!(
            rpc_error(&preflight, None),
            RpcError::Preflight {
                err: crate::TxErrorDetail {
                    ix_index: Some(1),
                    custom: Some(6003),
                    message: r#"{"InstructionError":[1,{"Custom":6003}]}"#.into(),
                },
                logs: vec!["a".into(), "b".into()],
            }
        );
        let bare = json!({"code": -32002, "message": "x", "data": {"err": null}});
        assert!(matches!(
            rpc_error(&bare, None),
            RpcError::Rpc { code: -32002, .. }
        ));
        assert!(matches!(rpc_error(&json!({}), None), RpcError::Decode(_)));
    }

    #[test]
    fn account_data_must_be_base64() {
        assert_eq!(account_data(&json!(["AQI=", "base64"])), Ok(vec![1, 2]));
        assert!(account_data(&json!(["AQI=", "base58"])).is_err());
        assert!(account_data(&json!("AQI=")).is_err());
        assert!(account_data(&json!(["!!", "base64"])).is_err());
    }

    #[test]
    fn statuses_without_confirmation_status() {
        let rooted = json!({"slot": 4, "confirmations": null, "err": null});
        assert_eq!(level_of(&rooted), Level::Finalized);
        let recent = json!({"slot": 4, "confirmations": 2, "err": null});
        assert_eq!(level_of(&recent), Level::Processed);
    }
}
