//! [`HttpRpc`]: `solana-rpc-client`'s nonblocking client per URL with
//! failover (feature `rpc-client`, node, KRC and admin CLI).
//!
//! Requests go through `RpcClient::send` with the client's typed configs and
//! responses, so the context slot of every read and the JSON-RPC error codes
//! (`minContextSlot` not reached, preflight failure) reach the caller. The
//! convenience methods drop both.

use std::fmt;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use solana_account_decoder_client_types::{UiAccount, UiAccountEncoding, UiDataSliceConfig};
use solana_commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client_api::client_error::{Error as ClientError, ErrorKind};
use solana_rpc_client_api::config::{
    RpcAccountInfoConfig, RpcContextConfig, RpcProgramAccountsConfig, RpcSendTransactionConfig,
    RpcSignatureStatusConfig, RpcSimulateTransactionConfig,
};
use solana_rpc_client_api::filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType};
use solana_rpc_client_api::request::{RpcError as ApiError, RpcRequest, RpcResponseErrorData};
use solana_rpc_client_api::response::{
    OptionalContext, Response, RpcBlockhash, RpcKeyedAccount, RpcPrioritizationFee,
    RpcSimulateTransactionResult,
};
use solana_transaction_status_client_types::{
    TransactionConfirmationStatus, TransactionStatus, UiTransactionEncoding,
};

use super::ProviderError;
use super::codes::{MIN_CONTEXT_SLOT_NOT_REACHED, PREFLIGHT_FAILURE};
use super::failover::{Failover, RpcErrorCount};
use crate::wire::{error_detail, first_signature};
use crate::{
    AccountData, Address, BoxFuture, Filter, Level, RpcError, Simulation, SolanaRpc, TxStatus,
};

/// `solana-rpc-client` nonblocking `RpcClient` per URL. Rotates to the next
/// URL after 3 consecutive transport, 429 or 5xx failures.
pub struct HttpRpc {
    clients: Vec<RpcClient>,
    failover: Failover,
}

impl fmt::Debug for HttpRpc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRpc")
            .field("failover", &self.failover)
            .finish_non_exhaustive()
    }
}

impl HttpRpc {
    /// One client per URL, in failover order, each with `timeout` per
    /// request.
    pub fn new(urls: Vec<String>, timeout: Duration) -> Result<Self, ProviderError> {
        let clients = urls
            .iter()
            .map(|u| RpcClient::new_with_timeout(u.clone(), timeout))
            .collect();
        Ok(Self {
            clients,
            failover: Failover::new(urls)?,
        })
    }

    /// Index of the URL calls currently go to.
    pub fn current_url(&self) -> usize {
        self.failover.current().0
    }

    pub fn error_counts(&self) -> Vec<RpcErrorCount> {
        self.failover.error_counts()
    }

    async fn call<T: DeserializeOwned>(
        &self,
        request: RpcRequest,
        params: Value,
        min_slot: Option<u64>,
    ) -> Result<T, RpcError> {
        let (index, _) = self.failover.current();
        let result = self.clients[index]
            .send::<T>(request, params)
            .await
            .map_err(|e| client_error(e, min_slot));
        self.failover.record(index, &result);
        result
    }
}

fn client_error(e: ClientError, min_slot: Option<u64>) -> RpcError {
    match *e.kind {
        ErrorKind::Reqwest(e) => {
            if e.is_timeout() {
                RpcError::Timeout
            } else if let Some(status) = e.status() {
                match status.as_u16() {
                    429 => RpcError::RateLimited,
                    code => RpcError::Http(code),
                }
            } else if e.is_decode() {
                RpcError::Decode(e.to_string())
            } else {
                RpcError::Transport(e.to_string())
            }
        }
        ErrorKind::Middleware(e) => RpcError::Transport(e.to_string()),
        ErrorKind::Io(e) => RpcError::Transport(e.to_string()),
        ErrorKind::RpcError(ApiError::RpcResponseError {
            code,
            message,
            data,
        }) => match (code, data, min_slot) {
            (MIN_CONTEXT_SLOT_NOT_REACHED, _, Some(min_slot)) => {
                RpcError::MinContextSlot { min_slot }
            }
            (
                PREFLIGHT_FAILURE,
                RpcResponseErrorData::SendTransactionPreflightFailure(
                    RpcSimulateTransactionResult {
                        err: Some(err),
                        logs,
                        ..
                    },
                ),
                _,
            ) => match serde_json::to_value(&err) {
                Ok(err) => RpcError::Preflight {
                    err: error_detail(&err),
                    logs: logs.unwrap_or_default(),
                },
                Err(e) => RpcError::Decode(e.to_string()),
            },
            (code, _, _) => RpcError::Rpc { code, message },
        },
        other => RpcError::Decode(other.to_string()),
    }
}

fn commitment(level: Level) -> CommitmentConfig {
    CommitmentConfig {
        commitment: match level {
            Level::Processed => CommitmentLevel::Processed,
            Level::Confirmed => CommitmentLevel::Confirmed,
            Level::Finalized => CommitmentLevel::Finalized,
        },
    }
}

fn account_config(
    level: Level,
    min_slot: Option<u64>,
    data_slice: Option<UiDataSliceConfig>,
) -> RpcAccountInfoConfig {
    RpcAccountInfoConfig {
        encoding: Some(UiAccountEncoding::Base64),
        data_slice,
        commitment: Some(commitment(level)),
        min_context_slot: min_slot,
    }
}

fn b58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

fn key(s: &str) -> Result<Address, RpcError> {
    let mut out = [0u8; 32];
    match bs58::decode(s).onto(&mut out) {
        Ok(32) => Ok(out),
        _ => Err(RpcError::Decode("address is not 32 bytes of base58".into())),
    }
}

fn account(ui: Option<UiAccount>, context_slot: u64) -> Result<Option<AccountData>, RpcError> {
    let Some(ui) = ui else {
        return Ok(None);
    };
    Ok(Some(AccountData {
        owner: key(&ui.owner)?,
        lamports: ui.lamports,
        data: ui
            .data
            .decode()
            .ok_or_else(|| RpcError::Decode("account data is not base64".into()))?,
        context_slot,
    }))
}

fn filter(f: &Filter) -> RpcFilterType {
    match f {
        Filter::DataSize(n) => RpcFilterType::DataSize(*n),
        Filter::Memcmp { offset, bytes } => RpcFilterType::Memcmp(Memcmp::new(
            usize::try_from(*offset).unwrap_or(usize::MAX),
            MemcmpEncodedBytes::Base64(BASE64.encode(bytes)),
        )),
    }
}

fn tx_status(s: TransactionStatus) -> Result<TxStatus, RpcError> {
    let level = match s.confirmation_status {
        Some(TransactionConfirmationStatus::Finalized) => Level::Finalized,
        Some(TransactionConfirmationStatus::Confirmed) => Level::Confirmed,
        Some(TransactionConfirmationStatus::Processed) => Level::Processed,
        // A rooted status without `confirmationStatus` has no confirmations
        // count.
        None if s.confirmations.is_none() => Level::Finalized,
        None => Level::Processed,
    };
    let err = match s.err {
        Some(e) => Some(error_detail(
            &serde_json::to_value(&e).map_err(|e| RpcError::Decode(e.to_string()))?,
        )),
        None => None,
    };
    Ok(TxStatus {
        slot: s.slot,
        level,
        err,
    })
}

impl SolanaRpc for HttpRpc {
    fn get_account(
        &self,
        key: Address,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AccountData>, RpcError>> {
        Box::pin(async move {
            let params = json!([b58(&key), account_config(level, min_slot, None)]);
            let r: Response<Option<UiAccount>> = self
                .call(RpcRequest::GetAccountInfo, params, min_slot)
                .await?;
            account(r.value, r.context.slot)
        })
    }

    fn get_multiple_accounts(
        &self,
        keys: Vec<Address>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<Option<AccountData>>), RpcError>> {
        Box::pin(async move {
            let n = keys.len();
            let keys: Vec<String> = keys.iter().map(|k| b58(k)).collect();
            let params = json!([keys, account_config(level, min_slot, None)]);
            let r: Response<Vec<Option<UiAccount>>> = self
                .call(RpcRequest::GetMultipleAccounts, params, min_slot)
                .await?;
            if r.value.len() != n {
                return Err(RpcError::Decode(
                    "getMultipleAccounts returned another number of accounts".into(),
                ));
            }
            let slot = r.context.slot;
            let accounts = r
                .value
                .into_iter()
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
            let config = RpcProgramAccountsConfig {
                filters: Some(filters.iter().map(filter).collect()),
                account_config: account_config(
                    level,
                    min_slot,
                    slice.map(|(offset, length)| UiDataSliceConfig { offset, length }),
                ),
                with_context: Some(true),
                sort_results: None,
            };
            let params = json!([b58(&program), config]);
            let r: OptionalContext<Vec<RpcKeyedAccount>> = self
                .call(RpcRequest::GetProgramAccounts, params, min_slot)
                .await?;
            let OptionalContext::Context(r) = r else {
                return Err(RpcError::Decode(
                    "getProgramAccounts answered without a context".into(),
                ));
            };
            let accounts =
                r.value
                    .into_iter()
                    .map(|k| {
                        let data =
                            k.account.data.decode().ok_or_else(|| {
                                RpcError::Decode("account data is not base64".into())
                            })?;
                        Ok((key(&k.pubkey)?, data))
                    })
                    .collect::<Result<_, RpcError>>()?;
            Ok((r.context.slot, accounts))
        })
    }

    fn latest_blockhash(&self, level: Level) -> BoxFuture<'_, Result<([u8; 32], u64), RpcError>> {
        Box::pin(async move {
            let config = RpcContextConfig {
                commitment: Some(commitment(level)),
                min_context_slot: None,
            };
            let r: Response<RpcBlockhash> = self
                .call(RpcRequest::GetLatestBlockhash, json!([config]), None)
                .await?;
            Ok((key(&r.value.blockhash)?, r.value.last_valid_block_height))
        })
    }

    fn send_transaction(
        &self,
        wire: Vec<u8>,
        skip_preflight: bool,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<[u8; 64], RpcError>> {
        Box::pin(async move {
            let expected = first_signature(&wire)
                .ok_or_else(|| RpcError::Decode("transaction without a signature".into()))?;
            let config = RpcSendTransactionConfig {
                skip_preflight,
                preflight_commitment: Some(CommitmentLevel::Confirmed),
                encoding: Some(UiTransactionEncoding::Base64),
                max_retries: None,
                min_context_slot: min_slot,
            };
            let params = json!([BASE64.encode(&wire), config]);
            let s: String = self
                .call(RpcRequest::SendTransaction, params, min_slot)
                .await?;
            let mut signature = [0u8; 64];
            if !matches!(bs58::decode(&s).onto(&mut signature), Ok(64)) {
                return Err(RpcError::Decode(
                    "signature is not 64 bytes of base58".into(),
                ));
            }
            if signature != expected {
                return Err(RpcError::Decode(
                    "node returned the signature of another transaction".into(),
                ));
            }
            Ok(signature)
        })
    }

    fn simulate_transaction(&self, wire: Vec<u8>) -> BoxFuture<'_, Result<Simulation, RpcError>> {
        Box::pin(async move {
            let config = RpcSimulateTransactionConfig {
                sig_verify: false,
                replace_recent_blockhash: false,
                commitment: Some(commitment(Level::Confirmed)),
                encoding: Some(UiTransactionEncoding::Base64),
                accounts: None,
                min_context_slot: None,
                inner_instructions: false,
            };
            let params = json!([BASE64.encode(&wire), config]);
            let r: Response<RpcSimulateTransactionResult> = self
                .call(RpcRequest::SimulateTransaction, params, None)
                .await?;
            let err = match r.value.err {
                Some(e) => Some(error_detail(
                    &serde_json::to_value(&e).map_err(|e| RpcError::Decode(e.to_string()))?,
                )),
                None => None,
            };
            Ok(Simulation {
                units: r.value.units_consumed,
                logs: r.value.logs.unwrap_or_default(),
                err,
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
            // The status cache forgets a signature a few hundred slots after
            // it lands. Without the history search a transaction resolved
            // at startup that landed before then would read as expired.
            let config = RpcSignatureStatusConfig {
                search_transaction_history: true,
            };
            let r: Response<Vec<Option<TransactionStatus>>> = self
                .call(
                    RpcRequest::GetSignatureStatuses,
                    json!([sigs, config]),
                    None,
                )
                .await?;
            if r.value.len() != n {
                return Err(RpcError::Decode(
                    "getSignatureStatuses returned another number of statuses".into(),
                ));
            }
            r.value
                .into_iter()
                .map(|s| s.map(tx_status).transpose())
                .collect()
        })
    }

    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            let config = RpcContextConfig {
                commitment: Some(commitment(level)),
                min_context_slot: None,
            };
            self.call(RpcRequest::GetSlot, json!([config]), None).await
        })
    }

    fn block_height(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            let config = RpcContextConfig {
                commitment: Some(commitment(level)),
                min_context_slot: None,
            };
            self.call(RpcRequest::GetBlockHeight, json!([config]), None)
                .await
        })
    }

    fn genesis_hash(&self) -> BoxFuture<'_, Result<[u8; 32], RpcError>> {
        Box::pin(async move {
            let s: String = self
                .call(RpcRequest::GetGenesisHash, Value::Null, None)
                .await?;
            key(&s)
        })
    }

    fn recent_prioritization_fees(
        &self,
        writable: Vec<Address>,
    ) -> BoxFuture<'_, Result<Vec<u64>, RpcError>> {
        Box::pin(async move {
            let keys: Vec<String> = writable.iter().map(|k| b58(k)).collect();
            let fees: Vec<RpcPrioritizationFee> = self
                .call(RpcRequest::GetRecentPrioritizationFees, json!([keys]), None)
                .await?;
            Ok(fees.into_iter().map(|f| f.prioritization_fee).collect())
        })
    }

    fn minimum_balance_for_rent_exemption(
        &self,
        len: usize,
    ) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            self.call(
                RpcRequest::GetMinimumBalanceForRentExemption,
                json!([len]),
                None,
            )
            .await
        })
    }
}
