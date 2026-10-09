//! Implements every async trait of the crate with bodies that hold each
//! argument across an await point, so a signature that cannot be
//! implemented fails to compile here rather than in a later package.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::Mutex;
use timescales_chain::Address;
use timescales_core::crypto::Signature;
use timescales_core::{ExecutorId, Hash32, OrderCommitment};
use timescales_executor::attestation::{Evidence, Platform};
use timescales_node::events::LiveEvent;
use timescales_node::{
    AdminCmd, AdminReply, BoxFuture, EventsSince, ExecClient, ExecClientError, NodeApi, NodeError,
    SessionError, SessionRef, SubmitError, VerifiedSubmission,
};
use timescales_service::api::{
    B58, B64, Cluster, CreateSessionRequest, CurrentEpoch, EnclavePlatform, ErrorCode, Hex, Hex32,
    Info, InfoLimits, KeyGeneration, MarketDetail, MarketSummary, MpcStatus, OverallStatus,
    ParkedItem, ProfileJson, Quotas, QuoteGeneration, QuoteVerification, ReferencePrice,
    RetractResult, Session, SessionNonce, Status, StreamEvent, SubmitResult, SubmitStatus, Trust,
    U64,
};
use timescales_service::store::node::NodeRepo;
use timescales_service::wire::{
    EnclaveIdentity, EpochKeyBundle, ExecutePosted, ExecuteReady, ExecuteRequest, PublishRequest,
};
use tokio::sync::broadcast;
use tokio::task::yield_now;

struct FakeExec;

impl ExecClient for FakeExec {
    fn execute(
        &self,
        enclave: usize,
        req: Arc<ExecuteRequest>,
    ) -> BoxFuture<'_, Result<ExecuteReady, ExecClientError>> {
        Box::pin(async move {
            yield_now().await;
            if enclave > 0 {
                return Err(ExecClientError::UnknownEnclave(enclave));
            }
            Ok(ExecuteReady {
                executor: ExecutorId([1; 32]),
                header_digest: req.batch.header.digest(),
                outcome_digest: Hash32::ZERO,
                cosign: Signature([0; 64]),
                unauthenticated: vec![],
            })
        })
    }

    fn publish(
        &self,
        enclave: usize,
        req: PublishRequest,
    ) -> BoxFuture<'_, Result<ExecutePosted, ExecClientError>> {
        Box::pin(async move {
            yield_now().await;
            Err(ExecClientError::Refused {
                code: "NotExecuted".into(),
                detail: format!("{enclave} {}", req.header_digest),
            })
        })
    }

    fn identity(&self, enclave: usize) -> BoxFuture<'_, Result<EnclaveIdentity, ExecClientError>> {
        Box::pin(async move {
            yield_now().await;
            Ok(EnclaveIdentity {
                executor: ExecutorId([u8::try_from(enclave).unwrap(); 32]),
                seal_key: [2; 32],
                platform: Platform::Simulated,
                measurement: Hash32::ZERO,
                evidence: Evidence {
                    platform: Platform::Simulated,
                    quote: vec![],
                },
                fee_payer: [3; 32],
            })
        })
    }
}

fn info() -> Info {
    Info {
        api_version: "1.0".into(),
        protocol_version: 1,
        header_version: 2,
        node_version: "0.1.0".into(),
        git_sha: "unknown".into(),
        profile: ProfileJson::Local,
        cluster: Cluster::Localnet,
        genesis_hash: B58([0; 32]),
        program_id: B58([1; 32]),
        server_time_ms: 0,
        markets: vec![],
        trust: Trust {
            enclave: EnclavePlatform::Simulated,
            quote_generation: QuoteGeneration::Simulated,
            quote_verification: QuoteVerification::SimulatedVendor,
            key_generation: KeyGeneration::TrustedDealerFeldman,
            dkg: false,
            mpc: MpcStatus::Disabled,
            reference_price: ReferencePrice::Fixed,
            receipt_quorum: 1,
            registered_executors: 1,
            notes: vec![],
        },
        limits: InfoLimits {
            submit_max_body_bytes: 2048,
            session_max_ttl_s: 86_400,
        },
    }
}

struct FakeNode {
    info: Info,
    details: BTreeMap<Address, MarketDetail>,
    current: BTreeMap<Address, CurrentEpoch>,
    sessions: Mutex<BTreeMap<[u8; 32], Session>>,
    events: broadcast::Sender<Arc<LiveEvent>>,
    repo: Option<NodeRepo>,
    log: Mutex<Vec<String>>,
}

impl NodeApi for FakeNode {
    fn info(&self) -> Info {
        self.info.clone()
    }

    fn status(&self) -> Status {
        Status {
            status: OverallStatus::Ok,
            server_time_ms: self.info.server_time_ms,
            components: vec![],
            markets: vec![],
            notice: None,
        }
    }

    fn markets(&self) -> Vec<MarketSummary> {
        self.details.values().map(|d| d.summary.clone()).collect()
    }

    fn market(&self, m: Address) -> Option<MarketDetail> {
        self.details.get(&m).cloned()
    }

    fn current(&self, m: Address) -> Option<CurrentEpoch> {
        self.current.get(&m).cloned()
    }

    fn submit(
        &self,
        m: Address,
        items: Vec<VerifiedSubmission>,
        session: SessionRef,
    ) -> BoxFuture<'_, Vec<Result<SubmitResult, SubmitError>>> {
        Box::pin(async move {
            yield_now().await;
            items
                .iter()
                .map(|v| {
                    let env = &v.inner.submission.envelope;
                    Ok(SubmitResult {
                        status: SubmitStatus::Accepted,
                        market: B58(m),
                        epoch: U64(env.epoch.0),
                        commitment: Hex32(env.commitment.0),
                        envelope_digest: Hex32(v.inner.envelope_digest.0),
                        received_at_ms: 0,
                        promise_b64: B64(session.session_key.to_vec()),
                        duplicate: false,
                    })
                })
                .collect()
        })
    }

    fn parked(
        &self,
        m: Address,
        session: SessionRef,
    ) -> BoxFuture<'_, Result<Vec<ParkedItem>, NodeError>> {
        Box::pin(async move {
            yield_now().await;
            if session.market.is_some_and(|s| s != m) {
                return Err(NodeError::MarketUnknown(m));
            }
            Ok(vec![])
        })
    }

    fn retract_parked(
        &self,
        m: Address,
        session: SessionRef,
        c: OrderCommitment,
    ) -> BoxFuture<'_, Result<RetractResult, NodeError>> {
        Box::pin(async move {
            yield_now().await;
            self.log
                .lock()
                .push(format!("retract {} {} {}", m[0], session.wallet[0], c.0[0]));
            Ok(RetractResult {
                removed_epochs: vec![],
                kept_open_epoch: None,
            })
        })
    }

    fn session_nonce(&self) -> BoxFuture<'_, Result<SessionNonce, NodeError>> {
        Box::pin(async move {
            yield_now().await;
            Ok(SessionNonce {
                nonce: Hex(vec![0; 16]),
                expires_at_ms: self.info.server_time_ms + 300_000,
                domain: "localhost:4173".into(),
                uri: "http://localhost:4173".into(),
                chain_id: "localnet".into(),
                statement: String::new(),
                template_version: 1,
            })
        })
    }

    fn create_session(
        &self,
        req: CreateSessionRequest,
        min_context_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Session, SessionError>> {
        Box::pin(async move {
            yield_now().await;
            if min_context_slot.is_some_and(|s| s > 1_000) {
                return Err(SessionError::Refused {
                    code: ErrorCode::WalletNotEligible,
                    detail: req.message,
                });
            }
            let session = Session {
                session_key: Hex32([4; 32]),
                wallet: req.wallet,
                market: None,
                expires_at_ms: 0,
                quotas: Quotas {
                    max_envelopes_per_wallet_per_epoch: 16,
                    max_parked_per_wallet: 64,
                },
                usage: None,
                evicted: None,
            };
            self.sessions.lock().insert([4; 32], session.clone());
            Ok(session)
        })
    }

    fn session(&self, key: [u8; 32]) -> BoxFuture<'_, Result<Option<Session>, NodeError>> {
        Box::pin(async move {
            yield_now().await;
            Ok(self.sessions.lock().get(&key).cloned())
        })
    }

    fn revoke_session(&self, key: [u8; 32]) -> BoxFuture<'_, Result<(), NodeError>> {
        Box::pin(async move {
            yield_now().await;
            self.sessions.lock().remove(&key);
            Ok(())
        })
    }

    fn events(&self) -> broadcast::Receiver<Arc<LiveEvent>> {
        self.events.subscribe()
    }

    fn head_seq(&self) -> u64 {
        0
    }

    fn events_since(
        &self,
        seq: u64,
        topics: Vec<String>,
    ) -> BoxFuture<'_, Result<EventsSince, NodeError>> {
        Box::pin(async move {
            yield_now().await;
            self.log
                .lock()
                .push(format!("since {seq} {}", topics.len()));
            Ok(EventsSince::TooOld { head_seq: seq })
        })
    }

    fn stream_id(&self) -> [u8; 16] {
        [5; 16]
    }

    fn store(&self) -> &NodeRepo {
        self.repo.as_ref().expect("the fake node has no store")
    }

    fn put_key_bundle(
        &self,
        m: Address,
        b: EpochKeyBundle,
    ) -> BoxFuture<'_, Result<(), NodeError>> {
        Box::pin(async move {
            yield_now().await;
            self.log
                .lock()
                .push(format!("bundle {} {}", m[0], b.announcement.epoch.0));
            Ok(())
        })
    }

    fn admin(&self, cmd: AdminCmd) -> BoxFuture<'_, Result<AdminReply, NodeError>> {
        Box::pin(async move {
            yield_now().await;
            match cmd {
                AdminCmd::Abort(m, e) => Ok(AdminReply::Refused {
                    reason: format!("{} {e}", m[0]),
                    runbook: "abort",
                }),
                _ => Ok(AdminReply::Ok),
            }
        })
    }
}

#[tokio::test]
async fn every_async_trait_is_implementable_and_object_safe() {
    let exec: Arc<dyn ExecClient> = Arc::new(FakeExec);
    let id = exec.identity(0).await.unwrap();
    assert_eq!(id.executor, ExecutorId([0; 32]));
    let p = exec
        .publish(
            0,
            PublishRequest {
                market: [0; 32],
                epoch: timescales_core::EpochId(1),
                header_digest: Hash32::ZERO,
                cosigs: vec![],
            },
        )
        .await;
    assert!(p.is_err());

    let (events, _) = broadcast::channel(4);
    let node: Arc<dyn NodeApi> = Arc::new(FakeNode {
        info: info(),
        details: BTreeMap::new(),
        current: BTreeMap::new(),
        sessions: Mutex::default(),
        events,
        repo: None,
        log: Mutex::default(),
    });
    assert_eq!(node.info().header_version, 2);
    assert_eq!(node.status().status, OverallStatus::Ok);
    assert!(node.markets().is_empty());
    assert!(node.market([0; 32]).is_none());
    assert!(node.current([0; 32]).is_none());
    let session = SessionRef {
        session_key: [4; 32],
        wallet: [6; 32],
        market: None,
    };
    assert!(node.submit([0; 32], vec![], session).await.is_empty());
    assert!(node.parked([0; 32], session).await.unwrap().is_empty());
    node.retract_parked([0; 32], session, OrderCommitment([7; 32]))
        .await
        .unwrap();
    node.session_nonce().await.unwrap();
    let created = node
        .create_session(
            CreateSessionRequest {
                wallet: B58([6; 32]),
                message: "grant".into(),
                signature_b64: B64(vec![]),
                method: timescales_service::api::GrantMethodJson::SignIn,
                min_context_slot: None,
            },
            Some(5),
        )
        .await
        .unwrap();
    assert!(node.session([4; 32]).await.unwrap().is_some());
    node.revoke_session([4; 32]).await.unwrap();
    assert_eq!(created.wallet, B58([6; 32]));
    let _rx = node.events();
    node.events_since(3, vec!["status".into()]).await.unwrap();
    assert_eq!(node.stream_id(), [5; 16]);
    assert_eq!(node.admin(AdminCmd::Status).await.unwrap(), AdminReply::Ok);
}
