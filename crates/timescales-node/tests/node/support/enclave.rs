//! `FakeEnclaves`: an [`ExecClient`] whose enclaves run the real
//! `TeeExecutor` in process (simulated platform) against key-release
//! members that read the LiteSVM chain, and post through `MarketChain` from
//! their own fee payers, describes: execute returns only digests and
//! a co-signature. Publish posts only with `receipt_quorum - 1` valid
//! co-signatures, sends them, and returns the artifacts once the quorum is
//! on chain (the same-outcome path co-signs a batch another enclave
//! posted). The balance-sheet check is not modelled here. The end-to-end
//! stack exercises the real enclave service.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use rand::SeedableRng;
use rand::rngs::StdRng;
use timescales_auction::CommittedStatus;
use timescales_auction::receipts::cosign_digest;
use timescales_chain::program::BatchStatus;
use timescales_chain::{BatchPredicate, Level, MarketChain, PostOutcome, TxSigner};
use timescales_core::crypto::verify_digest;
use timescales_core::{EpochId, ExecutorId, Hash32, MarketId, TraderId};
use timescales_executor::ExecutionResult;
use timescales_executor::attestation::{Evidence, Platform};
use timescales_executor::tee::{
    BatchView, BoxFuture as TeeFuture, Enclave, EpochInputs, EpochKey, KeyReleaseMember,
    KeyReleaseRequest, KeyReleaseService, LocalTeeDeployment, PublishedEpochKeys, ReleaseContext,
    ReleaseError, SealedShare, TeeExecutor, program_measurement,
};
use timescales_node::sessions::verify_grant_signature;
use timescales_node::{BoxFuture, ExecClient, ExecClientError};
use timescales_service::relay::Submission;
use timescales_service::wire::{
    EnclaveIdentity, ExecutePosted, ExecuteReady, ExecuteRequest, PostedTx, ProvenanceEntry,
    PublishRequest, parse_session_message,
};

/// What an enclave does when called.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Normal,
    /// Every call fails as if the host were down.
    Offline,
    /// A poster that posts its receipt but sends none of the co-signatures
    /// and returns at once: the node must send them (phase 9 d).
    PostOnly,
    /// Accepts the request and then answers nothing for an hour, far past
    /// any `attempt_timeout_ms` the tests configure.
    Hang,
}

/// How long a [`Mode::Hang`] enclave holds a request before failing it.
pub const HANG: Duration = Duration::from_secs(3_600);

/// A member as an enclave reaches it: it builds its release context from
/// the chain at finalized, as a KRC member does.
struct ChainMember {
    member: Arc<KeyReleaseMember>,
    executor: ExecutorId,
    market: [u8; 32],
    chain: Arc<dyn MarketChain>,
}

fn status(s: BatchStatus) -> CommittedStatus {
    match s {
        BatchStatus::Committed => CommittedStatus::Committed,
        BatchStatus::BeaconRevealed => CommittedStatus::BeaconRevealed,
        BatchStatus::ReceiptPosted => CommittedStatus::ReceiptPosted,
        BatchStatus::Verified => CommittedStatus::Verified,
        BatchStatus::Settled => CommittedStatus::Settled,
        BatchStatus::Aborted => CommittedStatus::Aborted,
    }
}

impl ChainMember {
    async fn context(&self, epoch: u64) -> Result<ReleaseContext, ReleaseError> {
        let m = self
            .chain
            .market(Level::Finalized)
            .await
            .map_err(|_| ReleaseError::NotFinal)?;
        let b = self
            .chain
            .batch(epoch, Level::Finalized)
            .await
            .map_err(|_| ReleaseError::NotFinal)?;
        Ok(ReleaseContext {
            executors: m
                .executors
                .iter()
                .filter(|k| **k != [0; 32])
                .map(|k| ExecutorId(*k))
                .collect(),
            committee_digest: m.committee_digest,
            prev_committee_digest: m.prev_committee_digest,
            params: m.params,
            last_settled: EpochId(m.last_settled),
            state_root: m.state_root,
            prev_receipt: m.prev_receipt,
            halted: m.halted,
            batch: b.map(|b| BatchView {
                status: status(b.status),
                root: b.root,
                count: b.count,
                terms_digest: b.terms_digest,
                beacon: (b.status >= BatchStatus::BeaconRevealed).then_some(b.beacon),
                header_digest: (b.status >= BatchStatus::ReceiptPosted).then_some(b.header_digest),
                applied_count: b.applied_count,
            }),
        })
    }
}

impl KeyReleaseService for ChainMember {
    fn index(&self) -> u8 {
        self.member.index()
    }

    fn challenge(
        &self,
        market: MarketId,
        epoch: EpochId,
    ) -> TeeFuture<'_, Result<Hash32, ReleaseError>> {
        Box::pin(async move { self.member.issue_nonce(market, epoch, self.executor) })
    }

    fn release(&self, req: KeyReleaseRequest) -> TeeFuture<'_, Result<SealedShare, ReleaseError>> {
        Box::pin(async move {
            if req.attestation.executor != self.executor {
                return Err(ReleaseError::Unauthenticated);
            }
            let _ = self.market;
            let ctx = self.context(req.header.epoch.0).await?;
            let member = self.member.clone();
            tokio::task::spawn_blocking(move || member.decide(&req, &ctx))
                .await
                .map_err(|_| ReleaseError::Unavailable)?
        })
    }
}

struct Done {
    ready: ExecuteReady,
    result: ExecutionResult,
    header: [u8; 283],
    epoch: u64,
}

pub struct FakeEnclave {
    pub enclave: Arc<Enclave>,
    executor: TeeExecutor,
    pub fee_payer: Arc<dyn TxSigner>,
    mode: Mutex<Mode>,
    done: Mutex<HashMap<Hash32, Arc<Done>>>,
    /// Every request received, also while offline.
    pub requests: Mutex<Vec<Arc<ExecuteRequest>>>,
    pub executes: AtomicU64,
    pub publishes: AtomicU64,
    /// Epoch of every publish request received.
    pub published: Mutex<Vec<u64>>,
    /// The platform `/enclave/v1/identity` reports. `None` answers the way
    /// the node's HTTP client does today (route unavailable).
    pub platform: Mutex<Option<Platform>>,
}

impl FakeEnclave {
    pub fn executor(&self) -> [u8; 32] {
        self.enclave.executor_id().0
    }

    pub fn set_mode(&self, m: Mode) {
        *self.mode.lock() = m;
    }
}

pub struct FakeEnclaves {
    pub list: Vec<FakeEnclave>,
    pub members: Vec<Arc<KeyReleaseMember>>,
    pub market: [u8; 32],
    pub program: [u8; 32],
    pub domains: Vec<String>,
    chain: Mutex<Option<Arc<dyn MarketChain>>>,
}

impl FakeEnclaves {
    /// `n` enclaves over a committee of `members` with threshold `t`.
    pub fn new(
        n: usize,
        members: u8,
        t: u8,
        market: [u8; 32],
        program: [u8; 32],
        domains: Vec<String>,
        fee_payers: Vec<Arc<dyn TxSigner>>,
    ) -> Self {
        let dep = LocalTeeDeployment::new(members, t, 11);
        let mut rng = StdRng::seed_from_u64(99);
        let list = (0..n)
            .map(|i| {
                let platform = Arc::new(dep.vendor.platform(&mut rng, 5));
                let enclave = Arc::new(Enclave::boot(platform, program_measurement(), false));
                (i, enclave)
            })
            .collect::<Vec<_>>();
        let members_list = dep.members.clone();
        Self {
            list: list
                .into_iter()
                .zip(fee_payers)
                .map(|((_, enclave), fee_payer)| FakeEnclave {
                    executor: placeholder(&enclave),
                    enclave,
                    fee_payer,
                    mode: Mutex::new(Mode::Normal),
                    done: Mutex::default(),
                    requests: Mutex::default(),
                    executes: AtomicU64::new(0),
                    publishes: AtomicU64::new(0),
                    published: Mutex::default(),
                    platform: Mutex::new(None),
                })
                .collect(),
            members: members_list,
            market,
            program,
            domains,
            chain: Mutex::new(None),
        }
    }

    /// Connects the enclaves to the chain once the market exists: the
    /// members serve each enclave through `chain`.
    pub fn connect(&mut self, chain: Arc<dyn MarketChain>, committee_digest: Hash32, t: u8) {
        for e in &mut self.list {
            let committee: Vec<Arc<dyn KeyReleaseService>> = self
                .members
                .iter()
                .map(|m| {
                    Arc::new(ChainMember {
                        member: m.clone(),
                        executor: e.enclave.executor_id(),
                        market: self.market,
                        chain: chain.clone(),
                    }) as Arc<dyn KeyReleaseService>
                })
                .collect();
            e.executor = TeeExecutor::new(
                e.enclave.clone(),
                committee,
                t,
                Arc::new(PublishedEpochKeys::default()),
                Duration::from_secs(30),
            )
            .unwrap()
            .with_committee_digest(committee_digest);
        }
        *self.chain.lock() = Some(chain);
    }

    fn chain(&self) -> Arc<dyn MarketChain> {
        self.chain.lock().clone().expect("enclaves connected")
    }

    pub fn set_all(&self, m: Mode) {
        for e in &self.list {
            e.set_mode(m);
        }
    }

    /// the admission vector from the provenance.
    fn admission(&self, req: &ExecuteRequest) -> Vec<Option<TraderId>> {
        let p = &req.provenance;
        req.batch
            .envelopes
            .iter()
            .zip(&p.entries)
            .map(|(env, entry)| {
                if entry.grant == ProvenanceEntry::NO_GRANT {
                    return None;
                }
                let g = p.grants.get(usize::try_from(entry.grant).ok()?)?;
                let grant = parse_session_message(&g.text).ok()?;
                if !self.domains.contains(&grant.domain) || grant.program != self.program {
                    return None;
                }
                if !verify_grant_signature(&grant.wallet, g.text.as_bytes(), &g.signature.0) {
                    return None;
                }
                let session = TraderId(grant.session_key);
                let digest = Submission::digest(env, None, &session);
                verify_digest(&grant.session_key, &digest, &entry.session_signature).ok()?;
                Some(TraderId(grant.wallet))
            })
            .collect()
    }

    async fn run(
        &self,
        i: usize,
        req: Arc<ExecuteRequest>,
    ) -> Result<ExecuteReady, ExecClientError> {
        let e = &self.list[i];
        let header_digest = req.batch.header.digest();
        if let Some(d) = e.done.lock().get(&header_digest) {
            return Ok(d.ready.clone());
        }
        let m = self
            .chain()
            .market(Level::Confirmed)
            .await
            .map_err(|err| refused("BadRequest", &err.to_string()))?;
        let mut allowed = vec![m.committee_digest];
        if m.prev_committee_digest != Hash32::ZERO {
            allowed.push(m.prev_committee_digest);
        }
        let (epoch_pk, _) = req
            .bundle
            .verify(&req.committee, &allowed, false)
            .map_err(|err| refused("BindingMismatch", &err.to_string()))?;
        let inputs = EpochInputs {
            market_address: req.market,
            price_commitment: req.price_commitment,
            key: EpochKey {
                epoch_pk,
                commitments: req.bundle.announcement.commitments.clone(),
            },
            announcement_digest: req.bundle.announcement.digest(),
            admission: Some(self.admission(&req)),
        };
        let exec = e
            .executor
            .execute_epoch(Arc::new(req.batch.clone()), inputs)
            .await
            .map_err(|err| refused("KeyUnavailable", &err.to_string()))?;
        let receipt = &exec.result.receipt;
        let outcome_digest = receipt.outcome.digest();
        let epoch = req.batch.header.epoch;
        let ready = ExecuteReady {
            executor: e.enclave.executor_id(),
            header_digest,
            outcome_digest,
            cosign: e
                .enclave
                .sign_cosign(&req.market, epoch, &header_digest, &outcome_digest),
            unauthenticated: exec.result.metrics.unauthenticated.clone(),
        };
        let header: [u8; 283] = timescales_core::Encode::to_bytes(&req.batch.header)
            .try_into()
            .unwrap();
        e.done.lock().insert(
            header_digest,
            Arc::new(Done {
                ready: ready.clone(),
                result: exec.result,
                header,
                epoch: epoch.0,
            }),
        );
        Ok(ready)
    }

    async fn post(&self, i: usize, req: PublishRequest) -> Result<ExecutePosted, ExecClientError> {
        let e = &self.list[i];
        let Some(done) = e.done.lock().get(&req.header_digest).cloned() else {
            return Err(refused("NotExecuted", "no completed execution"));
        };
        let chain = self.chain();
        let m = chain
            .market(Level::Confirmed)
            .await
            .map_err(|err| refused("PostFailed", &err.to_string()))?;
        let own = done.ready.outcome_digest;
        let mut cosigners = BTreeMap::new();
        for (executor, sig) in &req.cosigs {
            let d = cosign_digest(&self.market, EpochId(done.epoch), &req.header_digest, &own);
            if executor.0 != e.executor()
                && m.executor_slot(&executor.0).is_some()
                && verify_digest(&executor.0, &d, sig).is_ok()
            {
                cosigners.insert(executor.0, sig.0);
            }
        }
        let quorum = usize::from(m.receipt_quorum);
        let batch = chain
            .batch(done.epoch, Level::Confirmed)
            .await
            .map_err(|err| refused("PostFailed", &err.to_string()))?
            .ok_or_else(|| refused("PostFailed", "no batch"))?;
        let receipt = timescales_core::Encode::to_bytes(&done.result.receipt);
        let mut slot = batch.receipt_slot;
        if batch.status >= BatchStatus::ReceiptPosted {
            if batch.outcome_digest != own {
                return Err(refused("OutcomeMismatch", "another outcome is posted"));
            }
            let bit = m
                .executor_slot(&e.executor())
                .is_some_and(|slot| batch.cosign_bitmap & (1 << slot) != 0);
            if batch.status == BatchStatus::ReceiptPosted && !bit {
                chain
                    .ensure_cosigned(
                        done.epoch,
                        vec![(e.executor(), done.ready.cosign.0)],
                        e.fee_payer.clone(),
                    )
                    .await
                    .map_err(|err| refused("PostFailed", &err.to_string()))?;
            }
        } else {
            if cosigners.len() + 1 < quorum {
                return Err(refused("QuorumInvalid", "too few co-signatures"));
            }
            match chain
                .ensure_posted(done.epoch, done.header, receipt, e.fee_payer.clone())
                .await
                .map_err(|err| refused("PostFailed", &err.to_string()))?
            {
                PostOutcome::Posted { slot: s } => slot = s,
                PostOutcome::AlreadyPosted { same_receipt: true } => {}
                other => return Err(refused("PostFailed", &format!("{other:?}"))),
            }
            let post_only = *e.mode.lock() == Mode::PostOnly;
            if !post_only {
                chain
                    .ensure_cosigned(
                        done.epoch,
                        cosigners.into_iter().collect(),
                        e.fee_payer.clone(),
                    )
                    .await
                    .map_err(|err| refused("PostFailed", &err.to_string()))?;
            }
        }
        if *e.mode.lock() != Mode::PostOnly {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            chain
                .wait_batch(
                    done.epoch,
                    BatchPredicate::CosignsAtLeast(m.receipt_quorum),
                    Level::Confirmed,
                    deadline,
                )
                .await
                .map_err(|err| refused("QuorumPending", &err.to_string()))?;
        }
        Ok(ExecutePosted {
            receipt: done.result.receipt.clone(),
            artifacts: done.result.artifacts.clone(),
            attestation: done.result.attestation.clone().unwrap_or_default(),
            posted: PostedTx {
                signature: [0; 64],
                slot,
            },
            cosigned: Vec::new(),
        })
    }

    /// Executes and publishes epoch `req` on enclave `i` directly, as an
    /// enclave would on its own (backstops, a foreign poster).
    pub async fn execute_and_post(
        &self,
        i: usize,
        req: Arc<ExecuteRequest>,
        cosigners: &[usize],
    ) -> Result<ExecutePosted, ExecClientError> {
        let ready = self.run(i, req.clone()).await?;
        let mut cosigs = Vec::new();
        for j in cosigners {
            let r = self.run(*j, req.clone()).await?;
            cosigs.push((r.executor, r.cosign));
        }
        self.post(
            i,
            PublishRequest {
                market: self.market,
                epoch: req.batch.header.epoch,
                header_digest: ready.header_digest,
                cosigs,
            },
        )
        .await
    }
}

fn refused(code: &str, detail: &str) -> ExecClientError {
    ExecClientError::Refused {
        code: code.to_owned(),
        detail: detail.to_owned(),
    }
}

/// An executor without members, replaced by [`FakeEnclaves::connect`].
fn placeholder(enclave: &Arc<Enclave>) -> TeeExecutor {
    let member: Arc<dyn KeyReleaseService> = Arc::new(Unconnected);
    TeeExecutor::new(
        enclave.clone(),
        vec![member],
        1,
        Arc::new(PublishedEpochKeys::default()),
        Duration::from_secs(1),
    )
    .unwrap()
}

struct Unconnected;

impl KeyReleaseService for Unconnected {
    fn index(&self) -> u8 {
        1
    }

    fn challenge(&self, _: MarketId, _: EpochId) -> TeeFuture<'_, Result<Hash32, ReleaseError>> {
        Box::pin(async { Err(ReleaseError::Unavailable) })
    }

    fn release(&self, _: KeyReleaseRequest) -> TeeFuture<'_, Result<SealedShare, ReleaseError>> {
        Box::pin(async { Err(ReleaseError::Unavailable) })
    }
}

impl ExecClient for FakeEnclaves {
    fn execute(
        &self,
        enclave: usize,
        req: Arc<ExecuteRequest>,
    ) -> BoxFuture<'_, Result<ExecuteReady, ExecClientError>> {
        Box::pin(async move {
            let e = self
                .list
                .get(enclave)
                .ok_or(ExecClientError::UnknownEnclave(enclave))?;
            e.requests.lock().push(req.clone());
            e.executes.fetch_add(1, Ordering::Relaxed);
            let mode = *e.mode.lock();
            match mode {
                Mode::Offline => return Err(refused("Unavailable", "enclave offline")),
                Mode::Hang => {
                    tokio::time::sleep(HANG).await;
                    return Err(refused("Unavailable", "enclave hung"));
                }
                Mode::Normal | Mode::PostOnly => {}
            }
            self.run(enclave, req).await
        })
    }

    fn publish(
        &self,
        enclave: usize,
        req: PublishRequest,
    ) -> BoxFuture<'_, Result<ExecutePosted, ExecClientError>> {
        Box::pin(async move {
            let e = self
                .list
                .get(enclave)
                .ok_or(ExecClientError::UnknownEnclave(enclave))?;
            e.publishes.fetch_add(1, Ordering::Relaxed);
            e.published.lock().push(req.epoch.0);
            let mode = *e.mode.lock();
            match mode {
                Mode::Offline => return Err(refused("Unavailable", "enclave offline")),
                Mode::Hang => {
                    tokio::time::sleep(HANG).await;
                    return Err(refused("Unavailable", "enclave hung"));
                }
                Mode::Normal | Mode::PostOnly => {}
            }
            self.post(enclave, req).await
        })
    }

    fn identity(&self, enclave: usize) -> BoxFuture<'_, Result<EnclaveIdentity, ExecClientError>> {
        Box::pin(async move {
            let e = self
                .list
                .get(enclave)
                .ok_or(ExecClientError::UnknownEnclave(enclave))?;
            let Some(platform) = *e.platform.lock() else {
                return Err(refused("Unavailable", "identity route not served"));
            };
            Ok(EnclaveIdentity {
                executor: e.enclave.executor_id(),
                seal_key: e.enclave.seal_key(),
                platform,
                measurement: e.enclave.measurement().0,
                evidence: Evidence {
                    platform,
                    quote: Vec::new(),
                },
                fee_payer: e.fee_payer.address(),
            })
        })
    }
}

impl FakeEnclaves {
    /// Publish requests the node sent for `epoch`, over every enclave.
    pub fn publishes_for(&self, epoch: u64) -> usize {
        self.list
            .iter()
            .map(|e| e.published.lock().iter().filter(|p| **p == epoch).count())
            .sum()
    }
}

impl FakeEnclaves {
    /// The artifacts of the execution of `epoch` an enclave holds.
    pub fn artifacts(
        &self,
        epoch: u64,
    ) -> Option<timescales_auction::receipts::ExecutionArtifacts> {
        self.list.iter().find_map(|e| {
            e.done
                .lock()
                .values()
                .find(|d| d.epoch == epoch)
                .map(|d| d.result.artifacts.clone())
        })
    }

    /// The last request the node sent for `epoch`, to any enclave.
    pub fn request(&self, epoch: u64) -> Option<Arc<ExecuteRequest>> {
        self.list.iter().find_map(|e| {
            e.requests
                .lock()
                .iter()
                .rev()
                .find(|r| r.batch.header.epoch.0 == epoch)
                .cloned()
        })
    }
}
