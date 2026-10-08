//! A header v2 batch end to end through the TEE path: members that decide
//! against a chain context, Feldman-checked shares, the secret order seed
//! and provenance admission. The reference executor, holding the same
//! secret, must agree on everything.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_auction::{BatchHeader, CommittedStatus, batch_leaves, epoch_binding, terms_digest};
use timescales_core::crypto::{EpochSecret, ScalarSealSecret, SealSecret};
use timescales_core::identity::ExecutorKey;
use timescales_core::{
    CommitmentScheme, EpochId, ExecutorId, FlowMode, HEADER_VERSION_ENVELOPE_BOUND, Hash32,
    MarketId, TraderId,
};
use timescales_executor::attestation::Platform;
use timescales_executor::attestation::simulated::SimulatedVendor;
use timescales_executor::policy::AttestationPolicy;
use timescales_executor::tee::{
    BatchView, BoxFuture, Enclave, EpochInputs, EpochKey, EpochKeyDealer, HeldAnnouncement,
    KeyReleaseMember, KeyReleaseRequest, KeyReleaseService, PublishedEpochKeys, ReleaseContext,
    ReleaseError, SealedShare, TeeExecutor, program_measurement,
};
use timescales_executor::workload::{WorkloadConfig, default_params, generate};
use timescales_executor::{ExecutionBatch, ExecutorError, KeyProvider, ReferenceExecutor};

const COMMITTEE: Hash32 = Hash32([0xc0; 32]);
const ANNOUNCEMENT: Hash32 = Hash32([0xa1; 32]);
const PRICE: Hash32 = Hash32([0x9c; 32]);
const ADDRESS: [u8; 32] = [0xad; 32];

/// A member reached by one executor, deciding against a fixed chain read.
struct ChainMember {
    member: Arc<KeyReleaseMember>,
    executor: ExecutorId,
    ctx: ReleaseContext,
}

impl KeyReleaseService for ChainMember {
    fn index(&self) -> u8 {
        self.member.index()
    }

    fn challenge(
        &self,
        market: MarketId,
        epoch: EpochId,
    ) -> BoxFuture<'_, Result<Hash32, ReleaseError>> {
        Box::pin(async move { self.member.issue_nonce(market, epoch, self.executor) })
    }

    fn release(&self, req: KeyReleaseRequest) -> BoxFuture<'_, Result<SealedShare, ReleaseError>> {
        Box::pin(async move {
            if req.attestation.executor != self.executor {
                return Err(ReleaseError::Unauthenticated);
            }
            self.member.decide(&req, &self.ctx)
        })
    }
}

/// The epoch secret in the form an enclave reconstructs it.
struct ThresholdKey(SealSecret);

impl KeyProvider for ThresholdKey {
    fn epoch_public(&self, _: MarketId, _: EpochId) -> Result<[u8; 32], ExecutorError> {
        Ok(self.0.public())
    }
    fn epoch_secret(&self, _: MarketId, _: EpochId) -> Result<SealSecret, ExecutorError> {
        Ok(SealSecret::from_bytes(self.0.to_bytes()))
    }
    fn epoch_key(&self, _: MarketId, _: EpochId) -> Result<EpochSecret, ExecutorError> {
        Ok(EpochSecret::Threshold(ScalarSealSecret::from_x25519(
            &self.0,
        )))
    }
}

struct Setup {
    members: Vec<Arc<KeyReleaseMember>>,
    enclave: Arc<Enclave>,
    keys: Arc<PublishedEpochKeys>,
    batch: Arc<ExecutionBatch>,
    ctx: ReleaseContext,
    inputs: EpochInputs,
    secret: SealSecret,
}

fn setup(seed: u64) -> Setup {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let vendor = SimulatedVendor::new(&mut rng, 5);
    let platform = Arc::new(vendor.platform(&mut rng, 5));
    let enclave = Arc::new(Enclave::boot(platform, program_measurement(), false));
    let policy = AttestationPolicy::strict([Platform::Simulated], [program_measurement()]);

    let mut params = default_params(FlowMode::DualFlow, CommitmentScheme::Sha256);
    params.band_half_width = 4;
    let mut cfg = WorkloadConfig::new(params, 80, seed);
    cfg.traders = 20;
    cfg.cancel_pct = 5;
    cfg.noop_pct = 10;

    let secret = SealSecret::generate(&mut rng);
    let dealt = EpochKeyDealer {
        threshold: 3,
        members: 5,
    }
    .deal_secret(&mut rng, &ScalarSealSecret::from_x25519(&secret))
    .unwrap();
    let keys = Arc::new(PublishedEpochKeys::default());
    keys.publish_dealing(
        params.market,
        cfg.epoch,
        dealt.public,
        dealt.commitments.clone(),
    );
    let announcement = HeldAnnouncement {
        digest: ANNOUNCEMENT,
        committee_digest: COMMITTEE,
    };
    let members: Vec<Arc<KeyReleaseMember>> = dealt
        .shares
        .into_iter()
        .map(|share| {
            let m = KeyReleaseMember::new(share.index, Arc::new(vendor.verifier()), policy.clone())
                .unwrap();
            m.store_dealt_share(params.market, cfg.epoch, share, announcement)
                .unwrap();
            Arc::new(m)
        })
        .collect();

    let w = generate(&cfg, keys.as_ref());
    let v1 = w.batch.header;
    let binding = epoch_binding(&PRICE, &ANNOUNCEMENT, &COMMITTEE);
    let header = BatchHeader::assemble_v2(
        params,
        cfg.epoch,
        v1.band,
        binding,
        &batch_leaves(&w.batch.envelopes),
        Hash32([0xbe; 32]),
        v1.prior_state_root,
        v1.balances_root,
        Hash32([0x7e; 32]),
    );
    assert_eq!(header.version, HEADER_VERSION_ENVELOPE_BOUND);
    let batch = ExecutionBatch {
        header,
        masked: Vec::new(),
        ..w.batch
    };
    let ctx = ReleaseContext {
        executors: vec![enclave.executor_id()],
        committee_digest: COMMITTEE,
        prev_committee_digest: Hash32::ZERO,
        params,
        last_settled: EpochId(cfg.epoch.0 - 1),
        state_root: header.prior_state_root,
        prev_receipt: header.prev_receipt,
        halted: false,
        batch: Some(BatchView {
            status: CommittedStatus::BeaconRevealed,
            root: header.batch_root,
            count: header.envelope_count,
            terms_digest: terms_digest(&header.band, &binding),
            beacon: Some(header.beacon),
            header_digest: None,
            applied_count: 0,
        }),
    };
    let admission: Vec<Option<TraderId>> =
        w.intents.iter().map(|(pi, _)| pi.body.trader()).collect();
    let inputs = EpochInputs {
        market_address: ADDRESS,
        price_commitment: PRICE,
        key: EpochKey {
            epoch_pk: dealt.public,
            commitments: dealt.commitments,
        },
        announcement_digest: ANNOUNCEMENT,
        admission: Some(admission),
    };
    Setup {
        members,
        enclave,
        keys,
        batch: Arc::new(batch),
        ctx,
        inputs,
        secret,
    }
}

fn executor(s: &Setup, ctx: &ReleaseContext) -> TeeExecutor {
    let committee = s
        .members
        .iter()
        .map(|m| {
            Arc::new(ChainMember {
                member: Arc::clone(m),
                executor: s.enclave.executor_id(),
                ctx: ctx.clone(),
            }) as Arc<dyn KeyReleaseService>
        })
        .collect();
    TeeExecutor::new(
        Arc::clone(&s.enclave),
        committee,
        3,
        s.keys.clone(),
        Duration::from_secs(5),
    )
    .unwrap()
    .with_committee_digest(COMMITTEE)
}

fn reference(s: &Setup) -> ReferenceExecutor<ThresholdKey> {
    ReferenceExecutor::new(
        Arc::new(ThresholdKey(SealSecret::from_bytes(s.secret.to_bytes()))),
        ExecutorKey::from_seed([1; 32]),
    )
    .with_market_address(ADDRESS)
}

#[tokio::test(flavor = "multi_thread")]
async fn tee_and_reference_agree_on_a_version_2_batch() {
    let s = setup(1);
    let tee = executor(&s, &s.ctx)
        .execute_epoch(Arc::clone(&s.batch), s.inputs.clone())
        .await
        .unwrap();
    assert_eq!(tee.used, vec![1, 2, 3]);
    assert!(tee.member_failures.is_empty());
    let r = reference(&s)
        .execute_admitted(&s.batch, s.inputs.admission.as_deref())
        .unwrap();
    assert_eq!(tee.result.receipt.outcome, r.receipt.outcome);
    assert_eq!(tee.result.receipt.trace, r.receipt.trace);
    assert_eq!(tee.result.artifacts, r.artifacts);
    assert_eq!(
        tee.result.metrics.unauthenticated,
        r.metrics.unauthenticated
    );
    assert!(tee.result.metrics.unauthenticated.is_empty());
    assert!(!r.artifacts.fills.is_empty(), "the batch trades");

    // A different market address gives a different order.
    let elsewhere = reference(&s).with_market_address([0xae; 32]);
    let other = elsewhere
        .execute_admitted(&s.batch, s.inputs.admission.as_deref())
        .unwrap();
    assert_ne!(other.receipt.trace, r.receipt.trace);
}

#[tokio::test(flavor = "multi_thread")]
async fn provenance_failures_are_listed_and_agree_with_the_reference() {
    let s = setup(2);
    let mut inputs = s.inputs.clone();
    let admission = inputs.admission.as_mut().unwrap();
    let real: Vec<usize> = (0..admission.len())
        .filter(|&i| admission[i].is_some())
        .take(2)
        .collect();
    // One intent submitted under someone else's grant, one as cover.
    admission[real[0]] = Some(TraderId([0xee; 32]));
    admission[real[1]] = None;
    let tee = executor(&s, &s.ctx)
        .execute_epoch(Arc::clone(&s.batch), inputs.clone())
        .await
        .unwrap();
    let r = reference(&s)
        .execute_admitted(&s.batch, inputs.admission.as_deref())
        .unwrap();
    assert_eq!(tee.result.receipt.outcome, r.receipt.outcome);
    assert_eq!(
        tee.result.metrics.unauthenticated,
        r.metrics.unauthenticated
    );
    let listed: Vec<usize> = tee
        .result
        .metrics
        .unauthenticated
        .iter()
        .map(|&i| i as usize)
        .collect();
    assert_eq!(listed, real);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_binding_to_another_announcement_is_refused_before_any_member_call() {
    let s = setup(3);
    let mut inputs = s.inputs.clone();
    inputs.announcement_digest = Hash32([0xa2; 32]);
    let err = executor(&s, &s.ctx)
        .execute_epoch(Arc::clone(&s.batch), inputs)
        .await
        .unwrap_err();
    assert_eq!(err, ExecutorError::BadHeader("epoch binding"));
    assert!(s.members.iter().all(|m| m.outstanding_nonces() == 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn members_refuse_terms_the_relay_did_not_commit() {
    let s = setup(4);
    let mut ctx = s.ctx.clone();
    let mut batch = ctx.batch.unwrap();
    batch.terms_digest = Hash32([0; 32]);
    ctx.batch = Some(batch);
    match executor(&s, &ctx)
        .execute_epoch(Arc::clone(&s.batch), s.inputs.clone())
        .await
    {
        Err(ExecutorError::KeyUnavailable(f)) => {
            assert_eq!(f.members.len(), 5);
            assert!(
                f.members
                    .iter()
                    .all(|m| m.refusal == Some(ReleaseError::BindingMismatch.code()))
            );
        }
        other => panic!("expected refusals, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admission_vector_of_the_wrong_length_is_refused() {
    let s = setup(5);
    let mut inputs = s.inputs.clone();
    inputs.admission.as_mut().unwrap().pop();
    assert!(matches!(
        executor(&s, &s.ctx)
            .execute_epoch(Arc::clone(&s.batch), inputs)
            .await,
        Err(ExecutorError::BadHeader(_))
    ));
}
