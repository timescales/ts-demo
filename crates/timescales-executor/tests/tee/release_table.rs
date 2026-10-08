//! The key-release decision check by check, in table order, against
//! one hand-built chain context per case.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_auction::{BatchHeader, BatchLeaf, CommittedStatus, epoch_binding, terms_digest};
use timescales_core::crypto::{SealSecret, open};
use timescales_core::identity::ExecutorKey;
use timescales_core::{
    CommitmentScheme, EpochId, ExecutorId, FlowMode, Hash32, MarketId, OrderCommitment, Tick,
};
use timescales_executor::attestation::simulated::{SimulatedPlatform, SimulatedVendor};
use timescales_executor::attestation::{AttestationError, Measurement, Platform};
use timescales_executor::policy::{AttestationPolicy, PolicyViolation};
use timescales_executor::tee::{
    BatchView, EpochKeyDealer, HeldAnnouncement, KeyReleaseMember, KeyReleaseRequest,
    KeyReleaseService, MAX_RELEASES_PER_EPOCH, NonceLimits, ReleaseContext, ReleaseError,
    SealedShare, program_measurement,
};
use timescales_executor::tee::{Enclave, Quoter};
use timescales_executor::workload::default_params;

const EPOCH: EpochId = EpochId(3);
const COMMITTEE: Hash32 = Hash32([0xc0; 32]);
const ANNOUNCEMENT: Hash32 = Hash32([0xa1; 32]);
const PRICE: Hash32 = Hash32([0x9c; 32]);
/// The member under test. Its nonce sits at index 1 of the attestation.
const INDEX: u8 = 2;

struct Fixture {
    vendor: SimulatedVendor,
    platform: Arc<SimulatedPlatform>,
    seal: [u8; 32],
    enclave: Enclave,
    member: KeyReleaseMember,
    share: [u8; 32],
    header: BatchHeader,
    ctx: ReleaseContext,
}

fn header(price_commitment: Hash32) -> BatchHeader {
    let params = default_params(FlowMode::DualFlow, CommitmentScheme::Sha256);
    let leaves = [BatchLeaf {
        commitment: OrderCommitment([1; 32]),
        envelope_digest: Hash32([2; 32]),
    }];
    BatchHeader::assemble_v2(
        params,
        EPOCH,
        params.band(Tick(1_000)).unwrap(),
        epoch_binding(&price_commitment, &ANNOUNCEMENT, &COMMITTEE),
        &leaves,
        Hash32([0xbe; 32]),
        Hash32([0x51; 32]),
        Hash32([0xba; 32]),
        Hash32([0x7e; 32]),
    )
}

fn fixture() -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let vendor = SimulatedVendor::new(&mut rng, 5);
    let platform = Arc::new(vendor.platform(&mut rng, 5));
    let seal = SealSecret::from_bytes([0x5e; 32]);
    let seal_public = seal.public();
    let enclave = Enclave::boot_with_keys(
        platform.clone() as Arc<dyn Quoter>,
        program_measurement(),
        false,
        seal,
        ExecutorKey::from_seed([0xe1; 32]),
    );
    let policy = AttestationPolicy::strict([Platform::Simulated], [program_measurement()]);
    let member = KeyReleaseMember::new(INDEX, Arc::new(vendor.verifier()), policy).unwrap();
    let dealt = EpochKeyDealer {
        threshold: 2,
        members: 3,
    }
    .deal(&mut rng)
    .unwrap();
    let share = dealt.shares[usize::from(INDEX - 1)].clone();
    let share_bytes = share.value.to_bytes();
    let header = header(PRICE);
    member
        .store_dealt_share(
            header.market,
            EPOCH,
            share,
            HeldAnnouncement {
                digest: ANNOUNCEMENT,
                committee_digest: COMMITTEE,
            },
        )
        .unwrap();
    let ctx = ReleaseContext {
        executors: vec![ExecutorId([9; 32]), enclave.executor_id()],
        committee_digest: COMMITTEE,
        prev_committee_digest: Hash32::ZERO,
        params: header.params,
        last_settled: EpochId(EPOCH.0 - 1),
        state_root: header.prior_state_root,
        prev_receipt: header.prev_receipt,
        halted: false,
        batch: Some(BatchView {
            status: CommittedStatus::BeaconRevealed,
            root: header.batch_root,
            count: header.envelope_count,
            terms_digest: terms_digest(&header.band, &header.price_commitment),
            beacon: Some(header.beacon),
            header_digest: None,
            applied_count: 0,
        }),
    };
    assert_eq!(enclave.seal_key(), seal_public);
    Fixture {
        vendor,
        platform,
        seal: [0x5e; 32],
        enclave,
        member,
        share: share_bytes,
        header,
        ctx,
    }
}

/// Give `member` its share of a fresh dealing for (market, epoch), under the
/// fixture's announcement.
fn hold(member: &KeyReleaseMember, market: MarketId, epoch: EpochId) {
    let share = EpochKeyDealer {
        threshold: 2,
        members: 3,
    }
    .deal(&mut ChaCha20Rng::seed_from_u64(epoch.0))
    .unwrap()
    .shares
    .remove(usize::from(member.index() - 1));
    member
        .store_dealt_share(
            market,
            epoch,
            share,
            HeldAnnouncement {
                digest: ANNOUNCEMENT,
                committee_digest: COMMITTEE,
            },
        )
        .unwrap();
}

impl Fixture {
    /// A request for `header` attested by `enclave`, carrying a fresh nonce
    /// from the member.
    fn request_from(&self, enclave: &Enclave, header: BatchHeader) -> KeyReleaseRequest {
        let nonce = self
            .member
            .issue_nonce(header.market, header.epoch, enclave.executor_id())
            .unwrap();
        self.request_with_nonce(enclave, header, nonce)
    }

    fn request_with_nonce(
        &self,
        enclave: &Enclave,
        header: BatchHeader,
        nonce: Hash32,
    ) -> KeyReleaseRequest {
        let nonces = vec![Hash32([0x0a; 32]), nonce, Hash32([0x0b; 32])];
        KeyReleaseRequest {
            header,
            price_commitment: PRICE,
            attestation: enclave.attest_v2(&header, nonces, COMMITTEE),
        }
    }

    fn request(&self) -> KeyReleaseRequest {
        self.request_from(&self.enclave, self.header)
    }

    fn decide(&self, req: &KeyReleaseRequest) -> Result<SealedShare, ReleaseError> {
        self.member.decide(req, &self.ctx)
    }

    /// The share as the enclave opens it.
    fn opened(&self, s: &SealedShare, header: &BatchHeader) -> Vec<u8> {
        let mut info = b"key-release".to_vec();
        info.extend_from_slice(&header.market.0.to_le_bytes());
        info.extend_from_slice(&header.epoch.0.to_le_bytes());
        open(
            &SealSecret::from_bytes(self.seal),
            &s.sealed.ephemeral,
            &info,
            header.digest().as_bytes(),
            &s.sealed.ciphertext,
        )
        .unwrap()
        .to_vec()
    }
}

#[test]
fn a_valid_request_gets_the_share_sealed_to_the_attested_key() {
    let f = fixture();
    let s = f.decide(&f.request()).unwrap();
    assert_eq!(s.member, INDEX);
    let pt = f.opened(&s, &f.header);
    assert_eq!(pt[0], INDEX);
    assert_eq!(pt[1..], f.share);
}

#[test]
fn d_executor_must_be_registered() {
    let mut f = fixture();
    f.ctx.executors = vec![ExecutorId([9; 32])];
    assert_eq!(f.decide(&f.request()), Err(ReleaseError::NotRegistered));
    // The zero slot never counts, even if listed.
    f.ctx.executors = vec![ExecutorId([0; 32])];
    let mut req = f.request();
    req.attestation.executor = ExecutorId([0; 32]);
    assert_eq!(f.decide(&req), Err(ReleaseError::NotRegistered));
}

#[test]
fn e_attested_committee_must_be_the_acked_one_and_on_chain() {
    let mut f = fixture();
    let mut req = f.request();
    req.attestation.committee_digest = Hash32([0xc1; 32]);
    assert_eq!(f.decide(&req), Err(ReleaseError::CommitteeMismatch));

    // The chain moved on to another committee: refused...
    f.ctx.committee_digest = Hash32([0xc2; 32]);
    assert_eq!(f.decide(&f.request()), Err(ReleaseError::CommitteeMismatch));
    //...unless the acked one is the previous committee (graceful rotation).
    f.ctx.prev_committee_digest = COMMITTEE;
    assert!(f.decide(&f.request()).is_ok());

    // No announcement held for the epoch (nor a share, so the member issues
    // no nonce for it either).
    let mut other = f.header;
    other.epoch = EpochId(EPOCH.0 + 1);
    let req = f.request_with_nonce(&f.enclave, other, Hash32([0x77; 32]));
    assert_eq!(f.decide(&req), Err(ReleaseError::CommitteeMismatch));
}

#[test]
fn f_nonce_is_single_use_bound_to_executor_and_epoch_and_expires() {
    let mut f = fixture();
    f.member = KeyReleaseMember::new(
        INDEX,
        Arc::new(f.vendor.verifier()),
        AttestationPolicy::strict([Platform::Simulated], [program_measurement()]),
    )
    .unwrap()
    .with_nonce_limits(NonceLimits {
        ttl: Duration::from_secs(60),
        ..NonceLimits::default()
    });
    f.member
        .store_dealt_share(
            f.header.market,
            EPOCH,
            EpochKeyDealer {
                threshold: 2,
                members: 3,
            }
            .deal(&mut ChaCha20Rng::seed_from_u64(2))
            .unwrap()
            .shares
            .remove(usize::from(INDEX - 1)),
            HeldAnnouncement {
                digest: ANNOUNCEMENT,
                committee_digest: COMMITTEE,
            },
        )
        .unwrap();

    // Replay.
    let req = f.request();
    assert!(f.decide(&req).is_ok());
    assert_eq!(f.decide(&req), Err(ReleaseError::BadNonce));

    // A nonce never issued, or missing from the member's slot.
    let mut req = f.request();
    req.attestation.nonces[1] = Hash32([0x77; 32]);
    assert_eq!(f.decide(&req), Err(ReleaseError::BadNonce));
    let mut req = f.request();
    req.attestation.nonces.truncate(1);
    assert_eq!(f.decide(&req), Err(ReleaseError::BadNonce));

    // Issued to another executor.
    let nonce = f
        .member
        .issue_nonce(f.header.market, EPOCH, ExecutorId([9; 32]))
        .unwrap();
    let mut req = f.request();
    req.attestation.nonces[1] = nonce;
    assert_eq!(f.decide(&req), Err(ReleaseError::BadNonce));

    // Issued for another epoch.
    hold(&f.member, f.header.market, EpochId(9));
    let nonce = f
        .member
        .issue_nonce(f.header.market, EpochId(9), f.enclave.executor_id())
        .unwrap();
    let mut req = f.request();
    req.attestation.nonces[1] = nonce;
    assert_eq!(f.decide(&req), Err(ReleaseError::BadNonce));

    // Expired.
    let req = f.request();
    let later = Instant::now() + Duration::from_secs(61);
    assert_eq!(
        f.member.decide_at(&req, &f.ctx, later),
        Err(ReleaseError::BadNonce)
    );

    // Consumed by a request that fails a later check.
    let req = f.request();
    let mut halted = f.ctx.clone();
    halted.halted = true;
    assert_eq!(f.member.decide(&req, &halted), Err(ReleaseError::Halted));
    assert_eq!(f.decide(&req), Err(ReleaseError::BadNonce));
}

#[test]
fn g_batch_status_and_identity() {
    let mut f = fixture();
    let cases = [
        (None, ReleaseError::NotCommitted),
        (
            Some(CommittedStatus::Committed),
            ReleaseError::BeaconMissing,
        ),
        (Some(CommittedStatus::Settled), ReleaseError::EpochClosed),
        (Some(CommittedStatus::Aborted), ReleaseError::EpochClosed),
    ];
    let batch = f.ctx.batch.unwrap();
    for (status, err) in cases {
        f.ctx.batch = status.map(|status| BatchView { status, ..batch });
        assert_eq!(f.decide(&f.request()), Err(err), "{status:?}");
    }
    f.ctx.batch = Some(BatchView {
        status: CommittedStatus::Verified,
        applied_count: 1,
        header_digest: Some(f.header.digest()),
        ..batch
    });
    assert_eq!(f.decide(&f.request()), Err(ReleaseError::EpochClosed));

    for bad in [
        BatchView {
            root: Hash32([0; 32]),
            ..batch
        },
        BatchView {
            count: batch.count + 1,
            ..batch
        },
        BatchView {
            beacon: Some(Hash32([0; 32])),
            ..batch
        },
        BatchView {
            beacon: None,
            ..batch
        },
    ] {
        f.ctx.batch = Some(bad);
        assert_eq!(f.decide(&f.request()), Err(ReleaseError::HeaderMismatch));
    }
}

#[test]
fn g_re_release_only_for_the_posted_header_until_applied() {
    let mut f = fixture();
    let batch = f.ctx.batch.unwrap();
    for status in [CommittedStatus::ReceiptPosted, CommittedStatus::Verified] {
        f.ctx.batch = Some(BatchView {
            status,
            header_digest: Some(Hash32([0x11; 32])),
            ..batch
        });
        assert_eq!(f.decide(&f.request()), Err(ReleaseError::HeaderMismatch));
        f.ctx.batch = Some(BatchView {
            status,
            header_digest: Some(f.header.digest()),
            ..batch
        });
        assert!(f.decide(&f.request()).is_ok(), "{status:?}");
    }
}

#[test]
fn g2_epoch_binding_names_the_announcement_and_the_committed_terms() {
    let mut f = fixture();
    let mut req = f.request();
    req.price_commitment = Hash32([0x9d; 32]);
    assert_eq!(f.decide(&req), Err(ReleaseError::BindingMismatch));

    // A header bound to another price, with the terms that commit to it.
    let other = header(Hash32([0x9d; 32]));
    let mut req = f.request_from(&f.enclave, other);
    req.price_commitment = Hash32([0x9d; 32]);
    let mut batch = f.ctx.batch.unwrap();
    batch.root = other.batch_root;
    f.ctx.batch = Some(batch);
    assert_eq!(f.decide(&req), Err(ReleaseError::BindingMismatch));
}

#[test]
fn h_market_state() {
    let f = fixture();
    let mut ctx = f.ctx.clone();
    ctx.halted = true;
    assert_eq!(
        f.member.decide(&f.request(), &ctx),
        Err(ReleaseError::Halted)
    );

    let mut ctx = f.ctx.clone();
    ctx.last_settled = EpochId(EPOCH.0 - 2);
    assert_eq!(
        f.member.decide(&f.request(), &ctx),
        Err(ReleaseError::PrevNotTerminal)
    );

    let edits: [fn(&mut ReleaseContext); 3] = [
        |c| c.params.taker_fee.0 += 1,
        |c| c.state_root = Hash32([0; 32]),
        |c| c.prev_receipt = Hash32([0; 32]),
    ];
    for edit in edits {
        let mut ctx = f.ctx.clone();
        edit(&mut ctx);
        assert_eq!(
            f.member.decide(&f.request(), &ctx),
            Err(ReleaseError::HeaderMismatch)
        );
    }
}

#[test]
fn h_version_1_headers_are_refused_outside_simulations_that_allow_them() {
    let mut f = fixture();
    let mut v1 = f.header;
    v1.version = 1;
    let req = f.request_from(&f.enclave, v1);
    assert_eq!(f.decide(&req), Err(ReleaseError::HeaderMismatch));

    // The same member configured for local simulations releases it. No
    // epoch binding applies to version 1.
    f.member = f.member.accept_header_v1();
    assert_ne!(f.header.version, v1.version);
    let req = f.request_from(&f.enclave, v1);
    assert!(f.decide(&req).is_ok());
}

#[test]
fn h_accepting_version_1_does_not_accept_other_versions() {
    let mut f = fixture();
    f.member = f.member.accept_header_v1();
    for version in [0, 3, u8::MAX] {
        let mut h = f.header;
        h.version = version;
        let req = f.request_from(&f.enclave, h);
        assert_eq!(f.decide(&req), Err(ReleaseError::HeaderMismatch));
    }
}

#[test]
fn j_attestation_must_be_for_this_header() {
    let f = fixture();
    let mut req = f.request();
    req.attestation.header_digest = Hash32([0x44; 32]);
    assert_eq!(f.decide(&req), Err(ReleaseError::HeaderMismatch));
}

#[test]
fn k_l_evidence_and_policy() {
    let f = fixture();
    // Evidence from another vendor's platform.
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let foreign = SimulatedVendor::new(&mut rng, 5);
    let forged = Enclave::boot(
        Arc::new(foreign.platform(&mut rng, 5)),
        program_measurement(),
        false,
    );
    let mut req = f.request();
    req.attestation.evidence = forged
        .attest_v2(&f.header, req.attestation.nonces.clone(), COMMITTEE)
        .evidence;
    assert_eq!(
        f.decide(&req),
        Err(ReleaseError::Attestation(AttestationError::BadEndorsement))
    );

    let other_code = Enclave::boot(
        f.platform.clone(),
        Measurement::of_program("other", "1", b""),
        false,
    );
    let debug = Enclave::boot(f.platform.clone(), program_measurement(), true);
    let mut f2 = fixture();
    for (enclave, violation) in [
        (&other_code, PolicyViolation::Measurement),
        (&debug, PolicyViolation::Debug),
    ] {
        f2.ctx.executors.push(enclave.executor_id());
        let req = f2.request_from(enclave, f2.header);
        assert_eq!(f2.decide(&req), Err(ReleaseError::Policy(violation)));
    }

    // Evidence that does not bind the claimed seal key.
    let mut req = f.request();
    req.attestation.seal_key = [0x33; 32];
    assert_eq!(
        f.decide(&req),
        Err(ReleaseError::Policy(PolicyViolation::ReportData))
    );
}

#[test]
fn i_one_header_is_pinned_and_only_after_attestation() {
    let f = fixture();
    // A header that differs only in its (unchecked) balances root.
    let mut other = f.header;
    other.balances_root = Hash32([0xbb; 32]);

    // Failing the policy does not pin.
    let debug = Enclave::boot(f.platform.clone(), program_measurement(), true);
    let mut ctx = f.ctx.clone();
    ctx.executors.push(debug.executor_id());
    let req = f.request_from(&debug, other);
    assert!(matches!(
        f.member.decide(&req, &ctx),
        Err(ReleaseError::Policy(_))
    ));

    assert!(f.decide(&f.request_from(&f.enclave, other)).is_ok());
    assert_eq!(f.decide(&f.request()), Err(ReleaseError::HeaderPinned));
    assert!(f.decide(&f.request_from(&f.enclave, other)).is_ok());
}

#[test]
fn m_releases_per_epoch_are_capped() {
    let f = fixture();
    for _ in 0..MAX_RELEASES_PER_EPOCH {
        assert!(f.decide(&f.request()).is_ok());
    }
    assert_eq!(f.decide(&f.request()), Err(ReleaseError::TooManyReleases));
}

#[test]
fn nonces_are_bounded_per_executor_and_overall() {
    let f = fixture();
    let m = f.header.market;
    let x = f.enclave.executor_id();
    let limits = f.member.nonce_limits();
    assert_eq!(
        (limits.ttl, limits.per_executor, limits.total),
        (Duration::from_secs(60), 16, 4096)
    );
    for _ in 0..16 {
        f.member.issue_nonce(m, EPOCH, x).unwrap();
    }
    assert_eq!(
        f.member.issue_nonce(m, EPOCH, x),
        Err(ReleaseError::RateLimited)
    );
    // Other executors and epochs have their own allowance.
    assert!(f.member.issue_nonce(m, EPOCH, ExecutorId([9; 32])).is_ok());
    hold(&f.member, m, EpochId(4));
    assert!(f.member.issue_nonce(m, EpochId(4), x).is_ok());
    assert_eq!(f.member.outstanding_nonces(), 18);

    let small = KeyReleaseMember::new(
        1,
        Arc::new(f.vendor.verifier()),
        AttestationPolicy::strict([Platform::Simulated], [program_measurement()]),
    )
    .unwrap()
    .with_nonce_limits(NonceLimits {
        ttl: Duration::from_secs(1),
        per_executor: 16,
        total: 3,
    });
    for e in 0..4 {
        hold(&small, m, EpochId(e));
    }
    let now = Instant::now();
    for e in 0..3 {
        small.issue_nonce_at(m, EpochId(e), x, now).unwrap();
    }
    assert_eq!(
        small.issue_nonce_at(m, EpochId(3), x, now),
        Err(ReleaseError::RateLimited)
    );
    // Expired nonces make room.
    let later = now + Duration::from_secs(2);
    assert!(small.issue_nonce_at(m, EpochId(3), x, later).is_ok());
}

#[test]
fn prune_destroys_terminal_epochs_and_their_nonces() {
    let f = fixture();
    let m = f.header.market;
    let x = f.enclave.executor_id();
    let pending = f.request();
    hold(&f.member, m, EpochId(EPOCH.0 + 1));
    f.member.issue_nonce(m, EpochId(EPOCH.0 + 1), x).unwrap();
    assert_eq!(f.member.outstanding_nonces(), 2);
    assert_eq!(f.member.prune(m, EpochId(EPOCH.0 - 1)).unwrap(), 0);
    assert!(f.member.holds(m, EPOCH));
    assert_eq!(f.member.prune(m, EPOCH).unwrap(), 1);
    assert!(!f.member.holds(m, EPOCH));
    assert_eq!(f.member.outstanding_nonces(), 1);
    assert_eq!(f.decide(&pending), Err(ReleaseError::CommitteeMismatch));
    assert_eq!(
        f.member.issue_nonce(m, EPOCH, x),
        Err(ReleaseError::NoShare)
    );
}

#[tokio::test]
async fn nonces_are_issued_only_for_epochs_with_a_share() {
    let f = fixture();
    let m = f.header.market;
    let x = f.enclave.executor_id();
    // Without this, a registered executor could use up the overall budget
    // with nonces for epochs this member cannot serve.
    for (market, epoch) in [
        (m, EpochId(EPOCH.0 + 1)),
        (m, EpochId(99)),
        (MarketId(m.0 + 1), EPOCH),
    ] {
        assert_eq!(
            f.member.issue_nonce(market, epoch, x),
            Err(ReleaseError::NoShare)
        );
    }
    assert_eq!(f.member.outstanding_nonces(), 0);
    assert!(f.member.issue_nonce(m, EPOCH, x).is_ok());

    // The in-process service challenges through the same check.
    let member = Arc::new(f.member);
    let service = member.serve(x);
    assert_eq!(
        service.challenge(m, EpochId(99)).await,
        Err(ReleaseError::NoShare)
    );
    assert!(service.challenge(m, EPOCH).await.is_ok());
    assert_eq!(member.outstanding_nonces(), 2);
}

#[test]
fn shares_are_held_once_per_epoch_and_index() {
    let f = fixture();
    let ann = HeldAnnouncement {
        digest: ANNOUNCEMENT,
        committee_digest: COMMITTEE,
    };
    let dealt = EpochKeyDealer {
        threshold: 2,
        members: 3,
    }
    .deal(&mut ChaCha20Rng::seed_from_u64(4))
    .unwrap();
    let m = f.header.market;
    // Another member's share.
    assert_eq!(
        f.member
            .store_dealt_share(m, EpochId(7), dealt.shares[0].clone(), ann),
        Err(ReleaseError::BadRequest)
    );
    let mine = dealt.shares[usize::from(INDEX - 1)].clone();
    f.member
        .store_dealt_share(m, EpochId(7), mine.clone(), ann)
        .unwrap();
    // The same delivery again is a no-op. Anything else for the epoch is not.
    f.member
        .store_dealt_share(m, EpochId(7), mine.clone(), ann)
        .unwrap();
    let other_ann = HeldAnnouncement {
        digest: Hash32([0xa2; 32]),
        ..ann
    };
    assert_eq!(
        f.member.store_dealt_share(m, EpochId(7), mine, other_ann),
        Err(ReleaseError::BadRequest)
    );
    assert!(
        KeyReleaseMember::new(
            0,
            Arc::new(f.vendor.verifier()),
            AttestationPolicy::strict([], [])
        )
        .is_err()
    );
    assert!(
        KeyReleaseMember::new(
            17,
            Arc::new(f.vendor.verifier()),
            AttestationPolicy::strict([], [])
        )
        .is_err()
    );
}

#[test]
fn pins_survive_a_restart_through_restore() {
    let f = fixture();
    let m = f.header.market;
    assert_eq!(f.member.pin(m, EPOCH), None);
    assert!(f.decide(&f.request()).is_ok());
    let (pinned, releases) = f.member.pin(m, EPOCH).unwrap();
    assert_eq!((pinned, releases), (f.header.digest(), 1));

    // A restarted member holds its share again and restores the pin.
    let restarted = fixture();
    restarted
        .member
        .restore_pin(m, EPOCH, pinned, MAX_RELEASES_PER_EPOCH)
        .unwrap();
    assert_eq!(
        restarted.decide(&restarted.request()),
        Err(ReleaseError::TooManyReleases)
    );
    let mut other = restarted.header;
    other.balances_root = Hash32([0xbb; 32]);
    assert_eq!(
        restarted.member.restore_pin(m, EPOCH, other.digest(), 0),
        Err(ReleaseError::HeaderPinned)
    );
    assert_eq!(
        restarted
            .member
            .restore_pin(m, EpochId(EPOCH.0 + 1), pinned, 0),
        Err(ReleaseError::NoShare)
    );
}
