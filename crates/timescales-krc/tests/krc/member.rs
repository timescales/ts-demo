//! The member service: share acceptance, challenges and the
//! release rules, the header pin, persistence and pruning.

#![allow(clippy::unwrap_used)]

use super::common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use rand_core::{OsRng, RngCore};
use tempfile::TempDir;
use timescales_chain::program::{BatchAccount, BatchStatus};
use timescales_core::{EpochId, Hash32};
use timescales_executor::attestation::{Measurement, Platform};
use timescales_executor::tee::SealedShare;
use timescales_krc::config::MemberConfig;
use timescales_krc::member::{Member, ShareRefusal};
use timescales_service::store::member::MemberRepo;
use timescales_service::store::{RatchetSealer, Schema, Store, StoreOptions};
use timescales_service::wire::{ChallengeRequest, EpochKeyAck, ReleaseRefusal};

const N: u8 = 3;
const T: u8 = 2;
const KEYS: u8 = 1;
const E: u64 = 5;

struct World {
    dir: TempDir,
    chain: Chain,
    committee: Committee,
    cfg: MemberConfig,
    member: Arc<Member>,
    enclave: Enclave,
    other: Enclave,
    stranger: Enclave,
    cache: Duration,
}

impl World {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(edit: impl FnOnce(&mut MemberConfig)) -> Self {
        Self::build(Duration::ZERO, edit)
    }

    fn build(cache: Duration, edit: impl FnOnce(&mut MemberConfig)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let committee = committee(market_address(), N, T, KEYS);
        let file = dir.path().join("committee.bin");
        committee.write(&file);
        let (enclave, other, stranger) = (Enclave::new(1), Enclave::new(3), Enclave::new(2));
        let mut market = market_account(
            committee.digest(),
            &[enclave.executor.public(), other.executor.public()],
        );
        market.last_committed = E - 1;
        market.last_settled = E - 1;
        let chain = Chain::new(market);
        let mut cfg = member_config(dir.path(), 1, file);
        edit(&mut cfg);
        let member = Arc::new(open_member(
            dir.path(),
            cfg.clone(),
            KEYS,
            chain.krc_cached(cache),
        ));
        Self {
            dir,
            chain,
            committee,
            cfg,
            member,
            enclave,
            other,
            stranger,
            cache,
        }
    }

    /// Opens the member again over the same files.
    fn restart(&mut self) {
        self.member = Arc::new(open_member(
            self.dir.path(),
            self.cfg.clone(),
            KEYS,
            self.chain.krc_cached(self.cache),
        ));
    }

    async fn deliver(&self, d: &TestDealing) -> Result<EpochKeyAck, ShareRefusal> {
        self.member
            .accept_share(dealer_key().public(), d.deliveries[0].clone())
            .await
    }

    /// The relay commits epoch `d`'s batch and the beacon is revealed.
    fn commit(&self, d: &TestDealing) -> BatchAccount {
        let e = d.announcement.epoch.0;
        self.chain
            .update_market(|m| m.last_committed = m.last_committed.max(e));
        let batch = revealed_batch(&d.announcement);
        self.chain.put_batch(&batch);
        batch
    }

    /// Epoch E dealt, its share accepted, committed and revealed.
    async fn ready(&self) -> (TestDealing, BatchAccount) {
        let d = deal(&self.committee, E);
        self.deliver(&d).await.unwrap();
        let batch = self.commit(&d);
        (d, batch)
    }

    async fn challenge(&self, enclave: &Enclave, epoch: u64) -> Result<Hash32, ReleaseRefusal> {
        self.member
            .challenge(
                enclave.id(),
                ChallengeRequest {
                    market: market_address(),
                    epoch: EpochId(epoch),
                    executor: enclave.id(),
                },
            )
            .await
            .map(|c| c.nonce)
    }

    fn request(
        &self,
        enclave: &Enclave,
        d: &TestDealing,
        batch: &BatchAccount,
        nonce: Hash32,
        balances: u8,
    ) -> timescales_executor::tee::KeyReleaseRequest {
        let market = self.chain.market.lock().clone();
        release_request(
            enclave,
            header(&market, batch, Hash32([balances; 32])),
            &d.announcement,
            1,
            N,
            nonce,
            MEASUREMENT,
        )
    }

    /// The header a request for `batch` with variant `balances` carries.
    fn header_of(
        &self,
        d: &TestDealing,
        batch: &BatchAccount,
        balances: u8,
    ) -> timescales_auction::BatchHeader {
        self.request(&self.enclave, d, batch, Hash32::ZERO, balances)
            .header
    }

    /// Challenge, then release with header variant `balances`.
    async fn release(
        &self,
        enclave: &Enclave,
        d: &TestDealing,
        batch: &BatchAccount,
        balances: u8,
    ) -> Result<SealedShare, ReleaseRefusal> {
        let nonce = self.challenge(enclave, batch.epoch).await?;
        let req = self.request(enclave, d, batch, nonce, balances);
        self.member.release(enclave.id(), req).await
    }
}

#[tokio::test]
async fn accepts_a_verified_share_and_re_acks_the_same_announcement() {
    let w = World::new();
    let d = deal(&w.committee, E);
    let ack = w.deliver(&d).await.unwrap();
    assert_eq!(ack.member, 1);
    ack.verify(
        &d.announcement.digest(),
        &w.committee.desc.members[0].identity,
    )
    .unwrap();
    let statement = w.member.policy();
    statement
        .verify(&w.committee.desc.members[0].identity)
        .unwrap();
    assert_eq!(ack.policy_digest, statement.digest());
    assert_eq!(statement.committee_digest, w.committee.digest());
    assert_eq!(statement.platforms, 1, "simulated only");
    // The same delivery again: the same ack, nothing else changes.
    assert_eq!(w.deliver(&d).await.unwrap(), ack);
    let (held, held_ack) = w
        .member
        .announcement(market_address(), EpochId(E))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held, d.announcement);
    assert_eq!(held_ack, ack);
    assert_eq!(w.member.metrics().second_announcement.get(), 0);
}

#[tokio::test]
async fn a_second_announcement_gets_the_stored_digest_and_an_alert() {
    let w = World::new();
    let first = deal(&w.committee, E);
    w.deliver(&first).await.unwrap();
    let second = deal(&w.committee, E);
    match w.deliver(&second).await {
        Err(ShareRefusal::SecondAnnouncement { stored }) => {
            assert_eq!(stored, first.announcement.digest());
        }
        other => panic!("expected a second-announcement refusal, got {other:?}"),
    }
    assert_eq!(w.member.metrics().second_announcement.get(), 1);
    let (held, _) = w
        .member
        .announcement(market_address(), EpochId(E))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held, first.announcement);
}

#[tokio::test]
async fn deliveries_are_checked_before_they_are_stored() {
    let w = World::new();
    let d = deal(&w.committee, E);
    let stranger = timescales_core::crypto::Keypair::from_seed([9; 32]);
    assert!(matches!(
        w.member
            .accept_share(stranger.public(), d.deliveries[0].clone())
            .await,
        Err(ShareRefusal::Unauthenticated)
    ));
    // Another market's committee.
    let elsewhere = committee([0x44; 32], N, T, KEYS);
    assert!(matches!(
        w.deliver(&deal(&elsewhere, E)).await,
        Err(ShareRefusal::UnknownMarket)
    ));
    // Member 2's delivery handed to member 1.
    assert!(matches!(
        w.member
            .accept_share(dealer_key().public(), d.deliveries[1].clone())
            .await,
        Err(ShareRefusal::BadShare)
    ));
    // A commitment changed: the announcement no longer opens the box.
    let mut forged = d.deliveries[0].clone();
    forged.announcement.commitments.swap(0, 1);
    assert!(matches!(
        w.member.accept_share(dealer_key().public(), forged).await,
        Err(ShareRefusal::BadShare)
    ));
    // Too late: the epoch is committed.
    let late = deal(&w.committee, E - 1);
    assert!(matches!(w.deliver(&late).await, Err(ShareRefusal::TooLate)));
    // The chain names another committee.
    w.chain
        .update_market(|m| m.committee_digest = Hash32([0xcc; 32]));
    assert!(matches!(
        w.deliver(&d).await,
        Err(ShareRefusal::CommitteeMismatch)
    ));
    assert!(
        w.member
            .announcement(market_address(), EpochId(E))
            .await
            .unwrap()
            .is_none()
    );
}

/// A member of both the old and the new committee, configured with the
/// new one after an emergency rotation.
async fn rotated(
    prev_on_chain: impl FnOnce(&Committee) -> Hash32,
) -> (World, TestDealing, TestDealing) {
    let mut w = World::new();
    let old = deal(&w.committee, E);
    w.deliver(&old).await.unwrap();
    let new_committee = committee(market_address(), N, 3, KEYS);
    let prev = prev_on_chain(&w.committee);
    w.chain.update_market(|m| {
        m.prev_committee_digest = prev;
        m.committee_digest = new_committee.digest();
    });
    let file = w.dir.path().join("committee-new.bin");
    new_committee.write(&file);
    w.cfg.markets[0].committee_file = file;
    w.committee = new_committee;
    w.restart();
    let new = deal(&w.committee, E);
    (w, old, new)
}

#[tokio::test]
async fn an_emergency_rotation_replaces_a_share_of_the_previous_committee() {
    let (w, old, new) = rotated(Committee::digest).await;
    let ack = w.deliver(&new).await.unwrap();
    ack.verify(
        &new.announcement.digest(),
        &w.committee.desc.members[0].identity,
    )
    .unwrap();
    let (held, _) = w
        .member
        .announcement(market_address(), EpochId(E))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held, new.announcement);
    assert_ne!(held, old.announcement);
    assert_eq!(w.member.metrics().second_announcement.get(), 0);
    // The share released for the epoch is the new one.
    let batch = w.commit(&new);
    let share = w.release(&w.enclave, &new, &batch, 1).await.unwrap();
    let plain = open_released(&w.enclave, &w.header_of(&new, &batch, 1), &share);
    assert_eq!(plain[1..], new.shares[0].value.to_bytes());
}

#[tokio::test]
async fn a_rotation_replaces_only_a_share_of_the_previous_committee() {
    // The chain's previous committee is not the one the stored share names.
    let (w, old, new) = rotated(|_| Hash32([0xdd; 32])).await;
    match w.deliver(&new).await {
        Err(ShareRefusal::SecondAnnouncement { stored }) => {
            assert_eq!(stored, old.announcement.digest());
        }
        other => panic!("expected a second-announcement refusal, got {other:?}"),
    }
    assert_eq!(w.member.metrics().second_announcement.get(), 1);
}

#[tokio::test]
async fn releases_the_share_to_an_attested_registered_executor() {
    let w = World::new();
    let (d, batch) = w.ready().await;
    let share = w.release(&w.enclave, &d, &batch, 1).await.unwrap();
    assert_eq!(share.member, 1);
    let plain = open_released(&w.enclave, &w.header_of(&d, &batch, 1), &share);
    assert_eq!(plain[0], 1);
    assert_eq!(plain[1..], d.shares[0].value.to_bytes());
    assert_eq!(w.member.metrics().releases("released"), 1);
}

/// Runs one scenario per refusal code and returns the code it produced.
async fn refusal_scenarios() -> Vec<ReleaseRefusal> {
    let mut seen = Vec::new();
    let refused = |r: Result<SealedShare, ReleaseRefusal>| r.unwrap_err();

    // Unavailable: the confirmed Market read fails.
    let w = World::new();
    let (_, _) = w.ready().await;
    w.chain.backend.fail_reads(4);
    seen.push(w.challenge(&w.enclave, E).await.unwrap_err());

    // Unauthenticated: the envelope sender is not the attested executor.
    let w = World::new();
    let (d, batch) = w.ready().await;
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    let req = w.request(&w.enclave, &d, &batch, nonce, 1);
    seen.push(refused(w.member.release(w.other.id(), req).await));

    // RateLimited: one request per second.
    let w = World::with(|c| {
        c.per_caller_rps = 1;
        c.per_caller_burst = 1;
    });
    let (_, _) = w.ready().await;
    w.challenge(&w.enclave, E).await.unwrap();
    seen.push(w.challenge(&w.enclave, E).await.unwrap_err());

    // BadRequest: a market this member does not serve.
    let w = World::new();
    seen.push(
        w.member
            .challenge(
                w.enclave.id(),
                ChallengeRequest {
                    market: [0x44; 32],
                    epoch: EpochId(E),
                    executor: w.enclave.id(),
                },
            )
            .await
            .unwrap_err(),
    );

    // NotRegistered.
    let w = World::new();
    let (d, batch) = w.ready().await;
    seen.push(w.challenge(&w.stranger, E).await.unwrap_err());
    let req = w.request(&w.stranger, &d, &batch, Hash32([1; 32]), 1);
    assert_eq!(
        refused(w.member.release(w.stranger.id(), req).await),
        ReleaseRefusal::NotRegistered
    );

    // CommitteeMismatch: the evidence names another committee.
    let w = World::new();
    let (d, batch) = w.ready().await;
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    let mut req = w.request(&w.enclave, &d, &batch, nonce, 1);
    req.attestation.committee_digest = Hash32([0xcc; 32]);
    req.attestation.evidence = evidence(MEASUREMENT, req.attestation.expected_report_data());
    seen.push(refused(w.member.release(w.enclave.id(), req).await));

    // BadNonce: a nonce this member never issued.
    let w = World::new();
    let (d, batch) = w.ready().await;
    let req = w.request(&w.enclave, &d, &batch, Hash32([7; 32]), 1);
    seen.push(refused(w.member.release(w.enclave.id(), req).await));

    // NotCommitted: the batch is gone by the time of the release.
    let w = World::new();
    let (d, batch) = w.ready().await;
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    w.chain.remove_batch(E);
    let req = w.request(&w.enclave, &d, &batch, nonce, 1);
    seen.push(refused(w.member.release(w.enclave.id(), req).await));

    // BeaconMissing: committed, not revealed.
    let w = World::new();
    let d = deal(&w.committee, E);
    w.deliver(&d).await.unwrap();
    let mut batch = w.commit(&d);
    batch.status = BatchStatus::Committed;
    w.chain.put_batch(&batch);
    seen.push(refused(w.release(&w.enclave, &d, &batch, 1).await));

    // NotFinal: the providers disagree.
    let w = World::new();
    let (d, batch) = w.ready().await;
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    w.chain.backend.disagree(true);
    let req = w.request(&w.enclave, &d, &batch, nonce, 1);
    seen.push(refused(w.member.release(w.enclave.id(), req).await));

    // EpochClosed.
    let w = World::new();
    let (d, mut batch) = w.ready().await;
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    batch.status = BatchStatus::Settled;
    w.chain.put_batch(&batch);
    let req = w.request(&w.enclave, &d, &batch, nonce, 1);
    seen.push(refused(w.member.release(w.enclave.id(), req).await));

    // HeaderMismatch: the header's count is not the batch's.
    let w = World::new();
    let (d, batch) = w.ready().await;
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    let mut wrong = batch.clone();
    wrong.count += 1;
    let req = w.request(&w.enclave, &d, &wrong, nonce, 1);
    seen.push(refused(w.member.release(w.enclave.id(), req).await));

    // PrevNotTerminal.
    let w = World::new();
    let (d, batch) = w.ready().await;
    w.chain.update_market(|m| m.last_settled = E - 2);
    seen.push(refused(w.release(&w.enclave, &d, &batch, 1).await));

    // HeaderPinned: a second header for the epoch.
    let w = World::new();
    let (d, batch) = w.ready().await;
    w.release(&w.enclave, &d, &batch, 1).await.unwrap();
    seen.push(refused(w.release(&w.enclave, &d, &batch, 2).await));

    // Attestation: evidence the verifier cannot check.
    let w = World::new();
    let (d, batch) = w.ready().await;
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    let mut req = w.request(&w.enclave, &d, &batch, nonce, 1);
    req.attestation.evidence.platform = Platform::IntelTdx;
    seen.push(refused(w.member.release(w.enclave.id(), req).await));

    // Policy: a measurement outside the allowlist.
    let w = World::new();
    let (d, batch) = w.ready().await;
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    let mut req = w.request(&w.enclave, &d, &batch, nonce, 1);
    req.attestation.evidence = evidence(
        Measurement(Hash32([0x11; 32])),
        req.attestation.expected_report_data(),
    );
    seen.push(refused(w.member.release(w.enclave.id(), req).await));

    // TooManyReleases.
    let w = World::with(|c| c.max_releases_per_epoch = 1);
    let (d, batch) = w.ready().await;
    w.release(&w.enclave, &d, &batch, 1).await.unwrap();
    seen.push(refused(w.release(&w.other, &d, &batch, 1).await));

    // NoShare: a committed epoch this member was never dealt.
    let w = World::new();
    let d = deal(&w.committee, E);
    w.commit(&d);
    seen.push(w.challenge(&w.enclave, E).await.unwrap_err());

    // Halted.
    let w = World::new();
    let (d, batch) = w.ready().await;
    w.chain.update_market(|m| m.halted = true);
    seen.push(refused(w.release(&w.enclave, &d, &batch, 1).await));

    // BindingMismatch: the header binds another price commitment.
    let w = World::new();
    let (d, batch) = w.ready().await;
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    let mut req = w.request(&w.enclave, &d, &batch, nonce, 1);
    req.price_commitment = Hash32([0x01; 32]);
    seen.push(refused(w.member.release(w.enclave.id(), req).await));

    seen
}

#[tokio::test]
async fn every_release_refusal_is_reachable() {
    let seen = refusal_scenarios().await;
    let expected = [
        ReleaseRefusal::Unavailable,
        ReleaseRefusal::Unauthenticated,
        ReleaseRefusal::RateLimited,
        ReleaseRefusal::BadRequest,
        ReleaseRefusal::NotRegistered,
        ReleaseRefusal::CommitteeMismatch,
        ReleaseRefusal::BadNonce,
        ReleaseRefusal::NotCommitted,
        ReleaseRefusal::BeaconMissing,
        ReleaseRefusal::NotFinal,
        ReleaseRefusal::EpochClosed,
        ReleaseRefusal::HeaderMismatch,
        ReleaseRefusal::PrevNotTerminal,
        ReleaseRefusal::HeaderPinned,
        ReleaseRefusal::Attestation,
        ReleaseRefusal::Policy,
        ReleaseRefusal::TooManyReleases,
        ReleaseRefusal::NoShare,
        ReleaseRefusal::Halted,
        ReleaseRefusal::BindingMismatch,
    ];
    assert_eq!(seen, expected, "backend: {}", Backend::name());
    let all: BTreeSet<u8> = ReleaseRefusal::ALL.iter().map(|c| *c as u8).collect();
    let reached: BTreeSet<u8> = seen.iter().map(|c| *c as u8).collect();
    assert_eq!(reached, all);
}

#[tokio::test]
async fn the_pin_is_taken_only_after_the_attestation_passed() {
    let w = World::new();
    let (d, batch) = w.ready().await;
    // Header 2 with evidence that fails the policy: refused, not pinned.
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    let mut req = w.request(&w.enclave, &d, &batch, nonce, 2);
    req.attestation.evidence = evidence(
        Measurement(Hash32([0x11; 32])),
        req.attestation.expected_report_data(),
    );
    assert_eq!(
        w.member.release(w.enclave.id(), req).await.unwrap_err(),
        ReleaseRefusal::Policy
    );
    // Header 1 is still free, and once released it is the pinned one.
    w.release(&w.enclave, &d, &batch, 1).await.unwrap();
    assert_eq!(
        w.release(&w.other, &d, &batch, 2).await.unwrap_err(),
        ReleaseRefusal::HeaderPinned
    );
    w.release(&w.other, &d, &batch, 1).await.unwrap();
}

#[tokio::test]
async fn re_release_after_the_receipt_only_for_the_posted_header() {
    let w = World::new();
    let (d, mut batch) = w.ready().await;
    w.release(&w.enclave, &d, &batch, 1).await.unwrap();
    let posted = w.header_of(&d, &batch, 1);
    batch.status = BatchStatus::ReceiptPosted;
    batch.header_digest = posted.digest();
    w.chain.put_batch(&batch);
    // A co-signer recovers the same header.
    w.release(&w.other, &d, &batch, 1).await.unwrap();
    // Another header is not the posted one.
    assert_eq!(
        w.release(&w.other, &d, &batch, 2).await.unwrap_err(),
        ReleaseRefusal::HeaderMismatch
    );
    // Verified with nothing applied: still the posted header only.
    batch.status = BatchStatus::Verified;
    w.chain.put_batch(&batch);
    w.release(&w.enclave, &d, &batch, 1).await.unwrap();
    // Once deltas are applied the epoch is closed.
    batch.applied_count = 1;
    w.chain.put_batch(&batch);
    assert_eq!(
        w.release(&w.enclave, &d, &batch, 1).await.unwrap_err(),
        ReleaseRefusal::EpochClosed
    );
}

#[tokio::test]
async fn the_pin_and_the_release_count_survive_a_restart() {
    let mut w = World::with(|c| c.max_releases_per_epoch = 2);
    let (d, batch) = w.ready().await;
    w.release(&w.enclave, &d, &batch, 1).await.unwrap();
    w.restart();
    assert_eq!(
        w.release(&w.enclave, &d, &batch, 2).await.unwrap_err(),
        ReleaseRefusal::HeaderPinned
    );
    w.release(&w.enclave, &d, &batch, 1).await.unwrap();
    w.restart();
    assert_eq!(
        w.release(&w.enclave, &d, &batch, 1).await.unwrap_err(),
        ReleaseRefusal::TooManyReleases
    );
}

#[tokio::test]
async fn provider_disagreement_is_not_final() {
    let w = World::new();
    let (d, batch) = w.ready().await;
    w.chain.backend.disagree(true);
    assert_eq!(
        w.challenge(&w.enclave, E).await.unwrap_err(),
        ReleaseRefusal::NotFinal
    );
    w.chain.backend.disagree(false);
    let nonce = w.challenge(&w.enclave, E).await.unwrap();
    w.chain.backend.disagree(true);
    let req = w.request(&w.enclave, &d, &batch, nonce, 1);
    assert_eq!(
        w.member.release(w.enclave.id(), req).await.unwrap_err(),
        ReleaseRefusal::NotFinal
    );
    // The nonce is still unused: decide never ran on a disputed read.
    w.chain.backend.disagree(false);
    let req = w.request(&w.enclave, &d, &batch, nonce, 1);
    w.member.release(w.enclave.id(), req).await.unwrap();
}

#[tokio::test]
async fn a_challenge_flood_stays_bounded() {
    const FLOOD: usize = 100_000;
    let w = World::build(Duration::from_secs(2), |c| {
        c.max_nonces_per_epoch_executor = 16;
        c.max_outstanding_nonces = 20;
        c.per_caller_rps = 1_000_000;
        c.per_caller_burst = 1_000_000;
    });
    w.ready().await;
    let mut issued = 0usize;
    let mut refusals = std::collections::BTreeMap::<u8, usize>::new();
    for i in 0..FLOOD {
        let result = match i % 4 {
            0 => w.challenge(&w.enclave, E).await,
            1 => w.challenge(&w.other, E).await,
            _ => {
                // A fresh key every time, as an attacker would.
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                let k = timescales_core::crypto::Keypair::from_seed(seed);
                let id = timescales_core::ExecutorId(k.public());
                w.member
                    .challenge(
                        id,
                        ChallengeRequest {
                            market: market_address(),
                            epoch: EpochId(E),
                            executor: id,
                        },
                    )
                    .await
                    .map(|c| c.nonce)
            }
        };
        match result {
            Ok(_) => issued += 1,
            Err(code) => *refusals.entry(code as u8).or_default() += 1,
        }
        assert!(w.member.outstanding_nonces() <= 20);
        assert!(w.member.tracked_callers() <= 4096);
    }
    // 16 for the first executor, the remaining 4 of the overall budget
    // for the second. Everything else refused.
    assert_eq!(issued, 20);
    assert_eq!(w.member.outstanding_nonces(), 20);
    assert_eq!(
        refusals.values().sum::<usize>(),
        FLOOD - 20,
        "refusals: {refusals:?}"
    );
    assert!(refusals.contains_key(&(ReleaseRefusal::RateLimited as u8)));
    assert!(refusals.contains_key(&(ReleaseRefusal::NotRegistered as u8)));
    assert_eq!(
        w.member.metrics().challenges.get(),
        u64::try_from(FLOOD).unwrap()
    );
}

#[tokio::test]
async fn member_sqlite_and_its_backup_hold_no_share_material() {
    let w = World::new();
    let (d, batch) = w.ready().await;
    w.release(&w.enclave, &d, &batch, 1).await.unwrap();
    let dir = w.dir.path().to_path_buf();
    let scalar = d.shares[0].value.to_bytes();
    drop(w.member);

    let member = Store::open(
        &dir.join("data/member.sqlite"),
        Schema::Member,
        StoreOptions::default(),
    )
    .unwrap();
    let backup = dir.join("backup/member.sqlite");
    std::fs::create_dir_all(backup.parent().unwrap()).unwrap();
    let report = member.backup_to(backup.clone(), &[]).await.unwrap();
    assert!(report.integrity_ok);
    let shares = Store::open(
        &dir.join("shares/shares.sqlite"),
        Schema::MemberShares,
        StoreOptions::default(),
    )
    .unwrap();
    assert!(
        shares
            .backup_to(dir.join("backup/shares.sqlite"), &[])
            .await
            .is_err()
    );
    drop((member, shares));

    // Neither the plaintext share nor its at-rest ciphertext is anywhere
    // but shares.sqlite, and the plaintext is nowhere at all.
    assert!(files_containing(&dir, &scalar).is_empty());
    let at_rest = RatchetSealer::load(&dir.join("kek.keys")).unwrap();
    let repo = member_repo(&dir, &Arc::new(at_rest));
    let sealed = repo.share(market_address(), E).await.unwrap().unwrap();
    drop(repo);
    let holders = files_containing(&dir, &sealed);
    assert!(!holders.is_empty());
    for path in holders {
        assert!(path.starts_with(dir.join("shares")), "{}", path.display());
    }
}

#[tokio::test]
async fn pruning_destroys_terminal_shares_and_truncates_the_wal() {
    let w = World::new();
    let (d, _) = w.ready().await;
    let next = deal(&w.committee, E + 1);
    w.deliver(&next).await.unwrap();
    w.challenge(&w.enclave, E).await.unwrap();
    let nonces_before = w.member.outstanding_nonces();
    let dir = w.dir.path().to_path_buf();
    let repo = member_repo(&dir, &at_rest(&dir));
    let sealed = repo.share(market_address(), E).await.unwrap().unwrap();

    w.chain.update_market(|m| m.last_settled = E);
    w.member.prune().await.unwrap();

    assert!(repo.share(market_address(), E).await.unwrap().is_none());
    assert!(
        repo.announcement(market_address(), E)
            .await
            .unwrap()
            .is_none()
    );
    assert!(repo.share(market_address(), E + 1).await.unwrap().is_some());
    assert!(w.member.outstanding_nonces() < nonces_before);
    assert_eq!(w.member.metrics().shares_held.get(), 1);
    let wal = dir.join("shares/shares.sqlite-wal");
    assert_eq!(std::fs::metadata(&wal).map_or(0, |m| m.len()), 0);
    assert!(files_containing(&dir.join("shares"), &sealed).is_empty());
    assert!(files_containing(&dir, &d.shares[0].value.to_bytes()).is_empty());
    // A destroyed epoch is never accepted again.
    assert!(w.deliver(&d).await.is_err());
}

#[tokio::test]
async fn the_at_rest_key_ratchets_and_erases_generations_nothing_needs() {
    let w = World::with(|c| c.kek_ratchet_epochs = 2);
    let (d, _) = w.ready().await;
    let dir = w.dir.path().to_path_buf();
    let generations = || {
        std::fs::read_to_string(dir.join("kek.keys"))
            .unwrap()
            .lines()
            .skip(1)
            .count()
    };
    assert_eq!(generations(), 1);
    // The first prune only notes where the ratchet stands.
    w.member.prune().await.unwrap();
    assert_eq!(w.member.metrics().kek_generation.get(), 0);
    // Two more settled epochs: a new generation. The old one stays while
    // the share sealed under it lives.
    w.chain.update_market(|m| m.last_settled = E + 1);
    let late = deal(&w.committee, E + 2);
    w.deliver(&late).await.unwrap();
    w.member.prune().await.unwrap();
    assert_eq!(w.member.metrics().kek_generation.get(), 1);
    assert_eq!(generations(), 2);
    drop(d);
    // E + 2's share is sealed under generation 0 still. Once it is gone,
    // generation 0 is erased.
    w.chain.update_market(|m| m.last_settled = E + 2);
    w.member.prune().await.unwrap();
    assert_eq!(generations(), 1);
}

#[tokio::test]
async fn rekey_advances_the_generation_offline() {
    let w = World::new();
    let (_d, _) = w.ready().await;
    let cfg = w.cfg.clone();
    drop(w.member);
    let generation = timescales_krc::service::rekey(&cfg).await.unwrap();
    assert_eq!(generation, 1);
    // The share sealed under generation 0 keeps that generation alive.
    let text = std::fs::read_to_string(cfg.kek_file).unwrap();
    assert_eq!(text.lines().skip(1).count(), 2);
    let repo: MemberRepo = member_repo(w.dir.path(), &at_rest(w.dir.path()));
    assert!(repo.share(market_address(), E).await.unwrap().is_some());
}
