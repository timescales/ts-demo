//! The enclave service end to end: real HTTP between the node (the
//! test), enclaves on the simulated platform and key-release members, over
//! the settlement program in LiteSVM.

#![cfg(all(feature = "sim-platform", feature = "litesvm", feature = "test-util"))]
#![allow(clippy::unwrap_used)]

use super::common;

use std::time::{Duration, Instant};

use common::{EpochSpec, Options, OrderSpec, World};
use timescales_auction::receipts::{
    BackendKind, ExecutionOutcome, ExecutionReceipt, cosign_digest,
};
use timescales_chain::program::BatchStatus;
use timescales_chain::{MarketChain, PostOutcome, RpcMethod};
use timescales_core::crypto::{Keypair, Signature, verify_digest};
use timescales_core::{
    Decode, EpochId, ExecutorId, Hash32, MarketId, PROTOCOL_VERSION, QuoteAtoms, Role, Side,
    TraderId,
};
use timescales_service::wire::{EnclaveRefusal, ExecuteReady};

fn assert_refused(r: Result<impl std::fmt::Debug, common::Refusal>, code: EnclaveRefusal) -> u16 {
    match r {
        Err((status, body)) => {
            assert_eq!(body.code, code, "{body:?}");
            status
        }
        Ok(v) => panic!("expected {code:?}, got {v:?}"),
    }
}

fn cosig(r: &ExecuteReady) -> (ExecutorId, Signature) {
    (r.executor, r.cosign)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_about_fills_leaves_before_publish_and_the_quorum_posts() {
    let w = World::new(Options {
        enclaves: 2,
        quorum: 2,
        ..Options::default()
    })
    .await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let (a, b) = (&w.enclaves[0], &w.enclaves[1]);

    // ExecuteReady is exactly digests, a co-signature and the indices that
    // failed authentication: its encoding has room for nothing else.
    let raw = a.execute_raw(&e.req).await.unwrap();
    let ready = ExecuteReady::decode_exact(&raw).unwrap();
    assert_eq!(
        raw.len(),
        ExecuteReady::MIN_ENCODED_LEN + 4 * ready.unauthenticated.len()
    );
    assert!(
        ready.unauthenticated.is_empty(),
        "{:?}",
        ready.unauthenticated
    );
    assert_eq!(ready.executor, a.executor());
    assert_eq!(ready.header_digest, e.header_digest());
    let digest = cosign_digest(
        &w.market,
        EpochId(1),
        &ready.header_digest,
        &ready.outcome_digest,
    );
    verify_digest(&a.executor().0, &digest, &ready.cosign).unwrap();
    // Nothing is on chain yet.
    let batch = w.batch(1).await.unwrap();
    assert_eq!(batch.status, BatchStatus::BeaconRevealed);
    assert_eq!(batch.receipt, Hash32::ZERO);

    let ready_b = b.execute(&e.req).await.unwrap();
    assert_eq!(ready_b.outcome_digest, ready.outcome_digest);

    let posted = a
        .publish(&e.publish(w.market, vec![cosig(&ready_b)]))
        .await
        .unwrap();
    // There were fills to hide.
    assert!(posted.receipt.outcome.fill_count > 0);
    assert!(!posted.artifacts.fills.is_empty());
    posted
        .artifacts
        .check_against(&posted.receipt.outcome)
        .unwrap();
    assert_eq!(posted.receipt.outcome.digest(), ready.outcome_digest);
    assert_ne!(
        posted.posted.signature, [0; 64],
        "the post's signature is known"
    );
    assert_eq!(posted.cosigned.len(), 1);

    let batch = w.batch(1).await.unwrap();
    let m = w.market_account().await;
    assert_eq!(batch.status, BatchStatus::ReceiptPosted);
    assert_eq!(batch.receipt, posted.receipt.digest());
    assert!(m.quorum_met(batch.cosign_bitmap));

    // Publishing again returns the same result.
    let again = a
        .publish(&e.publish(w.market, vec![cosig(&ready_b)]))
        .await
        .unwrap();
    assert_eq!(again, posted);
    assert_eq!(a.svc.metrics().posts("posted"), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publish_is_refused_without_quorum_cosignatures() {
    let w = World::new(Options {
        enclaves: 2,
        extra_executors: 1,
        quorum: 2,
        ..Options::default()
    })
    .await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let (a, b) = (&w.enclaves[0], &w.enclaves[1]);
    let ready = a.execute(&e.req).await.unwrap();
    let ready_b = b.execute(&e.req).await.unwrap();
    let publish = |cosigs| e.publish(w.market, cosigs);

    // None, its own, an unregistered key's, a duplicate, and a registered
    // executor's signature over another outcome.
    let status = assert_refused(
        a.publish(&publish(vec![])).await,
        EnclaveRefusal::QuorumInvalid,
    );
    assert_eq!(status, 422);
    assert_refused(
        a.publish(&publish(vec![cosig(&ready)])).await,
        EnclaveRefusal::QuorumInvalid,
    );
    let stranger = Keypair::from_seed([0x77; 32]);
    let digest = cosign_digest(
        &w.market,
        EpochId(1),
        &ready.header_digest,
        &ready.outcome_digest,
    );
    assert_refused(
        a.publish(&publish(vec![(
            ExecutorId(stranger.public()),
            stranger.sign_digest(&digest),
        )]))
        .await,
        EnclaveRefusal::QuorumInvalid,
    );
    assert_refused(
        a.publish(&publish(vec![cosig(&ready_b), cosig(&ready_b)]))
            .await,
        EnclaveRefusal::QuorumInvalid,
    );
    let mismatch = w.extra_cosign(0, 1, &ready.header_digest, &Hash32([0xee; 32]));
    assert_refused(
        a.publish(&publish(vec![mismatch])).await,
        EnclaveRefusal::QuorumInvalid,
    );
    // No completed execution for another header.
    let mut unknown = publish(vec![cosig(&ready_b)]);
    unknown.header_digest = Hash32([3; 32]);
    let status = assert_refused(a.publish(&unknown).await, EnclaveRefusal::NotExecuted);
    assert_eq!(status, 404);

    // Nothing was posted by any of these.
    let batch = w.batch(1).await.unwrap();
    assert_eq!(batch.status, BatchStatus::BeaconRevealed);
    assert_eq!(a.svc.metrics().posts("quorum_invalid"), 5);

    // The registered executor's co-signature over this outcome is enough.
    let extra = w.extra_cosign(0, 1, &ready.header_digest, &ready.outcome_digest);
    let posted = a.publish(&publish(vec![extra])).await.unwrap();
    assert_eq!(w.batch(1).await.unwrap().receipt, posted.receipt.digest());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_executes_share_one_krc_round() {
    let w = World::new(Options::default()).await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let a = &w.enclaves[0];
    let (r1, r2) = tokio::join!(a.execute(&e.req), a.execute(&e.req));
    let (r1, r2) = (r1.unwrap(), r2.unwrap());
    assert_eq!(r1, r2);
    for m in &w.members {
        assert_eq!(m.challenges(), 1, "member {}", m.state.index);
        assert_eq!(m.releases(), 1, "member {}", m.state.index);
    }
    // A later retry is answered from the result cache.
    assert_eq!(a.execute(&e.req).await.unwrap(), r1);
    assert_eq!(w.challenges(), 3);
    assert_eq!(w.releases(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_shares_are_dropped() {
    let w = World::new(Options {
        bad_member: Some(1),
        ..Options::default()
    })
    .await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let a = &w.enclaves[0];
    let ready = a.execute(&e.req).await.unwrap();
    assert_eq!(a.svc.metrics().share_rejects.get(), 1);
    // The two good shares reconstruct the announced key: the batch runs and
    // its receipt posts.
    let posted = a.publish(&e.publish(w.market, vec![])).await.unwrap();
    assert_eq!(posted.receipt.outcome.digest(), ready.outcome_digest);
    assert!(posted.receipt.outcome.fill_count > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_committee_is_a_binding_mismatch() {
    let w = World::new(Options::default()).await;
    let e = w
        .epoch(
            1,
            EpochSpec {
                forged_committee: true,
                ..EpochSpec::default()
            },
        )
        .await;
    let a = &w.enclaves[0];
    let status = assert_refused(a.execute(&e.req).await, EnclaveRefusal::BindingMismatch);
    assert_eq!(status, 409);
    assert_eq!(w.challenges(), 0, "no member was asked for a key");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_binding_to_another_price_commitment_is_a_binding_mismatch() {
    let w = World::new(Options::default()).await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let a = &w.enclaves[0];
    let mut req = e.req.clone();
    req.price_commitment = Hash32([0x42; 32]);
    assert_refused(a.execute(&req).await, EnclaveRefusal::BindingMismatch);
    assert_eq!(w.challenges(), 0);
    // The honest request runs.
    a.execute(&e.req).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deflated_or_inflated_sheet_is_refused_before_any_challenge() {
    let w = World::new(Options::default()).await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let a = &w.enclaves[0];
    let (t0, t1) = (w.traders[0].id(), w.traders[1].id());

    let deflated = e.with_sheet(|s| {
        let mut b = s.get(&t0);
        b.quote = QuoteAtoms(b.quote.0 - 1);
        s.set(t0, b);
    });
    let inflated = e.with_sheet(|s| {
        let mut b = s.get(&t1);
        b.base.0 += 1;
        s.set(t1, b);
    });
    let missing = e.with_sheet(|s| {
        *s = s
            .iter()
            .filter(|(t, _)| **t != t0)
            .map(|(t, b)| (*t, *b))
            .collect();
    });
    let stranger = e.with_sheet(|s| {
        let mut b = s.get(&t0);
        b.quote = QuoteAtoms(5);
        s.set(TraderId([0x99; 32]), b);
    });
    for req in [&deflated, &inflated, &missing, &stranger] {
        match a.execute(req).await {
            Err((409, body)) => {
                assert_eq!(body.code, EnclaveRefusal::BalanceMismatch);
                assert_eq!(body.detail, "1 trader(s)");
            }
            other => panic!("expected a balance mismatch, got {other:?}"),
        }
    }
    assert_eq!(w.challenges(), 0, "no key was requested");
    assert_eq!(a.svc.metrics().balance_check_failures.get(), 4);
    // The honest sheet passes.
    a.execute(&e.req).await.unwrap();
    assert_eq!(w.challenges(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_phished_intent_through_another_wallets_session_is_unauthenticated() {
    let w = World::new(Options::default()).await;
    let mut orders = common::crossing_orders();
    // Trader 0 signed this intent (for example on a phishing site), but it
    // arrives through trader 1's session, under trader 1's grant.
    orders.push(OrderSpec {
        via: Some(1),
        ..OrderSpec::new(0, Side::Buy, Role::Taker, 116, 50)
    });
    // And one under a grant for another domain.
    orders.push(OrderSpec::new(1, Side::Sell, Role::Taker, 84, 50));
    let phished = orders.len() - 2;
    let foreign = orders.len() - 1;
    let e = w
        .epoch(
            1,
            EpochSpec {
                orders,
                foreign_domain: vec![foreign],
                ..EpochSpec::default()
            },
        )
        .await;
    let a = &w.enclaves[0];
    let ready = a.execute(&e.req).await.unwrap();
    let phished = u32::try_from(phished).unwrap();
    let foreign = u32::try_from(foreign).unwrap();
    assert_eq!(ready.unauthenticated, vec![phished, foreign]);
    // Only the foreign-domain grant failed provenance. The phished envelope
    // passed it for the wrong wallet and the executor refused its intent.
    assert_eq!(a.svc.metrics().provenance_rejects.get(), 1);

    let posted = a.publish(&e.publish(w.market, vec![])).await.unwrap();
    let skipped = [
        e.req.batch.envelopes[phished as usize].commitment,
        e.req.batch.envelopes[foreign as usize].commitment,
    ];
    assert!(posted.receipt.outcome.fill_count > 0);
    assert!(
        posted
            .artifacts
            .fills
            .iter()
            .all(|f| !skipped.contains(&f.commitment))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_post_deadline_re_observes_a_receipt_that_landed() {
    let w = World::new(Options {
        post_deadline_ms: 2_000,
        ..Options::default()
    })
    .await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let a = &w.enclaves[0];
    a.execute(&e.req).await.unwrap();
    // The post reaches the cluster, but its confirmation never reaches the
    // enclave before the deadline.
    a.fault_both(|p| p.delay(RpcMethod::SignatureStatuses, Some(Duration::from_secs(5))));
    let started = Instant::now();
    let posted = a.publish(&e.publish(w.market, vec![])).await.unwrap();
    assert!(started.elapsed() >= Duration::from_millis(2_000));
    a.fault_both(|p| p.clear());
    let batch = w.batch(1).await.unwrap();
    assert_eq!(batch.receipt, posted.receipt.digest());
    assert_eq!(posted.posted.slot, batch.receipt_slot);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_post_that_did_not_land_fails_and_keeps_the_result() {
    let w = World::new(Options {
        post_deadline_ms: 1_500,
        ..Options::default()
    })
    .await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let a = &w.enclaves[0];
    let ready = a.execute(&e.req).await.unwrap();
    let challenges = w.challenges();
    a.fault_both(|p| p.black_hole_sends(1_000));
    let status = assert_refused(
        a.publish(&e.publish(w.market, vec![])).await,
        EnclaveRefusal::PostFailed,
    );
    assert_eq!(status, 503);
    assert_eq!(
        w.batch(1).await.unwrap().status,
        BatchStatus::BeaconRevealed
    );
    a.fault_both(|p| p.clear());
    // The result was kept: the next publish posts without a KRC round.
    let posted = a.publish(&e.publish(w.market, vec![])).await.unwrap();
    assert_eq!(posted.receipt.outcome.digest(), ready.outcome_digest);
    assert_eq!(w.challenges(), challenges);
    assert_eq!(w.batch(1).await.unwrap().receipt, posted.receipt.digest());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_outcome_recovery_path_waits_for_the_quorum_on_chain() {
    let w = World::new(Options {
        enclaves: 3,
        extra_executors: 1,
        quorum: 3,
        ..Options::default()
    })
    .await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let (a, b, c) = (&w.enclaves[0], &w.enclaves[1], &w.enclaves[2]);
    let ra = a.execute(&e.req).await.unwrap();
    let rb = b.execute(&e.req).await.unwrap();
    let rc = c.execute(&e.req).await.unwrap();
    assert_eq!(ra.outcome_digest, rb.outcome_digest);
    assert_eq!(ra.outcome_digest, rc.outcome_digest);
    let x = w.extra_cosign(0, 1, &ra.header_digest, &ra.outcome_digest);
    let posted_a = a
        .publish(&e.publish(w.market, vec![cosig(&rb), x]))
        .await
        .unwrap();
    // The extra executor is removed: its weight goes with it and the quorum
    // is no longer met on chain.
    w.remove_executor(&w.extra[0].public()).await;
    let m = w.market_account().await;
    assert!(!m.quorum_met(w.batch(1).await.unwrap().cosign_bitmap));

    // B's bit is set, but the quorum is not on chain: nothing yet.
    let status = assert_refused(
        b.publish(&e.publish(w.market, vec![])).await,
        EnclaveRefusal::QuorumPending,
    );
    assert_eq!(status, 409);
    // C co-signs itself and, with the quorum on chain, answers with its own
    // receipt and the same artifacts.
    let posted_c = c.publish(&e.publish(w.market, vec![])).await.unwrap();
    assert_eq!(posted_c.receipt.executor, c.executor());
    assert_eq!(posted_c.receipt.outcome, posted_a.receipt.outcome);
    assert_eq!(posted_c.artifacts, posted_a.artifacts);
    assert!(
        w.market_account()
            .await
            .quorum_met(w.batch(1).await.unwrap().cosign_bitmap)
    );
    let posted_b = b.publish(&e.publish(w.market, vec![])).await.unwrap();
    assert_eq!(posted_b.receipt.executor, b.executor());
    assert_eq!(posted_b.artifacts, posted_a.artifacts);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_posted_outcome_is_an_outcome_mismatch_with_the_receipt() {
    let w = World::new(Options {
        extra_executors: 1,
        ..Options::default()
    })
    .await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let a = &w.enclaves[0];
    let ready = a.execute(&e.req).await.unwrap();

    // A registered executor posts another outcome for the same header.
    let x = &w.extra[0];
    let outcome = ExecutionOutcome {
        market: MarketId(w.market_id),
        epoch: EpochId(1),
        header_digest: e.header_digest(),
        clearing: vec![],
        fill_count: 0,
        fills_root: Hash32([0xf1; 32]),
        cancelled_root: Hash32([0xca; 32]),
        next_state_root: Hash32([0x5e; 32]),
        settlement_count: 0,
        settlement_root: Hash32::ZERO,
        fees: QuoteAtoms(0),
    };
    let id = ExecutorId(x.public());
    let digest = ExecutionReceipt::signing_digest(
        &outcome,
        BackendKind::Tee,
        &id,
        &Hash32::ZERO,
        &Hash32::ZERO,
        &Hash32::ZERO,
    );
    let other = ExecutionReceipt {
        version: PROTOCOL_VERSION,
        outcome,
        backend: BackendKind::Tee,
        executor: id,
        attestation: Hash32::ZERO,
        proof: Hash32::ZERO,
        trace: Hash32::ZERO,
        signature: x.sign_digest(&digest),
    };
    let header: [u8; 283] = timescales_core::Encode::to_bytes(&e.header)
        .try_into()
        .unwrap();
    let out = w
        .chain
        .ensure_posted(
            1,
            header,
            timescales_core::Encode::to_bytes(&other),
            w.cranker.clone(),
        )
        .await
        .unwrap();
    assert!(matches!(out, PostOutcome::Posted { .. }), "{out:?}");

    let (status, body) = a.publish(&e.publish(w.market, vec![])).await.unwrap_err();
    assert_eq!(status, 409);
    assert_eq!(body.code, EnclaveRefusal::OutcomeMismatch);
    let evidence = body.receipt.unwrap();
    evidence.verify_signature().unwrap();
    assert_eq!(evidence.executor, a.executor());
    assert_eq!(evidence.outcome.header_digest, e.header_digest());
    assert_eq!(evidence.outcome.digest(), ready.outcome_digest);
    assert_ne!(evidence.outcome.digest(), other.outcome.digest());
    assert_eq!(a.svc.metrics().posts("outcome_mismatch"), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reveal_backstop_fires() {
    let w = World::new(Options {
        reveal_backstop_slots: 4,
        ..Options::default()
    })
    .await;
    let e = w
        .epoch(
            1,
            EpochSpec {
                reveal: false,
                ..EpochSpec::default()
            },
        )
        .await;
    let a = &w.enclaves[0];
    // Not due yet: the beacon inputs exist only after commit_slot + 2d.
    a.svc.backstop_pass().await;
    assert_eq!(w.batch(1).await.unwrap().status, BatchStatus::Committed);
    assert_eq!(a.svc.metrics().reveal_backstop.get(), 0);

    let due = e.commit_slot + 2 * u64::from(common::BEACON_DELAY) + 4;
    while w.svm.current_slot() < due + 2 {
        tokio::time::sleep(common::SLOT).await;
    }
    a.svc.backstop_pass().await;
    let batch = w.batch(1).await.unwrap();
    assert_eq!(batch.status, BatchStatus::BeaconRevealed);
    assert_eq!(a.svc.metrics().reveal_backstop.get(), 1);
    assert!(
        !a.log
            .landed(&w.market, 1, timescales_chain::TxOp::Reveal)
            .is_empty()
    );
    // Once revealed, further passes do nothing.
    a.svc.backstop_pass().await;
    assert_eq!(a.svc.metrics().reveal_backstop.get(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_identity_binds_its_keys_to_the_market_and_nonce() {
    use base64::Engine as _;
    use timescales_executor::attestation::simulated::SimulatedQuoteVerifier;
    use timescales_executor::attestation::{Evidence, QuoteVerifier, registration_report_data};

    let w = World::new(Options::default()).await;
    let a = &w.enclaves[0];
    let market = bs58::encode(w.market).into_string();
    let nonce = [0x11u8; 32];
    let path = format!(
        "/enclave/v1/identity?market={market}&nonce={}",
        hex::encode(nonce)
    );
    let (status, body) = common::http_get(&a.url, &path).await;
    assert_eq!(status, 200, "{body}");
    let id: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(id["market"], market.as_str());
    assert_eq!(id["platform"], "simulated");
    assert_eq!(id["executor"], bs58::encode(a.executor().0).into_string());
    assert_eq!(
        id["fee_payer"],
        bs58::encode(a.svc.fee_payer()).into_string()
    );
    assert_eq!(id["seal_key"], hex::encode(a.svc.seal_key()));
    let evidence = base64::engine::general_purpose::STANDARD
        .decode(id["evidence_b64"].as_str().unwrap())
        .unwrap();
    let evidence = Evidence::decode_exact(&evidence).unwrap();
    let vendor = timescales_executor::attestation::simulated::SimulatedVendor::from_seed(
        common::VENDOR_SEED,
        0,
    );
    let report = SimulatedQuoteVerifier::from_root(vendor.root_key(), 0)
        .verify(&evidence)
        .unwrap();
    assert_eq!(
        report.report_data,
        registration_report_data(
            &a.svc.seal_key(),
            &a.executor(),
            &common::program(),
            &w.market,
            &nonce
        )
    );
    assert_eq!(
        report.measurement,
        timescales_executor::tee::program_measurement()
    );
    assert_eq!(id["measurement"], report.measurement.0.to_hex());
    assert!(!report.debug);

    // A market it does not serve, a malformed nonce.
    let (status, _) = common::http_get(
        &a.url,
        &format!(
            "/enclave/v1/identity?market={}&nonce={}",
            bs58::encode([9u8; 32]).into_string(),
            hex::encode(nonce)
        ),
    )
    .await;
    assert_eq!(status, 404);
    let (status, _) = common::http_get(
        &a.url,
        &format!("/enclave/v1/identity?market={market}&nonce=00"),
    )
    .await;
    assert_eq!(status, 400);
    // The route is limited per client address (burst 5 in this world).
    let mut limited = false;
    for _ in 0..8 {
        if common::http_get(&a.url, &path).await.0 == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "eight requests in a burst of five were all served");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_settlement_backstop_cranks_a_stalled_posted_batch() {
    let w = World::new(Options {
        settle_backstop_after_ms: 300,
        ..Options::default()
    })
    .await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let a = &w.enclaves[0];
    a.execute(&e.req).await.unwrap();
    let posted = a.publish(&e.publish(w.market, vec![])).await.unwrap();
    assert!(!posted.artifacts.settlement.deltas.is_empty());
    // Nobody settles: the first pass records the progress, a pass after the
    // backstop delay cranks.
    a.svc.backstop_pass().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    a.svc.backstop_pass().await;
    let settled = w
        .chain
        .wait_batch(
            1,
            timescales_chain::BatchPredicate::Terminal,
            timescales_chain::Level::Confirmed,
            tokio::time::Instant::now() + Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(settled.status, BatchStatus::Settled);
    let m = w.market_account().await;
    assert_eq!(m.last_settled, 1);
    assert_eq!(m.state_root, posted.receipt.outcome.next_state_root);
    // The enclave's sender records the close once it sees it confirmed,
    // which may be just after the test does.
    let closed_by_enclave = async {
        while a
            .log
            .landed(&w.market, 1, timescales_chain::TxOp::Close)
            .is_empty()
        {
            tokio::time::sleep(common::SLOT).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(30), closed_by_enclave)
        .await
        .expect("the enclave's backstop sent the CloseBatch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_epoch_dealt_under_the_previous_committee_still_executes() {
    let w = World::new(Options {
        rotate_committee: true,
        ..Options::default()
    })
    .await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let a = &w.enclaves[0];
    let ready = a.execute(&e.req).await.unwrap();
    let posted = a.publish(&e.publish(w.market, vec![])).await.unwrap();
    assert_eq!(posted.receipt.outcome.digest(), ready.outcome_digest);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_configured_node_keys_may_call_execute_and_publish() {
    use std::sync::Arc;

    use timescales_core::Encode;
    use timescales_service::wire::MessageKind;
    use timescales_service::{ClientError, SignedClient};

    let w = World::new(Options::default()).await;
    let e = w.epoch(1, EpochSpec::default()).await;
    let a = &w.enclaves[0];
    let stranger = SignedClient::new(
        Arc::new(Keypair::from_seed([0x51; 32])),
        a.executor().0,
        None,
        Duration::from_secs(30),
    )
    .unwrap();
    for (path, kind, body) in [
        ("execute", MessageKind::ExecuteRequest, e.req.to_bytes()),
        (
            "publish",
            MessageKind::PublishRequest,
            e.publish(w.market, vec![]).to_bytes(),
        ),
    ] {
        match stranger
            .call(&format!("{}/enclave/v1/{path}", a.url), kind, body)
            .await
        {
            Err(ClientError::Status(403)) => {}
            other => panic!("{path}: expected 403, got {other:?}"),
        }
    }
    assert_eq!(w.challenges(), 0);
    // A malformed body from the node is a signed BadRequest.
    let env = a
        .client
        .call(
            &format!("{}/enclave/v1/execute", a.url),
            MessageKind::ExecuteRequest,
            vec![1, 2, 3],
        )
        .await;
    match env {
        Err(ClientError::Refused {
            status: 400,
            envelope,
        }) => {
            let body =
                timescales_service::wire::ErrorResponse::decode_exact(&envelope.body).unwrap();
            assert_eq!(body.code, EnclaveRefusal::BadRequest);
        }
        other => panic!("expected a signed 400, got {other:?}"),
    }
}
