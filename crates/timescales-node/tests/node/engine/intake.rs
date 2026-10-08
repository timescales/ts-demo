//! Intake: promises, deduplication with the original promise,
//! collateral-scaled quotas, fair share, the park window and relay-signed
//! refusals. Parked envelopes injected when their epoch opens. Signatures
//! verified by intake whatever the caller claims.

use std::time::Duration;

use timescales_core::intent::{PrivateIntent, SealedEnvelope};
use timescales_core::{
    CommitmentScheme, Decode, Encode, EpochId, Lots, MarketId, Order, OrderKind, Role, Side, Tick,
    TraderId,
};
use timescales_node::{NodeApi, SubmitError, VerifiedSubmission};
use timescales_service::api::{ErrorCode, SubmitStatus};
use timescales_service::relay::InclusionPromiseV2;
use timescales_service::store::node::Phase;
use timescales_service::wire::RelayRefusal;

use crate::support::world::{Options, World};

/// The refusal carried by `e`, verified as the relay's.
fn refusal(w: &World, e: &SubmitError) -> RelayRefusal {
    let r =
        RelayRefusal::decode_exact(e.refusal.as_deref().expect("a relay-signed refusal")).unwrap();
    r.verify().unwrap();
    assert_eq!(r.market, w.market);
    let b64 = e.details["refusal_b64"].as_str().unwrap();
    assert!(!b64.is_empty());
    r
}

#[tokio::test(start_paused = true)]
async fn duplicates_quotas_and_the_park_window() {
    let mut w = World::new(Options {
        // Quota = min(16, available value / 1000): 3 envelopes per epoch.
        min_value_per_envelope: 1_000,
        ..Options::default()
    })
    .await;
    w.start_node().await.unwrap();
    w.deal(1..=3).await;
    let t = w.trader(0, 3_000).await;
    let s = t.session.unwrap();
    let e = w.fresh_epoch().await;
    // Bundles through e + 2 only (the park window is 4).
    w.deal(e..=e + 2).await;
    let mid = MarketId(w.market_id);
    let pk = w.epoch_pk(e);
    let (a, _) = t.order(&w.relay_cfg, mid, e, &pk, Side::Buy, Role::Taker, 100, 1);

    // The same bytes again return the original promise.
    let first = w.node().submit(w.market, vec![a.clone()], s).await[0]
        .clone()
        .unwrap();
    let again = w.node().submit(w.market, vec![a.clone()], s).await[0]
        .clone()
        .unwrap();
    assert!(!first.duplicate && again.duplicate);
    assert_eq!(first.promise_b64, again.promise_b64);
    let p = InclusionPromiseV2::decode_exact(&first.promise_b64.0).unwrap();
    assert!(p.verify());
    assert_eq!(p.envelope_digest.0, first.envelope_digest.0);

    // Other bytes under the same commitment: DUPLICATE_COMMITMENT with the
    // original promise.
    let env = &a.inner.submission.envelope;
    let order = Order {
        market: mid,
        trader: TraderId(t.id()),
        nonce: 999,
        side: Side::Buy,
        role: Role::Taker,
        kind: OrderKind::Limit,
        limit: Tick(100),
        quantity: Lots(1),
        valid_from: EpochId(e),
        expires_at: EpochId(e),
    };
    let mut rng = rand::thread_rng();
    let (intent, _) =
        PrivateIntent::place(&mut rng, &t.key, CommitmentScheme::Sha256, order).unwrap();
    let resealed =
        SealedEnvelope::seal(&mut rng, mid, EpochId(e), &pk, env.commitment, &intent).unwrap();
    let other = t.submission(&w.relay_cfg, resealed);
    let r = w.node().submit(w.market, vec![other], s).await;
    let err = r[0].clone().unwrap_err();
    assert_eq!(err.code, ErrorCode::DuplicateCommitment);
    assert_eq!(
        err.details["promise_b64"].as_str().unwrap(),
        serde_json::to_value(&first.promise_b64)
            .unwrap()
            .as_str()
            .unwrap()
    );

    // A batched request: two more fit the quota of three, the fourth is
    // refused with a relay-signed refusal.
    let (b, _) = t.order(&w.relay_cfg, mid, e, &pk, Side::Buy, Role::Taker, 99, 1);
    let (c, _) = t.order(&w.relay_cfg, mid, e, &pk, Side::Buy, Role::Taker, 98, 1);
    let (d, _) = t.order(&w.relay_cfg, mid, e, &pk, Side::Buy, Role::Taker, 97, 1);
    let r = w.node().submit(w.market, vec![b, c, d], s).await;
    assert!(r[0].is_ok() && r[1].is_ok(), "{r:?}");
    let err = r[2].clone().unwrap_err();
    assert_eq!(err.code, ErrorCode::QuotaExceeded);
    let rf = refusal(&w, &err);
    assert_eq!(rf.code, RelayRefusal::QUOTA_EXCEEDED);
    assert_eq!(rf.epoch.0, e);

    // The park window.
    let pk1 = w.epoch_pk(e + 1);
    let (parked, parked_c) = t.order(
        &w.relay_cfg,
        mid,
        e + 1,
        &pk1,
        Side::Buy,
        Role::Taker,
        100,
        1,
    );
    let r = w.node().submit(w.market, vec![parked], s).await;
    let ok = r[0].clone().unwrap();
    assert_eq!(ok.status, SubmitStatus::Parked);
    let pk_far = w.epoch_pk(e + 3);
    let (nokey, _) = t.order(
        &w.relay_cfg,
        mid,
        e + 3,
        &pk_far,
        Side::Buy,
        Role::Taker,
        100,
        1,
    );
    let r = w.node().submit(w.market, vec![nokey], s).await;
    assert_eq!(
        r[0].clone().unwrap_err().code,
        ErrorCode::EpochKeyUnavailable
    );
    let pk_too_far = w.epoch_pk(e + 6);
    let (far, _) = t.order(
        &w.relay_cfg,
        mid,
        e + 6,
        &pk_too_far,
        Side::Buy,
        Role::Taker,
        100,
        1,
    );
    let r = w.node().submit(w.market, vec![far], s).await;
    assert_eq!(r[0].clone().unwrap_err().code, ErrorCode::EpochTooFar);
    let parked_list = w.node().parked(w.market, s).await.unwrap();
    assert_eq!(parked_list.len(), 1);
    assert_eq!(parked_list[0].epoch.0, e + 1);

    // A submission after the cutoff: EPOCH_CLOSED with the next epoch.
    w.to_cutoff().await;
    w.phase(
        e,
        &[
            Phase::Closed,
            Phase::Committing,
            Phase::Committed,
            Phase::Snapshotted,
            Phase::Revealed,
            Phase::Sealed,
            Phase::Executing,
            Phase::Posted,
            Phase::Settled,
        ],
    )
    .await;
    let (late, _) = t.order(&w.relay_cfg, mid, e, &pk, Side::Buy, Role::Taker, 96, 1);
    let r = w.node().submit(w.market, vec![late], s).await;
    let err = r[0].clone().unwrap_err();
    assert_eq!(err.code, ErrorCode::EpochClosed);
    assert_eq!(refusal(&w, &err).code, RelayRefusal::EPOCH_CLOSED);
    assert!(
        err.details["next_epoch"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > e
    );

    // The parked envelope becomes a submission of e + 1 when it opens, with
    // the promise it was given.
    w.phase(
        e + 1,
        &[
            Phase::Open,
            Phase::Closed,
            Phase::Committing,
            Phase::Committed,
        ],
    )
    .await;
    let subs = w.node().store().submissions(w.market, e + 1).await.unwrap();
    let injected = subs
        .iter()
        .find(|row| row.commitment == parked_c)
        .expect("the parked envelope is a submission of its epoch");
    assert_eq!(injected.promise, ok.promise_b64.0);
    assert!(w.node().parked(w.market, s).await.unwrap().is_empty());
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test(start_paused = true)]
async fn fair_share_when_capacity_runs_low() {
    let mut w = World::new(Options {
        max_real: 12,
        min_value_per_envelope: 1_000,
        ..Options::default()
    })
    .await;
    w.start_node().await.unwrap();
    w.deal(1..=3).await;
    let a = w.trader(0, 100_000).await;
    let b = w.trader(0, 100_000).await;
    let c = w.trader(0, 100_000).await;
    let e = w.fresh_epoch().await;
    let mid = MarketId(w.market_id);
    let pk = w.epoch_pk(e);
    let orders = |t: &crate::support::trader::Trader, n: u64| {
        (0..n)
            .map(|i| {
                t.order(&w.relay_cfg, mid, e, &pk, Side::Buy, Role::Taker, 90 + i, 1)
                    .0
            })
            .collect::<Vec<_>>()
    };
    // Ten of twelve slots: not low yet.
    let r = w
        .node()
        .submit(w.market, orders(&a, 10), a.session.unwrap())
        .await;
    assert!(r.iter().all(Result::is_ok), "{r:?}");
    // Fewer than a quarter left: one more each.
    let r = w
        .node()
        .submit(w.market, orders(&a, 2), a.session.unwrap())
        .await;
    assert!(r[0].is_ok());
    let err = r[1].clone().unwrap_err();
    assert_eq!(err.code, ErrorCode::BatchFull);
    assert_eq!(err.details["fair_share"], 1);
    assert_eq!(refusal(&w, &err).code, RelayRefusal::BATCH_FULL);
    let r = w
        .node()
        .submit(w.market, orders(&b, 1), b.session.unwrap())
        .await;
    assert!(r[0].is_ok(), "{r:?}");
    // Full.
    let r = w
        .node()
        .submit(w.market, orders(&c, 1), c.session.unwrap())
        .await;
    let err = r[0].clone().unwrap_err();
    assert_eq!(err.code, ErrorCode::BatchFull);
    assert!(err.details.get("fair_share").is_none());
    assert_eq!(
        w.view().open.unwrap().slots_left,
        timescales_node::market::SlotsLeft::Full
    );
}

#[tokio::test(start_paused = true)]
async fn intake_verifies_every_signature_itself() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    w.deal(1..=3).await;
    let t = w.trader(0, 100_000).await;
    let s = t.session.unwrap();
    let e = w.fresh_epoch().await;
    let mid = MarketId(w.market_id);
    let pk = w.epoch_pk(e);
    let (good, _) = t.order(&w.relay_cfg, mid, e, &pk, Side::Buy, Role::Taker, 100, 1);

    // A forged item: the signature is broken, but the caller claims it
    // verified.
    let mut sub = good.inner.submission.clone();
    sub.signature.0[0] ^= 1;
    let forged = VerifiedSubmission {
        raw: sub.to_bytes(),
        inner: timescales_service::relay::VerifiedSubmission {
            envelope_digest: sub.envelope.digest(),
            submission: sub,
        },
    };
    // Valid bytes, but `inner` claims another submission.
    let (other, _) = t.order(&w.relay_cfg, mid, e, &pk, Side::Buy, Role::Taker, 99, 1);
    let mismatched = VerifiedSubmission {
        raw: good.raw.clone(),
        inner: other.inner.clone(),
    };
    let r = w
        .node()
        .submit(w.market, vec![forged.clone(), mismatched, good.clone()], s)
        .await;
    assert_eq!(r[0].clone().unwrap_err().code, ErrorCode::BadSignature);
    assert_eq!(r[1].clone().unwrap_err().code, ErrorCode::BadRequest);
    assert!(r[2].is_ok(), "{r:?}");
    let stored = w.node().store().submissions(w.market, e).await.unwrap();
    assert_eq!(stored.len(), 1);

    // The helper the API layer builds items with.
    let built = w
        .node()
        .verify_submission(w.market, other.raw.clone())
        .await
        .unwrap();
    assert_eq!(built, other);
    let err = w
        .node()
        .verify_submission(w.market, forged.raw.clone())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadSignature);
    let err = w
        .node()
        .verify_submission(w.market, good.raw[..good.raw.len() - 1].to_vec())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::DecodeFailed);
    assert_eq!(err.details["reason"], "eof");
}
