//! `DealerRepo` over `dealer.sqlite`.

use timescales_core::Hash32;
use timescales_service::store::StoreError;
use timescales_service::store::node::PutOutcome;

use crate::common::{MARKET, OTHER_MARKET, ack, announcement, dealer, outside};

fn deliveries(tag: u8) -> Vec<(u8, Vec<u8>)> {
    (1..=3).map(|m| (m, vec![tag ^ m; 120])).collect()
}

#[tokio::test]
async fn record_dealing_is_durable_before_any_send() {
    let f = dealer();
    let (ann, _) = announcement(MARKET, 10, 0xc0, 1);
    assert_eq!(
        f.repo
            .record_dealing(MARKET, 10, ann.clone(), deliveries(0x10))
            .await
            .unwrap(),
        PutOutcome::Inserted
    );
    // Committed when the call returns: another process reads the sealed
    // deliveries the dealer is about to send.
    let stored: Vec<(i64, Vec<u8>)> = {
        let conn = outside(&f.db());
        let mut st = conn
            .prepare("SELECT member, sealed FROM deliveries WHERE epoch = 10 ORDER BY member")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(
        stored,
        deliveries(0x10)
            .into_iter()
            .map(|(m, d)| (i64::from(m), d))
            .collect::<Vec<_>>()
    );

    // A restart re-sends exactly the stored deliveries. It never re-deals.
    assert_eq!(
        f.repo
            .record_dealing(MARKET, 10, ann.clone(), deliveries(0x20))
            .await
            .unwrap(),
        PutOutcome::Identical
    );
    let (second, _) = announcement(MARKET, 10, 0xc0, 2);
    assert_eq!(
        f.repo
            .record_dealing(MARKET, 10, second, deliveries(0x30))
            .await
            .unwrap(),
        PutOutcome::Conflict
    );
    let dealing = f.repo.dealing(MARKET, 10).await.unwrap().unwrap();
    assert_eq!(dealing.announcement, ann);
    assert_eq!(dealing.deliveries, deliveries(0x10));
    assert!(dealing.acks.is_empty());
    assert_eq!((dealing.bundle, dealing.bundle_delivered), (None, false));
    assert_eq!(f.repo.dealing(MARKET, 11).await.unwrap(), None);
    assert_eq!(f.repo.dealing(OTHER_MARKET, 10).await.unwrap(), None);
}

#[tokio::test]
async fn record_dealing_refuses_malformed_input() {
    let f = dealer();
    let (ann, _) = announcement(MARKET, 10, 0xc0, 1);
    let twice = vec![(1, vec![1; 10]), (1, vec![2; 10])];
    assert_eq!(
        f.repo.record_dealing(MARKET, 10, ann.clone(), twice).await,
        Err(StoreError::Conflict("two deliveries for one member"))
    );
    assert_eq!(
        f.repo
            .record_dealing(MARKET, 11, ann.clone(), deliveries(1))
            .await,
        Err(StoreError::Conflict(
            "the announcement names another market or epoch"
        ))
    );
    assert_eq!(
        f.repo
            .record_dealing(OTHER_MARKET, 10, ann, deliveries(1))
            .await,
        Err(StoreError::Conflict(
            "the announcement names another market or epoch"
        ))
    );
    assert_eq!(
        f.repo
            .record_dealing(MARKET, 10, vec![1; 40], deliveries(1))
            .await,
        Err(StoreError::Conflict("the announcement does not decode"))
    );
    assert_eq!(f.repo.dealing(MARKET, 10).await.unwrap(), None);
}

#[tokio::test]
async fn acks_bundles_and_delivery() {
    let f = dealer();
    let (ann, _) = announcement(MARKET, 10, 0xc0, 1);
    assert_eq!(
        f.repo.record_ack(MARKET, 10, ack(1, 0xa)).await,
        Err(StoreError::Conflict("no dealing for this epoch"))
    );
    f.repo
        .record_dealing(MARKET, 10, ann, deliveries(0x10))
        .await
        .unwrap();
    assert_eq!(f.repo.record_ack(MARKET, 10, ack(1, 0xa)).await.unwrap(), 1);
    assert_eq!(f.repo.record_ack(MARKET, 10, ack(3, 0xa)).await.unwrap(), 2);
    // A member's newer ack (a new policy statement) replaces its old one.
    assert_eq!(f.repo.record_ack(MARKET, 10, ack(1, 0xb)).await.unwrap(), 2);
    assert_eq!(
        f.repo.record_ack(MARKET, 10, vec![1, 2, 3]).await,
        Err(StoreError::Conflict("the ack does not decode"))
    );
    assert_eq!(
        f.repo.dealing(MARKET, 10).await.unwrap().unwrap().acks,
        vec![ack(1, 0xb), ack(3, 0xa)]
    );

    assert_eq!(
        f.repo.bundle_delivered(MARKET, 10).await,
        Err(StoreError::Conflict("no bundle intent for this epoch"))
    );
    f.repo
        .bundle_intent(MARKET, 10, vec![0xbb; 300])
        .await
        .unwrap();
    f.repo
        .bundle_intent(MARKET, 10, vec![0xbb; 300])
        .await
        .unwrap();
    assert_eq!(
        f.repo.bundle_intent(MARKET, 10, vec![0xbc; 300]).await,
        Err(StoreError::Conflict("a different bundle is recorded"))
    );
    let pending = f.repo.dealing(MARKET, 10).await.unwrap().unwrap();
    assert_eq!(
        (pending.bundle.clone(), pending.bundle_delivered),
        (Some(vec![0xbb; 300]), false)
    );
    assert_eq!(
        pending.deliveries.len(),
        3,
        "kept until the bundle is delivered"
    );

    f.repo.bundle_delivered(MARKET, 10).await.unwrap();
    let done = f.repo.dealing(MARKET, 10).await.unwrap().unwrap();
    assert_eq!(
        (done.bundle, done.bundle_delivered),
        (Some(vec![0xbb; 300]), true)
    );
    assert!(done.deliveries.is_empty());
    assert_eq!(done.acks.len(), 2);
    let in_file: i64 = outside(&f.db())
        .query_row("SELECT count(*) FROM deliveries", [], |r| r.get(0))
        .unwrap();
    assert_eq!(in_file, 0);
    assert_eq!(
        f.repo.bundle_intent(MARKET, 11, vec![1]).await,
        Err(StoreError::Conflict("no dealing for this epoch"))
    );
}

#[tokio::test]
async fn adopt_rebuilds_from_members_without_deliveries() {
    let f = dealer();
    let (ann, _) = announcement(MARKET, 20, 0xc0, 1);
    f.repo
        .adopt(MARKET, 20, ann.clone(), vec![ack(2, 0xa)])
        .await
        .unwrap();
    let adopted = f.repo.dealing(MARKET, 20).await.unwrap().unwrap();
    assert_eq!(adopted.announcement, ann);
    assert!(
        adopted.deliveries.is_empty(),
        "the dealer no longer holds the shares"
    );
    assert_eq!(adopted.acks, vec![ack(2, 0xa)]);

    // Adopting again adds the acks it lacks and keeps the ones it has.
    f.repo
        .adopt(MARKET, 20, ann.clone(), vec![ack(2, 0xb), ack(1, 0xa)])
        .await
        .unwrap();
    assert_eq!(
        f.repo.dealing(MARKET, 20).await.unwrap().unwrap().acks,
        vec![ack(1, 0xa), ack(2, 0xa)]
    );

    let (other, _) = announcement(MARKET, 20, 0xc0, 2);
    assert_eq!(
        f.repo.adopt(MARKET, 20, other.clone(), vec![]).await,
        Err(StoreError::Conflict(
            "another announcement is recorded for this epoch"
        ))
    );
    assert_eq!(
        f.repo
            .record_dealing(MARKET, 20, other, deliveries(1))
            .await
            .unwrap(),
        PutOutcome::Conflict,
        "an adopted epoch is never dealt again"
    );
    assert_eq!(
        f.repo
            .adopt(
                MARKET,
                21,
                announcement(MARKET, 21, 0xc0, 1).0,
                vec![vec![0; 3]]
            )
            .await,
        Err(StoreError::Conflict("an ack does not decode"))
    );
    assert_eq!(f.repo.dealing(MARKET, 21).await.unwrap(), None);
}

#[tokio::test]
async fn supersede_drops_the_old_committee_and_keeps_an_audit_row() {
    let f = dealer();
    let old = Hash32([0xc0; 32]);
    for e in 30..=33 {
        let (ann, _) = announcement(MARKET, e, 0xc0, e as u8);
        f.repo
            .record_dealing(MARKET, e, ann, deliveries(e as u8))
            .await
            .unwrap();
        f.repo.record_ack(MARKET, e, ack(1, 0xa)).await.unwrap();
    }
    f.repo
        .bundle_intent(MARKET, 32, vec![0xbb; 10])
        .await
        .unwrap();
    // Another market under the same committee is untouched.
    let (elsewhere, _) = announcement(OTHER_MARKET, 32, 0xc0, 1);
    f.repo
        .record_dealing(OTHER_MARKET, 32, elsewhere, deliveries(9))
        .await
        .unwrap();

    assert_eq!(f.repo.supersede(MARKET, 32, old).await.unwrap(), 2);
    assert!(f.repo.dealing(MARKET, 31).await.unwrap().is_some());
    for e in [32, 33] {
        assert_eq!(f.repo.dealing(MARKET, e).await.unwrap(), None);
    }
    assert!(f.repo.dealing(OTHER_MARKET, 32).await.unwrap().is_some());
    let conn = outside(&f.db());
    for table in ["deliveries", "acks", "bundles"] {
        let left: i64 = conn
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE market = ?1 AND epoch >= 32"),
                [MARKET],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(left, 0, "{table}");
    }
    let audit: Vec<(i64, Vec<u8>, Vec<u8>)> = {
        let mut st = conn
            .prepare("SELECT epoch, committee_digest, ann_digest FROM superseded ORDER BY epoch")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].0, 32);
    assert_eq!(audit[0].1, old.0.to_vec());
    assert_eq!(audit[0].2, announcement(MARKET, 32, 0xc0, 32).1.0.to_vec());

    // The old committee never deals those epochs again. The new one does,
    // once.
    let (again, _) = announcement(MARKET, 32, 0xc0, 99);
    assert_eq!(
        f.repo
            .record_dealing(MARKET, 32, again.clone(), deliveries(1))
            .await
            .unwrap(),
        PutOutcome::Conflict
    );
    assert_eq!(
        f.repo.adopt(MARKET, 32, again, vec![]).await,
        Err(StoreError::Conflict(
            "the announcement's committee was superseded for this epoch"
        ))
    );
    let (rotated, _) = announcement(MARKET, 32, 0xc1, 1);
    assert_eq!(
        f.repo
            .record_dealing(MARKET, 32, rotated.clone(), deliveries(2))
            .await
            .unwrap(),
        PutOutcome::Inserted
    );
    let (rotated_again, _) = announcement(MARKET, 32, 0xc1, 2);
    assert_eq!(
        f.repo
            .record_dealing(MARKET, 32, rotated_again, deliveries(3))
            .await
            .unwrap(),
        PutOutcome::Conflict
    );
    // Superseding again finds nothing more under the old committee.
    assert_eq!(f.repo.supersede(MARKET, 32, old).await.unwrap(), 0);
}

#[tokio::test]
async fn terminal_epochs_lose_their_deliveries_and_keep_their_announcement() {
    let f = dealer();
    for e in [10, 11, 12] {
        let (ann, _) = announcement(MARKET, e, 0xc0, 1);
        f.repo
            .record_dealing(MARKET, e, ann, deliveries(0x10))
            .await
            .unwrap();
    }
    let (other, _) = announcement(OTHER_MARKET, 10, 0xc0, 1);
    f.repo
        .record_dealing(OTHER_MARKET, 10, other, deliveries(0x10))
        .await
        .unwrap();

    assert_eq!(f.repo.prune_through(MARKET, 11).await.unwrap(), 6);
    for e in [10, 11] {
        let dealing = f.repo.dealing(MARKET, e).await.unwrap().unwrap();
        assert!(dealing.deliveries.is_empty(), "epoch {e}");
    }
    let kept = |m, e| {
        let repo = &f.repo;
        async move { repo.dealing(m, e).await.unwrap().unwrap().deliveries }
    };
    assert_eq!(kept(MARKET, 12).await, deliveries(0x10));
    assert_eq!(kept(OTHER_MARKET, 10).await, deliveries(0x10));
    assert_eq!(f.repo.prune_through(MARKET, 11).await.unwrap(), 0);

    // The announcement stays, so a pruned epoch is never dealt again.
    let (again, _) = announcement(MARKET, 10, 0xc0, 2);
    assert_eq!(
        f.repo
            .record_dealing(MARKET, 10, again, deliveries(0x30))
            .await
            .unwrap(),
        PutOutcome::Conflict
    );
}
