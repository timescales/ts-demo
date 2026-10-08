//! `MemberRepo` over `member.sqlite` and `shares.sqlite`.

use timescales_core::Hash32;
use timescales_service::store::member::{PinOutcome, ReleaseAudit};
use timescales_service::store::node::PutOutcome;
use timescales_service::store::{SecretSealer, StoreError};

use crate::common::{
    KEK_0, MARKET, OTHER_MARKET, announcement, db_files, file_contains, member, outside, share_aad,
    wal_len,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The plaintext the fixture seals for a share (`[marker; 33]`).
fn plaintext(marker: u8) -> [u8; 33] {
    [marker; 33]
}

#[tokio::test]
async fn shares_never_in_member_db() {
    let f = member();
    let mut sealed = Vec::new();
    for e in 1..=3u64 {
        let (ann, digest) = announcement(MARKET, e, 0xc0, e as u8);
        let share = f.seal_share(e, 0xa0 + e as u8);
        let outcome = f
            .repo
            .put_share(MARKET, e, ann, digest, share.clone(), 1_000)
            .await
            .unwrap();
        assert_eq!(outcome, PutOutcome::Inserted);
        sealed.push(share);
    }
    f.repo
        .pin_and_count(MARKET, 1, Hash32([0x11; 32]), 8)
        .await
        .unwrap();
    for share in &sealed {
        for file in db_files(&f.member_db()) {
            assert!(
                !file_contains(&file, share),
                "sealed share in {}",
                file.display()
            );
        }
        assert!(
            file_contains(&f.shares_db(), share)
                || file_contains(&db_files(&f.shares_db())[1], share)
        );
    }
    for marker in [0xa1, 0xa2, 0xa3] {
        for file in db_files(&f.member_db())
            .into_iter()
            .chain(db_files(&f.shares_db()))
        {
            assert!(
                !file_contains(&file, &plaintext(marker)),
                "plaintext share in {}",
                file.display()
            );
        }
    }
    // The member database has no share table, and its backups
    // carry no share material either.
    let tables = crate::common::tables(&f.member_db());
    assert!(!tables.contains(&"shares".to_owned()), "{tables:?}");
    assert_eq!(
        f.repo.share(MARKET, 2).await.unwrap(),
        Some(sealed[1].clone())
    );
    let opened = f.sealer.open(&share_aad(2), &sealed[1]).unwrap();
    assert_eq!(&*opened, &plaintext(0xa2));
}

#[tokio::test]
async fn put_share_is_idempotent_and_refuses_a_second_announcement() {
    let f = member();
    let (ann, digest) = announcement(MARKET, 4, 0xc0, 1);
    let share = f.seal_share(4, 1);
    assert_eq!(
        f.repo
            .put_share(MARKET, 4, ann.clone(), digest, share.clone(), 5)
            .await
            .unwrap(),
        PutOutcome::Inserted
    );
    assert_eq!(
        f.repo
            .put_share(MARKET, 4, ann.clone(), digest, f.seal_share(4, 1), 6)
            .await
            .unwrap(),
        PutOutcome::Identical
    );
    assert_eq!(f.repo.share(MARKET, 4).await.unwrap(), Some(share));
    let (other, other_digest) = announcement(MARKET, 4, 0xc0, 2);
    assert_eq!(
        f.repo
            .put_share(MARKET, 4, other, other_digest, f.seal_share(4, 2), 7)
            .await
            .unwrap(),
        PutOutcome::Conflict
    );
    assert_eq!(
        f.repo.announcement(MARKET, 4).await.unwrap(),
        Some((ann.clone(), digest))
    );

    // Refused outright: a digest that is not the announcement's, an
    // announcement for another market or epoch, an unsealed share.
    assert_eq!(
        f.repo
            .put_share(
                MARKET,
                5,
                announcement(MARKET, 5, 0xc0, 1).0,
                digest,
                f.seal_share(5, 1),
                1
            )
            .await,
        Err(StoreError::Conflict(
            "the announcement does not match its digest"
        ))
    );
    let (wrong_epoch, wrong_digest) = announcement(MARKET, 6, 0xc0, 1);
    assert_eq!(
        f.repo
            .put_share(MARKET, 5, wrong_epoch, wrong_digest, f.seal_share(5, 1), 1)
            .await,
        Err(StoreError::Conflict(
            "the announcement names another market or epoch"
        ))
    );
    let (ann5, digest5) = announcement(MARKET, 5, 0xc0, 1);
    assert_eq!(
        f.repo
            .put_share(MARKET, 5, ann5.clone(), digest5, vec![1, 2, 3], 1)
            .await,
        Err(StoreError::Conflict("the share is not sealed at rest"))
    );
    assert_eq!(
        f.repo
            .put_share(MARKET, 5, vec![0; 10], digest5, f.seal_share(5, 1), 1)
            .await,
        Err(StoreError::Conflict("the announcement does not decode"))
    );
    // None of those refusals wrote anything.
    assert_eq!(f.repo.announcement(MARKET, 5).await.unwrap(), None);

    // A crash between the two files left only the announcement: the next
    // delivery stores the share.
    outside(&f.member_db())
        .execute(
            "INSERT INTO announcements(market, epoch, announcement, ann_digest, received_at_ms)
             VALUES (?1, 5, ?2, ?3, 1)",
            rusqlite::params![MARKET, ann5, digest5.0],
        )
        .unwrap();
    let share5 = f.seal_share(5, 5);
    assert_eq!(
        f.repo
            .put_share(MARKET, 5, ann5, digest5, share5.clone(), 2)
            .await
            .unwrap(),
        PutOutcome::Inserted
    );
    assert_eq!(f.repo.share(MARKET, 5).await.unwrap(), Some(share5));
    let (ann_other, digest_other) = announcement(OTHER_MARKET, 4, 0xc0, 9);
    assert_eq!(
        f.repo
            .put_share(
                OTHER_MARKET,
                4,
                ann_other,
                digest_other,
                f.seal_share(4, 9),
                1
            )
            .await
            .unwrap(),
        PutOutcome::Inserted
    );
}

#[tokio::test]
async fn pin_and_count_pins_one_header_and_bounds_releases() {
    let f = member();
    let h = Hash32([0x11; 32]);
    assert_eq!(
        f.repo.pin_and_count(MARKET, 3, h, 3).await.unwrap(),
        PinOutcome::Pinned
    );
    assert_eq!(
        f.repo.pin_and_count(MARKET, 3, h, 3).await.unwrap(),
        PinOutcome::Matches
    );
    assert_eq!(
        f.repo
            .pin_and_count(MARKET, 3, Hash32([0x22; 32]), 3)
            .await
            .unwrap(),
        PinOutcome::Other(h)
    );
    assert_eq!(
        f.repo.pin_and_count(MARKET, 3, h, 3).await.unwrap(),
        PinOutcome::Matches
    );
    assert_eq!(
        f.repo.pin_and_count(MARKET, 3, h, 3).await.unwrap(),
        PinOutcome::TooMany
    );
    let releases: i64 = outside(&f.member_db())
        .query_row("SELECT releases FROM pins WHERE epoch = 3", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(releases, 3);
    assert_eq!(
        f.repo.pin_and_count(MARKET, 4, h, 0).await.unwrap(),
        PinOutcome::TooMany
    );
    assert_eq!(
        f.repo
            .pin_and_count(OTHER_MARKET, 3, Hash32([0x22; 32]), 3)
            .await
            .unwrap(),
        PinOutcome::Pinned
    );
}

#[tokio::test]
async fn secure_delete_and_truncate_shares() {
    let f = member();
    let mut sealed = Vec::new();
    for e in 1..=3u64 {
        let (ann, digest) = announcement(MARKET, e, 0xc0, e as u8);
        let share = f.seal_share(e, e as u8);
        f.repo
            .put_share(MARKET, e, ann, digest, share.clone(), 1)
            .await
            .unwrap();
        f.repo
            .pin_and_count(MARKET, e, Hash32([e as u8; 32]), 8)
            .await
            .unwrap();
        sealed.push(share);
    }
    let (other_ann, other_digest) = announcement(OTHER_MARKET, 1, 0xc0, 7);
    let other_share = f.seal_share(1, 7);
    f.repo
        .put_share(
            OTHER_MARKET,
            1,
            other_ann,
            other_digest,
            other_share.clone(),
            1,
        )
        .await
        .unwrap();
    assert!(wal_len(&f.shares_db()) > 0);

    assert_eq!(f.repo.destroy_through(MARKET, 2).await.unwrap(), 2);
    // No copy of a destroyed share is left in the file or a WAL.
    assert_eq!(wal_len(&f.shares_db()), 0);
    for share in &sealed[..2] {
        for file in db_files(&f.shares_db()) {
            assert!(
                !file_contains(&file, share),
                "destroyed share in {}",
                file.display()
            );
        }
    }
    assert!(file_contains(&f.shares_db(), &sealed[2]));
    assert!(file_contains(&f.shares_db(), &other_share));
    assert_eq!(f.repo.share(MARKET, 1).await.unwrap(), None);
    assert_eq!(
        f.repo.share(MARKET, 3).await.unwrap(),
        Some(sealed[2].clone())
    );
    assert_eq!(
        f.repo.share(OTHER_MARKET, 1).await.unwrap(),
        Some(other_share)
    );
    // Pins and announcements of those epochs went with them.
    assert_eq!(f.repo.announcement(MARKET, 2).await.unwrap(), None);
    assert!(f.repo.announcement(MARKET, 3).await.unwrap().is_some());
    let pins: i64 = outside(&f.member_db())
        .query_row("SELECT count(*) FROM pins", [], |r| r.get(0))
        .unwrap();
    assert_eq!(pins, 1);

    // A destroyed epoch is never stored again.
    let (ann, digest) = announcement(MARKET, 2, 0xc0, 2);
    assert_eq!(
        f.repo
            .put_share(MARKET, 2, ann, digest, f.seal_share(2, 2), 9)
            .await,
        Err(StoreError::Conflict(
            "the epoch's shares were already destroyed"
        ))
    );
    // Destroying less than before keeps the high-water mark.
    assert_eq!(f.repo.destroy_through(MARKET, 1).await.unwrap(), 0);
    let (ann, digest) = announcement(MARKET, 2, 0xc0, 2);
    assert!(
        f.repo
            .put_share(MARKET, 2, ann, digest, f.seal_share(2, 2), 9)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn ratchet_erases_old_generation() {
    let f = member();
    let (ann1, d1) = announcement(MARKET, 1, 0xc0, 1);
    let old = f.seal_share(1, 0x01);
    f.repo
        .put_share(MARKET, 1, ann1, d1, old.clone(), 1)
        .await
        .unwrap();
    assert_eq!(f.sealer.advance().unwrap(), 1);
    let (ann2, d2) = announcement(MARKET, 2, 0xc0, 2);
    let new = f.seal_share(2, 0x02);
    f.repo
        .put_share(MARKET, 2, ann2, d2, new.clone(), 1)
        .await
        .unwrap();

    // Generation 0 still protects the live share of epoch 1.
    f.repo.ratchet(1).await.unwrap();
    assert!(file_contains(&f.key_file(), hex(&KEK_0).as_bytes()));
    assert_eq!(&*f.sealer.open(&share_aad(1), &old).unwrap(), &[0x01; 33]);

    // Once epoch 1's share is destroyed, generation 0 is erased.
    f.repo.destroy_through(MARKET, 1).await.unwrap();
    f.repo.ratchet(1).await.unwrap();
    assert!(!file_contains(&f.key_file(), hex(&KEK_0).as_bytes()));
    assert_eq!(
        f.sealer.open(&share_aad(1), &old).unwrap_err(),
        StoreError::Corrupt("sealed under an erased key generation")
    );
    let reloaded = timescales_service::store::RatchetSealer::load(&f.key_file()).unwrap();
    assert!(reloaded.open(&share_aad(1), &old).is_err());
    assert_eq!(&*reloaded.open(&share_aad(2), &new).unwrap(), &[0x02; 33]);

    // A share sealed under the erased generation is refused.
    let (ann3, d3) = announcement(MARKET, 3, 0xc0, 3);
    assert_eq!(
        f.repo.put_share(MARKET, 3, ann3, d3, old, 1).await,
        Err(StoreError::Conflict(
            "the share is sealed under an erased key generation"
        ))
    );
    // The current generation is kept whatever is asked.
    f.repo.ratchet(u32::MAX).await.unwrap();
    assert_eq!(f.sealer.current_generation(), 1);
    assert_eq!(&*f.sealer.open(&share_aad(2), &new).unwrap(), &[0x02; 33]);
}

#[tokio::test]
async fn rotate_share_replaces_the_previous_committee_share() {
    let f = member();
    let (old_ann, old_digest) = announcement(MARKET, 7, 0xc0, 1);
    let old_share = f.seal_share(7, 0x0a);
    f.repo
        .put_share(MARKET, 7, old_ann, old_digest, old_share.clone(), 1)
        .await
        .unwrap();

    // Another announcement under the same committee is not a rotation.
    let (same_committee, same_digest) = announcement(MARKET, 7, 0xc0, 2);
    assert_eq!(
        f.repo
            .rotate_share(
                MARKET,
                7,
                same_committee,
                same_digest,
                f.seal_share(7, 0x0b),
                2
            )
            .await,
        Err(StoreError::Conflict(
            "a rotation needs an announcement under another committee"
        ))
    );

    let (new_ann, new_digest) = announcement(MARKET, 7, 0xc1, 3);
    let new_share = f.seal_share(7, 0x0c);
    f.repo
        .rotate_share(MARKET, 7, new_ann.clone(), new_digest, new_share.clone(), 3)
        .await
        .unwrap();
    assert_eq!(
        f.repo.share(MARKET, 7).await.unwrap(),
        Some(new_share.clone())
    );
    assert_eq!(
        f.repo.announcement(MARKET, 7).await.unwrap(),
        Some((new_ann.clone(), new_digest))
    );
    // The old share is destroyed with it, WAL included.
    for file in db_files(&f.shares_db()) {
        assert!(
            !file_contains(&file, &old_share),
            "old share in {}",
            file.display()
        );
    }
    // Repeating the rotation is a no-op. A delivery of the new
    // announcement is now an identical re-delivery.
    f.repo
        .rotate_share(
            MARKET,
            7,
            new_ann.clone(),
            new_digest,
            f.seal_share(7, 0x0d),
            4,
        )
        .await
        .unwrap();
    assert_eq!(f.repo.share(MARKET, 7).await.unwrap(), Some(new_share));
    assert_eq!(
        f.repo
            .put_share(MARKET, 7, new_ann, new_digest, f.seal_share(7, 0x0c), 5)
            .await
            .unwrap(),
        PutOutcome::Identical
    );

    let (nothing, nothing_digest) = announcement(MARKET, 8, 0xc1, 1);
    assert_eq!(
        f.repo
            .rotate_share(MARKET, 8, nothing, nothing_digest, f.seal_share(8, 1), 1)
            .await,
        Err(StoreError::Conflict("no share to rotate"))
    );
}

#[tokio::test]
async fn the_audit_log_is_pruned_by_age() {
    let f = member();
    for (i, at) in [1_000u64, 2_000, 3_000].into_iter().enumerate() {
        f.repo
            .audit(ReleaseAudit {
                market: MARKET,
                epoch: 1,
                executor: [i as u8; 32],
                seal_key: [0x5e; 32],
                header_digest: Hash32([0x4d; 32]),
                quote_hash: Hash32([0x9a; 32]),
                result: if i == 1 { 7 } else { 0 },
                at_ms: at,
            })
            .await
            .unwrap();
    }
    let report = f.repo.prune_audit(2_500).await.unwrap();
    assert_eq!((report.rows_deleted, report.wallets_nulled), (2, 0));
    let left: Vec<(i64, i64)> = {
        let conn = outside(&f.member_db());
        let mut st = conn.prepare("SELECT result, at_ms FROM releases").unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(left, vec![(0, 3_000)]);
}
