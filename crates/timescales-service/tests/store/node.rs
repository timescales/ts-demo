//! `NodeRepo` over `node.sqlite`.

use proptest::prelude::*;
use timescales_chain::{TxErrorDetail, TxJournal, TxOp, TxOutcome, TxRecord};
use timescales_core::{BookId, ClearingPrice, Encode, Hash32, Lots, OrderCommitment, Tick};
use timescales_service::store::StoreError;
use timescales_service::store::node::{
    DeltaRow, EpochPatch, EpochRow, FillRow, InsertSubmission, MAX_PAGE, NodeRepo, Phase,
    PostedResult, PutOutcome, Retention,
};

use crate::common::{
    MARKET, OTHER_MARKET, bare_row, node, open_row, outside, session, session_pk, submission,
};

const HOUR_MS: u64 = 3_600_000;

fn c(byte: u8) -> OrderCommitment {
    OrderCommitment([byte; 32])
}

/// Schedules, opens and closes epoch `e` of `MARKET`.
async fn closed_epoch(repo: &NodeRepo, e: u64) {
    repo.put_key_bundle(MARKET, e, vec![e as u8; 64], e)
        .await
        .unwrap();
    repo.open_epoch(open_row(e), Vec::new()).await.unwrap();
    repo.close_epoch(
        MARKET,
        e,
        vec![0xc1; 100],
        vec![0x1e; 64],
        Hash32([0x40; 32]),
        64,
        1,
        63,
    )
    .await
    .unwrap();
}

/// The start of an encoded `ExecutionReceipt` (what the tape reads), then
/// filler standing in for the rest.
fn receipt(e: u64, tick: u64, volume: u64, fills: u32) -> Vec<u8> {
    let mut out = vec![1u8];
    out.extend_from_slice(&7u64.to_le_bytes());
    out.extend_from_slice(&e.to_le_bytes());
    out.extend_from_slice(&[0x99; 32]);
    out.extend_from_slice(&1u32.to_le_bytes());
    ClearingPrice {
        book: BookId::Single,
        tick: Tick(tick),
        volume: Lots(volume),
    }
    .encode(&mut out);
    out.extend_from_slice(&fills.to_le_bytes());
    out.extend_from_slice(&[0x5e; 64]);
    out
}

fn result(e: u64) -> PostedResult {
    PostedResult {
        market: MARKET,
        epoch: e,
        receipt: receipt(e, 10_003, 6, 2),
        artifacts: vec![0xa7; 300],
        attestation: Some(vec![0xa5; 40]),
        cosigs: vec![([0xe1; 32], [0x51; 64]), ([0xe2; 32], [0x52; 64])],
        fills: vec![
            FillRow {
                idx: 0,
                commitment: c(1),
                trader: [1; 32],
                book: 0,
                side: 0,
                role: 1,
                qty: 6,
                tick: 10_003,
            },
            FillRow {
                idx: 1,
                commitment: c(2),
                trader: [2; 32],
                book: 0,
                side: 1,
                role: 0,
                qty: 6,
                tick: 10_003,
            },
        ],
        deltas: vec![
            DeltaRow {
                idx: 0,
                trader: [1; 32],
                base: 6,
                quote: -60_018,
            },
            DeltaRow {
                idx: 1,
                trader: [2; 32],
                base: -6,
                quote: 60_018,
            },
        ],
        cancelled: vec![c(3)],
        order_state: vec![0x05; 50],
        order_state_root: Hash32([0x0e; 32]),
    }
}

#[tokio::test]
async fn meta_round_trips() {
    let f = node();
    assert_eq!(f.repo.meta("stream_id").await.unwrap(), None);
    f.repo.set_meta("stream_id", b"one".to_vec()).await.unwrap();
    f.repo.set_meta("stream_id", b"two".to_vec()).await.unwrap();
    assert_eq!(
        f.repo.meta("stream_id").await.unwrap(),
        Some(b"two".to_vec())
    );
}

#[tokio::test]
async fn key_bundles_schedule_and_are_never_replaced_once_used() {
    let f = node();
    let r = &f.repo;
    assert_eq!(
        r.put_key_bundle(MARKET, 5, vec![1; 10], 100).await.unwrap(),
        PutOutcome::Inserted
    );
    let row = r.epoch(MARKET, 5).await.unwrap().unwrap();
    assert_eq!(
        row,
        EpochRow {
            updated_at_ms: 100,
            ..bare_row(5, Phase::Scheduled)
        }
    );
    assert_eq!(
        r.put_key_bundle(MARKET, 5, vec![1; 10], 200).await.unwrap(),
        PutOutcome::Identical
    );
    // Unused: a different bundle replaces it (and is logged).
    assert_eq!(
        r.put_key_bundle(MARKET, 5, vec![2; 10], 300).await.unwrap(),
        PutOutcome::Inserted
    );
    assert_eq!(r.key_bundle(MARKET, 5).await.unwrap(), Some(vec![2; 10]));

    // Served in the park window: never replaced.
    r.mark_bundle_served(MARKET, 5).await.unwrap();
    assert_eq!(
        r.put_key_bundle(MARKET, 5, vec![3; 10], 400).await.unwrap(),
        PutOutcome::Conflict
    );
    assert_eq!(r.key_bundle(MARKET, 5).await.unwrap(), Some(vec![2; 10]));
    assert_eq!(
        r.put_key_bundle(MARKET, 5, vec![2; 10], 400).await.unwrap(),
        PutOutcome::Identical
    );

    // Parked under: never replaced.
    r.put_key_bundle(MARKET, 6, vec![6; 10], 100).await.unwrap();
    r.insert_parked(vec![submission(6, 1, 1)]).await.unwrap();
    assert_eq!(
        r.put_key_bundle(MARKET, 6, vec![7; 10], 100).await.unwrap(),
        PutOutcome::Conflict
    );

    // Opened: never replaced.
    r.put_key_bundle(MARKET, 7, vec![7; 10], 100).await.unwrap();
    r.open_epoch(open_row(7), Vec::new()).await.unwrap();
    assert_eq!(
        r.put_key_bundle(MARKET, 7, vec![8; 10], 100).await.unwrap(),
        PutOutcome::Conflict
    );

    assert_eq!(
        r.mark_bundle_served(MARKET, 99).await,
        Err(StoreError::Conflict("no key bundle for this epoch"))
    );
    assert_eq!(r.key_bundle(OTHER_MARKET, 5).await.unwrap(), None);
}

#[tokio::test]
async fn open_epoch_injects_parked_envelopes_and_drops_the_rest() {
    let f = node();
    let r = &f.repo;
    r.put_key_bundle(MARKET, 4, vec![4; 10], 1).await.unwrap();
    r.insert_parked(vec![submission(4, 1, 1), submission(4, 2, 2)])
        .await
        .unwrap();
    r.open_epoch(open_row(4), vec![(c(1), [1; 32])])
        .await
        .unwrap();
    assert_eq!(r.epoch(MARKET, 4).await.unwrap(), Some(open_row(4)));
    assert_eq!(
        r.submissions(MARKET, 4).await.unwrap(),
        vec![submission(4, 1, 1)]
    );
    assert!(r.parked_for_epoch(MARKET, 4).await.unwrap().is_empty());

    assert_eq!(
        r.open_epoch(open_row(4), Vec::new()).await,
        Err(StoreError::Conflict("epoch already opened"))
    );
    assert_eq!(
        r.open_epoch(open_row(5), Vec::new()).await,
        Err(StoreError::Conflict("another epoch of the market is open"))
    );
    assert_eq!(
        r.open_epoch(bare_row(5, Phase::Closed), Vec::new()).await,
        Err(StoreError::Conflict("open_epoch takes a row in phase open"))
    );
    // Another market is independent, and a refused open writes nothing.
    let other = EpochRow {
        market: OTHER_MARKET,
        ..open_row(1)
    };
    assert_eq!(
        r.open_epoch(other.clone(), vec![(c(9), [9; 32])]).await,
        Err(StoreError::Conflict(
            "injected envelope is not parked for this epoch"
        ))
    );
    assert_eq!(r.epoch(OTHER_MARKET, 1).await.unwrap(), None);
    r.open_epoch(other, Vec::new()).await.unwrap();
}

#[tokio::test]
async fn close_epoch_is_idempotent() {
    let f = node();
    let r = &f.repo;
    closed_epoch(r, 2).await;
    let row = r.epoch(MARKET, 2).await.unwrap().unwrap();
    assert_eq!(row.phase, Phase::Closed);
    assert_eq!(row.root, Some(Hash32([0x40; 32])));
    assert_eq!(
        (row.envelope_count, row.real_count, row.cover_count),
        (Some(64), Some(1), Some(63))
    );
    assert_eq!(r.leaves(MARKET, 2).await.unwrap(), Some(vec![0x1e; 64]));

    let again = r
        .close_epoch(
            MARKET,
            2,
            vec![0xc1; 100],
            vec![0x1e; 64],
            Hash32([0x40; 32]),
            64,
            1,
            63,
        )
        .await;
    assert_eq!(again, Ok(()));
    let other = r
        .close_epoch(
            MARKET,
            2,
            vec![0xc2; 100],
            vec![0x1e; 64],
            Hash32([0x40; 32]),
            64,
            1,
            63,
        )
        .await;
    assert_eq!(
        other,
        Err(StoreError::Conflict("epoch closed with another batch"))
    );
    let unknown = r
        .close_epoch(MARKET, 9, vec![], vec![], Hash32([0; 32]), 0, 0, 0)
        .await;
    assert_eq!(unknown, Err(StoreError::Conflict("no such epoch")));
    r.put_key_bundle(MARKET, 3, vec![3; 4], 1).await.unwrap();
    let scheduled = r
        .close_epoch(MARKET, 3, vec![], vec![], Hash32([0; 32]), 0, 0, 0)
        .await;
    assert_eq!(scheduled, Err(StoreError::Conflict("epoch is not open")));
}

#[tokio::test]
async fn phase_never_goes_backwards() {
    let f = node();
    let r = &f.repo;
    closed_epoch(r, 1).await;
    let backwards = Err(StoreError::Conflict("epoch phase cannot move backwards"));

    let steps: [(Phase, EpochPatch); 9] = [
        (Phase::Committing, EpochPatch::default()),
        (
            Phase::Committed,
            EpochPatch {
                commit_slot: Some(100),
                commit_sig: Some([0x5c; 64]),
                ..EpochPatch::default()
            },
        ),
        (
            Phase::Snapshotted,
            EpochPatch {
                snapshot_slot: Some(101),
                ..EpochPatch::default()
            },
        ),
        (
            Phase::Revealed,
            EpochPatch {
                beacon: Some(Hash32([0xbe; 32])),
                reveal_slot: Some(110),
                ..EpochPatch::default()
            },
        ),
        (
            Phase::Sealed,
            EpochPatch {
                header: Some(vec![0x4e; 283]),
                ..EpochPatch::default()
            },
        ),
        (Phase::Executing, EpochPatch::default()),
        (
            Phase::Posted,
            EpochPatch {
                receipt: Some(vec![0x7e; 10]),
                receipt_slot: Some(120),
                ..EpochPatch::default()
            },
        ),
        (
            Phase::Posted,
            EpochPatch {
                artifacts_public: Some(true),
                ..EpochPatch::default()
            },
        ),
        (
            Phase::Settled,
            EpochPatch {
                terminal_slot: Some(130),
                ..EpochPatch::default()
            },
        ),
    ];
    for (to, patch) in steps {
        // Each phase needs its artefact stored first.
        let missing = r.advance(MARKET, 1, to, patch.clone()).await;
        match to {
            Phase::Snapshotted => {
                assert_eq!(
                    missing,
                    Err(StoreError::Conflict("the balance snapshot is not stored"))
                );
                r.put_snapshot(MARKET, 1, vec![0x5a; 40], 101)
                    .await
                    .unwrap();
            }
            Phase::Sealed => {
                assert_eq!(
                    missing,
                    Err(StoreError::Conflict("the sealed batch is not stored"))
                );
                r.put_sealed(MARKET, 1, [0x4e; 283], vec![0xba; 500])
                    .await
                    .unwrap();
            }
            Phase::Executing => {
                assert_eq!(missing, Err(StoreError::Conflict("no attempt is recorded")));
                r.begin_attempt(MARKET, 1, "enclave-a".into(), 5)
                    .await
                    .unwrap();
            }
            Phase::Posted if r.epoch(MARKET, 1).await.unwrap().unwrap().phase != Phase::Posted => {
                assert_eq!(
                    missing,
                    Err(StoreError::Conflict("the result is not stored"))
                );
                r.put_result(result(1)).await.unwrap();
            }
            _ => {}
        }
        if missing.is_err() {
            r.advance(MARKET, 1, to, patch).await.unwrap();
        }
        let now = r.epoch(MARKET, 1).await.unwrap().unwrap();
        assert_eq!(now.phase, to);
        // Every earlier phase is refused, and the refusal changes nothing.
        for earlier in Phase::ALL
            .into_iter()
            .filter(|p| *p < to && *p != Phase::Aborting)
        {
            if to.is_terminal() || earlier < to {
                assert_eq!(
                    r.advance(MARKET, 1, earlier, EpochPatch::default()).await,
                    backwards
                );
            }
        }
        assert_eq!(r.epoch(MARKET, 1).await.unwrap().unwrap(), now);
    }
    let settled = r.epoch(MARKET, 1).await.unwrap().unwrap();
    assert_eq!(settled.commit_slot, Some(100));
    assert_eq!(settled.beacon, Some(Hash32([0xbe; 32])));
    assert!(settled.artifacts_public);
    assert_eq!(settled.terminal_slot, Some(130));
    // A terminal phase never changes, not even to an abort.
    for to in [Phase::Aborting, Phase::Aborted] {
        assert_eq!(
            r.advance(MARKET, 1, to, EpochPatch::default()).await,
            backwards
        );
    }

    // Aborts: from any live phase. A superseded abort resumes at committed
    // or later, never earlier.
    closed_epoch(r, 2).await;
    r.advance(MARKET, 2, Phase::Committing, EpochPatch::default())
        .await
        .unwrap();
    r.advance(
        MARKET,
        2,
        Phase::Aborting,
        EpochPatch {
            abort_reason: Some(2),
            abort_detail: Some("closed batch lost".into()),
            ..EpochPatch::default()
        },
    )
    .await
    .unwrap();
    for earlier in [
        Phase::Scheduled,
        Phase::Open,
        Phase::Closed,
        Phase::Committing,
    ] {
        assert_eq!(
            r.advance(MARKET, 2, earlier, EpochPatch::default()).await,
            backwards
        );
    }
    r.advance(MARKET, 2, Phase::Committed, EpochPatch::default())
        .await
        .unwrap();
    r.advance(
        MARKET,
        2,
        Phase::Aborted,
        EpochPatch {
            terminal_slot: Some(9),
            ..EpochPatch::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        r.advance(MARKET, 2, Phase::Committed, EpochPatch::default())
            .await,
        backwards
    );
    let aborted = r.epoch(MARKET, 2).await.unwrap().unwrap();
    assert_eq!(aborted.phase, Phase::Aborted);
    assert_eq!(aborted.abort_reason, Some(2));
    assert_eq!(aborted.abort_detail.as_deref(), Some("closed batch lost"));

    assert_eq!(
        r.advance(MARKET, 77, Phase::Open, EpochPatch::default())
            .await,
        Err(StoreError::Conflict("no such epoch"))
    );
}

/// The rule, restated independently of the crate.
fn allowed(from: Phase, to: Phase) -> bool {
    use Phase::*;
    if from == to {
        return true;
    }
    if matches!(from, Settled | Aborted) {
        return false;
    }
    if matches!(to, Aborting | Aborted) {
        return true;
    }
    if from == Aborting {
        return to.code() >= Committed.code();
    }
    to.code() > from.code()
}

fn phase() -> impl Strategy<Value = Phase> {
    (0..Phase::ALL.len()).prop_map(|i| Phase::ALL[i])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Random moves on an epoch whose every artefact is stored: the store
    /// takes exactly the moves the rule allows, and a stored phase only
    /// ever decreases when a superseded abort resumes.
    #[test]
    fn random_moves_follow_the_phase_rule(moves in proptest::collection::vec(phase(), 1..24)) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let f = node();
            let r = &f.repo;
            r.put_key_bundle(MARKET, 1, vec![1; 8], 1).await.unwrap();
            outside(&f.db())
                .execute(
                    "INSERT INTO closed(market, epoch, closed, leaves) VALUES (?1, 1, x'00', x'00')",
                    [MARKET],
                )
                .unwrap();
            r.put_snapshot(MARKET, 1, vec![1], 1).await.unwrap();
            r.put_sealed(MARKET, 1, [0; 283], vec![1]).await.unwrap();
            r.begin_attempt(MARKET, 1, "e".into(), 1).await.unwrap();
            r.put_result(result(1)).await.unwrap();

            let mut current = Phase::Scheduled;
            for to in moves {
                let outcome = r.advance(MARKET, 1, to, EpochPatch::default()).await;
                prop_assert_eq!(outcome.is_ok(), allowed(current, to), "{:?} -> {:?}", current, to);
                if outcome.is_ok() {
                    prop_assert!(
                        to >= current || (current == Phase::Aborting && to >= Phase::Committed),
                        "{:?} -> {:?}", current, to
                    );
                    current = to;
                }
                prop_assert_eq!(r.epoch(MARKET, 1).await.unwrap().unwrap().phase, current);
            }
            Ok(())
        })?;
    }
}

#[tokio::test]
async fn epochs_are_listed_and_paged_newest_first() {
    let f = node();
    let r = &f.repo;
    assert_eq!(r.max_epoch(MARKET).await.unwrap(), None);
    for e in 1..=5 {
        r.put_key_bundle(MARKET, e, vec![e as u8; 4], e)
            .await
            .unwrap();
    }
    r.put_key_bundle(OTHER_MARKET, 9, vec![9; 4], 1)
        .await
        .unwrap();
    assert_eq!(r.max_epoch(MARKET).await.unwrap(), Some(5));
    r.open_epoch(open_row(1), Vec::new()).await.unwrap();
    r.advance(MARKET, 2, Phase::Aborted, EpochPatch::default())
        .await
        .unwrap();
    let live: Vec<u64> = r
        .non_terminal_epochs(MARKET)
        .await
        .unwrap()
        .iter()
        .map(|e| e.epoch)
        .collect();
    assert_eq!(live, vec![1, 3, 4, 5]);

    let page = |rows: Vec<EpochRow>| rows.iter().map(|e| e.epoch).collect::<Vec<_>>();
    let (rows, next) = r.epochs_page(MARKET, None, 2).await.unwrap();
    assert_eq!((page(rows), next), (vec![5, 4], Some(4)));
    let (rows, next) = r.epochs_page(MARKET, Some(4), 2).await.unwrap();
    assert_eq!((page(rows), next), (vec![3, 2], Some(2)));
    let (rows, next) = r.epochs_page(MARKET, Some(2), 2).await.unwrap();
    assert_eq!((page(rows), next), (vec![1], None));
    // The limit is clamped to 1..=MAX_PAGE.
    let (rows, next) = r.epochs_page(MARKET, None, 0).await.unwrap();
    assert_eq!((page(rows), next), (vec![5], Some(5)));
    let (rows, next) = r.epochs_page(MARKET, None, MAX_PAGE * 10).await.unwrap();
    assert_eq!((page(rows), next), (vec![5, 4, 3, 2, 1], None));
    let (rows, next) = r.epochs_page(MARKET, Some(u64::MAX), 1).await.unwrap();
    assert_eq!((page(rows), next), (vec![5], Some(5)));
}

#[tokio::test]
async fn submissions_deduplicate_on_commitment_and_wallet() {
    let f = node();
    let r = &f.repo;
    r.insert_session(session(1, session_pk(1)[0], 10), 4)
        .await
        .unwrap();
    let first = submission(3, 0x21, 1);
    assert_eq!(
        r.insert_submission(first.clone()).await.unwrap(),
        InsertSubmission::Inserted
    );
    assert_eq!(
        r.insert_submission(first.clone()).await.unwrap(),
        InsertSubmission::Duplicate {
            promise: first.promise.clone()
        }
    );
    let other_bytes = submission(3, 0x21, 1);
    let other_bytes = timescales_service::store::node::SubmissionRow {
        submission: vec![0x22; 386],
        promise: vec![0; 201],
        ..other_bytes
    };
    assert_eq!(
        r.insert_submission(other_bytes).await.unwrap(),
        InsertSubmission::SameCommitmentOtherBytes {
            promise: first.promise.clone()
        }
    );
    // The same commitment from another wallet is its own submission.
    let second = submission(3, 0x21, 2);
    assert_eq!(
        r.insert_submission(second.clone()).await.unwrap(),
        InsertSubmission::Inserted
    );
    assert_eq!(
        r.submissions(MARKET, 3).await.unwrap(),
        vec![first.clone(), second]
    );
    assert_eq!(r.submissions(MARKET, 4).await.unwrap(), vec![]);

    let anonymous = timescales_service::store::node::SubmissionRow {
        wallet: None,
        ..submission(3, 0x30, 1)
    };
    assert_eq!(
        r.insert_submission(anonymous).await,
        Err(StoreError::Conflict(
            "an envelope needs its submitting wallet"
        ))
    );
    // The submitting session is kept while the envelope needs its grant.
    let s = r.session(session_pk(1)).await.unwrap().unwrap();
    assert_eq!(s.keep_until_epoch, Some(3));
}

#[tokio::test]
async fn parking_retracting_and_invalidating() {
    let f = node();
    let r = &f.repo;
    let rows = vec![
        submission(5, 1, 1),
        submission(6, 1, 1),
        submission(7, 1, 1),
        submission(6, 2, 2),
    ];
    let inserted = r.insert_parked(rows.clone()).await.unwrap();
    assert_eq!(inserted, vec![InsertSubmission::Inserted; 4]);
    assert_eq!(
        r.insert_parked(vec![submission(6, 1, 1)]).await.unwrap(),
        vec![InsertSubmission::Duplicate {
            promise: submission(6, 1, 1).promise
        }]
    );
    let no_session = timescales_service::store::node::SubmissionRow {
        session_pk: None,
        ..submission(8, 1, 1)
    };
    assert_eq!(
        r.insert_parked(vec![submission(8, 2, 1), no_session]).await,
        Err(StoreError::Conflict(
            "a parked envelope needs its wallet and session"
        ))
    );
    assert!(r.parked_for_epoch(MARKET, 8).await.unwrap().is_empty());

    assert_eq!(
        r.parked_for_epoch(MARKET, 6).await.unwrap(),
        vec![rows[1].clone(), rows[3].clone()]
    );
    assert_eq!(r.wallet_usage(MARKET, 6, [1; 32]).await.unwrap(), (1, 3));
    r.insert_submission(submission(6, 9, 1)).await.unwrap();
    assert_eq!(r.wallet_usage(MARKET, 6, [1; 32]).await.unwrap(), (2, 3));
    assert_eq!(r.wallet_usage(MARKET, 6, [3; 32]).await.unwrap(), (0, 0));

    assert_eq!(
        r.parked_by_wallet(MARKET, [1; 32]).await.unwrap(),
        vec![(5, c(1)), (6, c(1)), (7, c(1))]
    );
    assert_eq!(
        r.retract_parked(MARKET, [1; 32], c(1), 5).await.unwrap(),
        vec![6, 7]
    );
    assert_eq!(
        r.parked_by_wallet(MARKET, [1; 32]).await.unwrap(),
        vec![(5, c(1))]
    );
    assert_eq!(
        r.retract_parked(MARKET, [1; 32], c(1), 5).await.unwrap(),
        Vec::<u64>::new()
    );

    assert_eq!(r.invalidate_parked(MARKET, vec![5, 6]).await.unwrap(), 2);
    assert!(r.parked_for_epoch(MARKET, 5).await.unwrap().is_empty());
    assert!(r.parked_for_epoch(MARKET, 6).await.unwrap().is_empty());
    assert!(
        r.parked_by_wallet(MARKET, [2; 32])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn cover_carry_is_replaced_by_each_close() {
    let f = node();
    let r = &f.repo;
    r.replace_cover_carry(
        MARKET,
        1,
        vec![(c(1), vec![0xa1; 48]), (c(2), vec![0xa2; 48])],
    )
    .await
    .unwrap();
    r.replace_cover_carry(OTHER_MARKET, 1, vec![(c(1), vec![0xf1; 48])])
        .await
        .unwrap();
    // The next close no longer carries c(1), carries c(2) on and adds c(3).
    r.replace_cover_carry(
        MARKET,
        2,
        vec![(c(3), vec![0xa3; 48]), (c(2), vec![0xb2; 48])],
    )
    .await
    .unwrap();
    assert_eq!(
        r.cover_carry(MARKET, 10).await.unwrap(),
        vec![(c(2), vec![0xb2; 48]), (c(3), vec![0xa3; 48])]
    );
    assert_eq!(
        r.cover_carry(MARKET, 1).await.unwrap(),
        vec![(c(2), vec![0xb2; 48])]
    );
    assert_eq!(
        r.cover_carry(OTHER_MARKET, 10).await.unwrap(),
        vec![(c(1), vec![0xf1; 48])]
    );
    let last_epochs: Vec<i64> = {
        let conn = outside(&f.db());
        let mut st = conn
            .prepare("SELECT last_epoch FROM cover_carry WHERE market = ?1 ORDER BY commitment")
            .unwrap();
        st.query_map([MARKET], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(last_epochs, [2, 2]);
    // A close that carries nothing empties the set.
    r.replace_cover_carry(MARKET, 3, Vec::new()).await.unwrap();
    assert!(r.cover_carry(MARKET, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn insert_session_evicts_oldest() {
    let f = node();
    let r = &f.repo;
    let s1 = session(1, 0x11, 1_000);
    let s2 = session(1, 0x12, 2_000);
    let s3 = session(1, 0x13, 3_000);
    let other = session(2, 0x21, 500);
    assert_eq!(
        r.insert_session(s1.clone(), 2).await.unwrap(),
        (s1.clone(), 0)
    );
    assert_eq!(
        r.insert_session(other.clone(), 2).await.unwrap(),
        (other.clone(), 0)
    );
    assert_eq!(
        r.insert_session(s2.clone(), 2).await.unwrap(),
        (s2.clone(), 0)
    );
    assert_eq!(
        r.insert_session(s3.clone(), 2).await.unwrap(),
        (s3.clone(), 1)
    );

    assert!(r.session(s1.session_pk).await.unwrap().unwrap().revoked);
    assert!(!r.session(s2.session_pk).await.unwrap().unwrap().revoked);
    assert!(!r.session(s3.session_pk).await.unwrap().unwrap().revoked);
    assert!(
        !r.session(other.session_pk).await.unwrap().unwrap().revoked,
        "another wallet's session"
    );

    // An identical grant returns the stored session and evicts nothing.
    assert_eq!(
        r.insert_session(s3.clone(), 2).await.unwrap(),
        (s3.clone(), 0)
    );
    assert_eq!(
        r.session_by_grant(s3.wallet, s3.nonce).await.unwrap(),
        Some(s3.clone())
    );
    // The same grant nonce with another key or signature is refused.
    let replay = timescales_service::store::node::SessionRow {
        session_pk: [0x99; 32],
        ..s3.clone()
    };
    assert_eq!(
        r.insert_session(replay, 2).await,
        Err(StoreError::Conflict("grant nonce already used"))
    );
    let key_reuse = timescales_service::store::node::SessionRow {
        nonce: [0x98; 16],
        ..s3.clone()
    };
    assert_eq!(
        r.insert_session(key_reuse, 2).await,
        Err(StoreError::Conflict("session key already registered"))
    );

    // With a limit of one, every new session evicts all older ones.
    let s4 = session(1, 0x14, 4_000);
    assert_eq!(
        r.insert_session(s4.clone(), 1).await.unwrap(),
        (s4.clone(), 2)
    );
    for old in [&s2, &s3] {
        assert!(r.session(old.session_pk).await.unwrap().unwrap().revoked);
    }

    r.revoke_session(s4.session_pk).await.unwrap();
    assert!(r.session(s4.session_pk).await.unwrap().unwrap().revoked);
    r.revoke_session([0x77; 32]).await.unwrap();
    assert_eq!(r.session([0x77; 32]).await.unwrap(), None);
}

#[tokio::test]
async fn nonces_and_bans() {
    let f = node();
    let r = &f.repo;
    assert!(r.use_nonce([1; 16], 10_000).await.unwrap());
    assert!(!r.use_nonce([1; 16], 10_000).await.unwrap());
    assert!(r.use_nonce([2; 16], 10_000).await.unwrap());

    r.ban(MARKET, [5; 32], 10, "unauthenticated").await.unwrap();
    assert!(r.banned(MARKET, [5; 32], 10).await.unwrap());
    assert!(!r.banned(MARKET, [5; 32], 11).await.unwrap());
    assert!(!r.banned(OTHER_MARKET, [5; 32], 1).await.unwrap());
    // A shorter ban never cuts a longer one short.
    r.ban(MARKET, [5; 32], 4, "again").await.unwrap();
    assert!(r.banned(MARKET, [5; 32], 10).await.unwrap());
    r.ban(MARKET, [5; 32], 20, "longer").await.unwrap();
    assert!(r.banned(MARKET, [5; 32], 20).await.unwrap());
}

#[tokio::test]
async fn snapshots_and_sealed_batches() {
    let f = node();
    let r = &f.repo;
    assert_eq!(r.snapshot(MARKET, 1).await.unwrap(), None);
    r.put_snapshot(MARKET, 1, vec![1; 10], 100).await.unwrap();
    r.put_snapshot(MARKET, 1, vec![1; 10], 100).await.unwrap();
    // Retaken (late snapshot) until a header is sealed over it.
    r.put_snapshot(MARKET, 1, vec![2; 10], 105).await.unwrap();
    assert_eq!(
        r.snapshot(MARKET, 1).await.unwrap(),
        Some((vec![2; 10], 105))
    );

    r.put_sealed(MARKET, 1, [7; 283], vec![8; 64])
        .await
        .unwrap();
    r.put_sealed(MARKET, 1, [7; 283], vec![8; 64])
        .await
        .unwrap();
    assert_eq!(
        r.put_sealed(MARKET, 1, [7; 283], vec![9; 64]).await,
        Err(StoreError::Conflict("a different sealed batch is stored"))
    );
    assert_eq!(
        r.sealed(MARKET, 1).await.unwrap(),
        Some(([7; 283], vec![8; 64]))
    );
    assert_eq!(
        r.put_snapshot(MARKET, 1, vec![3; 10], 106).await,
        Err(StoreError::Conflict(
            "the snapshot is already part of a sealed header"
        ))
    );
    r.put_snapshot(MARKET, 1, vec![2; 10], 105).await.unwrap();
}

#[tokio::test]
async fn attempt_row_before_dispatch() {
    let f = node();
    let r = &f.repo;
    closed_epoch(r, 3).await;
    for to in [Phase::Committing, Phase::Committed] {
        r.advance(MARKET, 3, to, EpochPatch::default())
            .await
            .unwrap();
    }
    r.put_snapshot(MARKET, 3, vec![1], 1).await.unwrap();
    r.put_sealed(MARKET, 3, [1; 283], vec![1]).await.unwrap();
    for to in [Phase::Snapshotted, Phase::Revealed, Phase::Sealed] {
        r.advance(MARKET, 3, to, EpochPatch::default())
            .await
            .unwrap();
    }
    // No attempt row: the epoch cannot be executing.
    assert_eq!(
        r.advance(MARKET, 3, Phase::Executing, EpochPatch::default())
            .await,
        Err(StoreError::Conflict("no attempt is recorded"))
    );

    let n = r
        .begin_attempt(MARKET, 3, "enclave-a".into(), 1_000)
        .await
        .unwrap();
    assert_eq!(n, 1);
    // Durable when begin_attempt returns: another process sees the row
    // before the request could have been sent.
    let (enclave, started, result): (String, i64, Option<String>) = outside(&f.db())
        .query_row(
            "SELECT enclave, started_at_ms, result FROM attempts WHERE market = ?1 AND epoch = 3 AND n = 1",
            [MARKET],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (enclave.as_str(), started, result),
        ("enclave-a", 1_000, None)
    );
    r.advance(MARKET, 3, Phase::Executing, EpochPatch::default())
        .await
        .unwrap();

    assert_eq!(
        r.begin_attempt(MARKET, 3, "enclave-b".into(), 1_001)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        r.begin_attempt(MARKET, 4, "enclave-a".into(), 1_002)
            .await
            .unwrap(),
        1
    );
    r.finish_attempt(MARKET, 3, 1, "ready", "outcome 0xab".into())
        .await
        .unwrap();
    assert_eq!(
        r.finish_attempt(MARKET, 3, 9, "ready", String::new()).await,
        Err(StoreError::Conflict("no such attempt"))
    );
    let attempts = r.attempts(MARKET, 3).await.unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].result.as_deref(), Some("ready"));
    assert_eq!(attempts[0].detail.as_deref(), Some("outcome 0xab"));
    assert_eq!(
        (
            attempts[1].n,
            attempts[1].enclave.as_str(),
            attempts[1].result.clone()
        ),
        (2, "enclave-b", None)
    );
}

#[tokio::test]
async fn results_are_public_only_once_the_quorum_is_on_chain() {
    let f = node();
    let r = &f.repo;
    closed_epoch(r, 3).await;
    r.put_sealed(MARKET, 3, [0x4e; 283], vec![0xba; 10])
        .await
        .unwrap();
    assert_eq!(
        r.set_artifacts_public(MARKET, 3).await,
        Err(StoreError::Conflict("no stored result for this epoch"))
    );
    r.put_result(result(3)).await.unwrap();
    r.put_result(result(3)).await.unwrap();
    let mut different = result(3);
    different.receipt = receipt(3, 10_004, 6, 2);
    assert_eq!(
        r.put_result(different).await,
        Err(StoreError::Conflict("a different result is stored"))
    );
    let mut duplicate_fill = result(4);
    duplicate_fill.fills[1].idx = 0;
    assert_eq!(
        r.put_result(duplicate_fill).await,
        Err(StoreError::Conflict("duplicate fill or delta index"))
    );

    assert_eq!(r.public_artifacts(MARKET, 3).await.unwrap(), None);
    assert!(r.tape_page(MARKET, None, 10).await.unwrap().0.is_empty());
    assert_eq!(
        r.order_state(MARKET, 3).await.unwrap(),
        Some((vec![0x05; 50], Hash32([0x0e; 32]), false))
    );

    r.advance(MARKET, 3, Phase::Aborting, EpochPatch::default())
        .await
        .unwrap();
    r.set_artifacts_public(MARKET, 3).await.unwrap();
    let public = r.public_artifacts(MARKET, 3).await.unwrap().unwrap();
    assert_eq!(
        public.header,
        vec![0x4e; 283],
        "the sealed header, while the epoch row has none"
    );
    assert_eq!(public.receipt, result(3).receipt);
    assert_eq!(public.artifacts, vec![0xa7; 300]);
    assert_eq!(public.attestation, Some(vec![0xa5; 40]));
    assert_eq!(public.cosigs, result(3).cosigs);

    let (tape, next) = r.tape_page(MARKET, None, 10).await.unwrap();
    assert_eq!(next, None);
    assert_eq!(tape.len(), 1);
    assert_eq!(tape[0].epoch, 3);
    assert_eq!(tape[0].cutoff_ms, 40_000);
    assert_eq!(tape[0].phase, Phase::Aborting);
    assert_eq!(
        tape[0].clearing,
        vec![ClearingPrice {
            book: BookId::Single,
            tick: Tick(10_003),
            volume: Lots(6)
        }]
    );
    assert_eq!(
        (
            tape[0].matched_lots,
            tape[0].fill_count,
            tape[0].envelope_count
        ),
        (6, 2, 64)
    );
    assert_eq!(tape[0].terminal_at_ms, None);
    r.advance(
        MARKET,
        3,
        Phase::Aborted,
        EpochPatch {
            updated_at_ms: Some(77_000),
            ..EpochPatch::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        r.tape_page(MARKET, None, 10).await.unwrap().0[0].terminal_at_ms,
        Some(77_000)
    );

    r.confirm_order_state(MARKET, 3).await.unwrap();
    assert!(r.order_state(MARKET, 3).await.unwrap().unwrap().2);
    assert_eq!(
        r.confirm_order_state(MARKET, 4).await,
        Err(StoreError::Conflict(
            "no candidate order state for this epoch"
        ))
    );
    let fills: i64 = outside(&f.db())
        .query_row("SELECT count(*) FROM fills WHERE epoch = 3", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(fills, 2);
}

#[tokio::test]
async fn events_keep_their_sequences_across_pruning() {
    let f = node();
    let r = &f.repo;
    let ev = |topic: &str, at: u64| {
        (
            Some(MARKET),
            topic.to_owned(),
            at,
            format!("{{\"t\":\"{topic}\"}}"),
        )
    };
    let first = r
        .append_events(vec![
            ev("epochs", 1_000),
            ev("tape", 1_000),
            ev("epochs", 1_001),
        ])
        .await
        .unwrap();
    assert_eq!(first, vec![(1, 1), (2, 1), (3, 2)]);
    r.append_events(vec![(None, "status".into(), 1_002, "{}".into())])
        .await
        .unwrap();

    let all = r.events_since(0, Vec::new(), 100).await.unwrap();
    assert_eq!(
        all.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert_eq!(all[3].market, None);
    let epochs = r.events_since(1, vec!["epochs".into()], 100).await.unwrap();
    assert_eq!(
        epochs
            .iter()
            .map(|e| (e.seq, e.topic_seq))
            .collect::<Vec<_>>(),
        vec![(3, 2)]
    );
    let two = r
        .events_since(0, vec!["epochs".into(), "tape".into()], 2)
        .await
        .unwrap();
    assert_eq!(two.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(two[0].event, "{\"t\":\"epochs\"}");

    let retention = Retention {
        private_keep_epochs: 64,
        wallet_link_hours: 24,
        event_log_hours: 1,
    };
    let report = r
        .prune(MARKET, 1_002 + 2 * HOUR_MS, 0, retention)
        .await
        .unwrap();
    assert_eq!(report.rows_deleted, 4);
    assert!(r.events_since(0, Vec::new(), 100).await.unwrap().is_empty());
    // Neither sequence restarts once the log is empty.
    let after = r
        .append_events(vec![ev("epochs", 9_000_000)])
        .await
        .unwrap();
    assert_eq!(after, vec![(5, 3)]);
}

#[tokio::test]
async fn the_tx_journal_is_the_txs_table() {
    let f = node();
    let r = &f.repo;
    let rec = |op, sig: u8| TxRecord {
        id: None,
        market: MARKET,
        epoch: Some(3),
        op,
        signature: [sig; 64],
        last_valid_block_height: 500,
        sent_at_ms: 1_000 + u64::from(sig),
    };
    let commit = r.before_send(rec(TxOp::Commit, 1)).await.unwrap();
    let reveal = r.before_send(rec(TxOp::Reveal, 2)).await.unwrap();
    let post = r.before_send(rec(TxOp::Post, 3)).await.unwrap();
    let pending = r.pending().await.unwrap();
    assert_eq!(pending.len(), 3);
    assert_eq!(
        pending[0],
        TxRecord {
            id: Some(commit),
            ..rec(TxOp::Commit, 1)
        }
    );

    assert_eq!(r.last_landed_slot().await.unwrap(), 0);
    r.resolved(commit, TxOutcome::Landed { slot: 77 })
        .await
        .unwrap();
    r.resolved(
        reveal,
        TxOutcome::Failed {
            slot: 78,
            err: TxErrorDetail {
                ix_index: Some(1),
                custom: Some(6012),
                message: "custom program error".into(),
            },
        },
    )
    .await
    .unwrap();
    r.resolved(post, TxOutcome::Expired).await.unwrap();
    assert_eq!(r.last_landed_slot().await.unwrap(), 78);
    assert!(r.pending().await.unwrap().is_empty());
    assert!(r.resolved(999, TxOutcome::Expired).await.is_err());

    let txs = r.txs_for(MARKET, 3).await.unwrap();
    let summary: Vec<_> = txs
        .iter()
        .map(|t| (t.op.as_str(), t.status.as_str(), t.slot, t.error.clone()))
        .collect();
    assert_eq!(
        summary,
        vec![
            ("commit", "landed", Some(77), None),
            (
                "reveal",
                "failed",
                Some(78),
                Some("instruction 1, custom 6012: custom program error".to_owned())
            ),
            ("post", "expired", None, None),
        ]
    );
    assert_eq!(txs[0].signature, [1; 64]);
    assert_eq!(txs[0].last_valid_block_height, 500);
    assert!(r.txs_for(MARKET, 4).await.unwrap().is_empty());
}

#[tokio::test]
async fn wallet_link_purge() {
    let f = node();
    let r = &f.repo;
    let retention = Retention {
        private_keep_epochs: 64,
        wallet_link_hours: 24,
        event_log_hours: 24,
    };
    let s = session(1, session_pk(1)[0], 1);
    r.insert_session(s.clone(), 4).await.unwrap();
    // Epoch 1 ends at t = 10 h. Epoch 2 is still live. Epoch 3 is parked.
    closed_epoch(r, 1).await;
    r.insert_submission(submission(1, 1, 1)).await.unwrap();
    r.insert_submission(submission(1, 2, 2)).await.unwrap();
    r.advance(
        MARKET,
        1,
        Phase::Aborted,
        EpochPatch {
            updated_at_ms: Some(10 * HOUR_MS),
            ..EpochPatch::default()
        },
    )
    .await
    .unwrap();
    r.put_key_bundle(MARKET, 2, vec![2; 4], 1).await.unwrap();
    r.open_epoch(open_row(2), Vec::new()).await.unwrap();
    r.insert_submission(submission(2, 1, 1)).await.unwrap();
    r.insert_parked(vec![submission(3, 1, 1)]).await.unwrap();
    r.revoke_session(s.session_pk).await.unwrap();

    // 23 h after the end: kept.
    let early = r.prune(MARKET, 33 * HOUR_MS, 1, retention).await.unwrap();
    assert_eq!(early.wallets_nulled, 0);
    assert!(
        r.submissions(MARKET, 1)
            .await
            .unwrap()
            .iter()
            .all(|s| s.wallet.is_some())
    );

    // 24 h after the end: the terminal epoch's wallet links are gone.
    let due = r.prune(MARKET, 34 * HOUR_MS, 1, retention).await.unwrap();
    assert_eq!(due.wallets_nulled, 2);
    let purged = r.submissions(MARKET, 1).await.unwrap();
    assert_eq!(
        purged.len(),
        2,
        "the envelopes stay until private_keep_epochs"
    );
    for row in &purged {
        assert_eq!((row.wallet, row.session_pk), (None, None));
    }
    // Live and parked envelopes keep theirs, and so the session stays.
    assert_eq!(
        r.submissions(MARKET, 2).await.unwrap()[0].wallet,
        Some([1; 32])
    );
    assert_eq!(
        r.parked_for_epoch(MARKET, 3).await.unwrap()[0].wallet,
        Some([1; 32])
    );
    assert!(r.session(s.session_pk).await.unwrap().is_some());
    // A second prune finds nothing more to null.
    assert_eq!(
        r.prune(MARKET, 35 * HOUR_MS, 1, retention)
            .await
            .unwrap()
            .wallets_nulled,
        0
    );
    let in_file: i64 = outside(&f.db())
        .query_row(
            "SELECT count(*) FROM submissions WHERE epoch = 1 AND wallet IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(in_file, 0);

    // Once nothing links to the revoked session it goes as well.
    r.retract_parked(MARKET, [1; 32], c(1), 0).await.unwrap();
    r.advance(
        MARKET,
        2,
        Phase::Aborted,
        EpochPatch {
            updated_at_ms: Some(40 * HOUR_MS),
            ..EpochPatch::default()
        },
    )
    .await
    .unwrap();
    r.prune(MARKET, 64 * HOUR_MS, 2, retention).await.unwrap();
    assert_eq!(r.session(s.session_pk).await.unwrap(), None);
}

#[tokio::test]
async fn prune_deletes_private_rows_after_the_keep_window() {
    let f = node();
    let r = &f.repo;
    let retention = Retention {
        private_keep_epochs: 2,
        wallet_link_hours: 24,
        event_log_hours: 24,
    };
    for e in 1..=3 {
        closed_epoch(r, e).await;
        r.insert_submission(submission(e, 1, 1)).await.unwrap();
        r.put_snapshot(MARKET, e, vec![1], 1).await.unwrap();
        r.put_sealed(MARKET, e, [1; 283], vec![1]).await.unwrap();
        r.put_result(result(e)).await.unwrap();
        r.advance(MARKET, e, Phase::Aborted, EpochPatch::default())
            .await
            .unwrap();
    }
    r.replace_cover_carry(MARKET, 3, vec![(c(7), vec![7; 8])])
        .await
        .unwrap();
    r.ban(MARKET, [4; 32], 1, "x").await.unwrap();
    r.ban(MARKET, [5; 32], 9, "y").await.unwrap();
    r.use_nonce([1; 16], 100).await.unwrap();
    r.use_nonce([2; 16], 10_000).await.unwrap();

    // last_terminal 3, keep 2: epoch 1 goes, 2 and 3 stay.
    let report = r.prune(MARKET, 5_000, 3, retention).await.unwrap();
    // submissions, closed, snapshots, sealed of epoch 1. One expired ban.
    // One expired nonce.
    assert_eq!(report.rows_deleted, 6);
    assert!(r.submissions(MARKET, 1).await.unwrap().is_empty());
    assert_eq!(r.leaves(MARKET, 1).await.unwrap(), None);
    assert_eq!(r.snapshot(MARKET, 1).await.unwrap(), None);
    assert_eq!(r.sealed(MARKET, 1).await.unwrap(), None);
    assert_eq!(r.submissions(MARKET, 2).await.unwrap().len(), 1);
    assert!(r.leaves(MARKET, 2).await.unwrap().is_some());
    // Public rows are kept.
    assert!(r.epoch(MARKET, 1).await.unwrap().is_some());
    assert!(r.order_state(MARKET, 1).await.unwrap().is_some());
    assert!(!r.banned(MARKET, [4; 32], 1).await.unwrap());
    assert!(r.banned(MARKET, [5; 32], 9).await.unwrap());
    assert!(
        r.use_nonce([1; 16], 100).await.unwrap(),
        "an expired nonce row was dropped"
    );
    assert!(!r.use_nonce([2; 16], 10_000).await.unwrap());
    // Carried cover goes once the epoch it was last carried in is old enough.
    assert_eq!(r.cover_carry(MARKET, 10).await.unwrap().len(), 1);
    r.prune(MARKET, 5_000, 5, retention).await.unwrap();
    assert!(r.cover_carry(MARKET, 10).await.unwrap().is_empty());
    assert!(r.submissions(MARKET, 3).await.unwrap().is_empty());
}
