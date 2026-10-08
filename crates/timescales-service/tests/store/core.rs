//! The writer, its group commit and fail-stop, migrations, backups and WAL
//! checkpoints, on a real file.

use std::sync::mpsc;
use std::time::Duration;

use rusqlite::params;
use timescales_service::store::node::NodeRepo;
use timescales_service::store::{Schema, Store, StoreError, StoreOptions};

use crate::common::{
    MARKET, db_files, file_contains, node, open, opts, outside, session, submission, tables,
    wal_len,
};

fn count(store_path: &std::path::Path, table: &str) -> i64 {
    outside(store_path)
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn set_meta(
    k: &'static str,
    v: &'static [u8],
) -> impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(), StoreError> + Send + 'static {
    move |tx| {
        tx.execute(
            "INSERT INTO meta(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![k, v],
        )?;
        Ok(())
    }
}

#[tokio::test]
async fn an_acknowledged_write_is_committed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    let store = open(dir.path(), "node.sqlite", Schema::Node);
    store.write(set_meta("a", b"1")).await.unwrap();
    // Another connection, as another process would see the file.
    let v: Vec<u8> = outside(&path)
        .query_row("SELECT v FROM meta WHERE k = 'a'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, b"1");
    let read = store
        .read(|c| {
            Ok(c.query_row("SELECT v FROM meta WHERE k = 'a'", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })?)
        })
        .await
        .unwrap();
    assert_eq!(read, b"1");
    store.barrier().await.unwrap();
}

#[tokio::test]
async fn concurrent_writes_share_a_group_and_a_refusal_rolls_back_only_itself() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    let store = std::sync::Arc::new(
        Store::open(
            &path,
            Schema::Node,
            StoreOptions {
                group_commit_ms: 50,
                ..opts()
            },
        )
        .unwrap(),
    );
    let mut tasks = Vec::new();
    for i in 0..40u32 {
        let store = std::sync::Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            store
                .write(move |tx| {
                    tx.execute(
                        "INSERT INTO meta(k, v) VALUES (?1, ?2)",
                        params![format!("k{i}"), i.to_le_bytes()],
                    )?;
                    if i % 10 == 3 {
                        // Changes made before a refusal must not survive it.
                        return Err(StoreError::Conflict("refused on purpose"));
                    }
                    Ok(i)
                })
                .await
        }));
    }
    for (i, task) in (0u32..).zip(tasks) {
        let result = task.await.unwrap();
        if i % 10 == 3 {
            assert_eq!(result, Err(StoreError::Conflict("refused on purpose")));
        } else {
            assert_eq!(result, Ok(i));
        }
    }
    assert!(!store.is_closed());
    assert_eq!(count(&path, "meta"), 36);
    let refused: i64 = outside(&path)
        .query_row(
            "SELECT count(*) FROM meta WHERE k IN ('k3', 'k13', 'k23', 'k33')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(refused, 0);
}

#[tokio::test]
async fn fail_stop_on_write_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    let store = std::sync::Arc::new(
        Store::open(
            &path,
            Schema::Node,
            StoreOptions {
                group_commit_ms: 2_000,
                ..opts()
            },
        )
        .unwrap(),
    );
    store.write(set_meta("before", b"1")).await.unwrap();

    // Two writes in one group: the first is fine, the second fails in
    // SQLite. The first is still committed. The second is not.
    let first = {
        let store = std::sync::Arc::clone(&store);
        tokio::spawn(async move { store.write(set_meta("same-group", b"2")).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let failing = store
        .write(|tx| {
            tx.execute("INSERT INTO meta(k, v) VALUES ('doomed', x'00')", [])?;
            tx.execute("INSERT INTO no_such_table VALUES (1)", [])?;
            Ok(())
        })
        .await;
    assert!(matches!(failing, Err(StoreError::Sqlite(_))), "{failing:?}");
    assert_eq!(first.await.unwrap(), Ok(()));

    // Closed for good: writes, reads, barriers, backups and checkpoints.
    assert!(store.is_closed());
    assert_eq!(
        store.write(set_meta("after", b"3")).await,
        Err(StoreError::Closed)
    );
    assert_eq!(store.read(|_| Ok(())).await, Err(StoreError::Closed));
    assert_eq!(store.barrier().await, Err(StoreError::Closed));
    assert_eq!(store.checkpoint_truncate().await, Err(StoreError::Closed));
    assert_eq!(
        store
            .backup_to(dir.path().join("copy.sqlite"), &[])
            .await
            .map(|_| ()),
        Err(StoreError::Closed)
    );

    let keys: Vec<String> = {
        let conn = outside(&path);
        let mut st = conn.prepare("SELECT k FROM meta ORDER BY k").unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(keys, vec!["before".to_owned(), "same-group".to_owned()]);
}

#[tokio::test]
async fn a_panicking_write_closes_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path(), "dealer.sqlite", Schema::Dealer);
    let result = store
        .write(|_| -> Result<(), StoreError> { panic!("write closure bug") })
        .await;
    assert!(
        matches!(result, Err(StoreError::Sqlite(ref m)) if m.contains("panicked")),
        "{result:?}"
    );
    assert!(store.is_closed());
    assert_eq!(store.barrier().await, Err(StoreError::Closed));
}

#[tokio::test]
async fn a_refused_write_keeps_the_store_open() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path(), "node.sqlite", Schema::Node);
    for refusal in [
        StoreError::Conflict("no"),
        StoreError::Corrupt("bad row"),
        StoreError::Full,
    ] {
        let expected = refusal.clone();
        let result = store
            .write(move |_| -> Result<(), StoreError> { Err(refusal) })
            .await;
        assert_eq!(result, Err(expected));
    }
    assert!(!store.is_closed());
    store.write(set_meta("k", b"v")).await.unwrap();
}

#[tokio::test]
async fn a_full_queue_is_reported_not_waited_on() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        &dir.path().join("node.sqlite"),
        Schema::Node,
        StoreOptions {
            queue: 1,
            group_commit_ms: 0,
            ..opts()
        },
    )
    .unwrap();
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();

    // The writer takes this job and blocks inside it.
    let mut blocking = std::pin::pin!(store.write(move |_| {
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        Ok(1)
    }));
    assert!(
        tokio::time::timeout(Duration::ZERO, &mut blocking)
            .await
            .is_err()
    );
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();

    // The next job fills the queue of one. The one after it is refused.
    let mut queued = std::pin::pin!(store.write(|_| Ok(2)));
    assert!(
        tokio::time::timeout(Duration::ZERO, &mut queued)
            .await
            .is_err()
    );
    assert_eq!(store.write(|_| Ok(3)).await, Err(StoreError::Full));

    release_tx.send(()).unwrap();
    assert_eq!(blocking.await, Ok(1));
    assert_eq!(queued.await, Ok(2));
    assert!(!store.is_closed());
}

#[tokio::test]
async fn queue_depth_counts_the_writes_waiting_for_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        &dir.path().join("node.sqlite"),
        Schema::Node,
        StoreOptions {
            group_commit_ms: 0,
            ..opts()
        },
    )
    .unwrap();
    assert_eq!(store.queue_depth(), 0);
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let mut blocking = std::pin::pin!(store.write(move |_| {
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        Ok(0)
    }));
    assert!(
        tokio::time::timeout(Duration::ZERO, &mut blocking)
            .await
            .is_err()
    );
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    // The write being applied is not waiting. The two behind it are.
    assert_eq!(store.queue_depth(), 0);
    let mut queued = Vec::new();
    for i in 1..=2 {
        let mut write = Box::pin(store.write(move |_| Ok(i)));
        assert!(
            tokio::time::timeout(Duration::ZERO, &mut write)
                .await
                .is_err()
        );
        queued.push(write);
    }
    assert_eq!(store.queue_depth(), 2);
    release_tx.send(()).unwrap();
    assert_eq!(blocking.await, Ok(0));
    for (i, write) in (1..).zip(queued) {
        assert_eq!(write.await, Ok(i));
    }
    assert_eq!(store.queue_depth(), 0);
}

#[tokio::test]
async fn the_commit_observer_sees_every_committed_group() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path(), "node.sqlite", Schema::Node);
    let groups = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = std::sync::Arc::clone(&groups);
    store.set_commit_observer(move |took, writes| seen.lock().unwrap().push((took, writes)));
    for _ in 0..8 {
        store.write(set_meta("k", b"v")).await.unwrap();
    }
    // A refused write is rolled back alone. Its group still commits.
    assert!(
        store
            .write(|_| -> Result<(), StoreError> { Err(StoreError::Conflict("no")) })
            .await
            .is_err()
    );
    let groups = groups.lock().unwrap().clone();
    assert_eq!(groups.iter().map(|(_, n)| n).sum::<usize>(), 9);
    assert!(groups.iter().all(|(_, n)| *n >= 1));
}

#[tokio::test]
async fn future_schema_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    drop(open(dir.path(), "node.sqlite", Schema::Node));
    outside(&path)
        .pragma_update(None, "user_version", 7)
        .unwrap();
    let err = Store::open(&path, Schema::Node, opts()).unwrap_err();
    assert_eq!(err, StoreError::FutureSchema { have: 7, max: 1 });
    // Refused before anything was copied or migrated.
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("pre-migrate")
    }));
    let have: i64 = outside(&path)
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(have, 7);
}

#[tokio::test]
async fn a_file_of_another_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    drop(open(dir.path(), "node.sqlite", Schema::Node));
    for other in [Schema::Member, Schema::MemberShares, Schema::Dealer] {
        let err = Store::open(&path, other, opts()).unwrap_err();
        assert_eq!(
            err,
            StoreError::Conflict("database file belongs to another schema")
        );
    }
    // A database someone else created without a schema version.
    let foreign = dir.path().join("foreign.sqlite");
    outside(&foreign)
        .execute_batch("CREATE TABLE t(x)")
        .unwrap();
    assert_eq!(
        Store::open(&foreign, Schema::Node, opts()).unwrap_err(),
        StoreError::Conflict("database has tables but no schema version")
    );
}

#[tokio::test]
async fn reopening_keeps_the_data_and_the_version() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path(), "member.sqlite", Schema::Member);
    assert_eq!(store.schema_version(), 1);
    store.write(set_meta("identity_pub", b"key")).await.unwrap();
    drop(store);
    let store = open(dir.path(), "member.sqlite", Schema::Member);
    assert_eq!(store.schema_version(), 1);
    let v = store
        .read(|c| Ok(c.query_row("SELECT v FROM meta", [], |r| r.get::<_, Vec<u8>>(0))?))
        .await
        .unwrap();
    assert_eq!(v, b"key");
}

#[tokio::test]
async fn backup_strips_private_tables() {
    let f = node();
    let private = submission(3, 0xc7, 9);
    f.repo.insert_submission(private.clone()).await.unwrap();
    f.repo
        .insert_session(session(9, 0x91, 1_000), 4)
        .await
        .unwrap();
    f.repo
        .ban(MARKET, [9; 32], 10, "unauthenticated")
        .await
        .unwrap();
    f.repo
        .put_key_bundle(MARKET, 3, vec![0xb0; 300], 1)
        .await
        .unwrap();
    f.repo
        .set_meta("stream_id", b"stream-1".to_vec())
        .await
        .unwrap();

    let dest = f.dir.path().join("backups").join("node-nightly.sqlite");
    std::fs::create_dir(dest.parent().unwrap()).unwrap();
    let report = f.repo.backup(dest.clone()).await.unwrap();
    assert!(report.integrity_ok);
    assert_eq!(report.path, dest);
    assert_eq!(report.bytes, std::fs::metadata(&dest).unwrap().len());
    assert_eq!(
        report.stripped,
        timescales_service::store::node::PRIVATE_TABLES.to_vec()
    );

    let kept = tables(&dest);
    for private_table in timescales_service::store::node::PRIVATE_TABLES {
        assert!(
            !kept.contains(&(*private_table).to_owned()),
            "{private_table} kept"
        );
    }
    for public in [
        "epochs",
        "meta",
        "key_bundles",
        "results",
        "fills",
        "events",
        "txs",
    ] {
        assert!(kept.contains(&public.to_owned()), "{public} missing");
    }
    // No page of a dropped table survives, and the copy stands alone.
    assert!(!file_contains(&dest, &private.submission));
    assert!(!file_contains(&dest, &[0x91; 64]));
    assert!(!db_files(&dest)[1].exists());
    let conn = outside(&dest);
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    let stream: Vec<u8> = conn
        .query_row("SELECT v FROM meta WHERE k = 'stream_id'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stream, b"stream-1");

    // The live database still has everything.
    assert_eq!(f.repo.submissions(MARKET, 3).await.unwrap(), vec![private]);
}

#[tokio::test]
async fn a_backup_replaces_an_older_copy_and_runs_beside_writes() {
    let dir = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(open(dir.path(), "member.sqlite", Schema::Member));
    store.write(set_meta("v", b"old")).await.unwrap();
    let dest = dir.path().join("member-backup.sqlite");
    store.backup_to(dest.clone(), &[]).await.unwrap();

    let writer = {
        let store = std::sync::Arc::clone(&store);
        tokio::spawn(async move {
            for i in 0..50u32 {
                store
                    .write(move |tx| {
                        tx.execute(
                            "INSERT INTO meta(k, v) VALUES (?1, x'01')",
                            [format!("w{i}")],
                        )?;
                        Ok(())
                    })
                    .await
                    .unwrap();
            }
        })
    };
    store.write(set_meta("v", b"new")).await.unwrap();
    let report = store.backup_to(dest.clone(), &[]).await.unwrap();
    writer.await.unwrap();
    assert!(report.integrity_ok);
    assert!(report.stripped.is_empty());
    let v: Vec<u8> = outside(&dest)
        .query_row("SELECT v FROM meta WHERE k = 'v'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, b"new");
}

#[tokio::test]
async fn shares_are_never_backed_up() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path(), "shares.sqlite", Schema::MemberShares);
    let dest = dir.path().join("shares-copy.sqlite");
    assert_eq!(
        store.backup_to(dest.clone(), &[]).await.map(|_| ()),
        Err(StoreError::Conflict("shares.sqlite is never backed up"))
    );
    assert!(!dest.exists());
    // A refusal, not a write error.
    assert!(!store.is_closed());
}

#[tokio::test]
async fn backup_refuses_a_table_name_that_is_not_an_identifier() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path(), "node.sqlite", Schema::Node);
    let dest = dir.path().join("copy.sqlite");
    let result = store
        .backup_to(dest.clone(), &["meta; DROP TABLE epochs"])
        .await;
    assert!(matches!(result, Err(StoreError::Sqlite(_))), "{result:?}");
    assert!(!dest.exists());
}

#[tokio::test]
async fn checkpoint_truncate_empties_the_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    let store = open(dir.path(), "node.sqlite", Schema::Node);
    for i in 0..20u32 {
        store
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO meta(k, v) VALUES (?1, zeroblob(4096))",
                    [format!("k{i}")],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }
    assert!(wal_len(&path) > 0);
    store.checkpoint_truncate().await.unwrap();
    assert_eq!(wal_len(&path), 0);
    assert_eq!(count(&path, "meta"), 20);
}

#[tokio::test]
async fn checkpoint_reports_a_reader_that_blocks_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    let store = Store::open(
        &path,
        Schema::Node,
        StoreOptions {
            busy_timeout_ms: 100,
            ..opts()
        },
    )
    .unwrap();
    store.write(set_meta("a", b"1")).await.unwrap();
    // A reader outside the store holds a snapshot of the WAL.
    let reader = outside(&path);
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader
        .query_row("SELECT count(*) FROM meta", [], |r| r.get(0))
        .unwrap();
    store.write(set_meta("b", b"2")).await.unwrap();
    let blocked = store.checkpoint_truncate().await;
    assert!(
        matches!(blocked, Err(StoreError::Sqlite(ref m)) if m.contains("blocked")),
        "{blocked:?}"
    );
    // Not a write error: the store stays open.
    assert!(!store.is_closed());
    reader.execute_batch("COMMIT").unwrap();
    store.checkpoint_truncate().await.unwrap();
    assert_eq!(wal_len(&path), 0);
}

#[test]
#[should_panic(expected = "NodeRepo needs node.sqlite")]
fn a_repository_checks_its_schema() {
    let dir = tempfile::tempdir().unwrap();
    let _ = NodeRepo::new(open(dir.path(), "dealer.sqlite", Schema::Dealer));
}
