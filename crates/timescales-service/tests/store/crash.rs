//! Crash durability: a child process writes through the store and prints
//! every acknowledged write. The parent SIGKILLs it mid-stream and checks
//! that each acknowledged write is in the reopened database.
//!
//! SIGKILL ends the process, not the machine: what the OS already holds
//! survives it. The test shows that the store acknowledges a
//! write only after its transaction committed, and that the file recovers
//! cleanly from any point. Durability across power loss rests on
//! `synchronous = FULL` and is not exercised here.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use timescales_core::{Hash32, OrderCommitment};
use timescales_service::store::node::{NodeRepo, SubmissionRow};
use timescales_service::store::{Schema, Store, StoreOptions};

use crate::common::{MARKET, outside};

const CHILD_DB: &str = "TIMESCALES_STORE_CRASH_DB";
const CHILD_ROUND: &str = "TIMESCALES_STORE_CRASH_ROUND";
const WRITERS: u32 = 8;
const ROUNDS: u32 = 3;
/// Acknowledgements the parent waits for before it kills the child.
const KILL_AFTER: usize = 2_000;

fn row(id: u32) -> SubmissionRow {
    let mut c = [0u8; 32];
    c[..4].copy_from_slice(&id.to_le_bytes());
    SubmissionRow {
        market: MARKET,
        epoch: 1,
        commitment: OrderCommitment(c),
        envelope_digest: Hash32([0xee; 32]),
        wallet: Some([0x77; 32]),
        session_pk: None,
        submission: id.to_le_bytes().repeat(96),
        promise: vec![0x55; 201],
        received_at_ms: u64::from(id),
    }
}

fn id_of(c: &OrderCommitment) -> u32 {
    u32::from_le_bytes(c.0[..4].try_into().unwrap())
}

fn options() -> StoreOptions {
    StoreOptions {
        group_commit_ms: 2,
        readers: 1,
        ..StoreOptions::default()
    }
}

/// The child: `WRITERS` tasks write until the process is killed and print
/// `ack <id>` once each write is acknowledged.
#[test]
#[ignore = "the child half of crash_durability"]
fn crash_child() {
    let Some(db) = std::env::var_os(CHILD_DB) else {
        return;
    };
    let round: u32 = std::env::var(CHILD_ROUND).unwrap().parse().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let repo = Arc::new(NodeRepo::new(
            Store::open(Path::new(&db), Schema::Node, options()).unwrap(),
        ));
        let mut tasks = Vec::new();
        for w in 0..WRITERS {
            let repo = Arc::clone(&repo);
            tasks.push(tokio::spawn(async move {
                // Runs until the parent kills the process.
                for i in 0..1u32 << 20 {
                    let id = round << 28 | w << 20 | i;
                    repo.insert_submission(row(id)).await.unwrap();
                    println!("ack {id}");
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    });
}

#[test]
fn crash_durability() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("node.sqlite");
    let mut acked = BTreeSet::new();
    for round in 0..ROUNDS {
        let err_log = dir.path().join(format!("child-{round}.err"));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "crash::crash_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_DB, &db)
            .env(CHILD_ROUND, round.to_string())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(&err_log).unwrap())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut this_round = 0;
        while this_round < KILL_AFTER {
            assert!(
                Instant::now() < deadline,
                "child wrote too slowly: {}",
                std::fs::read_to_string(&err_log).unwrap_or_default()
            );
            let Some(line) = lines.next() else {
                panic!(
                    "child exited early: {}",
                    std::fs::read_to_string(&err_log).unwrap_or_default()
                );
            };
            if let Some(id) = line.unwrap().strip_prefix("ack ") {
                acked.insert(id.parse::<u32>().unwrap());
                this_round += 1;
            }
        }
        // `kill` is SIGKILL: no destructor, no final commit, no checkpoint.
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(9), "{status:?}");
        // Acknowledgements printed before the kill are still in the pipe.
        for line in lines {
            if let Some(id) = line.unwrap().strip_prefix("ack ") {
                acked.insert(id.parse::<u32>().unwrap());
            }
        }

        let check: String = outside(&db)
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(check, "ok");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let stored: BTreeSet<u32> = rt.block_on(async {
            let repo = NodeRepo::new(Store::open(&db, Schema::Node, options()).unwrap());
            let rows = repo.submissions(MARKET, 1).await.unwrap();
            for r in &rows {
                assert_eq!(*r, row(id_of(&r.commitment)), "a torn row");
            }
            rows.iter().map(|r| id_of(&r.commitment)).collect()
        });
        let lost: Vec<_> = acked.difference(&stored).collect();
        assert!(
            lost.is_empty(),
            "round {round}: acknowledged writes lost: {lost:?}"
        );
    }
    assert!(acked.len() >= KILL_AFTER * usize::try_from(ROUNDS).unwrap());
}
