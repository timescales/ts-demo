//! One database file: migrations, the writer thread with group commit, the
//! pool of read-only connections, online backups and WAL checkpoints.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use tokio::sync::oneshot;

use crate::store::{BackupReport, Schema, StoreError, StoreOptions};

/// One database file: a writer on a dedicated `std::thread` fed by a
/// bounded channel, and a pool of read-only connections.
pub struct Store {
    shared: Arc<Shared>,
    writer: Option<SyncSender<Job>>,
    readers: Option<SyncSender<ReadJob>>,
    threads: Vec<JoinHandle<()>>,
}

/// Called by the writer after each committed group with the group's
/// duration and number of writes.
type CommitObserver = Arc<dyn Fn(Duration, usize) + Send + Sync>;

struct Shared {
    path: PathBuf,
    schema: Schema,
    version: u32,
    busy_timeout: Duration,
    closed: AtomicBool,
    /// Jobs sent to the writer that it has not taken yet.
    queued: AtomicUsize,
    observer: Mutex<Option<CommitObserver>>,
}

impl Shared {
    /// Fail-stop: no write, read, backup or checkpoint is accepted after
    /// this.
    fn fail(&self, error: &StoreError) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            tracing::error!(
                path = %self.path.display(),
                schema = self.schema.name(),
                %error,
                "write failed; the store is closed"
            );
        }
    }
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.shared.path)
            .field("schema", &self.shared.schema)
            .field("version", &self.shared.version)
            .field("closed", &self.is_closed())
            .finish()
    }
}

enum Job {
    Write(Box<dyn WriteJob>),
    Checkpoint(oneshot::Sender<Result<(), StoreError>>),
}

type ReadJob = Box<dyn FnOnce(&Connection) + Send>;

/// Called with the result of the group's commit.
type Finish = Box<dyn FnOnce(Result<(), StoreError>) + Send>;

/// What a write did inside its savepoint.
enum Outcome {
    /// Kept. Acknowledged once the group commits.
    Applied,
    /// The closure refused the write. Its changes were rolled back.
    Refused,
    /// SQLite failed or the closure panicked: fail-stop.
    Failed(StoreError),
}

trait WriteJob: Send {
    fn run(self: Box<Self>, tx: &Transaction<'_>) -> (Outcome, Finish);
    fn reject(self: Box<Self>, error: StoreError);
}

struct PendingWrite<F, T> {
    f: F,
    reply: oneshot::Sender<Result<T, StoreError>>,
}

impl<F, T> WriteJob for PendingWrite<F, T>
where
    F: FnOnce(&Transaction<'_>) -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    fn run(self: Box<Self>, tx: &Transaction<'_>) -> (Outcome, Finish) {
        let PendingWrite { f, reply } = *self;
        let result = panic::catch_unwind(AssertUnwindSafe(|| f(tx)))
            .unwrap_or_else(|_| Err(StoreError::Sqlite("a write closure panicked".to_owned())));
        let outcome = match &result {
            Ok(_) => Outcome::Applied,
            Err(e @ StoreError::Sqlite(_)) => Outcome::Failed(e.clone()),
            Err(_) => Outcome::Refused,
        };
        let finish: Finish = Box::new(move |commit| {
            let _ = reply.send(result.and_then(|v| commit.map(|()| v)));
        });
        (outcome, finish)
    }

    fn reject(self: Box<Self>, error: StoreError) {
        let _ = self.reply.send(Err(error));
    }
}

/// How the writer batches writes into one transaction.
#[derive(Clone, Copy)]
struct GroupPolicy {
    window: Duration,
    max: usize,
}

impl Store {
    /// Runs migrations. Takes a `VACUUM INTO` copy before migrating.
    pub fn open(path: &Path, schema: Schema, opts: StoreOptions) -> Result<Self, StoreError> {
        Self::open_with(path, schema, schema.migrations(), opts)
    }

    pub(crate) fn open_with(
        path: &Path,
        schema: Schema,
        migrations: &[&str],
        opts: StoreOptions,
    ) -> Result<Self, StoreError> {
        let busy_timeout = Duration::from_millis(opts.busy_timeout_ms);
        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(busy_timeout)?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Sqlite(format!(
                "{}: journal mode is {mode}, not wal",
                path.display()
            )));
        }
        let synchronous = if opts.synchronous_full {
            "FULL"
        } else {
            "NORMAL"
        };
        conn.pragma_update(None, "synchronous", synchronous)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "trusted_schema", "OFF")?;
        if opts.secure_delete || schema == Schema::MemberShares {
            conn.pragma_update(None, "secure_delete", "ON")?;
        }
        let version = migrate(&mut conn, path, schema, migrations)?;

        let shared = Arc::new(Shared {
            path: path.to_path_buf(),
            schema,
            version,
            busy_timeout,
            closed: AtomicBool::new(false),
            queued: AtomicUsize::new(0),
            observer: Mutex::new(None),
        });
        let mut threads = Vec::new();
        let (read_tx, read_rx) = mpsc::sync_channel::<ReadJob>(opts.queue.max(1));
        let read_rx = Arc::new(Mutex::new(read_rx));
        for i in 0..opts.readers.max(1) {
            let conn = open_reader(path, busy_timeout)?;
            let jobs = Arc::clone(&read_rx);
            threads.push(spawn(format!("store-read-{i}"), move || {
                run_reader(&conn, &jobs);
            })?);
        }
        let (write_tx, write_rx) = mpsc::sync_channel::<Job>(opts.queue.max(1));
        let policy = GroupPolicy {
            window: Duration::from_millis(opts.group_commit_ms),
            max: opts.group_commit_max.max(1),
        };
        let writer_shared = Arc::clone(&shared);
        threads.push(spawn("store-write".to_owned(), move || {
            run_writer(conn, &write_rx, &writer_shared, policy);
        })?);
        Ok(Store {
            shared,
            writer: Some(write_tx),
            readers: Some(read_tx),
            threads,
        })
    }

    /// Runs `f` in the writer's transaction and returns once the group it
    /// belongs to is committed. `Full` when the write queue is full. The
    /// caller decides how long to wait and retry.
    pub async fn write<T: Send + 'static>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        self.check_open()?;
        let (reply, rx) = oneshot::channel();
        self.send(Job::Write(Box::new(PendingWrite { f, reply })))?;
        rx.await.unwrap_or(Err(StoreError::Closed))
    }

    /// Runs `f` on a read-only connection inside one read transaction, so
    /// everything `f` reads comes from one snapshot.
    pub async fn read<T: Send + 'static>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        self.check_open()?;
        let (reply, rx) = oneshot::channel();
        let job: ReadJob = Box::new(move |conn: &Connection| {
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                let snapshot = conn.unchecked_transaction()?;
                f(&snapshot)
            }))
            .unwrap_or_else(|_| Err(StoreError::Sqlite("a read closure panicked".to_owned())));
            let _ = reply.send(result);
        });
        let readers = self.readers.as_ref().ok_or(StoreError::Closed)?;
        readers.try_send(job).map_err(|e| match e {
            TrySendError::Full(_) => StoreError::Full,
            TrySendError::Disconnected(_) => StoreError::Closed,
        })?;
        rx.await.unwrap_or(Err(StoreError::Closed))
    }

    /// All earlier writes are durable.
    pub async fn barrier(&self) -> Result<(), StoreError> {
        self.write(|_| Ok(())).await
    }

    /// `rusqlite::backup` + `integrity_check` of the copy. `strip` lists
    /// tables dropped from the copy before it is returned.
    ///
    /// The copy is a consistent snapshot taken on its own connection, so
    /// writes carry on meanwhile. Dropped tables are vacuumed out, so none of
    /// their pages survive in the file. `dest` is replaced atomically.
    /// `shares.sqlite` is never backed up.
    pub async fn backup_to(
        &self,
        dest: PathBuf,
        strip: &'static [&'static str],
    ) -> Result<BackupReport, StoreError> {
        self.check_open()?;
        if self.shared.schema == Schema::MemberShares {
            return Err(StoreError::Conflict("shares.sqlite is never backed up"));
        }
        let (reply, rx) = oneshot::channel();
        let shared = Arc::clone(&self.shared);
        spawn("store-backup".to_owned(), move || {
            let _ = reply.send(backup(&shared, &dest, strip));
        })?;
        rx.await.unwrap_or(Err(StoreError::Closed))
    }

    /// `PRAGMA wal_checkpoint(TRUNCATE)`.
    ///
    /// Runs on the writer between groups, so every earlier write is in the
    /// database file and the WAL is empty afterwards. An error when a reader
    /// kept the checkpoint from completing.
    pub async fn checkpoint_truncate(&self) -> Result<(), StoreError> {
        self.check_open()?;
        let (reply, rx) = oneshot::channel();
        self.send(Job::Checkpoint(reply))?;
        rx.await.unwrap_or(Err(StoreError::Closed))
    }

    pub fn schema_version(&self) -> u32 {
        self.shared.version
    }

    /// Writes and checkpoints waiting for the writer thread. The ones in
    /// the group it is applying are not counted.
    pub fn queue_depth(&self) -> usize {
        self.shared.queued.load(Ordering::Acquire)
    }

    /// Replaces the function the writer calls after each committed group,
    /// with the time from opening the group's transaction to the end of
    /// its commit, and the number of writes in it. It runs on the writer
    /// thread, so it should only record the values.
    pub fn set_commit_observer(&self, observer: impl Fn(Duration, usize) + Send + Sync + 'static) {
        *self.shared.observer.lock() = Some(Arc::new(observer));
    }

    /// True after a write error (fail-stop). Every call then returns
    /// [`StoreError::Closed`].
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    pub(crate) fn schema(&self) -> Schema {
        self.shared.schema
    }

    fn check_open(&self) -> Result<(), StoreError> {
        if self.is_closed() {
            Err(StoreError::Closed)
        } else {
            Ok(())
        }
    }

    fn send(&self, job: Job) -> Result<(), StoreError> {
        let writer = self.writer.as_ref().ok_or(StoreError::Closed)?;
        // Counted before it is sent, so the writer never takes a job it has
        // not been counted for.
        self.shared.queued.fetch_add(1, Ordering::AcqRel);
        writer.try_send(job).map_err(|e| {
            self.shared.queued.fetch_sub(1, Ordering::AcqRel);
            match e {
                TrySendError::Full(_) => StoreError::Full,
                TrySendError::Disconnected(_) => StoreError::Closed,
            }
        })
    }
}

impl Drop for Store {
    /// Lets queued writes finish and closes every connection.
    fn drop(&mut self) {
        self.writer.take();
        self.readers.take();
        let me = thread::current().id();
        for handle in self.threads.drain(..) {
            if handle.thread().id() != me {
                let _ = handle.join();
            }
        }
    }
}

fn spawn(name: String, f: impl FnOnce() + Send + 'static) -> Result<JoinHandle<()>, StoreError> {
    thread::Builder::new()
        .name(name.clone())
        .spawn(f)
        .map_err(|e| StoreError::Sqlite(format!("spawning thread {name}: {e}")))
}

fn open_reader(path: &Path, busy_timeout: Duration) -> Result<Connection, StoreError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(busy_timeout)?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(conn)
}

fn run_reader(conn: &Connection, jobs: &Mutex<Receiver<ReadJob>>) {
    loop {
        let job = jobs.lock().recv();
        match job {
            Ok(job) => job(conn),
            Err(_) => return,
        }
    }
}

fn run_writer(mut conn: Connection, jobs: &Receiver<Job>, shared: &Shared, policy: GroupPolicy) {
    let mut next = None;
    loop {
        let job = match next.take() {
            Some(job) => job,
            None => match jobs.recv() {
                Ok(job) => {
                    shared.queued.fetch_sub(1, Ordering::AcqRel);
                    job
                }
                Err(_) => return,
            },
        };
        match job {
            Job::Checkpoint(reply) => {
                let _ = reply.send(checkpoint(&conn));
            }
            Job::Write(first) => {
                next = commit_group(&mut conn, jobs, shared, policy, first);
                if shared.closed.load(Ordering::SeqCst) {
                    // Queued jobs are dropped with the receiver. Their callers
                    // see `Closed`.
                    return;
                }
            }
        }
    }
}

enum GroupState {
    Healthy,
    /// A write failed and was rolled back. Commit the rest, then close.
    Failing(StoreError),
    /// The transaction itself is unusable. Roll everything back and close.
    Broken(StoreError),
}

/// Applies `first` and every write that arrives within the group window (at
/// most `policy.max`), each in its own savepoint, and commits once. Returns
/// the job that ended the group if it was not a write.
fn commit_group(
    conn: &mut Connection,
    jobs: &Receiver<Job>,
    shared: &Shared,
    policy: GroupPolicy,
    first: Box<dyn WriteJob>,
) -> Option<Job> {
    let started = Instant::now();
    let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(e) => {
            let error = StoreError::from(e);
            shared.fail(&error);
            first.reject(error);
            return None;
        }
    };
    let mut finishes = Vec::new();
    let mut state = GroupState::Healthy;
    apply(&tx, first, &mut finishes, &mut state);

    let deadline = Instant::now() + policy.window;
    let mut ended_by = None;
    while matches!(state, GroupState::Healthy) && finishes.len() < policy.max {
        let job = match jobs.try_recv() {
            Ok(job) => job,
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                match jobs.recv_timeout(left) {
                    Ok(job) => job,
                    Err(_) => break,
                }
            }
        };
        shared.queued.fetch_sub(1, Ordering::AcqRel);
        match job {
            Job::Write(write) => apply(&tx, write, &mut finishes, &mut state),
            other => {
                ended_by = Some(other);
                break;
            }
        }
    }

    let commit = match state {
        GroupState::Broken(error) => {
            drop(tx);
            shared.fail(&error);
            Err(error)
        }
        GroupState::Failing(error) => {
            shared.fail(&error);
            tx.commit().map_err(StoreError::from)
        }
        GroupState::Healthy => tx.commit().map_err(|e| {
            let error = StoreError::from(e);
            shared.fail(&error);
            error
        }),
    };
    let took = started.elapsed();
    let writes = finishes.len();
    let committed = commit.is_ok();
    for finish in finishes {
        finish(commit.clone());
    }
    // After the acknowledgements, so observing never delays a write.
    if committed {
        let observer = shared.observer.lock().clone();
        if let Some(observe) = observer {
            observe(took, writes);
        }
    }
    ended_by
}

/// Runs one write inside a savepoint of the group's transaction.
fn apply(
    tx: &Transaction<'_>,
    job: Box<dyn WriteJob>,
    finishes: &mut Vec<Finish>,
    state: &mut GroupState,
) {
    if let Err(e) = tx.execute_batch("SAVEPOINT store_write") {
        let error = StoreError::from(e);
        job.reject(error.clone());
        *state = GroupState::Broken(error);
        return;
    }
    let (outcome, finish) = job.run(tx);
    finishes.push(finish);
    if tx.is_autocommit() {
        *state = GroupState::Broken(StoreError::Sqlite(
            "a write closure ended the group's transaction".to_owned(),
        ));
        return;
    }
    let end = match outcome {
        Outcome::Applied => tx.execute_batch("RELEASE store_write"),
        Outcome::Refused | Outcome::Failed(_) => {
            tx.execute_batch("ROLLBACK TO store_write; RELEASE store_write")
        }
    };
    if let Err(e) = end {
        *state = GroupState::Broken(StoreError::from(e));
    } else if let Outcome::Failed(error) = outcome {
        *state = GroupState::Failing(error);
    }
}

fn checkpoint(conn: &Connection) -> Result<(), StoreError> {
    let (busy, frames, done): (i64, i64, i64) =
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if busy != 0 {
        return Err(StoreError::Sqlite(format!(
            "wal_checkpoint(TRUNCATE) blocked by a reader ({done} of {frames} frames copied)"
        )));
    }
    Ok(())
}

/// Brings the file to the schema's latest version in one transaction.
fn migrate(
    conn: &mut Connection,
    path: &Path,
    schema: Schema,
    migrations: &[&str],
) -> Result<u32, StoreError> {
    let max =
        u32::try_from(migrations.len()).map_err(|_| StoreError::Corrupt("too many migrations"))?;
    let have: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let have = u32::try_from(have).map_err(|_| StoreError::Corrupt("negative user_version"))?;
    if have > max {
        return Err(StoreError::FutureSchema { have, max });
    }
    if have == 0 {
        let objects: i64 =
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
        if objects > 0 {
            return Err(StoreError::Conflict(
                "database has tables but no schema version",
            ));
        }
    } else {
        let id: i32 = conn.pragma_query_value(None, "application_id", |row| row.get(0))?;
        if id != schema.application_id() {
            return Err(StoreError::Conflict(
                "database file belongs to another schema",
            ));
        }
    }
    if have == max {
        return Ok(max);
    }
    // A fresh file has nothing to keep, and shares are never copied.
    if have > 0 && schema != Schema::MemberShares {
        pre_migrate_copy(conn, path, have, max)?;
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
    for (version, sql) in (1u32..).zip(migrations).filter(|(v, _)| *v > have) {
        tx.execute_batch(sql).map_err(|e| {
            StoreError::Sqlite(format!("{} migration {version}: {e}", schema.name()))
        })?;
    }
    tx.pragma_update(None, "application_id", schema.application_id())?;
    tx.pragma_update(None, "user_version", max)?;
    tx.commit()?;
    tracing::info!(path = %path.display(), schema = schema.name(), from = have, to = max, "migrated");
    Ok(max)
}

/// `VACUUM INTO <dir>/pre-migrate-<from>-<to>.sqlite`: rolling back a
/// migration is restoring this copy.
pub(crate) fn pre_migrate_copy(
    conn: &Connection,
    path: &Path,
    from: u32,
    to: u32,
) -> Result<PathBuf, StoreError> {
    let dest = parent(path).join(format!("pre-migrate-{from}-{to}.sqlite"));
    let partial = with_suffix(&dest, ".partial");
    remove_if_exists(&partial)?;
    let target = partial
        .to_str()
        .ok_or(StoreError::Conflict("database path is not UTF-8"))?;
    conn.execute("VACUUM INTO ?1", [target])?;
    durable_rename(&partial, &dest)?;
    tracing::info!(copy = %dest.display(), from, to, "copied the database before migrating");
    Ok(dest)
}

fn backup(
    shared: &Shared,
    dest: &Path,
    strip: &'static [&'static str],
) -> Result<BackupReport, StoreError> {
    if let Some(bad) = strip.iter().find(|t| !is_identifier(t)) {
        return Err(StoreError::Sqlite(format!("cannot strip table {bad:?}")));
    }
    let src = open_reader(&shared.path, shared.busy_timeout)?;
    let partial = with_suffix(dest, ".partial");
    remove_if_exists(&partial)?;
    let copied = (|| {
        let mut copy = Connection::open(&partial)?;
        copy_database(&src, &mut copy)?;
        // A standalone file: no WAL beside it.
        let _: String =
            copy.pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))?;
        copy.pragma_update(None, "secure_delete", "ON")?;
        let mut stripped = Vec::new();
        for &table in strip {
            let exists: bool = copy.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )?;
            if exists {
                copy.execute_batch(&format!("DROP TABLE {table}"))?;
                stripped.push(table);
            }
        }
        // Rebuild the file so no page of a dropped table survives in it.
        copy.execute_batch("VACUUM")?;
        let mut check = copy.prepare("PRAGMA integrity_check")?;
        let rows = check
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok::<_, StoreError>((stripped, rows == ["ok"]))
    })();
    let (stripped, integrity_ok) = match copied {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_file(&partial);
            return Err(e);
        }
    };
    durable_rename(&partial, dest)?;
    let bytes = fs::metadata(dest)
        .map_err(|e| io_error("reading", dest, &e))?
        .len();
    Ok(BackupReport {
        path: dest.to_path_buf(),
        bytes,
        stripped,
        integrity_ok,
    })
}

/// Copies every page in one step, so the copy is one consistent snapshot of
/// the source (a WAL reader never blocks the writer).
fn copy_database(src: &Connection, dst: &mut Connection) -> Result<(), StoreError> {
    let backup = Backup::new(src, dst)?;
    for _ in 0..100 {
        match backup.step(-1)? {
            StepResult::Done => return Ok(()),
            StepResult::More => {}
            _ => thread::sleep(Duration::from_millis(20)),
        }
    }
    Err(StoreError::Sqlite(
        "backup kept finding the source busy".to_owned(),
    ))
}

fn is_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

pub(crate) fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

pub(crate) fn io_error(op: &str, path: &Path, e: &io::Error) -> StoreError {
    StoreError::Sqlite(format!("{op} {}: {e}", path.display()))
}

fn remove_if_exists(path: &Path) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_error("removing", path, &e)),
    }
}

/// fsync `from`, rename it to `to` and fsync the directory, so `to` is
/// either the old file or the complete new one after a crash.
pub(crate) fn durable_rename(from: &Path, to: &Path) -> Result<(), StoreError> {
    File::open(from)
        .and_then(|f| f.sync_all())
        .map_err(|e| io_error("syncing", from, &e))?;
    fs::rename(from, to).map_err(|e| io_error("renaming", from, &e))?;
    sync_dir(parent(to))
}

pub(crate) fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| io_error("syncing directory", dir, &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = "CREATE TABLE a(x INTEGER PRIMARY KEY, v TEXT NOT NULL);";
    const V2: &str = "CREATE TABLE b(y INTEGER PRIMARY KEY); ALTER TABLE a ADD COLUMN w TEXT;";

    fn opts() -> StoreOptions {
        StoreOptions {
            readers: 1,
            group_commit_ms: 0,
            ..StoreOptions::default()
        }
    }

    fn tables(path: &Path) -> Vec<String> {
        let conn = Connection::open(path).unwrap();
        let mut st = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn user_version(path: &Path) -> i64 {
        let conn = Connection::open(path).unwrap();
        conn.pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap()
    }

    #[tokio::test]
    async fn pre_migrate_backup_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.sqlite");
        let copy = dir.path().join("pre-migrate-1-2.sqlite");

        let store = Store::open_with(&path, Schema::Node, &[V1], opts()).unwrap();
        assert_eq!(store.schema_version(), 1);
        store
            .write(|tx| {
                tx.execute("INSERT INTO a(v) VALUES ('kept')", [])?;
                Ok(())
            })
            .await
            .unwrap();
        drop(store);
        // Creating the file has nothing to keep.
        assert!(!copy.exists());
        assert!(!dir.path().join("pre-migrate-0-1.sqlite").exists());

        let store = Store::open_with(&path, Schema::Node, &[V1, V2], opts()).unwrap();
        assert_eq!(store.schema_version(), 2);
        drop(store);

        assert!(copy.exists());
        assert!(!with_suffix(&copy, ".partial").exists());
        assert_eq!(user_version(&copy), 1);
        assert_eq!(tables(&copy), vec!["a".to_owned()]);
        let conn = Connection::open(&copy).unwrap();
        let v: String = conn.query_row("SELECT v FROM a", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "kept");

        assert_eq!(user_version(&path), 2);
        assert_eq!(tables(&path), vec!["a".to_owned(), "b".to_owned()]);
    }

    #[tokio::test]
    async fn failed_migration_leaves_the_file_and_the_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dealer.sqlite");
        drop(Store::open_with(&path, Schema::Dealer, &[V1], opts()).unwrap());

        let broken = "CREATE TABLE c(z INTEGER); INSERT INTO no_such_table VALUES (1);";
        let err = Store::open_with(&path, Schema::Dealer, &[V1, broken], opts()).unwrap_err();
        assert!(
            matches!(err, StoreError::Sqlite(ref m) if m.contains("migration 2")),
            "{err}"
        );
        // One transaction: nothing of migration 2 is left behind.
        assert_eq!(user_version(&path), 1);
        assert_eq!(tables(&path), vec!["a".to_owned()]);
        assert!(dir.path().join("pre-migrate-1-2.sqlite").exists());

        // The next attempt replaces the stale copy and succeeds.
        let store = Store::open_with(&path, Schema::Dealer, &[V1, V2], opts()).unwrap();
        assert_eq!(store.schema_version(), 2);
    }

    #[tokio::test]
    async fn shares_are_never_copied_before_a_migration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shares.sqlite");
        drop(Store::open_with(&path, Schema::MemberShares, &[V1], opts()).unwrap());
        let store = Store::open_with(&path, Schema::MemberShares, &[V1, V2], opts()).unwrap();
        assert_eq!(store.schema_version(), 2);
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            names.iter().all(|n| !n.starts_with("pre-migrate")),
            "{names:?}"
        );
    }
}
