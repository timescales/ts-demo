//! `node.sqlite` (schema): the node's epochs, submissions, sessions,
//! pipeline artifacts, transaction journal and event log.
//!
//! Every write method is one transaction. Invariants the repository keeps
//! whatever its caller does:
//!
//! * An epoch's phase never moves backwards (see [`NodeRepo::advance`]), and
//!   a phase is entered only when the artefact it names is stored.
//! * A submission or parked envelope is deduplicated on (commitment,
//!   submitting wallet) per epoch.
//! * A stored key bundle is never replaced once served, opened or parked
//!   under.
//! * fills, deltas and artifacts are readable through the public reads only
//!   once `artifacts_public` is set.

use crate::wire::GrantMethod;
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params, params_from_iter};
use timescales_chain::{
    BoxFuture, JournalError, TxErrorDetail, TxJournal, TxOp, TxOutcome, TxRecord,
};
use timescales_core::{
    ClearingPrice, Decode, DecodeError, Encode, Hash32, OrderCommitment, PriceBand, Reader,
};

use crate::store::sql::{
    arr, bound, count, exec, flag, hash, int, now_ms, opt_arr, opt_hash, opt_int, opt_uint,
    opt_uint8, opt_uint32, placeholders, row, rows, uint, uint8, uint32,
};
use crate::store::{Address, BackupReport, PruneReport, Schema, Store, StoreError};

/// Persisted epoch phases. The phase only moves forward.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    Scheduled = 1,
    Open,
    Closed,
    Committing,
    Committed,
    Snapshotted,
    Revealed,
    Sealed,
    Executing,
    Posted,
    Settled,
    Aborting,
    Aborted,
}

impl Phase {
    pub const ALL: [Phase; 13] = [
        Phase::Scheduled,
        Phase::Open,
        Phase::Closed,
        Phase::Committing,
        Phase::Committed,
        Phase::Snapshotted,
        Phase::Revealed,
        Phase::Sealed,
        Phase::Executing,
        Phase::Posted,
        Phase::Settled,
        Phase::Aborting,
        Phase::Aborted,
    ];

    /// The number stored in `epochs.phase`.
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: u8) -> Option<Phase> {
        Self::ALL.into_iter().find(|p| p.code() == code)
    }

    /// `Settled` and `Aborted`.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Phase::Settled | Phase::Aborted)
    }

    /// Whether [`NodeRepo::advance`] may move an epoch from `self` to `to`.
    ///
    /// Forward means a higher phase number, with these rules: a terminal
    /// phase never changes. Any other phase may move to `Aborting` or
    /// `Aborted`. An abort the chain superseded resumes at the phase the
    /// batch's status implies, which is
    /// `Committed` or later. Staying in the same phase is allowed, to
    /// update columns.
    pub fn can_move_to(self, to: Phase) -> bool {
        if self == to {
            return true;
        }
        if self.is_terminal() {
            return false;
        }
        match (self, to) {
            (_, Phase::Aborting | Phase::Aborted) => true,
            (Phase::Aborting, to) => to >= Phase::Committed,
            (from, to) => to > from,
        }
    }

    fn column(self) -> i64 {
        i64::from(self.code())
    }

    fn from_column(v: i64) -> Result<Phase, StoreError> {
        u8::try_from(v)
            .ok()
            .and_then(Phase::from_code)
            .ok_or(StoreError::Corrupt("unknown epoch phase"))
    }
}

/// Every column of `epochs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRow {
    pub market: Address,
    pub epoch: u64,
    pub phase: Phase,
    pub opens_at_ms: Option<u64>,
    pub cutoff_ms: Option<u64>,
    pub reference: Option<u64>,
    pub band: Option<PriceBand>,
    pub price_commitment: Option<Hash32>,
    pub committee_digest: Option<Hash32>,
    pub binding: Option<Hash32>,
    pub terms_digest: Option<Hash32>,
    /// Relay-signed `EpochAnnouncement`.
    pub announcement: Option<Vec<u8>>,
    pub root: Option<Hash32>,
    pub envelope_count: Option<u32>,
    pub real_count: Option<u32>,
    pub cover_count: Option<u32>,
    pub commit_sig: Option<[u8; 64]>,
    pub commit_slot: Option<u64>,
    pub snapshot_slot: Option<u64>,
    pub snapshot_late: bool,
    pub beacon: Option<Hash32>,
    pub reveal_slot: Option<u64>,
    /// Header v2, 283 bytes.
    pub header: Option<Vec<u8>>,
    pub receipt: Option<Vec<u8>>,
    pub receipt_slot: Option<u64>,
    pub artifacts_public: bool,
    /// The settlement program's abort reason numbering.
    pub abort_reason: Option<u8>,
    pub abort_detail: Option<String>,
    pub terminal_slot: Option<u64>,
    pub updated_at_ms: u64,
}

/// One optional value per column of `epochs`. `None` leaves it unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EpochPatch {
    pub opens_at_ms: Option<u64>,
    pub cutoff_ms: Option<u64>,
    pub reference: Option<u64>,
    pub band: Option<PriceBand>,
    pub price_commitment: Option<Hash32>,
    pub committee_digest: Option<Hash32>,
    pub binding: Option<Hash32>,
    pub terms_digest: Option<Hash32>,
    pub announcement: Option<Vec<u8>>,
    pub root: Option<Hash32>,
    pub envelope_count: Option<u32>,
    pub real_count: Option<u32>,
    pub cover_count: Option<u32>,
    pub commit_sig: Option<[u8; 64]>,
    pub commit_slot: Option<u64>,
    pub snapshot_slot: Option<u64>,
    pub snapshot_late: Option<bool>,
    pub beacon: Option<Hash32>,
    pub reveal_slot: Option<u64>,
    pub header: Option<Vec<u8>>,
    pub receipt: Option<Vec<u8>>,
    pub receipt_slot: Option<u64>,
    pub artifacts_public: Option<bool>,
    pub abort_reason: Option<u8>,
    pub abort_detail: Option<String>,
    pub terminal_slot: Option<u64>,
    pub updated_at_ms: Option<u64>,
}

impl EpochPatch {
    fn apply(self, row: &mut EpochRow) {
        fn set<T>(column: &mut Option<T>, value: Option<T>) {
            if value.is_some() {
                *column = value;
            }
        }
        set(&mut row.opens_at_ms, self.opens_at_ms);
        set(&mut row.cutoff_ms, self.cutoff_ms);
        set(&mut row.reference, self.reference);
        set(&mut row.band, self.band);
        set(&mut row.price_commitment, self.price_commitment);
        set(&mut row.committee_digest, self.committee_digest);
        set(&mut row.binding, self.binding);
        set(&mut row.terms_digest, self.terms_digest);
        set(&mut row.announcement, self.announcement);
        set(&mut row.root, self.root);
        set(&mut row.envelope_count, self.envelope_count);
        set(&mut row.real_count, self.real_count);
        set(&mut row.cover_count, self.cover_count);
        set(&mut row.commit_sig, self.commit_sig);
        set(&mut row.commit_slot, self.commit_slot);
        set(&mut row.snapshot_slot, self.snapshot_slot);
        if let Some(v) = self.snapshot_late {
            row.snapshot_late = v;
        }
        set(&mut row.beacon, self.beacon);
        set(&mut row.reveal_slot, self.reveal_slot);
        set(&mut row.header, self.header);
        set(&mut row.receipt, self.receipt);
        set(&mut row.receipt_slot, self.receipt_slot);
        if let Some(v) = self.artifacts_public {
            row.artifacts_public = v;
        }
        set(&mut row.abort_reason, self.abort_reason);
        set(&mut row.abort_detail, self.abort_detail);
        set(&mut row.terminal_slot, self.terminal_slot);
        if let Some(v) = self.updated_at_ms {
            row.updated_at_ms = v;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutOutcome {
    Inserted,
    Identical,
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertSubmission {
    Inserted,
    Duplicate { promise: Vec<u8> },
    SameCommitmentOtherBytes { promise: Vec<u8> },
}

/// A row of `submissions` or `parked`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionRow {
    pub market: Address,
    pub epoch: u64,
    pub commitment: OrderCommitment,
    pub envelope_digest: Hash32,
    /// Nulled `wallet_link_hours` after the epoch is terminal.
    pub wallet: Option<Address>,
    pub session_pk: Option<[u8; 32]>,
    /// Exact 386-byte submission.
    pub submission: Vec<u8>,
    pub promise: Vec<u8>,
    pub received_at_ms: u64,
}

/// A row of `sessions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    pub session_pk: [u8; 32],
    pub wallet: Address,
    pub market: Option<Address>,
    pub grant_text: String,
    pub signature: [u8; 64],
    pub method: GrantMethod,
    pub nonce: [u8; 16],
    pub issued_at_ms: Option<u64>,
    pub expires_at_ms: Option<u64>,
    pub revoked: bool,
    /// Kept while parked envelopes need its grant (provenance).
    pub keep_until_epoch: Option<u64>,
}

/// A row of `attempts`, written before the request is sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRow {
    pub market: Address,
    pub epoch: u64,
    pub n: u32,
    pub enclave: String,
    pub started_at_ms: u64,
    pub result: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FillRow {
    pub idx: u32,
    pub commitment: OrderCommitment,
    pub trader: Address,
    pub book: u8,
    pub side: u8,
    pub role: u8,
    pub qty: u64,
    pub tick: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeltaRow {
    pub idx: u32,
    pub trader: Address,
    pub base: i64,
    pub quote: i64,
}

/// Everything persisted when an epoch reaches `posted`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostedResult {
    pub market: Address,
    pub epoch: u64,
    pub receipt: Vec<u8>,
    pub artifacts: Vec<u8>,
    pub attestation: Option<Vec<u8>>,
    /// (executor, signature) per co-signature.
    pub cosigs: Vec<(Address, [u8; 64])>,
    pub fills: Vec<FillRow>,
    pub deltas: Vec<DeltaRow>,
    pub cancelled: Vec<OrderCommitment>,
    /// Candidate `OrderStateTable` after this epoch, confirmed at settlement.
    pub order_state: Vec<u8>,
    pub order_state_root: Hash32,
}

/// A row of `events`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEvent {
    pub seq: u64,
    pub market: Option<Address>,
    pub topic: String,
    pub topic_seq: u64,
    pub at_ms: u64,
    /// The event as JSON.
    pub event: String,
}

/// One row of the public clearing tape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapeRowData {
    pub epoch: u64,
    pub cutoff_ms: u64,
    pub phase: Phase,
    pub clearing: Vec<ClearingPrice>,
    pub matched_lots: u64,
    pub fill_count: u32,
    pub envelope_count: u32,
    pub terminal_at_ms: Option<u64>,
}

/// Public artifacts of an epoch whose quorum is on chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactsRow {
    pub header: Vec<u8>,
    pub receipt: Vec<u8>,
    pub artifacts: Vec<u8>,
    pub attestation: Option<Vec<u8>>,
    pub cosigs: Vec<(Address, [u8; 64])>,
}

/// A row of `txs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRow {
    pub id: i64,
    pub market: Address,
    pub epoch: Option<u64>,
    pub op: String,
    pub signature: [u8; 64],
    pub last_valid_block_height: u64,
    pub status: String,
    pub error: Option<String>,
    pub sent_at_ms: u64,
    pub slot: Option<u64>,
}

/// Retention settings (`[store]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    pub private_keep_epochs: u64,
    pub wallet_link_hours: u64,
    pub event_log_hours: u64,
}

/// Tables every long-retention backup leaves out.
pub const PRIVATE_TABLES: &[&str] = &[
    "submissions",
    "parked",
    "sessions",
    "closed",
    "cover_carry",
    "sealed",
    "snapshots",
    "bans",
];

/// Largest page of [`NodeRepo::epochs_page`] and [`NodeRepo::tape_page`].
pub const MAX_PAGE: u32 = 200;

/// Repository over `node.sqlite`. Each write method is one transaction.
#[derive(Debug)]
pub struct NodeRepo {
    store: Store,
}

#[allow(clippy::too_many_arguments)]
impl NodeRepo {
    /// # Panics
    ///
    /// If `store` was not opened with [`Schema::Node`].
    pub fn new(store: Store) -> Self {
        assert_eq!(store.schema(), Schema::Node, "NodeRepo needs node.sqlite");
        Self { store }
    }

    /// The underlying store, for readiness (`is_closed`) and metrics
    /// (`queue_depth`, `set_commit_observer`).
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Online backup with the private tables stripped.
    pub async fn backup(&self, dest: std::path::PathBuf) -> Result<BackupReport, StoreError> {
        self.store.backup_to(dest, PRIVATE_TABLES).await
    }

    // meta, keys and bundles
    pub async fn meta(&self, k: &'static str) -> Result<Option<Vec<u8>>, StoreError> {
        self.store
            .read(move |c| row(c, "SELECT v FROM meta WHERE k = ?1", [k], |r| Ok(r.get(0)?)))
            .await
    }

    pub async fn set_meta(&self, k: &'static str, v: Vec<u8>) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                exec(tx,
                    "INSERT INTO meta(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                    params![k, v],
                )?;
                Ok(())
            })
            .await
    }

    /// Stores the epoch's verified bundle and schedules the epoch (phase
    /// 1). A different bundle replaces the stored one only while the epoch
    /// is not open, nothing is parked for it and it was not served in the
    /// park window. `Inserted` reports such a replacement too.
    pub async fn put_key_bundle(
        &self,
        m: Address,
        e: u64,
        bundle: Vec<u8>,
        at_ms: u64,
    ) -> Result<PutOutcome, StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                let at = int(at_ms)?;
                let stored = row(
                    tx,
                    "SELECT bundle, served FROM key_bundles WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                    |r| Ok((r.get::<_, Vec<u8>>(0)?, flag(r.get(1)?)?)),
                )?;
                match stored {
                    Some((stored, _)) if stored == bundle => Ok(PutOutcome::Identical),
                    Some((_, served)) => {
                        let opened = phase_of(tx, &m, epoch)?.is_some_and(|p| p >= Phase::Open);
                        let parked: i64 = tx.query_row(
                            "SELECT count(*) FROM parked WHERE market = ?1 AND epoch = ?2",
                            params![m, epoch],
                            |r| r.get(0),
                        )?;
                        if served || opened || parked > 0 {
                            return Ok(PutOutcome::Conflict);
                        }
                        exec(tx,
                            "UPDATE key_bundles SET bundle = ?3, received_at_ms = ?4
                             WHERE market = ?1 AND epoch = ?2",
                            params![m, epoch, bundle, at],
                        )?;
                        tracing::warn!(epoch = e, "replaced a stored epoch-key bundle");
                        Ok(PutOutcome::Inserted)
                    }
                    None => {
                        exec(tx,
                            "INSERT INTO key_bundles(market, epoch, bundle, received_at_ms)
                             VALUES (?1, ?2, ?3, ?4)",
                            params![m, epoch, bundle, at],
                        )?;
                        exec(tx,
                            "INSERT INTO epochs(market, epoch, phase, updated_at_ms) VALUES (?1, ?2, ?3, ?4)
                             ON CONFLICT(market, epoch) DO NOTHING",
                            params![m, epoch, Phase::Scheduled.column(), at],
                        )?;
                        Ok(PutOutcome::Inserted)
                    }
                }
            })
            .await
    }

    pub async fn key_bundle(&self, m: Address, e: u64) -> Result<Option<Vec<u8>>, StoreError> {
        self.store
            .read(move |c| {
                row(
                    c,
                    "SELECT bundle FROM key_bundles WHERE market = ?1 AND epoch = ?2",
                    params![m, bound(e)],
                    |r| Ok(r.get(0)?),
                )
            })
            .await
    }

    /// Served in park_window: never replaced.
    pub async fn mark_bundle_served(&self, m: Address, e: u64) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let changed = exec(
                    tx,
                    "UPDATE key_bundles SET served = 1 WHERE market = ?1 AND epoch = ?2",
                    params![m, int(e)?],
                )?;
                if changed == 0 {
                    return Err(StoreError::Conflict("no key bundle for this epoch"));
                }
                Ok(())
            })
            .await
    }

    // epochs (phase moves forward only, a backwards move is StoreError::Conflict)
    pub async fn epoch(&self, m: Address, e: u64) -> Result<Option<EpochRow>, StoreError> {
        self.store.read(move |c| load_epoch(c, &m, bound(e))).await
    }

    /// Every epoch of the market that is not settled or aborted, oldest
    /// first (the startup reconciliation order).
    pub async fn non_terminal_epochs(&self, m: Address) -> Result<Vec<EpochRow>, StoreError> {
        self.store
            .read(move |c| {
                rows(
                    c,
                    &format!(
                        "SELECT {EPOCH_COLUMNS} FROM epochs
                         WHERE market = ?1 AND phase NOT IN (?2, ?3) ORDER BY epoch"
                    ),
                    params![m, Phase::Settled.column(), Phase::Aborted.column()],
                    epoch_from,
                )
            })
            .await
    }

    pub async fn max_epoch(&self, m: Address) -> Result<Option<u64>, StoreError> {
        self.store
            .read(move |c| {
                let max: Option<i64> = c.query_row(
                    "SELECT MAX(epoch) FROM epochs WHERE market = ?1",
                    [m],
                    |r| r.get(0),
                )?;
                opt_uint(max)
            })
            .await
    }

    /// Writes the row of an epoch that opens now (`row.phase` must be
    /// `Open`) and moves its parked envelopes: those in `parked_injected`
    /// (commitment, wallet) become submissions of the epoch, the others are
    /// dropped. Refused when the epoch is past `Scheduled` or another epoch
    /// of the market is open (at most one).
    pub async fn open_epoch(
        &self,
        row: EpochRow,
        parked_injected: Vec<(OrderCommitment, Address)>,
    ) -> Result<(), StoreError> {
        if row.phase != Phase::Open {
            return Err(StoreError::Conflict("open_epoch takes a row in phase open"));
        }
        self.store
            .write(move |tx| {
                let epoch = int(row.epoch)?;
                if phase_of(tx, &row.market, epoch)?.is_some_and(|p| p != Phase::Scheduled) {
                    return Err(StoreError::Conflict("epoch already opened"));
                }
                let other: Option<i64> = tx
                    .query_row(
                        "SELECT epoch FROM epochs WHERE market = ?1 AND phase = ?2 AND epoch <> ?3",
                        params![row.market, Phase::Open.column(), epoch],
                        |r| r.get(0),
                    )
                    .optional()?;
                if other.is_some() {
                    return Err(StoreError::Conflict("another epoch of the market is open"));
                }
                write_epoch(tx, &row)?;
                for (c, wallet) in parked_injected {
                    let parked: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM parked
                         WHERE market = ?1 AND epoch = ?2 AND commitment = ?3 AND wallet = ?4)",
                        params![row.market, epoch, c.0, wallet],
                        |r| r.get(0),
                    )?;
                    if !parked {
                        return Err(StoreError::Conflict(
                            "injected envelope is not parked for this epoch",
                        ));
                    }
                    exec(tx,
                        "INSERT OR IGNORE INTO submissions(market, epoch, commitment, envelope_digest,
                           wallet, session_pk, submission, promise, received_at_ms)
                         SELECT market, epoch, commitment, envelope_digest, wallet, session_pk,
                           submission, promise, received_at_ms
                         FROM parked WHERE market = ?1 AND epoch = ?2 AND commitment = ?3 AND wallet = ?4",
                        params![row.market, epoch, c.0, wallet],
                    )?;
                }
                exec(tx,
                    "DELETE FROM parked WHERE market = ?1 AND epoch = ?2",
                    params![row.market, epoch],
                )?;
                Ok(())
            })
            .await
    }

    /// Persists the `ClosedBatch` and its sorted leaves and moves the epoch
    /// from `open` to `closed` (phase 3). Repeating the same close is a
    /// no-op.
    pub async fn close_epoch(
        &self,
        m: Address,
        e: u64,
        closed: Vec<u8>,
        leaves: Vec<u8>,
        root: Hash32,
        count: u32,
        real: u32,
        cover: u32,
    ) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                match phase_of(tx, &m, epoch)? {
                    Some(Phase::Open) => {}
                    Some(Phase::Closed) => {
                        let same: Option<bool> = tx
                            .query_row(
                                "SELECT closed = ?3 AND leaves = ?4 FROM closed
                                 WHERE market = ?1 AND epoch = ?2",
                                params![m, epoch, closed, leaves],
                                |r| r.get(0),
                            )
                            .optional()?;
                        return if same == Some(true) {
                            Ok(())
                        } else {
                            Err(StoreError::Conflict("epoch closed with another batch"))
                        };
                    }
                    Some(_) => return Err(StoreError::Conflict("epoch is not open")),
                    None => return Err(StoreError::Conflict("no such epoch")),
                }
                exec(tx,
                    "INSERT OR REPLACE INTO closed(market, epoch, closed, leaves) VALUES (?1, ?2, ?3, ?4)",
                    params![m, epoch, closed, leaves],
                )?;
                exec(tx,
                    "UPDATE epochs SET phase = ?3, root = ?4, envelope_count = ?5, real_count = ?6,
                       cover_count = ?7, updated_at_ms = ?8
                     WHERE market = ?1 AND epoch = ?2",
                    params![
                        m,
                        epoch,
                        Phase::Closed.column(),
                        root.0,
                        count,
                        real,
                        cover,
                        int(now_ms())?
                    ],
                )?;
                Ok(())
            })
            .await
    }

    /// Moves the epoch to `to` and applies `patch` in one transaction.
    ///
    /// `Conflict` when the epoch does not exist, when the move goes
    /// backwards ([`Phase::can_move_to`]), or when `to` names an artefact
    /// that is not stored: `closed` and `committing` need the closed batch,
    /// `snapshotted` the balance snapshot, `sealed` the sealed batch,
    /// `executing` an attempt row and `posted` the result.
    pub async fn advance(
        &self,
        m: Address,
        e: u64,
        to: Phase,
        patch: EpochPatch,
    ) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                let mut row =
                    load_epoch(tx, &m, epoch)?.ok_or(StoreError::Conflict("no such epoch"))?;
                if !row.phase.can_move_to(to) {
                    return Err(StoreError::Conflict("epoch phase cannot move backwards"));
                }
                require_artefact(tx, &m, epoch, to)?;
                patch.apply(&mut row);
                row.phase = to;
                write_epoch(tx, &row)
            })
            .await
    }

    // submissions, parking, cover
    /// Deduplicates on (commitment, wallet) per epoch: the identical
    /// bytes again are `Duplicate`, other bytes `SameCommitmentOtherBytes`,
    /// both with the original promise.
    pub async fn insert_submission(
        &self,
        s: SubmissionRow,
    ) -> Result<InsertSubmission, StoreError> {
        self.store
            .write(move |tx| insert_envelope(tx, "submissions", &s))
            .await
    }

    /// The epoch's submissions in the order they were accepted.
    pub async fn submissions(&self, m: Address, e: u64) -> Result<Vec<SubmissionRow>, StoreError> {
        self.store
            .read(move |c| {
                rows(
                    c,
                    &format!(
                        "SELECT {ENVELOPE_COLUMNS} FROM submissions
                         WHERE market = ?1 AND epoch = ?2 ORDER BY received_at_ms, rowid"
                    ),
                    params![m, bound(e)],
                    envelope_from,
                )
            })
            .await
    }

    /// (this epoch, parked): the wallet's envelopes for epoch `e`, submitted
    /// or parked, and its parked envelopes over every epoch of the market.
    pub async fn wallet_usage(
        &self,
        m: Address,
        e: u64,
        wallet: Address,
    ) -> Result<(u32, u32), StoreError> {
        self.store
            .read(move |c| {
                let (epoch, parked): (i64, i64) = c.query_row(
                    "SELECT
                       (SELECT count(*) FROM submissions WHERE market = ?1 AND epoch = ?2 AND wallet = ?3)
                     + (SELECT count(*) FROM parked WHERE market = ?1 AND epoch = ?2 AND wallet = ?3),
                       (SELECT count(*) FROM parked WHERE market = ?1 AND wallet = ?3)",
                    params![m, bound(e), wallet],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                Ok((uint32(epoch)?, uint32(parked)?))
            })
            .await
    }

    /// Parks envelopes for future epochs in one transaction, with the same
    /// deduplication as [`NodeRepo::insert_submission`]. One result per row.
    pub async fn insert_parked(
        &self,
        rows: Vec<SubmissionRow>,
    ) -> Result<Vec<InsertSubmission>, StoreError> {
        self.store
            .write(move |tx| {
                if rows
                    .iter()
                    .any(|r| r.wallet.is_none() || r.session_pk.is_none())
                {
                    return Err(StoreError::Conflict(
                        "a parked envelope needs its wallet and session",
                    ));
                }
                rows.iter()
                    .map(|r| insert_envelope(tx, "parked", r))
                    .collect()
            })
            .await
    }

    pub async fn parked_for_epoch(
        &self,
        m: Address,
        e: u64,
    ) -> Result<Vec<SubmissionRow>, StoreError> {
        self.store
            .read(move |c| {
                rows(
                    c,
                    &format!(
                        "SELECT {ENVELOPE_COLUMNS} FROM parked
                         WHERE market = ?1 AND epoch = ?2 ORDER BY received_at_ms, rowid"
                    ),
                    params![m, bound(e)],
                    envelope_from,
                )
            })
            .await
    }

    /// (epoch, commitment) of every envelope the wallet has parked.
    pub async fn parked_by_wallet(
        &self,
        m: Address,
        wallet: Address,
    ) -> Result<Vec<(u64, OrderCommitment)>, StoreError> {
        self.store
            .read(move |c| {
                rows(
                    c,
                    "SELECT epoch, commitment FROM parked WHERE market = ?1 AND wallet = ?2
                     ORDER BY epoch, commitment",
                    params![m, wallet],
                    |r| Ok((uint(r.get(0)?)?, OrderCommitment(arr(r.get(1)?)?))),
                )
            })
            .await
    }

    /// Removes the wallet's parked envelopes for `c` in epochs after
    /// `after`. Returns those epochs.
    pub async fn retract_parked(
        &self,
        m: Address,
        wallet: Address,
        c: OrderCommitment,
        after: u64,
    ) -> Result<Vec<u64>, StoreError> {
        self.store
            .write(move |tx| {
                let epochs = rows(
                    tx,
                    "SELECT epoch FROM parked
                     WHERE market = ?1 AND wallet = ?2 AND commitment = ?3 AND epoch > ?4 ORDER BY epoch",
                    params![m, wallet, c.0, bound(after)],
                    |r| uint(r.get(0)?),
                )?;
                exec(tx,
                    "DELETE FROM parked WHERE market = ?1 AND wallet = ?2 AND commitment = ?3 AND epoch > ?4",
                    params![m, wallet, c.0, bound(after)],
                )?;
                Ok(epochs)
            })
            .await
    }

    /// Deletes every parked envelope of the given epochs (emergency
    /// committee rotation). Returns how many.
    pub async fn invalidate_parked(&self, m: Address, epochs: Vec<u64>) -> Result<u64, StoreError> {
        self.store
            .write(move |tx| {
                let mut deleted = 0;
                for e in epochs {
                    deleted += count(exec(
                        tx,
                        "DELETE FROM parked WHERE market = ?1 AND epoch = ?2",
                        params![m, bound(e)],
                    )?);
                }
                Ok(deleted)
            })
            .await
    }

    /// Replaces the market's carried cover with `carried`: what the relay
    /// exports after closing `last_epoch`, each intent sealed by the caller
    /// under the node KEK with AAD `market || C`. Intents the relay no
    /// longer carries are deleted. The others count as carried in
    /// `last_epoch`, the measure retention uses.
    pub async fn replace_cover_carry(
        &self,
        m: Address,
        last_epoch: u64,
        carried: Vec<(OrderCommitment, Vec<u8>)>,
    ) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(last_epoch)?;
                exec(tx, "DELETE FROM cover_carry WHERE market = ?1", params![m])?;
                for (c, sealed_intent) in carried {
                    exec(
                        tx,
                        "INSERT INTO cover_carry(market, commitment, sealed_intent, last_epoch)
                         VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(market, commitment) DO UPDATE
                           SET sealed_intent = excluded.sealed_intent",
                        params![m, c.0, sealed_intent, epoch],
                    )?;
                }
                Ok(())
            })
            .await
    }

    /// Up to `limit` carried cover intents, in commitment order.
    pub async fn cover_carry(
        &self,
        m: Address,
        limit: u32,
    ) -> Result<Vec<(OrderCommitment, Vec<u8>)>, StoreError> {
        self.store
            .read(move |c| {
                rows(
                    c,
                    "SELECT commitment, sealed_intent FROM cover_carry WHERE market = ?1
                     ORDER BY commitment LIMIT ?2",
                    params![m, limit],
                    |r| Ok((OrderCommitment(arr(r.get(0)?)?), r.get(1)?)),
                )
            })
            .await
    }

    // sessions and bans
    /// Returns the stored row and how many older sessions were evicted.
    ///
    /// The same grant again (same wallet, nonce, session key and signature)
    /// returns the stored session and evicts nothing. Another grant with
    /// that wallet and nonce, or a session key already in use, is a
    /// `Conflict`. Otherwise the wallet's oldest sessions are revoked
    /// until, with the new one, at most `max_per_wallet` are live. Revoked
    /// rows stay until no envelope links to them, because provenance needs
    /// their grants.
    pub async fn insert_session(
        &self,
        s: SessionRow,
        max_per_wallet: u32,
    ) -> Result<(SessionRow, u32), StoreError> {
        self.store
            .write(move |tx| {
                let same_grant = row(
                    tx,
                    &format!(
                        "SELECT {SESSION_COLUMNS} FROM sessions WHERE wallet = ?1 AND nonce = ?2"
                    ),
                    params![s.wallet, s.nonce],
                    session_from,
                )?;
                if let Some(stored) = same_grant {
                    if stored.session_pk == s.session_pk && stored.signature == s.signature {
                        return Ok((stored, 0));
                    }
                    return Err(StoreError::Conflict("grant nonce already used"));
                }
                let key_taken: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sessions WHERE session_pk = ?1)",
                    [s.session_pk],
                    |r| r.get(0),
                )?;
                if key_taken {
                    return Err(StoreError::Conflict("session key already registered"));
                }
                let live = rows(
                    tx,
                    "SELECT session_pk FROM sessions WHERE wallet = ?1 AND revoked = 0
                     ORDER BY COALESCE(issued_at_ms, 0), rowid",
                    [s.wallet],
                    |r| Ok(r.get::<_, Vec<u8>>(0)?),
                )?;
                let keep = usize::try_from(max_per_wallet.max(1) - 1).unwrap_or(usize::MAX);
                let evict = live.len().saturating_sub(keep);
                for pk in &live[..evict] {
                    exec(
                        tx,
                        "UPDATE sessions SET revoked = 1 WHERE session_pk = ?1",
                        [pk],
                    )?;
                }
                exec(
                    tx,
                    &format!(
                        "INSERT INTO sessions({SESSION_COLUMNS})
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
                    ),
                    params![
                        s.session_pk,
                        s.wallet,
                        s.market,
                        s.grant_text,
                        s.signature,
                        method_column(s.method),
                        s.nonce,
                        opt_int(s.issued_at_ms)?,
                        opt_int(s.expires_at_ms)?,
                        s.revoked,
                        opt_int(s.keep_until_epoch)?,
                    ],
                )?;
                let evicted = u32::try_from(evict).unwrap_or(u32::MAX);
                Ok((s, evicted))
            })
            .await
    }

    pub async fn session(&self, pk: [u8; 32]) -> Result<Option<SessionRow>, StoreError> {
        self.store
            .read(move |c| {
                row(
                    c,
                    &format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE session_pk = ?1"),
                    [pk],
                    session_from,
                )
            })
            .await
    }

    pub async fn session_by_grant(
        &self,
        wallet: Address,
        nonce: [u8; 16],
    ) -> Result<Option<SessionRow>, StoreError> {
        self.store
            .read(move |c| {
                row(
                    c,
                    &format!(
                        "SELECT {SESSION_COLUMNS} FROM sessions WHERE wallet = ?1 AND nonce = ?2"
                    ),
                    params![wallet, nonce],
                    session_from,
                )
            })
            .await
    }

    /// Revoking an unknown or already revoked session does nothing.
    pub async fn revoke_session(&self, pk: [u8; 32]) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                exec(
                    tx,
                    "UPDATE sessions SET revoked = 1 WHERE session_pk = ?1",
                    [pk],
                )?;
                Ok(())
            })
            .await
    }

    /// `true` when the nonce was fresh.
    pub async fn use_nonce(&self, nonce: [u8; 16], expires_at_ms: u64) -> Result<bool, StoreError> {
        self.store
            .write(move |tx| {
                let inserted = exec(
                    tx,
                    "INSERT INTO used_nonces(nonce, expires_at_ms) VALUES (?1, ?2)
                     ON CONFLICT(nonce) DO NOTHING",
                    params![nonce, int(expires_at_ms)?],
                )?;
                Ok(inserted == 1)
            })
            .await
    }

    /// Bans the wallet through `until_epoch`. An existing longer ban stays.
    pub async fn ban(
        &self,
        m: Address,
        wallet: Address,
        until_epoch: u64,
        reason: &'static str,
    ) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                exec(
                    tx,
                    "INSERT INTO bans(market, wallet, until_epoch, reason) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(market, wallet) DO UPDATE
                       SET until_epoch = excluded.until_epoch, reason = excluded.reason
                       WHERE excluded.until_epoch > bans.until_epoch",
                    params![m, wallet, int(until_epoch)?, reason],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn banned(
        &self,
        m: Address,
        wallet: Address,
        epoch: u64,
    ) -> Result<bool, StoreError> {
        self.store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM bans WHERE market = ?1 AND wallet = ?2 AND until_epoch >= ?3)",
                    params![m, wallet, bound(epoch)],
                    |r| r.get(0),
                )?)
            })
            .await
    }

    // pipeline artifacts
    /// Stores the epoch's balance snapshot. A snapshot may be retaken until
    /// a header has been sealed over it.
    pub async fn put_snapshot(
        &self,
        m: Address,
        e: u64,
        sheet: Vec<u8>,
        slot: u64,
    ) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                let slot = int(slot)?;
                let stored = row(
                    tx,
                    "SELECT sheet, slot FROM snapshots WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                    |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
                )?;
                if stored.as_ref().is_some_and(|(s, at)| *s == sheet && *at == slot) {
                    return Ok(());
                }
                if stored.is_some() && exists(tx, "sealed", &m, epoch)? {
                    return Err(StoreError::Conflict(
                        "the snapshot is already part of a sealed header",
                    ));
                }
                exec(tx,
                    "INSERT OR REPLACE INTO snapshots(market, epoch, sheet, slot) VALUES (?1, ?2, ?3, ?4)",
                    params![m, epoch, sheet, slot],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn snapshot(&self, m: Address, e: u64) -> Result<Option<(Vec<u8>, u64)>, StoreError> {
        self.store
            .read(move |c| {
                row(
                    c,
                    "SELECT sheet, slot FROM snapshots WHERE market = ?1 AND epoch = ?2",
                    params![m, bound(e)],
                    |r| Ok((r.get(0)?, uint(r.get(1)?)?)),
                )
            })
            .await
    }

    /// Header assembly is deterministic: storing the same sealed batch again
    /// is a no-op, a different one is a `Conflict`.
    pub async fn put_sealed(
        &self,
        m: Address,
        e: u64,
        header: [u8; 283],
        batch: Vec<u8>,
    ) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                let stored = row(
                    tx,
                    "SELECT header, batch FROM sealed WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                    |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
                )?;
                match stored {
                    Some((h, b)) if h == header && b == batch => Ok(()),
                    Some(_) => Err(StoreError::Conflict("a different sealed batch is stored")),
                    None => {
                        exec(tx,
                            "INSERT INTO sealed(market, epoch, header, batch) VALUES (?1, ?2, ?3, ?4)",
                            params![m, epoch, header, batch],
                        )?;
                        Ok(())
                    }
                }
            })
            .await
    }

    pub async fn sealed(
        &self,
        m: Address,
        e: u64,
    ) -> Result<Option<([u8; 283], Vec<u8>)>, StoreError> {
        self.store
            .read(move |c| {
                row(
                    c,
                    "SELECT header, batch FROM sealed WHERE market = ?1 AND epoch = ?2",
                    params![m, bound(e)],
                    |r| Ok((arr(r.get(0)?)?, r.get(1)?)),
                )
            })
            .await
    }

    /// Durable BEFORE dispatch: returns the attempt's number once its row is
    /// committed, so a request is never sent without a row.
    pub async fn begin_attempt(
        &self,
        m: Address,
        e: u64,
        enclave: String,
        at_ms: u64,
    ) -> Result<u32, StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                let last: i64 = tx.query_row(
                    "SELECT COALESCE(MAX(n), 0) FROM attempts WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                    |r| r.get(0),
                )?;
                let n = uint32(last)?
                    .checked_add(1)
                    .ok_or(StoreError::Conflict("too many attempts"))?;
                exec(
                    tx,
                    "INSERT INTO attempts(market, epoch, n, enclave, started_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![m, epoch, n, enclave, int(at_ms)?],
                )?;
                Ok(n)
            })
            .await
    }

    pub async fn finish_attempt(
        &self,
        m: Address,
        e: u64,
        n: u32,
        result: &'static str,
        detail: String,
    ) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let changed = exec(
                    tx,
                    "UPDATE attempts SET result = ?4, detail = ?5
                     WHERE market = ?1 AND epoch = ?2 AND n = ?3",
                    params![m, int(e)?, n, result, detail],
                )?;
                if changed == 0 {
                    return Err(StoreError::Conflict("no such attempt"));
                }
                Ok(())
            })
            .await
    }

    pub async fn attempts(&self, m: Address, e: u64) -> Result<Vec<AttemptRow>, StoreError> {
        self.store
            .read(move |c| {
                rows(
                    c,
                    "SELECT market, epoch, n, enclave, started_at_ms, result, detail FROM attempts
                     WHERE market = ?1 AND epoch = ?2 ORDER BY n",
                    params![m, bound(e)],
                    |r| {
                        Ok(AttemptRow {
                            market: arr(r.get(0)?)?,
                            epoch: uint(r.get(1)?)?,
                            n: uint32(r.get(2)?)?,
                            enclave: r.get(3)?,
                            started_at_ms: uint(r.get(4)?)?,
                            result: r.get(5)?,
                            detail: r.get(6)?,
                        })
                    },
                )
            })
            .await
    }

    /// Receipt, artifacts, attestation, cosigs, fills/deltas/cancelled,
    /// candidate order_state.
    ///
    /// Storing the same receipt again is a no-op. Another receipt for the
    /// epoch is a `Conflict`. The order state starts unconfirmed.
    pub async fn put_result(&self, r: PostedResult) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(r.epoch)?;
                let stored = row(
                    tx,
                    "SELECT receipt FROM results WHERE market = ?1 AND epoch = ?2",
                    params![r.market, epoch],
                    |row| Ok(row.get::<_, Vec<u8>>(0)?),
                )?;
                match stored {
                    Some(receipt) if receipt == r.receipt => return Ok(()),
                    Some(_) => return Err(StoreError::Conflict("a different result is stored")),
                    None => {}
                }
                if !distinct(r.fills.iter().map(|f| f.idx)) || !distinct(r.deltas.iter().map(|d| d.idx))
                {
                    return Err(StoreError::Conflict("duplicate fill or delta index"));
                }
                exec(tx,
                    "INSERT INTO results(market, epoch, receipt, artifacts, attestation, cosigs)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        r.market,
                        epoch,
                        r.receipt,
                        r.artifacts,
                        r.attestation,
                        encode_cosigs(&r.cosigs)
                    ],
                )?;
                for f in &r.fills {
                    exec(tx,
                        "INSERT INTO fills(market, epoch, idx, commitment, trader, book, side, role, qty, tick)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            r.market,
                            epoch,
                            f.idx,
                            f.commitment.0,
                            f.trader,
                            f.book,
                            f.side,
                            f.role,
                            int(f.qty)?,
                            int(f.tick)?
                        ],
                    )?;
                }
                for d in &r.deltas {
                    exec(tx,
                        "INSERT INTO deltas(market, epoch, idx, trader, base, quote)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![r.market, epoch, d.idx, d.trader, d.base, d.quote],
                    )?;
                }
                for (idx, c) in (0u32..).zip(&r.cancelled) {
                    exec(tx,
                        "INSERT INTO cancelled(market, epoch, idx, commitment) VALUES (?1, ?2, ?3, ?4)",
                        params![r.market, epoch, idx, c.0],
                    )?;
                }
                exec(tx,
                    "INSERT OR REPLACE INTO order_state(market, epoch, tbl, root, confirmed)
                     VALUES (?1, ?2, ?3, ?4, 0)",
                    params![r.market, epoch, r.order_state, r.order_state_root.0],
                )?;
                Ok(())
            })
            .await
    }

    /// Marks the epoch's stored result public (its quorum is on chain).
    pub async fn set_artifacts_public(&self, m: Address, e: u64) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                if !exists(tx, "results", &m, epoch)? {
                    return Err(StoreError::Conflict("no stored result for this epoch"));
                }
                let changed = exec(
                    tx,
                    "UPDATE epochs SET artifacts_public = 1 WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                )?;
                if changed == 0 {
                    return Err(StoreError::Conflict("no such epoch"));
                }
                Ok(())
            })
            .await
    }

    pub async fn confirm_order_state(&self, m: Address, e: u64) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let changed = exec(
                    tx,
                    "UPDATE order_state SET confirmed = 1 WHERE market = ?1 AND epoch = ?2",
                    params![m, int(e)?],
                )?;
                if changed == 0 {
                    return Err(StoreError::Conflict(
                        "no candidate order state for this epoch",
                    ));
                }
                Ok(())
            })
            .await
    }

    /// (table, root, confirmed)
    pub async fn order_state(
        &self,
        m: Address,
        e: u64,
    ) -> Result<Option<(Vec<u8>, Hash32, bool)>, StoreError> {
        self.store
            .read(move |c| {
                row(
                    c,
                    "SELECT tbl, root, confirmed FROM order_state WHERE market = ?1 AND epoch = ?2",
                    params![m, bound(e)],
                    |r| Ok((r.get(0)?, hash(r.get(1)?)?, flag(r.get(2)?)?)),
                )
            })
            .await
    }

    // events
    /// Each event is (market, topic, at_ms, json). Returns (seq, topic_seq).
    ///
    /// `seq` is global and strictly increasing. `topic_seq` is contiguous
    /// per topic. Neither restarts when the log is pruned.
    pub async fn append_events(
        &self,
        ev: Vec<(Option<Address>, String, u64, String)>,
    ) -> Result<Vec<(u64, u64)>, StoreError> {
        self.store
            .write(move |tx| {
                let mut out = Vec::with_capacity(ev.len());
                for (market, topic, at_ms, event) in ev {
                    let key = format!("topic_seq:{topic}");
                    let last = row(tx, "SELECT v FROM meta WHERE k = ?1", [&key], |r| {
                        Ok(u64::from_le_bytes(arr(r.get(0)?)?))
                    })?
                    .unwrap_or(0);
                    let topic_seq = last
                        .checked_add(1)
                        .ok_or(StoreError::Conflict("topic sequence exhausted"))?;
                    exec(tx,
                        "INSERT INTO events(market, topic, topic_seq, at_ms, event) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![market, topic, int(topic_seq)?, int(at_ms)?, event],
                    )?;
                    let seq = uint(tx.last_insert_rowid())?;
                    exec(tx,
                        "INSERT INTO meta(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                        params![key, topic_seq.to_le_bytes()],
                    )?;
                    out.push((seq, topic_seq));
                }
                Ok(out)
            })
            .await
    }

    /// Up to `limit` events after `seq`, oldest first. Only the given topics
    /// unless `topics` is empty.
    pub async fn events_since(
        &self,
        seq: u64,
        topics: Vec<String>,
        limit: u32,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        self.store
            .read(move |c| {
                let filter = if topics.is_empty() {
                    String::new()
                } else {
                    format!("AND topic IN ({})", placeholders(3, topics.len()))
                };
                let sql = format!(
                    "SELECT seq, market, topic, topic_seq, at_ms, event FROM events
                     WHERE seq > ?1 {filter} ORDER BY seq LIMIT ?2"
                );
                let mut values = vec![Value::Integer(bound(seq)), Value::Integer(i64::from(limit))];
                values.extend(topics.into_iter().map(Value::Text));
                rows(c, &sql, params_from_iter(values), |r| {
                    Ok(StoredEvent {
                        seq: uint(r.get(0)?)?,
                        market: opt_arr(r.get(1)?)?,
                        topic: r.get(2)?,
                        topic_seq: uint(r.get(3)?)?,
                        at_ms: uint(r.get(4)?)?,
                        event: r.get(5)?,
                    })
                })
            })
            .await
    }

    // public reads (API, newest first, before/limit pagination)
    /// Epochs before `before` (all when `None`), newest first. `limit` is
    /// clamped to 1..=[`MAX_PAGE`]. The second value is the `before` of the
    /// next page, `None` on the last page.
    pub async fn epochs_page(
        &self,
        m: Address,
        before: Option<u64>,
        limit: u32,
    ) -> Result<(Vec<EpochRow>, Option<u64>), StoreError> {
        let limit = limit.clamp(1, MAX_PAGE);
        self.store
            .read(move |c| {
                let page = rows(
                    c,
                    &format!(
                        "SELECT {EPOCH_COLUMNS} FROM epochs
                         WHERE market = ?1 AND (?2 IS NULL OR epoch < ?2)
                         ORDER BY epoch DESC LIMIT ?3"
                    ),
                    params![m, before.map(bound), limit + 1],
                    epoch_from,
                )?;
                Ok(paginate(page, limit, |r| r.epoch))
            })
            .await
    }

    /// The clearing tape: epochs whose result is public, newest first, with
    /// the clearing prices and fill count of their receipt. Pagination as
    /// in [`NodeRepo::epochs_page`].
    pub async fn tape_page(
        &self,
        m: Address,
        before: Option<u64>,
        limit: u32,
    ) -> Result<(Vec<TapeRowData>, Option<u64>), StoreError> {
        let limit = limit.clamp(1, MAX_PAGE);
        self.store
            .read(move |c| {
                let page = rows(
                    c,
                    "SELECT e.epoch, e.cutoff_ms, e.phase, r.receipt, e.envelope_count, e.updated_at_ms
                     FROM epochs e JOIN results r ON r.market = e.market AND r.epoch = e.epoch
                     WHERE e.market = ?1 AND e.artifacts_public = 1 AND (?2 IS NULL OR e.epoch < ?2)
                     ORDER BY e.epoch DESC LIMIT ?3",
                    params![m, before.map(bound), limit + 1],
                    |r| {
                        let phase = Phase::from_column(r.get(2)?)?;
                        let (clearing, fill_count) = receipt_summary(&r.get::<_, Vec<u8>>(3)?)?;
                        let matched_lots = clearing
                            .iter()
                            .try_fold(0u64, |sum, p| sum.checked_add(p.volume.0))
                            .ok_or(StoreError::Corrupt("matched volume overflows"))?;
                        Ok(TapeRowData {
                            epoch: uint(r.get(0)?)?,
                            cutoff_ms: opt_uint(r.get(1)?)?
                                .ok_or(StoreError::Corrupt("public epoch without a cutoff"))?,
                            phase,
                            clearing,
                            matched_lots,
                            fill_count,
                            envelope_count: opt_uint32(r.get(4)?)?
                                .ok_or(StoreError::Corrupt("public epoch without a count"))?,
                            terminal_at_ms: if phase.is_terminal() {
                                Some(uint(r.get(5)?)?)
                            } else {
                                None
                            },
                        })
                    },
                )?;
                Ok(paginate(page, limit, |r| r.epoch))
            })
            .await
    }

    /// The sorted leaves (`count x (C || envelope digest)`) of the closed
    /// batch. Gone once private rows are pruned.
    pub async fn leaves(&self, m: Address, e: u64) -> Result<Option<Vec<u8>>, StoreError> {
        self.store
            .read(move |c| {
                row(
                    c,
                    "SELECT leaves FROM closed WHERE market = ?1 AND epoch = ?2",
                    params![m, bound(e)],
                    |r| Ok(r.get(0)?),
                )
            })
            .await
    }

    /// `None` until public.
    pub async fn public_artifacts(
        &self,
        m: Address,
        e: u64,
    ) -> Result<Option<ArtifactsRow>, StoreError> {
        self.store
            .read(move |c| {
                row(
                    c,
                    "SELECT COALESCE(e.header, s.header), r.receipt, r.artifacts, r.attestation, r.cosigs
                     FROM epochs e
                     JOIN results r ON r.market = e.market AND r.epoch = e.epoch
                     LEFT JOIN sealed s ON s.market = e.market AND s.epoch = e.epoch
                     WHERE e.market = ?1 AND e.epoch = ?2 AND e.artifacts_public = 1",
                    params![m, bound(e)],
                    |r| {
                        Ok(ArtifactsRow {
                            header: r
                                .get::<_, Option<Vec<u8>>>(0)?
                                .ok_or(StoreError::Corrupt("public epoch without a header"))?,
                            receipt: r.get(1)?,
                            artifacts: r.get(2)?,
                            attestation: r.get(3)?,
                            cosigs: decode_cosigs(r.get(4)?)?,
                        })
                    },
                )
            })
            .await
    }

    /// The epoch's journalled transactions in the order they were sent.
    pub async fn txs_for(&self, m: Address, e: u64) -> Result<Vec<TxRow>, StoreError> {
        self.store
            .read(move |c| {
                rows(
                    c,
                    "SELECT id, market, epoch, op, signature, last_valid_block_height, status, error,
                       sent_at_ms, slot
                     FROM txs WHERE market = ?1 AND epoch = ?2 ORDER BY id",
                    params![m, bound(e)],
                    |r| {
                        Ok(TxRow {
                            id: r.get(0)?,
                            market: arr(r.get(1)?)?,
                            epoch: opt_uint(r.get(2)?)?,
                            op: r.get(3)?,
                            signature: arr(r.get(4)?)?,
                            last_valid_block_height: uint(r.get(5)?)?,
                            status: r.get(6)?,
                            error: r.get(7)?,
                            sent_at_ms: uint(r.get(8)?)?,
                            slot: opt_uint(r.get(9)?)?,
                        })
                    },
                )
            })
            .await
    }

    // retention
    /// Applies the retention rules to one market:
    ///
    /// * Wallet and session links of submissions are nulled once their epoch
    ///   has been terminal for `wallet_link_hours` (the terminal time is the
    ///   row's `updated_at_ms`).
    /// * `submissions`, `parked`, `closed`, `snapshots` and `sealed` rows,
    ///   and carried cover, go once their epoch is `private_keep_epochs`
    ///   behind `last_terminal`.
    /// * Bans that end at or before `last_terminal` go.
    /// * Events older than `event_log_hours` go (this market's and the
    ///   market-less ones), and so do expired session nonces.
    /// * Revoked or expired sessions go once no envelope links to them.
    pub async fn prune(
        &self,
        m: Address,
        now_ms: u64,
        last_terminal: u64,
        r: Retention,
    ) -> Result<PruneReport, StoreError> {
        self.store
            .write(move |tx| {
                let mut report = PruneReport::default();
                let link_cutoff = now_ms.saturating_sub(r.wallet_link_hours.saturating_mul(HOUR_MS));
                report.wallets_nulled = count(exec(tx,
                    "UPDATE submissions SET wallet = NULL, session_pk = NULL
                     WHERE market = ?1 AND (wallet IS NOT NULL OR session_pk IS NOT NULL)
                       AND epoch IN (SELECT epoch FROM epochs
                                     WHERE market = ?1 AND phase IN (?2, ?3) AND updated_at_ms <= ?4)",
                    params![
                        m,
                        Phase::Settled.column(),
                        Phase::Aborted.column(),
                        bound(link_cutoff)
                    ],
                )?);
                if let Some(through) = last_terminal.checked_sub(r.private_keep_epochs) {
                    for table in ["submissions", "parked", "closed", "snapshots", "sealed"] {
                        report.rows_deleted += count(exec(tx,
                            &format!("DELETE FROM {table} WHERE market = ?1 AND epoch <= ?2"),
                            params![m, bound(through)],
                        )?);
                    }
                    report.rows_deleted += count(exec(tx,
                        "DELETE FROM cover_carry WHERE market = ?1 AND last_epoch <= ?2",
                        params![m, bound(through)],
                    )?);
                }
                report.rows_deleted += count(exec(tx,
                    "DELETE FROM bans WHERE market = ?1 AND until_epoch <= ?2",
                    params![m, bound(last_terminal)],
                )?);
                let event_cutoff = now_ms.saturating_sub(r.event_log_hours.saturating_mul(HOUR_MS));
                report.rows_deleted += count(exec(tx,
                    "DELETE FROM events WHERE at_ms < ?2 AND (market = ?1 OR market IS NULL)",
                    params![m, bound(event_cutoff)],
                )?);
                report.rows_deleted += count(exec(tx,
                    "DELETE FROM used_nonces WHERE expires_at_ms < ?1",
                    [bound(now_ms)],
                )?);
                report.rows_deleted += count(exec(tx,
                    "DELETE FROM sessions
                     WHERE (revoked = 1 OR expires_at_ms < ?1)
                       AND NOT EXISTS (SELECT 1 FROM submissions s WHERE s.session_pk = sessions.session_pk)
                       AND NOT EXISTS (SELECT 1 FROM parked p WHERE p.session_pk = sessions.session_pk)",
                    [bound(now_ms)],
                )?);
                Ok(report)
            })
            .await
    }
}

/// The node's transaction journal is the `txs` table.
impl TxJournal for NodeRepo {
    fn before_send(&self, rec: TxRecord) -> BoxFuture<'_, Result<i64, JournalError>> {
        Box::pin(async move {
            self.store
                .write(move |tx| {
                    exec(tx,
                        "INSERT INTO txs(market, epoch, op, signature, last_valid_block_height, status, sent_at_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                        params![
                            rec.market,
                            opt_int(rec.epoch)?,
                            rec.op.as_str(),
                            rec.signature,
                            int(rec.last_valid_block_height)?,
                            int(rec.sent_at_ms)?
                        ],
                    )?;
                    Ok(tx.last_insert_rowid())
                })
                .await
                .map_err(journal_error)
        })
    }

    fn resolved(&self, id: i64, outcome: TxOutcome) -> BoxFuture<'_, Result<(), JournalError>> {
        Box::pin(async move {
            self.store
                .write(move |tx| {
                    let (status, slot, error) = match outcome {
                        TxOutcome::Landed { slot } => ("landed", Some(slot), None),
                        TxOutcome::Failed { slot, err } => {
                            ("failed", Some(slot), Some(describe(&err)))
                        }
                        TxOutcome::Expired => ("expired", None, None),
                    };
                    let changed = exec(
                        tx,
                        "UPDATE txs SET status = ?2, slot = ?3, error = ?4 WHERE id = ?1",
                        params![id, status, opt_int(slot)?, error],
                    )?;
                    if changed == 0 {
                        return Err(StoreError::Conflict("no such transaction"));
                    }
                    Ok(())
                })
                .await
                .map_err(journal_error)
        })
    }

    fn pending(&self) -> BoxFuture<'_, Result<Vec<TxRecord>, JournalError>> {
        Box::pin(async move {
            self.store
                .read(|c| {
                    rows(
                        c,
                        "SELECT id, market, epoch, op, signature, last_valid_block_height, sent_at_ms
                         FROM txs WHERE status = 'pending' ORDER BY id",
                        [],
                        |r| {
                            Ok(TxRecord {
                                id: Some(r.get(0)?),
                                market: arr(r.get(1)?)?,
                                epoch: opt_uint(r.get(2)?)?,
                                op: parse_op(&r.get::<_, String>(3)?)
                                    .ok_or(StoreError::Corrupt("unknown transaction op"))?,
                                signature: arr(r.get(4)?)?,
                                last_valid_block_height: uint(r.get(5)?)?,
                                sent_at_ms: uint(r.get(6)?)?,
                            })
                        },
                    )
                })
                .await
                .map_err(journal_error)
        })
    }

    /// `txs` rows are never pruned, so the maximum only grows.
    fn last_landed_slot(&self) -> BoxFuture<'_, Result<u64, JournalError>> {
        Box::pin(async move {
            self.store
                .read(|c| {
                    row(
                        c,
                        "SELECT COALESCE(MAX(slot), 0) FROM txs WHERE status IN ('landed', 'failed')",
                        [],
                        |r| uint(r.get(0)?),
                    )
                })
                .await
                .map(Option::unwrap_or_default)
                .map_err(journal_error)
        })
    }
}

const HOUR_MS: u64 = 3_600_000;

const EPOCH_COLUMNS: &str = "market, epoch, phase, opens_at_ms, cutoff_ms, reference, band, \
    price_commitment, committee_digest, binding, terms_digest, announcement, root, envelope_count, \
    real_count, cover_count, commit_sig, commit_slot, snapshot_slot, snapshot_late, beacon, \
    reveal_slot, header, receipt, receipt_slot, artifacts_public, abort_reason, abort_detail, \
    terminal_slot, updated_at_ms";

const ENVELOPE_COLUMNS: &str = "market, epoch, commitment, envelope_digest, wallet, session_pk, \
    submission, promise, received_at_ms";

const SESSION_COLUMNS: &str = "session_pk, wallet, market, grant_text, signature, method, nonce, \
    issued_at_ms, expires_at_ms, revoked, keep_until_epoch";

fn epoch_from(r: &Row<'_>) -> Result<EpochRow, StoreError> {
    Ok(EpochRow {
        market: arr(r.get(0)?)?,
        epoch: uint(r.get(1)?)?,
        phase: Phase::from_column(r.get(2)?)?,
        opens_at_ms: opt_uint(r.get(3)?)?,
        cutoff_ms: opt_uint(r.get(4)?)?,
        reference: opt_uint(r.get(5)?)?,
        band: r
            .get::<_, Option<Vec<u8>>>(6)?
            .map(|b| PriceBand::decode_exact(&b))
            .transpose()
            .map_err(|_| StoreError::Corrupt("stored price band does not decode"))?,
        price_commitment: opt_hash(r.get(7)?)?,
        committee_digest: opt_hash(r.get(8)?)?,
        binding: opt_hash(r.get(9)?)?,
        terms_digest: opt_hash(r.get(10)?)?,
        announcement: r.get(11)?,
        root: opt_hash(r.get(12)?)?,
        envelope_count: opt_uint32(r.get(13)?)?,
        real_count: opt_uint32(r.get(14)?)?,
        cover_count: opt_uint32(r.get(15)?)?,
        commit_sig: opt_arr(r.get(16)?)?,
        commit_slot: opt_uint(r.get(17)?)?,
        snapshot_slot: opt_uint(r.get(18)?)?,
        snapshot_late: flag(r.get(19)?)?,
        beacon: opt_hash(r.get(20)?)?,
        reveal_slot: opt_uint(r.get(21)?)?,
        header: r.get(22)?,
        receipt: r.get(23)?,
        receipt_slot: opt_uint(r.get(24)?)?,
        artifacts_public: flag(r.get(25)?)?,
        abort_reason: opt_uint8(r.get(26)?)?,
        abort_detail: r.get(27)?,
        terminal_slot: opt_uint(r.get(28)?)?,
        updated_at_ms: uint(r.get(29)?)?,
    })
}

fn load_epoch(c: &Connection, m: &Address, epoch: i64) -> Result<Option<EpochRow>, StoreError> {
    row(
        c,
        &format!("SELECT {EPOCH_COLUMNS} FROM epochs WHERE market = ?1 AND epoch = ?2"),
        params![m, epoch],
        epoch_from,
    )
}

/// Inserts or replaces the whole row.
fn write_epoch(tx: &Transaction<'_>, r: &EpochRow) -> Result<(), StoreError> {
    exec(tx,
        &format!(
            "INSERT OR REPLACE INTO epochs({EPOCH_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
               ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
               ?27, ?28, ?29, ?30)"
        ),
        params![
            r.market,
            int(r.epoch)?,
            r.phase.column(),
            opt_int(r.opens_at_ms)?,
            opt_int(r.cutoff_ms)?,
            opt_int(r.reference)?,
            r.band.map(|b| b.to_bytes()),
            r.price_commitment.map(|h| h.0),
            r.committee_digest.map(|h| h.0),
            r.binding.map(|h| h.0),
            r.terms_digest.map(|h| h.0),
            r.announcement,
            r.root.map(|h| h.0),
            r.envelope_count,
            r.real_count,
            r.cover_count,
            r.commit_sig,
            opt_int(r.commit_slot)?,
            opt_int(r.snapshot_slot)?,
            r.snapshot_late,
            r.beacon.map(|h| h.0),
            opt_int(r.reveal_slot)?,
            r.header,
            r.receipt,
            opt_int(r.receipt_slot)?,
            r.artifacts_public,
            r.abort_reason,
            r.abort_detail,
            opt_int(r.terminal_slot)?,
            int(r.updated_at_ms)?,
        ],
    )?;
    Ok(())
}

fn phase_of(c: &Connection, m: &Address, epoch: i64) -> Result<Option<Phase>, StoreError> {
    row(
        c,
        "SELECT phase FROM epochs WHERE market = ?1 AND epoch = ?2",
        params![m, epoch],
        |r| Phase::from_column(r.get(0)?),
    )
}

/// Whether `table` has a row for the epoch. `table` is one of this module's
/// table names, never input.
fn exists(c: &Connection, table: &str, m: &Address, epoch: i64) -> Result<bool, StoreError> {
    Ok(c.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE market = ?1 AND epoch = ?2)"),
        params![m, epoch],
        |r| r.get(0),
    )?)
}

/// A phase counts as reached only once its artefact is stored.
fn require_artefact(c: &Connection, m: &Address, epoch: i64, to: Phase) -> Result<(), StoreError> {
    let (table, missing) = match to {
        Phase::Closed | Phase::Committing => ("closed", "the closed batch is not stored"),
        Phase::Snapshotted => ("snapshots", "the balance snapshot is not stored"),
        Phase::Sealed => ("sealed", "the sealed batch is not stored"),
        Phase::Executing => ("attempts", "no attempt is recorded"),
        Phase::Posted => ("results", "the result is not stored"),
        _ => return Ok(()),
    };
    if exists(c, table, m, epoch)? {
        Ok(())
    } else {
        Err(StoreError::Conflict(missing))
    }
}

/// Inserts into `submissions` or `parked` with (commitment, wallet)
/// deduplication, and keeps the submitting session for provenance.
fn insert_envelope(
    tx: &Transaction<'_>,
    table: &str,
    s: &SubmissionRow,
) -> Result<InsertSubmission, StoreError> {
    let wallet = s.wallet.ok_or(StoreError::Conflict(
        "an envelope needs its submitting wallet",
    ))?;
    let epoch = int(s.epoch)?;
    let stored = row(
        tx,
        &format!(
            "SELECT submission, promise FROM {table}
             WHERE market = ?1 AND epoch = ?2 AND commitment = ?3 AND wallet = ?4"
        ),
        params![s.market, epoch, s.commitment.0, wallet],
        |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
    )?;
    if let Some((bytes, promise)) = stored {
        return Ok(if bytes == s.submission {
            InsertSubmission::Duplicate { promise }
        } else {
            InsertSubmission::SameCommitmentOtherBytes { promise }
        });
    }
    exec(
        tx,
        &format!(
            "INSERT INTO {table}({ENVELOPE_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        ),
        params![
            s.market,
            epoch,
            s.commitment.0,
            s.envelope_digest.0,
            wallet,
            s.session_pk,
            s.submission,
            s.promise,
            int(s.received_at_ms)?
        ],
    )?;
    if let Some(pk) = s.session_pk {
        exec(
            tx,
            "UPDATE sessions SET keep_until_epoch = max(COALESCE(keep_until_epoch, ?2), ?2)
             WHERE session_pk = ?1",
            params![pk, epoch],
        )?;
    }
    Ok(InsertSubmission::Inserted)
}

fn envelope_from(r: &Row<'_>) -> Result<SubmissionRow, StoreError> {
    Ok(SubmissionRow {
        market: arr(r.get(0)?)?,
        epoch: uint(r.get(1)?)?,
        commitment: OrderCommitment(arr(r.get(2)?)?),
        envelope_digest: hash(r.get(3)?)?,
        wallet: opt_arr(r.get(4)?)?,
        session_pk: opt_arr(r.get(5)?)?,
        submission: r.get(6)?,
        promise: r.get(7)?,
        received_at_ms: uint(r.get(8)?)?,
    })
}

fn session_from(r: &Row<'_>) -> Result<SessionRow, StoreError> {
    Ok(SessionRow {
        session_pk: arr(r.get(0)?)?,
        wallet: arr(r.get(1)?)?,
        market: opt_arr(r.get(2)?)?,
        grant_text: r.get(3)?,
        signature: arr(r.get(4)?)?,
        method: method_from(r.get(5)?)?,
        nonce: arr(r.get(6)?)?,
        issued_at_ms: opt_uint(r.get(7)?)?,
        expires_at_ms: opt_uint(r.get(8)?)?,
        revoked: flag(r.get(9)?)?,
        keep_until_epoch: opt_uint(r.get(10)?)?,
    })
}

fn method_column(m: GrantMethod) -> i64 {
    match m {
        GrantMethod::SignIn => 0,
        GrantMethod::SignMessage => 1,
    }
}

fn method_from(v: i64) -> Result<GrantMethod, StoreError> {
    match uint8(v)? {
        0 => Ok(GrantMethod::SignIn),
        1 => Ok(GrantMethod::SignMessage),
        _ => Err(StoreError::Corrupt("unknown grant method")),
    }
}

fn distinct(items: impl Iterator<Item = u32>) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    items.into_iter().all(|i| seen.insert(i))
}

const COSIG_LEN: usize = 32 + 64;

/// `(executor32 || sig64)*`
fn encode_cosigs(cosigs: &[(Address, [u8; 64])]) -> Vec<u8> {
    let mut out = Vec::with_capacity(cosigs.len() * COSIG_LEN);
    for (executor, signature) in cosigs {
        out.extend_from_slice(executor);
        out.extend_from_slice(signature);
    }
    out
}

fn decode_cosigs(bytes: Option<Vec<u8>>) -> Result<Vec<(Address, [u8; 64])>, StoreError> {
    const WRONG_LENGTH: StoreError =
        StoreError::Corrupt("co-signature column has the wrong length");
    let bytes = bytes.unwrap_or_default();
    let (records, rest) = bytes.as_chunks::<COSIG_LEN>();
    if !rest.is_empty() {
        return Err(WRONG_LENGTH);
    }
    records
        .iter()
        .map(|record| {
            let (executor, signature) = record.split_first_chunk::<32>().ok_or(WRONG_LENGTH)?;
            Ok((
                *executor,
                <[u8; 64]>::try_from(signature).map_err(|_| WRONG_LENGTH)?,
            ))
        })
        .collect()
}

/// The clearing prices and fill count of an encoded `ExecutionReceipt`
/// (`timescales_auction::receipts`), which starts `version u8 || market u64 || epoch
/// u64 || header_digest32 || seq<ClearingPrice> (<= 2) || fill_count u32`.
fn receipt_summary(receipt: &[u8]) -> Result<(Vec<ClearingPrice>, u32), StoreError> {
    fn parse(r: &mut Reader<'_>) -> Result<(Vec<ClearingPrice>, u32), DecodeError> {
        r.u8()?;
        r.u64()?;
        r.u64()?;
        r.array::<32>()?;
        let clearing = r.seq::<ClearingPrice>(2)?;
        Ok((clearing, r.u32()?))
    }
    parse(&mut Reader::new(receipt))
        .map_err(|_| StoreError::Corrupt("stored receipt does not decode"))
}

/// Splits `limit + 1` rows into the page and the next page's `before`.
fn paginate<T>(mut page: Vec<T>, limit: u32, epoch: impl Fn(&T) -> u64) -> (Vec<T>, Option<u64>) {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    if page.len() > limit {
        page.truncate(limit);
        let next = page.last().map(epoch);
        (page, next)
    } else {
        (page, None)
    }
}

fn journal_error(e: StoreError) -> JournalError {
    JournalError(e.to_string())
}

fn describe(err: &TxErrorDetail) -> String {
    match (err.ix_index, err.custom) {
        (Some(ix), Some(code)) => format!("instruction {ix}, custom {code}: {}", err.message),
        (Some(ix), None) => format!("instruction {ix}: {}", err.message),
        (None, Some(code)) => format!("custom {code}: {}", err.message),
        (None, None) => err.message.clone(),
    }
}

fn parse_op(s: &str) -> Option<TxOp> {
    Some(match s {
        "commit" => TxOp::Commit,
        "reveal" => TxOp::Reveal,
        "post" => TxOp::Post,
        "cosign" => TxOp::Cosign,
        "verify" => TxOp::Verify,
        "finalize" => TxOp::Finalize,
        "apply" => TxOp::Apply,
        "close" => TxOp::Close,
        "abort" => TxOp::Abort,
        "apply_change" => TxOp::ApplyChange,
        "reclaim" => TxOp::Reclaim,
        "admin" => TxOp::Admin,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tx_op_round_trips() {
        // A new TxOp variant fails this match until parse_op learns it.
        fn listed(op: TxOp) -> bool {
            match op {
                TxOp::Commit
                | TxOp::Reveal
                | TxOp::Post
                | TxOp::Cosign
                | TxOp::Verify
                | TxOp::Finalize
                | TxOp::Apply
                | TxOp::Close
                | TxOp::Abort
                | TxOp::ApplyChange
                | TxOp::Reclaim
                | TxOp::Admin => true,
            }
        }
        let all = [
            TxOp::Commit,
            TxOp::Reveal,
            TxOp::Post,
            TxOp::Cosign,
            TxOp::Verify,
            TxOp::Finalize,
            TxOp::Apply,
            TxOp::Close,
            TxOp::Abort,
            TxOp::ApplyChange,
            TxOp::Reclaim,
            TxOp::Admin,
        ];
        for op in all {
            assert!(listed(op));
            assert_eq!(parse_op(op.as_str()), Some(op));
        }
        assert_eq!(parse_op("unknown"), None);
    }

    #[test]
    fn phase_codes_round_trip() {
        for (code, p) in (1u8..).zip(Phase::ALL) {
            assert_eq!(p.code(), code);
            assert_eq!(Phase::from_code(code), Some(p));
        }
        assert_eq!(Phase::from_code(0), None);
        assert_eq!(Phase::from_code(14), None);
    }

    #[test]
    fn cosigs_round_trip() {
        let cosigs = vec![([1u8; 32], [2u8; 64]), ([3u8; 32], [4u8; 64])];
        assert_eq!(decode_cosigs(Some(encode_cosigs(&cosigs))).unwrap(), cosigs);
        assert_eq!(decode_cosigs(None).unwrap(), vec![]);
        assert!(decode_cosigs(Some(vec![0; 95])).is_err());
    }
}
