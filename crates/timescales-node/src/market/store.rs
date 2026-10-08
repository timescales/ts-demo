//! Reads and one write the engine needs that `NodeRepo` does not offer
//! yet, as SQL over the node schema through `Store::read`/`write`. The
//! live here, next to their only callers.

use timescales_service::store::StoreError;
use timescales_service::store::node::{EpochRow, NodeRepo, Phase};

use crate::Address;

fn int(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Conflict("integer exceeds the store's range"))
}

fn uint(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt("negative integer column"))
}

/// The persisted `ClosedBatch` bytes of an epoch.
pub(crate) async fn closed_batch(
    repo: &NodeRepo,
    m: Address,
    e: u64,
) -> Result<Option<Vec<u8>>, StoreError> {
    let e = int(e)?;
    repo.store()
        .read(move |c| {
            let mut stmt =
                c.prepare("SELECT closed FROM closed WHERE market = ?1 AND epoch = ?2")?;
            let mut rows = stmt.query((m, e))?;
            match rows.next()? {
                Some(r) => Ok(Some(r.get::<_, Vec<u8>>(0)?)),
                None => Ok(None),
            }
        })
        .await
}

/// A stored result whether or not its artifacts are public yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredResult {
    pub(crate) receipt: Vec<u8>,
    pub(crate) artifacts: Vec<u8>,
    pub(crate) attestation: Option<Vec<u8>>,
    pub(crate) cosigs: Vec<(Address, [u8; 64])>,
}

pub(crate) async fn result(
    repo: &NodeRepo,
    m: Address,
    e: u64,
) -> Result<Option<StoredResult>, StoreError> {
    let e = int(e)?;
    repo.store()
        .read(move |c| {
            let mut stmt = c.prepare(
                "SELECT receipt, artifacts, attestation, cosigs FROM results
                 WHERE market = ?1 AND epoch = ?2",
            )?;
            let mut rows = stmt.query((m, e))?;
            let Some(r) = rows.next()? else {
                return Ok(None);
            };
            let cosigs: Option<Vec<u8>> = r.get(3)?;
            let cosigs = cosigs.unwrap_or_default();
            let (records, rest) = cosigs.as_chunks::<96>();
            if !rest.is_empty() {
                return Err(StoreError::Corrupt(
                    "co-signature column has the wrong length",
                ));
            }
            let cosigs = records
                .iter()
                .map(|rec| {
                    let mut executor = [0u8; 32];
                    let mut sig = [0u8; 64];
                    executor.copy_from_slice(&rec[..32]);
                    sig.copy_from_slice(&rec[32..]);
                    (executor, sig)
                })
                .collect();
            Ok(Some(StoredResult {
                receipt: r.get(0)?,
                artifacts: r.get(1)?,
                attestation: r.get(2)?,
                cosigs,
            }))
        })
        .await
}

/// The epoch a wallet's ban lasts through, if it is banned at `epoch`.
pub(crate) async fn banned_until(
    repo: &NodeRepo,
    m: Address,
    wallet: Address,
    epoch: u64,
) -> Result<Option<u64>, StoreError> {
    let e = int(epoch)?;
    repo.store()
        .read(move |c| {
            let mut stmt = c.prepare(
                "SELECT until_epoch FROM bans WHERE market = ?1 AND wallet = ?2 AND until_epoch >= ?3",
            )?;
            let mut rows = stmt.query((m, wallet, e))?;
            match rows.next()? {
                Some(r) => Ok(Some(uint(r.get(0)?)?)),
                None => Ok(None),
            }
        })
        .await
}

/// The newest settled or aborted epoch.
pub(crate) async fn last_terminal(
    repo: &NodeRepo,
    m: Address,
) -> Result<Option<EpochRow>, StoreError> {
    let settled = i64::from(Phase::Settled.code());
    let aborted = i64::from(Phase::Aborted.code());
    let epoch = repo
        .store()
        .read(move |c| {
            let mut stmt =
                c.prepare("SELECT MAX(epoch) FROM epochs WHERE market = ?1 AND phase IN (?2, ?3)")?;
            let mut rows = stmt.query((m, settled, aborted))?;
            match rows.next()? {
                Some(r) => r.get::<_, Option<i64>>(0)?.map(uint).transpose(),
                None => Ok(None),
            }
        })
        .await?;
    match epoch {
        Some(e) => repo.epoch(m, e).await,
        None => Ok(None),
    }
}

/// The newest settled epoch before `before` whose order state is
/// confirmed: the carried state the batch of `before` executes against.
pub(crate) async fn carried_state_epoch(
    repo: &NodeRepo,
    m: Address,
    before: u64,
) -> Result<Option<u64>, StoreError> {
    let before = int(before)?;
    repo.store()
        .read(move |c| {
            let mut stmt = c.prepare(
                "SELECT MAX(epoch) FROM order_state WHERE market = ?1 AND confirmed = 1 AND epoch < ?2",
            )?;
            let mut rows = stmt.query((m, before))?;
            match rows.next()? {
                Some(r) => r.get::<_, Option<i64>>(0)?.map(uint).transpose(),
                None => Ok(None),
            }
        })
        .await
}

/// The digest of the receipt of the newest settled epoch before `before`
/// (what `Market.prev_receipt` held while `before` was in flight), from
/// the stored rows.
pub(crate) async fn prev_receipt_before(
    repo: &NodeRepo,
    m: Address,
    before: u64,
) -> Result<Option<Vec<u8>>, StoreError> {
    let before = int(before)?;
    let settled = i64::from(Phase::Settled.code());
    repo.store()
        .read(move |c| {
            let mut stmt = c.prepare(
                "SELECT receipt FROM epochs WHERE market = ?1 AND phase = ?2 AND epoch < ?3
                 AND receipt IS NOT NULL ORDER BY epoch DESC LIMIT 1",
            )?;
            let mut rows = stmt.query((m, settled, before))?;
            match rows.next()? {
                Some(r) => Ok(Some(r.get::<_, Vec<u8>>(0)?)),
                None => Ok(None),
            }
        })
        .await
}

/// Writes the row of an epoch this database never had: one the chain
/// already holds and recovery adopts (AHEAD with
/// `--accept-chain-ahead`). An existing row is left alone.
pub(crate) async fn adopt_epoch(repo: &NodeRepo, row: EpochRow) -> Result<bool, StoreError> {
    let epoch = int(row.epoch)?;
    let phase = i64::from(row.phase.code());
    let root = row.root.map(|h| h.0);
    let count = row.envelope_count;
    let terms = row.terms_digest.map(|h| h.0);
    let commit_slot = row.commit_slot.map(int).transpose()?;
    let abort_reason = row.abort_reason;
    let detail = row.abort_detail.clone();
    let terminal = row.terminal_slot.map(int).transpose()?;
    let updated = int(row.updated_at_ms)?;
    let m = row.market;
    repo.store()
        .write(move |tx| {
            let n = tx.execute(
                "INSERT OR IGNORE INTO epochs(market, epoch, phase, root, envelope_count,
                   terms_digest, commit_slot, abort_reason, abort_detail, terminal_slot, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                (m, epoch, phase, root, count, terms, commit_slot, abort_reason, detail, terminal, updated),
            )?;
            Ok(n == 1)
        })
        .await
}

/// Lists the epochs with a stored key bundle at or after `from`, with the
/// bundle bytes and whether it was served.
pub(crate) async fn bundles_from(
    repo: &NodeRepo,
    m: Address,
    from: u64,
) -> Result<Vec<(u64, Vec<u8>, bool)>, StoreError> {
    let from = int(from)?;
    repo.store()
        .read(move |c| {
            let mut stmt = c.prepare(
                "SELECT epoch, bundle, served FROM key_bundles WHERE market = ?1 AND epoch >= ?2
                 ORDER BY epoch",
            )?;
            let mut rows = stmt.query((m, from))?;
            let mut out = Vec::new();
            while let Some(r) = rows.next()? {
                out.push((uint(r.get(0)?)?, r.get(1)?, r.get::<_, i64>(2)? != 0));
            }
            Ok(out)
        })
        .await
}

/// Every parked envelope of a market (start-up restore).
pub(crate) async fn all_parked(
    repo: &NodeRepo,
    m: Address,
) -> Result<Vec<timescales_service::store::node::SubmissionRow>, StoreError> {
    let epochs = repo
        .store()
        .read(move |c| {
            let mut stmt =
                c.prepare("SELECT DISTINCT epoch FROM parked WHERE market = ?1 ORDER BY epoch")?;
            let mut rows = stmt.query((m,))?;
            let mut out = Vec::new();
            while let Some(r) = rows.next()? {
                out.push(uint(r.get(0)?)?);
            }
            Ok(out)
        })
        .await?;
    let mut all = Vec::new();
    for e in epochs {
        all.extend(repo.parked_for_epoch(m, e).await?);
    }
    Ok(all)
}

/// Clears the abort columns of an epoch whose abort the chain superseded:
/// it resumes and may still settle.
pub(crate) async fn clear_abort(repo: &NodeRepo, m: Address, e: u64) -> Result<(), StoreError> {
    let e = int(e)?;
    repo.store()
        .write(move |tx| {
            tx.execute(
                "UPDATE epochs SET abort_reason = NULL, abort_detail = NULL
                 WHERE market = ?1 AND epoch = ?2",
                (m, e),
            )?;
            Ok(())
        })
        .await
}
