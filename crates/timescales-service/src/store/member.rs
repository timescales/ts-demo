//! A key-release member's two files: `member.sqlite` (announcements,
//! header pins, audit log. Backed up) and `shares.sqlite` (shares sealed
//! under the ratcheting at-rest key. Never backed up or replicated).
//!
//! Shares reach the repository already sealed with the member's
//! [`RatchetSealer`] (AAD `market || epoch || index`), so no plaintext share
//! is ever handed to SQLite. The repository reads the key generation from
//! the sealed value and keeps the sealer to erase generations nothing needs
//! any more. Writes that touch both files store the announcement before the
//! share and remove the share before anything else, so a crash between the
//! two leaves a state the next delivery or prune completes.

use std::sync::Arc;

use crate::wire::EpochKeyAnnouncement;
use rusqlite::{Connection, params};
use timescales_core::{Decode, Hash32};

use crate::store::node::PutOutcome;
use crate::store::sealer::sealed_generation;
use crate::store::sql::{arr, bound, count, exec, hash, int, now_ms, opt_uint32, row, uint32};
use crate::store::{Address, PruneReport, RatchetSealer, Schema, Store, StoreError};

/// Result of pinning a header for (market, epoch) and counting a release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinOutcome {
    Pinned,
    Matches,
    Other(Hash32),
    TooMany,
}

/// A row of the release audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseAudit {
    pub market: Address,
    pub epoch: u64,
    pub executor: [u8; 32],
    pub seal_key: [u8; 32],
    pub header_digest: Hash32,
    pub quote_hash: Hash32,
    /// `ReleaseRefusal` code, 0 for a release.
    pub result: u8,
    pub at_ms: u64,
}

#[derive(Debug)]
pub struct MemberRepo {
    member: Store,
    shares: Store,
    sealer: Arc<RatchetSealer>,
}

impl MemberRepo {
    /// # Panics
    ///
    /// If `member` was not opened with [`Schema::Member`] or `shares` with
    /// [`Schema::MemberShares`].
    pub fn new(member: Store, shares: Store, sealer: Arc<RatchetSealer>) -> Self {
        assert_eq!(
            member.schema(),
            Schema::Member,
            "MemberRepo needs member.sqlite"
        );
        assert_eq!(
            shares.schema(),
            Schema::MemberShares,
            "MemberRepo needs shares.sqlite"
        );
        Self {
            member,
            shares,
            sealer,
        }
    }

    /// `Conflict` = a different announcement is stored.
    ///
    /// Stores the announcement in `member.sqlite`, then the share in
    /// `shares.sqlite`. `Inserted` when the share was stored now (also after
    /// a crash that stored only the announcement), `Identical` when the
    /// same announcement and its share were already there. Refused (`Err`)
    /// when `ann` does not decode to `ann_digest` for (m, e), when the
    /// share is not sealed under a live key generation, and for an epoch
    /// whose shares were already destroyed.
    pub async fn put_share(
        &self,
        m: Address,
        e: u64,
        ann: Vec<u8>,
        ann_digest: Hash32,
        sealed: Vec<u8>,
        at_ms: u64,
    ) -> Result<PutOutcome, StoreError> {
        check_announcement(&ann, &ann_digest, m, e)?;
        let generation = sealed_generation(&sealed)
            .ok_or(StoreError::Conflict("the share is not sealed at rest"))?;
        let epoch = int(e)?;
        let at = int(at_ms)?;
        let announced = self
            .member
            .write(move |tx| {
                if pruned_through(tx, &m)?.is_some_and(|p| e <= p) {
                    return Err(StoreError::Conflict("the epoch's shares were already destroyed"));
                }
                match stored_digest(tx, "announcements", &m, epoch)? {
                    Some(d) if d == ann_digest => Ok(PutOutcome::Identical),
                    Some(_) => Ok(PutOutcome::Conflict),
                    None => {
                        exec(tx,
                            "INSERT INTO announcements(market, epoch, announcement, ann_digest, received_at_ms)
                             VALUES (?1, ?2, ?3, ?4, ?5)",
                            params![m, epoch, ann, ann_digest.0, at],
                        )?;
                        Ok(PutOutcome::Inserted)
                    }
                }
            })
            .await?;
        if announced == PutOutcome::Conflict {
            return Ok(PutOutcome::Conflict);
        }
        let sealer = Arc::clone(&self.sealer);
        self.shares
            .write(move |tx| match stored_digest(tx, "shares", &m, epoch)? {
                Some(d) if d == ann_digest => Ok(PutOutcome::Identical),
                Some(_) => Ok(PutOutcome::Conflict),
                None => {
                    if !sealer.has_generation(generation) {
                        return Err(StoreError::Conflict(
                            "the share is sealed under an erased key generation",
                        ));
                    }
                    exec(tx,
                        "INSERT INTO shares(market, epoch, ann_digest, kek_generation, share_sealed, received_at_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![m, epoch, ann_digest.0, generation, sealed, at],
                    )?;
                    Ok(PutOutcome::Inserted)
                }
            })
            .await
    }

    /// The stored announcement and its digest.
    pub async fn announcement(
        &self,
        m: Address,
        e: u64,
    ) -> Result<Option<(Vec<u8>, Hash32)>, StoreError> {
        self.member
            .read(move |c| {
                row(
                    c,
                    "SELECT announcement, ann_digest FROM announcements WHERE market = ?1 AND epoch = ?2",
                    params![m, bound(e)],
                    |r| Ok((r.get(0)?, hash(r.get(1)?)?)),
                )
            })
            .await
    }

    /// The share as sealed at rest. The member opens it inside a release.
    pub async fn share(&self, m: Address, e: u64) -> Result<Option<Vec<u8>>, StoreError> {
        self.shares
            .read(move |c| {
                row(
                    c,
                    "SELECT share_sealed FROM shares WHERE market = ?1 AND epoch = ?2",
                    params![m, bound(e)],
                    |r| Ok(r.get(0)?),
                )
            })
            .await
    }

    /// The pin and the release count in one transaction: pins `header_digest` for
    /// (m, e) unless another header is pinned, and counts this release
    /// unless `max` releases were already counted.
    pub async fn pin_and_count(
        &self,
        m: Address,
        e: u64,
        header_digest: Hash32,
        max: u32,
    ) -> Result<PinOutcome, StoreError> {
        self.member
            .write(move |tx| {
                let epoch = int(e)?;
                let pin = row(
                    tx,
                    "SELECT header_digest, releases FROM pins WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                    |r| Ok((hash(r.get(0)?)?, uint32(r.get(1)?)?)),
                )?;
                match pin {
                    None if max == 0 => Ok(PinOutcome::TooMany),
                    None => {
                        exec(
                            tx,
                            "INSERT INTO pins(market, epoch, header_digest, releases, pinned_at_ms)
                             VALUES (?1, ?2, ?3, 1, ?4)",
                            params![m, epoch, header_digest.0, int(now_ms())?],
                        )?;
                        Ok(PinOutcome::Pinned)
                    }
                    Some((pinned, _)) if pinned != header_digest => Ok(PinOutcome::Other(pinned)),
                    Some((_, releases)) if releases >= max => Ok(PinOutcome::TooMany),
                    Some((_, releases)) => {
                        exec(
                            tx,
                            "UPDATE pins SET releases = ?3 WHERE market = ?1 AND epoch = ?2",
                            params![m, epoch, releases + 1],
                        )?;
                        Ok(PinOutcome::Matches)
                    }
                }
            })
            .await
    }

    pub async fn audit(&self, row: ReleaseAudit) -> Result<(), StoreError> {
        self.member
            .write(move |tx| {
                exec(tx,
                    "INSERT INTO releases(market, epoch, executor, seal_key, header_digest, quote_hash, result, at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        row.market,
                        int(row.epoch)?,
                        row.executor,
                        row.seal_key,
                        row.header_digest.0,
                        row.quote_hash.0,
                        row.result,
                        int(row.at_ms)?
                    ],
                )?;
                Ok(())
            })
            .await
    }

    /// Deletes shares, pins and announcements of every epoch through `e`,
    /// then `checkpoint(TRUNCATE)`, so no destroyed share survives in the
    /// WAL either (`shares.sqlite` runs with `secure_delete`). Returns the
    /// number of shares destroyed. Deliveries for those epochs are refused
    /// from then on.
    pub async fn destroy_through(&self, m: Address, e: u64) -> Result<u64, StoreError> {
        let through = bound(e);
        let destroyed = self
            .shares
            .write(move |tx| {
                Ok(count(exec(
                    tx,
                    "DELETE FROM shares WHERE market = ?1 AND epoch <= ?2",
                    params![m, through],
                )?))
            })
            .await?;
        self.member
            .write(move |tx| {
                exec(tx,
                    "DELETE FROM pins WHERE market = ?1 AND epoch <= ?2",
                    params![m, through],
                )?;
                exec(tx,
                    "DELETE FROM announcements WHERE market = ?1 AND epoch <= ?2",
                    params![m, through],
                )?;
                if pruned_through(tx, &m)?.is_none_or(|p| p < e) {
                    exec(tx,
                        "INSERT INTO meta(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                        params![pruned_key(&m), e.to_le_bytes()],
                    )?;
                }
                Ok(())
            })
            .await?;
        self.shares.checkpoint_truncate().await?;
        Ok(destroyed)
    }

    /// Erases older at-rest key generations.
    ///
    /// Erases every generation below `keep_from_generation` that no stored
    /// share is sealed under (and never the current one). Runs on the
    /// shares writer, so a share stored concurrently either keeps its
    /// generation alive or is refused because the generation is gone.
    pub async fn ratchet(&self, keep_from_generation: u32) -> Result<(), StoreError> {
        let sealer = Arc::clone(&self.sealer);
        self.shares
            .write(move |tx| {
                let oldest: Option<i64> =
                    tx.query_row("SELECT MIN(kek_generation) FROM shares", [], |r| r.get(0))?;
                let keep_from = opt_uint32(oldest)?
                    .map_or(keep_from_generation, |g| g.min(keep_from_generation));
                let erased = sealer.erase_below(keep_from).map_err(|e| {
                    tracing::error!(error = %e, "erasing at-rest key generations failed");
                    StoreError::Conflict("the at-rest key file could not be rewritten")
                })?;
                if !erased.is_empty() {
                    tracing::info!(?erased, "erased at-rest key generations");
                }
                Ok(())
            })
            .await
    }

    /// Emergency rotation only: replaces a share whose
    /// announcement names `Market.prev_committee_digest` with one for
    /// `Market.committee_digest`, destroying the old share in the same
    /// transaction.
    ///
    /// The caller checks the two digests against chain state. This refuses
    /// a rotation when no share is stored or the new announcement names the
    /// stored one's committee. Repeating a completed rotation is a no-op.
    /// The WAL is truncated afterwards so the old share does not survive in
    /// it.
    pub async fn rotate_share(
        &self,
        m: Address,
        e: u64,
        ann: Vec<u8>,
        ann_digest: Hash32,
        sealed: Vec<u8>,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let new = check_announcement(&ann, &ann_digest, m, e)?;
        let generation = sealed_generation(&sealed)
            .ok_or(StoreError::Conflict("the share is not sealed at rest"))?;
        let epoch = int(e)?;
        let at = int(at_ms)?;
        let stored = self
            .member
            .read(move |c| {
                row(
                    c,
                    "SELECT announcement FROM announcements WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                    |r| Ok(r.get::<_, Vec<u8>>(0)?),
                )
            })
            .await?;
        if let Some(stored) = stored {
            let stored = EpochKeyAnnouncement::decode_exact(&stored)
                .map_err(|_| StoreError::Corrupt("stored announcement does not decode"))?;
            if stored.digest() != ann_digest && stored.committee_digest == new.committee_digest {
                return Err(StoreError::Conflict(
                    "a rotation needs an announcement under another committee",
                ));
            }
        }
        let sealer = Arc::clone(&self.sealer);
        let replaced =
            self.shares
                .write(move |tx| match stored_digest(tx, "shares", &m, epoch)? {
                    None => Err(StoreError::Conflict("no share to rotate")),
                    Some(d) if d == ann_digest => Ok(false),
                    Some(_) => {
                        if !sealer.has_generation(generation) {
                            return Err(StoreError::Conflict(
                                "the share is sealed under an erased key generation",
                            ));
                        }
                        exec(tx,
                        "UPDATE shares SET ann_digest = ?3, kek_generation = ?4, share_sealed = ?5,
                           received_at_ms = ?6
                         WHERE market = ?1 AND epoch = ?2",
                        params![m, epoch, ann_digest.0, generation, sealed, at],
                    )?;
                        Ok(true)
                    }
                })
                .await?;
        self.member
            .write(move |tx| {
                exec(tx,
                    "INSERT OR REPLACE INTO announcements(market, epoch, announcement, ann_digest, received_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![m, epoch, ann, ann_digest.0, at],
                )?;
                Ok(())
            })
            .await?;
        if replaced {
            self.shares.checkpoint_truncate().await?;
        }
        Ok(())
    }

    /// Drops expired audit rows. Shares are destroyed through
    /// [`MemberRepo::destroy_through`].
    pub async fn prune_audit(&self, older_than_ms: u64) -> Result<PruneReport, StoreError> {
        self.member
            .write(move |tx| {
                let rows_deleted = count(exec(
                    tx,
                    "DELETE FROM releases WHERE at_ms < ?1",
                    [bound(older_than_ms)],
                )?);
                Ok(PruneReport {
                    rows_deleted,
                    wallets_nulled: 0,
                })
            })
            .await
    }
}

/// Decodes `ann` and checks that it is the announcement for (m, e) whose
/// digest is `digest`.
fn check_announcement(
    ann: &[u8],
    digest: &Hash32,
    m: Address,
    e: u64,
) -> Result<EpochKeyAnnouncement, StoreError> {
    let decoded = EpochKeyAnnouncement::decode_exact(ann)
        .map_err(|_| StoreError::Conflict("the announcement does not decode"))?;
    if decoded.market != m || decoded.epoch.0 != e {
        return Err(StoreError::Conflict(
            "the announcement names another market or epoch",
        ));
    }
    if decoded.digest() != *digest {
        return Err(StoreError::Conflict(
            "the announcement does not match its digest",
        ));
    }
    Ok(decoded)
}

/// The announcement digest stored for (m, e) in `announcements` or `shares`.
fn stored_digest(
    c: &Connection,
    table: &str,
    m: &Address,
    epoch: i64,
) -> Result<Option<Hash32>, StoreError> {
    row(
        c,
        &format!("SELECT ann_digest FROM {table} WHERE market = ?1 AND epoch = ?2"),
        params![m, epoch],
        |r| hash(r.get(0)?),
    )
}

fn pruned_key(m: &Address) -> String {
    format!("pruned_through:{}", Hash32(*m).to_hex())
}

/// The last epoch [`MemberRepo::destroy_through`] destroyed for the market.
fn pruned_through(c: &Connection, m: &Address) -> Result<Option<u64>, StoreError> {
    row(c, "SELECT v FROM meta WHERE k = ?1", [pruned_key(m)], |r| {
        Ok(u64::from_le_bytes(arr(r.get(0)?)?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruned_key_names_the_market() {
        assert_eq!(
            pruned_key(&[0xab; 32]),
            format!("pruned_through:{}", "ab".repeat(32))
        );
    }
}
