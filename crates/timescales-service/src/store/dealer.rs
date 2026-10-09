//! The trusted dealer's `dealer.sqlite`: announcements, sealed share
//! deliveries until delivered, acks and bundle state. No plaintext secrets.
//!
//! The repository keeps the dealer's invariant: at most one announcement
//! per (market, epoch) and committee, ever. A dealing is recorded
//! before anything is sent and never replaced. [`DealerRepo::supersede`]
//! removes the dealings of a committee an emergency rotation replaced and
//! keeps an audit row for each, and no announcement under that committee is
//! accepted for those epochs again.

use std::collections::BTreeSet;

use crate::wire::{EpochKeyAck, EpochKeyAnnouncement};
use rusqlite::{Connection, params};
use timescales_core::{Decode, Hash32};

use crate::store::node::PutOutcome;
use crate::store::sql::{bound, count, exec, flag, int, now_ms, row, rows, uint, uint8};
use crate::store::{Address, Schema, Store, StoreError};

/// Everything recorded about one dealt epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dealing {
    pub announcement: Vec<u8>,
    /// (member index, sealed `ShareDelivery`) until the bundle is delivered.
    pub deliveries: Vec<(u8, Vec<u8>)>,
    pub acks: Vec<Vec<u8>>,
    pub bundle: Option<Vec<u8>>,
    pub bundle_delivered: bool,
    pub created_at_ms: u64,
}

#[derive(Debug)]
pub struct DealerRepo {
    store: Store,
}

impl DealerRepo {
    /// # Panics
    ///
    /// If `store` was not opened with [`Schema::Dealer`].
    pub fn new(store: Store) -> Self {
        assert_eq!(
            store.schema(),
            Schema::Dealer,
            "DealerRepo needs dealer.sqlite"
        );
        Self { store }
    }

    /// BEFORE any send.
    ///
    /// Records the announcement and the sealed deliveries (one per member
    /// index) in one transaction and returns once they are durable. The
    /// same announcement again is `Identical` (its stored deliveries are
    /// the ones to re-send). A different one, or one under a committee
    /// whose dealing for the epoch was superseded, is `Conflict`: an epoch
    /// is never dealt twice.
    pub async fn record_dealing(
        &self,
        m: Address,
        e: u64,
        ann: Vec<u8>,
        deliveries: Vec<(u8, Vec<u8>)>,
    ) -> Result<PutOutcome, StoreError> {
        let decoded = decode_announcement(&ann, m, e)?;
        let mut members = BTreeSet::new();
        if !deliveries.iter().all(|(member, _)| members.insert(*member)) {
            return Err(StoreError::Conflict("two deliveries for one member"));
        }
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                match stored_announcement(tx, &m, epoch)? {
                    Some(stored) if stored == ann => return Ok(PutOutcome::Identical),
                    Some(_) => return Ok(PutOutcome::Conflict),
                    None => {}
                }
                if superseded(tx, &m, epoch, &decoded.committee_digest)? {
                    return Ok(PutOutcome::Conflict);
                }
                insert_dealing(tx, &m, epoch, &ann, &decoded)?;
                for (member, sealed) in deliveries {
                    exec(tx,
                        "INSERT INTO deliveries(market, epoch, member, sealed) VALUES (?1, ?2, ?3, ?4)",
                        params![m, epoch, member, sealed],
                    )?;
                }
                Ok(PutOutcome::Inserted)
            })
            .await
    }

    pub async fn dealing(&self, m: Address, e: u64) -> Result<Option<Dealing>, StoreError> {
        self.store
            .read(move |c| {
                let epoch = bound(e);
                let Some((announcement, created_at_ms)) = row(
                    c,
                    "SELECT announcement, created_at_ms FROM dealings WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                    |r| Ok((r.get::<_, Vec<u8>>(0)?, uint(r.get(1)?)?)),
                )?
                else {
                    return Ok(None);
                };
                let deliveries = rows(
                    c,
                    "SELECT member, sealed FROM deliveries WHERE market = ?1 AND epoch = ?2 ORDER BY member",
                    params![m, epoch],
                    |r| Ok((uint8(r.get(0)?)?, r.get(1)?)),
                )?;
                let acks = rows(
                    c,
                    "SELECT ack FROM acks WHERE market = ?1 AND epoch = ?2 ORDER BY member",
                    params![m, epoch],
                    |r| Ok(r.get(0)?),
                )?;
                let bundle = row(
                    c,
                    "SELECT bundle, state FROM bundles WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                    |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?)),
                )?;
                let bundle_delivered = bundle.as_ref().is_some_and(|(_, s)| s == "delivered");
                Ok(Some(Dealing {
                    announcement,
                    deliveries,
                    acks,
                    bundle: bundle.map(|(b, _)| b),
                    bundle_delivered,
                    created_at_ms,
                }))
            })
            .await
    }

    /// Returns the number of acks so far.
    ///
    /// The member index is read from the encoded `EpochKeyAck`. A member's
    /// newer ack (for example after a policy change) replaces its older
    /// one. The caller verifies acks before recording them.
    pub async fn record_ack(&self, m: Address, e: u64, ack: Vec<u8>) -> Result<u8, StoreError> {
        let member = EpochKeyAck::decode_exact(&ack)
            .map_err(|_| StoreError::Conflict("the ack does not decode"))?
            .member;
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                if stored_announcement(tx, &m, epoch)?.is_none() {
                    return Err(StoreError::Conflict("no dealing for this epoch"));
                }
                exec(tx,
                    "INSERT INTO acks(market, epoch, member, ack, received_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(market, epoch, member) DO UPDATE
                       SET ack = excluded.ack, received_at_ms = excluded.received_at_ms",
                    params![m, epoch, member, ack, int(now_ms())?],
                )?;
                let acks: i64 = tx.query_row(
                    "SELECT count(*) FROM acks WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                    |r| r.get(0),
                )?;
                uint8(acks)
            })
            .await
    }

    /// Write-ahead before `KeyBundlePut`.
    ///
    /// Recording the same bundle again is a no-op. A different one for the
    /// epoch is a `Conflict`, so a dealer that restarts re-sends exactly
    /// the bundle it may already have delivered.
    pub async fn bundle_intent(
        &self,
        m: Address,
        e: u64,
        bundle: Vec<u8>,
    ) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                if stored_announcement(tx, &m, epoch)?.is_none() {
                    return Err(StoreError::Conflict("no dealing for this epoch"));
                }
                let stored = row(
                    tx,
                    "SELECT bundle FROM bundles WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                    |r| Ok(r.get::<_, Vec<u8>>(0)?),
                )?;
                match stored {
                    Some(stored) if stored == bundle => Ok(()),
                    Some(_) => Err(StoreError::Conflict("a different bundle is recorded")),
                    None => {
                        exec(
                            tx,
                            "INSERT INTO bundles(market, epoch, bundle, state, updated_at_ms)
                             VALUES (?1, ?2, ?3, 'intent', ?4)",
                            params![m, epoch, bundle, int(now_ms())?],
                        )?;
                        Ok(())
                    }
                }
            })
            .await
    }

    /// Deletes the stored deliveries.
    pub async fn bundle_delivered(&self, m: Address, e: u64) -> Result<(), StoreError> {
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                let changed = exec(
                    tx,
                    "UPDATE bundles SET state = 'delivered', updated_at_ms = ?3
                     WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch, int(now_ms())?],
                )?;
                if changed == 0 {
                    return Err(StoreError::Conflict("no bundle intent for this epoch"));
                }
                exec(
                    tx,
                    "DELETE FROM deliveries WHERE market = ?1 AND epoch = ?2",
                    params![m, epoch],
                )?;
                Ok(())
            })
            .await
    }

    /// Deletes the sealed deliveries of every epoch up to `e`, the market's
    /// last terminal epoch: the dealer keeps them only until the bundle is
    /// delivered or the epoch is terminal. Returns the rows deleted.
    /// Announcements, acks and bundles stay.
    pub async fn prune_through(&self, m: Address, e: u64) -> Result<u64, StoreError> {
        self.store
            .write(move |tx| {
                Ok(count(exec(
                    tx,
                    "DELETE FROM deliveries WHERE market = ?1 AND epoch <= ?2",
                    params![m, bound(e)],
                )?))
            })
            .await
    }

    /// Recovery.
    ///
    /// Records an announcement learned from members or the node after
    /// `dealer.sqlite` was lost, with the acks found for it. There are no
    /// deliveries: the dealer no longer holds the shares. Adopting the
    /// recorded announcement again adds acks it lacks. Another announcement
    /// for the epoch is a `Conflict`.
    pub async fn adopt(
        &self,
        m: Address,
        e: u64,
        ann: Vec<u8>,
        acks: Vec<Vec<u8>>,
    ) -> Result<(), StoreError> {
        let decoded = decode_announcement(&ann, m, e)?;
        let acks = acks
            .into_iter()
            .map(|ack| {
                let member = EpochKeyAck::decode_exact(&ack)
                    .map_err(|_| StoreError::Conflict("an ack does not decode"))?
                    .member;
                Ok((member, ack))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        self.store
            .write(move |tx| {
                let epoch = int(e)?;
                match stored_announcement(tx, &m, epoch)? {
                    Some(stored) if stored == ann => {}
                    Some(_) => {
                        return Err(StoreError::Conflict(
                            "another announcement is recorded for this epoch",
                        ));
                    }
                    None => {
                        if superseded(tx, &m, epoch, &decoded.committee_digest)? {
                            return Err(StoreError::Conflict(
                                "the announcement's committee was superseded for this epoch",
                            ));
                        }
                        insert_dealing(tx, &m, epoch, &ann, &decoded)?;
                    }
                }
                let at = int(now_ms())?;
                for (member, ack) in acks {
                    exec(tx,
                        "INSERT INTO acks(market, epoch, member, ack, received_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT(market, epoch, member) DO NOTHING",
                        params![m, epoch, member, ack, at],
                    )?;
                }
                Ok(())
            })
            .await
    }

    /// Emergency rotation. An audit row is kept.
    ///
    /// Removes every dealing of the market from `from_epoch` on that was
    /// dealt under `old_committee` (with its deliveries, acks and bundle)
    /// and records one `superseded` row per epoch. Returns how many
    /// dealings were removed.
    pub async fn supersede(
        &self,
        m: Address,
        from_epoch: u64,
        old_committee: Hash32,
    ) -> Result<u64, StoreError> {
        self.store
            .write(move |tx| {
                let victims = rows(
                    tx,
                    "SELECT epoch, ann_digest FROM dealings
                     WHERE market = ?1 AND epoch >= ?2 AND committee_digest = ?3 ORDER BY epoch",
                    params![m, bound(from_epoch), old_committee.0],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
                )?;
                let at = int(now_ms())?;
                for (epoch, ann_digest) in &victims {
                    for table in ["deliveries", "acks", "bundles", "dealings"] {
                        exec(
                            tx,
                            &format!("DELETE FROM {table} WHERE market = ?1 AND epoch = ?2"),
                            params![m, epoch],
                        )?;
                    }
                    exec(
                        tx,
                        "INSERT INTO superseded(market, epoch, committee_digest, ann_digest, at_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![m, epoch, old_committee.0, ann_digest, at],
                    )?;
                }
                Ok(count(victims.len()))
            })
            .await
    }
}

fn decode_announcement(ann: &[u8], m: Address, e: u64) -> Result<EpochKeyAnnouncement, StoreError> {
    let decoded = EpochKeyAnnouncement::decode_exact(ann)
        .map_err(|_| StoreError::Conflict("the announcement does not decode"))?;
    if decoded.market != m || decoded.epoch.0 != e {
        return Err(StoreError::Conflict(
            "the announcement names another market or epoch",
        ));
    }
    Ok(decoded)
}

fn stored_announcement(
    c: &Connection,
    m: &Address,
    epoch: i64,
) -> Result<Option<Vec<u8>>, StoreError> {
    row(
        c,
        "SELECT announcement FROM dealings WHERE market = ?1 AND epoch = ?2",
        params![m, epoch],
        |r| Ok(r.get(0)?),
    )
}

fn superseded(
    c: &Connection,
    m: &Address,
    epoch: i64,
    committee: &Hash32,
) -> Result<bool, StoreError> {
    let found: i64 = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM superseded WHERE market = ?1 AND epoch = ?2 AND committee_digest = ?3)",
        params![m, epoch, committee.0],
        |r| r.get(0),
    )?;
    flag(found)
}

fn insert_dealing(
    c: &Connection,
    m: &Address,
    epoch: i64,
    ann: &[u8],
    decoded: &EpochKeyAnnouncement,
) -> Result<(), StoreError> {
    exec(c,
        "INSERT INTO dealings(market, epoch, announcement, ann_digest, committee_digest, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            m,
            epoch,
            ann,
            decoded.digest().0,
            decoded.committee_digest.0,
            int(now_ms())?
        ],
    )?;
    Ok(())
}
