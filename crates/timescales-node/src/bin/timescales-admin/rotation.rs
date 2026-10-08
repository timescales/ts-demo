//! `rotation invalidate`: after an emergency committee
//! rotation, drop the node's scheduled epoch-key bundles that the old
//! committee dealt, delete the envelopes parked for those epochs and tell
//! clients (`parked.invalidated`), so the dealer re-deals them under the new
//! committee and the SDK re-seals.
//!
//! The node exposes no admin route for this (`AdminCmd` has no such
//! command), so the command works on the node's database directly, with the
//! node stopped: it takes the node's `LOCK` (the same `flock` the node
//! holds while running) and refuses if the node has it.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use timescales_core::{Decode, Hash32};
use timescales_service::store::node::{NodeRepo, Phase};
use timescales_service::store::{Schema, Store, StoreOptions};
use timescales_service::wire::EpochKeyBundle;

use crate::util::{Key, b58, now_ms};

/// The node's database and lock inside its `data_dir`.
const NODE_DB: &str = "node.sqlite";
const NODE_LOCK: &str = "LOCK";

/// Holds the node's lock for as long as it lives.
#[derive(Debug)]
pub(crate) struct NodeLock {
    _file: File,
}

pub(crate) fn lock_node(data_dir: &Path) -> Result<NodeLock> {
    let path = data_dir.join(NODE_LOCK);
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(NodeLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => bail!(
            "the node holds {}; stop it before invalidating (the rotation edits its database)",
            path.display()
        ),
        Err(std::fs::TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("lock {}", path.display()))
        }
    }
}

/// What one invalidation did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Invalidated {
    pub(crate) epochs: Vec<u64>,
    pub(crate) parked_deleted: u64,
    /// Scheduled epochs from `from_epoch` on whose bundle names the current
    /// committee already. They stay.
    pub(crate) kept: Vec<u64>,
}

/// Drops the scheduled bundles of epochs `>= from_epoch` that were dealt
/// under a committee other than `current` and deletes their parked
/// envelopes. Epochs past `Scheduled` (opened or committed) are left to run
/// to completion or abort.
pub(crate) async fn invalidate(
    repo: &NodeRepo,
    market: Key,
    from_epoch: u64,
    current: Hash32,
) -> Result<Invalidated> {
    let mut epochs = Vec::new();
    let mut kept = Vec::new();
    for row in repo.non_terminal_epochs(market).await? {
        if row.epoch < from_epoch || row.phase != Phase::Scheduled {
            continue;
        }
        let Some(bytes) = repo.key_bundle(market, row.epoch).await? else {
            continue;
        };
        let bundle = EpochKeyBundle::decode_exact(&bytes)
            .with_context(|| format!("stored bundle of epoch {}", row.epoch))?;
        if bundle.announcement.committee_digest == current {
            kept.push(row.epoch);
        } else {
            epochs.push(row.epoch);
        }
    }
    if epochs.is_empty() {
        return Ok(Invalidated {
            epochs,
            parked_deleted: 0,
            kept,
        });
    }
    let parked_deleted = repo.invalidate_parked(market, epochs.clone()).await?;
    let dropped = epochs.clone();
    repo.store()
        .write(move |tx| {
            for e in dropped {
                let e = i64::try_from(e).map_err(|_| {
                    timescales_service::store::StoreError::Corrupt("epoch out of range")
                })?;
                tx.execute(
                    "DELETE FROM key_bundles WHERE market = ?1 AND epoch = ?2",
                    (market, e),
                )?;
                tx.execute(
                    "DELETE FROM epochs WHERE market = ?1 AND epoch = ?2 AND phase = ?3",
                    (market, e, 1i64),
                )?;
            }
            Ok(())
        })
        .await?;
    let event = json!({
        "kind": "parked.invalidated",
        "market": b58(&market),
        "epochs": epochs.iter().map(u64::to_string).collect::<Vec<_>>(),
    });
    repo.append_events(vec![(
        Some(market),
        format!("market:{}", b58(&market)),
        now_ms(),
        event.to_string(),
    )])
    .await?;
    Ok(Invalidated {
        epochs,
        parked_deleted,
        kept,
    })
}

pub(crate) fn open_repo(data_dir: &Path) -> Result<NodeRepo> {
    let path = data_dir.join(NODE_DB);
    if !path.exists() {
        bail!("no node database at {}", path.display());
    }
    let store = Store::open(&path, Schema::Node, StoreOptions::default())
        .map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;
    Ok(NodeRepo::new(store))
}

pub(crate) async fn run(
    data_dir: PathBuf,
    market: Key,
    from_epoch: u64,
    chain: &crate::rpc::ChainArgs,
) -> Result<Value> {
    let (m, _) = chain.connect()?.market(market).await?;
    if m.prev_committee_digest == Hash32::ZERO {
        bail!(
            "the market has never rotated its committee (prev_committee_digest is zero); \
             apply the SetCommitteeDigest change first"
        );
    }
    if from_epoch <= m.last_committed {
        bail!(
            "epoch {from_epoch} is already committed (last committed {}); committed epochs \
             run to completion or abort",
            m.last_committed
        );
    }
    let _lock = lock_node(&data_dir)?;
    let repo = open_repo(&data_dir)?;
    let r = invalidate(&repo, market, from_epoch, m.committee_digest).await?;
    Ok(json!({
        "market": b58(&market),
        "committee_digest": m.committee_digest.to_hex(),
        "previous_committee_digest": m.prev_committee_digest.to_hex(),
        "invalidated_epochs": r.epochs.iter().map(u64::to_string).collect::<Vec<_>>(),
        "parked_envelopes_deleted": r.parked_deleted,
        "kept_epochs": r.kept.iter().map(u64::to_string).collect::<Vec<_>>(),
        "next": "the dealer re-deals the invalidated epochs under the new committee; \
                 start the node again",
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use timescales_core::{Encode, EpochId};
    use timescales_service::wire::{EpochKeyAnnouncement, KeyScheme};

    use super::*;

    fn bundle(market: Key, epoch: u64, committee: Hash32) -> Vec<u8> {
        EpochKeyBundle {
            announcement: EpochKeyAnnouncement {
                version: EpochKeyAnnouncement::VERSION,
                market,
                epoch: EpochId(epoch),
                committee_digest: committee,
                scheme: KeyScheme::DevX25519,
                epoch_pk: [9; 32],
                commitments: vec![],
            },
            acks: vec![],
        }
        .to_bytes()
    }

    #[tokio::test]
    async fn drops_old_committee_bundles_and_their_parked_envelopes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(
            &dir.path().join(NODE_DB),
            Schema::Node,
            StoreOptions::default(),
        )
        .unwrap();
        let repo = NodeRepo::new(store);
        let market = [4u8; 32];
        let (old, new) = (Hash32([1; 32]), Hash32([2; 32]));
        for (e, c) in [(5, old), (6, old), (7, new), (8, old)] {
            repo.put_key_bundle(market, e, bundle(market, e, c), 1)
                .await
                .unwrap();
        }
        let r = invalidate(&repo, market, 6, new).await.unwrap();
        assert_eq!(r.epochs, vec![6, 8]);
        assert_eq!(r.kept, vec![7]);
        assert!(repo.key_bundle(market, 5).await.unwrap().is_some());
        assert!(repo.key_bundle(market, 6).await.unwrap().is_none());
        assert!(repo.key_bundle(market, 7).await.unwrap().is_some());
        assert!(repo.key_bundle(market, 8).await.unwrap().is_none());
        assert!(repo.epoch(market, 6).await.unwrap().is_none());
        // The dealer can now store the re-dealt bundle.
        repo.put_key_bundle(market, 6, bundle(market, 6, new), 2)
            .await
            .unwrap();
        let events = repo.events_since(0, vec![], 10).await.unwrap();
        assert_eq!(events.len(), 1);
        let v: Value = serde_json::from_str(&events[0].event).unwrap();
        assert_eq!(v["kind"], "parked.invalidated");
        assert_eq!(v["epochs"], json!(["6", "8"]));
        assert_eq!(events[0].topic, format!("market:{}", b58(&market)));
    }

    #[test]
    fn refuses_while_the_node_holds_its_lock() {
        let dir = tempfile::tempdir().unwrap();
        let held = lock_node(dir.path()).unwrap();
        let err = lock_node(dir.path()).unwrap_err();
        assert!(err.to_string().contains("stop it"), "{err}");
        drop(held);
        lock_node(dir.path()).unwrap();
    }
}
