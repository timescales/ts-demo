//! [`TxLog`]: the enclave's transaction journal, in memory.
//!
//! The enclave persists nothing in TDX mode, so its journal does not
//! survive a restart. That is safe because every `MarketChain` operation
//! observes chain state before it acts: after a restart the enclave
//! re-reads the batch instead of resolving its own pending transactions.
//! While it runs, the log tells the publish path which signature carried a
//! post or a co-signature.

use std::collections::VecDeque;

use parking_lot::Mutex;
use timescales_chain::{Address, BoxFuture, JournalError, TxJournal, TxOp, TxOutcome, TxRecord};

/// Records kept at most. The oldest resolved ones go first.
const CAPACITY: usize = 4096;

#[derive(Debug, Default)]
struct Entries {
    next_id: i64,
    rows: VecDeque<(TxRecord, Option<TxOutcome>)>,
}

/// An in-memory [`TxJournal`].
#[derive(Debug, Default)]
pub struct TxLog {
    entries: Mutex<Entries>,
}

impl TxLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Signatures and slots of the transactions of `op` for (`market`,
    /// `epoch`) that landed, oldest first.
    pub fn landed(&self, market: &Address, epoch: u64, op: TxOp) -> Vec<([u8; 64], u64)> {
        self.entries
            .lock()
            .rows
            .iter()
            .filter(|(r, _)| r.market == *market && r.epoch == Some(epoch) && r.op == op)
            .filter_map(|(r, o)| match o {
                Some(TxOutcome::Landed { slot }) => Some((r.signature, *slot)),
                _ => None,
            })
            .collect()
    }
}

impl TxJournal for TxLog {
    fn before_send(&self, rec: TxRecord) -> BoxFuture<'_, Result<i64, JournalError>> {
        Box::pin(async move {
            let mut e = self.entries.lock();
            if e.rows.len() >= CAPACITY {
                // Unresolved rows stay: the sender resolves them.
                match e.rows.iter().position(|(_, o)| o.is_some()) {
                    Some(i) => {
                        e.rows.remove(i);
                    }
                    None => return Err(JournalError("transaction log full".to_owned())),
                }
            }
            e.next_id += 1;
            let id = e.next_id;
            e.rows.push_back((
                TxRecord {
                    id: Some(id),
                    ..rec
                },
                None,
            ));
            Ok(id)
        })
    }

    fn resolved(&self, id: i64, outcome: TxOutcome) -> BoxFuture<'_, Result<(), JournalError>> {
        Box::pin(async move {
            let mut e = self.entries.lock();
            if let Some(row) = e.rows.iter_mut().find(|(r, _)| r.id == Some(id)) {
                row.1 = Some(outcome);
            }
            Ok(())
        })
    }

    fn pending(&self) -> BoxFuture<'_, Result<Vec<TxRecord>, JournalError>> {
        Box::pin(async move {
            Ok(self
                .entries
                .lock()
                .rows
                .iter()
                .filter(|(_, o)| o.is_none())
                .map(|(r, _)| r.clone())
                .collect())
        })
    }

    fn last_landed_slot(&self) -> BoxFuture<'_, Result<u64, JournalError>> {
        Box::pin(async move {
            Ok(self
                .entries
                .lock()
                .rows
                .iter()
                .filter_map(|(_, o)| match o {
                    Some(TxOutcome::Landed { slot } | TxOutcome::Failed { slot, .. }) => {
                        Some(*slot)
                    }
                    _ => None,
                })
                .max()
                .unwrap_or(0))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(epoch: u64, op: TxOp, sig: u8) -> TxRecord {
        TxRecord {
            id: None,
            market: [1; 32],
            epoch: Some(epoch),
            op,
            signature: [sig; 64],
            last_valid_block_height: 10,
            sent_at_ms: 0,
        }
    }

    #[tokio::test]
    async fn landed_transactions_are_found_by_market_epoch_and_op() {
        let log = TxLog::new();
        let a = log.before_send(record(3, TxOp::Post, 1)).await.unwrap();
        let b = log.before_send(record(3, TxOp::Cosign, 2)).await.unwrap();
        let c = log.before_send(record(3, TxOp::Post, 3)).await.unwrap();
        log.resolved(a, TxOutcome::Expired).await.unwrap();
        log.resolved(b, TxOutcome::Landed { slot: 7 })
            .await
            .unwrap();
        log.resolved(c, TxOutcome::Landed { slot: 9 })
            .await
            .unwrap();
        assert_eq!(log.landed(&[1; 32], 3, TxOp::Post), vec![([3; 64], 9)]);
        assert_eq!(log.landed(&[1; 32], 3, TxOp::Cosign), vec![([2; 64], 7)]);
        assert!(log.landed(&[1; 32], 4, TxOp::Post).is_empty());
        assert_eq!(log.last_landed_slot().await.unwrap(), 9);
        assert!(log.pending().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_log_is_bounded_and_keeps_unresolved_rows() {
        let log = TxLog::new();
        for i in 0..CAPACITY {
            let id = log.before_send(record(1, TxOp::Reveal, 0)).await.unwrap();
            if i > 0 {
                log.resolved(id, TxOutcome::Expired).await.unwrap();
            }
        }
        log.before_send(record(2, TxOp::Reveal, 0)).await.unwrap();
        assert_eq!(log.entries.lock().rows.len(), CAPACITY);
        assert_eq!(log.pending().await.unwrap().len(), 2);
    }
}
