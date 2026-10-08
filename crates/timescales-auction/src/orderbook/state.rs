//! Cross-epoch order state.
//!
//! Orders may live for several epochs (`valid_from..=expires_at`). The trader
//! submits one envelope per epoch they want the order considered in. All of
//! them carry the same commitment. What links the epochs is this table,
//! keyed by commitment:
//!
//! * `filled` - cumulative quantity executed so far. The next batch only
//!   sees `quantity - filled`.
//! * `cancelled` - set by a cancel that took effect. Later envelopes for the
//!   same commitment are rejected.
//!
//! Every field is derivable from public receipts, so the table can be
//! rebuilt and checked by anyone. Entries are pruned `max_order_lifetime`
//! epochs after creation. By then the order has expired anyway.

use std::collections::BTreeMap;

use timescales_core::merkle::MerkleTree;
use timescales_core::{
    Decode, DecodeError, Encode, EpochId, Hash32, Lots, OrderCommitment, Reader, encoding::put_bool,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateEntry {
    pub commitment: OrderCommitment,
    pub filled: Lots,
    pub cancelled: bool,
    pub created: EpochId,
}

impl Encode for StateEntry {
    fn encode(&self, out: &mut Vec<u8>) {
        self.commitment.encode(out);
        self.filled.encode(out);
        put_bool(out, self.cancelled);
        self.created.encode(out);
    }
}

impl Decode for StateEntry {
    const MIN_ENCODED_LEN: usize = 32 + 8 + 1 + 8;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(StateEntry {
            commitment: OrderCommitment::decode(r)?,
            filled: Lots::decode(r)?,
            cancelled: r.bool()?,
            created: EpochId::decode(r)?,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrderStateTable {
    entries: BTreeMap<OrderCommitment, StateEntry>,
}

impl OrderStateTable {
    pub fn get(&self, c: &OrderCommitment) -> Option<&StateEntry> {
        self.entries.get(c)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = &StateEntry> {
        self.entries.values()
    }

    pub fn root(&self) -> Hash32 {
        let leaves: Vec<Vec<u8>> = self.entries.values().map(Encode::to_bytes).collect();
        MerkleTree::from_data(&leaves).root()
    }

    /// Apply one batch's public effects and prune entries older than
    /// `lifetime` epochs. Returns the entries created or changed.
    pub fn apply(
        &mut self,
        epoch: EpochId,
        lifetime: u32,
        fills: impl IntoIterator<Item = (OrderCommitment, Lots)>,
        cancelled: impl IntoIterator<Item = OrderCommitment>,
    ) -> Vec<StateEntry> {
        let mut touched = BTreeMap::new();
        for (c, q) in fills {
            let e = self.entries.entry(c).or_insert(StateEntry {
                commitment: c,
                filled: Lots::ZERO,
                cancelled: false,
                created: epoch,
            });
            // Fills are bounded by order quantity, which fits in u64.
            e.filled = e.filled.checked_add(q).unwrap_or(Lots::MAX);
            touched.insert(c, *e);
        }
        for c in cancelled {
            let e = self.entries.entry(c).or_insert(StateEntry {
                commitment: c,
                filled: Lots::ZERO,
                cancelled: false,
                created: epoch,
            });
            e.cancelled = true;
            touched.insert(c, *e);
        }
        self.prune(epoch, lifetime);
        touched.into_values().collect()
    }

    /// Drop entries created more than `lifetime` epochs before `epoch`.
    pub fn prune(&mut self, epoch: EpochId, lifetime: u32) {
        self.entries
            .retain(|_, e| e.created.0.saturating_add(u64::from(lifetime)) >= epoch.0);
    }
}

impl Encode for OrderStateTable {
    fn encode(&self, out: &mut Vec<u8>) {
        let v: Vec<StateEntry> = self.entries.values().copied().collect();
        timescales_core::encoding::put_seq(out, &v);
    }
}

impl Decode for OrderStateTable {
    const MIN_ENCODED_LEN: usize = 4;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let v: Vec<StateEntry> = r.seq(1 << 24)?;
        if v.windows(2).any(|w| w[0].commitment >= w[1].commitment) {
            return Err(DecodeError::InvalidValue("OrderStateTable order"));
        }
        Ok(v.into_iter().collect())
    }
}

impl FromIterator<StateEntry> for OrderStateTable {
    fn from_iter<T: IntoIterator<Item = StateEntry>>(iter: T) -> Self {
        Self {
            entries: iter.into_iter().map(|e| (e.commitment, e)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_and_prunes() {
        let mut t = OrderStateTable::default();
        let c = OrderCommitment([1; 32]);
        t.apply(EpochId(10), 2, [(c, Lots(3))], []);
        t.apply(EpochId(11), 2, [(c, Lots(4))], []);
        assert_eq!(t.get(&c).map(|e| e.filled), Some(Lots(7)));
        let r = t.root();
        t.apply(EpochId(12), 2, [], []);
        assert_eq!(t.root(), r);
        t.apply(EpochId(13), 2, [], []);
        assert!(t.get(&c).is_none());
    }

    #[test]
    fn minimum_encoded_lengths() {
        let e = StateEntry {
            commitment: OrderCommitment([1; 32]),
            filled: Lots(2),
            cancelled: true,
            created: EpochId(3),
        };
        assert_eq!(e.to_bytes().len(), StateEntry::MIN_ENCODED_LEN);
        let empty = OrderStateTable::default();
        assert_eq!(empty.to_bytes().len(), OrderStateTable::MIN_ENCODED_LEN);
        let one: OrderStateTable = [e].into_iter().collect();
        assert_eq!(OrderStateTable::decode_exact(&one.to_bytes()), Ok(one));
    }
}
