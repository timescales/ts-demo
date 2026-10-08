//! The balance-sheet check: the node's sheet against the
//! enclave's own read of every Trader account, before any key is
//! requested.
//!
//! Available balance never decreases between the commit and the apply,
//! so for every trader `t`, per side:
//!
//! * `sheet[t] <= available_now(t, e)`: an inflated entry would force a
//!   public outcome and then an `Insolvent` abort.
//! * `sheet[t] == available_now(t, e)` when the account has not changed
//!   since the commit (`last_change_slot < commit_slot`): a deflated entry
//!   would make a chosen wallet's orders fail for collateral.
//! * `sheet[t] >= floor(t)` when the account's floor is for this epoch.
//!
//! A trader missing from the sheet counts as 0, and so does a sheet entry
//! without an account.

use std::collections::BTreeMap;

use timescales_auction::collateral::{Balance, BalanceSheet};
use timescales_chain::{TraderEntry, TraderSnapshot};
use timescales_core::TraderId;

/// `(base, quote)` of a balance.
fn pair(b: Balance) -> (u64, u64) {
    (b.base.0, b.quote.0)
}

fn le(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 <= b.0 && a.1 <= b.1
}

/// The number of traders whose sheet entry fails a rule. Zero when the
/// sheet is consistent with `snapshot` for batch `epoch` committed at
/// `commit_slot`.
pub(crate) fn mismatches(
    sheet: &BalanceSheet,
    snapshot: &TraderSnapshot,
    epoch: u64,
    commit_slot: u64,
) -> u32 {
    // Available balances capped as the node's sheet caps them.
    let available = snapshot.balance_sheet(epoch);
    let accounts: BTreeMap<TraderId, &TraderEntry> = snapshot
        .traders
        .iter()
        .map(|t| (TraderId(t.owner), t))
        .collect();
    let mut traders: Vec<TraderId> = accounts.keys().copied().collect();
    traders.extend(sheet.iter().map(|(t, _)| *t));
    traders.sort_unstable();
    traders.dedup();
    let failing = traders.iter().filter(|t| {
        let claimed = pair(sheet.get(t));
        let now = pair(available.get(t));
        let Some(account) = accounts.get(t) else {
            return claimed != (0, 0);
        };
        let unchanged = account.last_change_slot < commit_slot;
        let floor =
            (account.floor_epoch == epoch).then_some((account.floor_base, account.floor_quote));
        !le(claimed, now) || (unchanged && claimed != now) || floor.is_some_and(|f| !le(f, claimed))
    });
    u32::try_from(failing.count()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use timescales_core::{BaseAtoms, QuoteAtoms};

    use super::*;

    fn entry(owner: u8, base: u64, quote: u64, last_change_slot: u64) -> TraderEntry {
        TraderEntry {
            owner: [owner; 32],
            base,
            quote,
            requested_base: 0,
            requested_quote: 0,
            request_epoch: 0,
            last_leaf_epoch: 0,
            last_change_slot,
            floor_epoch: 0,
            floor_base: 0,
            floor_quote: 0,
        }
    }

    fn sheet(entries: &[(u8, u64, u64)]) -> BalanceSheet {
        entries
            .iter()
            .map(|(t, b, q)| {
                (
                    TraderId([*t; 32]),
                    Balance {
                        base: BaseAtoms(*b),
                        quote: QuoteAtoms(*q),
                    },
                )
            })
            .collect()
    }

    const COMMIT: u64 = 100;

    #[test]
    fn an_honest_sheet_passes() {
        let snap = TraderSnapshot {
            slot: 120,
            traders: vec![entry(1, 10, 20, 50), entry(2, 5, 0, 60)],
        };
        assert_eq!(
            mismatches(&sheet(&[(1, 10, 20), (2, 5, 0)]), &snap, 7, COMMIT),
            0
        );
    }

    #[test]
    fn deflated_and_inflated_entries_fail() {
        let snap = TraderSnapshot {
            slot: 120,
            traders: vec![entry(1, 10, 20, 50), entry(2, 5, 0, 60)],
        };
        // Deflated, unchanged since the commit.
        assert_eq!(
            mismatches(&sheet(&[(1, 9, 20), (2, 5, 0)]), &snap, 7, COMMIT),
            1
        );
        // Inflated.
        assert_eq!(
            mismatches(&sheet(&[(1, 10, 21), (2, 6, 0)]), &snap, 7, COMMIT),
            2
        );
        // A trader left out of the sheet.
        assert_eq!(mismatches(&sheet(&[(1, 10, 20)]), &snap, 7, COMMIT), 1);
        // An entry without an account.
        assert_eq!(
            mismatches(
                &sheet(&[(1, 10, 20), (2, 5, 0), (3, 1, 0)]),
                &snap,
                7,
                COMMIT
            ),
            1
        );
    }

    #[test]
    fn a_deposit_after_the_commit_may_show_the_older_balance() {
        // Changed at slot 110 > commit 100: anything up to the current
        // available balance passes.
        let snap = TraderSnapshot {
            slot: 120,
            traders: vec![entry(1, 15, 20, 110)],
        };
        assert_eq!(mismatches(&sheet(&[(1, 10, 20)]), &snap, 7, COMMIT), 0);
        assert_eq!(mismatches(&sheet(&[(1, 16, 20)]), &snap, 7, COMMIT), 1);
    }

    #[test]
    fn the_floor_of_this_epoch_holds() {
        let mut t = entry(1, 15, 20, 110);
        t.floor_epoch = 7;
        t.floor_base = 12;
        t.floor_quote = 20;
        let snap = TraderSnapshot {
            slot: 120,
            traders: vec![t],
        };
        assert_eq!(mismatches(&sheet(&[(1, 11, 20)]), &snap, 7, COMMIT), 1);
        assert_eq!(mismatches(&sheet(&[(1, 12, 20)]), &snap, 7, COMMIT), 0);
        // Another epoch's floor does not apply.
        assert_eq!(mismatches(&sheet(&[(1, 11, 20)]), &snap, 8, COMMIT), 0);
    }
}
