//! `governance...` (tags 15-21): every timelocked change kind and
//! the immediate admin actions. Each command either signs with `--signer`
//! and sends, or with `--unsigned` prints the transaction for the admin
//! multisig.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use timescales_chain::program::{GovernanceChange, Ix, MarketAccount};
use timescales_chain::{ChangeOutcome, MarketChain, TxOp, TxSigner};
use timescales_core::Hash32;

use crate::market::{Timings, check_executors};
use crate::rpc::{ChainArgs, blockhash_for};
use crate::tx::unsigned_json;
use crate::util::{Key, b58, b58_sig, nonzero, parse_hash, parse_key, print_json};

#[derive(Clone, Debug, Args)]
pub(crate) struct Authority {
    /// Keypair file of the signing authority (admin, pending admin, or any
    /// payer for `apply`).
    #[arg(long, conflicts_with = "unsigned", global = true)]
    pub(crate) signer: Option<PathBuf>,
    /// Print an unsigned transaction for a multisig instead of sending.
    #[arg(long, global = true)]
    pub(crate) unsigned: bool,
    /// With `--unsigned`: the authority's address [default: read from the
    /// market].
    #[arg(long, requires = "unsigned", global = true)]
    pub(crate) authority: Option<String>,
    /// With `--unsigned`: the recent blockhash to build with (offline
    /// signing) [default: the cluster's latest finalized blockhash].
    #[arg(long, requires = "unsigned", global = true)]
    pub(crate) blockhash: Option<String>,
}

// The variants are the CLI's subcommand names (`set-relay`,...), which
// follow the program's change kinds.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Debug, Subcommand)]
pub(crate) enum Change {
    /// SetRelay (kind 1, between batches).
    SetRelay {
        #[arg(long)]
        relay: String,
    },
    /// SetExecutors (kind 2, between batches): the whole executor set.
    SetExecutors {
        /// Executor key (repeat for each, 1 to 8).
        #[arg(long = "executor", required = true)]
        executors: Vec<String>,
        #[arg(long)]
        quorum: u8,
    },
    /// SetCommitteeDigest (kind 3, between batches).
    SetCommitteeDigest {
        /// The digest (hex)...
        #[arg(
            long,
            conflicts_with = "committee",
            required_unless_present = "committee"
        )]
        digest: Option<String>,
        ///... or the committee description file to take it from.
        #[arg(long)]
        committee: Option<PathBuf>,
    },
    /// SetAdmin (kind 4, any time): the new admin must then `accept`.
    SetAdmin {
        #[arg(long)]
        admin: String,
    },
    /// SetTimings (kind 5, between batches).
    SetTimings {
        #[arg(long)]
        beacon_delay: u16,
        #[arg(long)]
        exec_timeout: u64,
        #[arg(long)]
        settle_timeout: u64,
    },
    /// SetTimelock (kind 6, any time, a decrease waits for the old timelock).
    SetTimelock {
        #[arg(long)]
        slots: u64,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum GovernanceCmd {
    /// ProposeChange: schedule a change at `slot + timelock_slots`.
    Propose {
        #[arg(long)]
        market: String,
        #[command(subcommand)]
        change: Change,
        #[command(flatten)]
        auth: Authority,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// ApplyChange: permissionless once the timelock has passed.
    Apply {
        #[arg(long)]
        market: String,
        #[command(flatten)]
        auth: Authority,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// CancelChange.
    Cancel {
        #[arg(long)]
        market: String,
        #[command(flatten)]
        auth: Authority,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// AcceptAdmin, signed by the pending admin.
    Accept {
        #[arg(long)]
        market: String,
        #[command(flatten)]
        auth: Authority,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// SetHalted (immediate): halt the batch path. Exits stay open.
    Halt {
        #[arg(long)]
        market: String,
        /// Lift the halt instead.
        #[arg(long)]
        off: bool,
        #[command(flatten)]
        auth: Authority,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// RemoveExecutor (immediate).
    RemoveExecutor {
        #[arg(long)]
        market: String,
        #[arg(long)]
        executor: String,
        #[command(flatten)]
        auth: Authority,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// ClaimFees from the quote vault.
    ClaimFees {
        #[arg(long)]
        market: String,
        /// Quote atoms, or `all` for everything claimable.
        #[arg(long)]
        amount: String,
        /// Destination token account (quote mint).
        #[arg(long)]
        dest: String,
        #[command(flatten)]
        auth: Authority,
        #[command(flatten)]
        chain: ChainArgs,
    },
}

impl Change {
    pub(crate) fn to_change(&self) -> Result<GovernanceChange> {
        Ok(match self {
            Change::SetRelay { relay } => {
                let k = parse_key(relay)?;
                nonzero(&k, "relay")?;
                GovernanceChange::SetRelay(k)
            }
            Change::SetExecutors { executors, quorum } => {
                let keys = executors
                    .iter()
                    .map(|s| parse_key(s))
                    .collect::<Result<Vec<_>>>()?;
                check_executors(&keys, *quorum)?;
                GovernanceChange::SetExecutors {
                    keys,
                    quorum: *quorum,
                }
            }
            Change::SetCommitteeDigest { digest, committee } => {
                let d = match (digest, committee) {
                    (Some(d), _) => parse_hash(d)?,
                    (None, Some(path)) => crate::committee::read(path)?.digest(),
                    (None, None) => bail!("give --digest or --committee"),
                };
                if d == Hash32::ZERO {
                    bail!("committee digest must not be zero");
                }
                GovernanceChange::SetCommitteeDigest(d)
            }
            Change::SetAdmin { admin } => {
                let k = parse_key(admin)?;
                nonzero(&k, "admin")?;
                GovernanceChange::SetAdmin(k)
            }
            Change::SetTimings {
                beacon_delay,
                exec_timeout,
                settle_timeout,
            } => {
                Timings {
                    beacon_delay_slots: *beacon_delay,
                    timelock_slots: 0,
                    exec_timeout_slots: *exec_timeout,
                    settle_timeout_slots: *settle_timeout,
                }
                .check()?;
                GovernanceChange::SetTimings {
                    beacon_delay_slots: *beacon_delay,
                    exec_timeout_slots: *exec_timeout,
                    settle_timeout_slots: *settle_timeout,
                }
            }
            Change::SetTimelock { slots } => {
                if *slots > 2_592_000 {
                    bail!("timelock must be at most 2592000 slots");
                }
                GovernanceChange::SetTimelock(*slots)
            }
        })
    }
}

/// The readable form of a change, as the API names its kind.
pub(crate) fn describe_change(c: &GovernanceChange) -> Value {
    match c {
        GovernanceChange::SetRelay(k) => json!({"kind": "set_relay", "relay": b58(k)}),
        GovernanceChange::SetExecutors { keys, quorum } => json!({
            "kind": "set_executors",
            "executors": keys.iter().map(b58).collect::<Vec<_>>(),
            "quorum": quorum,
        }),
        GovernanceChange::SetCommitteeDigest(d) => {
            json!({"kind": "set_committee_digest", "digest": d.to_hex()})
        }
        GovernanceChange::SetAdmin(k) => json!({"kind": "set_admin", "admin": b58(k)}),
        GovernanceChange::SetTimings {
            beacon_delay_slots,
            exec_timeout_slots,
            settle_timeout_slots,
        } => json!({
            "kind": "set_timings",
            "beacon_delay_slots": beacon_delay_slots,
            "exec_timeout_slots": exec_timeout_slots,
            "settle_timeout_slots": settle_timeout_slots,
        }),
        GovernanceChange::SetTimelock(s) => json!({"kind": "set_timelock", "slots": s}),
    }
}

/// Signs and sends `ixs`, or prints them unsigned for `authority`.
async fn submit(
    what: &str,
    op: TxOp,
    chain: &ChainArgs,
    auth: &Authority,
    default_authority: impl FnOnce(&MarketAccount) -> Result<Key>,
    market: &MarketAccount,
    build: impl FnOnce(&Key) -> Result<Vec<Ix>>,
) -> Result<Value> {
    if auth.unsigned {
        let authority = match &auth.authority {
            Some(a) => parse_key(a)?,
            None => default_authority(market)?,
        };
        let ixs = build(&authority)?;
        let blockhash = blockhash_for(chain, auth.blockhash.as_deref()).await?;
        return unsigned_json(what, &ixs, &authority, &blockhash);
    }
    let path = auth
        .signer
        .as_ref()
        .context("give --signer <keypair> or --unsigned")?;
    let signer = crate::keys::load_signer(path)?;
    let ixs = build(&signer.address())?;
    let landed = chain.connect()?.send(op, ixs, signer, vec![]).await?;
    Ok(json!({
        "action": what,
        "signature": b58_sig(&landed.signature),
        "slot": landed.slot,
    }))
}

fn admin_of(m: &MarketAccount) -> Result<Key> {
    Ok(m.admin)
}

pub(crate) async fn run(cmd: GovernanceCmd) -> Result<()> {
    let out = match cmd {
        GovernanceCmd::Propose {
            market,
            change,
            auth,
            chain,
        } => {
            let address = parse_key(&market)?;
            let change = change.to_change()?;
            let c = chain.connect()?;
            let (m, _) = c.market(address).await?;
            if let Some(p) = &m.pending {
                bail!(
                    "a change is already pending ({}, eta slot {}); cancel or apply it first",
                    describe_change(&p.change)["kind"],
                    p.eta_slot
                );
            }
            let mut out = submit(
                "propose_change",
                TxOp::Admin,
                &chain,
                &auth,
                admin_of,
                &m,
                |admin| {
                    Ok(vec![timescales_chain::program::propose_change(
                        &c.program, admin, &address, &change,
                    )?])
                },
            )
            .await?;
            out["change"] = describe_change(&change);
            out["timelock_slots"] = json!(m.timelock_slots);
            out
        }
        GovernanceCmd::Apply {
            market,
            auth,
            chain,
        } => {
            let address = parse_key(&market)?;
            let c = chain.connect()?;
            let (m, slot) = c.market(address).await?;
            let Some(pending) = &m.pending else {
                bail!("no change is pending");
            };
            if auth.unsigned {
                submit(
                    "apply_change",
                    TxOp::ApplyChange,
                    &chain,
                    &auth,
                    admin_of,
                    &m,
                    |payer| {
                        Ok(vec![timescales_chain::program::apply_change(
                            &c.program, payer, &address,
                        )])
                    },
                )
                .await?
            } else {
                let signer = load(&auth)?;
                let outcome = c
                    .market_chain(address)
                    .ensure_change_applied(signer)
                    .await?;
                json!({
                    "action": "apply_change",
                    "change": describe_change(&pending.change),
                    "eta_slot": pending.eta_slot,
                    "observed_slot": slot,
                    "outcome": change_outcome(&outcome),
                })
            }
        }
        GovernanceCmd::Cancel {
            market,
            auth,
            chain,
        } => {
            let address = parse_key(&market)?;
            let c = chain.connect()?;
            let (m, _) = c.market(address).await?;
            if m.pending.is_none() {
                bail!("no change is pending");
            }
            submit(
                "cancel_change",
                TxOp::Admin,
                &chain,
                &auth,
                admin_of,
                &m,
                |admin| {
                    Ok(vec![timescales_chain::program::cancel_change(
                        &c.program, admin, &address,
                    )])
                },
            )
            .await?
        }
        GovernanceCmd::Accept {
            market,
            auth,
            chain,
        } => {
            let address = parse_key(&market)?;
            let c = chain.connect()?;
            let (m, _) = c.market(address).await?;
            submit(
                "accept_admin",
                TxOp::Admin,
                &chain,
                &auth,
                |m| m.pending_admin.context("the market has no pending admin"),
                &m,
                |pending| {
                    if m.pending_admin != Some(*pending) {
                        bail!("{} is not the market's pending admin", b58(pending));
                    }
                    Ok(vec![timescales_chain::program::accept_admin(
                        &c.program, pending, &address,
                    )])
                },
            )
            .await?
        }
        GovernanceCmd::Halt {
            market,
            off,
            auth,
            chain,
        } => {
            let address = parse_key(&market)?;
            let c = chain.connect()?;
            let (m, _) = c.market(address).await?;
            let mut out = submit(
                if off { "resume" } else { "halt" },
                TxOp::Admin,
                &chain,
                &auth,
                admin_of,
                &m,
                |admin| {
                    Ok(vec![timescales_chain::program::set_halted(
                        &c.program, admin, &address, !off,
                    )])
                },
            )
            .await?;
            out["halted_before"] = json!(m.halted);
            out
        }
        GovernanceCmd::RemoveExecutor {
            market,
            executor,
            auth,
            chain,
        } => {
            let address = parse_key(&market)?;
            let key = parse_key(&executor)?;
            let c = chain.connect()?;
            let (m, _) = c.market(address).await?;
            if m.executor_slot(&key).is_none() {
                bail!("{} is not an executor of this market", b58(&key));
            }
            let mut out = submit(
                "remove_executor",
                TxOp::Admin,
                &chain,
                &auth,
                admin_of,
                &m,
                |admin| {
                    Ok(vec![timescales_chain::program::remove_executor(
                        &c.program, admin, &address, &key,
                    )])
                },
            )
            .await?;
            let live = m.executors.iter().filter(|k| **k != [0; 32]).count() - 1;
            if usize::from(m.receipt_quorum) > live {
                out["warning"] = json!(format!(
                    "receipt quorum {} now exceeds the {live} live executors: no receipt can \
                     finalize until a SetExecutors change applies",
                    m.receipt_quorum
                ));
            }
            out
        }
        GovernanceCmd::ClaimFees {
            market,
            amount,
            dest,
            auth,
            chain,
        } => {
            let address = parse_key(&market)?;
            let dest = parse_key(&dest)?;
            let c = chain.connect()?;
            let (m, _) = c.market(address).await?;
            let claimable = m.fees_accrued.saturating_sub(m.fees_claimed);
            let amount = if amount == "all" {
                claimable
            } else {
                amount.parse::<u64>().context("--amount")?
            };
            if amount == 0 || amount > claimable {
                bail!("{amount} is not claimable ({claimable} quote atoms are)");
            }
            let mut out = submit(
                "claim_fees",
                TxOp::Admin,
                &chain,
                &auth,
                admin_of,
                &m,
                |admin| {
                    Ok(vec![timescales_chain::program::claim_fees(
                        &c.program,
                        admin,
                        &address,
                        &m.quote_vault,
                        &dest,
                        amount,
                    )])
                },
            )
            .await?;
            out["amount"] = json!(amount.to_string());
            out
        }
    };
    print_json(&out)
}

fn load(auth: &Authority) -> Result<Arc<dyn TxSigner>> {
    let path = auth
        .signer
        .as_ref()
        .context("give --signer <keypair> or --unsigned")?;
    crate::keys::load_signer(path)
}

pub(crate) fn change_outcome(o: &ChangeOutcome) -> Value {
    match o {
        ChangeOutcome::Applied { kind } => json!({"applied": kind}),
        ChangeOutcome::NothingDue => json!("nothing_due"),
        ChangeOutcome::NotYet { slots_left } => json!({"not_yet": {"slots_left": slots_left}}),
        ChangeOutcome::InFlight => json!("in_flight"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn every_change_kind_parses_and_round_trips_its_payload() {
        let k = |b: u8| b58(&[b; 32]);
        let changes = [
            Change::SetRelay { relay: k(1) },
            Change::SetExecutors {
                executors: vec![k(2), k(3)],
                quorum: 2,
            },
            Change::SetCommitteeDigest {
                digest: Some(hex::encode([4u8; 32])),
                committee: None,
            },
            Change::SetAdmin { admin: k(5) },
            Change::SetTimings {
                beacon_delay: 8,
                exec_timeout: 750,
                settle_timeout: 9_000,
            },
            Change::SetTimelock { slots: 216_000 },
        ];
        for (i, c) in changes.iter().enumerate() {
            let g = c.to_change().unwrap();
            assert_eq!(usize::from(g.kind()), i + 1);
            let back = GovernanceChange::decode(g.kind(), &g.payload().unwrap()).unwrap();
            assert_eq!(back, g);
            assert!(describe_change(&g)["kind"].is_string());
        }
    }

    #[test]
    fn refuses_changes_the_program_refuses() {
        assert!(
            Change::SetRelay {
                relay: b58(&[0; 32])
            }
            .to_change()
            .is_err()
        );
        assert!(
            Change::SetExecutors {
                executors: vec![b58(&[1; 32])],
                quorum: 2
            }
            .to_change()
            .is_err()
        );
        assert!(
            Change::SetTimings {
                beacon_delay: 3,
                exec_timeout: 150,
                settle_timeout: 300
            }
            .to_change()
            .is_err()
        );
        assert!(
            Change::SetTimelock { slots: 2_592_001 }
                .to_change()
                .is_err()
        );
        assert!(
            Change::SetCommitteeDigest {
                digest: Some(hex::encode([0u8; 32])),
                committee: None
            }
            .to_change()
            .is_err()
        );
    }
}
