//! `inspect market|epoch|traders|program`: chain state as JSON.

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde_json::{Value, json};
use timescales_chain::program::{BatchAccount, MarketAccount, PendingChange, spl};
use timescales_chain::{Level, MarketChain, TraderEntry};

use crate::governance::describe_change;
use crate::rpc::{Chain, ChainArgs};
use crate::util::{Key, b58, parse_key, print_json};

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum InspectCmd {
    /// The Market account, its mints and vault balances.
    Market {
        #[arg(long)]
        market: String,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// One epoch's Batch account.
    Epoch {
        #[arg(long)]
        market: String,
        #[arg(long)]
        epoch: u64,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Every Trader account of the market (the snapshot read).
    Traders {
        #[arg(long)]
        market: String,
        /// Read at or after this slot (`minContextSlot`).
        #[arg(long)]
        at: Option<u64>,
        /// Batch the available balances are computed for [default: the next
        /// epoch to commit].
        #[arg(long)]
        epoch: Option<u64>,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// The settlement program: loader, upgrade authority, last deployment.
    Program {
        #[command(flatten)]
        chain: ChainArgs,
    },
}

pub(crate) fn market_json(address: &Key, m: &MarketAccount) -> Value {
    json!({
        "address": b58(address),
        "market_id": m.market_id.to_string(),
        "layout_version": m.layout_version,
        "halted": m.halted,
        "creator": b58(&m.creator),
        "salt": hex::encode(m.salt),
        "admin": b58(&m.admin),
        "pending_admin": m.pending_admin.as_ref().map(b58),
        "relay": b58(&m.relay),
        "base_mint": b58(&m.base_mint),
        "quote_mint": b58(&m.quote_mint),
        "base_vault": b58(&m.base_vault),
        "quote_vault": b58(&m.quote_vault),
        "params": crate::params::to_json(&m.params),
        "params_digest": m.params_digest.to_hex(),
        "committee_digest": m.committee_digest.to_hex(),
        "prev_committee_digest": m.prev_committee_digest.to_hex(),
        "executors": m.executors.iter().enumerate()
            .filter(|(_, k)| **k != [0; 32])
            .map(|(slot, k)| json!({"slot": slot, "key": b58(k)}))
            .collect::<Vec<_>>(),
        "receipt_quorum": m.receipt_quorum,
        "beacon_delay_slots": m.beacon_delay_slots,
        "timelock_slots": m.timelock_slots.to_string(),
        "exec_timeout_slots": m.exec_timeout_slots.to_string(),
        "settle_timeout_slots": m.settle_timeout_slots.to_string(),
        "last_committed": m.last_committed.to_string(),
        "last_settled": m.last_settled.to_string(),
        "in_flight": m.in_flight(),
        "last_progress_slot": m.last_progress_slot.to_string(),
        "fees_accrued": m.fees_accrued.to_string(),
        "fees_claimed": m.fees_claimed.to_string(),
        "prev_receipt": m.prev_receipt.to_hex(),
        "state_root": m.state_root.to_hex(),
        "pending": m.pending.as_ref().map(pending_json),
    })
}

fn pending_json(p: &PendingChange) -> Value {
    json!({"eta_slot": p.eta_slot.to_string(), "change": describe_change(&p.change)})
}

pub(crate) fn batch_json(address: &Key, b: &BatchAccount) -> Value {
    json!({
        "address": b58(address),
        "epoch": b.epoch.to_string(),
        "status": format!("{:?}", b.status),
        "abort_reason": b.abort_reason.map(|r| format!("{r:?}")),
        "root": b.root.to_hex(),
        "count": b.count,
        "terms_digest": b.terms_digest.to_hex(),
        "commit_slot": b.commit_slot.to_string(),
        "beacon_slots": [b.beacon_slot_a.to_string(), b.beacon_slot_b.to_string()],
        "beacon": b.beacon.to_hex(),
        "reveal_slot": b.reveal_slot.to_string(),
        "receipt_slot": b.receipt_slot.to_string(),
        "header_digest": b.header_digest.to_hex(),
        "receipt": b.receipt.to_hex(),
        "outcome_digest": b.outcome_digest.to_hex(),
        "next_state_root": b.next_state_root.to_hex(),
        "settlement_root": b.settlement_root.to_hex(),
        "settlement_count": b.settlement_count,
        "verified_count": b.verified_count,
        "applied_count": b.applied_count,
        "fees": b.fees.to_string(),
        "cosign_count": b.cosign_count,
        "cosign_bitmap": format!("{:08b}", b.cosign_bitmap),
        "sum_base": b.sum_base.to_string(),
        "sum_quote": b.sum_quote.to_string(),
    })
}

fn trader_json(t: &TraderEntry, epoch: u64) -> Value {
    let (base, quote) = t.available(epoch);
    json!({
        "owner": b58(&t.owner),
        "base": t.base.to_string(),
        "quote": t.quote.to_string(),
        "requested_base": t.requested_base.to_string(),
        "requested_quote": t.requested_quote.to_string(),
        "request_epoch": t.request_epoch.to_string(),
        "last_leaf_epoch": t.last_leaf_epoch.to_string(),
        "last_change_slot": t.last_change_slot.to_string(),
        "floor": {
            "epoch": t.floor_epoch.to_string(),
            "base": t.floor_base.to_string(),
            "quote": t.floor_quote.to_string(),
        },
        "available": {"base": base.to_string(), "quote": quote.to_string()},
    })
}

/// A mint's decimals and authorities, and how much of it a token account
/// holds (bytes 64..72 of a classic token account).
async fn token_view(c: &Chain, mint: &Key, account: &Key) -> Result<Value> {
    let mint_acc = c
        .account(*mint, Level::Confirmed)
        .await?
        .with_context(|| format!("no mint at {}", b58(mint)))?;
    let m =
        spl::decode_mint(&mint_acc.data).map_err(|e| anyhow::anyhow!("mint {}: {e}", b58(mint)))?;
    let amount = match c.account(*account, Level::Confirmed).await? {
        Some(a) if a.data.len() == spl::TOKEN_ACCOUNT_LEN => {
            let bytes: [u8; 8] = a.data[64..72].try_into()?;
            Some(u64::from_le_bytes(bytes).to_string())
        }
        _ => None,
    };
    Ok(json!({
        "mint": b58(mint),
        "decimals": m.decimals,
        "supply": m.supply.to_string(),
        "mint_authority": m.mint_authority.as_ref().map(b58),
        "freeze_authority": m.freeze_authority.as_ref().map(b58),
        "vault": b58(account),
        "vault_amount": amount,
    }))
}

pub(crate) async fn run(cmd: InspectCmd) -> Result<()> {
    let out = match cmd {
        InspectCmd::Market { market, chain } => {
            let address = parse_key(&market)?;
            let c = chain.connect()?;
            let (m, slot) = c.market(address).await?;
            let mut v = market_json(&address, &m);
            v["context_slot"] = json!(slot.to_string());
            v["base"] = token_view(&c, &m.base_mint, &m.base_vault).await?;
            v["quote"] = token_view(&c, &m.quote_mint, &m.quote_vault).await?;
            v
        }
        InspectCmd::Epoch {
            market,
            epoch,
            chain,
        } => {
            let address = parse_key(&market)?;
            let c = chain.connect()?;
            match c.batch(address, epoch).await? {
                Some((at, b)) => batch_json(&at, &b),
                None => bail!("no Batch account for epoch {epoch} (never committed, or reclaimed)"),
            }
        }
        InspectCmd::Traders {
            market,
            at,
            epoch,
            chain,
        } => {
            let address = parse_key(&market)?;
            let c = chain.connect()?;
            let (m, _) = c.market(address).await?;
            let epoch = epoch.unwrap_or(m.last_committed + 1);
            let snapshot = c
                .market_chain(address)
                .trader_snapshot(at.unwrap_or(0))
                .await?;
            json!({
                "market": b58(&address),
                "context_slot": snapshot.slot.to_string(),
                "available_for_epoch": epoch.to_string(),
                "traders": snapshot.traders.iter().map(|t| trader_json(t, epoch)).collect::<Vec<_>>(),
            })
        }
        InspectCmd::Program { chain } => {
            let c = chain.connect()?;
            let acc = c
                .account(c.program, Level::Confirmed)
                .await?
                .with_context(|| format!("no account at {}", b58(&c.program)))?;
            let mut v = json!({
                "program": b58(&c.program),
                "loader": b58(&acc.owner),
                "context_slot": acc.context_slot.to_string(),
            });
            if acc.owner == timescales_chain::program::BPF_LOADER_UPGRADEABLE {
                let pd = timescales_chain::program::loader::program_data_address(&c.program)?;
                let data = c
                    .account(pd, Level::Confirmed)
                    .await?
                    .context("the program's ProgramData account is missing")?;
                let p = timescales_chain::program::loader::decode_program_data(&data.data)
                    .map_err(|e| anyhow::anyhow!("ProgramData: {e}"))?;
                v["upgradeable"] = json!(true);
                v["program_data"] = json!(b58(&pd));
                v["upgrade_authority"] = json!(p.upgrade_authority.as_ref().map(b58));
                v["last_deploy_slot"] = json!(p.last_deploy_slot.to_string());
                v["program_data_len"] = json!(data.data.len());
            } else {
                // `solana-test-validator --bpf-program` loads the program
                // with a non-upgradeable loader.
                v["upgradeable"] = json!(false);
                v["program_len"] = json!(acc.data.len());
            }
            v
        }
    };
    print_json(&out)
}
