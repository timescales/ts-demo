//! `timescales-admin`: operator CLI. Governance commands print unsigned
//! transactions for the admin multisig (`--unsigned`). Local profiles use
//! keys labelled INSECURE-LOCAL.
//!
//! ```text
//! timescales-admin keygen --profile local --out target/e2e/secrets
//! timescales-admin market id --creator <admin> --salt <hex32>
//! timescales-admin committee build --market <addr> --threshold 2 --members members.toml --out committee.bin
//! timescales-admin market init... [--unsigned]
//! timescales-admin governance propose --market <addr> set-relay --relay <key> --unsigned
//! timescales-admin rotation invalidate --market <addr> --from-epoch <e> --data-dir <node data_dir>
//! timescales-admin executor verify --identity id.json --nonce <hex32> --market <addr> --member-config krc-1.toml
//! timescales-admin inspect market|epoch|traders|program...
//! timescales-admin crank reveal|cosign|settle|abort|reclaim...
//! timescales-admin bootstrap-local
//! ```

mod bootstrap;
mod committee;
mod crank;
mod executor;
mod governance;
mod inspect;
mod keys;
mod market;
mod params;
mod rotation;
mod rpc;
mod tx;
mod util;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

use crate::keys::KeyProfile;
use crate::market::{InitPlan, Timings};
use crate::rpc::{ChainArgs, blockhash_for};
use crate::util::{b58_sig, parse_hex32, parse_key, print_json};

#[derive(Parser)]
#[command(name = "timescales-admin", version, about = "Timescales operator CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate the key files of a profile (never overwrites).
    Keygen {
        #[arg(long, value_enum)]
        profile: KeyProfile,
        #[arg(long)]
        out: PathBuf,
    },
    /// Build a committee description or print its digest.
    Committee {
        #[command(subcommand)]
        cmd: CommitteeCmd,
    },
    /// Market id derivation and market initialisation.
    Market {
        #[command(subcommand)]
        cmd: MarketCmd,
    },
    /// Timelocked governance: propose, apply, cancel, accept, halt,
    /// remove-executor, claim-fees.
    Governance {
        #[command(subcommand)]
        cmd: governance::GovernanceCmd,
    },
    /// Emergency committee rotation.
    Rotation {
        #[command(subcommand)]
        cmd: RotationCmd,
    },
    /// Check an enclave's registration evidence with the members' verifier
    /// and policy, then print the `SetExecutors` proposal.
    Executor {
        #[command(subcommand)]
        cmd: ExecutorCmd,
    },
    /// Read market, epoch, trader and program state.
    Inspect {
        #[command(subcommand)]
        cmd: inspect::InspectCmd,
    },
    /// Send one permissionless crank transaction.
    Crank {
        #[command(subcommand)]
        cmd: crank::CrankCmd,
    },
    /// Bring up a local market with three enclaves and receipt quorum 2.
    BootstrapLocal(Box<bootstrap::BootstrapArgs>),
}

#[derive(Subcommand)]
enum CommitteeCmd {
    /// Write the description of a committee from the members' public keys.
    Build {
        /// Market address the committee serves.
        #[arg(long)]
        market: String,
        #[arg(long)]
        threshold: u8,
        /// `[[member]]` entries with `index`, `identity` and `transport`
        /// (hex), as `keygen` writes them.
        #[arg(long)]
        members: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Validate a description and print its digest and members.
    Digest {
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum MarketCmd {
    /// The market id and address for a creator and salt.
    Id {
        /// The creator's address, or its keypair file.
        #[arg(long)]
        creator: String,
        #[arg(long)]
        salt: String,
        /// Settlement program id [default: the dev id].
        #[arg(long)]
        program: Option<String>,
    },
    /// InitMarket, preceded by the creation of both vaults.
    Init(Box<InitArgs>),
}

#[derive(clap::Args)]
struct InitArgs {
    /// Creator keypair (signs and pays)...
    #[arg(
        long,
        conflicts_with = "unsigned",
        required_unless_present = "unsigned"
    )]
    creator_keypair: Option<PathBuf>,
    ///... or, with `--unsigned`, the creator's address.
    #[arg(long, requires = "unsigned")]
    creator: Option<String>,
    #[arg(long)]
    unsigned: bool,
    /// With `--unsigned`: recent blockhash for offline signing.
    #[arg(long, requires = "unsigned")]
    blockhash: Option<String>,
    #[arg(long)]
    salt: String,
    #[arg(long)]
    admin: String,
    #[arg(long)]
    relay: String,
    /// Market parameter file. `market` is replaced by the derived id.
    #[arg(long)]
    params: PathBuf,
    #[arg(long)]
    committee: PathBuf,
    #[arg(long)]
    base_mint: String,
    #[arg(long)]
    quote_mint: String,
    /// Executor key (repeat for each, 1 to 8).
    #[arg(long = "executor", required = true)]
    executors: Vec<String>,
    #[arg(long, default_value_t = 2)]
    receipt_quorum: u8,
    /// Timing defaults: `local` (d 4, exec 150, settle 1500, timelock 20)
    /// or `production` (d 8, exec 750, settle 9000, timelock 216000).
    #[arg(long, default_value = "production")]
    timings: String,
    #[arg(long)]
    beacon_delay: Option<u16>,
    #[arg(long)]
    timelock: Option<u64>,
    #[arg(long)]
    exec_timeout: Option<u64>,
    #[arg(long)]
    settle_timeout: Option<u64>,
    #[command(flatten)]
    chain: ChainArgs,
}

#[derive(Subcommand)]
enum RotationCmd {
    /// Drop the node's bundles dealt under the previous committee from
    /// `--from-epoch` on and delete their parked envelopes (node stopped).
    Invalidate {
        #[arg(long)]
        market: String,
        #[arg(long)]
        from_epoch: u64,
        /// The node's `data_dir` (holds `node.sqlite` and `LOCK`).
        #[arg(long)]
        data_dir: PathBuf,
        #[command(flatten)]
        chain: ChainArgs,
    },
}

#[derive(Subcommand)]
enum ExecutorCmd {
    /// Verify registration evidence. `--propose` adds the SetExecutors
    /// proposal for the multisig.
    Verify(Box<executor::VerifyArgs>),
}

async fn market_init(a: InitArgs) -> Result<serde_json::Value> {
    let program = a.chain.program_id()?;
    let signer = a
        .creator_keypair
        .as_deref()
        .map(keys::load_signer)
        .transpose()?;
    let creator = match (&signer, &a.creator) {
        (Some(s), _) => s.address(),
        (None, Some(c)) => parse_key(c)?,
        (None, None) => anyhow::bail!("give --creator-keypair, or --creator with --unsigned"),
    };
    let salt = parse_hex32(&a.salt).context("--salt")?;
    let address = market::derive(&program, &creator, &salt)?;
    let committee = committee::read(&a.committee)?;
    committee::check_market(&committee, &address.address)?;
    let mut timings = match a.timings.as_str() {
        "local" => Timings::LOCAL,
        "production" => Timings::PRODUCTION,
        other => anyhow::bail!("--timings is `local` or `production`, not `{other}`"),
    };
    if let Some(d) = a.beacon_delay {
        timings.beacon_delay_slots = d;
    }
    if let Some(t) = a.timelock {
        timings.timelock_slots = t;
    }
    if let Some(t) = a.exec_timeout {
        timings.exec_timeout_slots = t;
    }
    if let Some(t) = a.settle_timeout {
        timings.settle_timeout_slots = t;
    }
    let plan = InitPlan {
        creator,
        salt,
        admin: parse_key(&a.admin).context("--admin")?,
        relay: parse_key(&a.relay).context("--relay")?,
        params: params::load_for_market(&a.params, address.id)?,
        committee_digest: committee.digest(),
        timings,
        receipt_quorum: a.receipt_quorum,
        executors: a
            .executors
            .iter()
            .map(|e| parse_key(e))
            .collect::<Result<_>>()?,
        base_mint: parse_key(&a.base_mint).context("--base-mint")?,
        quote_mint: parse_key(&a.quote_mint).context("--quote-mint")?,
    };
    let ixs = plan.instructions(&program)?;
    let mut out = match signer {
        None => {
            let blockhash = blockhash_for(&a.chain, a.blockhash.as_deref()).await?;
            tx::unsigned_json("init_market", &ixs, &creator, &blockhash)?
        }
        Some(s) => {
            let landed = a
                .chain
                .connect()?
                .send(timescales_chain::TxOp::Admin, ixs, s, vec![])
                .await?;
            json!({
                "action": "init_market",
                "signature": b58_sig(&landed.signature),
                "slot": landed.slot,
            })
        }
    };
    out["market"] = market::describe_address(&program, &creator, &salt, &address);
    out["committee_digest"] = json!(committee.digest().to_hex());
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { profile, out } => {
            let m = keys::keygen(profile, &out)?;
            eprintln!("wrote the {} keys to {}", m["label"], out.display());
            print_json(&m)?;
        }
        Cmd::Committee { cmd } => match cmd {
            CommitteeCmd::Build {
                market,
                threshold,
                members,
                out,
            } => {
                let c = committee::build(
                    parse_key(&market)?,
                    threshold,
                    committee::read_members(&members)?,
                )?;
                committee::write(&out, &c)?;
                let mut v = committee::describe(&c);
                v["file"] = json!(out);
                print_json(&v)?;
            }
            CommitteeCmd::Digest { file } => {
                print_json(&committee::describe(&committee::read(&file)?))?
            }
        },
        Cmd::Market { cmd } => match cmd {
            MarketCmd::Id {
                creator,
                salt,
                program,
            } => {
                let program = ChainArgs {
                    rpc: None,
                    program,
                    priority_fee: 0,
                }
                .program_id()?;
                let creator = bootstrap::creator_key(&creator)?;
                let salt = parse_hex32(&salt).context("--salt")?;
                let m = market::derive(&program, &creator, &salt)?;
                print_json(&market::describe_address(&program, &creator, &salt, &m))?;
            }
            MarketCmd::Init(a) => print_json(&market_init(*a).await?)?,
        },
        Cmd::Governance { cmd } => governance::run(cmd).await?,
        Cmd::Rotation { cmd } => match cmd {
            RotationCmd::Invalidate {
                market,
                from_epoch,
                data_dir,
                chain,
            } => print_json(
                &rotation::run(data_dir, parse_key(&market)?, from_epoch, &chain).await?,
            )?,
        },
        Cmd::Executor { cmd } => match cmd {
            ExecutorCmd::Verify(a) => print_json(&executor::run(*a).await?)?,
        },
        Cmd::Inspect { cmd } => inspect::run(cmd).await?,
        Cmd::Crank { cmd } => crank::run(cmd).await?,
        Cmd::BootstrapLocal(a) => {
            let env = bootstrap::run(*a).await?;
            eprintln!(
                "market {} initialized; INSECURE-LOCAL keys",
                env["market"]["address"].as_str().unwrap_or_default()
            );
            print_json(&env)?;
        }
    }
    Ok(())
}
