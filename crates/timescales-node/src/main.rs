//! `timescales-node` command line.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use timescales_node::app;
use timescales_service::Profile;

#[derive(Parser)]
#[command(
    name = "timescales-node",
    version,
    about = "Timescales relay, coordinator and public API"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Debug, Subcommand)]
enum Cmd {
    /// Run the node.
    Run {
        #[arg(long)]
        config: PathBuf,
        /// Overrides the file's profile.
        #[arg(long)]
        profile: Option<String>,
        /// One-shot recovery override when the chain is ahead of the
        /// database.
        #[arg(long)]
        accept_chain_ahead: bool,
    },
    /// Validate a configuration. Without `--offline` also its chain
    /// bindings (genesis, Market accounts, relay key, executors, balances).
    ConfigCheck {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        profile: Option<String>,
        /// Only the rules that need no network: fields, production rules,
        /// market parameter and committee files.
        #[arg(long)]
        offline: bool,
    },
    /// Apply (or with `--check`, try on a copy) pending store migrations.
    Migrate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        check: bool,
    },
    /// Online backup with private tables stripped.
    Backup {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        to: PathBuf,
    },
    /// Rebuild a market's carried order state from chain and archive.
    RecoverState {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        market: String,
    },
    /// Print the configuration reference.
    PrintConfigDocs,
    /// Print the API JSON Schema.
    Schema,
    /// Exit 0 if the node answers ready (the distroless image has no curl).
    Healthcheck {
        #[arg(long, default_value = "http://127.0.0.1:9100/readyz")]
        url: String,
    },
}

fn profile(p: Option<&str>) -> anyhow::Result<Option<Profile>> {
    p.map(|s| Profile::parse(s).ok_or_else(|| anyhow::anyhow!("unknown profile {s:?}")))
        .transpose()
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(timescales_node::MAX_BLOCKING_THREADS)
        .build()?)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    match cli.cmd {
        Cmd::Run {
            config,
            profile: p,
            accept_chain_ahead,
        } => {
            let code = runtime()?.block_on(app::run(
                &config,
                profile(p.as_deref())?,
                accept_chain_ahead,
            ))?;
            Ok(u8::try_from(code).unwrap_or(1))
        }
        Cmd::ConfigCheck {
            config,
            profile: p,
            offline,
        } => {
            runtime()?.block_on(app::config_check(&config, profile(p.as_deref())?, offline))?;
            Ok(0)
        }
        Cmd::Migrate { config, check } => {
            app::migrate(&config, None, check)?;
            Ok(0)
        }
        Cmd::Backup { config, to } => {
            runtime()?.block_on(app::backup(&config, None, to))?;
            Ok(0)
        }
        Cmd::RecoverState { config, market } => {
            runtime()?.block_on(app::recover_state(&config, None, &market))?;
            Ok(0)
        }
        Cmd::PrintConfigDocs => {
            print!("{}", timescales_node::config::config_docs());
            Ok(0)
        }
        Cmd::Schema => {
            println!(
                "{}",
                serde_json::to_string_pretty(&timescales_service::api::schema::schema())?
            );
            Ok(0)
        }
        Cmd::Healthcheck { url } => Ok(if app::healthcheck(&url)? { 0 } else { 1 }),
    }
}
