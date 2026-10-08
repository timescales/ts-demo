//! `timescales-krc` command line: member and dealer services.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use timescales_krc::config::parse_b58_32;
use timescales_krc::service::{self, AnyConfig};
use timescales_service::{ConfigError, Profile, init_telemetry, shutdown_signal};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "timescales-krc",
    version,
    about = "Timescales key-release committee member and dealer"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProfileArg {
    Local,
    Devnet,
    Production,
}

impl From<ProfileArg> for Profile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Local => Profile::Local,
            ProfileArg::Devnet => Profile::Devnet,
            ProfileArg::Production => Profile::Production,
        }
    }
}

#[derive(Debug, clap::Args)]
struct ConfigArgs {
    /// The member or dealer configuration file.
    #[arg(long)]
    config: PathBuf,
    /// Overrides the file's `profile`.
    #[arg(long, value_enum)]
    profile: Option<ProfileArg>,
}

impl ConfigArgs {
    fn profile(&self) -> Option<Profile> {
        self.profile.map(Profile::from)
    }
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Committee member: `run`, `rekey`.
    Member {
        #[command(subcommand)]
        cmd: MemberCmd,
    },
    /// Run the trusted dealer.
    Dealer {
        #[command(flatten)]
        config: ConfigArgs,
        #[command(subcommand)]
        cmd: Option<DealerCmd>,
    },
    /// Validate a member or dealer configuration. Without `--offline` also
    /// its chain bindings.
    ConfigCheck {
        #[command(flatten)]
        config: ConfigArgs,
        /// Check the file and the files it names only, without RPC.
        #[arg(long)]
        offline: bool,
    },
}

#[derive(Debug, Subcommand)]
enum MemberCmd {
    Run {
        #[command(flatten)]
        config: ConfigArgs,
    },
    /// Advance the at-rest key generation and erase unused ones.
    /// Run it while the member is stopped.
    Rekey {
        #[command(flatten)]
        config: ConfigArgs,
    },
}

#[derive(Debug, Subcommand)]
enum DealerCmd {
    /// Emergency rotation: drop this dealer's dealings of the
    /// market's previous committee from an epoch on, so they are dealt
    /// again under the configured (current) committee.
    Supersede {
        /// Market address (base58).
        #[arg(long)]
        market: String,
        #[arg(long)]
        from_epoch: u64,
    },
}

fn telemetry(
    cfg: &timescales_service::TelemetryConfig,
    service: &'static str,
) -> anyhow::Result<timescales_service::TelemetryGuard> {
    init_telemetry(cfg, service).context("starting telemetry")
}

fn cancel_on_signal() -> CancellationToken {
    let token = CancellationToken::new();
    let t = token.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        t.cancel();
    });
    token
}

fn exit(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

async fn config_check(args: &ConfigArgs, offline: bool) -> anyhow::Result<ExitCode> {
    let cfg = match service::load_any(&args.config, args.profile()) {
        Ok(cfg) => cfg,
        Err(ConfigError::Invalid(issues)) => {
            for i in &issues {
                eprintln!("{i}");
            }
            eprintln!("{}: {} issue(s)", args.config.display(), issues.len());
            return Ok(ExitCode::from(2));
        }
        Err(e) => return Err(e.into()),
    };
    let mut issues = service::file_issues(&cfg);
    if !offline {
        issues.extend(service::chain_issues(&cfg).await?);
    }
    let (kind, profile) = match &cfg {
        AnyConfig::Member(m) => ("member", m.profile),
        AnyConfig::Dealer(d) => ("dealer", d.profile),
    };
    if issues.is_empty() {
        println!(
            "{}: {kind} configuration valid (profile {profile}{})",
            args.config.display(),
            if offline { ", offline" } else { "" }
        );
        Ok(ExitCode::SUCCESS)
    } else {
        for i in &issues {
            eprintln!("{i}");
        }
        eprintln!("{}: {} issue(s)", args.config.display(), issues.len());
        Ok(ExitCode::from(2))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    match Cli::parse().cmd {
        Cmd::ConfigCheck { config, offline } => config_check(&config, offline).await,
        Cmd::Member {
            cmd: MemberCmd::Run { config },
        } => {
            let cfg = service::load_member(&config.config, config.profile())?;
            let _telemetry = telemetry(&cfg.telemetry, "timescales-krc-member")?;
            let code = service::run_member(cfg, cancel_on_signal()).await?;
            Ok(exit(code))
        }
        Cmd::Member {
            cmd: MemberCmd::Rekey { config },
        } => {
            let cfg = service::load_member(&config.config, config.profile())?;
            let generation = service::rekey(&cfg).await?;
            println!("at-rest key generation is now {generation}");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Dealer { config, cmd: None } => {
            let cfg = service::load_dealer(&config.config, config.profile())?;
            let _telemetry = telemetry(&cfg.telemetry, "timescales-krc-dealer")?;
            let code = service::run_dealer(cfg, cancel_on_signal()).await?;
            Ok(exit(code))
        }
        Cmd::Dealer {
            config,
            cmd: Some(DealerCmd::Supersede { market, from_epoch }),
        } => {
            let cfg = service::load_dealer(&config.config, config.profile())?;
            let market = parse_b58_32(&market).context("--market is not a base58 address")?;
            let dropped = service::supersede(cfg, market, from_epoch).await?;
            println!("dropped {dropped} dealing(s) of the previous committee");
            Ok(ExitCode::SUCCESS)
        }
    }
}
