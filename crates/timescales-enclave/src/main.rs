//! `timescales-enclave` command line.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use timescales_enclave::run;
use timescales_service::{ConfigError, Profile, init_telemetry, shutdown_signal};

#[derive(Parser)]
#[command(
    name = "timescales-enclave",
    version,
    about = "Timescales enclave host service"
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
    /// The enclave configuration file.
    #[arg(long)]
    config: PathBuf,
    /// Overrides the file's `profile`.
    #[arg(long, value_enum)]
    profile: Option<ProfileArg>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    Run {
        #[command(flatten)]
        config: ConfigArgs,
    },
    /// Validate a configuration. Without `--offline` also its chain bindings.
    ConfigCheck {
        #[command(flatten)]
        config: ConfigArgs,
        /// Check the file and the files it names only, without RPC.
        #[arg(long)]
        offline: bool,
    },
    /// Write a simulated key file: a simulated platform key certified by the
    /// vendor seed. No security.
    Keygen {
        /// Required: only the simulated platform has a key file.
        #[arg(long)]
        simulated: bool,
        /// The dev vendor seed (64 hex digits) that certifies the platform.
        #[arg(long)]
        vendor_seed: PathBuf,
        /// The key file to create. Never overwritten.
        #[arg(long)]
        out: PathBuf,
    },
}

fn report(path: &std::path::Path, issues: &[timescales_service::ConfigIssue]) -> ExitCode {
    for i in issues {
        eprintln!("{i}");
    }
    eprintln!("{}: {} issue(s)", path.display(), issues.len());
    ExitCode::from(2)
}

async fn config_check(args: &ConfigArgs, offline: bool) -> anyhow::Result<ExitCode> {
    let cfg = match run::load(&args.config, args.profile.map(Profile::from)) {
        Ok(cfg) => cfg,
        Err(ConfigError::Invalid(issues)) => return Ok(report(&args.config, &issues)),
        Err(e) => return Err(e.into()),
    };
    let mut issues = cfg.file_issues();
    if !offline {
        issues.extend(run::chain_issues(&cfg).await?);
    }
    if !issues.is_empty() {
        return Ok(report(&args.config, &issues));
    }
    println!(
        "{}: enclave configuration valid (profile {}{})",
        args.config.display(),
        cfg.profile,
        if offline { ", offline" } else { "" }
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(feature = "sim-platform")]
fn keygen(vendor_seed: &std::path::Path, out: &std::path::Path) -> anyhow::Result<ExitCode> {
    let id = timescales_enclave::keygen_simulated(vendor_seed, out)?;
    println!(
        "wrote {} (simulated platform {id}; NO SECURITY: whoever holds the vendor seed or this \
         file can forge evidence)",
        out.display()
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(feature = "sim-platform"))]
fn keygen(_vendor_seed: &std::path::Path, _out: &std::path::Path) -> anyhow::Result<ExitCode> {
    anyhow::bail!("keygen writes simulated key files; this build has no sim-platform feature")
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    match Cli::parse().cmd {
        Cmd::ConfigCheck { config, offline } => config_check(&config, offline).await,
        Cmd::Run { config } => {
            let cfg = run::load(&config.config, config.profile.map(Profile::from))?;
            let _telemetry = init_telemetry(&cfg.telemetry, "timescales-enclave")
                .context("starting telemetry")?;
            run::run(cfg, shutdown_signal()).await?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Keygen {
            simulated,
            vendor_seed,
            out,
        } => {
            if !simulated {
                anyhow::bail!(
                    "only --simulated has a key file: an Intel TDX enclave draws its keys at boot"
                );
            }
            keygen(&vendor_seed, &out)
        }
    }
}
