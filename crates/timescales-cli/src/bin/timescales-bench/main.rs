// Floating point here only formats timings for humans. No financial value
// is ever a float.
#![allow(clippy::float_arithmetic, clippy::cast_possible_truncation)]

//! Experiment harness.
//!
//! `timescales-bench plan <suite>` runs every configuration of a suite, each in
//! a fresh child process (so peak memory is per configuration), and appends
//! one JSON object per configuration to `target/bench/results/<suite>.jsonl`.
//! `timescales-bench report` turns the JSONL files into `summary.md` and
//! LaTeX tables under `target/bench/tables`.
//!
//! What is measured and what is modelled:
//!
//! * Reference and TEE runs: wall-clock per stage, process CPU time, peak
//!   heap. The TEE is simulated (no memory encryption, no real quote).
//! * MPC runs: wall-clock of the in-process simulation of all parties
//!   (divided by the party count for per-party compute), plus counted rounds
//!   and bytes turned into LAN/WAN latency estimates by a network model.
//!   Preprocessing is counted, not costed.
//! * ZK runs: Groth16 setup, proving and verification wall-clock, constraint
//!   counts and sizes.

mod experiments;
mod report;
mod stats;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use peak_alloc::PeakAlloc;

#[global_allocator]
static PEAK: PeakAlloc = PeakAlloc;

pub(crate) fn peak_bytes() -> u64 {
    (PEAK.peak_usage_as_mb() as f64 * 1_048_576.0) as u64
}

#[derive(Parser)]
#[command(name = "timescales-bench")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run one configuration and print a JSON line (used by `plan`).
    Run {
        #[arg(long)]
        experiment: String,
        #[arg(long)]
        n: usize,
        #[arg(long, default_value_t = 5)]
        reps: usize,
        #[arg(long, default_value_t = 3)]
        parties: usize,
        #[arg(long, default_value = "log")]
        circuit: String,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        authenticated: bool,
        #[arg(long, default_value_t = 32)]
        half_width: u32,
    },
    /// Run a suite: quick | full | reference | tee | mpc | zk | sort | sizes.
    Plan {
        suite: String,
        #[arg(long, default_value = "target/bench/results")]
        out: PathBuf,
    },
    /// Build summary tables from collected results.
    Report {
        #[arg(long, default_value = "target/bench/results")]
        results: PathBuf,
        #[arg(long, default_value = "target/bench/tables")]
        tables: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run {
            experiment,
            n,
            reps,
            parties,
            circuit,
            authenticated,
            half_width,
        } => {
            let cfg = experiments::RunConfig {
                n,
                reps,
                parties,
                circuit,
                authenticated,
                half_width,
            };
            let v = experiments::run(&experiment, &cfg).await?;
            println!("{v}");
        }
        Cmd::Plan { suite, out } => experiments::plan(&suite, &out)?,
        Cmd::Report { results, tables } => report::write(&results, &tables)?,
    }
    Ok(())
}
