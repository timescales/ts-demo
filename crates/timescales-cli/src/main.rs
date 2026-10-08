// Floating point here only formats timings for humans. No financial value
// is ever a float.
#![allow(clippy::float_arithmetic, clippy::cast_possible_truncation)]

//! `timescales`: local tooling for the Timescales prototype.
//!
//! ```text
//! timescales keygen   -o key.hex                     new 32-byte key seed
//! timescales gen      --orders N -o batch.bin        synthetic sealed batch
//! timescales exec     --batch batch.bin -o out.bin --insecure-dev-keys
//! timescales verify   --batch batch.bin --result out.bin
//! timescales check-envelopes --input crosscheck.bin     open SDK-sealed envelopes
//! timescales demo     --epochs 5 --insecure-dev-keys    end-to-end dark pool
//! ```
//!
//! `exec` and `demo` derive every secret from fixed seeds and run simulated
//! executors, so they refuse to start without `--insecure-dev-keys` and
//! print a banner saying so.

mod check;
mod config;
mod demo;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use rand::{RngCore, SeedableRng};
use serde_json::json;
use timescales_auction::receipts::{ExecutionArtifacts, ExecutionReceipt};
use timescales_core::identity::ExecutorKey;
use timescales_core::{CommitmentScheme, Decode, Encode, FlowMode, Reader, encoding::put_bytes};
use timescales_executor::mpc::{MpcCommittee, MpcConfig, MpcExecutor, NetworkModel};
use timescales_executor::workload::{
    Funding, WorkloadConfig, attach_masked, default_params, generate,
};
use timescales_executor::{
    ConfidentialExecutor, ExecutionBatch, ExecutionResult, LocalKeySchedule, ReferenceExecutor,
};

#[derive(Parser)]
#[command(
    name = "timescales",
    version,
    about = "Timescales: confidential batch-auction dark pool (research prototype)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Flow {
    Single,
    Dual,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Backend {
    Reference,
    Tee,
    Mpc,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a 32-byte key seed (hex).
    Keygen {
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Write default market parameters as JSON.
    Params {
        #[arg(long, value_enum, default_value_t = Flow::Dual)]
        flow: Flow,
        /// Poseidon commitments (needed for markets with proofs).
        #[arg(long)]
        zk: bool,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Generate a synthetic sealed batch.
    Gen {
        #[arg(long, default_value_t = 1000)]
        orders: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, value_enum, default_value_t = Flow::Dual)]
        flow: Flow,
        /// Seed of the local epoch-key schedule (hex, 32 bytes).
        #[arg(
            long,
            default_value = "0707070707070707070707070707070707070707070707070707070707070707"
        )]
        key_seed: String,
        /// Fraction of traders funded for only a few orders, in percent.
        #[arg(long)]
        tight: Option<u8>,
        /// Seed of the simulated MPC committee issuing input masks.
        #[arg(long, default_value_t = 1)]
        committee_seed: u64,
        /// Market parameters (JSON, see `timescales params`). Overrides `--flow`.
        #[arg(long)]
        market_config: Option<PathBuf>,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Execute a batch file on a backend and write the result.
    Exec {
        #[arg(long)]
        batch: PathBuf,
        #[arg(long, value_enum, default_value_t = Backend::Reference)]
        backend: Backend,
        #[arg(
            long,
            default_value = "0707070707070707070707070707070707070707070707070707070707070707"
        )]
        key_seed: String,
        /// Must match the `gen` that issued the masks.
        #[arg(long, default_value_t = 1)]
        committee_seed: u64,
        #[arg(short, long)]
        out: PathBuf,
        /// Acknowledge that the epoch keys come from a fixed seed and the
        /// executors are simulated. Required.
        #[arg(long)]
        insecure_dev_keys: bool,
    },
    /// Check a result against its batch: signature, binding, roots, conservation.
    Verify {
        #[arg(long)]
        batch: PathBuf,
        #[arg(long)]
        result: PathBuf,
    },
    /// Open envelopes sealed by the TypeScript SDK
    /// (`ts/packages/sdk/scripts/crosscheck.ts`) and compare each with the
    /// intent recorded beside it.
    CheckEnvelopes {
        #[arg(long)]
        input: PathBuf,
    },
    /// Run a multi-epoch dark pool end to end in one process.
    Demo {
        #[arg(long, default_value_t = 4)]
        epochs: u64,
        #[arg(long, default_value_t = 200)]
        orders: usize,
        #[arg(long, default_value_t = 60)]
        traders: usize,
        /// Kill the TEE in this epoch to show failover to the MPC committee.
        #[arg(long)]
        fail_tee_at: Option<u64>,
        /// Acknowledge that every key comes from a fixed seed and the
        /// enclave, MPC committee and price notary are simulated. Required.
        #[arg(long)]
        insecure_dev_keys: bool,
    },
}

/// Refuses to run a command that derives its secrets from fixed seeds
/// unless the operator said so, then prints what is simulated.
fn require_insecure_dev_keys(command: &str, acknowledged: bool) -> Result<()> {
    if !acknowledged {
        bail!(
            "`timescales {command}` derives every key from a fixed seed and runs simulated \
             executors; pass --insecure-dev-keys to run it anyway"
        );
    }
    eprintln!("{}", simulation_banner(command));
    Ok(())
}

fn simulation_banner(command: &str) -> String {
    let rule = "=".repeat(72);
    format!(
        "{rule}\n\
         SIMULATION: `timescales {command}` runs with INSECURE development keys.\n\
         - Epoch keys and the executor key are derived from fixed seeds:\n  \
           anyone with the seed can read every order.\n\
         - TEE execution: simulated enclave on ordinary hardware.\n\
         - MPC backend: in-process simulation with a trusted dealer.\n\
         - Reference price (TLSNotary): modelled.\n\
         Never use these keys or results outside local testing.\n\
         {rule}"
    )
}

fn seed32(hex_str: &str) -> Result<[u8; 32]> {
    let v = hex::decode(hex_str).context("key seed is not hex")?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("key seed must be 32 bytes"))
}

pub(crate) fn write_result(r: &ExecutionResult) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, &r.receipt.to_bytes());
    put_bytes(&mut out, &r.artifacts.to_bytes());
    put_bytes(&mut out, r.attestation.as_deref().unwrap_or(&[]));
    put_bytes(&mut out, r.proof.as_ref().map_or(&[][..], |p| &p.bytes));
    out
}

fn read_result(b: &[u8]) -> Result<(ExecutionReceipt, ExecutionArtifacts)> {
    let mut r = Reader::new(b);
    let receipt = ExecutionReceipt::decode_exact(&r.bytes(1 << 20)?)?;
    let artifacts = ExecutionArtifacts::decode_exact(&r.bytes(1 << 30)?)?;
    Ok((receipt, artifacts))
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Params { flow, zk, out } => {
            let flow = match flow {
                Flow::Single => FlowMode::SingleBook,
                Flow::Dual => FlowMode::DualFlow,
            };
            let scheme = if zk {
                CommitmentScheme::PoseidonBn254
            } else {
                CommitmentScheme::Sha256
            };
            let params = config::to_json(&default_params(flow, scheme));
            let text = serde_json::to_string_pretty(&sorted_json(params))? + "\n";
            match out {
                Some(p) => std::fs::write(p, text)?,
                None => print!("{text}"),
            }
        }
        Cmd::Keygen { out } => {
            let mut s = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut s);
            let line = hex::encode(s);
            match out {
                Some(p) => std::fs::write(&p, format!("{line}\n"))
                    .with_context(|| format!("write {}", p.display()))?,
                None => println!("{line}"),
            }
        }
        Cmd::Gen {
            orders,
            seed,
            flow,
            key_seed,
            tight,
            committee_seed,
            market_config,
            out,
        } => {
            let flow = match flow {
                Flow::Single => FlowMode::SingleBook,
                Flow::Dual => FlowMode::DualFlow,
            };
            let params = match market_config {
                Some(p) => {
                    config::from_json(&serde_json::from_str(&std::fs::read_to_string(&p)?)?)?
                }
                None => default_params(flow, CommitmentScheme::Sha256),
            };
            let mut cfg = WorkloadConfig::new(params, orders, seed);
            if let Some(t) = tight {
                cfg.funding = Funding::Tight(t);
            }
            let keys = LocalKeySchedule::new(seed32(&key_seed)?);
            let mut w = generate(&cfg, &keys);
            // Masked encoding comes from a committee seeded like `exec --backend mpc`.
            let committee = committee(committee_seed);
            if orders <= 20_000 {
                attach_masked(&mut w, &committee);
            }
            std::fs::write(&out, w.batch.to_bytes())?;
            println!(
                "{}",
                json!({"orders": orders, "envelopes": w.batch.envelopes.len(), "masked": !w.batch.masked.is_empty(), "header": w.batch.header.digest().to_hex()})
            );
        }
        Cmd::Exec {
            batch,
            backend,
            key_seed,
            committee_seed,
            out,
            insecure_dev_keys,
        } => {
            require_insecure_dev_keys("exec", insecure_dev_keys)?;
            let b = ExecutionBatch::decode_exact(&std::fs::read(&batch)?).context("batch file")?;
            let keys = LocalKeySchedule::new(seed32(&key_seed)?);
            let r = match backend {
                Backend::Reference => {
                    ReferenceExecutor::new(Arc::new(keys), ExecutorKey::from_seed([42; 32]))
                        .execute(b)
                        .await?
                }
                Backend::Tee => {
                    // Split the batch's epoch key across a fresh local
                    // committee, commit the root, run attested execution.
                    let dep = timescales_executor::tee::LocalTeeDeployment::new(5, 3, 1);
                    let sk = timescales_executor::KeyProvider::epoch_secret(
                        &keys,
                        b.header.market,
                        b.header.epoch,
                    )?;
                    dep.install_epoch_secret(b.header.market, b.header.epoch, &sk);
                    dep.commit(&b.header);
                    dep.executor.execute(b).await?
                }
                Backend::Mpc => {
                    if b.masked.is_empty() {
                        bail!("batch has no masked encoding (generated with more than 20k orders)");
                    }
                    // The simulated dealer is deterministic, so replaying the
                    // mask requests rebuilds the committee state `gen` left.
                    let c = Arc::new(committee(committee_seed));
                    let layout_len = |m: &timescales_core::intent::MaskedIntent| match &m.body {
                        timescales_core::intent::MaskedBody::Place(p) => {
                            Some((p.trader, p.values.len(), p.mask_offset))
                        }
                        _ => None,
                    };
                    for m in &b.masked {
                        if let Some((t, len, off)) = layout_len(m) {
                            let (got, _) = c.request_masks_for(t, m.epoch, len)?;
                            if got != off {
                                bail!("committee seed does not match the one used by gen");
                            }
                        }
                    }
                    let r = MpcExecutor::new(c.clone()).execute(b).await?;
                    if let Some(rep) = c.last_report() {
                        eprintln!(
                            "mpc: parties {} rounds {} MB/party {:.1} comparisons {} triples {} compute/party {:.1} ms, LAN {:.1} ms, WAN {:.1} ms",
                            rep.parties,
                            rep.meter.rounds,
                            rep.meter.bytes_per_party(rep.parties) as f64 / 1e6,
                            rep.meter.comparisons,
                            rep.preprocessing.triples,
                            rep.per_party_compute().as_secs_f64() * 1e3,
                            rep.online_latency(&NetworkModel::LAN).as_secs_f64() * 1e3,
                            rep.online_latency(&NetworkModel::WAN).as_secs_f64() * 1e3,
                        );
                    }
                    r
                }
            };
            std::fs::write(&out, write_result(&r))?;
            let stages: serde_json::Map<String, serde_json::Value> = r
                .metrics
                .stages
                .iter()
                .map(|(k, v)| (k.to_string(), json!(v.as_secs_f64() * 1e3)))
                .collect();
            println!(
                "{}",
                json!({
                    "receipt": r.receipt.digest().to_hex(),
                    "fills": r.artifacts.fills.len(),
                    "clearing": r.receipt.outcome.clearing.iter().map(|c| json!({"book": format!("{:?}", c.book), "tick": c.tick.0, "volume": c.volume.0})).collect::<Vec<_>>(),
                    "accepted": r.metrics.accepted,
                    "rejected": r.metrics.rejected,
                    "stages_ms": stages,
                })
            );
        }
        Cmd::Verify { batch, result } => {
            let b = ExecutionBatch::decode_exact(&std::fs::read(&batch)?).context("batch file")?;
            let (receipt, artifacts) = read_result(&std::fs::read(&result)?)?;
            receipt.verify_signature()?;
            if receipt.outcome.header_digest != b.header.digest() {
                bail!("receipt is for a different batch");
            }
            artifacts.check_against(&receipt.outcome)?;
            artifacts
                .settlement
                .apply(&b.balances)
                .context("settlement would overdraw")?;
            println!(
                "{}",
                json!({"ok": true, "executor": receipt.executor.to_hex(), "backend": format!("{:?}", receipt.backend)})
            );
        }
        Cmd::CheckEnvelopes { input } => check::run(&input)?,
        Cmd::Demo {
            epochs,
            orders,
            traders,
            fail_tee_at,
            insecure_dev_keys,
        } => {
            require_insecure_dev_keys("demo", insecure_dev_keys)?;
            demo::run(epochs, orders, traders, fail_tee_at).await?
        }
    }
    Ok(())
}

/// Dealer seed for a `--committee-seed` value. `gen` and `exec` must agree.
/// It is the seed `seed_from_u64` expands to, so the mask stream is the one
/// the u64-seeded dealer produced.
fn dealer_seed(seed: u64) -> [u8; 32] {
    rand_chacha::ChaCha20Rng::seed_from_u64(seed).get_seed()
}

fn committee(seed: u64) -> MpcCommittee {
    MpcCommittee::new(
        MpcConfig {
            dealer_seed: Some(dealer_seed(seed)),
            ..MpcConfig::default()
        },
        ExecutorKey::from_seed([3; 32]),
    )
}

/// `v` with every object's keys in byte order, whatever `serde_json`
/// features the rest of the build enables.
fn sorted_json(v: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(m) => {
            let mut entries: Vec<(String, Value)> = m.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k, sorted_json(v)))
                    .collect(),
            )
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sorted_json).collect()),
        other => other,
    }
}
