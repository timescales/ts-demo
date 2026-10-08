//! `crank reveal|cosign|settle|abort|reclaim`: one manual run of a program
//! flow through the same idempotent `MarketChain` operations the node and
//! the enclaves use, for runbooks when those are down.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Subcommand, ValueEnum};
use serde_json::json;
use timescales_chain::program::AbortReason;
use timescales_chain::{
    AbortOutcome, CosignOutcome, MarketChain, RevealOutcome, SettleProgress, SettleStage,
};
use timescales_core::Decode;
use timescales_service::wire::ExecutePosted;

use crate::rpc::ChainArgs;
use crate::util::{b58, parse_key, parse_sig, print_json};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum Reason {
    /// Admin abort (status Committed..Verified, nothing applied).
    Admin,
    /// Relay abort, only before the beacon's first target slot.
    Relay,
    BeaconExpired,
    ExecTimeout,
    SettleTimeout,
    QuorumTimeout,
}

impl From<Reason> for AbortReason {
    fn from(r: Reason) -> Self {
        match r {
            Reason::Admin => AbortReason::Admin,
            Reason::Relay => AbortReason::Relay,
            Reason::BeaconExpired => AbortReason::BeaconExpired,
            Reason::ExecTimeout => AbortReason::ExecTimeout,
            Reason::SettleTimeout => AbortReason::SettleTimeout,
            Reason::QuorumTimeout => AbortReason::QuorumTimeout,
        }
    }
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum CrankCmd {
    /// RevealBeacon (permissionless).
    Reveal {
        #[arg(long)]
        market: String,
        #[arg(long)]
        epoch: u64,
        /// Fee payer keypair.
        #[arg(long)]
        payer: PathBuf,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// CoSignReceipt for each given co-signature (any fee payer).
    Cosign {
        #[arg(long)]
        market: String,
        #[arg(long)]
        epoch: u64,
        /// `<executor>:<signature>` over the cosign digest (repeat).
        #[arg(long = "cosig", required = true)]
        cosigs: Vec<String>,
        #[arg(long)]
        payer: PathBuf,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// VerifyDeltas, FinalizeVerification, ApplyDeltas and CloseBatch for a
    /// posted batch, from the enclave's `ExecutePosted` (bytes).
    Settle {
        #[arg(long)]
        market: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        posted: PathBuf,
        #[arg(long)]
        payer: PathBuf,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// AbortBatch with a reason. The signer must be allowed to use it.
    Abort {
        #[arg(long)]
        market: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long, value_enum)]
        reason: Reason,
        /// Admin keypair for `admin`, relay keypair for `relay`, any payer
        /// for the timeouts.
        #[arg(long)]
        signer: PathBuf,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// ReclaimBatch: return a terminal batch's rent to the relay once it is
    /// past retention.
    Reclaim {
        #[arg(long)]
        market: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        payer: PathBuf,
        #[command(flatten)]
        chain: ChainArgs,
    },
}

fn parse_cosig(s: &str) -> Result<([u8; 32], [u8; 64])> {
    let (executor, sig) = s
        .split_once(':')
        .context("a co-signature is `<executor>:<signature>`")?;
    Ok((parse_key(executor)?, parse_sig(sig)?))
}

pub(crate) async fn run(cmd: CrankCmd) -> Result<()> {
    let out = match cmd {
        CrankCmd::Reveal {
            market,
            epoch,
            payer,
            chain,
        } => {
            let mc = chain.connect()?.market_chain(parse_key(&market)?);
            let payer = crate::keys::load_signer(&payer)?;
            match mc.ensure_revealed(epoch, payer).await? {
                RevealOutcome::Revealed { beacon, slot } => {
                    json!({"revealed": {"beacon": beacon.to_hex(), "slot": slot}})
                }
                RevealOutcome::NotReady { slots_left } => {
                    json!({"not_ready": {"slots_left": slots_left}})
                }
                RevealOutcome::Expired => json!("expired"),
                RevealOutcome::Terminal(s) => json!({"terminal": format!("{s:?}")}),
            }
        }
        CrankCmd::Cosign {
            market,
            epoch,
            cosigs,
            payer,
            chain,
        } => {
            let cosigs = cosigs
                .iter()
                .map(|s| parse_cosig(s))
                .collect::<Result<Vec<_>>>()?;
            let executors: Vec<_> = cosigs.iter().map(|(e, _)| *e).collect();
            let mc = chain.connect()?.market_chain(parse_key(&market)?);
            let payer = crate::keys::load_signer(&payer)?;
            let outcomes = mc.ensure_cosigned(epoch, cosigs, payer).await?;
            json!(executors.iter().zip(outcomes).map(|(e, o)| json!({
                "executor": b58(e),
                "outcome": match o {
                    CosignOutcome::Cosigned { slot } => json!({"cosigned": slot}),
                    CosignOutcome::AlreadyCosigned => json!("already_cosigned"),
                    CosignOutcome::OutcomeMismatch => json!("outcome_mismatch"),
                    CosignOutcome::WrongStatus(s) => json!({"wrong_status": format!("{s:?}")}),
                    CosignOutcome::Rejected(e) => json!({"rejected": e.name()}),
                },
            })).collect::<Vec<_>>())
        }
        CrankCmd::Settle {
            market,
            epoch,
            posted,
            payer,
            chain,
        } => {
            let address = parse_key(&market)?;
            let bytes =
                std::fs::read(&posted).with_context(|| format!("read {}", posted.display()))?;
            let posted = ExecutePosted::decode_exact(&bytes)
                .with_context(|| format!("{} is not an ExecutePosted", posted.display()))?;
            let c = chain.connect()?;
            let Some((_, batch)) = c.batch(address, epoch).await? else {
                bail!("epoch {epoch} has no Batch account");
            };
            let outcome = posted.receipt.outcome.digest();
            if outcome != batch.outcome_digest {
                bail!(
                    "the artifacts are for outcome {}, the batch posted {}",
                    outcome.to_hex(),
                    batch.outcome_digest.to_hex()
                );
            }
            posted
                .artifacts
                .check_against(&posted.receipt.outcome)
                .map_err(|e| anyhow::anyhow!("artifacts do not match their receipt: {e}"))?;
            let payer = crate::keys::load_signer(&payer)?;
            let (tx, mut rx) = tokio::sync::mpsc::channel::<SettleProgress>(64);
            let progress = tokio::spawn(async move {
                while let Some(p) = rx.recv().await {
                    let stage = match p.stage {
                        SettleStage::Verifying => "verifying",
                        SettleStage::Finalizing => "finalizing",
                        SettleStage::Applying => "applying",
                        SettleStage::Closing => "closing",
                    };
                    eprintln!("{stage} {}/{}", p.done, p.total);
                }
            });
            let slot = c
                .market_chain(address)
                .ensure_settled(epoch, Arc::new(posted.artifacts.settlement), payer, tx)
                .await?;
            progress.await.ok();
            json!({"settled": {"epoch": epoch, "slot": slot}})
        }
        CrankCmd::Abort {
            market,
            epoch,
            reason,
            signer,
            chain,
        } => {
            let mc = chain.connect()?.market_chain(parse_key(&market)?);
            let signer = crate::keys::load_signer(&signer)?;
            match mc.ensure_aborted(epoch, reason.into(), signer).await? {
                AbortOutcome::Aborted { reason } => json!({"aborted": format!("{reason:?}")}),
                AbortOutcome::AlreadyTerminal(s) => json!({"already_terminal": format!("{s:?}")}),
                AbortOutcome::NotAllowedYet { slots_left } => {
                    json!({"not_allowed_yet": {"slots_left": slots_left}})
                }
                AbortOutcome::Superseded(s) => json!({"superseded": format!("{s:?}")}),
            }
        }
        CrankCmd::Reclaim {
            market,
            epoch,
            payer,
            chain,
        } => {
            let mc = chain.connect()?.market_chain(parse_key(&market)?);
            let payer = crate::keys::load_signer(&payer)?;
            mc.ensure_reclaimed(epoch, payer).await?;
            json!({"reclaimed": epoch})
        }
    };
    print_json(&out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::util::b58_sig;

    #[test]
    fn cosignatures_parse_as_executor_and_signature() {
        let (e, s) = parse_cosig(&format!("{}:{}", b58(&[3; 32]), b58_sig(&[4; 64]))).unwrap();
        assert_eq!((e, s), ([3; 32], [4; 64]));
        assert!(parse_cosig(&b58(&[3; 32])).is_err());
    }

    #[test]
    fn every_reason_maps_to_its_program_code() {
        let codes: Vec<u8> = Reason::value_variants()
            .iter()
            .map(|r| AbortReason::from(*r) as u8)
            .collect();
        assert_eq!(codes, [1, 2, 3, 4, 5, 6]);
    }
}
