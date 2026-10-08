//! Settlement crank (phases 10 -> 11): verify the settlement leaves,
//! finalize, apply and close, resuming from the batch's bitmaps after any
//! interruption (`ensure_settled`), with progress events at most once a
//! second. Missing co-signatures are re-sent first, since no leaf verifies
//! below the quorum. The poster enclave cranks the same way as a backstop,
//! so the node cannot stall a posted batch.

use std::sync::Arc;
use std::time::Duration;

use timescales_auction::receipts::ExecutionArtifacts;
use timescales_chain::program::{AbortReason, TimescalesProgramError};
use timescales_chain::{ChainError, Level, SettleStage};
use timescales_core::Decode;
use timescales_service::api::{Event, SettlementStage, U64};
use timescales_service::store::node::{EpochPatch, Phase};

use crate::archive::Terminal;
use crate::market::FenceReason;
use crate::market::JobOutput;
use crate::market::jobs::{JobCtx, Step, Stop};
use crate::market::recover::{Action, ChainState, action};

/// Program errors after which the batch cannot settle (abort
/// triggers: verify failure after posting).
fn unsettleable(e: &ChainError) -> bool {
    let ChainError::Program { code, .. } = e else {
        return false;
    };
    [
        TimescalesProgramError::Insolvent,
        TimescalesProgramError::BadProof,
        TimescalesProgramError::DuplicateTrader,
    ]
    .iter()
    .any(|p| *p as u32 == *code)
}

pub(crate) async fn settle_job(ctx: &JobCtx, e: u64) -> Step<JobOutput> {
    let row = ctx.row(e).await?;
    if row.phase != Phase::Posted {
        return Ok(JobOutput::Row(Box::new(row)));
    }
    let (state, batch) = ctx.chain_state(e).await?;
    match action(Some(row.phase), state) {
        Action::Settle => {}
        Action::MarkSettled => return mark_settled(ctx, e, None).await,
        Action::MarkAborted => {
            return Ok(JobOutput::Row(Box::new(
                ctx.mark_aborted(e, batch.as_ref()).await?,
            )));
        }
        _ => return Err(Stop::Fence(FenceReason::StateDivergence)),
    }
    let m = ctx.chain.market(Level::Confirmed).await?;
    if m.halted {
        return Ok(JobOutput::Halted);
    }
    let result = crate::market::store::result(&ctx.repo, ctx.market, e)
        .await?
        .ok_or_else(|| Stop::Failed(format!("epoch {e} is posted without a stored result")))?;
    let artifacts = ExecutionArtifacts::decode_exact(&result.artifacts)
        .map_err(|err| Stop::Failed(format!("stored artifacts do not decode: {err}")))?;
    if let Some(b) = batch.as_ref()
        && state == ChainState::ReceiptPosted
        && !m.quorum_met(b.cosign_bitmap)
    {
        let missing: Vec<_> = result
            .cosigs
            .iter()
            .filter(|(k, _)| {
                m.executor_slot(k)
                    .is_some_and(|s| b.cosign_bitmap & (1 << s) == 0)
            })
            .copied()
            .collect();
        if !missing.is_empty() {
            ctx.chain
                .ensure_cosigned(e, missing, ctx.cranker.clone())
                .await?;
        }
    }
    let settlement = Arc::new(artifacts.settlement);
    let deltas = settlement.deltas.len();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<timescales_chain::SettleProgress>(64);
    let forward = {
        let events = ctx.events.clone();
        let market = ctx.market;
        let clock = ctx.clock.clone();
        tokio::spawn(async move {
            let mut last_ms = 0u64;
            while let Some(p) = rx.recv().await {
                let now = clock.now_ms();
                let stage = match p.stage {
                    SettleStage::Verifying | SettleStage::Finalizing => SettlementStage::Verifying,
                    SettleStage::Applying | SettleStage::Closing => SettlementStage::Applying,
                };
                if now < last_ms.saturating_add(1_000) && p.done < p.total {
                    continue;
                }
                last_ms = now;
                let event = Event::EpochSettlement {
                    market: timescales_service::api::B58(market),
                    epoch: U64(e),
                    stage,
                    done: p.done,
                    total: p.total,
                };
                let _ = events.publish(vec![(Some(market), event)], now).await;
            }
        })
    };
    let settled = ctx
        .chain
        .ensure_settled(e, settlement, ctx.cranker.clone(), tx)
        .await;
    let _ = tokio::time::timeout(Duration::from_secs(1), forward).await;
    match settled {
        Ok(slot) => {
            ctx.metrics.chain_op("settle", "ok");
            ctx.metrics
                .settlement_deltas
                .get_or_create(&ctx.metrics.market(&ctx.market))
                .observe(deltas as f64);
            mark_settled(ctx, e, Some(slot)).await
        }
        Err(err) if unsettleable(&err) => {
            tracing::error!(epoch = e, error = %err, "the posted batch cannot settle");
            let earliest = row
                .receipt_slot
                .unwrap_or(0)
                .saturating_add(m.settle_timeout_slots)
                + 1;
            let row = ctx
                .begin_abort(
                    e,
                    AbortReason::SettleTimeout,
                    "verification failed after posting",
                    Some(earliest),
                )
                .await?;
            Ok(JobOutput::Row(Box::new(row)))
        }
        Err(err) => {
            ctx.metrics.chain_op("settle", "error");
            Err(err.into())
        }
    }
}

/// The candidate order state is confirmed, the epoch is
/// terminal and its public data archived.
async fn mark_settled(ctx: &JobCtx, e: u64, slot: Option<u64>) -> Step<JobOutput> {
    let slot = match slot {
        Some(s) => s,
        None => ctx.chain.slot(Level::Confirmed).await?,
    };
    match ctx.repo.confirm_order_state(ctx.market, e).await {
        Ok(()) | Err(timescales_service::store::StoreError::Conflict(_)) => {}
        Err(other) => return Err(other.into()),
    }
    let row = ctx
        .advance(
            e,
            Phase::Settled,
            EpochPatch {
                terminal_slot: Some(slot),
                ..EpochPatch::default()
            },
        )
        .await?;
    ctx.write_archive(&row, Terminal::Settled).await;
    let cutoff = row.cutoff_ms.unwrap_or(0);
    let took = Duration::from_millis(ctx.now().saturating_sub(cutoff));
    ctx.metrics
        .epoch_cutoff_to_terminal_seconds
        .get_or_create(&ctx.metrics.with(&ctx.market, &[("outcome", "settled")]))
        .observe(took.as_secs_f64());
    ctx.publish(vec![Event::EpochSettled {
        market: ctx.b58(),
        epoch: U64(e),
        slot: U64(slot),
    }])
    .await;
    Ok(JobOutput::Row(Box::new(row)))
}
