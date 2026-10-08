//! Implements every async trait of the crate with bodies that hold each
//! argument across an await point, so a signature that cannot be
//! implemented (borrowed arguments in a boxed future, non-`Send` captures)
//! fails to compile here rather than in a later package.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use parking_lot::Mutex;
use timescales_auction::settlement::SettlementBatch;
use timescales_chain::program::{AbortReason, BatchAccount, BatchStatus, MarketAccount};
use timescales_chain::{
    AbortOutcome, AccountData, Address, BatchPredicate, BoxFuture, ChainError, ChangeOutcome,
    CommitOutcome, CosignOutcome, Filter, JournalError, Level, MarketChain, PostOutcome,
    RevealOutcome, RpcError, SettleProgress, SettleStage, Simulation, SolanaRpc, TraderSnapshot,
    TxJournal, TxOp, TxOutcome, TxRecord, TxSigner, TxStatus,
};
use timescales_core::{EpochId, Hash32, MarketId, QuoteAtoms};
use tokio::sync::mpsc;
use tokio::task::yield_now;
use tokio::time::Instant;

#[derive(Default)]
struct Log(Mutex<Vec<String>>);

impl Log {
    fn push(&self, s: String) {
        self.0.lock().push(s);
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock())
    }
}

#[derive(Default)]
struct FakeRpc {
    log: Log,
}

impl SolanaRpc for FakeRpc {
    fn get_account(
        &self,
        key: Address,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AccountData>, RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log
                .push(format!("get_account {} {level:?} {min_slot:?}", key[0]));
            Ok(Some(AccountData {
                owner: key,
                lamports: 1,
                data: vec![],
                context_slot: min_slot.unwrap_or(0),
            }))
        })
    }

    fn get_multiple_accounts(
        &self,
        keys: Vec<Address>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<Option<AccountData>>), RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log.push(format!(
                "get_multiple_accounts {} {level:?} {min_slot:?}",
                keys.len()
            ));
            Ok((min_slot.unwrap_or(0), keys.iter().map(|_| None).collect()))
        })
    }

    fn get_program_accounts(
        &self,
        program: Address,
        filters: Vec<Filter>,
        slice: Option<(usize, usize)>,
        level: Level,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<(u64, Vec<(Address, Vec<u8>)>), RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log.push(format!(
                "get_program_accounts {} {filters:?} {slice:?} {level:?} {min_slot:?}",
                program[0]
            ));
            Ok((0, vec![(program, vec![])]))
        })
    }

    fn latest_blockhash(&self, level: Level) -> BoxFuture<'_, Result<([u8; 32], u64), RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log.push(format!("latest_blockhash {level:?}"));
            Ok(([1; 32], 100))
        })
    }

    fn send_transaction(
        &self,
        wire: Vec<u8>,
        skip_preflight: bool,
        min_slot: Option<u64>,
    ) -> BoxFuture<'_, Result<[u8; 64], RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log.push(format!(
                "send_transaction {} {skip_preflight} {min_slot:?}",
                wire.len()
            ));
            Ok([2; 64])
        })
    }

    fn simulate_transaction(&self, wire: Vec<u8>) -> BoxFuture<'_, Result<Simulation, RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log
                .push(format!("simulate_transaction {}", wire.len()));
            Ok(Simulation {
                units: Some(1),
                logs: vec![],
                err: None,
            })
        })
    }

    fn signature_statuses(
        &self,
        sigs: Vec<[u8; 64]>,
    ) -> BoxFuture<'_, Result<Vec<Option<TxStatus>>, RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log.push(format!("signature_statuses {}", sigs.len()));
            Ok(sigs
                .iter()
                .map(|_| {
                    Some(TxStatus {
                        slot: 1,
                        level: Level::Confirmed,
                        err: None,
                    })
                })
                .collect())
        })
    }

    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log.push(format!("slot {level:?}"));
            Ok(7)
        })
    }

    fn block_height(&self, level: Level) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log.push(format!("block_height {level:?}"));
            Ok(6)
        })
    }

    fn genesis_hash(&self) -> BoxFuture<'_, Result<[u8; 32], RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log.push("genesis_hash".into());
            Ok([3; 32])
        })
    }

    fn recent_prioritization_fees(
        &self,
        writable: Vec<Address>,
    ) -> BoxFuture<'_, Result<Vec<u64>, RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log
                .push(format!("recent_prioritization_fees {}", writable.len()));
            Ok(vec![0; writable.len()])
        })
    }

    fn minimum_balance_for_rent_exemption(
        &self,
        len: usize,
    ) -> BoxFuture<'_, Result<u64, RpcError>> {
        Box::pin(async move {
            yield_now().await;
            self.log.push(format!("rent {len}"));
            Ok((128 + len as u64) * 6960)
        })
    }
}

#[derive(Default)]
struct FakeJournal {
    rows: Mutex<Vec<TxRecord>>,
    last_landed: Mutex<u64>,
}

impl TxJournal for FakeJournal {
    fn before_send(&self, rec: TxRecord) -> BoxFuture<'_, Result<i64, JournalError>> {
        Box::pin(async move {
            yield_now().await;
            let mut rows = self.rows.lock();
            let id = i64::try_from(rows.len()).unwrap() + 1;
            rows.push(TxRecord {
                id: Some(id),
                ..rec
            });
            Ok(id)
        })
    }

    fn resolved(&self, id: i64, outcome: TxOutcome) -> BoxFuture<'_, Result<(), JournalError>> {
        Box::pin(async move {
            yield_now().await;
            let slot = match outcome {
                TxOutcome::Landed { slot } | TxOutcome::Failed { slot, .. } => slot,
                TxOutcome::Expired => return Err(JournalError(format!("{id} expired"))),
            };
            let mut last = self.last_landed.lock();
            *last = (*last).max(slot);
            self.rows.lock().retain(|r| r.id != Some(id));
            Ok(())
        })
    }

    fn pending(&self) -> BoxFuture<'_, Result<Vec<TxRecord>, JournalError>> {
        Box::pin(async move {
            yield_now().await;
            Ok(self.rows.lock().clone())
        })
    }

    fn last_landed_slot(&self) -> BoxFuture<'_, Result<u64, JournalError>> {
        Box::pin(async move {
            yield_now().await;
            Ok(*self.last_landed.lock())
        })
    }
}

struct FakeSigner;

impl TxSigner for FakeSigner {
    fn address(&self) -> Address {
        [9; 32]
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        [u8::try_from(message.len() % 256).unwrap(); 64]
    }
}

struct FakeChain {
    rpc: Arc<dyn SolanaRpc>,
    log: Log,
}

impl MarketChain for FakeChain {
    fn address(&self) -> Address {
        [4; 32]
    }

    fn market(&self, level: Level) -> BoxFuture<'_, Result<MarketAccount, ChainError>> {
        Box::pin(async move {
            self.rpc.slot(level).await?;
            Err(ChainError::Inconsistent("no market in the fake"))
        })
    }

    fn batch(
        &self,
        epoch: u64,
        level: Level,
    ) -> BoxFuture<'_, Result<Option<BatchAccount>, ChainError>> {
        Box::pin(async move {
            let slot = self.rpc.slot(level).await?;
            self.log.push(format!("batch {epoch} {slot}"));
            Ok(None)
        })
    }

    fn trader_snapshot(&self, min_slot: u64) -> BoxFuture<'_, Result<TraderSnapshot, ChainError>> {
        Box::pin(async move {
            let (slot, _) = self
                .rpc
                .get_program_accounts([5; 32], vec![], None, Level::Confirmed, Some(min_slot))
                .await?;
            Ok(TraderSnapshot {
                slot: slot.max(min_slot),
                traders: vec![],
            })
        })
    }

    fn slot(&self, level: Level) -> BoxFuture<'_, Result<u64, ChainError>> {
        Box::pin(async move { Ok(self.rpc.slot(level).await?) })
    }

    fn ensure_committed(
        &self,
        epoch: u64,
        root: Hash32,
        count: u32,
        terms: Hash32,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<CommitOutcome, ChainError>> {
        Box::pin(async move {
            let slot = self.rpc.slot(Level::Confirmed).await?;
            self.log.push(format!(
                "commit {epoch} {root} {count} {terms} {}",
                payer.address()[0]
            ));
            Ok(CommitOutcome::Committed { slot })
        })
    }

    fn ensure_revealed(
        &self,
        epoch: u64,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<RevealOutcome, ChainError>> {
        Box::pin(async move {
            let slot = self.rpc.slot(Level::Confirmed).await?;
            self.log
                .push(format!("reveal {epoch} {}", payer.address()[0]));
            Ok(RevealOutcome::Revealed {
                beacon: Hash32::ZERO,
                slot,
            })
        })
    }

    fn wait_batch(
        &self,
        epoch: u64,
        until: BatchPredicate,
        level: Level,
        deadline: Instant,
    ) -> BoxFuture<'_, Result<BatchAccount, ChainError>> {
        Box::pin(async move {
            tokio::time::sleep_until(deadline).await;
            self.rpc.slot(level).await?;
            self.log.push(format!("wait {epoch} {until:?}"));
            Err(ChainError::Inconsistent("no batch in the fake"))
        })
    }

    fn ensure_posted(
        &self,
        epoch: u64,
        header: [u8; 283],
        receipt: Vec<u8>,
        poster: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<PostOutcome, ChainError>> {
        Box::pin(async move {
            let slot = self.rpc.slot(Level::Confirmed).await?;
            let sig = poster.sign(&receipt);
            self.log
                .push(format!("post {epoch} {} {}", header[0], sig[0]));
            Ok(PostOutcome::Posted { slot })
        })
    }

    fn ensure_cosigned(
        &self,
        epoch: u64,
        cosigs: Vec<(Address, [u8; 64])>,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<Vec<CosignOutcome>, ChainError>> {
        Box::pin(async move {
            let slot = self.rpc.slot(Level::Confirmed).await?;
            self.log
                .push(format!("cosign {epoch} {}", payer.address()[0]));
            Ok(cosigs
                .iter()
                .map(|_| CosignOutcome::Cosigned { slot })
                .collect())
        })
    }

    fn ensure_settled(
        &self,
        epoch: u64,
        settlement: Arc<SettlementBatch>,
        payer: Arc<dyn TxSigner>,
        progress: mpsc::Sender<SettleProgress>,
    ) -> BoxFuture<'_, Result<u64, ChainError>> {
        Box::pin(async move {
            let slot = self.rpc.slot(Level::Confirmed).await?;
            let total = u32::try_from(settlement.deltas.len()).unwrap();
            progress
                .send(SettleProgress {
                    stage: SettleStage::Closing,
                    done: total,
                    total,
                })
                .await
                .map_err(|_| ChainError::Inconsistent("progress receiver dropped"))?;
            self.log
                .push(format!("settle {epoch} {}", payer.address()[0]));
            Ok(slot)
        })
    }

    fn ensure_aborted(
        &self,
        epoch: u64,
        reason: AbortReason,
        signer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<AbortOutcome, ChainError>> {
        Box::pin(async move {
            self.rpc.slot(Level::Confirmed).await?;
            self.log
                .push(format!("abort {epoch} {}", signer.address()[0]));
            Ok(AbortOutcome::Aborted { reason })
        })
    }

    fn ensure_change_applied(
        &self,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<ChangeOutcome, ChainError>> {
        Box::pin(async move {
            self.rpc.slot(Level::Confirmed).await?;
            self.log.push(format!("change {}", payer.address()[0]));
            Ok(ChangeOutcome::NothingDue)
        })
    }

    fn ensure_reclaimed(
        &self,
        epoch: u64,
        payer: Arc<dyn TxSigner>,
    ) -> BoxFuture<'_, Result<(), ChainError>> {
        Box::pin(async move {
            self.rpc.slot(Level::Confirmed).await?;
            self.log
                .push(format!("reclaim {epoch} {}", payer.address()[0]));
            Ok(())
        })
    }
}

fn record(op: TxOp) -> TxRecord {
    TxRecord {
        id: None,
        market: [4; 32],
        epoch: Some(1),
        op,
        signature: [2; 64],
        last_valid_block_height: 100,
        sent_at_ms: 0,
    }
}

#[tokio::test]
async fn every_async_trait_is_implementable_and_object_safe() {
    let rpc: Arc<dyn SolanaRpc> = Arc::new(FakeRpc::default());
    rpc.get_account([1; 32], Level::Finalized, Some(3))
        .await
        .unwrap();
    rpc.get_multiple_accounts(vec![[1; 32]], Level::Confirmed, None)
        .await
        .unwrap();
    rpc.latest_blockhash(Level::Confirmed).await.unwrap();
    rpc.send_transaction(vec![0; 10], false, Some(1))
        .await
        .unwrap();
    rpc.simulate_transaction(vec![0; 10]).await.unwrap();
    rpc.signature_statuses(vec![[0; 64]]).await.unwrap();
    rpc.block_height(Level::Processed).await.unwrap();
    rpc.genesis_hash().await.unwrap();
    rpc.recent_prioritization_fees(vec![[1; 32]]).await.unwrap();
    rpc.minimum_balance_for_rent_exemption(148).await.unwrap();

    let journal: Arc<dyn TxJournal> = Arc::new(FakeJournal::default());
    let id = journal.before_send(record(TxOp::Commit)).await.unwrap();
    assert_eq!(journal.pending().await.unwrap().len(), 1);
    journal
        .resolved(id, TxOutcome::Landed { slot: 2 })
        .await
        .unwrap();
    assert!(journal.pending().await.unwrap().is_empty());

    let chain: Arc<dyn MarketChain> = Arc::new(FakeChain {
        rpc: rpc.clone(),
        log: Log::default(),
    });
    let payer: Arc<dyn TxSigner> = Arc::new(FakeSigner);
    assert_eq!(chain.address(), [4; 32]);
    assert!(chain.market(Level::Confirmed).await.is_err());
    assert_eq!(chain.batch(1, Level::Confirmed).await.unwrap(), None);
    chain.trader_snapshot(5).await.unwrap();
    chain.slot(Level::Finalized).await.unwrap();
    chain
        .ensure_committed(1, Hash32::ZERO, 64, Hash32::ZERO, payer.clone())
        .await
        .unwrap();
    chain.ensure_revealed(1, payer.clone()).await.unwrap();
    assert!(
        chain
            .wait_batch(
                1,
                BatchPredicate::AtLeast(BatchStatus::BeaconRevealed),
                Level::Finalized,
                Instant::now(),
            )
            .await
            .is_err()
    );
    chain
        .ensure_posted(1, [2; 283], vec![1; 390], payer.clone())
        .await
        .unwrap();
    chain
        .ensure_cosigned(1, vec![([7; 32], [8; 64])], payer.clone())
        .await
        .unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let settlement = Arc::new(SettlementBatch {
        market: MarketId(1),
        epoch: EpochId(1),
        deltas: vec![],
        fees: QuoteAtoms(0),
    });
    chain
        .ensure_settled(1, settlement, payer.clone(), tx)
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().stage, SettleStage::Closing);
    chain
        .ensure_aborted(1, AbortReason::ExecTimeout, payer.clone())
        .await
        .unwrap();
    chain.ensure_change_applied(payer.clone()).await.unwrap();
    chain.ensure_reclaimed(1, payer).await.unwrap();
}

#[test]
fn fake_rpc_logs_every_call_once() {
    let rpc = FakeRpc::default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        rpc.slot(Level::Confirmed).await.unwrap();
        rpc.genesis_hash().await.unwrap();
    });
    assert_eq!(rpc.log.take(), vec!["slot Confirmed", "genesis_hash"]);
}
