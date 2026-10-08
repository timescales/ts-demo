//! Metric families of the node and log redaction.
//!
//! Labels carry the market address prefix, never a wallet. Logs name a
//! wallet only by `wallet_tag` at `info` and never carry envelopes,
//! submissions, grant texts, plaintexts, salts or keys. [`Redacted`] is the
//! one way a byte string reaches a log line.

use std::time::Duration;

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;

use crate::Address;

type Labels = Vec<(String, String)>;
type Hist = Family<Labels, Histogram, fn() -> Histogram>;

fn seconds() -> Histogram {
    Histogram::new(exponential_buckets(0.005, 2.0, 18))
}

fn counts() -> Histogram {
    Histogram::new(exponential_buckets(1.0, 2.0, 12))
}

fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// The `market` label: the first eight base58 characters of the address.
pub fn market_label(market: &Address) -> String {
    bs58::encode(market).into_string().chars().take(8).collect()
}

/// A byte string as it may appear in logs: its length and a short digest
/// prefix, never its contents.
#[derive(Clone, Copy)]
pub struct Redacted<'a>(pub &'a [u8]);

impl core::fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let d = timescales_core::crypto::hash(b"timescales/node/log-redaction", self.0);
        write!(f, "<{} bytes {}..>", self.0.len(), hex::encode(&d.0[..4]))
    }
}

impl core::fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

/// Every node metric family, registered once at start.
#[derive(Debug)]
pub struct NodeMetrics {
    pub epoch_current: Family<Labels, Gauge>,
    pub epoch_last_settled: Family<Labels, Gauge>,
    pub epoch_settlement_lag: Family<Labels, Gauge>,
    pub epoch_phase: Family<Labels, Gauge>,
    pub epoch_phase_seconds: Hist,
    pub epoch_cutoff_to_terminal_seconds: Hist,
    pub epoch_aborts: Family<Labels, Counter>,
    pub epoch_late_cutoff: Family<Labels, Counter>,
    pub intake_paused: Family<Labels, Gauge>,
    pub submissions: Family<Labels, Counter>,
    pub submission_verify_seconds: Histogram,
    pub batch_envelopes: Family<Labels, Histogram, fn() -> Histogram>,
    pub execution_attempts: Family<Labels, Counter>,
    pub execution_seconds: Hist,
    pub receipt_check_failures: Family<Labels, Counter>,
    pub cosign_mismatch: Family<Labels, Counter>,
    pub chain_tx: Family<Labels, Counter>,
    pub chain_slot_lag: Gauge,
    pub relay_balance_lamports: Gauge,
    pub cranker_balance_lamports: Gauge,
    pub settlement_deltas: Family<Labels, Histogram, fn() -> Histogram>,
    pub settlement_txs: Family<Labels, Histogram, fn() -> Histogram>,
    pub keys_ready_ahead: Family<Labels, Gauge>,
    pub governance_pending: Family<Labels, Gauge>,
    pub governance_due: Family<Labels, Gauge>,
    pub equivocation_detected: Family<Labels, Counter>,
    pub market_state: Family<Labels, Gauge>,
    pub store_commit_seconds: Histogram,
    pub store_queue_depth: Gauge,
    pub store_errors: Counter,
    pub snapshot_late: Family<Labels, Counter>,
    pub artifacts_lost: Family<Labels, Counter>,
    pub relay_refusals: Family<Labels, Counter>,
    pub bans: Family<Labels, Counter>,
    pub program_last_deploy_slot: Gauge,
    pub backup_last_success: Family<Labels, Gauge>,
}

impl NodeMetrics {
    pub fn register(registry: &mut Registry) -> Self {
        let m = NodeMetrics {
            epoch_current: Family::default(),
            epoch_last_settled: Family::default(),
            epoch_settlement_lag: Family::default(),
            epoch_phase: Family::default(),
            epoch_phase_seconds: Family::new_with_constructor(seconds),
            epoch_cutoff_to_terminal_seconds: Family::new_with_constructor(seconds),
            epoch_aborts: Family::default(),
            epoch_late_cutoff: Family::default(),
            intake_paused: Family::default(),
            submissions: Family::default(),
            submission_verify_seconds: seconds(),
            batch_envelopes: Family::new_with_constructor(counts),
            execution_attempts: Family::default(),
            execution_seconds: Family::new_with_constructor(seconds),
            receipt_check_failures: Family::default(),
            cosign_mismatch: Family::default(),
            chain_tx: Family::default(),
            chain_slot_lag: Gauge::default(),
            relay_balance_lamports: Gauge::default(),
            cranker_balance_lamports: Gauge::default(),
            settlement_deltas: Family::new_with_constructor(counts),
            settlement_txs: Family::new_with_constructor(counts),
            keys_ready_ahead: Family::default(),
            governance_pending: Family::default(),
            governance_due: Family::default(),
            equivocation_detected: Family::default(),
            market_state: Family::default(),
            store_commit_seconds: seconds(),
            store_queue_depth: Gauge::default(),
            store_errors: Counter::default(),
            snapshot_late: Family::default(),
            artifacts_lost: Family::default(),
            relay_refusals: Family::default(),
            bans: Family::default(),
            program_last_deploy_slot: Gauge::default(),
            backup_last_success: Family::default(),
        };
        let r = registry;
        r.register(
            "timescales_epoch_current",
            "Open or newest epoch",
            m.epoch_current.clone(),
        );
        r.register(
            "timescales_epoch_last_settled",
            "Last terminal epoch",
            m.epoch_last_settled.clone(),
        );
        r.register(
            "timescales_epoch_settlement_lag",
            "Epochs between the open epoch and the last terminal one",
            m.epoch_settlement_lag.clone(),
        );
        r.register(
            "timescales_epoch_phase",
            "Phase code by role",
            m.epoch_phase.clone(),
        );
        r.register(
            "timescales_epoch_phase_seconds",
            "Time spent in a phase",
            m.epoch_phase_seconds.clone(),
        );
        r.register(
            "timescales_epoch_cutoff_to_terminal_seconds",
            "Cutoff to settled or aborted",
            m.epoch_cutoff_to_terminal_seconds.clone(),
        );
        r.register(
            "timescales_epoch_aborts",
            "Aborted epochs by reason",
            m.epoch_aborts.clone(),
        );
        r.register(
            "timescales_epoch_late_cutoff",
            "Epochs closed after their cutoff by recovery",
            m.epoch_late_cutoff.clone(),
        );
        r.register(
            "timescales_intake_paused",
            "Intake paused (0/1) by reason",
            m.intake_paused.clone(),
        );
        r.register(
            "timescales_submissions",
            "Submissions by result",
            m.submissions.clone(),
        );
        r.register(
            "timescales_submission_verify_seconds",
            "Submission verification time",
            m.submission_verify_seconds.clone(),
        );
        r.register(
            "timescales_batch_envelopes",
            "Envelopes per closed batch by kind (internal only)",
            m.batch_envelopes.clone(),
        );
        r.register(
            "timescales_execution_attempts",
            "Enclave attempts by role and result",
            m.execution_attempts.clone(),
        );
        r.register(
            "timescales_execution_seconds",
            "Enclave call time",
            m.execution_seconds.clone(),
        );
        r.register(
            "timescales_receipt_check_failures",
            "Posted receipts that failed a node check",
            m.receipt_check_failures.clone(),
        );
        r.register(
            "timescales_cosign_mismatch",
            "Executors that returned different outcomes for one header",
            m.cosign_mismatch.clone(),
        );
        r.register(
            "timescales_chain_tx",
            "Chain operations by result",
            m.chain_tx.clone(),
        );
        r.register(
            "timescales_chain_slot_lag",
            "Slots between processed and confirmed",
            m.chain_slot_lag.clone(),
        );
        r.register(
            "timescales_relay_balance_lamports",
            "Relay key balance",
            m.relay_balance_lamports.clone(),
        );
        r.register(
            "timescales_cranker_balance_lamports",
            "Cranker key balance",
            m.cranker_balance_lamports.clone(),
        );
        r.register(
            "timescales_settlement_deltas",
            "Settlement leaves per epoch",
            m.settlement_deltas.clone(),
        );
        r.register(
            "timescales_settlement_txs",
            "Settlement transactions per epoch",
            m.settlement_txs.clone(),
        );
        r.register(
            "timescales_keys_ready_ahead",
            "Verified epoch-key bundles after the open epoch",
            m.keys_ready_ahead.clone(),
        );
        r.register(
            "timescales_governance_pending",
            "Pending governance change (eta slot) by kind",
            m.governance_pending.clone(),
        );
        r.register(
            "timescales_governance_due",
            "A due between-batches change blocks the next commit (0/1)",
            m.governance_due.clone(),
        );
        r.register(
            "timescales_equivocation_detected",
            "Batches committed with another root than ours",
            m.equivocation_detected.clone(),
        );
        r.register(
            "timescales_market_state",
            "Market state (1 for the current one)",
            m.market_state.clone(),
        );
        r.register(
            "timescales_store_commit_seconds",
            "SQLite group commit time",
            m.store_commit_seconds.clone(),
        );
        r.register(
            "timescales_store_queue_depth",
            "Queued store writes",
            m.store_queue_depth.clone(),
        );
        r.register(
            "timescales_store_errors",
            "Store write errors",
            m.store_errors.clone(),
        );
        r.register(
            "timescales_snapshot_late",
            "Balance snapshots taken after the beacon was revealed",
            m.snapshot_late.clone(),
        );
        r.register(
            "timescales_artifacts_lost",
            "Posted epochs whose artifacts nobody could provide",
            m.artifacts_lost.clone(),
        );
        r.register(
            "timescales_relay_refusals",
            "Relay-signed refusals by code",
            m.relay_refusals.clone(),
        );
        r.register(
            "timescales_bans",
            "Wallets banned by reason",
            m.bans.clone(),
        );
        r.register(
            "timescales_program_last_deploy_slot",
            "ProgramData last deploy slot",
            m.program_last_deploy_slot.clone(),
        );
        r.register(
            "timescales_backup_last_success_timestamp_seconds",
            "Last successful backup by kind",
            m.backup_last_success.clone(),
        );
        m
    }

    /// Families detached from any registry (tests and tools).
    pub fn unregistered() -> Self {
        Self::register(&mut Registry::default())
    }

    pub fn market(&self, m: &Address) -> Labels {
        labels(&[("market", &market_label(m))])
    }

    pub fn with(&self, m: &Address, extra: &[(&str, &str)]) -> Labels {
        let mut l = self.market(m);
        l.extend(labels(extra));
        l
    }

    pub fn observe_phase(&self, m: &Address, phase: &str, took: Duration) {
        self.epoch_phase_seconds
            .get_or_create(&self.with(m, &[("phase", phase)]))
            .observe(took.as_secs_f64());
    }

    pub fn submission(&self, m: &Address, result: &str) {
        self.submissions
            .get_or_create(&self.with(m, &[("result", result)]))
            .inc();
    }

    pub fn chain_op(&self, op: &str, result: &str) {
        self.chain_tx
            .get_or_create(&labels(&[("op", op), ("result", result)]))
            .inc();
    }

    pub fn attempt(&self, enclave: usize, role: &str, result: &str, took: Duration) {
        let enclave = enclave.to_string();
        let l = labels(&[("enclave", &enclave), ("role", role), ("result", result)]);
        self.execution_attempts.get_or_create(&l).inc();
        self.execution_seconds
            .get_or_create(&l)
            .observe(took.as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_never_shows_the_bytes() {
        let secret = [0xab_u8; 32];
        let shown = Redacted(&secret).to_string();
        assert!(!shown.contains(&hex::encode(secret)));
        assert!(shown.starts_with("<32 bytes "));
    }

    #[test]
    fn families_encode() {
        let mut registry = Registry::default();
        let m = NodeMetrics::register(&mut registry);
        m.submission(&[1; 32], "accepted");
        m.attempt(0, "poster", "ready", Duration::from_millis(5));
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &registry).unwrap();
        assert!(out.contains("timescales_submissions_total"));
        assert!(out.contains("timescales_execution_attempts_total"));
    }
}
