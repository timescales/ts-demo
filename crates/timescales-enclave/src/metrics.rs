//! The enclave metrics. Counters are registered without their
//! `_total` suffix, which the OpenMetrics encoder adds.

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;

type Labels = Vec<(String, String)>;

/// The enclave's metrics. Clones share the same series.
#[derive(Clone, Debug)]
pub struct EnclaveMetrics {
    pub execute_seconds: Histogram,
    pub share_rejects: Counter,
    posts: Family<Labels, Counter>,
    pub balance_check_failures: Counter,
    pub provenance_rejects: Counter,
    pub reveal_backstop: Counter,
    pub fee_payer_balance: Gauge,
    platform_info: Family<Labels, Gauge>,
}

impl Default for EnclaveMetrics {
    fn default() -> Self {
        Self {
            // 50 ms to about 100 s.
            execute_seconds: Histogram::new(exponential_buckets(0.05, 2.0, 12)),
            share_rejects: Counter::default(),
            posts: Family::default(),
            balance_check_failures: Counter::default(),
            provenance_rejects: Counter::default(),
            reveal_backstop: Counter::default(),
            fee_payer_balance: Gauge::default(),
            platform_info: Family::default(),
        }
    }
}

impl EnclaveMetrics {
    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "timescales_enclave_execute_seconds",
            "Time from an execute request to its ExecuteReady, KRC round included",
            self.execute_seconds.clone(),
        );
        registry.register(
            "timescales_enclave_share_rejects",
            "Released shares dropped because they did not open or verify against the commitments",
            self.share_rejects.clone(),
        );
        registry.register(
            "timescales_enclave_posts",
            "Publish calls by result: posted, cosigned, quorum_pending, outcome_mismatch, \
             quorum_invalid, failed",
            self.posts.clone(),
        );
        registry.register(
            "timescales_enclave_balance_check_failures",
            "Batches refused because the balance sheet disagrees with chain state",
            self.balance_check_failures.clone(),
        );
        registry.register(
            "timescales_enclave_provenance_rejects",
            "Envelopes whose grant or session signature failed the provenance check",
            self.provenance_rejects.clone(),
        );
        registry.register(
            "timescales_enclave_reveal_backstop",
            "Beacons this enclave revealed because nobody else did",
            self.reveal_backstop.clone(),
        );
        registry.register(
            "timescales_enclave_fee_payer_balance_lamports",
            "Lamports of the enclave's fee payer",
            self.fee_payer_balance.clone(),
        );
        registry.register(
            "timescales_enclave_platform_info",
            "The TEE platform and how quotes are generated; always 1",
            self.platform_info.clone(),
        );
    }

    pub fn post(&self, result: &str) {
        self.posts
            .get_or_create(&vec![("result".to_owned(), result.to_owned())])
            .inc();
    }

    pub fn posts(&self, result: &str) -> u64 {
        self.posts
            .get_or_create(&vec![("result".to_owned(), result.to_owned())])
            .get()
    }

    pub fn set_platform(&self, platform: &str, quote_generation: &str) {
        self.platform_info
            .get_or_create(&vec![
                ("platform".to_owned(), platform.to_owned()),
                ("quote_generation".to_owned(), quote_generation.to_owned()),
            ])
            .set(1);
    }
}
