//! The KRC and dealer metrics. Counters are registered without
//! their `_total` suffix, which the OpenMetrics encoder adds.

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

type Labels = Vec<(String, String)>;

fn label(key: &str, value: &str) -> Labels {
    vec![(key.to_owned(), value.to_owned())]
}

/// A member's metrics. Clones share the same series.
#[derive(Clone, Debug, Default)]
pub struct MemberMetrics {
    pub challenges: Counter,
    releases: Family<Labels, Counter>,
    pub shares_held: Gauge,
    pub nonces_outstanding: Gauge,
    pub second_announcement: Counter,
    pub kek_generation: Gauge,
    pub collateral_expiry: Gauge,
}

impl MemberMetrics {
    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "timescales_krc_challenges",
            "Challenge requests received",
            self.challenges.clone(),
        );
        registry.register(
            "timescales_krc_releases",
            "Release requests by result: released, or the refusal code name",
            self.releases.clone(),
        );
        registry.register(
            "timescales_krc_shares_held",
            "Epoch shares this member holds",
            self.shares_held.clone(),
        );
        registry.register(
            "timescales_krc_nonces_outstanding",
            "Challenge nonces issued and not yet presented or expired",
            self.nonces_outstanding.clone(),
        );
        registry.register(
            "timescales_krc_second_announcement",
            "Deliveries naming a second announcement for an epoch (faulty or compromised dealer)",
            self.second_announcement.clone(),
        );
        registry.register(
            "timescales_krc_kek_generation",
            "Current generation of the at-rest key",
            self.kek_generation.clone(),
        );
        registry.register(
            "timescales_krc_collateral_expiry_timestamp",
            "When the installed Intel TDX collateral expires (Unix seconds; 0 without TDX)",
            self.collateral_expiry.clone(),
        );
    }

    pub fn release(&self, result: &str) {
        self.releases.get_or_create(&label("result", result)).inc();
    }

    pub fn releases(&self, result: &str) -> u64 {
        self.releases.get_or_create(&label("result", result)).get()
    }
}

/// The dealer's metrics. Clones share the same series.
#[derive(Clone, Debug, Default)]
pub struct DealerMetrics {
    dealt: Family<Labels, Counter>,
    pub lookahead_epochs: Gauge,
    pub pending_deliveries: Gauge,
    pub recoveries: Counter,
    pub committee_mismatch: Gauge,
}

impl DealerMetrics {
    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "timescales_dealer_dealt",
            "Dealing attempts by result",
            self.dealt.clone(),
        );
        registry.register(
            "timescales_dealer_lookahead_epochs",
            "Epochs after the last committed one whose bundle reached the node",
            self.lookahead_epochs.clone(),
        );
        registry.register(
            "timescales_dealer_pending_deliveries",
            "Recorded dealings whose bundle has not reached the node",
            self.pending_deliveries.clone(),
        );
        registry.register(
            "timescales_dealer_recoveries",
            "Recoveries that adopted announcements from members",
            self.recoveries.clone(),
        );
        registry.register(
            "timescales_dealer_committee_mismatch",
            "1 while a configured committee differs from Market.committee_digest",
            self.committee_mismatch.clone(),
        );
    }

    pub fn dealt(&self, result: &str) {
        self.dealt.get_or_create(&label("result", result)).inc();
    }

    pub fn dealt_count(&self, result: &str) -> u64 {
        self.dealt.get_or_create(&label("result", result)).get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(register: impl FnOnce(&mut Registry)) -> String {
        let mut registry = Registry::default();
        register(&mut registry);
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &registry).unwrap();
        out
    }

    #[test]
    fn member_series_carry_the_d10_names() {
        let m = MemberMetrics::default();
        m.challenges.inc();
        m.second_announcement.inc();
        m.release("released");
        m.release("NotFinal");
        let text = encoded(|r| m.register(r));
        for name in [
            "timescales_krc_challenges_total 1",
            "timescales_krc_releases_total{result=\"released\"} 1",
            "timescales_krc_releases_total{result=\"NotFinal\"} 1",
            "timescales_krc_shares_held ",
            "timescales_krc_nonces_outstanding ",
            "timescales_krc_second_announcement_total 1",
            "timescales_krc_kek_generation ",
            "timescales_krc_collateral_expiry_timestamp ",
        ] {
            assert!(text.contains(name), "{name} missing in\n{text}");
        }
    }

    #[test]
    fn dealer_series_carry_the_d10_names() {
        let d = DealerMetrics::default();
        d.dealt("dealt");
        d.recoveries.inc();
        let text = encoded(|r| d.register(r));
        for name in [
            "timescales_dealer_dealt_total{result=\"dealt\"} 1",
            "timescales_dealer_lookahead_epochs ",
            "timescales_dealer_pending_deliveries ",
            "timescales_dealer_recoveries_total 1",
            "timescales_dealer_committee_mismatch ",
        ] {
            assert!(text.contains(name), "{name} missing in\n{text}");
        }
    }
}
