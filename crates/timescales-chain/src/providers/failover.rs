//! URL failover shared by [`HttpRpc`](crate::HttpRpc) and
//! [`MinimalRpc`](crate::MinimalRpc): every call goes to the current URL,
//! and three consecutive transport, 429 or 5xx failures there move the
//! current URL to the next one.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::ProviderError;
use crate::RpcError;

/// Consecutive endpoint failures after which the next URL is used.
pub(crate) const FAILOVER_AFTER: u32 = 3;

const KINDS: [&str; 10] = [
    "transport",
    "http",
    "rate_limited",
    "timeout",
    "rpc",
    "min_context_slot",
    "decode",
    "disagree",
    "unavailable",
    "preflight",
];

/// Errors of one kind returned by one URL, the input of
/// `timescales_chain_rpc_errors_total{url_index, kind}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcErrorCount {
    pub url_index: usize,
    pub kind: &'static str,
    pub count: u64,
}

#[derive(Debug)]
pub(crate) struct Failover {
    urls: Vec<String>,
    current: AtomicUsize,
    /// Consecutive endpoint failures of the current URL.
    consecutive: AtomicU32,
    errors: Vec<[AtomicU64; KINDS.len()]>,
}

impl Failover {
    pub(crate) fn new(urls: Vec<String>) -> Result<Self, ProviderError> {
        if urls.is_empty() {
            return Err(ProviderError::NoProviders);
        }
        let errors = urls
            .iter()
            .map(|_| std::array::from_fn(|_| AtomicU64::new(0)))
            .collect();
        Ok(Self {
            urls,
            current: AtomicUsize::new(0),
            consecutive: AtomicU32::new(0),
            errors,
        })
    }

    /// The URL the next call goes to, with its index.
    pub(crate) fn current(&self) -> (usize, &str) {
        let i = self.current.load(Ordering::Acquire);
        (i, &self.urls[i])
    }

    /// Counts `result` of a call made to URL `index`. Only failures of the
    /// URL that is still current move it on, so calls that were in flight
    /// during a rotation do not rotate again.
    pub(crate) fn record<T>(&self, index: usize, result: &Result<T, RpcError>) {
        let err = match result {
            Ok(_) => {
                if self.current.load(Ordering::Acquire) == index {
                    self.consecutive.store(0, Ordering::Release);
                }
                return;
            }
            Err(e) => e,
        };
        if let Some(slot) = KINDS.iter().position(|k| *k == err.kind()) {
            self.errors[index][slot].fetch_add(1, Ordering::Relaxed);
        }
        if self.current.load(Ordering::Acquire) != index {
            return;
        }
        if !err.is_transport() {
            self.consecutive.store(0, Ordering::Release);
            return;
        }
        let failures = self.consecutive.fetch_add(1, Ordering::AcqRel) + 1;
        if failures >= FAILOVER_AFTER {
            let next = (index + 1) % self.urls.len();
            if self
                .current
                .compare_exchange(index, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.consecutive.store(0, Ordering::Release);
                tracing::warn!(from = index, to = next, "RPC failover");
            }
        }
    }

    /// Non-zero error counters, by URL index and kind.
    pub(crate) fn error_counts(&self) -> Vec<RpcErrorCount> {
        self.errors
            .iter()
            .enumerate()
            .flat_map(|(url_index, counters)| {
                counters
                    .iter()
                    .zip(KINDS)
                    .map(move |(c, kind)| RpcErrorCount {
                        url_index,
                        kind,
                        count: c.load(Ordering::Relaxed),
                    })
            })
            .filter(|c| c.count > 0)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failover(n: usize) -> Failover {
        Failover::new((0..n).map(|i| format!("http://rpc-{i}")).collect()).unwrap()
    }

    fn fail(f: &Failover, e: RpcError) {
        let (i, _) = f.current();
        f.record::<()>(i, &Err(e));
    }

    #[test]
    fn three_consecutive_endpoint_failures_rotate() {
        let f = failover(2);
        fail(&f, RpcError::Transport("refused".into()));
        fail(&f, RpcError::Http(503));
        assert_eq!(f.current().0, 0);
        fail(&f, RpcError::RateLimited);
        assert_eq!(f.current(), (1, "http://rpc-1"));
        for _ in 0..3 {
            fail(&f, RpcError::Timeout);
        }
        assert_eq!(f.current().0, 0, "rotation wraps around");
    }

    #[test]
    fn answers_reset_the_count() {
        let f = failover(2);
        fail(&f, RpcError::Timeout);
        fail(&f, RpcError::Timeout);
        f.record::<u8>(0, &Ok(1));
        fail(&f, RpcError::Timeout);
        fail(&f, RpcError::Timeout);
        assert_eq!(f.current().0, 0);
        // A JSON-RPC error is an answer: the endpoint works.
        fail(&f, RpcError::MinContextSlot { min_slot: 9 });
        fail(&f, RpcError::Timeout);
        fail(&f, RpcError::Http(404));
        fail(&f, RpcError::Timeout);
        assert_eq!(f.current().0, 0);
    }

    #[test]
    fn late_failures_of_a_previous_url_do_not_rotate_again() {
        let f = failover(3);
        for _ in 0..3 {
            fail(&f, RpcError::Timeout);
        }
        assert_eq!(f.current().0, 1);
        for _ in 0..5 {
            f.record::<()>(0, &Err(RpcError::Timeout));
        }
        assert_eq!(f.current().0, 1);
    }

    #[test]
    fn counts_errors_per_url_and_kind() {
        let f = failover(2);
        fail(&f, RpcError::Timeout);
        fail(&f, RpcError::Timeout);
        fail(&f, RpcError::Disagree);
        f.record::<()>(1, &Err(RpcError::Http(500)));
        assert_eq!(
            f.error_counts(),
            vec![
                RpcErrorCount {
                    url_index: 0,
                    kind: "timeout",
                    count: 2
                },
                RpcErrorCount {
                    url_index: 0,
                    kind: "disagree",
                    count: 1
                },
                RpcErrorCount {
                    url_index: 1,
                    kind: "http",
                    count: 1
                },
            ]
        );
    }

    #[test]
    fn no_urls_is_an_error() {
        assert_eq!(
            Failover::new(vec![]).unwrap_err(),
            ProviderError::NoProviders
        );
    }
}
