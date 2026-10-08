//! Per-caller GCRA with a bounded number of tracked callers (b, F#4).
//!
//! Any key may send a challenge or release envelope (callers are
//! authorized by on-chain registration, which is checked after the rate
//! limit), so the table of callers must not grow with the number of keys
//! an attacker generates. Callers whose bucket is full again are dropped
//! when the table fills up. If it is still full, a caller it does not know
//! is refused until room frees up, while known callers keep their own
//! buckets.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Callers tracked at most.
pub(crate) const MAX_TRACKED_CALLERS: usize = 4096;

#[derive(Debug)]
pub(crate) struct CallerLimiter {
    /// Time between two cells at the sustained rate.
    emission: Duration,
    /// How far ahead of now the theoretical arrival time may run: the
    /// burst beyond the first cell.
    tolerance: Duration,
    capacity: usize,
    /// Theoretical arrival time per caller.
    tat: Mutex<HashMap<[u8; 32], Instant>>,
}

impl CallerLimiter {
    pub(crate) fn new(rps: u32, burst: u32, capacity: usize) -> Self {
        let emission = Duration::from_secs(1) / rps.max(1);
        Self {
            emission,
            tolerance: emission * burst.max(1).saturating_sub(1),
            capacity: capacity.max(1),
            tat: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `caller` may make a request at `now`. A request that is
    /// allowed uses up one cell.
    pub(crate) fn check_at(&self, caller: &[u8; 32], now: Instant) -> bool {
        let mut tat = self.tat.lock();
        if !tat.contains_key(caller) && tat.len() >= self.capacity {
            tat.retain(|_, t| *t > now);
            if tat.len() >= self.capacity {
                return false;
            }
        }
        let current = tat.get(caller).copied().unwrap_or(now).max(now);
        if current.duration_since(now) > self.tolerance {
            return false;
        }
        tat.insert(*caller, current + self.emission);
        true
    }

    pub(crate) fn check(&self, caller: &[u8; 32]) -> bool {
        self.check_at(caller, Instant::now())
    }

    /// Drops callers whose bucket is full again.
    pub(crate) fn prune(&self) {
        let now = Instant::now();
        self.tat.lock().retain(|_, t| *t > now);
    }

    pub(crate) fn tracked(&self) -> usize {
        self.tat.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_then_the_sustained_rate() {
        let l = CallerLimiter::new(10, 3, 16);
        let t0 = Instant::now();
        let k = [1; 32];
        assert!(l.check_at(&k, t0));
        assert!(l.check_at(&k, t0));
        assert!(l.check_at(&k, t0));
        assert!(!l.check_at(&k, t0));
        // One cell comes back every 100 ms.
        assert!(!l.check_at(&k, t0 + Duration::from_millis(50)));
        assert!(l.check_at(&k, t0 + Duration::from_millis(101)));
        // Another caller has its own bucket.
        assert!(l.check_at(&[2; 32], t0));
    }

    #[test]
    fn the_table_never_grows_past_its_capacity() {
        let l = CallerLimiter::new(1, 1, 8);
        let t0 = Instant::now();
        for i in 0..8u8 {
            assert!(l.check_at(&[i; 32], t0));
        }
        // Full of callers that are still limited: a stranger is refused,
        // a known caller keeps its own bucket.
        assert!(!l.check_at(&[100; 32], t0));
        assert!(!l.check_at(&[0; 32], t0));
        assert!(l.check_at(&[0; 32], t0 + Duration::from_millis(1001)));
        assert_eq!(l.tracked(), 8);
        // Once buckets refill, strangers get room again.
        let later = t0 + Duration::from_secs(5);
        assert!(l.check_at(&[101; 32], later));
        assert!(l.tracked() <= 8);
    }
}
