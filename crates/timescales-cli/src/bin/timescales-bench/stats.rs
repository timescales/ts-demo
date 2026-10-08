use std::time::Duration;

/// Nearest-rank percentile over a sample (`q` in 0..=100).
pub(crate) fn percentile(xs: &[Duration], q: u32) -> Duration {
    if xs.is_empty() {
        return Duration::ZERO;
    }
    let mut v = xs.to_vec();
    v.sort_unstable();
    let rank = (u64::from(q) * v.len() as u64).div_ceil(100).max(1) as usize;
    v[rank.min(v.len()) - 1]
}

pub(crate) fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank() {
        let xs: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
        assert_eq!(percentile(&xs, 50), Duration::from_millis(50));
        assert_eq!(percentile(&xs, 99), Duration::from_millis(99));
        assert_eq!(percentile(&xs[..3], 99), Duration::from_millis(3));
    }
}
