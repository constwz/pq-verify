use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use crate::Result;

pub(crate) struct Latency {
    pub(crate) samples: Vec<u128>,
    pub(crate) mean_ns: f64,
    pub(crate) p50_ns: u128,
    pub(crate) p95_ns: u128,
    pub(crate) p99_ns: u128,
}

pub(crate) struct Throughput {
    pub(crate) calls: u64,
    pub(crate) elapsed: Duration,
}

// SplitMix64 is only for repeatable traversal/job ordering, never key material.
pub(crate) struct OrderRng(pub(crate) u64);

impl OrderRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    pub(crate) fn shuffle<T>(&mut self, values: &mut [T]) {
        for i in (1..values.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            values.swap(i, j);
        }
    }
}

pub(crate) fn throughput(
    count: usize,
    duration: Duration,
    mut verify_expected: impl FnMut(usize) -> bool,
) -> Result<Throughput> {
    let start = Instant::now();
    let mut calls = 0;
    let mut cursor = 0;
    loop {
        // Amortize the deadline clock; every actual call and overshoot are counted.
        for _ in 0..64 {
            if !black_box(verify_expected(cursor)) {
                return Err("unexpected verification result".into());
            }
            calls += 1;
            cursor += 1;
            if cursor == count {
                cursor = 0;
            }
        }
        let elapsed = start.elapsed();
        if elapsed >= duration {
            return Ok(Throughput { calls, elapsed });
        }
    }
}

/// Collects up to `samples` observations, stopping early once `budget` (if any)
/// has elapsed so slow parameter sets do not dominate a run's wall time.
pub(crate) fn latency(
    count: usize,
    samples: usize,
    budget: Option<Duration>,
    mut verify: impl FnMut(usize) -> bool,
    expected: bool,
) -> Result<Latency> {
    let mut times = Vec::with_capacity(samples);
    let mut cursor = 0;
    let begin = Instant::now();
    for _ in 0..samples {
        if !times.is_empty() && budget.is_some_and(|budget| begin.elapsed() >= budget) {
            break;
        }
        let start = Instant::now();
        let result = black_box(verify(cursor));
        let elapsed = start.elapsed().as_nanos();
        if result != expected {
            return Err("unexpected verification result".into());
        }
        times.push(elapsed);
        cursor += 1;
        if cursor == count {
            cursor = 0;
        }
    }
    Ok(summarize(times))
}

fn summarize(samples: Vec<u128>) -> Latency {
    let mean_ns = samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64;
    let mut sorted = samples.clone();
    sorted.sort_unstable();
    // Nearest-rank quantiles of individual calls, not quantiles of batch means.
    let quantile = |percent: usize| sorted[(sorted.len() * percent).div_ceil(100) - 1];
    Latency { p50_ns: quantile(50), p95_ns: quantile(95), p99_ns: quantile(99), mean_ns, samples }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_use_individual_calls() {
        let stats = summarize((1..=100).rev().collect());
        assert_eq!((stats.p50_ns, stats.p95_ns, stats.p99_ns), (50, 95, 99));
        assert_eq!(stats.mean_ns, 50.5);
        assert_eq!(summarize(vec![7]).p99_ns, 7);
    }

    #[test]
    fn traversal_is_repeatable_and_visits_every_sample() {
        let mut a: Vec<_> = (0..100).collect();
        let mut b = a.clone();
        OrderRng(42).shuffle(&mut a);
        OrderRng(42).shuffle(&mut b);
        assert_eq!(a, b);
        a.sort_unstable();
        assert_eq!(a, (0..100).collect::<Vec<_>>());
    }

    #[test]
    fn failed_verification_aborts_both_measurements() {
        assert!(throughput(1, Duration::ZERO, |_| false).is_err());
        assert!(latency(1, 1, None, |_| false, true).is_err());
        assert!(latency(1, 1, None, |_| false, false).is_ok());
    }

    #[test]
    fn latency_budget_caps_samples_but_keeps_at_least_one() -> Result<()> {
        assert_eq!(latency(3, 100, Some(Duration::ZERO), |_| true, true)?.samples.len(), 1);
        assert_eq!(latency(3, 100, None, |_| true, true)?.samples.len(), 100);
        assert_eq!(
            latency(3, 100, Some(Duration::from_secs(60)), |_| true, true)?.samples.len(),
            100
        );
        Ok(())
    }
}
