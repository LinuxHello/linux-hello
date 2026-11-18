//! The arithmetic of the latency benchmark: percentiles of the timed calls and the rule that
//! turns them into an exit code. It has no bus and no clock, so that `tests/bench_stats.rs` can
//! test it under `make test`; the benchmark itself runs only under `make bench`.

use std::time::Duration;

/// The budget of scenario L1 (Arc42 section 10): the slowest 1 call in 100 must not take longer.
pub const BUDGET: Duration = Duration::from_millis(5);

/// What the timed calls of one situation came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// How many calls were timed.
    pub n: usize,
    /// The median.
    pub p50: Duration,
    /// The 99th percentile.
    pub p99: Duration,
    /// The slowest call.
    pub max: Duration,
}

/// The `p`-th percentile (1 to 100) of `sorted`, which is sorted ascending: the value at index
/// `ceil(n * p / 100) - 1`. `None` for an empty list or a `p` outside 1 to 100, never zero.
pub fn percentile(sorted: &[Duration], p: usize) -> Option<Duration> {
    if sorted.is_empty() || !(1..=100).contains(&p) {
        return None;
    }
    let index = (sorted.len() * p).div_ceil(100) - 1;
    sorted.get(index).copied()
}

/// Sorts `samples` and summarises them; `None` when there are none.
pub fn summarise(samples: &mut [Duration]) -> Option<Summary> {
    samples.sort_unstable();
    Some(Summary {
        n: samples.len(),
        p50: percentile(samples, 50)?,
        p99: percentile(samples, 99)?,
        max: percentile(samples, 100)?,
    })
}

/// The exit code of the benchmark: 0, unless the budget is enforced (`LH_ENFORCE_BUDGET=1`) and
/// the p99 of any situation is above [`BUDGET`].
pub fn exit_code(p99s: &[Duration], enforce: bool) -> u8 {
    u8::from(enforce && p99s.iter().any(|p99| *p99 > BUDGET))
}

/// Adds the outcome of one call to `samples`. A failed call is an error that ends the run; it is
/// never counted as a fast call.
///
/// # Errors
///
/// The text of the failed call.
pub fn record(
    samples: &mut Vec<Duration>,
    outcome: Result<Duration, String>,
) -> Result<(), String> {
    samples.push(outcome?);
    Ok(())
}
