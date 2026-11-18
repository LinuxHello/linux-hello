//! Tests of the latency benchmark's arithmetic (`benches/latency/stats.rs`), run under
//! `make test`: a bench target with its own `main` does not run unit tests.

#[path = "../benches/latency/stats.rs"]
mod stats;

use stats::{exit_code, percentile, record, summarise};
use std::time::Duration;

/// `n` milliseconds.
fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn percentile_of_known_values() {
    let hundred: Vec<Duration> = (1..=100).map(ms).collect();
    assert_eq!(percentile(&hundred, 50), Some(ms(50)));
    assert_eq!(percentile(&hundred, 99), Some(ms(99)));
    assert_eq!(percentile(&hundred, 100), Some(ms(100)));
    let one = [ms(7)];
    assert_eq!(percentile(&one, 50), Some(ms(7)));
    assert_eq!(percentile(&one, 99), Some(ms(7)));
    assert_eq!(percentile(&one, 100), Some(ms(7)));
    assert_eq!(percentile(&[], 99), None);
    assert_eq!(summarise(&mut []), None);
    assert_eq!(percentile(&hundred, 0), None);
    assert_eq!(percentile(&hundred, 101), None);
}

#[test]
fn a_summary_sorts_its_samples() {
    let mut samples = vec![ms(3), ms(1), ms(2)];
    let summary = summarise(&mut samples).unwrap();
    assert_eq!((summary.n, summary.p50, summary.max), (3, ms(2), ms(3)));
}

#[test]
fn the_budget_is_enforced_only_when_asked() {
    assert_eq!(exit_code(&[ms(7)], false), 0);
    assert_eq!(exit_code(&[ms(7)], true), 1);
    assert_eq!(exit_code(&[Duration::from_micros(4900)], false), 0);
    assert_eq!(exit_code(&[Duration::from_micros(4900)], true), 0);
    assert_eq!(exit_code(&[ms(1), ms(7)], true), 1, "any situation counts");
    assert_eq!(
        exit_code(&[ms(5)], true),
        0,
        "exactly the budget is within it"
    );
}

#[test]
fn a_failed_call_stops_the_run() {
    let mut samples = Vec::new();
    assert_eq!(record(&mut samples, Ok(ms(1))), Ok(()));
    assert_eq!(
        record(&mut samples, Err("no reply".into())),
        Err("no reply".into())
    );
    assert_eq!(samples, vec![ms(1)], "the failure is not a sample");
}
