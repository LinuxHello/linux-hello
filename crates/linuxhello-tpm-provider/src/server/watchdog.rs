//! The provider's watchdog: how it tells systemd it is alive, and how it notices that it is not.
//!
//! systemd gives a service a datagram socket in `NOTIFY_SOCKET` and, when the unit sets
//! `WatchdogSec=`, the interval in `WATCHDOG_USEC`; the service must send `WATCHDOG=1` within that
//! interval or systemd stops it and, with `Restart=on-failure`, starts it again. The provider is
//! one thread that takes one request at a time, so a TPM call that never returns would leave the
//! Agent without PIN checks until someone restarted it by hand (review finding R-29, #371). A
//! second thread pings, and stops pinging when the request thread has been inside one request for
//! longer than [`STUCK_AFTER`]: an idle provider, which is only waiting for a connection, keeps
//! pinging. The datagram itself is sent by `linuxhello_dbus::notify`, which the Agent uses too.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long one request may take before the provider counts as stuck. The longest honest request
/// is making a key on a slow chip, well below this; the unit's `WatchdogSec` is 60 s.
pub const STUCK_AFTER: Duration = Duration::from_secs(45);

/// Whether the request thread is inside a request, and since when.
#[derive(Debug)]
pub struct Busy {
    /// When this record was made, the origin of the times below.
    origin: Instant,
    /// Milliseconds since `origin` plus one at which the current request began; zero when none runs.
    since: AtomicU64,
}

impl Default for Busy {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            since: AtomicU64::new(0),
        }
    }
}

impl Busy {
    /// Notes that a request begins.
    pub fn begin(&self) {
        let millis = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        self.since.store(millis.saturating_add(1), Ordering::SeqCst);
    }

    /// Notes that the request is over.
    pub fn end(&self) {
        self.since.store(0, Ordering::SeqCst);
    }

    /// Whether a request has been running for longer than `limit`: the provider is stuck.
    pub fn stuck_for(&self, limit: Duration) -> bool {
        match self.since.load(Ordering::SeqCst) {
            0 => false,
            since => {
                let now = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
                now.saturating_sub(since - 1) > u64::try_from(limit.as_millis()).unwrap_or(u64::MAX)
            }
        }
    }
}

/// Whether to send a ping now: unless the request thread is stuck.
pub fn should_ping(busy: &Busy) -> bool {
    !busy.stuck_for(STUCK_AFTER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_provider_keeps_pinging() {
        // Waiting for a connection is not being stuck: nothing is running.
        let busy = Busy::default();
        assert!(should_ping(&busy));
        assert!(!busy.stuck_for(Duration::ZERO));
    }

    #[test]
    fn a_request_that_never_returns_stops_the_pings() {
        // R-29, #371: a TPM call that hangs must end in a restart, not in an Agent that waits for
        // ever. The provider counts as stuck once a request has run for longer than the limit.
        let busy = Busy::default();
        busy.begin();
        assert!(!busy.stuck_for(Duration::from_millis(200)), "just started");
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            busy.stuck_for(Duration::from_millis(20)),
            "past a short limit"
        );
        assert!(
            !busy.stuck_for(Duration::from_secs(5)),
            "not past a long one"
        );
        busy.end();
        assert!(
            !busy.stuck_for(Duration::ZERO),
            "a request that ended is not stuck"
        );
    }
}
