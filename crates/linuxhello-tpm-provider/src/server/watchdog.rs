//! The provider's watchdog: how it tells systemd it is alive, and how it notices that it is not.
//!
//! systemd gives a service a datagram socket in `NOTIFY_SOCKET` and, when the unit sets
//! `WatchdogSec=`, the interval in `WATCHDOG_USEC`; the service must send `WATCHDOG=1` within that
//! interval or systemd stops it and, with `Restart=on-failure`, starts it again. The provider is
//! one thread that takes one request at a time, so a TPM call that never returns would leave the
//! Agent without PIN checks until someone restarted it by hand (review finding R-29, #371). A
//! second thread pings, and stops pinging when the request thread has been inside one request for
//! longer than [`STUCK_AFTER`]: an idle provider, which is only waiting for a connection, keeps
//! pinging. Nothing here needs a library: the protocol is one line of text in one datagram.

use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The message that tells the service manager the service is still working.
pub const WATCHDOG: &str = "WATCHDOG=1";

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

/// Where notifications go: a path, or an abstract name (written `@name` in `NOTIFY_SOCKET`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    /// A socket file.
    Path(String),
    /// An abstract socket, without its leading `@`.
    Abstract(String),
}

/// A connection to the service manager's notification socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notifier {
    /// The socket to send to.
    target: Target,
}

impl Notifier {
    /// The notifier named by `NOTIFY_SOCKET`, or none when the provider is not started by a service
    /// manager that wants notifications.
    pub fn from_env() -> Option<Self> {
        Self::parse(&std::env::var("NOTIFY_SOCKET").ok()?)
    }

    /// The notifier for the text of a `NOTIFY_SOCKET` value: an absolute path or `@name`; anything
    /// else is no socket (`notify_socket_names_are_a_path_or_an_abstract_name`).
    pub fn parse(value: &str) -> Option<Self> {
        let target = if let Some(name) = value.strip_prefix('@') {
            (!name.is_empty()).then(|| Target::Abstract(name.to_string()))?
        } else if value.starts_with('/') {
            Target::Path(value.to_string())
        } else {
            return None;
        };
        Some(Self { target })
    }

    /// Sends one message in one datagram.
    ///
    /// # Errors
    ///
    /// The error of creating the socket or sending; the caller logs it and goes on.
    pub fn send(&self, message: &str) -> io::Result<()> {
        let socket = UnixDatagram::unbound()?;
        match &self.target {
            Target::Path(path) => socket.send_to(message.as_bytes(), path)?,
            Target::Abstract(name) => {
                let address = SocketAddr::from_abstract_name(name.as_bytes())?;
                socket.send_to_addr(message.as_bytes(), &address)?
            }
        };
        Ok(())
    }
}

/// How often to ping: half of `WATCHDOG_USEC`, as the service manager recommends, or none when the
/// unit has no watchdog or the value is not a positive number of microseconds. `WATCHDOG_PID`,
/// when set, must be this process (`the_ping_interval_is_half_the_watchdog_time`).
pub fn interval() -> Option<Duration> {
    if let Ok(pid) = std::env::var("WATCHDOG_PID") {
        if pid.parse::<u32>().ok()? != std::process::id() {
            return None;
        }
    }
    interval_from(&std::env::var("WATCHDOG_USEC").ok()?)
}

/// Half of `usec` microseconds, for a positive whole number.
pub fn interval_from(usec: &str) -> Option<Duration> {
    let usec: u64 = usec.trim().parse().ok()?;
    (usec >= 2).then(|| Duration::from_micros(usec / 2))
}

/// Whether to send a ping now: unless the request thread is stuck.
pub fn should_ping(busy: &Busy) -> bool {
    !busy.stuck_for(STUCK_AFTER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ping_interval_is_half_the_watchdog_time() {
        assert_eq!(interval_from("60000000"), Some(Duration::from_secs(30)));
        assert_eq!(interval_from(" 2 "), Some(Duration::from_micros(1)));
        for bad in ["", "0", "1", "-5", "abc", "1.5"] {
            assert_eq!(interval_from(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn notify_socket_names_are_a_path_or_an_abstract_name() {
        assert!(Notifier::parse("/run/systemd/notify").is_some());
        assert!(Notifier::parse("@abstract").is_some());
        for bad in ["", "@", "relative/path", "notify"] {
            assert_eq!(Notifier::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_ping_is_one_datagram_to_the_notify_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let socket = UnixDatagram::bind(&path).unwrap();
        let notifier = Notifier::parse(path.to_str().unwrap()).unwrap();
        notifier.send(WATCHDOG).unwrap();
        let mut buffer = [0u8; 64];
        let size = socket.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], b"WATCHDOG=1");
    }

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
