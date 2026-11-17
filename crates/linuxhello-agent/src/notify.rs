//! The service manager's notification socket: how the Agent tells systemd it is alive.
//!
//! systemd gives a service a datagram socket in `NOTIFY_SOCKET` and, when the unit sets
//! `WatchdogSec=`, the interval in `WATCHDOG_USEC`. The service must send `WATCHDOG=1` within that
//! interval or systemd restarts it. The Agent sends it only after a call over the bus to its own
//! name has been answered, so a hung bus loop stops the pings and the unit is restarted
//! (`a_watchdog_ping_is_one_datagram_to_the_notify_socket`). It needs no library: the protocol is
//! one line of text in one datagram.
//!
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::time::Duration;

/// The message that tells the service manager the service is still working.
pub const WATCHDOG: &str = "WATCHDOG=1";

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
    /// The notifier named by `NOTIFY_SOCKET`, or none when the Agent is not started by a service
    /// manager that wants notifications.
    pub fn from_env() -> Option<Self> {
        Self::parse(&std::env::var("NOTIFY_SOCKET").ok()?)
    }

    /// The notifier for the text of a `NOTIFY_SOCKET` value: an absolute path or `@name`.
    /// Anything else is no socket (`notify_socket_names_are_a_path_or_an_abstract_name`).
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

    /// Tells the service manager the Agent is alive.
    ///
    /// # Errors
    ///
    /// As [`Notifier::send`].
    pub fn watchdog(&self) -> io::Result<()> {
        self.send(WATCHDOG)
    }
}

/// How often to ping: half of `WATCHDOG_USEC`, as the service manager recommends, or none when
/// the unit has no watchdog or the value is not a positive number of microseconds
/// (`the_ping_interval_is_half_the_watchdog_time`). `WATCHDOG_PID`, when set, must be this process.
pub fn watchdog_interval() -> Option<Duration> {
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

#[cfg(test)]
mod tests;
