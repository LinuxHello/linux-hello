//! The PIN socket: how a PIN reaches the Agent without passing through the bus daemon
//! ([ADR-0021](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0021-pin-transport.md),
//! decision 1).
//!
//! The Agent owns a stream socket in a directory only its own user can change. A client sends
//! one frame, the PIN, and nothing else: two bytes of length (big endian, 1 to
//! [`MAX_PIN_BYTES`]), the PIN, then it closes its writing side. The Agent answers with one byte,
//! [`REPLY_ACCEPTED`] or [`REPLY_REFUSED`]; every refusal is the same byte, so a refusal does
//! not say which rule failed.
//!
//! The Agent decides who may send a PIN from the peer credentials of the connection
//! (`SO_PEERCRED`: uid and pid, set by the kernel), never from the frame. A PIN is accepted only
//! from the process that made the control call on the bus, and only for the subject user that
//! call named: the control call ([`PinSocket::expect`]) records the caller's uid and pid and the
//! subject, and the socket takes the PIN from a connection with that uid and pid, once, within
//! [`EXPECTATION_TTL`]. The control call itself applies the rule of the prompts (root or the
//! subject may ask), so a PIN for a user can only come from that user or root. A process that
//! made no control call, or another user's process, is refused and does not use up anyone's
//! expectation.
//!
//! Not here yet: the control call on the bus, the PIN verifier that consumes a [`Submission`],
//! the AppArmor rule and the unit settings for the socket, and the client in the PAM module.
//! Nothing starts this socket in the Agent until the PIN path exists. Memory hygiene beyond
//! [`Zeroizing`] is #189: the buffers and the missing `Debug` are tested here; core dumps are off in the unit (`LimitCORE=0`).
//!
//! Security property: `pin_is_never_a_dbus_message_body` (P-31) and the tests of this module.
//!
//! C4 component: `pinSocket` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// The longest PIN a frame may carry, in bytes. A longer frame is refused unread.
pub const MAX_PIN_BYTES: usize = 256;

/// The reply to a PIN that was handed to the Agent.
pub const REPLY_ACCEPTED: u8 = 0;

/// The reply to anything else, whatever the reason.
pub const REPLY_REFUSED: u8 = 1;

/// How long a control call stays valid before its PIN must arrive.
pub const EXPECTATION_TTL: Duration = Duration::from_secs(30);

/// How many control calls may wait for their PIN at once.
const MAX_EXPECTATIONS: usize = 64;

/// How long the Agent waits for a client to send its frame and close its writing side.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);

/// A process as the kernel reports it for a connection or the bus reports it for a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Process {
    /// The user id.
    pub uid: u32,
    /// The process id.
    pub pid: u32,
}

/// A PIN that arrived, and who it is for. It has no `Debug` so that no log line can print it.
pub struct Submission {
    /// The user the control call named.
    pub subject: u32,
    /// The process that sent it.
    pub from: Process,
    /// The PIN as sent. It is overwritten when the value is dropped.
    pub pin: Zeroizing<Vec<u8>>,
}

/// A control call that waits for its PIN.
struct Expectation {
    /// The process that made the control call.
    caller: Process,
    /// The user whose PIN it is.
    subject: u32,
    /// When it was made.
    made: Instant,
}

/// The control calls waiting for a PIN.
#[derive(Default)]
struct Expectations {
    /// The waiting calls, at most one per process.
    waiting: Vec<Expectation>,
}

impl Expectations {
    /// Drops what has expired.
    fn expire(&mut self, now: Instant, ttl: Duration) {
        self.waiting
            .retain(|e| now.saturating_duration_since(e.made) <= ttl);
    }
}

/// The control-call table is full: too many callers wait for a PIN.
#[derive(Debug, PartialEq, Eq)]
pub struct TooMany;

/// The PIN socket of the Agent.
pub struct PinSocket {
    /// The listening socket.
    listener: UnixListener,
    /// The control calls waiting for their PIN.
    expectations: Mutex<Expectations>,
    /// How long a control call stays valid.
    ttl: Duration,
}

impl PinSocket {
    /// Binds the socket at `path`. The directory that holds it must be owned by `owner_uid` and
    /// writable by nobody else, so no other user can replace the socket; a stale socket file left
    /// by an earlier run is removed, and anything else at `path` is refused. The socket itself
    /// is connectable by every user: who may send a PIN is decided by the peer credentials.
    ///
    /// # Errors
    ///
    /// An error when the directory cannot be examined or is not safe, when `path` holds
    /// something that is not a socket, or when binding fails.
    pub fn bind(path: &Path, owner_uid: u32) -> io::Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "no directory"))?;
        let dir = std::fs::symlink_metadata(parent)?;
        if !dir.is_dir() || dir.uid() != owner_uid || dir.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "the directory of the PIN socket is not private to the Agent",
            ));
        }
        match std::fs::symlink_metadata(path) {
            Ok(old) if old.file_type().is_socket() && old.uid() == owner_uid => {
                std::fs::remove_file(path)?;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    "something that is not the Agent's socket is in the way",
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
        Ok(Self {
            listener,
            expectations: Mutex::new(Expectations::default()),
            ttl: EXPECTATION_TTL,
        })
    }

    /// The same socket with another lifetime for control calls, for tests.
    #[must_use]
    pub fn with_ttl(self, ttl: Duration) -> Self {
        Self { ttl, ..self }
    }

    /// Records a control call: `caller` asked to send the PIN of `subject`. The caller is the
    /// peer the bus reported; the rule that root or the subject may ask is the control call's.
    /// A second call by the same process replaces the first.
    ///
    /// # Errors
    ///
    /// [`TooMany`] when 64 callers already wait.
    pub fn expect(&self, caller: Process, subject: u32) -> Result<(), TooMany> {
        let mut table = self
            .expectations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        table.expire(now, self.ttl);
        table.waiting.retain(|e| e.caller != caller);
        if table.waiting.len() >= MAX_EXPECTATIONS {
            return Err(TooMany);
        }
        table.waiting.push(Expectation {
            caller,
            subject,
            made: now,
        });
        Ok(())
    }

    /// Takes the control call of `caller`, if one is waiting and has not expired.
    fn take(&self, caller: Process) -> Option<u32> {
        let mut table = self
            .expectations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        table.expire(Instant::now(), self.ttl);
        let at = table.waiting.iter().position(|e| e.caller == caller)?;
        Some(table.waiting.remove(at).subject)
    }

    /// Accepts one connection and handles it: reads the peer credentials, takes the caller's
    /// control call, reads the frame, hands a PIN to `sink` and replies. It returns once the
    /// connection is done; the caller loops. A client that is slow or silent is dropped after
    /// two seconds.
    ///
    /// # Errors
    ///
    /// An error of accepting the connection. A refused client is not an error.
    pub fn serve_one(&self, sink: &mut dyn FnMut(Submission)) -> io::Result<()> {
        let (stream, _) = self.listener.accept()?;
        self.handle(stream, sink);
        Ok(())
    }

    /// Handles one connection and replies; every failure is the same refusal.
    fn handle(&self, mut stream: UnixStream, sink: &mut dyn FnMut(Submission)) {
        let accepted = self.receive(&mut stream, sink);
        let reply = if accepted {
            REPLY_ACCEPTED
        } else {
            REPLY_REFUSED
        };
        drop(stream.write_all(&[reply]));
    }

    /// Whether the PIN on `stream` was handed to `sink`.
    fn receive(&self, stream: &mut UnixStream, sink: &mut dyn FnMut(Submission)) -> bool {
        let Some(from) = peer_of(stream) else {
            return false;
        };
        // Identity first: a connection without a control call of its own touches nothing.
        let Some(subject) = self.take(from) else {
            return false;
        };
        if stream.set_read_timeout(Some(CLIENT_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(CLIENT_TIMEOUT)).is_err()
        {
            return false;
        }
        let Some(pin) = read_frame(stream) else {
            return false;
        };
        sink(Submission { subject, from, pin });
        true
    }
}

/// The process on the other end of `stream`, as the kernel reports it.
fn peer_of(stream: &UnixStream) -> Option<Process> {
    let cred = rustix::net::sockopt::socket_peercred(stream).ok()?;
    Some(Process {
        uid: cred.uid.as_raw(),
        pid: u32::try_from(cred.pid.as_raw_nonzero().get()).ok()?,
    })
}

/// Reads one frame and the end of the stream. `None` for an empty or oversized PIN, a frame cut
/// short, anything after the PIN, or a client that does not close its writing side in time.
fn read_frame(stream: &mut UnixStream) -> Option<Zeroizing<Vec<u8>>> {
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).ok()?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > MAX_PIN_BYTES {
        return None;
    }
    let mut pin = Zeroizing::new(vec![0_u8; length]);
    stream.read_exact(&mut pin).ok()?;
    let mut rest = [0_u8; 1];
    match stream.read(&mut rest) {
        Ok(0) => Some(pin),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
