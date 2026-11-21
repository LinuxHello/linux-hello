//! A synchronous connection to the system bus, in the calling thread (ADR-0023, amendment of
//! 2026-11-21, point 1).
//!
//! In plain words: D-Bus is a message service; programs connect to a socket of the bus daemon,
//! prove who they are, and then exchange messages. This module does that one step at a time on a
//! plain Unix socket: it connects, authenticates with `EXTERNAL` (the bus reads the caller's user id
//! from the socket itself, so nothing is claimed), says `Hello`, and then writes a call and reads
//! messages until the reply to that call arrives. Signals that arrive while it waits for a reply
//! are kept in order for the caller. Every read has a deadline, so a bus or an Agent that hangs
//! costs at most that time. Nothing runs in the background.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use super::wire::{self, Arg, Kind, Message, Value};

/// The bus daemon's own name, path and interface.
const BUS_NAME: &str = "org.freedesktop.DBus";
/// The bus daemon's object path.
const BUS_PATH: &str = "/org/freedesktop/DBus";

/// The longest line of the authentication exchange that is read.
const MAX_LINE: usize = 512;

/// Why a step on the bus failed. Every one of them makes the module answer "unavailable".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BusError {
    /// The socket could not be reached, or it closed.
    Unreachable,
    /// The deadline passed.
    Timeout,
    /// The bus sent something that is not a message the module can read.
    Malformed,
    /// A call was answered with an error; the error's name.
    Refused(String),
}

impl From<wire::Malformed> for BusError {
    fn from(_: wire::Malformed) -> Self {
        Self::Malformed
    }
}

/// Maps an I/O error of a socket read or write: a timeout is [`BusError::Timeout`], anything
/// else [`BusError::Unreachable`].
fn io_error(error: &io::Error) -> BusError {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => BusError::Timeout,
        _ => BusError::Unreachable,
    }
}

/// The time left until `deadline`, at least one millisecond (a socket timeout of zero means "no
/// timeout"), or [`BusError::Timeout`] when it has passed.
fn left(deadline: Instant) -> Result<Duration, BusError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(BusError::Timeout);
    }
    Ok((deadline - now).max(Duration::from_millis(1)))
}

/// One connection to the bus.
pub struct Bus {
    /// The socket.
    stream: UnixStream,
    /// The serial of the last message sent.
    serial: u32,
    /// Signals read while waiting for a reply, oldest first.
    queue: VecDeque<Message>,
}

impl Bus {
    /// Connects to the bus at `path`, authenticates and says `Hello`, all within `limit`.
    ///
    /// # Errors
    ///
    /// [`BusError`] when any step fails or `limit` passes.
    pub fn connect(path: &Path, limit: Duration) -> Result<Self, BusError> {
        let deadline = Instant::now() + limit;
        let stream = UnixStream::connect(path).map_err(|_| BusError::Unreachable)?;
        let mut bus = Self {
            stream,
            serial: 0,
            queue: VecDeque::new(),
        };
        bus.authenticate(deadline)?;
        bus.call(BUS_NAME, BUS_PATH, BUS_NAME, "Hello", &[], deadline)?;
        Ok(bus)
    }

    /// The `EXTERNAL` exchange: no identity is sent, so the bus uses the one of the socket.
    fn authenticate(&mut self, deadline: Instant) -> Result<(), BusError> {
        self.write(b"\0AUTH EXTERNAL\r\n", deadline)?;
        let mut line = self.line(deadline)?;
        if line == "DATA" {
            self.write(b"DATA\r\n", deadline)?;
            line = self.line(deadline)?;
        }
        if !line.starts_with("OK ") {
            return Err(BusError::Refused(line));
        }
        self.write(b"BEGIN\r\n", deadline)
    }

    /// Writes all of `bytes` before `deadline`.
    fn write(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), BusError> {
        self.stream
            .set_write_timeout(Some(left(deadline)?))
            .map_err(|_| BusError::Unreachable)?;
        self.stream.write_all(bytes).map_err(|e| io_error(&e))
    }

    /// Reads one line of the authentication exchange, without its `\r\n`.
    fn line(&mut self, deadline: Instant) -> Result<String, BusError> {
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            self.fill(&mut byte, deadline)?;
            if byte[0] == b'\n' && line.last() == Some(&b'\r') {
                line.pop();
                return String::from_utf8(line).map_err(|_| BusError::Malformed);
            }
            line.push(byte[0]);
            if line.len() > MAX_LINE {
                return Err(BusError::Malformed);
            }
        }
    }

    /// Fills `buffer` completely before `deadline`.
    fn fill(&mut self, buffer: &mut [u8], deadline: Instant) -> Result<(), BusError> {
        let mut at = 0;
        while at < buffer.len() {
            self.stream
                .set_read_timeout(Some(left(deadline)?))
                .map_err(|_| BusError::Unreachable)?;
            match self.stream.read(&mut buffer[at..]) {
                Ok(0) => return Err(BusError::Unreachable),
                Ok(n) => at += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(io_error(&e)),
            }
        }
        Ok(())
    }

    /// Reads the next message from the socket, before `deadline`. With `idle`, a deadline that
    /// passes before the first byte arrives is `Ok(None)`; once a message has begun, the rest of it
    /// must follow before the same deadline.
    fn read_message(&mut self, deadline: Instant, idle: bool) -> Result<Option<Message>, BusError> {
        let mut head = [0_u8; 16];
        match self.fill(&mut head[..1], deadline) {
            Ok(()) => {}
            Err(BusError::Timeout) if idle => return Ok(None),
            Err(other) => return Err(other),
        }
        self.fill(&mut head[1..], deadline)?;
        let total = wire::total_length(&head)?;
        let mut bytes = vec![0_u8; total];
        bytes[..16].copy_from_slice(&head);
        self.fill(&mut bytes[16..], deadline)?;
        Ok(Some(wire::parse(&bytes)?))
    }

    /// Calls `member` and returns the body of its reply, before `deadline`. Signals that arrive
    /// first are queued for [`Bus::next_signal`]; other messages are dropped.
    ///
    /// # Errors
    ///
    /// [`BusError::Refused`] with the error's name when the call is answered with an error, and the
    /// other [`BusError`]s when the bus fails or `deadline` passes.
    pub fn call(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
        args: &[Arg<'_>],
        deadline: Instant,
    ) -> Result<Vec<Value>, BusError> {
        self.serial = self.serial.wrapping_add(1).max(1);
        let serial = self.serial;
        let bytes = wire::method_call(serial, destination, path, interface, member, args)?;
        self.write(&bytes, deadline)?;
        loop {
            let Some(message) = self.read_message(deadline, false)? else {
                return Err(BusError::Timeout);
            };
            match message.kind {
                Kind::Return if message.reply_serial == Some(serial) => return Ok(message.body),
                Kind::Error if message.reply_serial == Some(serial) => {
                    return Err(BusError::Refused(message.error_name.unwrap_or_default()))
                }
                Kind::Signal => self.queue.push_back(message),
                _ => {}
            }
        }
    }

    /// The next signal, from the queue or the socket; `None` when none arrives before `deadline`.
    ///
    /// # Errors
    ///
    /// [`BusError`] when the bus fails or sends something unreadable, including a message cut off
    /// by the deadline (the connection cannot be used after that).
    pub fn next_signal(&mut self, deadline: Instant) -> Result<Option<Message>, BusError> {
        if let Some(message) = self.queue.pop_front() {
            return Ok(Some(message));
        }
        loop {
            match self.read_message(deadline, true)? {
                None => return Ok(None),
                Some(message) if message.kind == Kind::Signal => return Ok(Some(message)),
                Some(_) => {}
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
