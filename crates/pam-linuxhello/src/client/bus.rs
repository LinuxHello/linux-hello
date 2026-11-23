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
//!
//! What it does not read it does not decode. The system bus lets any user send a signal to any
//! connection, and a message's body is not checked by the bus, so a body is decoded only when it is
//! the reply to the module's own call, or a signal of the connection that owns the Agent's name
//! ([`Bus::trust_signals_from`]); a signal of another sender is dropped by its header, and a signal
//! whose body the codec cannot read is skipped. One hostile message therefore cannot end an
//! attempt as "unavailable" (review finding R-03, #346, `a_signal_nobody_may_send_is_dropped_unread`).

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

/// The most signals kept while a call waits for its reply.
const MAX_QUEUED: usize = 64;

/// A message read from the socket whose body has not been decoded.
struct Raw {
    /// The header.
    parts: wire::Parts,
    /// The whole message.
    bytes: Vec<u8>,
}

/// How long to wait between two tries to connect to a socket whose queue is full.
const CONNECT_RETRY: Duration = Duration::from_millis(5);

/// Connects to the Unix socket at `path` and gives up at `deadline`. `UnixStream::connect` sleeps
/// without limit when the queue of a listening socket is full, and a limit that starts after it
/// returns does not help; here the socket is made non-blocking, a full queue (`EAGAIN`) is tried
/// again until the deadline, and the stream is made blocking again once it is connected
/// (`a_bus_with_a_full_queue_cannot_hold_the_module_beyond_its_limit`, review finding R-16,
/// #358).
///
/// # Errors
///
/// [`BusError::Timeout`] when the queue stays full until `deadline`, [`BusError::Unreachable`]
/// when the path is too long, nobody listens there, or the socket cannot be made.
pub(crate) fn connect_within(path: &Path, deadline: Instant) -> Result<UnixStream, BusError> {
    use rustix::io::Errno;
    use rustix::net::{
        connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType,
    };
    let address = SocketAddrUnix::new(path).map_err(|_| BusError::Unreachable)?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| BusError::Unreachable)?;
    loop {
        match connect(&socket, &address) {
            Ok(()) => break,
            Err(Errno::AGAIN | Errno::INTR) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(BusError::Timeout);
                }
                std::thread::sleep(CONNECT_RETRY.min(deadline - now));
            }
            Err(_) => return Err(BusError::Unreachable),
        }
    }
    let stream = UnixStream::from(socket);
    stream
        .set_nonblocking(false)
        .map_err(|_| BusError::Unreachable)?;
    Ok(stream)
}

/// One connection to the bus.
pub struct Bus {
    /// The socket.
    stream: UnixStream,
    /// The serial of the last message sent.
    serial: u32,
    /// Signals read while waiting for a reply, oldest first.
    queue: VecDeque<Message>,
    /// The only sender whose signals are read. Until it is known no signal is read at all: the
    /// module has subscribed to nothing yet, so any signal that arrives is from someone else.
    trusted: Option<String>,
}

impl Bus {
    /// Connects to the bus at `path`, authenticates and says `Hello`, all within `limit`.
    ///
    /// # Errors
    ///
    /// [`BusError`] when any step fails or `limit` passes.
    pub fn connect(path: &Path, limit: Duration) -> Result<Self, BusError> {
        let deadline = Instant::now() + limit;
        let stream = connect_within(path, deadline)?;
        let mut bus = Self {
            stream,
            serial: 0,
            queue: VecDeque::new(),
            trusted: None,
        };
        bus.authenticate(deadline)?;
        bus.call(BUS_NAME, BUS_PATH, BUS_NAME, "Hello", &[], deadline)?;
        Ok(bus)
    }

    /// From now on only the signals sent by the connection `name` are read; the signals of every
    /// other sender are dropped by their header, without their body being decoded. Before this is
    /// called every signal is dropped, so a flood sent while the module looks up the Agent's name
    /// cannot fill the queue and crowd out what the Agent says later
    /// (`signals_before_the_agent_is_known_are_dropped`, R-03).
    pub fn trust_signals_from(&mut self, name: String) {
        self.queue
            .retain(|m| m.sender.as_deref() == Some(name.as_str()));
        self.trusted = Some(name);
    }

    /// The message of `raw` as a signal this connection may read: from the trusted sender, with a
    /// body the codec can read. `None` otherwise, and always before a sender is trusted (the signal
    /// is skipped, not an error).
    fn usable(&self, raw: Raw) -> Option<Message> {
        let trusted = self.trusted.as_deref()?;
        if raw.parts.message.sender.as_deref() != Some(trusted) {
            return None;
        }
        let body = raw.parts.body(&raw.bytes).ok()?;
        Some(Message {
            body,
            ..raw.parts.message
        })
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
    fn read_message(&mut self, deadline: Instant, idle: bool) -> Result<Option<Raw>, BusError> {
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
        let parts = wire::parse_header(&bytes)?;
        Ok(Some(Raw { parts, bytes }))
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
            let Some(raw) = self.read_message(deadline, false)? else {
                return Err(BusError::Timeout);
            };
            let message = &raw.parts.message;
            match message.kind {
                Kind::Return if message.reply_serial == Some(serial) => {
                    return Ok(raw.parts.body(&raw.bytes)?)
                }
                Kind::Error if message.reply_serial == Some(serial) => {
                    return Err(BusError::Refused(
                        message.error_name.clone().unwrap_or_default(),
                    ))
                }
                Kind::Signal => {
                    if let Some(signal) = self.usable(raw) {
                        if self.queue.len() < MAX_QUEUED {
                            self.queue.push_back(signal);
                        }
                    }
                }
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
                Some(raw) if raw.parts.message.kind == Kind::Signal => {
                    if let Some(signal) = self.usable(raw) {
                        return Ok(Some(signal));
                    }
                }
                Some(_) => {}
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
