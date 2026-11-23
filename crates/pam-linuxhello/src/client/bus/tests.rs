//! Tests of the bus connection against a fake bus daemon on a socket in a temporary directory.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::{Duration, Instant};

use super::super::wire::{encode_for_tests, parse, total_length, Kind, Message, Value};
use super::*;

/// The server side of one connection.
pub(crate) struct Peer {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Peer {
    pub(crate) fn new(stream: UnixStream) -> Self {
        let writer = stream.try_clone().unwrap();
        Self {
            reader: BufReader::new(stream),
            writer,
        }
    }

    /// The authentication exchange as dbus-daemon does it for `EXTERNAL` without an identity.
    pub(crate) fn accept_auth(&mut self) {
        let mut nul = [0_u8; 1];
        self.reader.read_exact(&mut nul).unwrap();
        assert_eq!(nul[0], 0);
        let mut line = String::new();
        self.reader.read_line(&mut line).unwrap();
        assert_eq!(line, "AUTH EXTERNAL\r\n");
        self.writer.write_all(b"DATA\r\n").unwrap();
        line.clear();
        self.reader.read_line(&mut line).unwrap();
        assert_eq!(line, "DATA\r\n");
        self.writer.write_all(b"OK 0123456789abcdef\r\n").unwrap();
        line.clear();
        self.reader.read_line(&mut line).unwrap();
        assert_eq!(line, "BEGIN\r\n");
    }

    /// The next message the client sent.
    pub(crate) fn read(&mut self) -> Message {
        let mut head = [0_u8; 16];
        self.reader.read_exact(&mut head).unwrap();
        let mut bytes = vec![0_u8; total_length(&head).unwrap()];
        bytes[..16].copy_from_slice(&head);
        self.reader.read_exact(&mut bytes[16..]).unwrap();
        parse(&bytes).unwrap()
    }

    /// Sends `bytes` as they are.
    pub(crate) fn send_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).unwrap();
    }

    /// Sends `message`.
    pub(crate) fn send(&mut self, message: &Message) {
        self.writer.write_all(&encode_for_tests(message)).unwrap();
    }

    /// Answers the call `to` with a reply holding `body`.
    pub(crate) fn reply(&mut self, to: &Message, body: Vec<Value>) {
        self.send(&Message {
            kind: Kind::Return,
            serial: 1000 + to.serial,
            reply_serial: Some(to.serial),
            interface: None,
            member: None,
            error_name: None,
            sender: Some("org.freedesktop.DBus".into()),
            body,
        });
    }

    /// Reads `Hello` and answers it.
    pub(crate) fn hello(&mut self) {
        let hello = self.read();
        assert_eq!(hello.member.as_deref(), Some("Hello"));
        self.reply(&hello, vec![Value::Str(":1.42".into())]);
    }
}

/// A listening socket in a fresh directory, and its path.
pub(crate) fn listen() -> (tempfile::TempDir, std::path::PathBuf, UnixListener) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bus");
    let listener = UnixListener::bind(&path).unwrap();
    (dir, path, listener)
}

pub(crate) fn signal(member: &str, sender: &str, body: Vec<Value>) -> Message {
    Message {
        kind: Kind::Signal,
        serial: 77,
        reply_serial: None,
        interface: Some("io.github.LinuxHello.Agent1".into()),
        member: Some(member.into()),
        error_name: None,
        sender: Some(sender.into()),
        body,
    }
}

/// A signal whose body the codec cannot read: the one argument has the type `i`, which the Agent
/// never sends and the codec does not model. The bytes of a well-formed signal with a `u` argument,
/// with the type in the header changed.
pub(crate) fn unreadable_signal(member: &str, sender: &str) -> Vec<u8> {
    let mut bytes = encode_for_tests(&signal(member, sender, vec![Value::U32(5)]));
    let at = bytes
        .windows(7)
        .position(|w| w == [8, 1, b'g', 0, 1, b'u', 0])
        .expect("the signature field");
    bytes[at + 5] = b'i';
    assert!(parse(&bytes).is_err(), "the codec must not model `i`");
    bytes
}

#[test]
fn a_missing_socket_is_unreachable_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let result = Bus::connect(&dir.path().join("none"), Duration::from_millis(250));
    assert_eq!(result.err(), Some(BusError::Unreachable));
    assert!(started.elapsed() < Duration::from_millis(250));
}

#[test]
fn a_bus_that_never_answers_times_out_within_the_limit() {
    let (_dir, path, listener) = listen();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(2));
        drop(stream);
    });
    let started = Instant::now();
    let result = Bus::connect(&path, Duration::from_millis(250));
    let took = started.elapsed();
    assert_eq!(result.err(), Some(BusError::Timeout));
    assert!(took >= Duration::from_millis(240), "{took:?}");
    assert!(took < Duration::from_millis(600), "{took:?}");
    server.join().unwrap();
}

#[test]
fn a_bus_that_refuses_authentication_is_refused() {
    let (_dir, path, listener) = listen();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut peer = Peer::new(stream);
        let mut buffer = [0_u8; 16];
        let _ = peer.reader.read(&mut buffer);
        peer.writer.write_all(b"REJECTED EXTERNAL\r\n").unwrap();
    });
    let result = Bus::connect(&path, Duration::from_millis(500));
    assert_eq!(
        result.err(),
        Some(BusError::Refused("REJECTED EXTERNAL".into()))
    );
    server.join().unwrap();
}

#[test]
fn a_call_returns_its_reply_and_signals_that_came_first_are_kept() {
    let (_dir, path, listener) = listen();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut peer = Peer::new(stream);
        peer.accept_auth();
        peer.hello();
        let call = peer.read();
        assert_eq!(call.member.as_deref(), Some("OpenPrompt"));
        assert_eq!(call.kind, Kind::Call);
        // A signal and an unrelated reply before the real reply.
        peer.send(&signal(
            "ActiveMethods",
            ":1.5",
            vec![Value::Str("p".into()), Value::Strs(vec!["pin".into()])],
        ));
        let mut other = call.clone();
        other.serial += 500;
        peer.reply(&other, vec![]);
        peer.reply(&call, vec![]);
        let refused = peer.read();
        peer.send(&Message {
            kind: Kind::Error,
            serial: 9,
            reply_serial: Some(refused.serial),
            interface: None,
            member: None,
            error_name: Some("io.github.LinuxHello.Agent1.Error.Denied".into()),
            sender: Some(":1.5".into()),
            body: vec![Value::Str("denied".into())],
        });
    });
    let mut bus = Bus::connect(&path, Duration::from_millis(500)).unwrap();
    bus.trust_signals_from(":1.5".into());
    let soon = || Instant::now() + Duration::from_secs(2);
    let body = bus
        .call("d", "/p", "i", "OpenPrompt", &[Arg::Str("p")], soon())
        .unwrap();
    assert!(body.is_empty());
    let queued = bus.next_signal(soon()).unwrap().unwrap();
    assert_eq!(queued.member.as_deref(), Some("ActiveMethods"));
    assert_eq!(
        bus.call("d", "/p", "i", "Authenticate", &[], soon()),
        Err(BusError::Refused(
            "io.github.LinuxHello.Agent1.Error.Denied".into()
        ))
    );
    server.join().unwrap();
}

#[test]
fn no_signal_before_the_deadline_is_none_and_the_connection_stays_usable() {
    let (_dir, path, listener) = listen();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut peer = Peer::new(stream);
        peer.accept_auth();
        peer.hello();
        thread::sleep(Duration::from_millis(300));
        peer.send(&signal("Closed", ":1.5", vec![Value::Str("p".into())]));
        thread::sleep(Duration::from_millis(300));
    });
    let mut bus = Bus::connect(&path, Duration::from_millis(500)).unwrap();
    bus.trust_signals_from(":1.5".into());
    let started = Instant::now();
    assert_eq!(
        bus.next_signal(Instant::now() + Duration::from_millis(100)),
        Ok(None)
    );
    assert!(started.elapsed() < Duration::from_millis(300));
    let later = bus
        .next_signal(Instant::now() + Duration::from_secs(2))
        .unwrap()
        .unwrap();
    assert_eq!(later.member.as_deref(), Some("Closed"));
    server.join().unwrap();
}

#[test]
fn a_bus_that_closes_is_unreachable() {
    let (_dir, path, listener) = listen();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut peer = Peer::new(stream);
        peer.accept_auth();
        peer.hello();
    });
    let mut bus = Bus::connect(&path, Duration::from_millis(500)).unwrap();
    server.join().unwrap();
    assert_eq!(
        bus.next_signal(Instant::now() + Duration::from_secs(1)),
        Err(BusError::Unreachable)
    );
}

#[test]
fn a_signal_nobody_may_send_is_dropped_unread() {
    // The system bus lets any user send a signal to any connection. With the Agent's connection
    // trusted, a signal of another sender is dropped by its header: its body, which the codec cannot
    // read, does not end the exchange (R-03, #346).
    let (_dir, path, listener) = listen();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut peer = Peer::new(stream);
        peer.accept_auth();
        peer.hello();
        peer.send_raw(&unreadable_signal("Result", ":1.99"));
        peer.send(&signal("Closed", ":1.5", vec![Value::Str("p".into())]));
        thread::sleep(Duration::from_millis(200));
    });
    let mut bus = Bus::connect(&path, Duration::from_millis(500)).unwrap();
    bus.trust_signals_from(":1.5".into());
    let heard = bus
        .next_signal(Instant::now() + Duration::from_secs(2))
        .unwrap()
        .unwrap();
    assert_eq!(heard.member.as_deref(), Some("Closed"));
    assert_eq!(heard.sender.as_deref(), Some(":1.5"));
    server.join().unwrap();
}

#[test]
fn a_signal_whose_body_cannot_be_read_is_skipped_not_an_error() {
    // Even from the trusted sender: a signal with an argument type the codec does not know, as a
    // future version of the Agent might send, must not break every sign-in (R-03, #346).
    let (_dir, path, listener) = listen();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut peer = Peer::new(stream);
        peer.accept_auth();
        peer.hello();
        let call = peer.read();
        peer.send_raw(&unreadable_signal("MethodEnded", ":1.5"));
        peer.reply(&call, vec![]);
        peer.send_raw(&unreadable_signal("MethodEnded", ":1.5"));
        peer.send(&signal("Closed", ":1.5", vec![Value::Str("p".into())]));
        thread::sleep(Duration::from_millis(200));
    });
    let mut bus = Bus::connect(&path, Duration::from_millis(500)).unwrap();
    bus.trust_signals_from(":1.5".into());
    let soon = || Instant::now() + Duration::from_secs(2);
    // The reply to a call is still read, with the unreadable signal before it skipped.
    assert!(bus
        .call("d", "/p", "i", "Subscribe", &[], soon())
        .unwrap()
        .is_empty());
    let heard = bus.next_signal(soon()).unwrap().unwrap();
    assert_eq!(heard.member.as_deref(), Some("Closed"));
    server.join().unwrap();
}

#[test]
fn a_flood_of_signals_while_a_call_waits_is_bounded() {
    let (_dir, path, listener) = listen();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut peer = Peer::new(stream);
        peer.accept_auth();
        peer.hello();
        let call = peer.read();
        for _ in 0..(MAX_QUEUED * 4) {
            peer.send(&signal("Closed", ":1.5", vec![Value::Str("p".into())]));
        }
        peer.reply(&call, vec![]);
    });
    let mut bus = Bus::connect(&path, Duration::from_millis(500)).unwrap();
    bus.trust_signals_from(":1.5".into());
    bus.call(
        "d",
        "/p",
        "i",
        "Subscribe",
        &[],
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(bus.queue.len(), MAX_QUEUED);
    server.join().unwrap();
}

#[test]
fn signals_before_the_agent_is_known_are_dropped() {
    // While the module looks up the Agent's name, a connection that floods it with signals must
    // fill nothing: no signal is kept until a sender is trusted, and what is kept after that is
    // the trusted sender's alone (R-03, #346).
    let (_dir, path, listener) = listen();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut peer = Peer::new(stream);
        peer.accept_auth();
        peer.hello();
        let call = peer.read();
        for _ in 0..(MAX_QUEUED * 2) {
            peer.send(&signal("Closed", ":1.99", vec![Value::Str("p".into())]));
        }
        peer.reply(&call, vec![]);
        peer.send(&signal("Closed", ":1.5", vec![Value::Str("p".into())]));
        thread::sleep(Duration::from_millis(200));
    });
    let mut bus = Bus::connect(&path, Duration::from_millis(500)).unwrap();
    bus.call(
        "d",
        "/p",
        "i",
        "GetNameOwner",
        &[],
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert!(
        bus.queue.is_empty(),
        "nothing is kept before a sender is trusted"
    );
    bus.trust_signals_from(":1.5".into());
    let heard = bus
        .next_signal(Instant::now() + Duration::from_secs(2))
        .unwrap()
        .unwrap();
    assert_eq!(heard.sender.as_deref(), Some(":1.5"));
    server.join().unwrap();
}

/// A listener whose queue of waiting connections is full, so that the next `connect` has nowhere
/// to go. Returns the directory, the path and the connections that fill the queue.
fn full_listener() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Vec<rustix::fd::OwnedFd>,
    rustix::fd::OwnedFd,
) {
    use rustix::net::{
        bind, connect, listen, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("full");
    let address = SocketAddrUnix::new(&path).unwrap();
    let server = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    bind(&server, &address).unwrap();
    listen(&server, 0).unwrap();
    // Nobody accepts: connect until the queue says "again".
    let mut held = Vec::new();
    loop {
        let client = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        match connect(&client, &address) {
            Ok(()) => held.push(client),
            Err(rustix::io::Errno::AGAIN) => break,
            Err(other) => panic!("{other}"),
        }
    }
    (dir, path, held, server)
}

#[test]
fn a_bus_with_a_full_queue_cannot_hold_the_module_beyond_its_limit() {
    // R-16, #358: `UnixStream::connect` sleeps without limit when the queue of a socket is full,
    // and the 250 ms limit started only after the connection. Now the connect itself is bounded.
    let (_dir, path, _held, _server) = full_listener();
    let started = Instant::now();
    let result = Bus::connect(&path, Duration::from_millis(200));
    let took = started.elapsed();
    assert!(
        matches!(result, Err(BusError::Timeout)),
        "{:?}",
        result.err()
    );
    assert!(took < Duration::from_millis(1000), "{took:?}");
}

#[test]
fn connect_within_reaches_a_socket_that_has_room() {
    let (_dir, path, _listener) = listen();
    let stream = connect_within(&path, Instant::now() + Duration::from_millis(500));
    assert!(stream.is_ok());
}

#[test]
fn connect_within_says_unreachable_for_a_path_nobody_listens_on() {
    let dir = tempfile::tempdir().unwrap();
    let stream = connect_within(
        &dir.path().join("none"),
        Instant::now() + Duration::from_millis(500),
    );
    assert!(matches!(stream, Err(BusError::Unreachable)));
}
