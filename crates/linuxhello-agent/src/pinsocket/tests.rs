//! Tests of the PIN socket: who may send a PIN, for whom, how often, and in what shape.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

use super::*;

/// The user and process running the test.
fn me() -> Process {
    Process {
        uid: rustix::process::getuid().as_raw(),
        pid: std::process::id(),
    }
}

/// A socket in a private directory, and the directory.
fn socket() -> (PinSocket, PathBuf, TempDir) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("pin.sock");
    let socket = PinSocket::bind(&path, me().uid).unwrap();
    (socket, path, dir)
}

/// What a client does: sends `bytes`, closes its writing side, reads the reply.
fn send(path: &PathBuf, bytes: &[u8]) -> u8 {
    let mut stream = UnixStream::connect(path).unwrap();
    stream.write_all(bytes).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = [9_u8; 1];
    stream.read_exact(&mut reply).unwrap();
    reply[0]
}

/// A frame carrying `pin`.
fn frame(pin: &[u8]) -> Vec<u8> {
    let mut bytes = u16::try_from(pin.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(pin);
    bytes
}

/// Runs one client against the socket and returns its reply and what the sink got.
fn exchange(socket: &PinSocket, path: &PathBuf, bytes: &[u8]) -> (u8, Vec<(u32, Vec<u8>)>) {
    let mut got = Vec::new();
    let reply = thread::scope(|scope| {
        let client = scope.spawn(|| send(path, bytes));
        socket
            .serve_one(&mut |s| got.push((s.subject, s.pin.to_vec())))
            .unwrap();
        client.join().unwrap()
    });
    (reply, got)
}

#[test]
fn the_pin_is_accepted_only_for_the_subject_the_bus_named() {
    let (socket, path, _dir) = socket();
    socket.expect(me(), 4242).unwrap();
    let (reply, got) = exchange(&socket, &path, &frame(b"1234"));
    assert_eq!(reply, REPLY_ACCEPTED);
    // The subject comes from the control call; the frame names nobody.
    assert_eq!(got, vec![(4242, b"1234".to_vec())]);
}

#[test]
fn a_caller_that_made_no_control_call_is_refused() {
    let (socket, path, _dir) = socket();
    let (reply, got) = exchange(&socket, &path, &frame(b"1234"));
    assert_eq!(reply, REPLY_REFUSED);
    assert!(got.is_empty());
}

#[test]
fn a_caller_of_another_user_cannot_use_the_socket() {
    let (socket, path, _dir) = socket();
    // A control call by another user's process, and by another process of this user.
    let other_user = Process {
        uid: me().uid.wrapping_add(1),
        pid: me().pid,
    };
    let other_process = Process {
        uid: me().uid,
        pid: me().pid.wrapping_add(1),
    };
    socket.expect(other_user, me().uid).unwrap();
    socket.expect(other_process, me().uid).unwrap();
    let (reply, got) = exchange(&socket, &path, &frame(b"1234"));
    assert_eq!(reply, REPLY_REFUSED);
    assert!(got.is_empty());
    // The refused connection did not use up what belongs to the others.
    assert_eq!(socket.take(other_user), Some(me().uid));
    assert_eq!(socket.take(other_process), Some(me().uid));
}

#[test]
fn a_control_call_is_used_once() {
    let (socket, path, _dir) = socket();
    socket.expect(me(), 1000).unwrap();
    assert_eq!(exchange(&socket, &path, &frame(b"1234")).0, REPLY_ACCEPTED);
    let (reply, got) = exchange(&socket, &path, &frame(b"1234"));
    assert_eq!(reply, REPLY_REFUSED);
    assert!(got.is_empty());
}

#[test]
fn a_control_call_expires() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("pin.sock");
    let socket = PinSocket::bind(&path, me().uid)
        .unwrap()
        .with_ttl(Duration::from_millis(50));
    socket.expect(me(), 1000).unwrap();
    thread::sleep(Duration::from_millis(120));
    let (reply, got) = exchange(&socket, &path, &frame(b"1234"));
    assert_eq!(reply, REPLY_REFUSED);
    assert!(got.is_empty());
}

#[test]
fn a_second_control_call_replaces_the_first() {
    let (socket, path, _dir) = socket();
    socket.expect(me(), 1000).unwrap();
    socket.expect(me(), 1001).unwrap();
    let (_, got) = exchange(&socket, &path, &frame(b"1234"));
    assert_eq!(got, vec![(1001, b"1234".to_vec())]);
}

#[test]
fn too_many_waiting_control_calls_are_refused() {
    let (socket, _path, _dir) = socket();
    for pid in 0..MAX_EXPECTATIONS {
        let caller = Process {
            uid: 1000,
            pid: u32::try_from(pid).unwrap(),
        };
        socket.expect(caller, 1000).unwrap();
    }
    let one_more = Process {
        uid: 1000,
        pid: 9999,
    };
    assert_eq!(socket.expect(one_more, 1000), Err(TooMany));
}

#[test]
fn a_frame_that_is_not_exactly_one_pin_is_refused() {
    let mut too_long = frame(&vec![b'1'; MAX_PIN_BYTES + 1]);
    too_long[0] = 0x01; // 257, read as a length
    let mut trailing = frame(b"1234");
    trailing.push(b'x');
    let mut cut_short = frame(b"1234");
    cut_short.truncate(4);
    let cases: [(&str, Vec<u8>); 5] = [
        ("empty", frame(b"")),
        ("too long", too_long),
        ("trailing bytes", trailing),
        ("cut short", cut_short),
        ("nothing", Vec::new()),
    ];
    for (name, bytes) in cases {
        let (socket, path, _dir) = socket();
        socket.expect(me(), 1000).unwrap();
        let (reply, got) = exchange(&socket, &path, &bytes);
        assert_eq!(reply, REPLY_REFUSED, "{name}");
        assert!(got.is_empty(), "{name}");
    }
    // The longest PIN is accepted.
    let (socket, path, _dir) = socket();
    socket.expect(me(), 1000).unwrap();
    let longest = vec![b'7'; MAX_PIN_BYTES];
    let (reply, got) = exchange(&socket, &path, &frame(&longest));
    assert_eq!(reply, REPLY_ACCEPTED);
    assert_eq!(got[0].1, longest);
}

#[test]
fn every_refusal_is_the_same_single_byte() {
    // No control call, and a bad frame under a control call, look alike to the client.
    let (socket, path, _dir) = socket();
    let (none, _) = exchange(&socket, &path, &frame(b"1234"));
    socket.expect(me(), 1000).unwrap();
    let (bad, _) = exchange(&socket, &path, &frame(b""));
    assert_eq!(none, bad);
    assert_eq!(none, REPLY_REFUSED);
}

#[test]
fn the_directory_must_be_private_to_the_agent() {
    // Another owner: refused.
    let dir = TempDir::new().unwrap();
    let wrong_owner = me().uid.wrapping_add(1);
    assert!(PinSocket::bind(&dir.path().join("pin.sock"), wrong_owner).is_err());
    // Writable by group or others: refused.
    for mode in [0o770, 0o707, 0o777] {
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            PinSocket::bind(&dir.path().join("pin.sock"), me().uid).is_err(),
            "mode {mode:o}"
        );
    }
    // Searchable by everyone, changeable by nobody else: accepted.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(PinSocket::bind(&dir.path().join("pin.sock"), me().uid).is_ok());
}

#[test]
fn a_stale_socket_is_replaced_and_anything_else_is_not() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("pin.sock");
    drop(PinSocket::bind(&path, me().uid).unwrap());
    // The file of the earlier run is still there; a new socket takes its place.
    assert!(path.exists());
    assert!(PinSocket::bind(&path, me().uid).is_ok());
    // A regular file is never removed.
    let file = dir.path().join("other");
    std::fs::write(&file, "x").unwrap();
    assert!(PinSocket::bind(&file, me().uid).is_err());
    assert!(file.exists());
}

#[test]
fn the_socket_is_open_to_every_user_but_its_directory_is_not() {
    let (_socket, path, dir) = socket();
    let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o666, "the credentials decide, not the file mode");
    let dir_mode = std::fs::metadata(dir.path()).unwrap().mode() & 0o022;
    assert_eq!(dir_mode, 0, "nobody but the owner can change the directory");
}

#[test]
fn a_silent_client_is_dropped() {
    let (socket, path, _dir) = socket();
    socket.expect(me(), 1000).unwrap();
    let mut got = Vec::new();
    thread::scope(|scope| {
        let client = scope.spawn(|| {
            // Connects, sends a length and half a PIN, and never closes.
            let mut stream = UnixStream::connect(&path).unwrap();
            stream.write_all(&[0, 4, b'1']).unwrap();
            let mut reply = [9_u8; 1];
            stream.read_exact(&mut reply).unwrap();
            reply[0]
        });
        socket.serve_one(&mut |s| got.push(s.subject)).unwrap();
        assert_eq!(client.join().unwrap(), REPLY_REFUSED);
    });
    assert!(got.is_empty());
}
