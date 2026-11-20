//! Tests of the PIN commands against a real Agent service on a private bus and a real PIN socket,
//! with an in-memory stand-in for the TPM. Needs `dbus-daemon`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use linuxhello_agent::bus::{serve_with_extras, Extras, PinChange};
use linuxhello_agent::methods::pin::enrol::PinEnrolment;
use linuxhello_agent::methods::pin::tpm::EnrolError;
use linuxhello_agent::methods::pin::PinInbox;
use linuxhello_agent::pinlock::service::{Limits, PinLockService};
use linuxhello_agent::pinlock::store::PinLockFile;
use linuxhello_agent::pinsocket::PinSocket;
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;

use super::*;

/// A private bus, stopped when dropped.
struct Daemon {
    child: Child,
    address: String,
}

impl Daemon {
    fn start() -> Self {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon must be installed");
        let stdout = child.stdout.take().unwrap();
        let mut address = String::new();
        BufReader::new(stdout).read_line(&mut address).unwrap();
        Self {
            child,
            address: address.trim().to_string(),
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A stand-in that keeps one PIN per user in memory.
#[derive(Default)]
struct Memory(Mutex<HashMap<u32, Vec<u8>>>);

impl PinEnrolment for Memory {
    fn has_pin(&self, uid: u32) -> bool {
        self.0.lock().unwrap().contains_key(&uid)
    }

    fn set(&self, uid: u32, pin: &[u8]) -> Result<(), EnrolError> {
        self.0.lock().unwrap().insert(uid, pin.to_vec());
        Ok(())
    }

    fn change(&self, uid: u32, old: &[u8], new: &[u8], _history: u32) -> Result<(), EnrolError> {
        let mut pins = self.0.lock().unwrap();
        match pins.get_mut(&uid) {
            Some(current) if current.as_slice() == old => {
                *current = new.to_vec();
                Ok(())
            }
            Some(_) => Err(EnrolError::WrongPin),
            None => Err(EnrolError::NotEnrolled),
        }
    }
}

/// PINs read from a list, in order.
struct Script(Vec<&'static [u8]>);

impl Pins for Script {
    fn read(&mut self, _label: &str) -> Option<Zeroizing<Vec<u8>>> {
        (!self.0.is_empty()).then(|| Zeroizing::new(self.0.remove(0).to_vec()))
    }
}

/// An Agent on a private bus, and a connection of the command to it.
struct World {
    _daemon: Daemon,
    _agent: Connection,
    client: Connection,
    socket: std::path::PathBuf,
    memory: Arc<Memory>,
    uid: u32,
    _dir: tempfile::TempDir,
}

fn world() -> World {
    futures_lite::future::block_on(async {
        let daemon = Daemon::start();
        let dir = crate::private_tempdir();
        let uid = rustix::process::getuid().as_raw();
        let socket_path = dir.path().join("pin.sock");
        let socket = Arc::new(PinSocket::bind(&socket_path, uid).unwrap());
        let inbox = Arc::new(PinInbox::default());
        let sink = Arc::clone(&inbox);
        PinSocket::serve_forever(Arc::clone(&socket), move |s| {
            sink.deliver(s.subject, s.pin);
        });
        let lock = Arc::new(PinLockService::start(
            PinLockFile::new(dir.path().join("pinlock.toml"), uid),
            Limits {
                max_attempts: 2,
                lockout_secs: 600,
                max_lockout_secs: 86_400,
            },
        ));
        let memory = Arc::new(Memory::default());
        let agent = serve_with_extras(
            zbus::connection::Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
            Some(UserPolicyStore::new(dir.path().join("users"))),
            Extras {
                pin_socket: Some(socket),
                pin_lock: Some(lock),
                pin_change: Some(PinChange {
                    inbox,
                    enrolment: Arc::clone(&memory) as Arc<dyn PinEnrolment>,
                }),
                ..Extras::default()
            },
        )
        .await
        .unwrap();
        let client = zbus::connection::Builder::address(daemon.address.as_str())
            .build()
            .await
            .unwrap();
        World {
            _daemon: daemon,
            _agent: agent,
            client,
            socket: socket_path,
            memory,
            uid,
            _dir: dir,
        }
    })
}

/// Runs the command with `pins` and returns the exit code and what it said.
fn command(w: &World, change: bool, pins: Vec<&'static [u8]>) -> (u8, String) {
    let mut out = Vec::new();
    let code = run(
        &w.client,
        &w.socket,
        w.uid,
        change,
        &mut Script(pins),
        &mut out,
    );
    (code, String::from_utf8(out).unwrap())
}

#[test]
fn pin_set_then_pin_change_work_end_to_end() {
    let w = world();
    let (code, said) = command(&w, false, vec![b"123456", b"123456"]);
    assert_eq!((code, said.as_str()), (0, "Done.\n"));
    assert_eq!(w.memory.0.lock().unwrap()[&w.uid], b"123456");

    let (code, said) = command(&w, true, vec![b"123456", b"654321", b"654321"]);
    assert_eq!((code, said.as_str()), (0, "Done.\n"));
    assert_eq!(w.memory.0.lock().unwrap()[&w.uid], b"654321");
}

#[test]
fn a_wrong_current_pin_is_said_and_changes_nothing() {
    let w = world();
    w.memory.set(w.uid, b"123456").unwrap();
    let (code, said) = command(&w, true, vec![b"000000", b"654321", b"654321"]);
    assert_eq!(code, 1);
    assert!(said.contains("current PIN is wrong"), "{said}");
    assert_eq!(w.memory.0.lock().unwrap()[&w.uid], b"123456");
}

#[test]
fn two_different_new_pins_send_nothing() {
    let w = world();
    let (code, said) = command(&w, false, vec![b"123456", b"123457"]);
    assert_eq!(code, 1);
    assert!(said.contains("not the same"), "{said}");
    assert!(!w.memory.has_pin(w.uid));
}

#[test]
fn a_set_for_a_user_who_has_a_pin_is_refused_in_words() {
    let w = world();
    w.memory.set(w.uid, b"123456").unwrap();
    let (code, said) = command(&w, false, vec![b"654321", b"654321"]);
    assert_eq!(code, 1);
    assert!(said.contains("refused"), "{said}");
    assert_eq!(w.memory.0.lock().unwrap()[&w.uid], b"123456");
}

#[test]
fn a_pin_that_cannot_be_read_is_said_and_nothing_is_started() {
    let w = world();
    let (code, said) = command(&w, false, vec![]);
    assert_eq!(code, 1);
    assert!(said.contains("No PIN was read"), "{said}");
}

#[test]
fn every_outcome_is_said_in_words_and_only_success_exits_zero() {
    assert_eq!(describe("success", "", 0), ("Done.".to_string(), 0));
    assert_eq!(describe("locked-out", "", 600).1, 1);
    assert!(describe("locked-out", "", 600).0.contains("10 minutes"));
    assert!(describe("failure", "not-recognised", 0).0.contains("wrong"));
    assert_eq!(describe("failure", "", 0).1, 1);
    assert_eq!(describe("something new", "", 0).1, 1);
}
