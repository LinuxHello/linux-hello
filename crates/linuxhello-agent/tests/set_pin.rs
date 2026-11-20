//! `SetPin` and `ChangePin` on a real private bus and a real PIN socket, with an in-memory stand-in
//! for the TPM: the calls, `ExpectPin`, the PINs on the socket and the `Result` signal.

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{call, connect, is_error, my_uid, next_within, pid, run, signals, Daemon};
use linuxhello_agent::bus::{serve_with_extras, Extras, PinChange};
use linuxhello_agent::methods::pin::enrol::PinEnrolment;
use linuxhello_agent::methods::pin::tpm::EnrolError;
use linuxhello_agent::methods::pin::PinInbox;
use linuxhello_agent::pinlock::service::{Limits, PinLockService};
use linuxhello_agent::pinlock::store::PinLockFile;
use linuxhello_agent::pinsocket::{PinSocket, REPLY_ACCEPTED};
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;
use zbus::connection::Builder;

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

    fn change(&self, uid: u32, old: &[u8], new: &[u8]) -> Result<(), EnrolError> {
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

/// Sends one frame carrying `pin` on the socket and returns the reply byte.
fn send_pin(path: &Path, pin: &[u8]) -> u8 {
    let mut stream = UnixStream::connect(path).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = u16::try_from(pin.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(pin);
    drop(stream.write_all(&bytes));
    drop(stream.shutdown(std::net::Shutdown::Write));
    let mut reply = [9_u8; 1];
    stream.read_exact(&mut reply).expect("one byte of reply");
    reply[0]
}

/// The Agent with the PIN-change path wired as `main` does.
struct World {
    daemon: Daemon,
    _service: zbus::Connection,
    socket: std::path::PathBuf,
    memory: Arc<Memory>,
    id: String,
    _dir: tempfile::TempDir,
}

async fn world() -> World {
    let daemon = Daemon::start();
    let dir = tempfile::TempDir::new().unwrap();
    let socket_path = dir.path().join("pin.sock");
    let socket = Arc::new(PinSocket::bind(&socket_path, my_uid()).unwrap());
    let inbox = Arc::new(PinInbox::default());
    let sink = Arc::clone(&inbox);
    PinSocket::serve_forever(Arc::clone(&socket), move |s| {
        sink.deliver(s.subject, s.pin);
    });
    let lock = Arc::new(PinLockService::start(
        PinLockFile::new(dir.path().join("pinlock.toml"), my_uid()),
        Limits {
            max_attempts: 2,
            lockout_secs: 600,
            max_lockout_secs: 86_400,
        },
    ));
    let memory = Arc::new(Memory::default());
    let service = serve_with_extras(
        Builder::address(daemon.address.as_str()),
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
    .expect("serve the Agent");
    World {
        daemon,
        _service: service,
        socket: socket_path,
        memory,
        id: pid("p1"),
        _dir: dir,
    }
}

/// Opens the prompt of `world` and subscribes to it.
async fn open(client: &zbus::Connection, world: &World) {
    call(
        client,
        "OpenPrompt",
        &(world.id.as_str(), i64::from(my_uid())),
    )
    .await
    .expect("open the prompt");
    call(client, "Subscribe", &(world.id.as_str(),))
        .await
        .expect("subscribe");
}

/// Announces one PIN and sends it.
async fn announce_and_send(client: &zbus::Connection, world: &World, pin: &[u8]) {
    call(client, "ExpectPin", &(world.id.as_str(),))
        .await
        .expect("expect a PIN");
    assert_eq!(send_pin(&world.socket, pin), REPLY_ACCEPTED);
}

/// The `(result, reason, seconds)` of the next `Result` signal.
async fn result_of(heard: &mut zbus::MessageStream) -> (String, String, u32) {
    let signal = next_within(heard, 5_000).await.expect("a Result signal");
    let (_prompt, result, reason, seconds): (String, String, String, u32) =
        signal.body().deserialize().expect("the signal");
    (result, reason, seconds)
}

#[test]
fn set_pin_enrols_the_user_and_set_pin_twice_is_refused() {
    run(async {
        let world = world().await;
        let client = connect(&world.daemon).await;
        open(&client, &world).await;
        let mut heard = signals(&client, "Result").await;

        // ChangePin needs a PIN to change.
        let early = call(&client, "ChangePin", &(world.id.as_str(),)).await;
        assert!(
            is_error(&early, "io.github.LinuxHello.Error.InvalidArgument"),
            "{early:?}"
        );

        call(&client, "SetPin", &(world.id.as_str(),))
            .await
            .expect("set a PIN");
        announce_and_send(&client, &world, b"123456").await;
        assert_eq!(
            result_of(&mut heard).await,
            ("success".to_string(), String::new(), 0)
        );
        assert!(world.memory.has_pin(my_uid()));

        let again = call(&client, "SetPin", &(world.id.as_str(),)).await;
        assert!(
            is_error(&again, "io.github.LinuxHello.Error.InvalidArgument"),
            "{again:?}"
        );
    });
}

#[test]
fn change_pin_needs_the_current_pin_and_counts_a_wrong_one() {
    run(async {
        let world = world().await;
        let client = connect(&world.daemon).await;
        open(&client, &world).await;
        let mut heard = signals(&client, "Result").await;
        world.memory.set(my_uid(), b"123456").unwrap();

        call(&client, "ChangePin", &(world.id.as_str(),))
            .await
            .expect("change the PIN");
        announce_and_send(&client, &world, b"000000").await;
        announce_and_send(&client, &world, b"567890").await;
        let first = result_of(&mut heard).await;
        assert_eq!(
            first,
            ("failure".to_string(), "not-recognised".to_string(), 0)
        );
        assert_eq!(world.memory.0.lock().unwrap()[&my_uid()], b"123456");

        call(&client, "ChangePin", &(world.id.as_str(),))
            .await
            .expect("change the PIN again");
        announce_and_send(&client, &world, b"123456").await;
        announce_and_send(&client, &world, b"567890").await;
        let second = result_of(&mut heard).await;
        assert_eq!(second.0, "success");
        assert_eq!(world.memory.0.lock().unwrap()[&my_uid()], b"567890");
    });
}

#[test]
fn a_pin_for_another_user_is_never_set() {
    run(async {
        let world = world().await;
        let client = connect(&world.daemon).await;
        // A prompt that is for another user: only that user's own call could set a PIN for it.
        let other = i64::from(my_uid()) + 1;
        let opened = call(&client, "OpenPrompt", &(world.id.as_str(), other)).await;
        if opened.is_ok() {
            let denied = call(&client, "SetPin", &(world.id.as_str(),)).await;
            assert!(
                is_error(&denied, "io.github.LinuxHello.Error.Denied")
                    || is_error(&denied, "io.github.LinuxHello.Error.InvalidArgument"),
                "{denied:?}"
            );
        }
        assert!(!world.memory.has_pin(my_uid() + 1));
    });
}

#[test]
fn set_pin_and_change_pin_are_listed_in_capabilities() {
    run(async {
        let world = world().await;
        let client = connect(&world.daemon).await;
        let reply = call(&client, "GetCapabilities", &())
            .await
            .expect("capabilities");
        let listed: (u32, Vec<String>) = reply.body().deserialize().expect("the reply");
        for member in ["SetPin", "ChangePin"] {
            assert!(
                listed.1.iter().any(|m| m == member),
                "{member} missing: {listed:?}"
            );
        }
    });
}
