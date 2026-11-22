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
    let dir = private_tempdir();
    let socket_path = dir.path().join("pin.sock");
    let socket = Arc::new(PinSocket::bind(&socket_path, my_uid()).unwrap());
    let inbox = Arc::new(PinInbox::default());
    let sink = Arc::clone(&inbox);
    PinSocket::serve_forever(Arc::clone(&socket), move |s| {
        sink.deliver_to(&s.target, s.pin);
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
    announce_and_send_on(client, &world.id, world, pin).await;
}

/// Announces one PIN for the prompt `id` and sends it. Both connections of a test are one process,
/// and the socket keeps one announcement per process, so each PIN is announced and sent before
/// the next is announced.
async fn announce_and_send_on(client: &zbus::Connection, id: &str, world: &World, pin: &[u8]) {
    call(client, "ExpectPin", &(id,))
        .await
        .expect("expect a PIN");
    assert_eq!(send_pin(&world.socket, pin), REPLY_ACCEPTED);
}

/// Opens the prompt `id` as `client` and subscribes to it.
async fn open_prompt(client: &zbus::Connection, id: &str) {
    call(client, "OpenPrompt", &(id, i64::from(my_uid())))
        .await
        .expect("open the prompt");
    call(client, "Subscribe", &(id,)).await.expect("subscribe");
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
fn a_pin_that_breaks_the_policys_character_rules_ends_in_failure_and_writes_nothing() {
    run(async {
        let world = world().await;
        let client = connect(&world.daemon).await;
        open(&client, &world).await;
        let mut heard = signals(&client, "Result").await;
        // The default policy requires a digit.
        call(&client, "SetPin", &(world.id.as_str(),))
            .await
            .expect("set a PIN");
        announce_and_send(&client, &world, b"abcdefgh").await;
        let outcome = result_of(&mut heard).await;
        assert_eq!(outcome.0, "failure");
        assert!(!world.memory.has_pin(my_uid()));
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

/// A temporary directory that only its owner can use, whatever the umask of the shell that runs the
/// tests (the code under test refuses a directory that others can write).
fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("a temporary directory")
}

#[test]
fn a_pin_typed_at_one_prompt_never_reaches_a_change_pin_on_another() {
    // Review finding R-01 (#344, P-46). V is the person's real prompt Y and has a PIN change
    // running (the way a settings page does); A is a program of the same user that opened prompt
    // X and started its own `ChangePin` after V's. The PINs V types at Y must reach Y and only Y.
    run(async {
        let world = world().await;
        let victim = connect(&world.daemon).await;
        let attacker = connect(&world.daemon).await;
        let (y, x) = (pid("a1"), pid("a2"));
        world.memory.set(my_uid(), b"123456").unwrap();
        open_prompt(&victim, &y).await;
        open_prompt(&attacker, &x).await;
        let mut heard_victim = signals(&victim, "Result").await;
        let mut heard_attacker = signals(&attacker, "Result").await;
        call(&victim, "ChangePin", &(y.as_str(),))
            .await
            .expect("V changes the PIN");
        call(&attacker, "ChangePin", &(x.as_str(),))
            .await
            .expect("A starts a change after V");

        // V types its current PIN and a new one at Y.
        announce_and_send_on(&victim, &y, &world, b"123456").await;
        announce_and_send_on(&victim, &y, &world, b"567890").await;
        assert_eq!(result_of(&mut heard_victim).await.0, "success");
        assert_eq!(world.memory.0.lock().unwrap()[&my_uid()], b"567890");
        // A heard nothing for X from V's PINs, and the PIN was never changed to one A chose.
        assert!(
            next_within(&mut heard_attacker, 500).await.is_none(),
            "A's job took a PIN that was typed at another prompt"
        );

        // A's own PINs, with a wrong current PIN, end X in a failure that counts one wrong PIN.
        announce_and_send_on(&attacker, &x, &world, b"000000").await;
        announce_and_send_on(&attacker, &x, &world, b"999999").await;
        assert_eq!(
            result_of(&mut heard_attacker).await,
            ("failure".to_string(), "not-recognised".to_string(), 0)
        );
        assert_eq!(world.memory.0.lock().unwrap()[&my_uid()], b"567890");
    });
}

#[test]
fn a_job_on_another_prompt_does_not_end_the_job_that_waits() {
    run(async {
        let world = world().await;
        let victim = connect(&world.daemon).await;
        let attacker = connect(&world.daemon).await;
        let (y, x) = (pid("b1"), pid("b2"));
        world.memory.set(my_uid(), b"123456").unwrap();
        open_prompt(&victim, &y).await;
        open_prompt(&attacker, &x).await;
        let mut heard_victim = signals(&victim, "Result").await;
        call(&victim, "ChangePin", &(y.as_str(),))
            .await
            .expect("V changes the PIN");
        // A starts a job on its own prompt and ends it again.
        call(&attacker, "ChangePin", &(x.as_str(),))
            .await
            .expect("A starts a change");
        call(&attacker, "ClosePrompt", &(x.as_str(),))
            .await
            .expect("A closes its prompt");
        async_io::Timer::after(Duration::from_millis(300)).await;

        // V's PINs still complete the change on Y.
        announce_and_send_on(&victim, &y, &world, b"123456").await;
        announce_and_send_on(&victim, &y, &world, b"567890").await;
        assert_eq!(result_of(&mut heard_victim).await.0, "success");
        assert_eq!(world.memory.0.lock().unwrap()[&my_uid()], b"567890");
    });
}
