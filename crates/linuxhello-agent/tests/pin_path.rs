//! The whole PIN path on a real private bus and a real socket, with a verifier whose answers are
//! scripted: `Authenticate`, `ExpectPin`, the PIN on the socket, the PIN lock and the result.
//! The TPM side does not exist yet; what is real here is everything in front of it.

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::{call, connect, my_uid, next_within, pid, run, signals, Daemon};
use linuxhello_agent::bus::{serve_with_extras, Extras, MethodFactory};
use linuxhello_agent::methods::pin::{PinInbox, PinMethod, PinVerifier, VerifyError};
use linuxhello_agent::pinlock::service::{wall_clock_seconds, Limits, PinLockService};
use linuxhello_agent::pinlock::store::PinLockFile;
use linuxhello_agent::pinsocket::{PinSocket, REPLY_ACCEPTED};
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;
use zbus::connection::Builder;

/// A verifier that says whether the PIN is `1234`.
struct Right1234;

impl PinVerifier for Right1234 {
    fn available(&self, _uid: u32) -> bool {
        true
    }

    fn verify(&self, _uid: u32, pin: &[u8]) -> Result<bool, VerifyError> {
        Ok(pin == b"1234")
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

/// The Agent with the PIN path wired as `main` does, and a client that has opened a prompt.
struct World {
    /// Keeps the bus alive.
    daemon: Daemon,
    /// Keeps the service alive.
    _service: zbus::Connection,
    /// The PIN socket path.
    socket: std::path::PathBuf,
    /// The prompt.
    id: String,
    /// The directory of every file of the test.
    _dir: tempfile::TempDir,
}

async fn world() -> World {
    let daemon = Daemon::start();
    let dir = tempfile::TempDir::new().unwrap();
    let socket_path = dir.path().join("pin.sock");
    let socket = Arc::new(PinSocket::bind(&socket_path, my_uid()).unwrap());
    let inbox = Arc::new(PinInbox::default());
    let sink_inbox = Arc::clone(&inbox);
    PinSocket::serve_forever(Arc::clone(&socket), move |s| {
        sink_inbox.deliver(s.subject, s.pin);
    });
    let limits = Limits {
        max_attempts: 2,
        lockout_secs: 600,
        max_lockout_secs: 86_400,
    };
    let lock = Arc::new(PinLockService::start(
        PinLockFile::new(dir.path().join("pinlock.toml"), my_uid()),
        limits,
    ));
    let verifier: Arc<dyn PinVerifier> = Arc::new(Right1234);
    let methods: MethodFactory = {
        let (inbox, lock) = (Arc::clone(&inbox), Arc::clone(&lock));
        Arc::new(move |subject| {
            vec![Box::new(PinMethod::new(
                subject,
                Arc::clone(&inbox),
                Arc::clone(&lock),
                Arc::clone(&verifier),
                wall_clock_seconds,
            ))]
        })
    };
    let service = serve_with_extras(
        Builder::address(daemon.address.as_str()),
        Config::new(vec![]),
        Some(UserPolicyStore::new(dir.path().join("users"))),
        Extras {
            pin_socket: Some(socket),
            pin_lock: Some(lock),
            methods: Some(methods),
            ..Extras::default()
        },
    )
    .await
    .expect("serve the Agent");
    World {
        daemon,
        _service: service,
        socket: socket_path,
        id: pid("p1"),
        _dir: dir,
    }
}

/// Opens the prompt, starts the authentication, announces a PIN and sends `pin`; returns the
/// socket's reply and the `Result` signal's `(result, reason, seconds)`.
async fn sign_in_with(
    client: &zbus::Connection,
    world: &World,
    pin: &[u8],
) -> (u8, (String, String, u32)) {
    let mut heard = signals(client, "Result").await;
    call(client, "Authenticate", &(world.id.as_str(), "login"))
        .await
        .expect("authenticate");
    call(client, "ExpectPin", &(world.id.as_str(),))
        .await
        .expect("expect a PIN");
    let reply = send_pin(&world.socket, pin);
    let signal = next_within(&mut heard, 5_000)
        .await
        .expect("a Result signal");
    let (_prompt, result, reason, seconds): (String, String, String, u32) =
        signal.body().deserialize().expect("the signal");
    (reply, (result, reason, seconds))
}

#[test]
fn the_right_pin_signs_in() {
    run(async {
        let world = world().await;
        let client = connect(&world.daemon).await;
        call(
            &client,
            "OpenPrompt",
            &(world.id.as_str(), i64::from(my_uid())),
        )
        .await
        .expect("open the prompt");
        call(&client, "Subscribe", &(world.id.as_str(),))
            .await
            .expect("subscribe");
        let (reply, result) = sign_in_with(&client, &world, b"1234").await;
        assert_eq!(reply, REPLY_ACCEPTED);
        assert_eq!(result, ("success".to_string(), String::new(), 0));
    });
}

#[test]
fn wrong_pins_fail_and_then_lock_the_user_and_the_status_says_so() {
    run(async {
        let world = world().await;
        let client = connect(&world.daemon).await;
        call(
            &client,
            "OpenPrompt",
            &(world.id.as_str(), i64::from(my_uid())),
        )
        .await
        .expect("open the prompt");
        call(&client, "Subscribe", &(world.id.as_str(),))
            .await
            .expect("subscribe");

        let (_, first) = sign_in_with(&client, &world, b"0000").await;
        assert_eq!(
            first,
            ("failure".to_string(), "not-recognised".to_string(), 0)
        );
        let (_, second) = sign_in_with(&client, &world, b"0000").await;
        assert_eq!(second.0, "locked-out");
        assert_eq!(second.2, 600);

        // Locked: even the right PIN is refused, with the seconds left.
        let (_, third) = sign_in_with(&client, &world, b"1234").await;
        assert_eq!(third.0, "locked-out");
        assert!(third.2 > 0 && third.2 <= 600, "{third:?}");

        // And the user is told so in the status, in whole minutes.
        let reply = call(&client, "GetStatus", &()).await.expect("status");
        let status: Vec<(String, String, String)> = reply.body().deserialize().expect("the reply");
        assert_eq!(status.len(), 1, "{status:?}");
        assert_eq!(status[0].0, "pin-locked");
        assert!(
            status[0].2.starts_with("Your PIN is locked for "),
            "{status:?}"
        );
    });
}
