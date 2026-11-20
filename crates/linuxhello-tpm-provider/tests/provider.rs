//! The provider over its socket, with a software TPM behind it: what the Agent can do through the
//! client, who is served, and what happens to a client that sends nonsense.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use linuxhello_tpm_provider::client::{ClientError, TpmClient};
use linuxhello_tpm_provider::server::Server;
use linuxhello_tpm_provider::testing::SoftTpm;
use linuxhello_tpm_provider::wire::{Auth, AUTH_BYTES};
use zeroize::Zeroizing;

/// The group id of this test, which stands for the Agent's group.
fn my_gid() -> u32 {
    std::os::unix::fs::MetadataExt::gid(&std::fs::metadata("/proc/self").unwrap())
}

/// The user id of this test, which owns the directory and is "the Agent".
fn me() -> u32 {
    std::os::unix::fs::MetadataExt::uid(&std::fs::metadata("/proc/self").unwrap())
}

fn auth(b: u8) -> Auth {
    Zeroizing::new([b; AUTH_BYTES])
}

/// A provider serving user `agent_uid` on a thread; returns its socket path and what keeps it alive.
fn provider(soft: &SoftTpm, agent_uid: u32) -> (PathBuf, tempfile::TempDir, mpsc::Sender<()>) {
    let dir = private_tempdir();
    let path = dir.path().join("tpm.sock");
    let mut server = Server::bind(&path, me(), agent_uid, my_gid(), soft.open()).unwrap();
    let (stop, stopped) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        // Serve until the test drops its end; one connection at a time, as in production.
        while stopped.try_recv() != Err(mpsc::TryRecvError::Disconnected) {
            let _ = server.serve_one();
        }
    });
    (path, dir, stop)
}

#[test]
fn the_agent_enrols_verifies_and_changes_the_pin_through_the_socket() {
    let Some(soft) = SoftTpm::start() else { return };
    let (path, _dir, _stop) = provider(&soft, me());
    let client = TpmClient::new(&path);

    let blobs = client.enrol(auth(1)).unwrap();
    assert_eq!(client.verify(blobs.clone(), auth(1)), Ok(true));
    assert_eq!(client.verify(blobs.clone(), auth(2)), Ok(false));

    let changed = client.change_auth(blobs.clone(), auth(1), auth(2)).unwrap();
    assert_eq!(client.verify(changed.clone(), auth(2)), Ok(true));
    assert_eq!(client.verify(changed, auth(1)), Ok(false));
    // A wrong current PIN changes nothing.
    assert_eq!(
        client.change_auth(blobs, auth(9), auth(3)).err(),
        Some(ClientError::Failed)
    );
}

#[test]
fn the_agent_reads_the_tpms_limits_through_the_socket() {
    let Some(soft) = SoftTpm::start() else { return };
    let (path, _dir, _stop) = provider(&soft, me());
    let limits = TpmClient::new(&path).limits().unwrap();
    assert!(
        limits.max_tries > 0,
        "a TPM that never locks reports no limit here"
    );
    assert!(limits.interval_secs > 0 && limits.recovery_secs > 0);
}

#[test]
fn the_agent_asks_whether_a_key_still_loads_through_the_socket() {
    let Some(soft) = SoftTpm::start() else { return };
    let (path, _dir, _stop) = provider(&soft, me());
    let client = TpmClient::new(&path);
    let blobs = client.enrol(auth(1)).unwrap();
    assert_eq!(client.key_loads(blobs.clone()), Ok(true));
    // A damaged blob does not load; nothing was counted as a wrong PIN.
    let mut damaged = blobs.clone();
    let last = damaged.private.len() - 1;
    damaged.private[last] ^= 0xff;
    assert_eq!(client.key_loads(damaged), Ok(false));
    assert_eq!(client.verify(blobs, auth(1)), Ok(true));
}

#[test]
fn a_user_who_is_not_the_agent_is_not_served() {
    let Some(soft) = SoftTpm::start() else { return };
    // The provider serves another user id; this test's connection is refused by closing it.
    let (path, _dir, _stop) = provider(&soft, me() + 1);
    let client = TpmClient::new(&path);
    assert_eq!(client.enrol(auth(1)).err(), Some(ClientError::Failed));
}

#[test]
fn a_client_that_sends_nonsense_is_dropped_and_the_next_one_is_served() {
    let Some(soft) = SoftTpm::start() else { return };
    let (path, _dir, _stop) = provider(&soft, me());
    for nonsense in [
        vec![],
        vec![0, 0, 0, 0],
        vec![0, 0, 0, 5, 1, 2],
        vec![0xff, 0xff, 0xff, 0xff],
        vec![0, 0, 0, 3, 9, 0, 0],
        vec![0, 0, 0, 4, 1, 0, 1, 7],
    ] {
        let mut stream = UnixStream::connect(&path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        drop(stream.write_all(&nonsense));
        drop(stream.shutdown(std::net::Shutdown::Write));
        let mut answer = Vec::new();
        // The provider closes without an answer.
        assert_eq!(
            stream
                .read_to_end(&mut answer)
                .map(|_| answer.len())
                .unwrap_or(0),
            0
        );
    }
    let client = TpmClient::new(&path);
    assert!(client.enrol(auth(1)).is_ok(), "the provider still serves");
}

#[test]
fn a_provider_that_is_not_there_is_a_failure_not_a_hang() {
    let dir = private_tempdir();
    let client = TpmClient::new(dir.path().join("nothing.sock"));
    assert_eq!(
        client.verify(some_blobs(), auth(1)),
        Err(ClientError::Failed)
    );
}

/// Blobs for a call that never reaches a TPM.
fn some_blobs() -> linuxhello_tpm_provider::wire::Blobs {
    linuxhello_tpm_provider::wire::Blobs {
        public: vec![1],
        private: vec![2],
    }
}

#[test]
fn the_socket_is_open_to_the_agents_group_and_to_nobody_else() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Some(soft) = SoftTpm::start() else { return };
    let (path, _dir, _stop) = provider(&soft, me());
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o660,
        "no access for other users"
    );
    assert_eq!(meta.gid(), my_gid(), "the Agent's group owns it");
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
