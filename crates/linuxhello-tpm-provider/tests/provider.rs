//! The provider over its socket, with a software TPM behind it: what the Agent can do through the
//! client, who is served, and what happens to a client that sends nonsense.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use linuxhello_tpm_provider::client::{ClientError, TpmClient};
use linuxhello_tpm_provider::server::Server;
use linuxhello_tpm_provider::testing::SoftTpm;
use linuxhello_tpm_provider::wire::{encode_request, write_frame, Auth, Request, AUTH_BYTES};
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

/// Sets the dictionary-attack limit of the TPM to `tries` wrong authorisations, with the tools of
/// tpm2-tools; `None` when they are not installed or refuse, and then the test says it was skipped
/// (and fails where `LH_REQUIRE_SWTPM` is set).
fn set_max_tries(soft: &SoftTpm, tries: u32) -> Option<()> {
    let status = Command::new("tpm2_dictionarylockout")
        .args([
            "--setup-parameters".to_string(),
            format!("--max-tries={tries}"),
            "--recovery-time=1000".to_string(),
            "--lockout-recovery-time=1000".to_string(),
        ])
        .env(
            "TPM2TOOLS_TCTI",
            format!("swtpm:host=127.0.0.1,port={}", soft.port),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    status.success().then_some(())
}

/// Skips the test when the limit cannot be set, unless the environment says it must run.
fn limit_or_skip(soft: &SoftTpm, tries: u32) -> bool {
    if set_max_tries(soft, tries).is_some() {
        return true;
    }
    assert!(
        std::env::var("LH_REQUIRE_SWTPM").is_err(),
        "tpm2-tools are required here"
    );
    eprintln!("SKIPPED: tpm2_dictionarylockout is not installed or refused");
    false
}

#[test]
fn the_provider_does_not_ask_the_tpm_when_one_more_wrong_try_would_lock_it_for_everyone() {
    // #345, cause 2: the TPM keeps one counter of wrong tries for the whole machine, and a lockout
    // needs an administrator. The last try before the limit is never spent by the provider, so
    // nobody can drive the TPM into it, with a wrong PIN or with a loop of "four wrong, one right".
    let Some(soft) = SoftTpm::start() else { return };
    if !limit_or_skip(&soft, 4) {
        return;
    }
    let (path, _dir, _stop) = provider(&soft, me());
    let client = TpmClient::new(&path);
    let blobs = client.enrol(auth(1)).unwrap();
    for _ in 0..3 {
        assert_eq!(client.verify(blobs.clone(), auth(9)), Ok(false));
    }
    assert_eq!(
        soft.open().counters(),
        Ok((3, 4)),
        "three of four are spent"
    );
    // Even the right PIN is not tried, and a change, which checks the old PIN, is not either.
    assert_eq!(
        client.verify(blobs.clone(), auth(1)).err(),
        Some(ClientError::Failed)
    );
    assert_eq!(
        client.change_auth(blobs, auth(1), auth(2)).err(),
        Some(ClientError::Failed)
    );
    assert_eq!(
        soft.open().counters(),
        Ok((3, 4)),
        "nothing was spent, and the TPM is not locked"
    );
}

#[test]
fn a_refusal_to_ask_the_tpm_is_not_a_failure_of_the_tpm() {
    // Five refusals in a row must not end the provider, which stops after five failures of the TPM.
    let Some(soft) = SoftTpm::start() else { return };
    if !limit_or_skip(&soft, 3) {
        return;
    }
    let (path, _dir, _stop) = provider(&soft, me());
    let client = TpmClient::new(&path);
    let blobs = client.enrol(auth(1)).unwrap();
    assert_eq!(client.verify(blobs.clone(), auth(9)), Ok(false));
    assert_eq!(client.verify(blobs.clone(), auth(9)), Ok(false));
    for _ in 0..8 {
        assert_eq!(
            client.verify(blobs.clone(), auth(1)).err(),
            Some(ClientError::Failed)
        );
    }
    // Still serving, and still answering what does not count a try.
    assert_eq!(client.key_loads(blobs), Ok(true));
}

#[test]
fn a_request_whose_client_has_already_gone_is_not_asked_of_the_tpm() {
    // #345, cause 4: the Agent gives up after a time and closes the connection, but the provider
    // used to do the check later all the same, and the TPM counted a wrong try that the Agent never
    // recorded.
    let Some(soft) = SoftTpm::start() else { return };
    if !limit_or_skip(&soft, 4) {
        return;
    }
    let (path, _dir, _stop) = provider(&soft, me());
    let client = TpmClient::new(&path);
    let blobs = client.enrol(auth(1)).unwrap();
    {
        let mut gone = UnixStream::connect(&path).unwrap();
        let body = encode_request(&Request::Verify {
            blobs: blobs.clone(),
            auth: auth(9),
        })
        .unwrap();
        write_frame(&mut gone, &body).unwrap();
    } // closed before any answer
      // The provider serves one connection at a time, in order: this answer comes after it.
    assert!(client.limits().is_ok());
    assert_eq!(
        soft.open().counters(),
        Ok((0, 4)),
        "the abandoned try was not made"
    );
    // A client that waits for its answer is served as before.
    assert_eq!(client.verify(blobs, auth(9)), Ok(false));
    assert_eq!(soft.open().counters(), Ok((1, 4)));
}
