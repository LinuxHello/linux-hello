//! The PIN verifier on a real stack: the Agent's stretching and record, the provider over its socket,
//! and a software TPM 2.0 behind it. Without `swtpm` the tests say so and return; with
//! `LH_REQUIRE_SWTPM=1` its absence is a failure.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};

use linuxhello_agent::methods::pin::tpm::{EnrolError, TpmVerifier};
use linuxhello_agent::methods::pin::{KeyProbe, PinInbox, PinMethod, PinVerifier, VerifyError};
use linuxhello_agent::orchestrator::{Cancel, Method, MethodEnd};
use linuxhello_agent::pinkdf::Params;
use linuxhello_agent::pinlock::service::{Limits, PinLockService};
use linuxhello_agent::pinlock::store::PinLockFile;
use linuxhello_agent::pinrecord::PinRecordStore;
use linuxhello_agent::pinsocket::PinTarget;
use linuxhello_tpm_provider::client::TpmClient;
use linuxhello_tpm_provider::server::Server;
use linuxhello_tpm_provider::testing::SoftTpm;

/// The user id of this test: "the Agent", who owns every file.
fn me() -> u32 {
    std::fs::metadata("/proc/self").unwrap().uid()
}

/// The group id of this test, which stands for the Agent's group.
fn my_gid() -> u32 {
    std::fs::metadata("/proc/self").unwrap().gid()
}

/// A provider on a thread over a software TPM, and a verifier of this test's "Agent" that uses it.
struct Stack {
    verifier: TpmVerifier,
    records: PathBuf,
    /// The provider's socket.
    socket: PathBuf,
    _soft: SoftTpm,
    _dir: tempfile::TempDir,
    _stop: mpsc::Sender<()>,
}

fn stack() -> Option<Stack> {
    let soft = SoftTpm::start()?;
    let dir = private_tempdir();
    let socket = dir.path().join("tpm.sock");
    let records = dir.path().join("users");
    let mut server = Server::bind(&socket, me(), me(), my_gid(), soft.open()).unwrap();
    let (stop, stopped) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        while stopped.try_recv() != Err(mpsc::TryRecvError::Disconnected) {
            let _ = server.serve_one();
        }
    });
    let verifier =
        TpmVerifier::new(PinRecordStore::new(&records, me()), &socket).with_params(Params::MINIMUM);
    Some(Stack {
        verifier,
        records,
        socket,
        _soft: soft,
        _dir: dir,
        _stop: stop,
    })
}

#[test]
fn a_pin_is_set_and_then_checked_by_the_tpm() {
    let Some(s) = stack() else { return };
    assert!(!s.verifier.available(1000), "no PIN yet");
    assert_eq!(s.verifier.verify(1000, b"1234"), Err(VerifyError));
    s.verifier.enrol(1000, b"1234").unwrap();
    assert!(s.verifier.available(1000));
    assert_eq!(s.verifier.verify(1000, b"1234"), Ok(true));
    assert_eq!(s.verifier.verify(1000, b"1235"), Ok(false));
    assert_eq!(
        s.verifier.verify(1000, b"1234"),
        Ok(true),
        "a wrong try changes nothing"
    );
    // Another user has no PIN, and this one's does not open for them.
    assert!(!s.verifier.available(1001));
    assert_eq!(s.verifier.verify(1001, b"1234"), Err(VerifyError));
}

#[test]
fn the_same_pin_typed_in_another_form_is_the_same_pin() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, "１２３４".as_bytes()).unwrap();
    assert_eq!(s.verifier.verify(1000, b"1234"), Ok(true));
}

#[test]
fn the_record_holds_a_salt_and_no_pin() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"hunter22").unwrap();
    let path = s.records.join("1000").join("pin-root.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("hunter22"));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // Two users with the same PIN get different salts and different blobs.
    s.verifier.enrol(1001, b"hunter22").unwrap();
    let other = std::fs::read_to_string(s.records.join("1001").join("pin-root.toml")).unwrap();
    let salt = |t: &str| {
        t.lines()
            .find(|l| l.starts_with("salt"))
            .unwrap()
            .to_string()
    };
    assert_ne!(salt(&text), salt(&other));
}

#[test]
fn a_second_enrolment_is_refused_and_changes_nothing() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"1234").unwrap();
    assert_eq!(
        s.verifier.enrol(1000, b"9999"),
        Err(EnrolError::AlreadyEnrolled)
    );
    assert_eq!(s.verifier.verify(1000, b"1234"), Ok(true));
    assert_eq!(s.verifier.verify(1000, b"9999"), Ok(false));
}

#[test]
fn a_pin_that_cannot_be_stretched_is_refused_before_anything_is_written() {
    let Some(s) = stack() else { return };
    assert!(matches!(
        s.verifier.enrol(1000, b""),
        Err(EnrolError::BadPin(_))
    ));
    assert!(matches!(
        s.verifier.enrol(1000, &[0xff, 0xfe]),
        Err(EnrolError::BadPin(_))
    ));
    assert!(!s.verifier.available(1000));
    assert!(!s.records.join("1000").join("pin-root.toml").exists());
}

#[test]
fn the_pin_changes_in_place_with_a_new_salt() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"old-pin").unwrap();
    let path = s.records.join("1000").join("pin-root.toml");
    let before = std::fs::read_to_string(&path).unwrap();
    s.verifier
        .change_pin(1000, b"old-pin", b"new-pin", 0)
        .unwrap();
    assert_eq!(s.verifier.verify(1000, b"new-pin"), Ok(true));
    assert_eq!(s.verifier.verify(1000, b"old-pin"), Ok(false));
    assert_ne!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "a new salt and new blobs"
    );
}

#[test]
fn a_wrong_current_pin_changes_nothing() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"old-pin").unwrap();
    let path = s.records.join("1000").join("pin-root.toml");
    let before = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        s.verifier.change_pin(1000, b"not-it", b"new-pin", 0),
        Err(EnrolError::WrongPin)
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    assert_eq!(s.verifier.verify(1000, b"old-pin"), Ok(true));
    assert_eq!(
        s.verifier.change_pin(1001, b"x", b"y", 0),
        Err(EnrolError::NotEnrolled)
    );
}

#[test]
fn a_record_that_cannot_be_trusted_is_never_replaced_or_used() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"1234").unwrap();
    let path = s.records.join("1000").join("pin-root.toml");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!s.verifier.available(1000));
    assert_eq!(s.verifier.verify(1000, b"1234"), Err(VerifyError));
    assert_eq!(s.verifier.enrol(1000, b"1234"), Err(EnrolError::Record));
    assert_eq!(
        s.verifier.change_pin(1000, b"1234", b"5678", 0),
        Err(EnrolError::Record)
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644,
        "untouched"
    );
}

#[test]
fn a_provider_that_is_not_there_is_not_a_wrong_pin() {
    let dir = private_tempdir();
    let verifier = TpmVerifier::new(
        PinRecordStore::new(dir.path().join("users"), me()),
        dir.path().join("none.sock"),
    )
    .with_params(Params::MINIMUM);
    assert!(matches!(
        verifier.enrol(1000, b"1234"),
        Err(EnrolError::Tpm(_))
    ));
    assert!(!verifier.available(1000), "no record was written");
}

#[test]
fn a_provider_that_goes_away_is_not_a_wrong_pin_when_a_pin_is_checked() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"1234").unwrap();
    // The same records, with nobody behind the socket.
    let dir = private_tempdir();
    let down = TpmVerifier::new(
        PinRecordStore::new(&s.records, me()),
        dir.path().join("none.sock"),
    )
    .with_params(Params::MINIMUM);
    assert!(down.available(1000), "the record is there");
    // Neither right nor wrong: the PIN lock must not count it.
    assert_eq!(down.verify(1000, b"1234"), Err(VerifyError));
    assert_eq!(down.verify(1000, b"wrong"), Err(VerifyError));
}

#[test]
fn a_change_with_no_provider_is_not_a_wrong_pin() {
    // R-18, #360: with the default history of zero the change went straight to the TPM, and the
    // client's answer for a missing provider was read as a wrong current PIN, which counts.
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"1234").unwrap();
    let dir = private_tempdir();
    let down = TpmVerifier::new(
        PinRecordStore::new(&s.records, me()),
        dir.path().join("none.sock"),
    )
    .with_params(Params::MINIMUM);
    for pin in [&b"1234"[..], b"wrong"] {
        assert!(
            matches!(
                down.change_pin(1000, pin, b"5678", 0),
                Err(EnrolError::Tpm(_))
            ),
            "{pin:?}: a provider that is down is a fault, not a wrong PIN"
        );
    }
    // The control: with the provider back, a wrong current PIN is a wrong PIN.
    assert_eq!(
        s.verifier.change_pin(1000, b"wrong", b"5678", 0),
        Err(EnrolError::WrongPin)
    );
}

/// The record as text, for what a test must not find in it.
fn record_text(s: &Stack) -> String {
    std::fs::read_to_string(s.records.join("1000").join("pin-root.toml")).unwrap()
}

#[test]
fn a_replaced_pin_cannot_be_used_again_within_the_history() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"pin-one").unwrap();
    s.verifier
        .change_pin(1000, b"pin-one", b"pin-two", 2)
        .unwrap();
    s.verifier
        .change_pin(1000, b"pin-two", b"pin-three", 2)
        .unwrap();
    // The last two replaced PINs and the current one are refused.
    for (current, new) in [
        (&b"pin-three"[..], &b"pin-two"[..]),
        (b"pin-three", b"pin-one"),
        (b"pin-three", b"pin-three"),
    ] {
        assert_eq!(
            s.verifier.change_pin(1000, current, new, 2),
            Err(EnrolError::Reused),
            "{}",
            String::from_utf8_lossy(new)
        );
    }
    assert_eq!(
        s.verifier.verify(1000, b"pin-three"),
        Ok(true),
        "nothing changed"
    );
    // One more change pushes the oldest out of a history of two.
    s.verifier
        .change_pin(1000, b"pin-three", b"pin-four", 2)
        .unwrap();
    s.verifier
        .change_pin(1000, b"pin-four", b"pin-one", 2)
        .unwrap();
    assert_eq!(s.verifier.verify(1000, b"pin-one"), Ok(true));
}

#[test]
fn with_no_history_only_the_current_pin_is_refused() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"pin-one").unwrap();
    assert_eq!(
        s.verifier.change_pin(1000, b"pin-one", b"pin-one", 0),
        Err(EnrolError::Reused)
    );
    s.verifier
        .change_pin(1000, b"pin-one", b"pin-two", 0)
        .unwrap();
    s.verifier
        .change_pin(1000, b"pin-two", b"pin-one", 0)
        .unwrap();
    assert!(
        !record_text(&s).contains("[[history]]"),
        "nothing is remembered"
    );
}

#[test]
fn the_same_pin_in_another_form_is_the_same_pin() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"1234").unwrap();
    assert_eq!(
        s.verifier
            .change_pin(1000, b"1234", "１２３４".as_bytes(), 0),
        Err(EnrolError::Reused)
    );
}

#[test]
fn the_history_is_only_asked_after_the_current_pin_is_right() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"pin-one").unwrap();
    s.verifier
        .change_pin(1000, b"pin-one", b"pin-two", 3)
        .unwrap();
    // A wrong current PIN gets the same answer whether or not the new PIN is a former one.
    assert_eq!(
        s.verifier.change_pin(1000, b"wrong", b"pin-one", 3),
        Err(EnrolError::WrongPin)
    );
    assert_eq!(
        s.verifier.change_pin(1000, b"wrong", b"brand-new", 3),
        Err(EnrolError::WrongPin)
    );
}

#[test]
fn the_history_never_holds_a_key_authorisation_or_a_pin() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"pin-one").unwrap();
    let first = record_text(&s);
    let key_salt = |t: &str| {
        t.lines()
            .find(|l| l.starts_with("salt"))
            .unwrap()
            .to_string()
    };
    s.verifier
        .change_pin(1000, b"pin-one", b"pin-two", 3)
        .unwrap();
    let text = record_text(&s);
    assert!(text.contains("[[history]]"));
    assert!(!text.contains("pin-one") && !text.contains("pin-two"));
    // The entry's salt is not the salt of the old key nor of the new one.
    let entry_salt = text
        .split("[[history]]")
        .nth(1)
        .unwrap()
        .lines()
        .find(|l| l.starts_with("salt"))
        .unwrap()
        .to_string();
    assert_ne!(entry_salt, key_salt(&first));
    assert_ne!(entry_salt, key_salt(&text));
}

#[test]
fn a_change_that_fails_leaves_the_history_alone() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"pin-one").unwrap();
    s.verifier
        .change_pin(1000, b"pin-one", b"pin-two", 3)
        .unwrap();
    let before = record_text(&s);
    assert_eq!(
        s.verifier.change_pin(1000, b"wrong", b"pin-three", 3),
        Err(EnrolError::WrongPin)
    );
    assert_eq!(
        s.verifier.change_pin(1000, b"pin-two", b"pin-one", 3),
        Err(EnrolError::Reused)
    );
    assert_eq!(record_text(&s), before);
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

/// The time of the test below: second 1000.
fn at_1000() -> u64 {
    1_000
}

#[test]
fn one_users_failed_pins_cannot_lock_out_another_user() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"pin-of-a").unwrap();
    s.verifier.enrol(1001, b"pin-of-b").unwrap();
    // The Agent's limit as the Agent derives it: the policy asks for five, the TPM allows what it
    // allows (the software TPM's default is three) and the Agent keeps its own limit below it.
    let tpm_tries = TpmClient::new(&s.socket).limits().unwrap().max_tries;
    let (limits, _) = Limits {
        max_attempts: 5,
        lockout_secs: 600,
        max_lockout_secs: 86_400,
    }
    .capped_by_tpm(tpm_tries);
    let dir = private_tempdir();
    let lock = Arc::new(PinLockService::start(
        PinLockFile::new(dir.path().join("pinlock.toml"), me()),
        limits,
    ));
    let inbox = Arc::new(PinInbox::default());
    let verifier: Arc<dyn PinVerifier> = Arc::new(
        TpmVerifier::new(PinRecordStore::new(&s.records, me()), &s.socket)
            .with_params(Params::MINIMUM),
    );
    let prompt_of = |uid: u32, n: u8| PinTarget {
        opener: uid,
        prompt: linuxhello_dbus::PromptId::parse(&format!("{n:064x}")).unwrap(),
    };
    let (prompt_a, prompt_b) = (prompt_of(1000, 1), prompt_of(1001, 2));
    let mut method_a = PinMethod::for_prompt(
        1000,
        prompt_a.clone(),
        &inbox,
        Arc::clone(&lock),
        Arc::clone(&verifier),
        at_1000,
    )
    .unwrap();
    let mut method_b = PinMethod::for_prompt(
        1001,
        prompt_b.clone(),
        &inbox,
        Arc::clone(&lock),
        Arc::clone(&verifier),
        at_1000,
    )
    .unwrap();
    // User A keeps guessing, far more often than the TPM would stand.
    let mut reached_the_tpm = 0;
    let mut stopped_by_the_agent = false;
    for _ in 0..(tpm_tries + 5) {
        assert!(inbox.deliver_to(&prompt_a, zeroize::Zeroizing::new(b"wrong-guess".to_vec())));
        match method_a.run(&Cancel::default()) {
            MethodEnd::Failure(_) => reached_the_tpm += 1,
            MethodEnd::LockedOut(_) => {
                stopped_by_the_agent = true;
                break;
            }
            other => panic!("unexpected end: {other:?}"),
        }
    }
    assert!(stopped_by_the_agent, "the Agent's own counter must stop A");
    assert!(
        reached_the_tpm < tpm_tries,
        "A made {reached_the_tpm} wrong tries at a TPM that locks everybody at {tpm_tries}"
    );
    // B's right PIN still opens B's key: the TPM is not locked out.
    assert!(inbox.deliver_to(&prompt_b, zeroize::Zeroizing::new(b"pin-of-b".to_vec())));
    assert_eq!(method_b.run(&Cancel::default()), MethodEnd::Success);
}

#[test]
fn a_pin_key_that_the_tpm_does_not_hold_is_told_apart_from_a_key_that_it_does() {
    let (Some(first), Some(second)) = (stack(), stack()) else {
        return;
    };
    // No record: nothing is claimed.
    assert_eq!(first.verifier.key_loads(1000), None);
    first.verifier.enrol(1000, b"pin-one").unwrap();
    assert_eq!(first.verifier.key_loads(1000), Some(true));
    // The same record on a machine whose TPM is another one (a cleared TPM has a new seed).
    let theirs = second.records.join("1000");
    std::fs::create_dir_all(&theirs).unwrap();
    std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::copy(
        first.records.join("1000").join("pin-root.toml"),
        theirs.join("pin-root.toml"),
    )
    .unwrap();
    assert_eq!(second.verifier.key_loads(1000), Some(false));
    // Nothing was counted as a wrong PIN: the TPM still answers normally.
    assert_eq!(second.verifier.verify(1000, b"pin-one"), Err(VerifyError));
    assert_eq!(first.verifier.verify(1000, b"pin-one"), Ok(true));
}

#[test]
fn a_provider_that_is_not_there_claims_nothing_about_the_key() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"pin-one").unwrap();
    let dir = private_tempdir();
    let down = TpmVerifier::new(
        PinRecordStore::new(&s.records, me()),
        dir.path().join("none.sock"),
    );
    assert_eq!(down.key_loads(1000), None, "unknown is not cleared");
}

#[test]
fn an_expired_pin_still_signs_in() {
    let Some(s) = stack() else { return };
    s.verifier.enrol(1000, b"1234").unwrap();
    let store = PinRecordStore::new(&s.records, me());
    let mut record = store.load(1000).unwrap().unwrap();
    assert_eq!(
        s.verifier.pin_changed_at(1000),
        Some(record.changed_at),
        "the status reads the record's time"
    );
    // Set on 1970-01-01: expired under any policy, and still the key's authorisation.
    record.changed_at = 0;
    store.save(1000, &record).unwrap();
    assert_eq!(s.verifier.pin_changed_at(1000), Some(0));
    assert_eq!(s.verifier.verify(1000, b"1234"), Ok(true));
    assert_eq!(s.verifier.pin_changed_at(1001), None, "no record, no time");
}

/// A PIN of user 1000 that the record says was set at `changed_at`.
fn enrolled_at(s: &Stack, pin: &[u8], changed_at: u64) -> PinRecordStore {
    s.verifier.enrol(1000, pin).unwrap();
    let store = PinRecordStore::new(&s.records, me());
    let mut record = store.load(1000).unwrap().unwrap();
    record.changed_at = changed_at;
    store.save(1000, &record).unwrap();
    store
}

#[test]
fn a_change_starts_the_count_again() {
    let Some(s) = stack() else { return };
    let store = enrolled_at(&s, b"old-pin", 0);
    let before = linuxhello_agent::pinrecord::now_unix();
    s.verifier
        .change_pin(1000, b"old-pin", b"new-pin", 0)
        .unwrap();
    let changed_at = store.load(1000).unwrap().unwrap().changed_at;
    assert!(changed_at >= before, "{changed_at} < {before}");
}

#[test]
fn a_change_that_fails_keeps_the_old_time() {
    let Some(s) = stack() else { return };
    let store = enrolled_at(&s, b"old-pin", 12_345);
    assert_eq!(
        s.verifier.change_pin(1000, b"not-it", b"new-pin", 0),
        Err(EnrolError::WrongPin)
    );
    assert_eq!(store.load(1000).unwrap().unwrap().changed_at, 12_345);
}
