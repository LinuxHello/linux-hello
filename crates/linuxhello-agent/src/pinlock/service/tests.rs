//! Tests of the Agent's PIN lock: restart, an untrusted file, the writer, and the limits.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::*;
use crate::policy::load;

/// Two wrong PINs start a lockout of ten minutes, never above a day.
const LIMITS: Limits = Limits {
    max_attempts: 2,
    lockout_secs: 600,
    max_lockout_secs: 86_400,
};

/// The uid of the test's own user, which owns the files it makes.
fn me() -> u32 {
    fs::metadata("/proc/self").unwrap().uid()
}

/// A lockout file in a temporary directory.
fn file_in(dir: &TempDir) -> PinLockFile {
    PinLockFile::new(dir.path().join("pinlock.toml"), me())
}

#[test]
fn a_lockout_survives_a_restart() {
    let dir = TempDir::new().unwrap();
    let first = PinLockService::start(file_in(&dir), LIMITS);
    assert_eq!(first.record_failure(1000, 1_000), Ok(0));
    assert_eq!(first.record_failure(1000, 1_000), Ok(600));
    // The writer saves what is pending when the service is dropped.
    drop(first);

    let second = PinLockService::start(file_in(&dir), LIMITS);
    assert_eq!(
        second.check(1000, 1_100),
        Err(PinLockError::Locked {
            retry_after_secs: 500
        })
    );
    assert_eq!(second.status_of(1000, 1_100), LockStatus::LockedFor(500));
    assert_eq!(second.status_of(1000, 1_600), LockStatus::Unlocked);
}

#[test]
fn a_correct_pin_is_saved_too() {
    let dir = TempDir::new().unwrap();
    let first = PinLockService::start(file_in(&dir), LIMITS);
    first.record_failure(1000, 1_000).unwrap();
    first.record_failure(1000, 1_000).unwrap();
    first.record_pin_success(1000).unwrap();
    drop(first);
    let second = PinLockService::start(file_in(&dir), LIMITS);
    assert_eq!(second.status_of(1000, 1_001), LockStatus::Unlocked);
}

#[test]
fn a_missing_file_is_a_first_start() {
    let dir = TempDir::new().unwrap();
    let service = PinLockService::start(file_in(&dir), LIMITS);
    assert_eq!(service.status_of(1000, 5), LockStatus::Unlocked);
    assert_eq!(service.check(1000, 5), Ok(()));
}

#[test]
fn a_file_that_cannot_be_trusted_refuses_every_attempt_of_the_service() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("pinlock.toml");
    fs::write(&path, "broken").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let service = PinLockService::start(file_in(&dir), LIMITS);
    assert_eq!(service.check(1000, 5), Err(PinLockError::BadRecords));
    assert_eq!(
        service.record_failure(1000, 5),
        Err(PinLockError::BadRecords)
    );
    assert_eq!(
        service.record_pin_success(1000),
        Err(PinLockError::BadRecords)
    );
    assert_eq!(service.status_of(1000, 5), LockStatus::Untrusted);
    drop(service);
    // Never replaced by an empty counter.
    assert_eq!(fs::read_to_string(&path).unwrap(), "broken");
}

#[test]
fn the_writer_does_not_block_the_caller() {
    let slow: Saver = Box::new(|_| {
        std::thread::sleep(Duration::from_secs(1));
        Ok(())
    });
    let service = PinLockService::with_saver(State::Trusted(PinLock::new(2, 600, 86_400)), slow);
    let started = Instant::now();
    assert_eq!(service.record_failure(1000, 1_000), Ok(0));
    assert_eq!(service.record_failure(1000, 1_000), Ok(600));
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "the callers waited {:?} for the disk",
        started.elapsed()
    );
}

#[test]
fn one_users_failures_do_not_show_in_another_users_status() {
    let dir = TempDir::new().unwrap();
    let service = PinLockService::start(file_in(&dir), LIMITS);
    service.record_failure(1000, 1_000).unwrap();
    service.record_failure(1000, 1_000).unwrap();
    assert_eq!(service.status_of(1000, 1_001), LockStatus::LockedFor(599));
    assert_eq!(service.status_of(1001, 1_001), LockStatus::Unlocked);
}

/// An admin directory owned by the test's user, with `files` in it.
fn admin_with(dir: &TempDir, files: &[(&str, &str)]) -> std::path::PathBuf {
    let admin = dir.path().join("policy.d");
    fs::create_dir(&admin).unwrap();
    fs::set_permissions(&admin, fs::Permissions::from_mode(0o755)).unwrap();
    for (name, text) in files {
        let path = admin.join(name);
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    admin
}

/// The limits of the admin layers alone.
fn limits_of(admin: &Path) -> Limits {
    Limits::from_policy(&load(
        admin,
        Path::new("/nonexistent/linuxhello/policy.toml"),
        me(),
    ))
}

#[test]
fn limits_come_from_the_admin_layers() {
    let dir = TempDir::new().unwrap();
    let admin = admin_with(
        &dir,
        &[(
            "10.toml",
            "[pin]\nlockout_attempts = 3\nlockout_minutes = 10\n",
        )],
    );
    assert_eq!(
        limits_of(&admin),
        Limits {
            max_attempts: 3,
            lockout_secs: 600,
            max_lockout_secs: 86_400
        }
    );
}

#[test]
fn limits_are_the_defaults_without_an_admin_file_and_in_the_pin_only_state() {
    let defaults = Limits {
        max_attempts: 5,
        lockout_secs: 900,
        max_lockout_secs: 86_400,
    };
    assert_eq!(
        limits_of(Path::new("/nonexistent/linuxhello/policy.d")),
        defaults
    );
    let dir = TempDir::new().unwrap();
    let broken = admin_with(&dir, &[("10.toml", "this is not a policy")]);
    assert_eq!(limits_of(&broken), defaults);
}
