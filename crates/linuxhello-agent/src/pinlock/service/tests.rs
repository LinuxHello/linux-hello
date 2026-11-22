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
    let dir = crate::private_tempdir();
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
    let dir = crate::private_tempdir();
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
    let dir = crate::private_tempdir();
    let service = PinLockService::start(file_in(&dir), LIMITS);
    assert_eq!(service.status_of(1000, 5), LockStatus::Unlocked);
    assert_eq!(service.check(1000, 5), Ok(()));
}

#[test]
fn a_file_that_cannot_be_trusted_refuses_every_attempt_of_the_service() {
    let dir = crate::private_tempdir();
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
    let dir = crate::private_tempdir();
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
    let dir = crate::private_tempdir();
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
    let dir = crate::private_tempdir();
    let broken = admin_with(&dir, &[("10.toml", "this is not a policy")]);
    assert_eq!(limits_of(&broken), defaults);
}

#[test]
fn the_agents_limit_stays_below_the_tpms() {
    let policy = Limits {
        max_attempts: 5,
        ..LIMITS
    };
    // A TPM that locks after 3 tries: the Agent allows 1, so its own lockout acts first.
    assert_eq!(
        policy.capped_by_tpm(3),
        (
            Limits {
                max_attempts: 1,
                ..policy
            },
            Some(TpmCap {
                tpm_tries: 3,
                allowed: 1
            })
        )
    );
    // 8 tries: the Agent allows 4, below the policy's 5.
    assert_eq!(policy.capped_by_tpm(8).0.max_attempts, 4);
    // 10 tries: half is 5, the policy's own, so nothing changes.
    assert_eq!(policy.capped_by_tpm(10), (policy, None));
    // A TPM that allows more, or a policy that asks for less, is left alone.
    assert_eq!(policy.capped_by_tpm(200), (policy, None));
    assert_eq!(LIMITS.capped_by_tpm(4), (LIMITS, None));
    // A TPM that reports 0 or 1 never takes the limit below one try.
    assert_eq!(policy.capped_by_tpm(0).0.max_attempts, 1);
    assert_eq!(policy.capped_by_tpm(1).0.max_attempts, 1);
}

#[test]
fn a_capped_service_locks_at_the_lowered_limit_and_says_so() {
    let dir = crate::private_tempdir();
    let policy = Limits {
        max_attempts: 5,
        ..LIMITS
    };
    let service = PinLockService::start_capped(file_in(&dir), policy, Some(4));
    assert_eq!(
        service.tpm_cap(),
        Some(TpmCap {
            tpm_tries: 4,
            allowed: 2
        })
    );
    assert_eq!(service.record_failure(1000, 1_000), Ok(0));
    assert_eq!(
        service.record_failure(1000, 1_000),
        Ok(600),
        "locked at 2, not 5"
    );

    let uncapped = PinLockService::start_capped(file_in(&crate::private_tempdir()), policy, None);
    assert_eq!(uncapped.tpm_cap(), None);
}

#[test]
fn a_tpm_limit_that_arrives_later_still_caps_the_agents() {
    // The provider was not up when the Agent started, so the TPM's limit (here 4) was not known and
    // the policy's five stood. When it is known, the Agent's limit drops to two, a user who already
    // has two wrong PINs is locked, and a user with one is not (R-02, #345).
    let dir = crate::private_tempdir();
    let policy = Limits {
        max_attempts: 5,
        ..LIMITS
    };
    let service = PinLockService::start_capped(file_in(&dir), policy, None);
    assert!(!service.tpm_limit_known());
    assert_eq!(service.tpm_cap(), None);
    service.record_failure(1000, 1_000).unwrap();
    service.record_failure(1000, 1_000).unwrap();
    service.record_failure(1001, 1_000).unwrap();
    service.apply_tpm_limit(4, 1_000);
    assert_eq!(
        service.tpm_cap(),
        Some(TpmCap {
            tpm_tries: 4,
            allowed: 2
        })
    );
    assert_eq!(service.status_of(1000, 1_001), LockStatus::LockedFor(599));
    assert_eq!(service.status_of(1001, 1_001), LockStatus::Unlocked);
    // A limit that is not lower changes nothing.
    service.apply_tpm_limit(200, 1_000);
    assert_eq!(service.tpm_cap().map(|c| c.allowed), Some(2));
}
