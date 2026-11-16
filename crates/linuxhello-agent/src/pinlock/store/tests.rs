//! Tests of the lockout file on temporary directories.

use super::*;
use tempfile::TempDir;

/// A directory with a file name in it and the uid that owns the directory.
fn setup() -> (TempDir, PinLockFile) {
    let tmp = TempDir::new().unwrap();
    let uid = fs::metadata(tmp.path()).unwrap().uid();
    let file = PinLockFile::new(tmp.path().join("pinlock.toml"), uid);
    (tmp, file)
}

/// A counter with three attempts and a lockout of 60 s, never above an hour.
fn counter() -> PinLock {
    PinLock::new(3, 60, 3600)
}

/// Loads with the settings of `counter`.
fn load(file: &PinLockFile) -> Result<PinLock, PinLockError> {
    file.load(3, 60, 3600)
}

#[test]
fn saved_records_are_read_back_after_a_restart() {
    let (_tmp, file) = setup();
    let mut lock = counter();
    for _ in 0..3 {
        lock.record_failure(1000, 10_000);
    }
    lock.record_failure(1001, 10_000);
    file.save(&lock).unwrap();

    // A restart: a new counter built only from the file.
    let restarted = load(&file).unwrap();
    assert_eq!(restarted.records(), lock.records());
    assert_eq!(
        restarted.check(1000, 10_030),
        Err(PinLockError::Locked {
            retry_after_secs: 30
        })
    );
    assert_eq!(restarted.check(1000, 10_061), Ok(()));
    // The other user's single failure was kept, and does not lock.
    assert_eq!(restarted.check(1001, 10_030), Ok(()));
}

#[test]
fn a_missing_file_is_a_fresh_counter() {
    let (_tmp, file) = setup();
    let lock = load(&file).unwrap();
    assert!(lock.records().is_empty());
}

#[test]
fn a_correct_pin_removes_the_record_from_the_file() {
    let (_tmp, file) = setup();
    let mut lock = counter();
    lock.record_failure(1000, 10_000);
    file.save(&lock).unwrap();
    lock.record_pin_success(1000);
    file.save(&lock).unwrap();
    assert!(load(&file).unwrap().records().is_empty());
}

#[test]
fn a_file_that_cannot_be_trusted_refuses_every_attempt() {
    let (tmp, file) = setup();
    let path = tmp.path().join("pinlock.toml");
    let write = |text: &str, mode: u32| {
        let _ = fs::remove_file(&path);
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    };
    let record = "[[record]]\nuid = 1000\nfailures = 1\nlockouts = 0\nlocked_until = 0\n";
    write(record, 0o600);
    assert!(load(&file).is_ok(), "the control case is trusted");

    write("this is not toml", 0o600);
    assert_eq!(load(&file).err(), Some(PinLockError::BadRecords));
    write(
        &record.replace("uid = 1000", "uid = 1000\nextra = 1"),
        0o600,
    );
    assert_eq!(load(&file).err(), Some(PinLockError::BadRecords));
    write(record, 0o644);
    assert_eq!(load(&file).err(), Some(PinLockError::BadRecords));
    // The same uid twice, and more failures than the limit allows: `restore` refuses both.
    write(&format!("{record}{record}"), 0o600);
    assert_eq!(load(&file).err(), Some(PinLockError::BadRecords));
    write(&record.replace("failures = 1", "failures = 3"), 0o600);
    assert_eq!(load(&file).err(), Some(PinLockError::BadRecords));
    // A file owned by someone else.
    write(record, 0o600);
    let other = PinLockFile::new(&path, file.owner_uid.wrapping_add(1));
    assert_eq!(load(&other).err(), Some(PinLockError::BadRecords));
    // A symbolic link, even to a good file.
    let target = tmp.path().join("target.toml");
    fs::write(&target, record).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert_eq!(load(&file).err(), Some(PinLockError::BadRecords));
    // A directory in its place.
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert_eq!(load(&file).err(), Some(PinLockError::BadRecords));
}

#[test]
fn save_replaces_the_file_with_mode_0600() {
    let (tmp, file) = setup();
    let path = tmp.path().join("pinlock.toml");
    let mut lock = counter();
    lock.record_failure(1000, 10_000);
    file.save(&lock).unwrap();
    // A second save, over a file that someone made world-readable.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    lock.record_failure(1000, 10_001);
    file.save(&lock).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(load(&file).unwrap().records(), lock.records());
    // The temporary file is gone: only the real file is left.
    let names: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["pinlock.toml"]);
}

#[test]
fn a_failed_save_leaves_the_old_file_unchanged() {
    let (tmp, file) = setup();
    let path = tmp.path().join("pinlock.toml");
    let mut lock = counter();
    lock.record_failure(1000, 10_000);
    file.save(&lock).unwrap();
    let before = fs::read_to_string(&path).unwrap();
    if fs::metadata(tmp.path()).unwrap().uid() == 0 {
        eprintln!("skipped: root can write into a directory without write permission");
        return;
    }
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o500)).unwrap();
    lock.record_failure(1000, 10_001);
    let saved = file.save(&lock);
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(saved.is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
}
