//! Tests of the PIN record store: what is saved comes back, and what cannot be trusted is refused.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use tempfile::TempDir;

use super::*;

fn me() -> u32 {
    fs::metadata("/proc/self").unwrap().uid()
}

fn record() -> PinRecord {
    PinRecord {
        params: Params::MINIMUM,
        salt: [7; SALT_BYTES],
        blobs: Blobs {
            public: vec![1, 2, 3, 250],
            private: vec![9; 200],
        },
        history: Vec::new(),
    }
}

fn entry(byte: u8) -> HistoryEntry {
    HistoryEntry {
        params: Params::MINIMUM,
        salt: [byte; SALT_BYTES],
        hash: [byte.wrapping_add(1); 32],
    }
}

fn store(dir: &TempDir) -> PinRecordStore {
    PinRecordStore::new(dir.path(), me())
}

#[test]
fn a_saved_record_comes_back_and_is_private() {
    let dir = crate::private_tempdir();
    let store = store(&dir);
    assert_eq!(store.load(1000), Ok(None), "no file is no PIN yet");
    store.save(1000, &record()).unwrap();
    assert_eq!(store.load(1000), Ok(Some(record())));
    let meta = fs::metadata(store.path(1000)).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(store.path(1000).parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    // Another user has none.
    assert_eq!(store.load(1001), Ok(None));
}

#[test]
fn a_save_replaces_the_record_and_leaves_nothing_behind() {
    let dir = crate::private_tempdir();
    let store = store(&dir);
    store.save(1000, &record()).unwrap();
    let mut newer = record();
    newer.salt = [8; SALT_BYTES];
    store.save(1000, &newer).unwrap();
    assert_eq!(store.load(1000), Ok(Some(newer)));
    let names: Vec<_> = fs::read_dir(dir.path().join("1000"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["pin-root.toml"]);
}

#[test]
fn a_record_that_cannot_be_trusted_is_refused_and_left_alone() {
    let dir = crate::private_tempdir();
    let store = store(&dir);
    store.save(1000, &record()).unwrap();
    let path = store.path(1000);
    let good = fs::read_to_string(&path).unwrap();

    // Readable by others.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(store.load(1000), Err(RecordError::Untrusted));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        store.load(1000),
        Ok(Some(record())),
        "and trusted again when private"
    );

    // Damaged in each field, one at a time.
    for (from, to) in [
        ("version = 1", "version = 2"),
        ("salt = \"07", "salt = \"zz"),
        ("memory_kib = 16384", "memory_kib = 1"),
        ("passes = 2", "passes = 0"),
        ("lanes = 1", "lanes = 99"),
    ] {
        assert!(good.contains(from), "{from} is in {good}");
        fs::write(&path, good.replace(from, to)).unwrap();
        assert_eq!(store.load(1000), Err(RecordError::Untrusted), "{to}");
    }
    for broken in ["", "not toml", "version = 1\n"] {
        fs::write(&path, broken).unwrap();
        assert_eq!(store.load(1000), Err(RecordError::Untrusted), "{broken:?}");
    }
    // Too large, a directory, a symbolic link.
    fs::write(&path, vec![b'#'; 20_000]).unwrap();
    assert_eq!(store.load(1000), Err(RecordError::Untrusted));
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert_eq!(store.load(1000), Err(RecordError::Untrusted));
    fs::remove_dir(&path).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
    assert_eq!(store.load(1000), Err(RecordError::Untrusted));
}

#[test]
fn a_file_owned_by_someone_else_is_refused() {
    let dir = crate::private_tempdir();
    let store = PinRecordStore::new(dir.path(), me() + 1);
    store.save(1000, &record()).unwrap();
    assert_eq!(store.load(1000), Err(RecordError::Untrusted));
}

#[test]
fn hexadecimal_round_trips_and_refuses_bad_text() {
    assert_eq!(unhex(&hex(&[0, 1, 254, 255])), Some(vec![0, 1, 254, 255]));
    assert_eq!(unhex(""), Some(vec![]));
    assert_eq!(unhex("abc"), None);
    assert_eq!(unhex("zz"), None);
    assert_eq!(unhex("é1"), None);
}

#[test]
fn a_history_comes_back_in_order() {
    let dir = TempDir::new().unwrap();
    let store = store(&dir);
    let mut with = record();
    with.history = vec![entry(3), entry(2), entry(1)];
    store.save(1000, &with).unwrap();
    assert_eq!(store.load(1000), Ok(Some(with)));
}

#[test]
fn an_old_record_without_a_history_is_read() {
    let dir = TempDir::new().unwrap();
    let store = store(&dir);
    store.save(1000, &record()).unwrap();
    // A record from before the history existed has no such key at all.
    let text = fs::read_to_string(store.path(1000)).unwrap();
    assert!(!text.contains("history") || text.contains("history = []"));
    let stripped: String = text
        .lines()
        .filter(|l| !l.starts_with("history"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(store.path(1000), stripped).unwrap();
    assert_eq!(store.load(1000), Ok(Some(record())));
}

#[test]
fn a_record_with_a_malformed_history_is_untrusted() {
    let dir = TempDir::new().unwrap();
    let store = store(&dir);
    let mut with = record();
    with.history = vec![entry(1)];
    store.save(1000, &with).unwrap();
    let good = fs::read_to_string(store.path(1000)).unwrap();
    let hash = hex(&entry(1).hash);
    let salt = hex(&entry(1).salt);
    for broken in [
        good.replace(&hash, "zz"),
        good.replace(&hash, &hash[2..]),
        good.replace(&salt, &salt[2..]),
    ] {
        if broken == good {
            continue;
        }
        fs::write(store.path(1000), &broken).unwrap();
        assert_eq!(store.load(1000), Err(RecordError::Untrusted), "{broken}");
    }
}

#[test]
fn an_entry_with_parameters_outside_the_accepted_range_is_untrusted() {
    let dir = TempDir::new().unwrap();
    let store = store(&dir);
    let mut with = record();
    let mut weak = entry(1);
    weak.params = Params {
        memory_kib: 8,
        passes: 1,
        lanes: 1,
    };
    with.history = vec![weak];
    store.save(1000, &with).unwrap();
    assert_eq!(store.load(1000), Err(RecordError::Untrusted));
}

#[test]
fn more_entries_than_the_limit_are_untrusted_and_a_save_never_writes_them() {
    let dir = TempDir::new().unwrap();
    let store = store(&dir);
    let mut with = record();
    with.history = (0..40).map(|b| entry(b as u8)).collect();
    store.save(1000, &with).unwrap();
    let loaded = store.load(1000).unwrap().unwrap();
    assert_eq!(loaded.history.len(), MAX_HISTORY);
}
