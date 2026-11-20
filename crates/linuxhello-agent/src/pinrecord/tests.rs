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
    }
}

fn store(dir: &TempDir) -> PinRecordStore {
    PinRecordStore::new(dir.path(), me())
}

#[test]
fn a_saved_record_comes_back_and_is_private() {
    let dir = TempDir::new().unwrap();
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
    let dir = TempDir::new().unwrap();
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
    let dir = TempDir::new().unwrap();
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
    let dir = TempDir::new().unwrap();
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
