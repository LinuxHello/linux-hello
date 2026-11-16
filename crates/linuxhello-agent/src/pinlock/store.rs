//! The file that keeps the PIN lockout records across a restart of the Agent.
//!
//! Without it, restarting the Agent (or crashing it) would clear every lockout. The file holds
//! the [`Record`]s of [`PinLock`] as TOML, one `[[record]]` per uid. The times in the records are
//! wall-clock seconds since the Unix epoch, so that they mean the same after a restart; the
//! caller passes the time in, as it does to [`PinLock`] (this module reads no clock).
//!
//! Collaborators: [`PinLock`] (the counter), the Agent's state directory (the file's place, mode
//! 0600, owned by the Agent's user).
//!
//! Fail closed (invariant 3): a missing file is a first start and gives an empty counter
//! (`a_missing_file_is_a_fresh_counter`); a file that exists but cannot be trusted (not a regular
//! file, readable by others, owned by someone else, too large, not TOML, records that
//! [`PinLock::restore`] refuses) gives [`PinLockError::BadRecords`] and the caller refuses every
//! attempt; it never starts from an empty counter (`a_file_that_cannot_be_trusted_refuses_every_attempt`).
//! A save writes a new file next to the old one and renames it over, so a crash leaves either the
//! old records or the new ones, never half of each (`save_replaces_the_file_with_mode_0600`).

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{PinLock, PinLockError, Record};

/// The largest lockout file that is read, in bytes. A larger file is not trusted.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// The file as TOML: a list of records.
#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileText {
    /// One entry per uid that has a record.
    #[serde(default)]
    record: Vec<FileRecord>,
}

/// One record as it is written in the file.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    /// The user the record belongs to.
    uid: u32,
    /// Wrong PINs counted since the last lockout started or the last correct PIN.
    failures: u32,
    /// Lockouts since the last correct PIN.
    lockouts: u32,
    /// The time, in seconds since the Unix epoch, before which the uid is refused.
    locked_until: u64,
}

/// The lockout file of the Agent.
#[derive(Clone, Debug)]
pub struct PinLockFile {
    /// Where the file is.
    path: PathBuf,
    /// The uid that must own the file: the Agent's own.
    owner_uid: u32,
}

impl PinLockFile {
    /// The lockout file at `path`, which must be owned by `owner_uid`.
    pub fn new(path: impl Into<PathBuf>, owner_uid: u32) -> Self {
        Self {
            path: path.into(),
            owner_uid,
        }
    }

    /// Rebuilds the counter from the file with the given settings.
    ///
    /// # Errors
    ///
    /// [`PinLockError::BadRecords`] when the file exists and cannot be trusted or read.
    pub fn load(
        &self,
        max_attempts: u32,
        lockout_secs: u64,
        max_lockout_secs: u64,
    ) -> Result<PinLock, PinLockError> {
        let records = self.read()?;
        PinLock::restore(max_attempts, lockout_secs, max_lockout_secs, records)
    }

    /// The records in the file: none when there is no file.
    fn read(&self) -> Result<Vec<Record>, PinLockError> {
        let meta = match fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(PinLockError::BadRecords),
        };
        let trusted = meta.is_file()
            && meta.uid() == self.owner_uid
            && meta.permissions().mode() & 0o077 == 0
            && meta.len() <= MAX_FILE_BYTES;
        if !trusted {
            return Err(PinLockError::BadRecords);
        }
        let text = fs::read_to_string(&self.path).map_err(|_| PinLockError::BadRecords)?;
        let parsed: FileText = toml::from_str(&text).map_err(|_| PinLockError::BadRecords)?;
        Ok(parsed
            .record
            .into_iter()
            .map(|r| Record {
                uid: r.uid,
                failures: r.failures,
                lockouts: r.lockouts,
                locked_until: r.locked_until,
            })
            .collect())
    }

    /// Writes the records of `lock` to the file: a new file next to it with mode 0600, then a
    /// rename over the old one.
    ///
    /// # Errors
    ///
    /// The I/O error that stopped the write; the old file is then still there, unchanged.
    pub fn save(&self, lock: &PinLock) -> io::Result<()> {
        let text = FileText {
            record: lock
                .records()
                .into_iter()
                .map(|r| FileRecord {
                    uid: r.uid,
                    failures: r.failures,
                    lockouts: r.lockouts,
                    locked_until: r.locked_until,
                })
                .collect(),
        };
        let body = toml::to_string(&text).map_err(io::Error::other)?;
        let temporary = self.temporary_path();
        let result = write_new_file(&temporary, body.as_bytes())
            .and_then(|()| fs::rename(&temporary, &self.path));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// The name of the file a save writes before it renames it over the real one.
    fn temporary_path(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".new");
        self.path.with_file_name(name)
    }
}

/// Creates `path` with mode 0600, writes `bytes` and syncs them to disk. A file that is already
/// there is removed first, so the mode is the one given here.
fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests;
