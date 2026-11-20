//! The record of a user's PIN root key: what the Agent keeps so that a PIN can be checked
//! (ADR-0021, decision 2 and its amendment of 2026-11-19).
//!
//! In plain words: to check a PIN the Agent needs three things that are not secret: the salt that
//! was mixed into the user's PIN, the cost settings the PIN was stretched with, and the two blobs of
//! the user's root key that only the TPM can open. This module keeps them in one small file per
//! user, `pin-root.toml` in the user's directory of the Agent's state, mode 0600, owned by the
//! Agent's user.
//!
//! Besides these it keeps a short history: fingerprints of the PINs that were replaced, so that a
//! change cannot go back to a former PIN (ADR-0021, amendment of 2026-11-20). An entry is the PIN
//! stretched under a salt of its own, so it opens nothing.
//!
//! Fail closed: a missing file means the user has no PIN yet; a file that exists and cannot be
//! trusted (not a regular file, readable by others, owned by someone else, too large, not TOML, a
//! version or a salt that is not ours, stretching parameters outside the accepted range) is
//! refused, and is never replaced by an empty or a default record. A save writes a new file next to
//! the old one and renames it over, so a crash leaves the old record or the new one.
//!
//! C4 component: `pinManager` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use linuxhello_tpm_provider::wire::Blobs;
use serde::{Deserialize, Serialize};

use crate::pinkdf::{Params, SALT_BYTES};

/// The version of this record format and of the stretching scheme it says was used.
pub const VERSION: u32 = 1;

/// The name of the file in a user's directory.
const FILE_NAME: &str = "pin-root.toml";

/// The largest record that is read, in bytes. A larger file is not trusted.
const MAX_FILE_BYTES: u64 = 16 * 1024;

/// The most earlier PINs a record remembers, whatever the policy says (ADR-0021, amendment of
/// 2026-11-20, point 3).
pub const MAX_HISTORY: usize = 24;

/// A fingerprint of a PIN that was replaced: the Argon2id result of the PIN under a salt of its
/// own, never the salt of a root key, so it is not the authorisation value of any key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The cost the fingerprint was made with.
    pub params: Params,
    /// The random salt of this entry.
    pub salt: [u8; SALT_BYTES],
    /// The 32 bytes of the stretching.
    pub hash: [u8; 32],
}

/// What a user's PIN root key needs to be used again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinRecord {
    /// The cost the PIN was stretched with.
    pub params: Params,
    /// The salt that was mixed into the stretching.
    pub salt: [u8; SALT_BYTES],
    /// The blobs of the root key.
    pub blobs: Blobs,
    /// Fingerprints of the PINs that were replaced, newest first; at most [`MAX_HISTORY`].
    pub history: Vec<HistoryEntry>,
}

/// Why a record could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The file exists and cannot be trusted. The caller refuses the user's PIN; it does not start
    /// from an empty record.
    Untrusted,
}

/// The file as TOML: the numbers as numbers, the bytes as hexadecimal text.
#[derive(Serialize, Deserialize)]
struct FileText {
    /// The version of the format.
    version: u32,
    /// Argon2 memory in KiB.
    memory_kib: u32,
    /// Argon2 passes.
    passes: u32,
    /// Argon2 lanes.
    lanes: u32,
    /// The salt, in hexadecimal.
    salt: String,
    /// The public blob, in hexadecimal.
    public: String,
    /// The private blob, in hexadecimal.
    private: String,
    /// The history, newest first; a record written before it existed has none.
    #[serde(default)]
    history: Vec<HistoryText>,
}

/// A history entry as TOML.
#[derive(Serialize, Deserialize)]
struct HistoryText {
    /// Argon2 memory in KiB.
    memory_kib: u32,
    /// Argon2 passes.
    passes: u32,
    /// Argon2 lanes.
    lanes: u32,
    /// The salt, in hexadecimal.
    salt: String,
    /// The result, in hexadecimal.
    hash: String,
}

/// The records of every user, under one root directory with a directory per user id.
pub struct PinRecordStore {
    /// The directory that holds a directory per user (the user policy store's root).
    root: PathBuf,
    /// The user id that must own the files: the Agent's own.
    owner_uid: u32,
}

impl PinRecordStore {
    /// The store under `root`, whose files must be owned by `owner_uid`.
    pub fn new(root: impl Into<PathBuf>, owner_uid: u32) -> Self {
        Self {
            root: root.into(),
            owner_uid,
        }
    }

    /// The path of the record of `uid`.
    pub fn path(&self, uid: u32) -> PathBuf {
        self.root.join(uid.to_string()).join(FILE_NAME)
    }

    /// The record of `uid`: `None` when there is no file.
    ///
    /// # Errors
    ///
    /// [`RecordError::Untrusted`] when the file exists and cannot be trusted or read.
    pub fn load(&self, uid: u32) -> Result<Option<PinRecord>, RecordError> {
        let path = self.path(uid);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(RecordError::Untrusted),
        };
        let trusted = meta.is_file()
            && meta.uid() == self.owner_uid
            && meta.permissions().mode() & 0o077 == 0
            && meta.len() <= MAX_FILE_BYTES;
        if !trusted {
            return Err(RecordError::Untrusted);
        }
        let text = fs::read_to_string(&path).map_err(|_| RecordError::Untrusted)?;
        let parsed: FileText = toml::from_str(&text).map_err(|_| RecordError::Untrusted)?;
        let params = Params {
            memory_kib: parsed.memory_kib,
            passes: parsed.passes,
            lanes: parsed.lanes,
        };
        let salt: [u8; SALT_BYTES] = unhex(&parsed.salt)
            .and_then(|b| b.try_into().ok())
            .ok_or(RecordError::Untrusted)?;
        let (public, private) = (
            unhex(&parsed.public).ok_or(RecordError::Untrusted)?,
            unhex(&parsed.private).ok_or(RecordError::Untrusted)?,
        );
        if parsed.history.len() > MAX_HISTORY {
            return Err(RecordError::Untrusted);
        }
        let history = parsed
            .history
            .iter()
            .map(|entry| {
                let params = Params {
                    memory_kib: entry.memory_kib,
                    passes: entry.passes,
                    lanes: entry.lanes,
                };
                Some(HistoryEntry {
                    params,
                    salt: unhex(&entry.salt)?.try_into().ok()?,
                    hash: unhex(&entry.hash)?.try_into().ok()?,
                })
            })
            .collect::<Option<Vec<_>>>()
            .filter(|entries| entries.iter().all(|e| e.params.acceptable()))
            .ok_or(RecordError::Untrusted)?;
        if parsed.version != VERSION
            || !params.acceptable()
            || public.is_empty()
            || private.is_empty()
        {
            return Err(RecordError::Untrusted);
        }
        Ok(Some(PinRecord {
            params,
            salt,
            blobs: Blobs { public, private },
            history,
        }))
    }

    /// Writes the record of `uid`: a new file next to the old one with mode 0600, then a rename over
    /// it. The user's directory is made (mode 0700) when it is not there.
    ///
    /// # Errors
    ///
    /// The I/O error that stopped the write; the old record is then still there, unchanged.
    pub fn save(&self, uid: u32, record: &PinRecord) -> io::Result<()> {
        let path = self.path(uid);
        let dir = path.parent().expect("a record has a directory");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let text = toml::to_string(&FileText {
            version: VERSION,
            memory_kib: record.params.memory_kib,
            passes: record.params.passes,
            lanes: record.params.lanes,
            salt: hex(&record.salt),
            public: hex(&record.blobs.public),
            private: hex(&record.blobs.private),
            history: record
                .history
                .iter()
                .take(MAX_HISTORY)
                .map(|entry| HistoryText {
                    memory_kib: entry.params.memory_kib,
                    passes: entry.params.passes,
                    lanes: entry.params.lanes,
                    salt: hex(&entry.salt),
                    hash: hex(&entry.hash),
                })
                .collect(),
        })
        .map_err(io::Error::other)?;
        let temporary = dir.join(format!(".{FILE_NAME}.{}", std::process::id()));
        let result =
            write_new(&temporary, text.as_bytes()).and_then(|()| fs::rename(&temporary, &path));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

/// Writes `bytes` to a new file at `path`, mode 0600, and flushes it to the disk.
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The bytes of a hexadecimal text, or `None` for an odd length or a character that is not a digit.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests;
