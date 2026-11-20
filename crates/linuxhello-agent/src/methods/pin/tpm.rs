//! The PIN verifier backed by the TPM: the Agent stretches the PIN, the provider asks the TPM
//! (ADR-0021, decisions 2 and 3, spike 0011).
//!
//! In plain words: the PIN is never given to the TPM as typed, and the Agent never sees what the TPM
//! decides with. To check a PIN the Agent reads the user's record (salt, cost, key blobs), stretches
//! the PIN with them, and sends the 32 stretched bytes and the blobs to the provider; the TPM says
//! right or wrong. To set a PIN the first time it makes a salt, stretches, and asks the provider for
//! a key under that authorisation; to change it, the TPM changes the key's authorisation in place.
//!
//! What counts as "not a wrong PIN" matters for the PIN lock: a record that cannot be trusted, a
//! provider that does not answer, a TPM in lockout and a PIN that is not text are all *not* a wrong
//! PIN, so they are never counted against the user (`PinMethod` treats them as unavailable).
//!
//! C4 component: `pinVerifier` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use linuxhello_tpm_provider::client::{ClientError, TpmClient};
use linuxhello_tpm_provider::wire::Auth;
use zeroize::Zeroizing;

use super::enrol::PinEnrolment;
use super::{KeyProbe, PinVerifier, VerifyError};
use crate::pinkdf::{stretch, KdfError, Params, SALT_BYTES};
use crate::pinrecord::{HistoryEntry, PinRecord, PinRecordStore, RecordError, MAX_HISTORY};

/// Why a PIN could not be set or changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolError {
    /// The user already has a PIN (setting one is for the first time only).
    AlreadyEnrolled,
    /// The user has no PIN to change.
    NotEnrolled,
    /// The current PIN is wrong.
    WrongPin,
    /// The new PIN is the current one or one of the last PINs that were replaced.
    Reused,
    /// The PIN is empty, not text or too long.
    BadPin(KdfError),
    /// The record cannot be trusted or written.
    Record,
    /// The provider or the TPM did not do it.
    Tpm(ClientError),
}

/// The PIN verifier of a machine that has a TPM provider.
pub struct TpmVerifier {
    /// The users' records.
    records: PinRecordStore,
    /// The provider.
    client: TpmClient,
    /// The cost a new PIN is stretched with.
    params: Params,
}

impl TpmVerifier {
    /// A verifier over `records` and the provider at `socket`, stretching new PINs with
    /// [`Params::DEFAULT`].
    pub fn new(records: PinRecordStore, socket: impl Into<PathBuf>) -> Self {
        Self {
            records,
            client: TpmClient::new(socket),
            params: Params::DEFAULT,
        }
    }

    /// The same verifier stretching new PINs with `params`, for tests.
    #[must_use]
    pub fn with_params(self, params: Params) -> Self {
        Self { params, ..self }
    }

    /// Sets the PIN of `uid` for the first time.
    ///
    /// # Errors
    ///
    /// [`EnrolError`]; nothing is written unless the provider made the key.
    pub fn enrol(&self, uid: u32, pin: &[u8]) -> Result<(), EnrolError> {
        match self.records.load(uid) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(EnrolError::AlreadyEnrolled),
            Err(RecordError::Untrusted) => return Err(EnrolError::Record),
        }
        let salt = random_salt().ok_or(EnrolError::Record)?;
        let auth = authorisation(pin, &salt, &self.params).map_err(EnrolError::BadPin)?;
        let blobs = self.client.enrol(auth).map_err(EnrolError::Tpm)?;
        self.records
            .save(
                uid,
                &PinRecord {
                    params: self.params,
                    salt,
                    blobs,
                    history: Vec::new(),
                },
            )
            .map_err(|_| EnrolError::Record)
    }

    /// Changes the PIN of `uid` from `old` to `new` in place: the TPM changes the key's
    /// authorisation, a new salt is made, and the record is replaced. The new PIN may not be the
    /// current one nor one of the last `history` PINs that were replaced (at most
    /// [`MAX_HISTORY`]); the replaced PIN is then remembered as a fingerprint (ADR-0021, amendment
    /// of 2026-11-20).
    ///
    /// # Errors
    ///
    /// [`EnrolError`]; the record is replaced only after the TPM changed the key, and a wrong `old`
    /// changes nothing. [`EnrolError::Reused`] is answered only after the TPM has accepted `old`,
    /// so that nobody without the current PIN learns whether a PIN is a former one; a new PIN equal
    /// to the `old` one supplied is refused at once, which tells nothing about the real PIN.
    pub fn change_pin(
        &self,
        uid: u32,
        old: &[u8],
        new: &[u8],
        history: u32,
    ) -> Result<(), EnrolError> {
        let record = match self.records.load(uid) {
            Ok(Some(record)) => record,
            Ok(None) => return Err(EnrolError::NotEnrolled),
            Err(RecordError::Untrusted) => return Err(EnrolError::Record),
        };
        let old_auth =
            authorisation(old, &record.salt, &record.params).map_err(EnrolError::BadPin)?;
        // The same PIN as the one supplied as current, in whatever form: refused without the TPM.
        let again = authorisation(new, &record.salt, &record.params).map_err(EnrolError::BadPin)?;
        if same(&again, &old_auth) {
            return Err(EnrolError::Reused);
        }
        let keep = usize::try_from(history)
            .unwrap_or(MAX_HISTORY)
            .min(MAX_HISTORY);
        if keep > 0 && !record.history.is_empty() {
            // Only now is the history asked: the TPM must first accept the current PIN.
            match self.client.verify(record.blobs.clone(), old_auth.clone()) {
                Ok(true) => {}
                Ok(false) => return Err(EnrolError::WrongPin),
                Err(other) => return Err(EnrolError::Tpm(other)),
            }
            for entry in record.history.iter().take(keep) {
                let hash = stretch(new, &entry.salt, &entry.params).map_err(EnrolError::BadPin)?;
                if same(hash.as_bytes(), &entry.hash) {
                    return Err(EnrolError::Reused);
                }
            }
        }
        let new_salt = random_salt().ok_or(EnrolError::Record)?;
        let new_auth = authorisation(new, &new_salt, &self.params).map_err(EnrolError::BadPin)?;
        // The fingerprint of the PIN that is being replaced, under a salt that is not any key's.
        let remembered = if keep > 0 {
            let salt = random_salt().ok_or(EnrolError::Record)?;
            let hash = stretch(old, &salt, &record.params).map_err(EnrolError::BadPin)?;
            Some(HistoryEntry {
                params: record.params,
                salt,
                hash: *hash.as_bytes(),
            })
        } else {
            None
        };
        let blobs = self
            .client
            .change_auth(record.blobs, old_auth, new_auth)
            .map_err(|error| match error {
                // The TPM refuses a wrong current authorisation as any other refusal.
                ClientError::Failed => EnrolError::WrongPin,
                other => EnrolError::Tpm(other),
            })?;
        let history: Vec<HistoryEntry> = remembered
            .into_iter()
            .chain(record.history)
            .take(keep)
            .collect();
        self.records
            .save(
                uid,
                &PinRecord {
                    params: self.params,
                    salt: new_salt,
                    blobs,
                    history,
                },
            )
            .map_err(|_| EnrolError::Record)
    }
}

/// Whether two 32-byte values are equal, comparing every byte.
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b)
        .fold(0_u8, |difference, (x, y)| difference | (x ^ y))
        == 0
}

impl PinVerifier for TpmVerifier {
    fn available(&self, uid: u32) -> bool {
        matches!(self.records.load(uid), Ok(Some(_)))
    }

    fn verify(&self, uid: u32, pin: &[u8]) -> Result<bool, VerifyError> {
        let Ok(Some(record)) = self.records.load(uid) else {
            return Err(VerifyError);
        };
        let auth = authorisation(pin, &record.salt, &record.params).map_err(|_| VerifyError)?;
        self.client
            .verify(record.blobs, auth)
            .map_err(|_| VerifyError)
    }
}

/// The authorisation value for `pin`: stretched, in a wiped buffer.
fn authorisation(pin: &[u8], salt: &[u8; SALT_BYTES], params: &Params) -> Result<Auth, KdfError> {
    let stretched = stretch(pin, salt, params)?;
    Ok(Zeroizing::new(*stretched.as_bytes()))
}

/// A salt of random bytes from the system; `None` if it cannot be read. The bytes come from the
/// device and are collected, not written over a fixed array: a static analysis cannot then mistake a
/// zero-filled buffer for a hard-coded salt.
fn random_salt() -> Option<[u8; SALT_BYTES]> {
    let mut bytes = Vec::with_capacity(SALT_BYTES);
    File::open("/dev/urandom")
        .ok()?
        .take(SALT_BYTES as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    bytes.try_into().ok()
}

impl PinEnrolment for TpmVerifier {
    fn has_pin(&self, uid: u32) -> bool {
        matches!(self.records.load(uid), Ok(Some(_)))
    }

    fn set(&self, uid: u32, pin: &[u8]) -> Result<(), EnrolError> {
        self.enrol(uid, pin)
    }

    fn change(&self, uid: u32, old: &[u8], new: &[u8], history: u32) -> Result<(), EnrolError> {
        self.change_pin(uid, old, new, history)
    }
}

impl KeyProbe for TpmVerifier {
    fn key_loads(&self, uid: u32) -> Option<bool> {
        let Ok(Some(record)) = self.records.load(uid) else {
            return None;
        };
        self.client.key_loads(record.blobs).ok()
    }
}
