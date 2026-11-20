//! The TPM key service: a user's root key, a non-primary child of a storage primary, whose
//! authorisation is the stretched PIN (ADR-0021, spike 0011).
//!
//! In plain words: the TPM keeps a key for each user that only opens for that user's PIN. The PIN
//! never reaches this module as typed: the caller passes the 32 bytes it got from the stretching
//! function. The key itself is stored as two blobs on disk that only this TPM can open; this module
//! makes them, checks a PIN against them, and changes the PIN without making a new key.
//!
//! Why a child of a primary and not a primary: a primary key cannot have its authorisation changed
//! in place (spike 0011), and the PIN must be changeable without losing the keys under it.
//!
//! How a PIN is checked: the root key loads under the primary without its own authorisation; using
//! it as a parent (here: making a throwaway child) needs its authorisation, so the TPM itself
//! decides. A wrong PIN is refused by the TPM and counts in the TPM's own dictionary-attack
//! counter; the Agent keeps its own per-user counter in front of this (P-14) and never resets the
//! TPM's.
//!
//! How the PIN-derived value is kept off the TPM interface: every command that carries or proves an
//! authorisation value runs in a salted HMAC session with parameter encryption. The session key is
//! agreed by encrypting a random salt to the storage primary, so someone who records the bytes
//! between this process and the TPM cannot derive it. A value that is *sent* (a new key's, the new
//! value of a change) is encrypted with that key; a value that is *proved* (the current one) is only
//! the key of an HMAC and is never sent. A plain password session would put it on the interface
//! in clear (`tpm_sessions_encrypt_the_authorisation_value` and its control).
//!
//! Not here yet: persistent handles (the blobs are kept on disk, so a primary is made again,
//! identically, from the owner hierarchy's seed, when needed).
//!
//! C4 component: `tpmKeys` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::str::FromStr;

use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::constants::{PropertyTag, SessionType};
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, Private, Public, RsaExponent, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::utils::create_restricted_decryption_rsa_public;
use tss_esapi::{Context, TctiNameConf};

use crate::wire::TpmLimits;

pub use crate::wire::{Blobs, AUTH_BYTES};

/// Why a TPM operation did not give an answer about the PIN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TpmError {
    /// The TPM is in dictionary-attack lockout: it refuses every authorisation for a while,
    /// whatever the PIN is.
    Locked,
    /// Anything else: no TPM, a refused command, a damaged blob. The text is the TPM stack's own and
    /// carries no PIN.
    Failed(String),
}

/// A connection to a TPM, with the storage primary the root keys hang under.
pub struct Tpm {
    /// The TSS2 context.
    context: Context,
    /// The storage primary of the owner hierarchy.
    primary: KeyHandle,
}

impl Tpm {
    /// Connects to the TPM named by `tcti` (for example `device:/dev/tpmrm0` or
    /// `swtpm:host=127.0.0.1,port=2321`) and makes the storage primary. The same template gives the
    /// same primary every time, so nothing about it is stored.
    ///
    /// # Errors
    ///
    /// [`TpmError::Failed`] when there is no TPM or it refuses.
    pub fn open(tcti: &str) -> Result<Self, TpmError> {
        let tcti = TctiNameConf::from_str(tcti).map_err(failed)?;
        let mut context = Context::new(tcti).map_err(failed)?;
        let primary = context
            .execute_with_nullauth_session(|c| {
                c.create_primary(
                    Hierarchy::Owner,
                    storage_template()?,
                    None,
                    None,
                    None,
                    None,
                )
            })
            .map_err(failed)?
            .key_handle;
        Ok(Self { context, primary })
    }

    /// The limits the TPM reports for wrong authorisations. Only reads; changes nothing.
    ///
    /// # Errors
    ///
    /// [`TpmError::Failed`] when the TPM does not report a value.
    pub fn limits(&mut self) -> Result<TpmLimits, TpmError> {
        let mut read = |tag: PropertyTag, name: &str| -> Result<u32, TpmError> {
            self.context
                .get_tpm_property(tag)
                .map_err(classify)?
                .ok_or_else(|| TpmError::Failed(format!("the TPM does not report {name}")))
        };
        Ok(TpmLimits {
            max_tries: read(PropertyTag::MaxAuthFail, "its attempt limit")?,
            interval_secs: read(PropertyTag::LockoutInterval, "its lockout interval")?,
            recovery_secs: read(PropertyTag::LockoutRecovery, "its lockout recovery")?,
        })
    }

    /// Makes a root key whose authorisation is `auth`.
    ///
    /// # Errors
    ///
    /// [`TpmError`] when the TPM refuses.
    pub fn enrol(&mut self, auth: &[u8; AUTH_BYTES]) -> Result<Blobs, TpmError> {
        let auth = auth_of(auth)?;
        let primary = self.primary;
        let session = self.encrypted_session()?;
        let created = self.context.execute_with_session(Some(session), |c| {
            c.create(primary, storage_template()?, Some(auth), None, None, None)
        });
        self.end(session);
        let created = created.map_err(classify)?;
        blobs_of(&created.out_public, &created.out_private)
    }

    /// Whether `auth` is the authorisation of the root key in `blobs`. A wrong one is `Ok(false)` and
    /// counts in the TPM's dictionary-attack counter.
    ///
    /// # Errors
    ///
    /// [`TpmError::Locked`] while the TPM is in lockout; [`TpmError::Failed`] for a blob that does
    /// not load or any other refusal. Neither is a wrong PIN.
    pub fn verify(&mut self, blobs: &Blobs, auth: &[u8; AUTH_BYTES]) -> Result<bool, TpmError> {
        let key = self.load(blobs)?;
        let session = match self.encrypted_session() {
            Ok(session) => session,
            Err(error) => {
                let _ = self.context.flush_context(key.into());
                return Err(error);
            }
        };
        let outcome = self.use_as_parent(key, auth, session);
        let _ = self.context.flush_context(key.into());
        match outcome {
            Ok(()) => Ok(true),
            Err(error) if is_wrong_auth(&error) => Ok(false),
            Err(error) => Err(classify(error)),
        }
    }

    /// Changes the authorisation of the root key from `old` to `new` without making a new key; the
    /// keys under it keep loading. Returns the new blobs; the old ones still open with the old
    /// authorisation (deleting them is the only revocation, spike 0011).
    ///
    /// # Errors
    ///
    /// [`TpmError::Failed`] with a wrong `old` (the TPM refuses) or any other refusal;
    /// [`TpmError::Locked`] in lockout.
    pub fn change_auth(
        &mut self,
        blobs: &Blobs,
        old: &[u8; AUTH_BYTES],
        new: &[u8; AUTH_BYTES],
    ) -> Result<Blobs, TpmError> {
        let key = self.load(blobs)?;
        let primary = self.primary;
        let old = auth_of(old)?;
        let new = auth_of(new)?;
        let session = self.encrypted_session();
        let changed = session.and_then(|session| {
            let changed = self.context.tr_set_auth(key.into(), old).and_then(|()| {
                self.context.execute_with_session(Some(session), |c| {
                    c.object_change_auth(key.into(), primary.into(), new)
                })
            });
            self.end(session);
            changed.map_err(classify)
        });
        let _ = self.context.flush_context(key.into());
        let private = changed?;
        let public = Public::unmarshall(&blobs.public).map_err(failed)?;
        blobs_of(&public, &private)
    }

    /// Loads the root key of `blobs` under the primary.
    fn load(&mut self, blobs: &Blobs) -> Result<KeyHandle, TpmError> {
        let public = Public::unmarshall(&blobs.public).map_err(failed)?;
        let private = Private::try_from(blobs.private.clone()).map_err(failed)?;
        let primary = self.primary;
        self.context
            .execute_with_nullauth_session(|c| c.load(primary, private, public))
            .map_err(classify)
    }

    /// Uses the loaded root key as a parent, which needs its authorisation: makes a throwaway child
    /// and discards it.
    fn use_as_parent(
        &mut self,
        key: KeyHandle,
        auth: &[u8; AUTH_BYTES],
        session: AuthSession,
    ) -> Result<(), tss_esapi::Error> {
        let auth = Auth::try_from(auth.to_vec())?;
        self.context.tr_set_auth(key.into(), auth)?;
        let created = self
            .context
            .execute_with_session(Some(session), |c| {
                c.create(key, storage_template()?, None, None, None, None)
            })
            .map(|_| ());
        self.end(session);
        created
    }

    /// A salted HMAC session whose parameters are encrypted both ways, with AES-128 in CFB mode and
    /// SHA-256. The salt is encrypted to the storage primary, so the session key cannot be derived
    /// from what crosses the TPM interface. One session serves one command; [`Self::end`] removes it.
    fn encrypted_session(&mut self) -> Result<AuthSession, TpmError> {
        let session = self
            .context
            .start_auth_session(
                Some(self.primary),
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(classify)?
            .ok_or_else(|| TpmError::Failed("the TPM gave no session".to_string()))?;
        let (attributes, mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        self.context
            .tr_sess_set_attributes(session, attributes, mask)
            .map_err(failed)?;
        Ok(session)
    }

    /// Removes a session that a command did not consume (a refused command leaves it). An error is
    /// ignored: the TPM drops the oldest session when it runs out of slots.
    fn end(&mut self, session: AuthSession) {
        let handle: tss_esapi::handles::SessionHandle = session.into();
        let _ = self.context.flush_context(handle.into());
    }
}

/// The template of the primary and of the root keys: a restricted RSA 2048 storage key with AES-128
/// protection of what is under it, as the SRK is.
fn storage_template() -> Result<Public, tss_esapi::Error> {
    create_restricted_decryption_rsa_public(
        SymmetricDefinitionObject::AES_128_CFB,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
}

/// An authorisation value for the TPM. The TSS library wipes its own copy when it is dropped.
fn auth_of(auth: &[u8; AUTH_BYTES]) -> Result<Auth, TpmError> {
    Auth::try_from(auth.to_vec()).map_err(failed)
}

/// The two blobs of a key, marshalled.
fn blobs_of(public: &Public, private: &Private) -> Result<Blobs, TpmError> {
    Ok(Blobs {
        public: public.marshall().map_err(failed)?,
        private: private.to_vec(),
    })
}

/// Whether the TPM refused the authorisation (a wrong PIN) and not something else.
fn is_wrong_auth(error: &tss_esapi::Error) -> bool {
    matches!(
        error,
        tss_esapi::Error::Tss2Error(rc)
            if matches!(rc.kind(), Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth))
    )
}

/// A TPM stack error as a [`TpmError`]: lockout is told apart.
fn classify(error: tss_esapi::Error) -> TpmError {
    match &error {
        tss_esapi::Error::Tss2Error(rc) if rc.kind() == Some(Tss2ResponseCodeKind::Lockout) => {
            TpmError::Locked
        }
        _ => failed(error),
    }
}

/// Any error as [`TpmError::Failed`].
fn failed(error: impl std::fmt::Display) -> TpmError {
    TpmError::Failed(error.to_string())
}
