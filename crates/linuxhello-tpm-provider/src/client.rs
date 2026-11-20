//! The Agent's side of the conversation with the TPM provider: one request on a fresh connection to
//! its socket, and the answer.
//!
//! The client has no TPM code. It sends stretched authorisation values, never a PIN, and wipes them
//! when it is done. Every wait has a limit, so a provider that hangs makes the call fail and does
//! not hold a login.
//!
//! C4 component: `tpmProviderApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::wire::{
    decode_limits, decode_response, encode_request, read_frame, write_frame, Auth, Blobs, Request,
    TpmLimits, STATUS_LOCKED, STATUS_OK, STATUS_WRONG,
};

/// How long a call to the provider may take: a TPM command takes a fraction of a second, and a
/// busy chip a few.
const CALL_LIMIT: Duration = Duration::from_secs(15);

/// Why a call did not give an answer about the PIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// The TPM is in dictionary-attack lockout.
    Locked,
    /// The provider is not there, did not answer in time, answered nonsense, or the TPM refused for
    /// a reason other than a wrong PIN.
    Failed,
}

/// A client of the provider at a socket path.
pub struct TpmClient {
    /// The provider's socket.
    path: PathBuf,
}

impl TpmClient {
    /// A client of the provider listening at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Makes a root key whose authorisation is `auth`.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the provider or the TPM does not give a key.
    pub fn enrol(&self, auth: Auth) -> Result<Blobs, ClientError> {
        let answer = self.call(&Request::Enrol { auth })?;
        match (answer.status, answer.blobs) {
            (STATUS_OK, Some(blobs)) => Ok(blobs),
            (STATUS_LOCKED, _) => Err(ClientError::Locked),
            _ => Err(ClientError::Failed),
        }
    }

    /// Whether `auth` is the authorisation of the root key in `blobs`.
    ///
    /// # Errors
    ///
    /// [`ClientError::Locked`] in lockout, [`ClientError::Failed`] for anything that is not an
    /// answer about the PIN.
    pub fn verify(&self, blobs: Blobs, auth: Auth) -> Result<bool, ClientError> {
        match self.call(&Request::Verify { blobs, auth })?.status {
            STATUS_OK => Ok(true),
            STATUS_WRONG => Ok(false),
            STATUS_LOCKED => Err(ClientError::Locked),
            _ => Err(ClientError::Failed),
        }
    }

    /// Changes the authorisation of the root key in `blobs` from `old` to `new`; returns the new
    /// blobs.
    ///
    /// # Errors
    ///
    /// [`ClientError`]; a wrong `old` is [`ClientError::Failed`].
    pub fn change_auth(&self, blobs: Blobs, old: Auth, new: Auth) -> Result<Blobs, ClientError> {
        let answer = self.call(&Request::ChangeAuth { blobs, old, new })?;
        match (answer.status, answer.blobs) {
            (STATUS_OK, Some(blobs)) => Ok(blobs),
            (STATUS_LOCKED, _) => Err(ClientError::Locked),
            _ => Err(ClientError::Failed),
        }
    }

    /// The limits the TPM reports for wrong authorisations.
    ///
    /// # Errors
    ///
    /// [`ClientError::Locked`] in lockout, [`ClientError::Failed`] otherwise.
    pub fn limits(&self) -> Result<TpmLimits, ClientError> {
        let answer = self.exchange(&Request::Limits)?;
        match decode_limits(&answer) {
            Some(Ok(limits)) => Ok(limits),
            Some(Err(STATUS_LOCKED)) => Err(ClientError::Locked),
            _ => Err(ClientError::Failed),
        }
    }

    /// One request, one answer, on a fresh connection.
    fn call(&self, request: &Request) -> Result<crate::wire::Response, ClientError> {
        let answer = self.exchange(request)?;
        decode_response(&answer).ok_or(ClientError::Failed)
    }

    /// The body the provider answers to `request`, on a fresh connection.
    fn exchange(&self, request: &Request) -> Result<Vec<u8>, ClientError> {
        let body = encode_request(request).ok_or(ClientError::Failed)?;
        let mut stream = UnixStream::connect(&self.path).map_err(|_| ClientError::Failed)?;
        stream
            .set_read_timeout(Some(CALL_LIMIT))
            .and_then(|()| stream.set_write_timeout(Some(CALL_LIMIT)))
            .map_err(|_| ClientError::Failed)?;
        write_frame(&mut stream, &body).map_err(|_| ClientError::Failed)?;
        let answer = read_frame(&mut stream)
            .map_err(|_| ClientError::Failed)?
            .ok_or(ClientError::Failed)?;
        Ok(answer.to_vec())
    }
}
