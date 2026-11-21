//! The PIN method: waits for the PIN of the user who signs in, checks the PIN lock, asks the
//! verifier, and counts the answer (ADR-0023 amendment 2026-11-19 second part, ADR-0021).
//!
//! In plain words: the PIN does not travel through this module's caller. It arrives on the Agent's
//! PIN socket, from the process that announced it with `ExpectPin`; the socket hands it to the
//! [`PinInbox`], which gives it to the PIN method that is waiting for that user. The method then:
//!
//! The method is registered in the inbox from the moment it is made, so that a PIN sent right after
//! the call that started the authentication is kept for it and not lost.
//!
//! 1. asks the PIN lock whether the user may try (a locked user is refused *before* the PIN
//!    reaches the verifier, so a locked user cannot be used to guess),
//! 2. asks the [`PinVerifier`], which stretches the PIN and checks it against the TPM,
//! 3. counts a wrong PIN in the lock, and ends the attempt: a success, a failure, or locked out.
//!
//! The verifier is a trait because the TPM side is not built yet: until it is, the Agent has a
//! verifier that says it is unavailable, and the PIN method is never offered. A PIN is only ever
//! held in [`Zeroizing`] buffers, and the method never logs it.
//!
//! C4 component: `methodOrch` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use linuxhello_dbus::{AuthMethod, PromptReason};
use zeroize::Zeroizing;

use crate::orchestrator::{Cancel, Method, MethodEnd};
use crate::pinlock::service::PinLockService;
use crate::pinlock::PinLockError;

/// How often a waiting method looks at the cancel flag.
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// Why a PIN could not be checked at all (as opposed to being wrong).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyError;

/// Checks a PIN. The real one stretches it and asks the TPM; none exists yet.
pub trait PinVerifier: Send + Sync {
    /// Whether PINs can be checked at all now (the TPM is there and the user has a PIN).
    fn available(&self, uid: u32) -> bool;

    /// Whether `pin` is the PIN of `uid`.
    ///
    /// # Errors
    ///
    /// [`VerifyError`] when it could not be checked; that is neither right nor wrong.
    fn verify(&self, uid: u32, pin: &[u8]) -> Result<bool, VerifyError>;
}

/// Whether a user's PIN key is still in the TPM, for the status (`tpm-cleared`).
pub trait KeyProbe: Send + Sync {
    /// `Some(false)` when the user has a PIN record but the TPM does not hold the key (it was
    /// cleared or replaced, or the record is damaged); `Some(true)` when it does; `None` when there
    /// is no record, or the TPM cannot be asked (nothing is claimed then).
    fn key_loads(&self, uid: u32) -> Option<bool>;

    /// When the PIN of `uid` was last set or changed, in seconds since the Unix epoch, for the
    /// expiry codes of the status (ADR-0021, amendment of 2026-11-21). `None` when the user has no
    /// record or it cannot be trusted: then no expiry is reported.
    fn pin_changed_at(&self, _uid: u32) -> Option<u64> {
        None
    }
}

/// The verifier of an Agent that has no way to check a PIN yet: always unavailable.
pub struct NoVerifier;

impl PinVerifier for NoVerifier {
    fn available(&self, _uid: u32) -> bool {
        false
    }

    fn verify(&self, _uid: u32, _pin: &[u8]) -> Result<bool, VerifyError> {
        Err(VerifyError)
    }
}

/// Where the PIN socket hands a PIN to the method that waits for it, by the user it is for.
#[derive(Default)]
pub struct PinInbox {
    /// The methods that are waiting, by subject.
    waiting: Mutex<HashMap<u32, Sender<Zeroizing<Vec<u8>>>>>,
}

impl PinInbox {
    /// Hands `pin` to the method that waits for `subject`. Returns whether there was one; if not,
    /// the PIN is dropped (and wiped) here.
    pub fn deliver(&self, subject: u32, pin: Zeroizing<Vec<u8>>) -> bool {
        let sender = self
            .waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&subject)
            .cloned();
        sender.is_some_and(|sender| sender.send(pin).is_ok())
    }

    /// Registers a method that waits for `subject`; the registration ends with the returned guard.
    pub(crate) fn expect(
        self: &Arc<Self>,
        subject: u32,
    ) -> (Waiting, Receiver<Zeroizing<Vec<u8>>>) {
        let (sender, receiver) = channel();
        self.waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(subject, sender);
        (
            Waiting {
                inbox: Arc::clone(self),
                subject,
            },
            receiver,
        )
    }
}

/// A registration in the inbox; dropping it removes it.
pub(crate) struct Waiting {
    /// The inbox it is in.
    inbox: Arc<PinInbox>,
    /// Who the method waits for.
    subject: u32,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.inbox
            .waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.subject);
    }
}

/// The PIN method for one user.
pub struct PinMethod {
    /// The user being authenticated.
    subject: u32,
    /// The registration in the inbox, which lasts as long as the method does.
    _registration: Waiting,
    /// Where the PIN for this method arrives.
    receiver: Receiver<Zeroizing<Vec<u8>>>,
    /// The per-user counter of wrong PINs.
    lock: Arc<PinLockService>,
    /// What decides whether a PIN is right.
    verifier: Arc<dyn PinVerifier>,
    /// The time in seconds since the Unix epoch.
    clock: fn() -> u64,
}

impl PinMethod {
    /// The method for `subject`. It starts waiting for a PIN at once, not when it runs: a client
    /// may send the PIN as soon as its call to start the authentication has returned, which is
    /// before the orchestrator has started this method on its thread. The registration ends when
    /// the method is dropped, and replaces an older one for the same user.
    pub fn new(
        subject: u32,
        inbox: Arc<PinInbox>,
        lock: Arc<PinLockService>,
        verifier: Arc<dyn PinVerifier>,
        clock: fn() -> u64,
    ) -> Self {
        let (registration, receiver) = inbox.expect(subject);
        Self {
            subject,
            _registration: registration,
            receiver,
            lock,
            verifier,
            clock,
        }
    }

    /// What a PIN that arrived comes to.
    fn judge(&self, pin: &Zeroizing<Vec<u8>>) -> MethodEnd {
        let now = (self.clock)();
        match self.lock.check(self.subject, now) {
            Ok(()) => {}
            Err(PinLockError::Locked { retry_after_secs }) => {
                return MethodEnd::LockedOut(u32::try_from(retry_after_secs).unwrap_or(u32::MAX));
            }
            Err(PinLockError::BadRecords) => return MethodEnd::Unavailable,
        }
        match self.verifier.verify(self.subject, pin) {
            Ok(true) => match self.lock.record_pin_success(self.subject) {
                Ok(()) => MethodEnd::Success,
                Err(_) => MethodEnd::Unavailable,
            },
            Ok(false) => match self.lock.record_failure(self.subject, now) {
                Ok(0) => MethodEnd::Failure(PromptReason::NotRecognised),
                Ok(seconds) => MethodEnd::LockedOut(u32::try_from(seconds).unwrap_or(u32::MAX)),
                Err(_) => MethodEnd::Unavailable,
            },
            Err(VerifyError) => MethodEnd::Unavailable,
        }
    }
}

impl Method for PinMethod {
    fn kind(&self) -> AuthMethod {
        AuthMethod::Pin
    }

    fn available(&self) -> bool {
        self.verifier.available(self.subject)
    }

    fn run(&mut self, cancel: &Cancel) -> MethodEnd {
        loop {
            if cancel.is_cancelled() {
                return MethodEnd::Cancelled;
            }
            match self.receiver.recv_timeout(CANCEL_POLL) {
                Ok(pin) => return self.judge(&pin),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return MethodEnd::Unavailable,
            }
        }
    }
}

pub mod enrol;
pub mod tpm;

#[cfg(test)]
mod tests;
