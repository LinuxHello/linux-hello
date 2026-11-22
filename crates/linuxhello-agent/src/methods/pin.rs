//! The PIN method: waits for the PIN of the user who signs in, checks the PIN lock, asks the
//! verifier, and counts the answer (ADR-0023 amendment 2026-11-19 second part, ADR-0021).
//!
//! In plain words: the PIN does not travel through this module's caller. It arrives on the Agent's
//! PIN socket, from the process that announced it with `ExpectPin`; the socket hands it to the
//! [`PinInbox`], which gives it to the PIN method that is waiting on the prompt the PIN was
//! announced for. The method then:
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use linuxhello_dbus::{AuthMethod, PromptReason};
use zeroize::Zeroizing;

use crate::orchestrator::{Cancel, Method, MethodEnd};
use crate::pinlock::service::PinLockService;
use crate::pinlock::PinLockError;
use crate::pinsocket::PinTarget;

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

    /// Whether `uid` has a PIN record, and when it was set, for `GetPinState` (ADR-0027, point 1).
    /// The default reads [`KeyProbe::pin_changed_at`] and cannot tell a damaged record from none.
    fn pin_record(&self, uid: u32) -> PinRecordState {
        self.pin_changed_at(uid)
            .map_or(PinRecordState::Absent, PinRecordState::Set)
    }
}

/// What the Agent knows about a user's PIN record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinRecordState {
    /// The user has no PIN record.
    Absent,
    /// The user has a record; the PIN was set or last changed at this time, in seconds since the
    /// Unix epoch.
    Set(u64),
    /// A record exists but cannot be read or trusted.
    Damaged,
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

/// One wait: where its PIN goes, and the number of the registration that made it, so that a wait
/// that ends can tell its own entry from a newer one.
type Slot = (u64, Sender<Zeroizing<Vec<u8>>>);

/// Where the PIN socket hands a PIN to the method that waits for it: by the prompt the PIN was
/// announced for, never by the user it is for. A PIN typed at one prompt can therefore not be taken
/// by a job on another prompt of the same user (P-46, review finding R-01, #344); there is no
/// function that delivers or waits by user (`the_inbox_has_no_wait_by_user`).
#[derive(Default)]
pub struct PinInbox {
    /// The methods that are waiting, by prompt.
    waiting: Mutex<HashMap<PinTarget, Slot>>,
    /// The number of the next registration.
    next: AtomicU64,
}

impl PinInbox {
    /// Hands `pin` to the wait of the prompt `target` and to nobody else, a job of the same user
    /// on another prompt included (`a_pin_goes_only_to_the_wait_of_its_prompt`, P-46). Returns
    /// whether that prompt has a wait; if not, the PIN is dropped (and wiped) here.
    pub fn deliver_to(&self, target: &PinTarget, pin: Zeroizing<Vec<u8>>) -> bool {
        let sender = self
            .waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(target)
            .map(|(_, sender)| sender.clone());
        sender.is_some_and(|sender| sender.send(pin).is_ok())
    }

    /// Registers a wait for the prompt `target`, which never replaces another: `None` when that
    /// prompt already has a wait, which then keeps its PIN
    /// (`a_second_wait_for_a_prompt_is_refused_and_the_first_keeps_its_pin`, P-46). The
    /// registration ends with the returned guard.
    pub(crate) fn expect_for(
        self: &Arc<Self>,
        target: PinTarget,
    ) -> Option<(Waiting, Receiver<Zeroizing<Vec<u8>>>)> {
        let (sender, receiver) = channel();
        let number = self.next.fetch_add(1, Ordering::Relaxed);
        {
            let mut waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
            if waiting.contains_key(&target) {
                return None;
            }
            waiting.insert(target.clone(), (number, sender));
        }
        Some((
            Waiting {
                inbox: Arc::clone(self),
                target,
                number,
            },
            receiver,
        ))
    }
}

/// A registration in the inbox; dropping it removes it, and only it.
pub(crate) struct Waiting {
    /// The inbox it is in.
    inbox: Arc<PinInbox>,
    /// The prompt the wait is for.
    target: PinTarget,
    /// The number of this registration.
    number: u64,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut waiting = self
            .inbox
            .waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Only this registration's own entry goes; the prompt can be waited for again afterwards.
        if waiting
            .get(&self.target)
            .is_some_and(|(number, _)| *number == self.number)
        {
            waiting.remove(&self.target);
        }
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
    /// The method for `subject` on the prompt `target`. It starts waiting for a PIN at once, not
    /// when it runs: a client may send the PIN as soon as its call to start the authentication has
    /// returned, which is before the orchestrator has started this method on its thread. It is
    /// registered for that prompt, so that only a PIN announced for it arrives, and it never takes
    /// the place of another wait. The registration ends when the method is dropped. `None` when
    /// the prompt already has a wait (P-46).
    pub fn for_prompt(
        subject: u32,
        target: PinTarget,
        inbox: &Arc<PinInbox>,
        lock: Arc<PinLockService>,
        verifier: Arc<dyn PinVerifier>,
        clock: fn() -> u64,
    ) -> Option<Self> {
        let (registration, receiver) = inbox.expect_for(target)?;
        Some(Self {
            subject,
            _registration: registration,
            receiver,
            lock,
            verifier,
            clock,
        })
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
