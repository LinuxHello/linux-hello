//! The work behind `SetPin` and `ChangePin` (ADR-0021, amendment 2026-11-20): wait for the PINs
//! that the caller sends on the PIN socket, make or change the user's root key, and say how it
//! ended.
//!
//! Setting a PIN takes one PIN, the new one. Changing it takes two, the current one first. The PINs
//! arrive through the [`PinInbox`], the way a sign-in's PIN does. A wrong current PIN is counted by
//! the per-user lock like a wrong sign-in PIN, so the change cannot be used to guess a PIN without
//! the lockout (`change_pin_with_a_wrong_current_pin_changes_nothing_and_counts`).

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use linuxhello_dbus::{PromptReason, PromptResult};
use zeroize::Zeroizing;

use super::tpm::EnrolError;
use super::{PinInbox, Waiting};
use crate::orchestrator::Cancel;
use crate::pinlock::service::PinLockService;
use crate::pinlock::PinLockError;
use crate::policy::view::PinRules;
use crate::state::Outcome;

/// How often a waiting job looks at whether its prompt was closed.
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// What sets and changes a user's PIN: the TPM provider in production, a stand-in in a test.
pub trait PinEnrolment: Send + Sync {
    /// Whether the user already has a PIN.
    fn has_pin(&self, uid: u32) -> bool;

    /// Sets the first PIN of `uid`.
    ///
    /// # Errors
    ///
    /// [`EnrolError`]; nothing is written unless the key was made.
    fn set(&self, uid: u32, pin: &[u8]) -> Result<(), EnrolError>;

    /// Changes the PIN of `uid` from `old` to `new`, which may not be the current PIN nor one of the
    /// last `history` PINs that were replaced.
    ///
    /// # Errors
    ///
    /// [`EnrolError`]; a wrong `old` changes nothing.
    fn change(&self, uid: u32, old: &[u8], new: &[u8], history: u32) -> Result<(), EnrolError>;
}

/// The registration that makes the PIN socket hand `uid`'s PINs to a job. Made before the call
/// that starts the job returns, so that no PIN sent right after it can be lost.
pub struct PinWait {
    /// The registration in the inbox; dropping it removes it.
    _registration: Waiting,
    /// Where the PINs arrive.
    receiver: Receiver<Zeroizing<Vec<u8>>>,
}

impl PinInbox {
    /// Registers a job that waits for PINs of `subject`. It replaces a sign-in that waits for the
    /// same user at the same moment; that sign-in then ends as unavailable.
    pub fn wait_for(self: &Arc<Self>, subject: u32) -> PinWait {
        let (registration, receiver) = self.expect(subject);
        PinWait {
            _registration: registration,
            receiver,
        }
    }
}

impl PinWait {
    /// The next PIN, within `within`; `None` when time runs out, the prompt is closed or the
    /// inbox is gone.
    fn next(&self, cancel: &Cancel, within: Duration) -> Option<Zeroizing<Vec<u8>>> {
        let end = Instant::now() + within;
        loop {
            if cancel.is_cancelled() || Instant::now() >= end {
                return None;
            }
            match self.receiver.recv_timeout(CANCEL_POLL) {
                Ok(pin) => return Some(pin),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    }
}

/// What a job needs besides its PINs.
pub struct Job<'a> {
    /// The user whose PIN it is.
    pub subject: u32,
    /// The PIN rules of the policy: length and the kinds of characters.
    pub rules: &'a PinRules,
    /// How long each PIN may take to arrive.
    pub wait: Duration,
    /// The counter of wrong PINs.
    pub lock: &'a PinLockService,
    /// What makes the key.
    pub enrolment: &'a dyn PinEnrolment,
    /// The time in seconds since the Unix epoch.
    pub clock: fn() -> u64,
}

/// A failure with a reason the client can show.
fn failure(reason: PromptReason) -> Outcome {
    Outcome {
        reason,
        ..Outcome::new(PromptResult::Failure)
    }
}

/// Whether one kind of character is present as the rule demands: `required` needs one,
/// `disallowed` needs none, `allowed` accepts either. A word that is none of the three is refused,
/// so a rule the Agent does not understand never lets a PIN through.
fn kind_ok(rule: &str, present: bool) -> bool {
    match rule {
        "required" => present,
        "disallowed" => !present,
        "allowed" => true,
        _ => false,
    }
}

/// Whether `pin` follows `rules`: its length in characters, and which kinds of characters it has.
/// Digits are the ASCII digits, letters are letters of any alphabet that have a case, and a special
/// character is any other that is not a letter or a digit (a space counts). A PIN that is not text
/// is left to the stretching, which refuses it.
pub fn rules_ok(pin: &[u8], rules: &PinRules) -> bool {
    let Ok(text) = std::str::from_utf8(pin) else {
        return true;
    };
    let length = u32::try_from(text.chars().count()).unwrap_or(u32::MAX);
    (rules.min_length..=rules.max_length).contains(&length)
        && kind_ok(&rules.digits, text.chars().any(|c| c.is_ascii_digit()))
        && kind_ok(&rules.lowercase, text.chars().any(char::is_lowercase))
        && kind_ok(&rules.uppercase, text.chars().any(char::is_uppercase))
        && kind_ok(&rules.special, text.chars().any(|c| !c.is_alphanumeric()))
}

/// Sets the first PIN of the subject: waits for one PIN and makes the key.
pub fn run_set(job: &Job<'_>, wait: &PinWait, cancel: &Cancel) -> Outcome {
    let Some(pin) = wait.next(cancel, job.wait) else {
        return failure(PromptReason::Timeout);
    };
    if !rules_ok(&pin, job.rules) {
        return failure(PromptReason::None);
    }
    match job.enrolment.set(job.subject, &pin) {
        Ok(()) => Outcome::new(PromptResult::Success),
        Err(_) => failure(PromptReason::None),
    }
}

/// Changes the PIN of the subject: waits for the current PIN and then the new one, and changes the
/// key's authorisation in place. The current PIN is counted by the lock.
pub fn run_change(job: &Job<'_>, wait: &PinWait, cancel: &Cancel) -> Outcome {
    let now = (job.clock)();
    match job.lock.check(job.subject, now) {
        Ok(()) => {}
        Err(PinLockError::Locked { retry_after_secs }) => {
            return Outcome {
                retry_after: u32::try_from(retry_after_secs).unwrap_or(u32::MAX),
                ..Outcome::new(PromptResult::LockedOut)
            };
        }
        Err(PinLockError::BadRecords) => return failure(PromptReason::None),
    }
    let Some(old) = wait.next(cancel, job.wait) else {
        return failure(PromptReason::Timeout);
    };
    let Some(new) = wait.next(cancel, job.wait) else {
        return failure(PromptReason::Timeout);
    };
    if !rules_ok(&new, job.rules) {
        return failure(PromptReason::None);
    }
    match job
        .enrolment
        .change(job.subject, &old, &new, job.rules.history)
    {
        Ok(()) => match job.lock.record_pin_success(job.subject) {
            Ok(()) => Outcome::new(PromptResult::Success),
            Err(_) => failure(PromptReason::None),
        },
        Err(EnrolError::WrongPin) => match job.lock.record_failure(job.subject, now) {
            Ok(0) => failure(PromptReason::NotRecognised),
            Ok(seconds) => Outcome {
                retry_after: u32::try_from(seconds).unwrap_or(u32::MAX),
                ..Outcome::new(PromptResult::LockedOut)
            },
            Err(_) => failure(PromptReason::None),
        },
        Err(_) => failure(PromptReason::None),
    }
}

#[cfg(test)]
mod tests;
