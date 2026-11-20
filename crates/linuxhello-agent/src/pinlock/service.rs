//! The Agent's handle on the PIN lock: one counter for the whole machine, built from the policy
//! at start-up, restored from the lockout file, and saved after every change without making a
//! caller wait for the disk.
//!
//! The counter and the file are in [`super`] and [`super::store`]; this module is what the Agent
//! holds. Nothing calls [`PinLockService::record_failure`] or
//! [`PinLockService::record_pin_success`] in production yet: the PIN verifier that decides a PIN
//! is wrong or right needs the TPM and does not exist. `GetStatus` reads [`PinLockService::status_of`].
//!
//! Fail closed (invariant 3): a lockout file that exists but cannot be trusted makes the whole
//! service [`LockStatus::Untrusted`]: every attempt is refused with
//! [`PinLockError::BadRecords`], and the file is never replaced by an empty counter
//! (`a_file_that_cannot_be_trusted_refuses_every_attempt_of_the_service`).
//!
//! The limits are the machine's: one set for every user, from the admin layers and the defaults
//! ([`Limits::from_policy`]). A stricter limit in a user's own layer is not honoured yet.
//!
//! C4 component: `pinManager` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::io;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;

use super::store::PinLockFile;
use super::{PinLock, PinLockError};
use crate::policy::Policy;

/// The longest a lockout can be: 24 hours. The policy has no key for it.
pub const MAX_LOCKOUT_SECS: u64 = 24 * 3600;

/// The wall clock in whole seconds since the Unix epoch; zero if the clock is before it. The lockout
/// file keeps these times, so they mean the same after a restart.
pub fn wall_clock_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The limits a [`PinLock`] is built with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Wrong PINs that start a lockout.
    pub max_attempts: u32,
    /// The length of the first lockout, in seconds.
    pub lockout_secs: u64,
    /// The longest a lockout can be, in seconds.
    pub max_lockout_secs: u64,
}

impl Limits {
    /// The limits of `policy`: `pin.lockout_attempts`, `pin.lockout_minutes` in seconds, and
    /// [`MAX_LOCKOUT_SECS`]. Pass the policy of the admin layers alone: the lock has one set of
    /// limits for every user, and a user's own layer must not change it for the others.
    pub fn from_policy(policy: &Policy) -> Self {
        let rules = policy.pin_rules();
        Self {
            max_attempts: rules.lockout_attempts,
            lockout_secs: u64::from(rules.lockout_minutes) * 60,
            max_lockout_secs: MAX_LOCKOUT_SECS,
        }
    }
}

/// How the TPM's own dictionary-attack limit lowered the Agent's limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmCap {
    /// Wrong tries after which the TPM locks every key, for every user.
    pub tpm_tries: u32,
    /// Wrong PINs the Agent allows instead of what the policy asks.
    pub allowed: u32,
}

impl Limits {
    /// These limits, with `max_attempts` lowered to half of `tpm_tries` when the policy asks for
    /// more. The TPM counts wrong tries of every user together and locks all of them at its own
    /// limit; keeping the Agent's limit at half of it lets the Agent's per-user lockout act first
    /// (`the_agents_limit_stays_below_the_tpms`). Returns the cap when it changed anything.
    pub fn capped_by_tpm(self, tpm_tries: u32) -> (Self, Option<TpmCap>) {
        let allowed = (tpm_tries / 2).max(1);
        if self.max_attempts <= allowed {
            return (self, None);
        }
        (
            Self {
                max_attempts: allowed,
                ..self
            },
            Some(TpmCap { tpm_tries, allowed }),
        )
    }
}

/// What the lock says about one user at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockStatus {
    /// The user may try a PIN.
    Unlocked,
    /// The user is locked for this many more seconds.
    LockedFor(u64),
    /// The lockout file cannot be trusted: nobody may try a PIN.
    Untrusted,
}

/// The state of the service: a counter that can be trusted, or a file that cannot.
enum State {
    /// The counter, restored from the file or fresh.
    Trusted(PinLock),
    /// The file exists and cannot be trusted.
    Untrusted,
}

/// What the writer thread waits on: the newest counter to save, and whether to stop.
#[derive(Default)]
struct Slot {
    /// The counter to save next; a newer one replaces an older one that was not written yet.
    pending: Option<PinLock>,
    /// The service is dropped: write what is pending and stop.
    closing: bool,
}

/// A way of saving a counter; the file in production, something slower in a test.
type Saver = Box<dyn Fn(&PinLock) -> io::Result<()> + Send>;

/// The Agent's PIN lock.
pub struct PinLockService {
    /// The counter or the refusal.
    state: Mutex<State>,
    /// The counter waiting to be saved, shared with the writer thread.
    slot: Arc<(Mutex<Slot>, Condvar)>,
    /// The writer thread; joined on drop so that nothing pending is lost.
    writer: Option<JoinHandle<()>>,
    /// Set when the TPM's limit lowered the Agent's.
    tpm_cap: Option<TpmCap>,
}

impl PinLockService {
    /// Restores the lock from `file` with `limits`. A missing file is a first start; a file that
    /// cannot be trusted makes the service [`LockStatus::Untrusted`] and is left as it is.
    pub fn start(file: PinLockFile, limits: Limits) -> Self {
        let state = match file.load(
            limits.max_attempts,
            limits.lockout_secs,
            limits.max_lockout_secs,
        ) {
            Ok(lock) => State::Trusted(lock),
            Err(_) => {
                eprintln!(
                    "linuxhello-agent: the PIN lockout file cannot be trusted; PIN attempts are refused"
                );
                State::Untrusted
            }
        };
        Self::with_saver(state, Box::new(move |lock| file.save(lock)))
    }

    /// The service with its own way of saving, for tests.
    fn with_saver(state: State, saver: Saver) -> Self {
        let slot: Arc<(Mutex<Slot>, Condvar)> = Arc::default();
        let shared = Arc::clone(&slot);
        let writer = std::thread::spawn(move || write_until_closed(&shared, &saver));
        Self {
            state: Mutex::new(state),
            slot,
            writer: Some(writer),
            tpm_cap: None,
        }
    }

    /// Like [`Self::start`], with the limit lowered when the TPM locks sooner than the policy
    /// expects: `tpm_tries` is what the TPM reports, `None` when it could not be asked.
    pub fn start_capped(file: PinLockFile, limits: Limits, tpm_tries: Option<u32>) -> Self {
        let (limits, cap) = tpm_tries.map_or((limits, None), |tries| limits.capped_by_tpm(tries));
        let mut service = Self::start(file, limits);
        service.tpm_cap = cap;
        service
    }

    /// The cap the TPM's limit put on the Agent's, if it did.
    pub fn tpm_cap(&self) -> Option<TpmCap> {
        self.tpm_cap
    }

    /// Locks the state, going on after a panic elsewhere: the counter is plain data.
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hands a copy of the counter to the writer thread; the caller does not wait for the disk.
    fn save(&self, lock: &PinLock) {
        let (slot, wake) = &*self.slot;
        slot.lock().unwrap_or_else(PoisonError::into_inner).pending = Some(lock.clone());
        wake.notify_one();
    }

    /// Whether `uid` may try a PIN at time `now`, in seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// [`PinLockError::Locked`] while the user is locked; [`PinLockError::BadRecords`] when the
    /// lockout file cannot be trusted.
    pub fn check(&self, uid: u32, now: u64) -> Result<(), PinLockError> {
        match &*self.state() {
            State::Trusted(lock) => lock.check(uid, now),
            State::Untrusted => Err(PinLockError::BadRecords),
        }
    }

    /// Counts one wrong PIN for `uid`. Returns the lockout in seconds that this failure started,
    /// or 0. The counter is saved in the background.
    ///
    /// # Errors
    ///
    /// [`PinLockError::BadRecords`] when the lockout file cannot be trusted; nothing changes.
    pub fn record_failure(&self, uid: u32, now: u64) -> Result<u64, PinLockError> {
        let mut state = self.state();
        let State::Trusted(lock) = &mut *state else {
            return Err(PinLockError::BadRecords);
        };
        let started = lock.record_failure(uid, now);
        self.save(lock);
        Ok(started)
    }

    /// A correct PIN: forgets the user's record. The counter is saved in the background.
    ///
    /// # Errors
    ///
    /// [`PinLockError::BadRecords`] when the lockout file cannot be trusted; nothing changes.
    pub fn record_pin_success(&self, uid: u32) -> Result<(), PinLockError> {
        let mut state = self.state();
        let State::Trusted(lock) = &mut *state else {
            return Err(PinLockError::BadRecords);
        };
        lock.record_pin_success(uid);
        self.save(lock);
        Ok(())
    }

    /// What the lock says about `uid` at time `now`.
    pub fn status_of(&self, uid: u32, now: u64) -> LockStatus {
        match self.check(uid, now) {
            Ok(()) => LockStatus::Unlocked,
            Err(PinLockError::Locked { retry_after_secs }) => {
                LockStatus::LockedFor(retry_after_secs)
            }
            Err(PinLockError::BadRecords) => LockStatus::Untrusted,
        }
    }
}

impl Drop for PinLockService {
    /// Writes what is pending and stops the writer.
    fn drop(&mut self) {
        let (slot, wake) = &*self.slot;
        slot.lock().unwrap_or_else(PoisonError::into_inner).closing = true;
        wake.notify_one();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

/// The writer thread: saves the newest pending counter, and stops once it is closed and nothing
/// is pending. A failed save is reported once on standard error and tried again at the next
/// change.
fn write_until_closed(slot: &(Mutex<Slot>, Condvar), saver: &Saver) {
    let (state, wake) = slot;
    loop {
        let next = {
            let mut guard = state.lock().unwrap_or_else(PoisonError::into_inner);
            loop {
                if let Some(lock) = guard.pending.take() {
                    break Some(lock);
                }
                if guard.closing {
                    break None;
                }
                guard = wake.wait(guard).unwrap_or_else(PoisonError::into_inner);
            }
        };
        let Some(lock) = next else { return };
        if let Err(error) = saver(&lock) {
            eprintln!("linuxhello-agent: the PIN lockout file was not saved: {error}");
        }
    }
}

#[cfg(test)]
mod tests;
