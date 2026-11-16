//! The per-user counter of failed PIN attempts.
//!
//! The TPM keeps one failed-tries counter for the whole machine, so one user's wrong PINs
//! could lock every other user out. This counter is the Agent's own: it counts per uid and
//! refuses a uid that is locked before the attempt would reach the TPM. It never touches
//! the TPM's dictionary-attack parameters and imports nothing from a TPM crate.
//!
//! The counter has no clock and does no I/O: the caller passes the time in whole seconds,
//! and the state leaves and enters as plain [`Record`]s (the file that holds them is in
//! [`store`]). Only [`PinLock::record_pin_success`] resets a counter; a face or fingerprint
//! success never does, so someone at the keyboard cannot guess PINs between the owner's
//! biometric unlocks.
//!
//! Security property: `one_users_failed_pins_cannot_lock_out_another_user` (P-14).
//!
//! C4 component: `pinManager` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

pub mod store;

use std::collections::BTreeMap;

/// One uid's saved state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The user the record belongs to.
    pub uid: u32,
    /// Wrong PINs counted since the last lockout started or the last correct PIN.
    pub failures: u32,
    /// How many lockouts this uid has had since its last correct PIN.
    pub lockouts: u32,
    /// The time, in seconds, before which the uid is refused.
    pub locked_until: u64,
}

/// Why the counter refused a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinLockError {
    /// The uid is locked; it may try again after this many seconds.
    Locked {
        /// Seconds until the lockout ends.
        retry_after_secs: u64,
    },
    /// Saved records that cannot be trusted: more failures than the limit allows, or one uid
    /// twice. The caller refuses the attempt; it does not start from an empty counter.
    BadRecords,
}

/// The per-uid counter of failed PIN attempts. Nothing is shared between uids.
#[derive(Clone, Debug)]
pub struct PinLock {
    /// Wrong PINs that start a lockout; at least 1.
    max_attempts: u32,
    /// The length of the first lockout, in seconds.
    lockout_secs: u64,
    /// The longest a lockout can be, in seconds.
    max_lockout_secs: u64,
    /// The state of every uid that has one, by uid.
    records: BTreeMap<u32, Record>,
}

impl PinLock {
    /// A counter where `max_attempts` wrong PINs start a lockout of `lockout_secs`, doubling
    /// with each repeat lockout and never above `max_lockout_secs`. `max_attempts` of 0
    /// behaves as 1.
    pub fn new(max_attempts: u32, lockout_secs: u64, max_lockout_secs: u64) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            lockout_secs,
            max_lockout_secs,
            records: BTreeMap::new(),
        }
    }

    /// Rebuilds the counter from saved records.
    ///
    /// # Errors
    ///
    /// [`PinLockError::BadRecords`] for a record whose `failures` is at or above the limit,
    /// or a uid that appears twice.
    pub fn restore(
        max_attempts: u32,
        lockout_secs: u64,
        max_lockout_secs: u64,
        records: Vec<Record>,
    ) -> Result<Self, PinLockError> {
        let mut lock = Self::new(max_attempts, lockout_secs, max_lockout_secs);
        for record in records {
            if record.failures >= lock.max_attempts {
                return Err(PinLockError::BadRecords);
            }
            if lock.records.insert(record.uid, record).is_some() {
                return Err(PinLockError::BadRecords);
            }
        }
        Ok(lock)
    }

    /// Whether `uid` may try a PIN at time `now`.
    ///
    /// # Errors
    ///
    /// [`PinLockError::Locked`] while the uid is locked, with the seconds left.
    pub fn check(&self, uid: u32, now: u64) -> Result<(), PinLockError> {
        match self.records.get(&uid) {
            Some(record) if now < record.locked_until => Err(PinLockError::Locked {
                retry_after_secs: record.locked_until - now,
            }),
            _ => Ok(()),
        }
    }

    /// Counts one wrong PIN for `uid` at time `now`. Returns the lockout in seconds that
    /// this failure started, or 0. A uid that is still locked is not counted: its attempt
    /// never reached the TPM.
    pub fn record_failure(&mut self, uid: u32, now: u64) -> u64 {
        let record = self.records.entry(uid).or_insert(Record {
            uid,
            failures: 0,
            lockouts: 0,
            locked_until: 0,
        });
        if now < record.locked_until {
            return 0;
        }
        record.failures += 1;
        if record.failures < self.max_attempts {
            return 0;
        }
        record.lockouts = record.lockouts.saturating_add(1);
        record.failures = 0;
        let doublings = (record.lockouts - 1).min(32);
        let length = self
            .lockout_secs
            .saturating_mul(1_u64 << doublings)
            .min(self.max_lockout_secs);
        record.locked_until = now.saturating_add(length);
        length
    }

    /// A correct PIN: forgets this uid's record. No other call resets anything.
    pub fn record_pin_success(&mut self, uid: u32) {
        self.records.remove(&uid);
    }

    /// The state to save: one record per uid that has one, sorted by uid.
    pub fn records(&self) -> Vec<Record> {
        self.records.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_of_one_uid_never_touch_another() {
        let mut lock = PinLock::new(3, 60, 3600);
        for _ in 0..4096 {
            lock.record_failure(990, 0);
        }
        assert_eq!(lock.check(1000, 0), Ok(()));
        assert!(lock.records().iter().all(|record| record.uid != 1000));
    }

    #[test]
    fn lockout_starts_at_the_limit_and_ends_after_the_delay() {
        let mut lock = PinLock::new(3, 60, 3600);
        assert_eq!(lock.record_failure(1000, 0), 0);
        assert_eq!(lock.record_failure(1000, 0), 0);
        assert_eq!(lock.check(1000, 0), Ok(()));
        assert_eq!(lock.record_failure(1000, 0), 60);
        assert_eq!(
            lock.check(1000, 59),
            Err(PinLockError::Locked {
                retry_after_secs: 1
            })
        );
        assert_eq!(lock.check(1000, 60), Ok(()));
    }

    #[test]
    fn each_repeat_lockout_doubles_the_delay_up_to_the_cap() {
        let mut lock = PinLock::new(1, 60, 200);
        let lengths: Vec<u64> = [0, 100, 300, 700]
            .iter()
            .map(|now| lock.record_failure(1000, *now))
            .collect();
        assert_eq!(lengths, vec![60, 120, 200, 200]);
    }

    #[test]
    fn only_a_correct_pin_resets_only_its_own_uid() {
        let mut lock = PinLock::new(5, 60, 3600);
        lock.record_failure(1000, 0);
        lock.record_failure(1000, 0);
        lock.record_failure(2000, 0);
        lock.record_pin_success(1000);
        assert_eq!(
            lock.records(),
            vec![Record {
                uid: 2000,
                failures: 1,
                lockouts: 0,
                locked_until: 0
            }]
        );
    }

    #[test]
    fn saved_records_restore_the_same_state() {
        let mut lock = PinLock::new(3, 60, 3600);
        for _ in 0..3 {
            lock.record_failure(1000, 0);
        }
        lock.record_failure(2000, 0);
        let saved = lock.records();
        let restored = PinLock::restore(3, 60, 3600, saved.clone()).unwrap();
        assert_eq!(restored.records(), saved);
        assert_eq!(restored.check(1000, 30), lock.check(1000, 30));
        assert!(restored.check(1000, 30).is_err());
        assert_eq!(restored.check(1000, 60), Ok(()));
        assert_eq!(restored.check(2000, 0), Ok(()));
    }

    #[test]
    fn unreadable_records_are_refused() {
        let over_the_limit = Record {
            uid: 1000,
            failures: 3,
            lockouts: 0,
            locked_until: 0,
        };
        assert_eq!(
            PinLock::restore(3, 60, 3600, vec![over_the_limit]).unwrap_err(),
            PinLockError::BadRecords
        );
        let twice = Record {
            uid: 1000,
            failures: 1,
            lockouts: 0,
            locked_until: 0,
        };
        assert_eq!(
            PinLock::restore(3, 60, 3600, vec![twice.clone(), twice]).unwrap_err(),
            PinLockError::BadRecords
        );
    }
}
