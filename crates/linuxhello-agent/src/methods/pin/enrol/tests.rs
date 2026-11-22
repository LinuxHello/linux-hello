//! Tests of setting and changing a PIN with a stand-in for the TPM and a real lock on disk.

use std::collections::HashMap;
use std::sync::Mutex;

use tempfile::TempDir;

use super::*;
use crate::pinlock::service::Limits;
use crate::pinlock::store::PinLockFile;
use crate::policy::view::PinRules;

/// A stand-in that keeps one PIN per user in memory and counts its calls.
#[derive(Default)]
struct Memory {
    pins: Mutex<HashMap<u32, Vec<u8>>>,
    calls: Mutex<u32>,
}

impl PinEnrolment for Memory {
    fn has_pin(&self, uid: u32) -> bool {
        self.pins.lock().unwrap().contains_key(&uid)
    }

    fn set(&self, uid: u32, pin: &[u8]) -> Result<(), EnrolError> {
        *self.calls.lock().unwrap() += 1;
        let mut pins = self.pins.lock().unwrap();
        if pins.contains_key(&uid) {
            return Err(EnrolError::AlreadyEnrolled);
        }
        pins.insert(uid, pin.to_vec());
        Ok(())
    }

    fn change(&self, uid: u32, old: &[u8], new: &[u8], _history: u32) -> Result<(), EnrolError> {
        *self.calls.lock().unwrap() += 1;
        let mut pins = self.pins.lock().unwrap();
        match pins.get_mut(&uid) {
            None => Err(EnrolError::NotEnrolled),
            Some(current) if current.as_slice() != old => Err(EnrolError::WrongPin),
            Some(current) => {
                *current = new.to_vec();
                Ok(())
            }
        }
    }
}

/// Two wrong PINs start a lockout of ten minutes.
const LIMITS: Limits = Limits {
    max_attempts: 2,
    lockout_secs: 600,
    max_lockout_secs: 86_400,
};

/// Rules of four to eight characters with a digit required and everything else allowed.
fn rules() -> PinRules {
    PinRules {
        min_length: 4,
        max_length: 8,
        digits: "required".into(),
        lowercase: "allowed".into(),
        uppercase: "allowed".into(),
        special: "allowed".into(),
        history: 0,
        expiry_days: None,
        lockout_attempts: 5,
        lockout_minutes: 15,
    }
}

/// The prompt `n` of the user `opener`: 64 hexadecimal characters made from `n`.
fn target(opener: u32, n: u8) -> PinTarget {
    PinTarget {
        opener,
        prompt: linuxhello_dbus::PromptId::parse(&format!("{n:064x}")).unwrap(),
    }
}

/// The time of every test.
fn at_1000() -> u64 {
    1_000
}

/// Everything a test needs.
struct Setup {
    inbox: Arc<PinInbox>,
    memory: Memory,
    lock: PinLockService,
    wait: PinWait,
    rules: PinRules,
    _dir: TempDir,
}

fn setup() -> Setup {
    let dir = crate::private_tempdir();
    let uid = std::fs::metadata(dir.path())
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap();
    let lock = PinLockService::start(
        PinLockFile::new(dir.path().join("pinlock.toml"), uid),
        LIMITS,
    );
    let inbox = Arc::new(PinInbox::default());
    let wait = inbox.wait_for_prompt(target(1000, 1)).unwrap();
    Setup {
        inbox,
        memory: Memory::default(),
        lock,
        wait,
        rules: rules(),
        _dir: dir,
    }
}

impl Setup {
    fn job(&self) -> Job<'_> {
        Job {
            subject: 1000,
            rules: &self.rules,
            wait: Duration::from_millis(300),
            lock: &self.lock,
            enrolment: &self.memory,
            clock: at_1000,
        }
    }

    fn send(&self, pin: &[u8]) {
        assert!(self
            .inbox
            .deliver_to(&target(1000, 1), Zeroizing::new(pin.to_vec())));
    }
}

#[test]
fn set_pin_makes_the_pin_work() {
    let s = setup();
    s.send(b"1234");
    let outcome = run_set(&s.job(), &s.wait, &Cancel::default());
    assert_eq!(outcome, Outcome::new(PromptResult::Success));
    assert!(s.memory.has_pin(1000));
}

#[test]
fn set_pin_without_a_pin_times_out_and_writes_nothing() {
    let s = setup();
    let outcome = run_set(&s.job(), &s.wait, &Cancel::default());
    assert_eq!(outcome.result, PromptResult::Failure);
    assert_eq!(outcome.reason, PromptReason::Timeout);
    assert_eq!(*s.memory.calls.lock().unwrap(), 0);
}

#[test]
fn a_pin_outside_the_policys_length_is_refused_before_the_tpm_is_asked() {
    for pin in [&b"123"[..], &b"123456789"[..]] {
        let s = setup();
        s.send(pin);
        let outcome = run_set(&s.job(), &s.wait, &Cancel::default());
        assert_eq!(outcome.result, PromptResult::Failure);
        assert_eq!(*s.memory.calls.lock().unwrap(), 0);
    }
}

#[test]
fn a_closed_prompt_stops_the_wait() {
    let s = setup();
    let cancel = Cancel::default();
    cancel.cancel();
    let started = Instant::now();
    let mut job = s.job();
    job.wait = Duration::from_secs(30);
    assert_eq!(
        run_set(&job, &s.wait, &cancel).result,
        PromptResult::Failure
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn change_pin_replaces_the_pin() {
    let s = setup();
    s.memory.set(1000, b"1234").unwrap();
    s.send(b"1234");
    s.send(b"5678");
    let outcome = run_change(&s.job(), &s.wait, &Cancel::default());
    assert_eq!(outcome, Outcome::new(PromptResult::Success));
    assert_eq!(s.memory.pins.lock().unwrap()[&1000], b"5678");
}

#[test]
fn change_pin_with_a_wrong_current_pin_changes_nothing_and_counts() {
    let s = setup();
    s.memory.set(1000, b"1234").unwrap();
    s.send(b"0000");
    s.send(b"5678");
    let outcome = run_change(&s.job(), &s.wait, &Cancel::default());
    assert_eq!(outcome.result, PromptResult::Failure);
    assert_eq!(outcome.reason, PromptReason::NotRecognised);
    assert_eq!(s.memory.pins.lock().unwrap()[&1000], b"1234");
    // The second wrong current PIN reaches the limit of two and locks the user.
    s.send(b"0000");
    s.send(b"5678");
    let locked = run_change(&s.job(), &s.wait, &Cancel::default());
    assert_eq!(locked.result, PromptResult::LockedOut);
    assert_eq!(locked.retry_after, 600);
}

#[test]
fn change_pin_while_locked_is_refused_without_asking_the_tpm() {
    let s = setup();
    s.memory.set(1000, b"1234").unwrap();
    s.lock.record_failure(1000, 1_000).unwrap();
    s.lock.record_failure(1000, 1_000).unwrap();
    let before = *s.memory.calls.lock().unwrap();
    s.send(b"1234");
    s.send(b"5678");
    let outcome = run_change(&s.job(), &s.wait, &Cancel::default());
    assert_eq!(outcome.result, PromptResult::LockedOut);
    assert_eq!(*s.memory.calls.lock().unwrap(), before);
    assert_eq!(s.memory.pins.lock().unwrap()[&1000], b"1234");
}

/// The default rules with one kind of character set to `rule`.
fn with(kind: &str, rule: &str) -> PinRules {
    let mut rules = rules();
    rules.min_length = 1;
    rules.digits = "allowed".into();
    match kind {
        "digits" => rules.digits = rule.into(),
        "lowercase" => rules.lowercase = rule.into(),
        "uppercase" => rules.uppercase = rule.into(),
        _ => rules.special = rule.into(),
    }
    rules
}

#[test]
fn each_kind_of_character_is_required_allowed_or_disallowed_as_the_policy_says() {
    // (kind, rule, a PIN that has the kind, a PIN that has not)
    let cases = [
        ("digits", "a1", "ab"),
        ("lowercase", "aB", "AB"),
        ("uppercase", "Ab", "ab"),
        ("special", "a!", "ab"),
    ];
    for (kind, has, lacks) in cases {
        let required = with(kind, "required");
        assert!(rules_ok(has.as_bytes(), &required), "{kind} required, has");
        assert!(
            !rules_ok(lacks.as_bytes(), &required),
            "{kind} required, lacks"
        );
        let disallowed = with(kind, "disallowed");
        assert!(
            !rules_ok(has.as_bytes(), &disallowed),
            "{kind} disallowed, has"
        );
        assert!(
            rules_ok(lacks.as_bytes(), &disallowed),
            "{kind} disallowed, lacks"
        );
        let allowed = with(kind, "allowed");
        assert!(rules_ok(has.as_bytes(), &allowed) && rules_ok(lacks.as_bytes(), &allowed));
    }
}

#[test]
fn a_rule_the_agent_does_not_understand_lets_no_pin_through() {
    assert!(!rules_ok(b"abcd1", &with("special", "sometimes")));
}

#[test]
fn length_counts_characters_not_bytes() {
    let mut rules = with("digits", "allowed");
    rules.min_length = 4;
    rules.max_length = 4;
    // Four characters of two bytes each.
    assert!(rules_ok("åäöü".as_bytes(), &rules));
    assert!(!rules_ok("åäö".as_bytes(), &rules));
}

#[test]
fn a_pin_without_the_required_digit_is_refused_before_the_tpm_is_asked() {
    let s = setup();
    s.send(b"abcdef");
    let outcome = run_set(&s.job(), &s.wait, &Cancel::default());
    assert_eq!(outcome.result, PromptResult::Failure);
    assert_eq!(*s.memory.calls.lock().unwrap(), 0);
}

/// A verifier that knows one PIN of user 1000.
struct Knows(&'static [u8]);

impl PinVerifier for Knows {
    fn available(&self, _uid: u32) -> bool {
        true
    }
    fn verify(&self, uid: u32, pin: &[u8]) -> Result<bool, crate::methods::pin::VerifyError> {
        Ok(uid == 1000 && pin == self.0)
    }
}

impl Setup {
    fn check(&self, verifier: &dyn PinVerifier) -> Result<(), Outcome> {
        let job = CheckJob {
            subject: 1000,
            wait: Duration::from_millis(300),
            lock: &self.lock,
            verifier,
            clock: at_1000,
        };
        run_check(&job, &self.wait, &Cancel::default())
    }
}

#[test]
fn enrolment_asks_for_the_pin_first() {
    let s = setup();
    let verifier = Knows(b"2468");
    // No PIN sent: the check ends without success.
    assert_eq!(
        s.check(&verifier).unwrap_err().reason,
        PromptReason::Timeout
    );
    s.send(b"2468");
    assert_eq!(s.check(&verifier), Ok(()));
}

#[test]
fn a_wrong_pin_starts_no_enrolment_and_counts() {
    let s = setup();
    let verifier = Knows(b"2468");
    s.send(b"1111");
    assert_eq!(
        s.check(&verifier).unwrap_err().reason,
        PromptReason::NotRecognised
    );
    // The second wrong PIN reaches the limit of two: the user is locked out, and a right PIN
    // is then refused without being checked.
    s.send(b"2222");
    assert_eq!(
        s.check(&verifier).unwrap_err().result,
        PromptResult::LockedOut
    );
    s.send(b"2468");
    assert_eq!(
        s.check(&verifier).unwrap_err().result,
        PromptResult::LockedOut
    );
}

#[test]
fn a_change_job_on_another_prompt_never_sees_a_sign_in_pin() {
    // A job waits on prompt X. A PIN is announced and delivered for prompt Y of the same user, as
    // when the person types it at a real prompt: the job must not take it as the current PIN
    // (R-01, #344, P-46).
    let dir = crate::private_tempdir();
    let uid = std::fs::metadata(dir.path())
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap();
    let lock = PinLockService::start(
        PinLockFile::new(dir.path().join("pinlock.toml"), uid),
        LIMITS,
    );
    let inbox = Arc::new(PinInbox::default());
    let wait = inbox.wait_for_prompt(target(1000, 1)).unwrap();
    // A second job on the same prompt is refused.
    assert!(inbox.wait_for_prompt(target(1000, 1)).is_none());
    let memory = Memory::default();
    memory.set(1000, b"1234").unwrap();
    let calls_before = *memory.calls.lock().unwrap();
    let rules = rules();
    let job = Job {
        subject: 1000,
        rules: &rules,
        wait: Duration::from_millis(300),
        lock: &lock,
        enrolment: &memory,
        clock: at_1000,
    };
    // The PINs of the real prompt, and of an attacker's change that follows them.
    assert!(!inbox.deliver_to(&target(1000, 2), Zeroizing::new(b"1234".to_vec())));
    assert!(!inbox.deliver_to(&target(1000, 2), Zeroizing::new(b"6666".to_vec())));
    let outcome = run_change(&job, &wait, &Cancel::default());
    assert_eq!(outcome.reason, PromptReason::Timeout);
    // The enrolment was never asked to change anything, and the PIN is the person's own.
    assert_eq!(*memory.calls.lock().unwrap(), calls_before);
    assert_eq!(memory.pins.lock().unwrap()[&1000], b"1234");
}
