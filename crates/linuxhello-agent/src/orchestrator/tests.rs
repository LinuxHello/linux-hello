//! Tests of the orchestrator on fake methods: who wins, who is cancelled, what is reported.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};

use linuxhello_dbus::{AuthMethod, PromptReason, PromptResult, PromptState};

use super::*;

/// What a fake method does.
#[derive(Clone, Copy)]
enum Script {
    /// Succeeds after this many milliseconds.
    SucceedAfter(u64),
    /// Fails with this reason after this many milliseconds.
    FailAfter(u64, PromptReason),
    /// Runs until it is cancelled.
    UntilCancelled,
    /// Ends as unavailable after this many milliseconds.
    UnavailableAfter(u64),
    /// Ignores `cancel` and ends after this many milliseconds.
    IgnoreCancelFor(u64),
    /// Panics.
    Panic,
}

/// A fake method that follows a [`Script`].
struct Fake {
    /// Which method it plays.
    kind: AuthMethod,
    /// Whether it says it can run.
    available: bool,
    /// What it does.
    script: Script,
    /// Set when it saw the cancel flag.
    saw_cancel: Arc<AtomicBool>,
    /// Set when it was started.
    started: Arc<AtomicBool>,
}

/// A fake with a script, and the flags to look at afterwards.
fn fake(kind: AuthMethod, script: Script) -> (Box<dyn Method>, Arc<AtomicBool>, Arc<AtomicBool>) {
    let (saw_cancel, started) = (Arc::default(), Arc::default());
    let method = Fake {
        kind,
        available: true,
        script,
        saw_cancel: Arc::clone(&saw_cancel),
        started: Arc::clone(&started),
    };
    (Box::new(method), saw_cancel, started)
}

impl Method for Fake {
    fn kind(&self) -> AuthMethod {
        self.kind
    }

    fn available(&self) -> bool {
        self.available
    }

    fn run(&mut self, cancel: &Cancel) -> MethodEnd {
        self.started.store(true, Ordering::SeqCst);
        let waited = |ms: u64| {
            let until = Instant::now() + Duration::from_millis(ms);
            while Instant::now() < until {
                if cancel.is_cancelled() {
                    self.saw_cancel.store(true, Ordering::SeqCst);
                    return false;
                }
                sleep(Duration::from_millis(5));
            }
            true
        };
        match self.script {
            Script::SucceedAfter(ms) => {
                if waited(ms) {
                    MethodEnd::Success
                } else {
                    MethodEnd::Cancelled
                }
            }
            Script::FailAfter(ms, reason) => {
                if waited(ms) {
                    MethodEnd::Failure(reason)
                } else {
                    MethodEnd::Cancelled
                }
            }
            Script::UntilCancelled => {
                waited(u64::MAX / 4);
                MethodEnd::Cancelled
            }
            Script::UnavailableAfter(ms) => {
                if waited(ms) {
                    MethodEnd::Unavailable
                } else {
                    MethodEnd::Cancelled
                }
            }
            Script::IgnoreCancelFor(ms) => {
                sleep(Duration::from_millis(ms));
                MethodEnd::Cancelled
            }
            Script::Panic => panic!("a method that panics"),
        }
    }
}

/// A reporter that keeps every update.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Update>>>);

impl Recorder {
    fn updates(&self) -> Vec<Update> {
        self.0.lock().unwrap().clone()
    }
}

impl Reporter for Recorder {
    fn report(&mut self, update: Update) {
        self.0.lock().unwrap().push(update);
    }
}

/// A rule that allows every method with one factor.
fn rule() -> MethodRule {
    MethodRule {
        methods: vec!["pin".into(), "fingerprint".into(), "face".into()],
        factors: 1,
        reverify_after: None,
        unsatisfiable: false,
    }
}

/// Runs the methods under `rule` with the given deadline and returns the outcome and the updates.
fn go(
    rule: &MethodRule,
    methods: Vec<Box<dyn Method>>,
    deadline_ms: u64,
) -> (Outcome, Vec<Update>) {
    let recorder = Recorder::default();
    let mut reporter = recorder.clone();
    let outcome = Orchestrator::run(
        rule,
        methods,
        &mut reporter,
        Duration::from_millis(deadline_ms),
        &Cancel::default(),
    );
    (outcome, recorder.updates())
}

/// The results among the updates.
fn results(updates: &[Update]) -> Vec<Outcome> {
    updates
        .iter()
        .filter_map(|u| match u {
            Update::Result(o) => Some(*o),
            _ => None,
        })
        .collect()
}

#[test]
fn the_first_success_wins_and_the_rest_are_cancelled() {
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(50));
    let (face, face_cancelled, _) = fake(AuthMethod::Face, Script::UntilCancelled);
    let (outcome, updates) = go(&rule(), vec![finger, face], 5_000);
    assert_eq!(outcome, Outcome::new(PromptResult::Success));
    assert!(
        face_cancelled.load(Ordering::SeqCst),
        "the face method saw the cancel flag"
    );
    assert_eq!(
        updates,
        vec![
            Update::Methods(vec![AuthMethod::Face, AuthMethod::Fingerprint]),
            Update::Active(vec![AuthMethod::Face, AuthMethod::Fingerprint]),
            Update::State(PromptState::Scanning),
            Update::Active(vec![]),
            Update::State(PromptState::Idle),
            Update::Result(Outcome::new(PromptResult::Success)),
        ]
    );
}

#[test]
fn two_successes_give_one_result() {
    let (a, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(20));
    let (b, _, _) = fake(AuthMethod::Face, Script::SucceedAfter(20));
    let (outcome, updates) = go(&rule(), vec![a, b], 5_000);
    assert_eq!(outcome.result, PromptResult::Success);
    assert_eq!(results(&updates).len(), 1);
}

#[test]
fn a_failed_method_does_not_stop_the_others() {
    let (face, _, _) = fake(
        AuthMethod::Face,
        Script::FailAfter(10, PromptReason::NoFace),
    );
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(100));
    let (outcome, updates) = go(&rule(), vec![face, finger], 5_000);
    assert_eq!(outcome.result, PromptResult::Success);
    assert!(
        updates.contains(&Update::Active(vec![AuthMethod::Fingerprint])),
        "the list of running methods shrank: {updates:?}"
    );
}

#[test]
fn every_method_failing_is_a_failure_with_the_last_reason() {
    let (face, _, _) = fake(
        AuthMethod::Face,
        Script::FailAfter(10, PromptReason::TooDark),
    );
    let (finger, _, _) = fake(
        AuthMethod::Fingerprint,
        Script::FailAfter(60, PromptReason::None),
    );
    let (outcome, _) = go(&rule(), vec![face, finger], 5_000);
    assert_eq!(outcome.result, PromptResult::Failure);
    assert_eq!(
        outcome.reason,
        PromptReason::NotRecognised,
        "the last failure had no reason of its own"
    );

    let (face, _, _) = fake(
        AuthMethod::Face,
        Script::FailAfter(60, PromptReason::NoFace),
    );
    let (finger, _, _) = fake(
        AuthMethod::Fingerprint,
        Script::FailAfter(10, PromptReason::NotRecognised),
    );
    let (outcome, _) = go(&rule(), vec![face, finger], 5_000);
    assert_eq!(outcome.reason, PromptReason::NoFace);
}

#[test]
fn only_unavailable_methods_are_a_failure_with_no_methods() {
    let mut unavailable = Fake {
        kind: AuthMethod::Fingerprint,
        available: false,
        script: Script::SucceedAfter(1),
        saw_cancel: Arc::default(),
        started: Arc::default(),
    };
    let started = Arc::clone(&unavailable.started);
    unavailable.available = false;
    let (outcome, updates) = go(&rule(), vec![Box::new(unavailable)], 5_000);
    assert_eq!(outcome, Outcome::new(PromptResult::Failure));
    assert_eq!(updates[0], Update::Methods(vec![]));
    assert!(
        !started.load(Ordering::SeqCst),
        "an unavailable method is never run"
    );

    // A method that turns out to be unavailable while running is a failure without a reason.
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::UnavailableAfter(10));
    let (outcome, _) = go(&rule(), vec![finger], 5_000);
    assert_eq!(outcome, Outcome::new(PromptResult::Failure));
}

#[test]
fn the_deadline_cancels_everything_and_says_timeout() {
    let (face, cancelled, _) = fake(AuthMethod::Face, Script::UntilCancelled);
    let started = Instant::now();
    let (outcome, _) = go(&rule(), vec![face], 100);
    assert_eq!(outcome.result, PromptResult::Failure);
    assert_eq!(outcome.reason, PromptReason::Timeout);
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "took {:?}",
        started.elapsed()
    );
    assert!(cancelled.load(Ordering::SeqCst));
}

#[test]
fn a_method_that_ignores_cancel_does_not_hold_the_orchestrator() {
    let (stubborn, _, _) = fake(AuthMethod::Face, Script::IgnoreCancelFor(3_000));
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(20));
    let started = Instant::now();
    let (outcome, _) = go(&rule(), vec![stubborn, finger], 5_000);
    assert_eq!(outcome.result, PromptResult::Success);
    assert!(
        started.elapsed() < Duration::from_millis(1_500),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn a_method_the_policy_does_not_allow_is_not_started() {
    let mut no_face = rule();
    no_face.methods = vec!["pin".into(), "fingerprint".into()];
    let (face, _, face_started) = fake(AuthMethod::Face, Script::SucceedAfter(1));
    let (pin, _, _) = fake(AuthMethod::Pin, Script::SucceedAfter(30));
    let (outcome, updates) = go(&no_face, vec![face, pin], 5_000);
    assert_eq!(outcome.result, PromptResult::Success);
    assert!(!face_started.load(Ordering::SeqCst));
    assert_eq!(updates[0], Update::Methods(vec![AuthMethod::Pin]));
    assert_eq!(updates[2], Update::State(PromptState::WaitingForInput));

    // The PIN is allowed even when the rule leaves it out.
    let mut nothing = rule();
    nothing.methods = vec![];
    let (pin, _, pin_started) = fake(AuthMethod::Pin, Script::SucceedAfter(1));
    let (outcome, _) = go(&nothing, vec![pin], 5_000);
    assert_eq!(outcome.result, PromptResult::Success);
    assert!(pin_started.load(Ordering::SeqCst));
}

#[test]
fn more_than_one_factor_is_not_run() {
    let mut two = rule();
    two.factors = 2;
    let (pin, _, started) = fake(AuthMethod::Pin, Script::SucceedAfter(1));
    let (outcome, updates) = go(&two, vec![pin], 5_000);
    assert_eq!(outcome, Outcome::new(PromptResult::Failure));
    assert!(!started.load(Ordering::SeqCst));
    assert_eq!(results(&updates).len(), 1);

    let mut unsatisfiable = rule();
    unsatisfiable.unsatisfiable = true;
    let (pin, _, started) = fake(AuthMethod::Pin, Script::SucceedAfter(1));
    let (outcome, _) = go(&unsatisfiable, vec![pin], 5_000);
    assert_eq!(outcome.result, PromptResult::Failure);
    assert!(!started.load(Ordering::SeqCst));
}

#[test]
fn a_panicking_method_is_a_failure_not_a_crash() {
    let (bad, _, _) = fake(AuthMethod::Face, Script::Panic);
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(60));
    let (outcome, _) = go(&rule(), vec![bad, finger], 5_000);
    assert_eq!(
        outcome.result,
        PromptResult::Success,
        "the others still run"
    );

    let (bad, _, _) = fake(AuthMethod::Face, Script::Panic);
    let (outcome, _) = go(&rule(), vec![bad], 5_000);
    assert_eq!(outcome, Outcome::new(PromptResult::Failure));
}

#[test]
fn an_outside_stop_cancels_everything_and_says_cancelled() {
    let (face, cancelled, _) = fake(AuthMethod::Face, Script::UntilCancelled);
    let stop = Cancel::default();
    let recorder = Recorder::default();
    let mut reporter = recorder.clone();
    let outcome = std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            Orchestrator::run(
                &rule(),
                vec![face],
                &mut reporter,
                Duration::from_secs(30),
                &stop,
            )
        });
        sleep(Duration::from_millis(100));
        stop.cancel();
        run.join().unwrap()
    });
    assert_eq!(outcome.result, PromptResult::Cancelled);
    assert_eq!(outcome.reason, PromptReason::Cancelled);
    assert!(cancelled.load(Ordering::SeqCst));
    assert_eq!(results(&recorder.updates()).len(), 1);
}
