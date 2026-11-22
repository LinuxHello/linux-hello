//! Tests of the orchestrator on fake methods: who wins, who is cancelled, what is reported.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};

use linuxhello_dbus::{AuthMethod, MethodOutcome, PromptReason, PromptResult, PromptState};

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
    /// Ends locked out for this many seconds after this many milliseconds.
    LockedOutAfter(u64, u32),
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
            Script::LockedOutAfter(ms, seconds) => {
                if waited(ms) {
                    MethodEnd::LockedOut(seconds)
                } else {
                    MethodEnd::Cancelled
                }
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
            Update::MethodEnded(
                AuthMethod::Fingerprint,
                MethodOutcome::Matched,
                PromptReason::None,
                0
            ),
            Update::Active(vec![]),
            Update::State(PromptState::Idle),
            Update::Result(Outcome::new(PromptResult::Success)),
        ]
    );
}

/// The `MethodEnded` reports among the updates.
fn ended(updates: &[Update]) -> Vec<(AuthMethod, MethodOutcome, PromptReason, u32)> {
    updates
        .iter()
        .filter_map(|u| match u {
            Update::MethodEnded(m, o, r, s) => Some((*m, *o, *r, *s)),
            _ => None,
        })
        .collect()
}

#[test]
fn each_method_that_ends_is_reported_with_its_outcome() {
    let (finger, _, _) = fake(
        AuthMethod::Fingerprint,
        Script::FailAfter(20, PromptReason::None),
    );
    let (face, _, _) = fake(AuthMethod::Face, Script::UnavailableAfter(60));
    let (pin, _, _) = fake(AuthMethod::Pin, Script::LockedOutAfter(100, 720));
    let (_, updates) = go(&rule(), vec![finger, face, pin], 5_000);
    assert_eq!(
        ended(&updates),
        [
            // A failure without a reason is reported as not recognised, as in `Result`.
            (
                AuthMethod::Fingerprint,
                MethodOutcome::Failed,
                PromptReason::NotRecognised,
                0
            ),
            (
                AuthMethod::Face,
                MethodOutcome::Unavailable,
                PromptReason::None,
                0
            ),
            (
                AuthMethod::Pin,
                MethodOutcome::LockedOut,
                PromptReason::None,
                720
            ),
        ]
    );
    // Each is reported before the list of running methods shrinks.
    let first_end = updates
        .iter()
        .position(|u| matches!(u, Update::MethodEnded(..)))
        .unwrap();
    assert_eq!(
        updates[first_end + 1],
        Update::Active(vec![AuthMethod::Face, AuthMethod::Pin])
    );
}

#[test]
fn a_method_stopped_because_another_won_reports_nothing() {
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(30));
    let (face, face_cancelled, _) = fake(AuthMethod::Face, Script::UntilCancelled);
    let (pin, _, _) = fake(AuthMethod::Pin, Script::UntilCancelled);
    let (_, updates) = go(&rule(), vec![finger, face, pin], 5_000);
    assert!(face_cancelled.load(Ordering::SeqCst));
    assert_eq!(
        ended(&updates),
        [(
            AuthMethod::Fingerprint,
            MethodOutcome::Matched,
            PromptReason::None,
            0
        )]
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

/// A rule that needs `factors` methods and allows every method.
fn factors(factors: u32) -> MethodRule {
    MethodRule { factors, ..rule() }
}

#[test]
fn fewer_methods_than_factors_is_not_run() {
    let (pin, _, started) = fake(AuthMethod::Pin, Script::SucceedAfter(1));
    let (outcome, updates) = go(&factors(2), vec![pin], 5_000);
    assert_eq!(outcome, Outcome::new(PromptResult::Failure));
    assert!(!started.load(Ordering::SeqCst));
    assert_eq!(updates[0], Update::Methods(vec![AuthMethod::Pin]));
    assert_eq!(results(&updates).len(), 1);

    let mut unsatisfiable = rule();
    unsatisfiable.unsatisfiable = true;
    let (pin, _, started) = fake(AuthMethod::Pin, Script::SucceedAfter(1));
    let (outcome, updates) = go(&unsatisfiable, vec![pin], 5_000);
    assert_eq!(outcome.result, PromptResult::Failure);
    assert!(!started.load(Ordering::SeqCst));
    assert_eq!(updates[0], Update::Methods(vec![]));
}

#[test]
fn two_factors_need_two_different_methods_in_stages() {
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(30));
    let (pin, _, _) = fake(AuthMethod::Pin, Script::SucceedAfter(300));
    let (outcome, updates) = go(&factors(2), vec![finger, pin], 5_000);
    assert_eq!(outcome, Outcome::new(PromptResult::Success));
    // Both ran in the first stage; the fingerprint won it, and the PIN got a stage of its own.
    assert_eq!(
        updates,
        vec![
            Update::Methods(vec![AuthMethod::Fingerprint, AuthMethod::Pin]),
            Update::Active(vec![AuthMethod::Fingerprint, AuthMethod::Pin]),
            Update::State(PromptState::Scanning),
            Update::MethodEnded(
                AuthMethod::Fingerprint,
                MethodOutcome::Matched,
                PromptReason::None,
                0
            ),
            Update::Active(vec![AuthMethod::Pin]),
            Update::State(PromptState::WaitingForInput),
            Update::MethodEnded(
                AuthMethod::Pin,
                MethodOutcome::Matched,
                PromptReason::None,
                0
            ),
            Update::Active(vec![]),
            Update::State(PromptState::Idle),
            Update::Result(Outcome::new(PromptResult::Success)),
        ]
    );
}

#[test]
fn the_second_factor_failing_fails_the_attempt() {
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(20));
    let (pin, _, _) = fake(
        AuthMethod::Pin,
        Script::FailAfter(60, PromptReason::NotRecognised),
    );
    let (outcome, _) = go(&factors(2), vec![finger, pin], 5_000);
    assert_eq!(outcome.result, PromptResult::Failure);
    assert_eq!(outcome.reason, PromptReason::NotRecognised);
}

#[test]
fn three_factors_need_all_three_methods() {
    let (face, _, _) = fake(AuthMethod::Face, Script::SucceedAfter(10));
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(60));
    let (pin, _, _) = fake(AuthMethod::Pin, Script::SucceedAfter(120));
    let (outcome, updates) = go(&factors(3), vec![face, finger, pin], 5_000);
    assert_eq!(outcome.result, PromptResult::Success);
    assert_eq!(results(&updates).len(), 1);
    // A stage for each factor: three lists of running methods, shrinking by the winner.
    let actives: Vec<&Update> = updates
        .iter()
        .filter(|u| matches!(u, Update::Active(a) if !a.is_empty()))
        .collect();
    assert!(actives.len() >= 3, "{updates:?}");
}

#[test]
fn a_method_never_counts_twice() {
    // Two factors, two methods, but one of them can never succeed: the attempt fails; the one that
    // can does not count a second time.
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(10));
    let (pin, _, _) = fake(AuthMethod::Pin, Script::UnavailableAfter(10));
    let (outcome, _) = go(&factors(2), vec![finger, pin], 5_000);
    assert_eq!(outcome.result, PromptResult::Failure);
}

#[test]
fn the_deadline_is_for_the_whole_attempt_not_for_a_stage() {
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(150));
    let (pin, _, _) = fake(AuthMethod::Pin, Script::SucceedAfter(200));
    let started = Instant::now();
    // The first stage takes 150 ms and the second 200 ms more: 350 ms, over the deadline of 300 ms,
    // though neither stage alone is.
    let (outcome, _) = go(&factors(2), vec![finger, pin], 300);
    assert_eq!(outcome.reason, PromptReason::Timeout);
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_stop_between_stages_ends_the_attempt() {
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(20));
    let (pin, _, _) = fake(AuthMethod::Pin, Script::UntilCancelled);
    let stop = Cancel::default();
    let recorder = Recorder::default();
    let mut reporter = recorder.clone();
    let outcome = std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            Orchestrator::run(
                &factors(2),
                vec![finger, pin],
                &mut reporter,
                Duration::from_secs(30),
                &stop,
            )
        });
        sleep(Duration::from_millis(250));
        stop.cancel();
        run.join().unwrap()
    });
    assert_eq!(outcome.result, PromptResult::Cancelled);
    assert_eq!(results(&recorder.updates()).len(), 1);
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

#[test]
fn a_locked_out_method_gives_a_locked_out_result_with_the_seconds() {
    let (pin, _, _) = fake(AuthMethod::Pin, Script::LockedOutAfter(10, 900));
    let (face, _, _) = fake(
        AuthMethod::Face,
        Script::FailAfter(30, PromptReason::NoFace),
    );
    let (outcome, updates) = go(&rule(), vec![pin, face], 5_000);
    assert_eq!(outcome.result, PromptResult::LockedOut);
    assert_eq!(outcome.retry_after, 900);
    assert_eq!(results(&updates), vec![outcome]);

    // A success of another method still wins over a lockout.
    let (pin, _, _) = fake(AuthMethod::Pin, Script::LockedOutAfter(10, 900));
    let (finger, _, _) = fake(AuthMethod::Fingerprint, Script::SucceedAfter(50));
    let (outcome, _) = go(&rule(), vec![pin, finger], 5_000);
    assert_eq!(outcome.result, PromptResult::Success);
    assert_eq!(outcome.retry_after, 0);
}
