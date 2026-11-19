//! The Method Orchestrator: runs the sign-in methods of a prompt side by side, lets the first
//! success win, cancels the rest and tells a [`Reporter`] what happens (ADR-0023, decision 1).
//!
//! In plain words: when someone signs in, the Agent may offer face, fingerprint and PIN at the
//! same time. This module starts every method that the policy allows and that works on this
//! machine, each on a thread of its own, and waits. The first method that succeeds ends the
//! attempt; the others are told to stop. If all of them fail, or the time runs out, the attempt
//! fails and says why.
//!
//! The orchestrator knows no real method and no bus: a [`Method`] is anything that can run and
//! be cancelled, and a [`Reporter`] is anything that wants the state in the shapes of the bus
//! (`Update`). Real methods (fprintd, Howdy, the PIN) and the call that starts it are later
//! slices of #195. This slice supports one factor: a context that asks for more is not run.
//!
//! The reporter is used only by the thread that calls [`Orchestrator::run`]; method threads only
//! send their end over a channel, so a method that is slow to stop can never report anything
//! later (`a_method_that_ignores_cancel_does_not_hold_the_orchestrator`).
//!
//! C4 component: `methodOrch` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use linuxhello_dbus::{AuthMethod, PromptReason, PromptResult, PromptState};

use crate::policy::MethodRule;
use crate::state::{Outcome, Update};

/// How often the orchestrator looks at the caller's stop flag.
const STOP_POLL: Duration = Duration::from_millis(50);

/// How long the orchestrator waits for cancelled methods to stop before it returns anyway.
const STOP_GRACE: Duration = Duration::from_secs(1);

/// What one method reports when it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodEnd {
    /// The user was recognised.
    Success,
    /// The method ran and did not recognise the user, with the reason it can give.
    Failure(PromptReason),
    /// The method could not run (the reader went away, Howdy failed to start).
    Unavailable,
    /// The method stopped because it was told to.
    Cancelled,
    /// The user is locked out of this method for this many seconds (too many wrong PINs).
    LockedOut(u32),
}

/// A flag that a method reads and the orchestrator sets.
#[derive(Clone, Debug, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// Whether the method must stop now.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Tells every holder of this flag to stop. The orchestrator does this to its methods; the
    /// Agent does it to an authentication whose prompt was closed.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A way of signing in: face, fingerprint or PIN. It runs on a thread of its own, so it may block.
pub trait Method: Send {
    /// Which method it is.
    fn kind(&self) -> AuthMethod;

    /// Whether the method can run now: the reader is there, Howdy is installed, a PIN is set.
    fn available(&self) -> bool;

    /// Runs until it succeeds, fails or `cancel` is set. It must look at `cancel` at least every
    /// 100 milliseconds.
    fn run(&mut self, cancel: &Cancel) -> MethodEnd;
}

/// Where the orchestrator tells the world what is happening.
pub trait Reporter: Send {
    /// One change of the prompt's state, in the terms of the bus signals.
    fn report(&mut self, update: Update);
}

/// The orchestrator; it has no state of its own.
pub struct Orchestrator;

impl Orchestrator {
    /// Runs the methods that `rule` allows and that are available, until one succeeds, all end
    /// without success, or `deadline` passes.
    ///
    /// `stop` is a flag of the caller: when it is set the attempt ends at once with the result
    /// `cancelled` (the prompt was closed). It is looked at every 50 milliseconds.
    ///
    /// Reports, in this order: `Methods` (the methods that run, none if none can), `Active`, the
    /// state, then, when the attempt ends, `Active` empty, `State(Idle)` and `Result`. An
    /// attempt that cannot start (more than one factor, an unsatisfiable context, no method)
    /// reports `Methods` and `Result` only.
    pub fn run(
        rule: &MethodRule,
        methods: Vec<Box<dyn Method>>,
        reporter: &mut dyn Reporter,
        deadline: Duration,
        stop: &Cancel,
    ) -> Outcome {
        let mut chosen: Vec<Box<dyn Method>> = methods
            .into_iter()
            .filter(|m| allowed(rule, m.kind()) && m.available())
            .collect();
        chosen.sort_by_key(|m| order(m.kind()));
        let kinds: Vec<AuthMethod> = chosen.iter().map(|m| m.kind()).collect();

        if rule.factors > 1 || rule.unsatisfiable || chosen.is_empty() {
            reporter.report(Update::Methods(if rule.factors > 1 || rule.unsatisfiable {
                Vec::new()
            } else {
                kinds
            }));
            return finish(reporter, Outcome::new(PromptResult::Failure));
        }

        reporter.report(Update::Methods(kinds.clone()));
        reporter.report(Update::Active(kinds.clone()));
        reporter.report(Update::State(
            if kinds
                .iter()
                .any(|k| matches!(k, AuthMethod::Face | AuthMethod::Fingerprint))
            {
                PromptState::Scanning
            } else {
                PromptState::WaitingForInput
            },
        ));

        let cancel = Cancel::default();
        let (sender, receiver) = channel();
        for (index, mut method) in chosen.into_iter().enumerate() {
            let (cancel, sender) = (cancel.clone(), sender.clone());
            std::thread::spawn(move || {
                // A method that panics is a method that could not run, not a crash of the Agent.
                let end = catch_unwind(AssertUnwindSafe(|| method.run(&cancel)))
                    .unwrap_or(MethodEnd::Unavailable);
                let _ = sender.send((index, end));
            });
        }
        drop(sender);

        let started = Instant::now();
        let mut running: Vec<(usize, AuthMethod)> = kinds.iter().copied().enumerate().collect();
        let mut last_failure: Option<PromptReason> = None;
        let mut locked_out: Option<u32> = None;
        let outcome = loop {
            if stop.is_cancelled() {
                cancel.cancel();
                wait_for_stop(&receiver, running.len());
                break Outcome {
                    reason: PromptReason::Cancelled,
                    ..Outcome::new(PromptResult::Cancelled)
                };
            }
            let Some(left) = deadline.checked_sub(started.elapsed()) else {
                break timed_out(&cancel, &receiver);
            };
            match receiver.recv_timeout(left.min(STOP_POLL)) {
                Ok((index, MethodEnd::Success)) if running.iter().any(|(i, _)| *i == index) => {
                    cancel.cancel();
                    wait_for_stop(&receiver, running.len().saturating_sub(1));
                    break Outcome::new(PromptResult::Success);
                }
                Ok((index, end)) => {
                    running.retain(|(i, _)| *i != index);
                    if let MethodEnd::LockedOut(seconds) = end {
                        locked_out = Some(seconds);
                    }
                    if let MethodEnd::Failure(reason) = end {
                        last_failure = Some(if reason == PromptReason::None {
                            PromptReason::NotRecognised
                        } else {
                            reason
                        });
                    }
                    if running.is_empty() {
                        break failed(last_failure, locked_out);
                    }
                    reporter.report(Update::Active(running.iter().map(|(_, k)| *k).collect()));
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break failed(last_failure, locked_out),
            }
        };
        reporter.report(Update::Active(Vec::new()));
        reporter.report(Update::State(PromptState::Idle));
        finish(reporter, outcome)
    }
}

/// The outcome when no method succeeded: locked out if a method said so, else a failure with the
/// reason of the last one.
fn failed(last_failure: Option<PromptReason>, locked_out: Option<u32>) -> Outcome {
    match locked_out {
        Some(seconds) => Outcome {
            retry_after: seconds,
            ..Outcome::new(PromptResult::LockedOut)
        },
        None => Outcome {
            reason: last_failure.unwrap_or(PromptReason::None),
            ..Outcome::new(PromptResult::Failure)
        },
    }
}

/// Reports the result and returns it.
fn finish(reporter: &mut dyn Reporter, outcome: Outcome) -> Outcome {
    reporter.report(Update::Result(outcome));
    outcome
}

/// The deadline passed: stop every method, wait for them a moment, and fail with `timeout`.
fn timed_out(cancel: &Cancel, receiver: &std::sync::mpsc::Receiver<(usize, MethodEnd)>) -> Outcome {
    cancel.cancel();
    wait_for_stop(receiver, usize::MAX);
    Outcome {
        reason: PromptReason::Timeout,
        ..Outcome::new(PromptResult::Failure)
    }
}

/// Waits until `count` more methods have ended or [`STOP_GRACE`] has passed, whichever is first.
/// A method that does not stop in time is left to end on its own.
fn wait_for_stop(receiver: &std::sync::mpsc::Receiver<(usize, MethodEnd)>, count: usize) {
    let until = Instant::now() + STOP_GRACE;
    let mut seen = 0;
    while seen < count {
        let Some(left) = until.checked_duration_since(Instant::now()) else {
            return;
        };
        match receiver.recv_timeout(left) {
            Ok(_) => seen += 1,
            Err(_) => return,
        }
    }
}

/// Whether the policy allows `kind`; the PIN is always allowed.
fn allowed(rule: &MethodRule, kind: AuthMethod) -> bool {
    kind == AuthMethod::Pin || rule.methods.iter().any(|name| name == kind.as_wire())
}

/// The order in which methods are listed and started: face, fingerprint, PIN.
fn order(kind: AuthMethod) -> u8 {
    match kind {
        AuthMethod::Face => 0,
        AuthMethod::Fingerprint => 1,
        AuthMethod::Pin => 2,
    }
}

#[cfg(test)]
mod tests;
