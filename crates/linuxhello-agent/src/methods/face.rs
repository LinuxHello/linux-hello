//! The face method: the Agent runs Howdy as a child process (ADR-0023, amendment 2026-11-19,
//! second part).
//!
//! In plain words: Howdy is a separate program with no bus interface. To check a face the Agent
//! starts it, once, for the user who signs in, and waits for it to end. Howdy says how it went by
//! its exit code. If the orchestrator says stop, the Agent ends the child.
//!
//! | Exit code of the compare script | Meaning here |
//! | :-- | :-- |
//! | 0 | success |
//! | 10 | the user has no face model: the method is unavailable |
//! | 11 | no match before Howdy's own timeout: failure, reason `not-recognised` |
//! | 12 | aborted: the method ends cancelled |
//! | anything else, or a signal | unavailable |
//!
//! These are the codes of Howdy's PAM wrapper at the time of writing; the tests pin them, and they
//! must be checked against the installed version. The command line is fixed (the interpreter, the
//! compare script of Howdy and the user's account name) and run with an empty environment and no
//! input or output: it is never built from anything the caller sends. The child inherits the Agent's
//! AppArmor profile (`ix`); a profile of its own would be narrower, but the kernel refuses to enter
//! it under the unit's NoNewPrivileges. Isolating Howdy with a helper unit is a follow-up.
//!
//! What this does **not** solve: Howdy keeps its face models readable by root only, so an Agent
//! that runs as its own user cannot read them until the deployment gives it access (a group, or a
//! helper). That is a packaging decision and is open on #195.
//!
//! C4 component: `methodOrch` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use linuxhello_dbus::{AuthMethod, PromptReason};

use crate::orchestrator::{Cancel, Method, MethodEnd};

/// The interpreter that runs Howdy's compare script.
const PYTHON: &str = "/usr/bin/python3";

/// Howdy's compare script, the program its own PAM module runs.
const COMPARE_SCRIPT: &str = "/lib/security/howdy/compare.py";

/// How often a running child is looked at.
const POLL: Duration = Duration::from_millis(50);

/// The longest the child may run, whatever Howdy's own timeout says.
const CHILD_LIMIT: Duration = Duration::from_secs(120);

/// How long a child gets to end after it was killed.
const REAP_LIMIT: Duration = Duration::from_secs(2);

/// The face method for one user.
pub struct FaceMethod {
    /// What to run: the program, and its arguments (the script and the account name).
    command: (PathBuf, Vec<String>),
    /// A file whose presence says that the method can run (the compare script).
    presence: PathBuf,
}

impl FaceMethod {
    /// The method for the account `username`, with Howdy's own command.
    pub fn new(username: &str) -> Self {
        Self {
            command: (
                PathBuf::from(PYTHON),
                vec![COMPARE_SCRIPT.to_string(), username.to_string()],
            ),
            presence: PathBuf::from(COMPARE_SCRIPT),
        }
    }

    /// The same method running `program` with `arguments` instead, and available when `presence`
    /// exists; for tests.
    #[must_use]
    pub fn with_command(
        program: impl Into<PathBuf>,
        arguments: Vec<String>,
        presence: impl Into<PathBuf>,
    ) -> Self {
        Self {
            command: (program.into(), arguments),
            presence: presence.into(),
        }
    }
}

impl Method for FaceMethod {
    fn kind(&self) -> AuthMethod {
        AuthMethod::Face
    }

    fn available(&self) -> bool {
        self.presence.exists()
    }

    fn run(&mut self, cancel: &Cancel) -> MethodEnd {
        let (program, arguments) = &self.command;
        let child = Command::new(program)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else {
            return MethodEnd::Unavailable;
        };
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return end_of(status.code()),
                Ok(None) => {}
                Err(_) => {
                    stop(&mut child);
                    return MethodEnd::Unavailable;
                }
            }
            if cancel.is_cancelled() {
                stop(&mut child);
                return MethodEnd::Cancelled;
            }
            if started.elapsed() >= CHILD_LIMIT {
                stop(&mut child);
                return MethodEnd::Unavailable;
            }
            std::thread::sleep(POLL);
        }
    }
}

/// What an exit code of the compare script means.
fn end_of(code: Option<i32>) -> MethodEnd {
    match code {
        Some(0) => MethodEnd::Success,
        Some(11) => MethodEnd::Failure(PromptReason::NotRecognised),
        Some(12) => MethodEnd::Cancelled,
        _ => MethodEnd::Unavailable,
    }
}

/// Ends the child and collects it, so that no zombie is left; gives up waiting after a moment.
fn stop(child: &mut Child) {
    let _ = child.kill();
    let until = Instant::now() + REAP_LIMIT;
    while Instant::now() < until {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests;
