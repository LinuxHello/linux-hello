//! Tests of the face method on stand-ins for Howdy: shell scripts that exit with a given code.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use linuxhello_dbus::PromptReason;
use tempfile::TempDir;

use super::*;

/// A method that runs `/bin/sh -c script`, available because `/bin/sh` is there.
fn sh(script: &str) -> FaceMethod {
    FaceMethod::with_command("/bin/sh", vec!["-c".into(), script.into()], "/bin/sh")
}

#[test]
fn howdys_exit_codes_are_mapped() {
    for (code, expected) in [
        (0, MethodEnd::Success),
        (10, MethodEnd::Unavailable),
        (11, MethodEnd::Failure(PromptReason::NotRecognised)),
        (12, MethodEnd::Cancelled),
        (1, MethodEnd::Unavailable),
        (13, MethodEnd::Unavailable),
        (255, MethodEnd::Unavailable),
    ] {
        let mut method = sh(&format!("exit {code}"));
        assert_eq!(method.run(&Cancel::default()), expected, "exit {code}");
    }
}

#[test]
fn a_child_that_is_killed_by_a_signal_is_unavailable() {
    let mut method = sh("kill -9 $$");
    assert_eq!(method.run(&Cancel::default()), MethodEnd::Unavailable);
}

#[test]
fn a_program_that_cannot_start_is_unavailable() {
    let mut method = FaceMethod::with_command("/nonexistent/howdy", vec![], "/bin/sh");
    assert_eq!(method.run(&Cancel::default()), MethodEnd::Unavailable);
}

#[test]
fn cancelling_ends_the_child() {
    let dir = TempDir::new().unwrap();
    let marker = dir.path().join("still-running");
    // Touches the marker every 50 ms for as long as it lives.
    let script = format!(
        "while true; do touch {}; sleep 0.05; done",
        marker.display()
    );
    let mut method = sh(&script);
    let cancel = Cancel::default();
    let flag = cancel.clone();
    let handle = std::thread::spawn(move || method.run(&flag));
    std::thread::sleep(Duration::from_millis(300));
    assert!(marker.exists(), "the child was running");
    let started = Instant::now();
    cancel.cancel();
    assert_eq!(handle.join().unwrap(), MethodEnd::Cancelled);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    // The child is gone: the marker stops being touched.
    std::fs::remove_file(&marker).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "the child still ran after the cancel");
}

#[test]
fn the_child_gets_an_empty_environment_and_no_input() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("env");
    // Records the variables it sees and succeeds only if standard input is empty.
    let script = format!("env > {}; test -z \"$(cat)\"", out.display());
    let mut method = sh(&script);
    assert_eq!(method.run(&Cancel::default()), MethodEnd::Success);
    let seen = std::fs::read_to_string(&out).unwrap();
    // Whatever the Agent itself runs with does not reach the child.
    assert!(!seen.contains("HOME="), "{seen}");
    assert!(!seen.contains("USER="), "{seen}");
    assert!(seen.contains("PATH=/usr/bin:/bin"), "{seen}");
}

#[test]
fn the_method_is_available_only_when_howdy_is_there() {
    let dir = TempDir::new().unwrap();
    let script: PathBuf = dir.path().join("compare.py");
    let method = FaceMethod::with_command("/bin/true", vec![], &script);
    assert!(!method.available());
    std::fs::write(&script, "").unwrap();
    assert!(method.available());
    // The real command line is fixed, and names the account and nothing else.
    let real = FaceMethod::new("anna");
    assert_eq!(real.command.0, Path::new("/usr/bin/python3"));
    assert_eq!(
        real.command.1,
        [
            "/lib/security/howdy/compare.py".to_string(),
            "anna".to_string()
        ]
    );
}
