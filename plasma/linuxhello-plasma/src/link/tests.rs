//! Tests of the Agent Link's connection handling: the pure parts run everywhere; the ones that
//! need a bus start a private `dbus-daemon` and a fake Agent on it, and are `#[ignore]`d where
//! that program is not installed (run them with `cargo test -- --ignored`; the Plasma job of the
//! pipeline does not have it, see the pull request that added them).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;

#[test]
fn the_wait_between_tries_doubles_and_stops_at_the_limit() {
    let mut delay = RETRY_FIRST;
    let mut seen = Vec::new();
    for _ in 0..8 {
        seen.push(delay);
        delay = next_delay(delay);
    }
    assert_eq!(seen[0], Duration::from_secs(1));
    assert_eq!(seen[1], Duration::from_secs(2));
    assert_eq!(seen[2], Duration::from_secs(4));
    assert_eq!(delay, RETRY_MAX);
    assert!(seen.iter().all(|d| *d <= RETRY_MAX));
}

#[test]
fn a_ping_that_is_not_answered_says_no_within_its_limit() {
    // R-26, #368: the question ran on the screen's own thread with no limit.
    let started = Instant::now();
    let answered = answers_within(Duration::from_millis(100), || {
        std::thread::sleep(Duration::from_secs(2));
        true
    });
    assert!(!answered);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn a_ping_that_is_answered_says_what_the_answer_was() {
    assert!(answers_within(Duration::from_secs(2), || true));
    assert!(!answers_within(Duration::from_secs(2), || false));
}

/// A private bus daemon that is stopped when the value is dropped.
struct Daemon {
    child: Child,
    address: String,
}

impl Daemon {
    /// Starts `dbus-daemon` with the default session configuration and reads its address.
    fn start() -> Self {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon must be installed to run this test");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        Self {
            child,
            address: line.trim().to_string(),
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An Agent that answers `WatchPrompts` and nothing else.
struct FakeAgent;

#[zbus::interface(name = "io.github.LinuxHello.Agent1")]
impl FakeAgent {
    /// Accepts the registration of a watcher.
    async fn watch_prompts(&self) {}
}

/// A connection to the daemon at `address` that owns the Agent's name and answers `WatchPrompts`.
async fn start_agent(address: &str) -> Connection {
    zbus::connection::Builder::address(address)
        .name(AGENT_BUS_NAME)
        .serve_at(AGENT_OBJECT_PATH, FakeAgent)
        .build()
        .await
        .unwrap()
}

/// Runs the listening loop against the daemon on a thread of its own; returns the `reachable`
/// values it published, in order.
fn listen_to(address: &str) -> Arc<Mutex<Vec<bool>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let address = address.to_string();
    std::thread::spawn(move || {
        futures_lite::future::block_on(keep_listening(
            || {
                let address = address.clone();
                async move {
                    zbus::connection::Builder::address(address.as_str())
                        .build()
                        .await
                }
            },
            Follow::Watch,
            move |_json, reachable| record.lock().unwrap().push(reachable),
            Duration::from_millis(50),
        ));
    });
    seen
}

/// Waits up to five seconds until `seen` satisfies `done`.
fn wait_until(seen: &Arc<Mutex<Vec<bool>>>, done: impl Fn(&[bool]) -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        if done(&seen.lock().unwrap()) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
#[ignore = "needs dbus-daemon; run with `cargo test -- --ignored`"]
fn an_agent_that_is_not_there_at_the_start_is_followed_when_it_appears() {
    // R-26, #368: a first start without the Agent was never retried.
    let daemon = Daemon::start();
    let seen = listen_to(&daemon.address);
    assert!(
        wait_until(&seen, |s| s.contains(&false)),
        "not reachable first"
    );
    assert!(!seen.lock().unwrap().contains(&true));
    let _agent = futures_lite::future::block_on(start_agent(&daemon.address));
    assert!(
        wait_until(&seen, |s| s.last() == Some(&true)),
        "reachable once the Agent is there: {:?}",
        seen.lock().unwrap()
    );
}

#[test]
#[ignore = "needs dbus-daemon; run with `cargo test -- --ignored`"]
fn a_new_agent_after_a_restart_is_followed() {
    // R-26, #368: after an Agent restart every signal was dropped (the sender is another unique
    // name) while the screen went on showing "reachable".
    let daemon = Daemon::start();
    let first = futures_lite::future::block_on(start_agent(&daemon.address));
    let seen = listen_to(&daemon.address);
    assert!(
        wait_until(&seen, |s| s.last() == Some(&true)),
        "follows the first Agent"
    );
    drop(first);
    assert!(
        wait_until(&seen, |s| s.last() == Some(&false)),
        "says not reachable when the Agent is gone: {:?}",
        seen.lock().unwrap()
    );
    let _second = futures_lite::future::block_on(start_agent(&daemon.address));
    assert!(
        wait_until(&seen, |s| s.last() == Some(&true)),
        "follows the Agent that came back: {:?}",
        seen.lock().unwrap()
    );
}
