//! How long the Agent takes to answer `GetState` and `ReportState` over a bus: budget L1 of
//! Arc42 section 10 (5 ms at p99). Run it with `make bench`.
//!
//! It prints one line per method and situation: the number of timed calls, p50, p99 and the
//! slowest call, in milliseconds. It exits 0 whatever the numbers are, unless `LH_ENFORCE_BUDGET=1`
//! is set, and then it exits 1 when any p99 is above 5 ms. The budget is not a CI gate yet: it
//! is not expected to hold before the request-path work of #150 is done.
//!
//! What the numbers are and are not. The Agent runs in this process, on a private `dbus-daemon`
//! with its default session configuration, not on the system bus with the Agent's bus policy and
//! AppArmor profile, so they are a lower bound. "A second user" is a second *connection* of the
//! same Linux user: a real second uid needs root and the system bus, which the confinement run
//! (`make vm-test-agent` in the workstation repository) covers.
//!
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#[path = "../../tests/common/mod.rs"]
mod common;
mod stats;

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{call, connect, my_uid, pid, run, Daemon};
use linuxhello_agent::bus::serve_with;
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;
use zbus::connection::Builder;

/// Calls that are made and not counted, so that connections and caches are warm.
const WARM_UP: usize = 200;

/// Calls that are timed, per caller.
const TIMED: usize = 2000;

/// The methods under test.
const METHODS: [&str; 2] = ["GetState", "ReportState"];

/// One situation: how many callers, and whether a second connection writes a user policy.
struct Situation {
    /// What the line is called.
    name: &'static str,
    /// Callers at once, each with its own connection and its own prompt.
    callers: usize,
    /// Whether a second connection calls `SetUserPolicy` in a loop.
    writer: bool,
}

/// The four situations of the brief of #255.
const SITUATIONS: [Situation; 4] = [
    Situation {
        name: "1 caller",
        callers: 1,
        writer: false,
    },
    Situation {
        name: "50 callers",
        callers: 50,
        writer: false,
    },
    Situation {
        name: "1 caller + writer",
        callers: 1,
        writer: true,
    },
    Situation {
        name: "50 callers + writer",
        callers: 50,
        writer: true,
    },
];

/// A valid user policy of about 1 KiB; `allowed` makes two texts that differ.
fn policy_text(allowed: bool) -> String {
    let mut text = format!("[methods]\nbiometrics_allowed = {allowed}\n");
    while text.len() < 1024 {
        text.push_str("# padding to make the file about a kilobyte, as a real layer would be\n");
    }
    text
}

/// One caller: opens its prompt, then times `calls` calls of `method` after `WARM_UP` more.
fn caller(daemon: &Daemon, index: usize, method: &str) -> Result<Vec<Duration>, String> {
    run(async {
        let connection = connect(daemon).await;
        let id = pid(&format!("bench-{index}"));
        call(
            &connection,
            "OpenPrompt",
            &(id.as_str(), i64::from(my_uid())),
        )
        .await
        .map_err(|e| format!("OpenPrompt: {e}"))?;
        let mut samples = Vec::with_capacity(TIMED);
        for round in 0..WARM_UP + TIMED {
            let started = Instant::now();
            let outcome = if method == "GetState" {
                call(&connection, "GetState", &(id.as_str(),)).await
            } else {
                call(
                    &connection,
                    "ReportState",
                    &(id.as_str(), "State", vec!["scanning"]),
                )
                .await
            };
            let elapsed = started.elapsed();
            if round >= WARM_UP {
                stats::record(
                    &mut samples,
                    outcome
                        .map(|_| elapsed)
                        .map_err(|e| format!("{method}: {e}")),
                )?;
            } else {
                outcome.map_err(|e| format!("{method}: {e}"))?;
            }
        }
        Ok(samples)
    })
}

/// Runs one method in one situation and returns all timed calls of all callers.
fn measure(daemon: &Daemon, situation: &Situation, method: &str) -> Result<Vec<Duration>, String> {
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let writer = situation.writer.then(|| {
            scope.spawn(|| {
                run(async {
                    let connection = connect(daemon).await;
                    let texts = [policy_text(false), policy_text(true)];
                    let mut turn = 0;
                    while !done.load(Ordering::Relaxed) {
                        call(&connection, "SetUserPolicy", &texts[turn % 2])
                            .await
                            .map_err(|e| format!("SetUserPolicy: {e}"))?;
                        turn += 1;
                    }
                    Ok::<(), String>(())
                })
            })
        });
        let callers: Vec<_> = (0..situation.callers)
            .map(|index| scope.spawn(move || caller(daemon, index, method)))
            .collect();
        let mut all = Vec::new();
        let mut failure = None;
        for handle in callers {
            match handle.join().map_err(|_| "a caller panicked".to_string())? {
                Ok(samples) => all.extend(samples),
                Err(error) => failure = Some(error),
            }
        }
        done.store(true, Ordering::Relaxed);
        if let Some(writer) = writer {
            writer
                .join()
                .map_err(|_| "the writer panicked".to_string())??;
        }
        failure.map_or(Ok(all), Err)
    })
}

/// A duration in milliseconds with two decimals.
fn ms(duration: Duration) -> String {
    format!("{:.2}", duration.as_secs_f64() * 1000.0)
}

/// Runs every situation and prints the table.
fn main() -> ExitCode {
    let daemon = Daemon::start();
    let store_dir = private_tempdir();
    let _service = run(serve_with(
        Builder::address(daemon.address.as_str()),
        Config::new(vec![]),
        Some(UserPolicyStore::new(store_dir.path())),
    ))
    .expect("serve the Agent");
    println!(
        "agent in this process, private dbus-daemon --session (a lower bound, see the file header)"
    );
    println!(
        "{:<12} {:<20} {:>7} {:>9} {:>9} {:>9}",
        "method", "situation", "n", "p50 ms", "p99 ms", "max ms"
    );
    let mut p99s = Vec::new();
    for method in METHODS {
        for situation in &SITUATIONS {
            let mut samples = match measure(&daemon, situation, method) {
                Ok(samples) => samples,
                Err(error) => {
                    eprintln!("the benchmark stopped: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let Some(summary) = stats::summarise(&mut samples) else {
                eprintln!("the benchmark stopped: no call was timed");
                return ExitCode::FAILURE;
            };
            println!(
                "{:<12} {:<20} {:>7} {:>9} {:>9} {:>9}",
                method,
                situation.name,
                summary.n,
                ms(summary.p50),
                ms(summary.p99),
                ms(summary.max)
            );
            p99s.push(summary.p99);
        }
    }
    let enforce = std::env::var("LH_ENFORCE_BUDGET").is_ok_and(|v| v == "1");
    let code = stats::exit_code(&p99s, enforce);
    if code != 0 {
        eprintln!("the budget of 5 ms at p99 is not met");
    }
    ExitCode::from(code)
}

/// A temporary directory that only its owner can use, whatever the umask of the shell that runs the
/// tests (the code under test refuses a directory that others can write).
fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("a temporary directory")
}
