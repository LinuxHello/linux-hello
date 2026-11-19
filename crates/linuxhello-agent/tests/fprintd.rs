//! The fingerprint method against a fake `fprintd` on a real private bus: the calls it makes, in
//! which order, and how it maps what `fprintd` says. There is no fingerprint reader here; what a
//! real `fprintd` does is not tested.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{connect, run, Daemon};
use linuxhello_agent::methods::fingerprint::FingerprintMethod;
use linuxhello_agent::orchestrator::{Cancel, Method, MethodEnd};
use linuxhello_dbus::PromptReason;
use zbus::connection::Builder;
use zbus::fdo;
use zbus::object_server::SignalEmitter;
use zbus::{interface, OwnedObjectPath};

/// The calls the fake received, in order.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, line: impl Into<String>) {
        self.0.lock().unwrap().push(line.into());
    }

    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

/// The fake manager: it has a default reader, or none.
struct Manager {
    has_reader: bool,
}

#[interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    async fn get_default_device(&self) -> fdo::Result<OwnedObjectPath> {
        if self.has_reader {
            Ok(OwnedObjectPath::try_from("/net/reactivated/Fprint/Device/0").unwrap())
        } else {
            Err(fdo::Error::Failed("no devices available".into()))
        }
    }
}

/// The fake reader: it answers a scan with a script of `VerifyStatus` results.
struct Device {
    log: Log,
    enrolled: Vec<String>,
    script: Vec<(String, bool)>,
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    async fn list_enrolled_fingers(&self, username: String) -> fdo::Result<Vec<String>> {
        self.log.push(format!("ListEnrolledFingers {username}"));
        if self.enrolled.is_empty() {
            Err(fdo::Error::Failed("NoEnrolledPrints".into()))
        } else {
            Ok(self.enrolled.clone())
        }
    }

    async fn claim(&self, username: String) -> fdo::Result<()> {
        self.log.push(format!("Claim {username}"));
        Ok(())
    }

    async fn release(&self) -> fdo::Result<()> {
        self.log.push("Release");
        Ok(())
    }

    async fn verify_start(
        &self,
        finger: String,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        self.log.push(format!("VerifyStart {finger}"));
        for (result, done) in &self.script {
            async_io::Timer::after(Duration::from_millis(20)).await;
            Self::verify_status(&emitter, result.clone(), *done)
                .await
                .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        }
        Ok(())
    }

    async fn verify_stop(&self) -> fdo::Result<()> {
        self.log.push("VerifyStop");
        Ok(())
    }

    #[zbus(signal)]
    async fn verify_status(
        emitter: &SignalEmitter<'_>,
        result: String,
        done: bool,
    ) -> zbus::Result<()>;
}

/// How the fake `fprintd` is set up.
struct Setup {
    has_reader: bool,
    enrolled: Vec<&'static str>,
    script: Vec<(&'static str, bool)>,
}

impl Setup {
    /// A reader with one enrolled finger that answers with `script`.
    fn with(script: Vec<(&'static str, bool)>) -> Self {
        Self {
            has_reader: true,
            enrolled: vec!["right-index-finger"],
            script,
        }
    }
}

/// Serves the fake `fprintd` on `daemon` and returns what it needs to stay alive and its log.
async fn fake_fprintd(daemon: &Daemon, setup: Setup) -> (zbus::Connection, Log) {
    let log = Log::default();
    let device = Device {
        log: log.clone(),
        enrolled: setup.enrolled.iter().map(|f| (*f).to_string()).collect(),
        script: setup
            .script
            .iter()
            .map(|(r, d)| ((*r).to_string(), *d))
            .collect(),
    };
    let connection = Builder::address(daemon.address.as_str())
        .name("net.reactivated.Fprint")
        .serve_at(
            "/net/reactivated/Fprint/Manager",
            Manager {
                has_reader: setup.has_reader,
            },
        )
        .serve_at("/net/reactivated/Fprint/Device/0", device)
        .build()
        .await
        .expect("serve the fake fprintd");
    (connection, log)
}

/// Runs the fingerprint method for `anna` on a thread and returns how it ended.
fn run_method(daemon: &Daemon, cancel: &Cancel) -> MethodEnd {
    let mut method = FingerprintMethod::new("anna").on_bus(daemon.address.clone());
    let cancel = cancel.clone();
    std::thread::spawn(move || method.run(&cancel))
        .join()
        .unwrap()
}

#[test]
fn a_matching_finger_is_a_success() {
    let daemon = Daemon::start();
    run(async {
        let (_fprintd, log) =
            fake_fprintd(&daemon, Setup::with(vec![("verify-match", true)])).await;
        assert_eq!(run_method(&daemon, &Cancel::default()), MethodEnd::Success);
        // The reader is claimed for the user who signs in, scanned, and given back.
        assert_eq!(
            log.lines(),
            [
                "ListEnrolledFingers anna",
                "Claim anna",
                "VerifyStart any",
                "Release"
            ]
        );
    });
}

#[test]
fn a_finger_that_does_not_match_is_not_recognised() {
    let daemon = Daemon::start();
    run(async {
        let (_fprintd, _log) =
            fake_fprintd(&daemon, Setup::with(vec![("verify-no-match", true)])).await;
        assert_eq!(
            run_method(&daemon, &Cancel::default()),
            MethodEnd::Failure(PromptReason::NotRecognised)
        );
    });
}

#[test]
fn a_retry_result_keeps_the_scan_going() {
    let daemon = Daemon::start();
    run(async {
        let script = vec![
            ("verify-retry-scan", false),
            ("verify-finger-not-centered", false),
            ("verify-match", true),
        ];
        let (_fprintd, _log) = fake_fprintd(&daemon, Setup::with(script)).await;
        assert_eq!(run_method(&daemon, &Cancel::default()), MethodEnd::Success);
    });
}

#[test]
fn a_reader_that_goes_away_is_unavailable() {
    for result in [
        "verify-disconnected",
        "verify-unknown-error",
        "verify-something-new",
    ] {
        let daemon = Daemon::start();
        run(async {
            let (_fprintd, _log) = fake_fprintd(&daemon, Setup::with(vec![(result, true)])).await;
            assert_eq!(
                run_method(&daemon, &Cancel::default()),
                MethodEnd::Unavailable,
                "{result}"
            );
        });
    }
}

#[test]
fn cancelling_stops_the_scan_and_gives_the_reader_back() {
    let daemon = Daemon::start();
    run(async {
        let (_fprintd, log) = fake_fprintd(&daemon, Setup::with(vec![])).await;
        let cancel = Cancel::default();
        let mut method = FingerprintMethod::new("anna").on_bus(daemon.address.clone());
        let flag = cancel.clone();
        let handle = std::thread::spawn(move || method.run(&flag));
        async_io::Timer::after(Duration::from_millis(400)).await;
        cancel.cancel();
        assert_eq!(handle.join().unwrap(), MethodEnd::Cancelled);
        let lines = log.lines();
        assert_eq!(
            &lines[lines.len() - 2..],
            ["VerifyStop", "Release"],
            "{lines:?}"
        );
    });
}

#[test]
fn a_user_with_no_enrolled_finger_is_unavailable() {
    let daemon = Daemon::start();
    run(async {
        let setup = Setup {
            enrolled: vec![],
            ..Setup::with(vec![("verify-match", true)])
        };
        let (_fprintd, log) = fake_fprintd(&daemon, setup).await;
        let method = FingerprintMethod::new("anna").on_bus(daemon.address.clone());
        assert!(!method.available());
        assert_eq!(
            run_method(&daemon, &Cancel::default()),
            MethodEnd::Unavailable
        );
        assert!(
            !log.lines().iter().any(|l| l.starts_with("Claim")),
            "nothing was claimed"
        );
    });
}

#[test]
fn no_reader_and_no_fprintd_are_unavailable() {
    let daemon = Daemon::start();
    run(async {
        // No fprintd on the bus at all.
        let method = FingerprintMethod::new("anna").on_bus(daemon.address.clone());
        assert!(!method.available());
        assert_eq!(
            run_method(&daemon, &Cancel::default()),
            MethodEnd::Unavailable
        );

        // fprintd without a reader.
        let setup = Setup {
            has_reader: false,
            ..Setup::with(vec![])
        };
        let (_fprintd, _log) = fake_fprintd(&daemon, setup).await;
        let _client = connect(&daemon).await;
        assert!(!method.available());
    });
}

#[test]
fn a_reader_with_a_finger_is_available() {
    let daemon = Daemon::start();
    run(async {
        let (_fprintd, _log) = fake_fprintd(&daemon, Setup::with(vec![])).await;
        let method = FingerprintMethod::new("anna").on_bus(daemon.address.clone());
        assert!(method.available());
    });
}
