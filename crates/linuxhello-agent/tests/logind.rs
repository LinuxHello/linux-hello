//! The Agent asks logind, about the process the bus names, whether a `sudo` or `session` caller is
//! at this machine before it starts a sensor (ADR-0023, amendment of 2026-11-23; review finding R-04,
//! #347). The bus is a real private `dbus-daemon` and logind is a fake on it that answers by process
//! id. Needs the `dbus-daemon` binary (package `dbus-daemon`).

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{call, connect, my_uid, next_within, pid, run, signals, Daemon};
use linuxhello_agent::audit::{Audit, AuditSink, Event};
use linuxhello_agent::bus::logind::{Locality, LogindProbe};
use linuxhello_agent::bus::{serve_with_extras, Extras, MethodFactory};
use linuxhello_agent::orchestrator::{Cancel, Method, MethodEnd};
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;
use linuxhello_dbus::AuthMethod;
use zbus::connection::Builder;
use zbus::DBusError;
use zbus::OwnedObjectPath;

/// What a fake logind says about the session of a process.
#[derive(Clone, Copy)]
struct Facts {
    /// `Remote`: a session of sshd or another remote service.
    remote: bool,
    /// The id of the seat, empty for a session without one.
    seat: &'static str,
    /// `Active`: in front.
    active: bool,
}

/// The local, active session on `seat0`: the one that may use a sensor.
const LOCAL: Facts = Facts {
    remote: false,
    seat: "seat0",
    active: true,
};

/// The error of logind for a process that is in no session.
#[derive(DBusError, Debug)]
#[zbus(prefix = "org.freedesktop.login1")]
enum LoginError {
    /// Plain failure of the fake.
    #[zbus(error)]
    ZBus(zbus::Error),
    /// The process is not in a session.
    NoSessionForPID(String),
}

/// What the fake logind does when it is asked for a session.
#[derive(Clone, Copy)]
enum Mode {
    /// Answers with the session of these facts.
    Session(Facts),
    /// Says the process is in no session.
    NoSession,
    /// Never answers.
    Silent,
}

/// The fake `org.freedesktop.login1.Manager`.
struct Manager {
    /// What it does.
    mode: Mode,
    /// The process ids it was asked about.
    asked: Arc<Mutex<Vec<u32>>>,
}

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Manager {
    /// The session of a process.
    #[zbus(name = "GetSessionByPID")]
    async fn get_session_by_pid(&self, pid: u32) -> Result<OwnedObjectPath, LoginError> {
        self.asked.lock().unwrap().push(pid);
        match self.mode {
            Mode::Session(_) => Ok(
                OwnedObjectPath::try_from("/org/freedesktop/login1/session/_1")
                    .expect("a valid path"),
            ),
            Mode::NoSession => Err(LoginError::NoSessionForPID("no session".into())),
            Mode::Silent => std::future::pending().await,
        }
    }
}

/// The fake `org.freedesktop.login1.Session`.
struct Session(Facts);

#[zbus::interface(name = "org.freedesktop.login1.Session")]
impl Session {
    /// Whether the session is remote.
    #[zbus(property)]
    fn remote(&self) -> bool {
        self.0.remote
    }

    /// Whether the session is in front.
    #[zbus(property)]
    fn active(&self) -> bool {
        self.0.active
    }

    /// The seat of the session: its id and its object path.
    #[zbus(property)]
    fn seat(&self) -> (String, OwnedObjectPath) {
        let path = if self.0.seat.is_empty() {
            "/".to_string()
        } else {
            format!("/org/freedesktop/login1/seat/{}", self.0.seat)
        };
        (
            self.0.seat.to_string(),
            OwnedObjectPath::try_from(path).expect("a valid path"),
        )
    }
}

/// A sensor that is always there and never recognises anybody; it ends when it is cancelled.
struct Sensor(AuthMethod);

impl Method for Sensor {
    fn kind(&self) -> AuthMethod {
        self.0
    }
    fn available(&self) -> bool {
        true
    }
    fn run(&mut self, cancel: &Cancel) -> MethodEnd {
        while !cancel.is_cancelled() {
            std::thread::sleep(Duration::from_millis(20));
        }
        MethodEnd::Cancelled
    }
}

/// A sink that keeps the events it is given.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Event>>>);

impl AuditSink for Recorder {
    fn record(&self, event: &Event) {
        self.0.lock().unwrap().push(event.clone());
    }
}

/// The `LH_EVENT` and `LH_REASON` words of the events that are about sensors.
fn refusals(recorder: &Recorder) -> Vec<(String, String)> {
    recorder
        .0
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| {
            let fields = event.fields();
            let word = |name: &str| {
                fields
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            };
            (word("LH_EVENT")? == "sensors_refused").then(|| {
                (
                    "sensors_refused".to_string(),
                    word("LH_REASON").unwrap_or_default(),
                )
            })
        })
        .collect()
}

/// The methods the Agent offers for a prompt of `context`, in order, when logind is as `logind`
/// says (`None`: nobody owns logind's name), the record of the audit and the process ids it asked.
fn offered(
    context: &str,
    logind: Option<Mode>,
    limit: Duration,
) -> (Vec<String>, Vec<(String, String)>, Vec<u32>) {
    let daemon = Daemon::start();
    let tmp = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let recorder = Recorder::default();
    let asked = Arc::new(Mutex::new(Vec::new()));
    run(async {
        let _logind = match logind {
            None => None,
            Some(mode) => {
                let facts = match mode {
                    Mode::Session(facts) => facts,
                    _ => LOCAL,
                };
                Some(
                    Builder::address(daemon.address.as_str())
                        .name("org.freedesktop.login1")
                        .serve_at(
                            "/org/freedesktop/login1",
                            Manager {
                                mode,
                                asked: Arc::clone(&asked),
                            },
                        )
                        .serve_at("/org/freedesktop/login1/session/_1", Session(facts))
                        .build()
                        .await
                        .expect("serve the fake logind"),
                )
            }
        };
        let methods: MethodFactory = Arc::new(|_subject, _target| {
            vec![
                Box::new(Sensor(AuthMethod::Pin)) as Box<dyn Method>,
                Box::new(Sensor(AuthMethod::Fingerprint)),
                Box::new(Sensor(AuthMethod::Face)),
            ]
        });
        let _service = serve_with_extras(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
            Some(UserPolicyStore::new(tmp.path().join("users"))),
            Extras {
                audit: Some(Audit::new(Box::new(recorder.clone()))),
                methods: Some(methods),
                session_probe: Some(Arc::new(LogindProbe::at(&daemon.address, limit))),
                ..Extras::default()
            },
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let id = pid("p1");
        call(&client, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");
        let mut heard = signals(&client, "MethodsAvailable").await;
        call(&client, "Subscribe", &(id.as_str(),))
            .await
            .expect("subscribe");
        call(&client, "Authenticate", &(id.as_str(), context))
            .await
            .expect("authenticate");
        let note = next_within(&mut heard, 5000)
            .await
            .expect("the methods are announced");
        let (_, methods): (String, Vec<String>) = note.body().deserialize().expect("the body");
        let _ = call(&client, "ClosePrompt", &(id.as_str(),)).await;
        (methods, refusals(&recorder), asked.lock().unwrap().clone())
    })
}

/// The default limit for the probe in the tests where logind answers.
const LIMIT: Duration = Duration::from_secs(2);

/// The methods are listed in the Agent's own order; compare as a set.
fn sorted(mut methods: Vec<String>) -> Vec<String> {
    methods.sort();
    methods
}

#[test]
fn a_local_active_session_gets_every_method_its_policy_allows() {
    let (methods, refusals, _) = offered("sudo", Some(Mode::Session(LOCAL)), LIMIT);
    assert_eq!(
        sorted(methods),
        ["fingerprint", "pin"],
        "sudo allows pin and fingerprint"
    );
    assert!(refusals.is_empty(), "{refusals:?}");
}

#[test]
fn a_remote_session_gets_no_sensor_for_sudo() {
    // R-04, #347: a shell over a stolen SSH key must not make the camera or the reader run.
    let remote = Facts {
        remote: true,
        ..LOCAL
    };
    let (methods, refusals, _) = offered("sudo", Some(Mode::Session(remote)), LIMIT);
    assert_eq!(methods, ["pin"]);
    assert_eq!(
        refusals,
        [("sensors_refused".to_string(), "remote".to_string())]
    );
}

#[test]
fn a_remote_session_gets_no_sensor_for_session_either() {
    let remote = Facts {
        remote: true,
        ..LOCAL
    };
    let (methods, refusals, _) = offered("session", Some(Mode::Session(remote)), LIMIT);
    assert_eq!(methods, ["pin"], "session allows pin, fingerprint and face");
    assert_eq!(refusals.len(), 1);
}

#[test]
fn a_session_without_a_seat_gets_no_sensor() {
    let seatless = Facts { seat: "", ..LOCAL };
    let (methods, refusals, _) = offered("sudo", Some(Mode::Session(seatless)), LIMIT);
    assert_eq!(methods, ["pin"]);
    assert_eq!(
        refusals,
        [("sensors_refused".to_string(), "no-seat".to_string())]
    );
}

#[test]
fn an_inactive_session_gets_no_sensor() {
    let behind = Facts {
        active: false,
        ..LOCAL
    };
    let (methods, refusals, _) = offered("sudo", Some(Mode::Session(behind)), LIMIT);
    assert_eq!(methods, ["pin"]);
    assert_eq!(
        refusals,
        [("sensors_refused".to_string(), "inactive".to_string())]
    );
}

#[test]
fn a_process_that_is_in_no_session_gets_no_sensor() {
    let (methods, refusals, _) = offered("sudo", Some(Mode::NoSession), LIMIT);
    assert_eq!(methods, ["pin"]);
    assert_eq!(
        refusals,
        [("sensors_refused".to_string(), "no-seat".to_string())]
    );
}

#[test]
fn a_logind_that_is_not_there_gets_the_pin_only() {
    let (methods, refusals, _) = offered("sudo", None, LIMIT);
    assert_eq!(methods, ["pin"]);
    assert_eq!(
        refusals,
        [("sensors_refused".to_string(), "unknown".to_string())]
    );
}

#[test]
fn a_logind_that_does_not_answer_gets_the_pin_only() {
    // The question has a limit: a logind that never answers costs half a second at most, and the
    // person can still type the PIN.
    let started = Instant::now();
    let (methods, refusals, _) = offered("sudo", Some(Mode::Silent), Duration::from_millis(300));
    assert_eq!(methods, ["pin"]);
    assert_eq!(
        refusals,
        [("sensors_refused".to_string(), "unknown".to_string())]
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn the_question_is_asked_about_the_process_the_bus_names() {
    // The caller cannot say where it is: the process id comes from the bus daemon's credentials.
    let (_, _, asked) = offered("sudo", Some(Mode::Session(LOCAL)), LIMIT);
    assert_eq!(asked, [std::process::id()]);
}

#[test]
fn the_login_and_unlock_contexts_are_not_asked_about_a_session() {
    // Decided so in the amendment: the login screen has no session of the person yet, and the lock
    // screen is left for later. Nothing is asked, and nothing is refused.
    let remote = Facts {
        remote: true,
        ..LOCAL
    };
    for context in ["login", "unlock"] {
        let (methods, refusals, asked) = offered(context, Some(Mode::Session(remote)), LIMIT);
        assert!(
            methods.contains(&"fingerprint".to_string()),
            "{context}: {methods:?}"
        );
        assert!(refusals.is_empty() && asked.is_empty(), "{context}");
    }
}

#[test]
fn a_session_is_local_only_when_it_has_a_seat_is_not_remote_and_is_in_front() {
    use linuxhello_agent::bus::logind::judge;
    assert_eq!(judge(false, "seat0", true), Locality::Local);
    assert_eq!(judge(true, "seat0", true), Locality::Remote);
    assert_eq!(
        judge(true, "", false),
        Locality::Remote,
        "remote is named first"
    );
    assert_eq!(judge(false, "", true), Locality::NoSeat);
    assert_eq!(judge(false, "seat0", false), Locality::Inactive);
}
