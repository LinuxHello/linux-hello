//! `Reset` on a real private bus with a fake polkit and an in-memory stand-in for the PIN records:
//! who is asked, what is deleted, and what is kept (ADR-0003, ADR-0027 point 5). What a real
//! polkit and its dialog do is not tested here.

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use common::{call, connect, my_uid, next_within, pid, run, signals, Daemon};
use linuxhello_agent::bus::polkit::Polkit;
use linuxhello_agent::bus::{serve_with_extras, Extras, PinChange};
use linuxhello_agent::methods::pin::enrol::PinEnrolment;
use linuxhello_agent::methods::pin::tpm::EnrolError;
use linuxhello_agent::methods::pin::PinInbox;
use linuxhello_agent::pinlock::service::{Limits, PinLockService};
use linuxhello_agent::pinlock::store::PinLockFile;
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;
use zbus::connection::Builder;
use zbus::interface;
use zbus::OwnedVariant;

/// A stand-in for the PIN records: who has a PIN.
#[derive(Default)]
struct Records(Mutex<HashSet<u32>>);

impl PinEnrolment for Records {
    fn has_pin(&self, uid: u32) -> bool {
        self.0.lock().unwrap().contains(&uid)
    }
    fn set(&self, uid: u32, _pin: &[u8]) -> Result<(), EnrolError> {
        self.0.lock().unwrap().insert(uid);
        Ok(())
    }
    fn change(&self, _uid: u32, _old: &[u8], _new: &[u8], _h: u32) -> Result<(), EnrolError> {
        Err(EnrolError::WrongPin)
    }
    fn forget(&self, uid: u32) -> Result<(), EnrolError> {
        self.0.lock().unwrap().remove(&uid);
        Ok(())
    }
}

/// Each check polkit was asked: subject kind, connection name, action, flags.
type Asked = Arc<Mutex<Vec<(String, String, String, u32)>>>;

/// What the fake polkit answers.
#[derive(Clone, Copy)]
enum Says {
    Yes,
    No,
    Dismissed,
}

/// The fake authority: answers every check the same and logs who and what was asked.
struct Authority {
    says: Says,
    asked: Asked,
}

#[interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl Authority {
    async fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedVariant>),
        action: String,
        _details: HashMap<String, String>,
        flags: u32,
        _cancel: String,
    ) -> (bool, bool, HashMap<String, String>) {
        let name = subject
            .1
            .get("name")
            .and_then(|v| String::try_from(v.clone()).ok())
            .unwrap_or_default();
        self.asked
            .lock()
            .unwrap()
            .push((subject.0, name, action, flags));
        let mut details = HashMap::new();
        match self.says {
            Says::Yes => (true, false, details),
            Says::No => (false, false, details),
            Says::Dismissed => {
                details.insert("polkit.dismissed".to_string(), "true".to_string());
                (false, false, details)
            }
        }
    }
}

/// The Agent with a reset path, a fake polkit that `says` (or none), and a user with a PIN.
struct World {
    daemon: Daemon,
    _service: zbus::Connection,
    _polkit: Option<zbus::Connection>,
    records: Arc<Records>,
    asked: Asked,
    _dir: tempfile::TempDir,
}

async fn agent_with(says: Option<Says>) -> World {
    let daemon = Daemon::start();
    let dir = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let asked: Asked = Arc::new(Mutex::new(Vec::new()));
    let polkit = match says {
        Some(says) => Some(
            Builder::address(daemon.address.as_str())
                .name("org.freedesktop.PolicyKit1")
                .serve_at(
                    "/org/freedesktop/PolicyKit1/Authority",
                    Authority {
                        says,
                        asked: Arc::clone(&asked),
                    },
                )
                .build()
                .await
                .expect("serve the fake polkit"),
        ),
        None => None,
    };
    let lock = Arc::new(PinLockService::start(
        PinLockFile::new(dir.path().join("pinlock.toml"), my_uid()),
        Limits {
            max_attempts: 2,
            lockout_secs: 600,
            max_lockout_secs: 86_400,
        },
    ));
    let records = Arc::new(Records::default());
    records.0.lock().unwrap().insert(my_uid());
    let service = serve_with_extras(
        Builder::address(daemon.address.as_str()),
        Config::new(vec![]),
        Some(UserPolicyStore::new(dir.path().join("users"))),
        Extras {
            pin_lock: Some(lock),
            pin_change: Some(PinChange {
                inbox: Arc::new(PinInbox::default()),
                enrolment: Arc::clone(&records) as Arc<dyn PinEnrolment>,
            }),
            polkit: Some(Polkit::on_bus(daemon.address.clone())),
            ..Extras::default()
        },
    )
    .await
    .expect("serve the Agent");
    World {
        daemon,
        _service: service,
        _polkit: polkit,
        records,
        asked,
        _dir: dir,
    }
}

/// Opens a prompt for the caller, resets on it and returns the `(result, reason)` of `Result`.
async fn reset(client: &zbus::Connection) -> (String, String) {
    let id = pid("reset");
    call(client, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
        .await
        .expect("open");
    call(client, "Subscribe", &(id.as_str(),))
        .await
        .expect("subscribe");
    let mut heard = signals(client, "Result").await;
    call(client, "Reset", &(id.as_str(),))
        .await
        .expect("reset starts");
    let signal = next_within(&mut heard, 5_000).await.expect("a Result");
    let (_p, result, reason, _s): (String, String, String, u32) =
        signal.body().deserialize().unwrap();
    (result, reason)
}

#[test]
fn reset_needs_polkit_or_root() {
    run(async {
        // polkit says no: nothing is deleted.
        let world = agent_with(Some(Says::No)).await;
        let client = connect(&world.daemon).await;
        assert_eq!(
            reset(&client).await,
            ("failure".to_string(), "not-recognised".to_string())
        );
        assert!(world.records.has_pin(my_uid()));
        // polkit was asked about this connection, for the reset action, with the dialog allowed.
        let asked = world.asked.lock().unwrap().clone();
        let me = client.unique_name().unwrap().to_string();
        assert_eq!(
            asked,
            [(
                "system-bus-name".to_string(),
                me,
                "io.github.LinuxHello.reset".to_string(),
                1
            )]
        );

        // The person closed the dialog: cancelled, nothing deleted.
        let world = agent_with(Some(Says::Dismissed)).await;
        let client = connect(&world.daemon).await;
        assert_eq!(reset(&client).await.0, "cancelled");
        assert!(world.records.has_pin(my_uid()));

        // No polkit on the bus: a failure, nothing deleted.
        let world = agent_with(None).await;
        let client = connect(&world.daemon).await;
        assert_eq!(reset(&client).await.0, "failure");
        assert!(world.records.has_pin(my_uid()));
    });
}

#[test]
fn reset_deletes_what_adr_0003_says_and_nothing_else() {
    run(async {
        let world = agent_with(Some(Says::Yes)).await;
        let client = connect(&world.daemon).await;
        let policy = "[methods]\nbiometrics_allowed = false\n".to_string();
        call(&client, "SetUserPolicy", &policy)
            .await
            .expect("set policy");
        assert_eq!(reset(&client).await.0, "success");
        // The PIN record and its key are gone.
        assert!(!world.records.has_pin(my_uid()));
        // The person's own policy layer stays.
        let kept = call(&client, "GetUserPolicy", &()).await.expect("policy");
        let text: String = kept.body().deserialize().unwrap();
        assert!(text.contains("biometrics_allowed = false"), "{text}");
    });
}
