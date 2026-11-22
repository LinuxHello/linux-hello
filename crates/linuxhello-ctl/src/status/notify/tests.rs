//! Tests of what `notify` shows, with a scripted Agent and a notifier that records.

use std::path::Path;

use super::*;

/// A machine whose Agent answers `reply`.
struct Scripted(Option<Vec<Reported>>);

impl Host for Scripted {
    fn agent_status(&self) -> Option<Vec<Reported>> {
        self.0.clone()
    }
    fn unit_active(&self, _unit: &str) -> Option<bool> {
        panic!("notify asks no unit")
    }
    fn fingerprint_reader(&self) -> Option<bool> {
        panic!("notify asks no reader")
    }
    fn read(&self, _path: &Path) -> Option<String> {
        panic!("notify reads no file")
    }
}

/// Records what it was asked to show; refuses everything when `refuse`.
#[derive(Default)]
struct Shown {
    notes: Vec<Note>,
    refuse: bool,
}

impl Notifier for Shown {
    fn show(&mut self, note: &Note) -> bool {
        self.notes.push(note.clone());
        !self.refuse
    }
}

fn reported(code: &str, severity: &str, sentence: &str) -> Reported {
    Reported {
        code: code.into(),
        severity: severity.into(),
        sentence: sentence.into(),
    }
}

#[test]
fn a_pin_that_expires_soon_gives_one_notification() {
    let host = Scripted(Some(vec![reported(
        "pin-expires-soon: 5",
        "warning",
        "Your PIN expires in 5 days. Change it with linuxhello-ctl pin change.",
    )]));
    let mut shown = Shown::default();
    assert_eq!(run(&host, &mut shown), 0);
    assert_eq!(shown.notes.len(), 1);
    // The days come from the code; the Agent's sentence, which names a command, is not shown.
    assert!(
        shown.notes[0].body.contains("in 5 days"),
        "{:?}",
        shown.notes
    );
    assert!(!shown.notes[0].body.contains("linuxhello-ctl"));
    assert!(!shown.notes[0].urgent);

    let tomorrow = notes_for(&[reported("pin-expires-soon: 1", "warning", "x")]);
    assert!(tomorrow[0].body.contains("tomorrow"), "{tomorrow:?}");
}

#[test]
fn only_what_to_act_on_is_notified() {
    let conditions = vec![
        reported(
            "tpm-dictionary-limit-low",
            "warning",
            "a note for the administrator",
        ),
        reported("pin-locked", "warning", "locked"),
        reported("pin-expired", "warning", "expired"),
        reported("tpm-cleared", "severe", "The TPM no longer holds the key."),
        reported("something-new", "severe", "A sentence of a newer Agent."),
        reported("pin-expires-soon", "warning", "a code without its days"),
    ];
    let notes = notes_for(&conditions);
    let bodies: Vec<&str> = notes.iter().map(|n| n.body.as_str()).collect();
    // Severe first, then the expiry; at most three; warnings for the administrator, the lock and
    // a code whose days cannot be read are not notified.
    assert_eq!(notes.len(), 3, "{notes:?}");
    assert_eq!(
        bodies[..2],
        [
            "The TPM no longer holds the key.",
            "A sentence of a newer Agent."
        ]
    );
    assert!(notes[0].urgent && notes[1].urgent && !notes[2].urgent);
    assert!(bodies[2].contains("has expired"));
}

#[test]
fn nothing_is_shown_without_an_answer_or_without_conditions() {
    let mut shown = Shown::default();
    assert_eq!(run(&Scripted(None), &mut shown), 1);
    assert_eq!(run(&Scripted(Some(vec![])), &mut shown), 0);
    assert!(shown.notes.is_empty());
}

#[test]
fn a_notification_the_service_refuses_is_a_failure() {
    let host = Scripted(Some(vec![reported("pin-expired", "warning", "x")]));
    let mut shown = Shown {
        refuse: true,
        ..Shown::default()
    };
    assert_eq!(run(&host, &mut shown), 1);
}

/// The `(app, summary, body, urgency)` of each `Notify` the fake received.
type Received = std::sync::Arc<std::sync::Mutex<Vec<(String, String, String, u8)>>>;

/// A fake notification service that records each `Notify`.
struct FakeService(Received);

#[zbus::interface(name = "org.freedesktop.Notifications")]
impl FakeService {
    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &self,
        app: String,
        _replaces: u32,
        _icon: String,
        summary: String,
        body: String,
        _actions: Vec<String>,
        hints: HashMap<String, zbus::OwnedVariant>,
        _timeout: i32,
    ) -> u32 {
        let urgency = hints
            .get("urgency")
            .and_then(|v| u8::try_from(v.clone()).ok())
            .unwrap_or(9);
        self.0.lock().unwrap().push((app, summary, body, urgency));
        1
    }
}

#[test]
fn the_session_notifier_calls_the_desktops_notification_service() {
    use std::io::{BufRead, BufReader};
    let mut daemon = std::process::Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("dbus-daemon must be installed");
    let mut address = String::new();
    BufReader::new(daemon.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    let address = address.trim().to_string();
    let seen: Received = std::sync::Arc::default();
    let _service = futures_lite::future::block_on(
        zbus::connection::Builder::address(address.as_str())
            .name("org.freedesktop.Notifications")
            .serve_at(
                "/org/freedesktop/Notifications",
                FakeService(std::sync::Arc::clone(&seen)),
            )
            .build(),
    )
    .expect("serve the fake service");
    let mut notifier = SessionNotifier::on_bus(address.clone());
    let note = Note {
        summary: "Linux Hello needs attention".into(),
        body: "The TPM no longer holds the key.".into(),
        urgent: true,
    };
    assert!(notifier.show(&note));
    let seen = seen.lock().unwrap().clone();
    let _ = daemon.kill();
    let _ = daemon.wait();
    assert_eq!(
        seen,
        [(
            "Linux Hello".to_string(),
            note.summary.clone(),
            note.body.clone(),
            2
        )]
    );
}
