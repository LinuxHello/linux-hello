//! `linuxhello-ctl notify`: one desktop notification after login for what the person should act
//! on, because a sign-in screen closes the moment the sign-in succeeds and nobody reads "Your PIN
//! expires in 5 days" there (linux-hello#324).
//!
//! The desktop starts it once per session from its autostart entry
//! (`plasma/autostart/linuxhello-notify.desktop`); no screen part starts it. It asks the Agent for
//! the caller's conditions (`GetStatus`, ADR-0024), picks `pin-expires-soon`, `pin-expired` and every
//! `severe` condition, and hands each to the desktop's notification service
//! (`org.freedesktop.Notifications` on the session bus) in its own words, chosen by code: the
//! days come from the code's parameter, never from the Agent's sentence (ADR-0024, amendment of
//! 2026-11-22). An unknown severe code shows the Agent's sentence. It starts no program
//! (ADR-0026) and shows nothing when the Agent does not answer.

use std::collections::HashMap;
use std::time::Duration;

use linuxhello_dbus::status::{
    days_of_pin_expires_soon, split_code, PIN_EXPIRED, PIN_EXPIRES_SOON,
};
use zbus::Variant;

use crate::ask::{self, Reported};
use crate::probe::Host;

/// The most notifications one run shows.
const MAX_NOTIFICATIONS: usize = 3;

/// How long the notification service may take to answer.
const ANSWER_WAIT: Duration = Duration::from_secs(5);

/// One notification: its title, its text and whether it is urgent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    /// The title.
    pub summary: String,
    /// The text.
    pub body: String,
    /// `true` for a severe condition, shown as critical.
    pub urgent: bool,
}

/// Where notifications go: the desktop's notification service, or a stand-in in a test.
pub trait Notifier {
    /// Shows `note`; whether the service took it.
    fn show(&mut self, note: &Note) -> bool;
}

/// The notification for `condition`, or `None` when it is not one to show after login.
fn note_for(condition: &Reported) -> Option<Note> {
    let (base, _) = split_code(&condition.code);
    if base == PIN_EXPIRES_SOON {
        let days = days_of_pin_expires_soon(&condition.code)?;
        let when = if days == 1 {
            "tomorrow".to_string()
        } else {
            format!("in {days} days")
        };
        return Some(Note {
            summary: "Your PIN expires soon".to_string(),
            body: format!(
                "Your Linux Hello PIN expires {when}. It keeps working, but change it before then."
            ),
            urgent: false,
        });
    }
    if base == PIN_EXPIRED {
        return Some(Note {
            summary: "Your PIN has expired".to_string(),
            body: "Your Linux Hello PIN has expired. It still works, but change it now."
                .to_string(),
            urgent: false,
        });
    }
    (condition.severity == "severe").then(|| Note {
        summary: "Linux Hello needs attention".to_string(),
        body: condition.sentence.clone(),
        urgent: true,
    })
}

/// The notifications for `conditions`, at most three, severe ones first
/// (`a_pin_that_expires_soon_gives_one_notification`, `only_what_to_act_on_is_notified`).
pub fn notes_for(conditions: &[Reported]) -> Vec<Note> {
    let mut notes: Vec<Note> = conditions.iter().filter_map(note_for).collect();
    notes.sort_by_key(|note| !note.urgent);
    notes.truncate(MAX_NOTIFICATIONS);
    notes
}

/// Runs `notify`: asks the Agent through `host` and shows what to act on through `notifier`.
/// Returns 0 when everything there was to show was shown (also when there was nothing), 1 when
/// the Agent did not answer or the service refused a notification.
pub fn run(host: &dyn Host, notifier: &mut dyn Notifier) -> u8 {
    let Some(conditions) = ask::get_status(host) else {
        return 1;
    };
    let mut code = 0;
    for note in notes_for(&conditions) {
        if !notifier.show(&note) {
            code = 1;
        }
    }
    code
}

/// The desktop's notification service on the person's session bus.
#[derive(Default)]
pub struct SessionNotifier {
    /// The address of the bus to use, or `None` for the session bus; tests give their own.
    address: Option<String>,
}

impl SessionNotifier {
    /// The service on the bus at `address`, for tests.
    #[cfg(test)]
    pub fn on_bus(address: impl Into<String>) -> Self {
        Self {
            address: Some(address.into()),
        }
    }

    /// Sends `note` with `Notify`; whether it was taken.
    async fn send(&self, note: &Note) -> bool {
        let builder = match &self.address {
            Some(address) => zbus::connection::Builder::address(address.as_str()),
            None => zbus::connection::Builder::session(),
        };
        let Ok(connection) = builder.method_timeout(ANSWER_WAIT).build().await else {
            return false;
        };
        let mut hints: HashMap<&str, Variant<'_>> = HashMap::new();
        hints.insert(
            "urgency",
            Variant::from(if note.urgent { 2_u8 } else { 1_u8 }),
        );
        hints.insert("desktop-entry", Variant::from("linuxhello-notify"));
        let actions: Vec<&str> = Vec::new();
        connection
            .call_method(
                Some("org.freedesktop.Notifications"),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "Notify",
                &(
                    "Linux Hello",
                    0_u32,
                    "",
                    note.summary.as_str(),
                    note.body.as_str(),
                    actions,
                    hints,
                    -1_i32,
                ),
            )
            .await
            .is_ok()
    }
}

impl Notifier for SessionNotifier {
    fn show(&mut self, note: &Note) -> bool {
        futures_lite::future::block_on(self.send(note))
    }
}

#[cfg(test)]
mod tests;
