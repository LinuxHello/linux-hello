//! The Agent as a client of polkit, the service that decides whether a program may do a
//! privileged action for a user and asks the person for their password when the rule says so.
//! The Agent asks it before the destructive reset (ADR-0027, point 5): the action
//! `io.github.LinuxHello.reset` has the default `auth_self`, so polkit's agent in the person's
//! session asks for the account password. The Agent never sees that password.
//!
//! The subject is the caller's bus connection (polkit's `system-bus-name` subject), which a
//! process cannot fake by reusing a process id. polkit lets the Agent's own user check the
//! action for another subject because the action file names it as an owner
//! (`org.freedesktop.policykit.owner`).

use std::collections::HashMap;
use std::time::Duration;

use futures_lite::future;
use zbus::connection::Builder;
use zbus::Proxy;
use zbus::Variant;

/// The bus name of polkit.
const POLKIT_NAME: &str = "org.freedesktop.PolicyKit1";

/// The object of polkit's authority.
const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";

/// The interface of polkit's authority.
const AUTHORITY_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// The flag that lets polkit ask the person (`AllowUserInteraction`).
const ALLOW_USER_INTERACTION: u32 = 1;

/// How long the person may take to answer polkit's dialog.
const ANSWER_LIMIT: Duration = Duration::from_secs(120);

/// The action of the destructive reset.
pub const RESET_ACTION: &str = "io.github.LinuxHello.reset";

/// What polkit answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The subject may do the action.
    Yes,
    /// The person gave a wrong password, or the rules say no.
    No,
    /// The person closed the dialog.
    Dismissed,
    /// polkit is not there, did not answer in time, or answered in another shape.
    Unavailable,
}

/// polkit on the system bus, or on a bus of a test.
#[derive(Clone, Debug, Default)]
pub struct Polkit {
    /// The address of the bus to use, or `None` for the system bus.
    address: Option<String>,
}

impl Polkit {
    /// polkit on the bus at `address`, for tests.
    #[must_use]
    pub fn on_bus(address: impl Into<String>) -> Self {
        Self {
            address: Some(address.into()),
        }
    }

    /// Asks whether the connection `sender` (a unique bus name such as `:1.42`) may do `action`,
    /// letting polkit ask the person.
    pub async fn check(&self, sender: &str, action: &str) -> Answer {
        let answer = future::or(self.ask(sender, action), async {
            async_io::Timer::after(ANSWER_LIMIT).await;
            None
        })
        .await;
        answer.unwrap_or(Answer::Unavailable)
    }

    /// The call itself; `None` when it could not be made.
    async fn ask(&self, sender: &str, action: &str) -> Option<Answer> {
        let builder = match &self.address {
            Some(address) => Builder::address(address.as_str()),
            None => Builder::system(),
        };
        let connection = builder.build().await.ok()?;
        let authority = Proxy::new(
            &connection,
            POLKIT_NAME,
            AUTHORITY_PATH,
            AUTHORITY_INTERFACE,
        )
        .await
        .ok()?;
        let mut details: HashMap<&str, Variant<'_>> = HashMap::new();
        details.insert("name", Variant::from(sender));
        let subject = ("system-bus-name", details);
        let none: HashMap<&str, &str> = HashMap::new();
        let reply: (bool, bool, HashMap<String, String>) = authority
            .call(
                "CheckAuthorization",
                &(subject, action, none, ALLOW_USER_INTERACTION, ""),
            )
            .await
            .ok()?;
        let (authorised, _challenge, details) = reply;
        Some(if authorised {
            Answer::Yes
        } else if details.get("polkit.dismissed").map(String::as_str) == Some("true") {
            Answer::Dismissed
        } else {
            Answer::No
        })
    }
}
