//! The Agent's D-Bus glue: serves the state API of ADR-0014 on a bus connection.
//!
//! This is the thin layer between the bus and [`Api`]. For every call it asks the bus for the
//! sender's credentials (`GetConnectionCredentials`) and passes the uid it got, or none, to the
//! request layer; it never takes a uid from a message. A subscriber is the calling connection
//! itself, named by its unique bus name from the message header, so nobody can subscribe
//! someone else. Notifications are sent as unicast signals to exactly the peers the request layer
//! names; the Agent emits no broadcast signal.
//!
//! The members are the Rust method names in PascalCase: `OpenPrompt`, `ReportState`, `GetState`,
//! `Subscribe`, `ClosePrompt`, and the signals `MethodsAvailable`, `ActiveMethod`, `State` and
//! `Result` of `linuxhello_dbus::SIGNALS`. A refusal is a D-Bus error: `AccessDenied`,
//! `LimitsExceeded` or `InvalidArgs`.
//!
//! Security properties: `signals_reach_only_the_subscribed_peer` (P-05, over a real bus) and
//! `caller_without_peer_credentials_is_refused` (P-02, in the request layer).
//!
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

use linuxhello_dbus::{AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};
use zbus::fdo;
use zbus::message::Header;
use zbus::names::{BusName, UniqueName};
use zbus::{connection, interface, Connection};

use crate::api::{Api, ApiError, Caller, Notification};
use crate::state::Config;

/// The Agent's state API as a D-Bus object.
pub struct AgentService {
    /// The request layer that decides every call.
    api: Api,
}

impl AgentService {
    /// A service over an empty state store with the given settings.
    pub fn new(config: Config) -> Self {
        Self {
            api: Api::new(config),
        }
    }
}

/// Serves the Agent's state API on the connection that `builder` makes: claims the bus name of
/// ADR-0012 and exports the object at its path. Production uses the system bus
/// (`connection::Builder::system()`); tests use the address of a private bus.
///
/// # Errors
///
/// Any error of the bus connection, of claiming the name, or of exporting the object.
pub async fn serve(builder: connection::Builder<'_>, config: Config) -> zbus::Result<Connection> {
    builder
        .name(AGENT_BUS_NAME)
        .serve_at(AGENT_OBJECT_PATH, AgentService::new(config))
        .build()
        .await
}

/// The caller as the bus describes it: the uid of the sender's connection, or none when there is
/// no sender or the bus does not answer.
async fn caller_of(connection: &Connection, sender: Option<&UniqueName<'_>>) -> Caller {
    let Some(sender) = sender else {
        return Caller { uid: None };
    };
    let Ok(bus) = fdo::DBusProxy::new(connection).await else {
        return Caller { uid: None };
    };
    let credentials = bus
        .get_connection_credentials(BusName::from(sender.clone()))
        .await;
    Caller {
        uid: credentials.ok().and_then(|c| c.unix_user_id()),
    }
}

/// The D-Bus error for a refusal of the request layer.
fn to_fdo(error: ApiError) -> fdo::Error {
    match error {
        ApiError::Denied => fdo::Error::AccessDenied("not allowed".to_string()),
        ApiError::LimitReached => fdo::Error::LimitsExceeded("limit reached".to_string()),
        ApiError::InvalidArgument => fdo::Error::InvalidArgs("invalid argument".to_string()),
    }
}

/// Sends one notification as a unicast signal to its peer. A peer that has gone away does not
/// undo the report, so a failure to send is ignored.
async fn send(connection: &Connection, note: &Notification) {
    let peer = Some(note.peer.0.as_str());
    let prompt = note.prompt_id.as_str();
    let sent = if note.signal == "MethodsAvailable" {
        connection
            .emit_signal(
                peer,
                AGENT_OBJECT_PATH,
                AGENT_INTERFACE,
                note.signal,
                &(prompt, &note.values),
            )
            .await
    } else {
        let value = note.values.first().map_or("", String::as_str);
        connection
            .emit_signal(
                peer,
                AGENT_OBJECT_PATH,
                AGENT_INTERFACE,
                note.signal,
                &(prompt, value),
            )
            .await
    };
    drop(sent);
}

#[interface(name = "io.github.LinuxHello.Agent1")]
impl AgentService {
    /// Opens a prompt owned by the caller. `subject_uid` is the uid being authenticated, or -1
    /// when it is not known yet.
    async fn open_prompt(
        &mut self,
        prompt_id: &str,
        subject_uid: i64,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<()> {
        let subject = match subject_uid {
            -1 => None,
            uid => Some(u32::try_from(uid).map_err(|_| to_fdo(ApiError::InvalidArgument))?),
        };
        let caller = caller_of(connection, header.sender()).await;
        self.api
            .open_prompt(caller, prompt_id, subject)
            .map_err(to_fdo)
    }

    /// Changes one part of a prompt's state and signals the subscribed peers. `signal` is one
    /// of `MethodsAvailable`, `ActiveMethod`, `State` and `Result`.
    async fn report_state(
        &mut self,
        prompt_id: &str,
        signal: &str,
        values: Vec<String>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<()> {
        let caller = caller_of(connection, header.sender()).await;
        let values: Vec<&str> = values.iter().map(String::as_str).collect();
        let notes = self
            .api
            .report_state(caller, prompt_id, signal, &values)
            .map_err(to_fdo)?;
        for note in &notes {
            send(connection, note).await;
        }
        Ok(())
    }

    /// The state of a prompt: the methods available, the active method, the state and the
    /// result. The active method and the result are empty strings when there is none.
    async fn get_state(
        &self,
        prompt_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<(Vec<String>, String, String, String)> {
        let caller = caller_of(connection, header.sender()).await;
        let reply = self.api.get_state(caller, prompt_id).map_err(to_fdo)?;
        Ok((
            reply.methods,
            reply.active.unwrap_or_default(),
            reply.state,
            reply.result.unwrap_or_default(),
        ))
    }

    /// Subscribes the calling connection to the prompt's signals.
    async fn subscribe(
        &mut self,
        prompt_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<()> {
        let caller = caller_of(connection, header.sender()).await;
        let sender = header
            .sender()
            .ok_or_else(|| to_fdo(ApiError::Denied))?
            .as_str()
            .to_string();
        self.api
            .subscribe(caller, &sender, prompt_id)
            .map_err(to_fdo)
    }

    /// Closes a prompt opened by the caller.
    async fn close_prompt(
        &mut self,
        prompt_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<()> {
        let caller = caller_of(connection, header.sender()).await;
        self.api.close_prompt(caller, prompt_id).map_err(to_fdo)
    }
}
