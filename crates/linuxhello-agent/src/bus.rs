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
//! `Subscribe`, `ClosePrompt`, `GetCapabilities`, and the signals `MethodsAvailable`, `ActiveMethods`, `State` and
//! `Result` of `linuxhello_dbus::SIGNALS`. A refusal is a D-Bus error of the closed set
//! `linuxhello_dbus::ERRORS` under `io.github.LinuxHello.Error` ([`AgentError`]): `Denied`,
//! `LimitReached`, `InvalidArgument`, `InvalidPolicy`, `Unavailable` or `Damaged`.
//!
//! Security properties: `signals_reach_only_the_subscribed_peer` (P-05, over a real bus) and
//! `caller_without_peer_credentials_is_refused` (P-02, in the request layer).
//!
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use futures_lite::StreamExt;
use linuxhello_dbus::{
    AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH, CAPABILITIES, INTERFACE_VERSION,
};
use std::time::Instant;

use zbus::fdo;
use zbus::message::Header;
use zbus::names::{BusName, UniqueName};
use zbus::{connection, interface, Connection};

use crate::api::{Api, ApiError, Caller, Notification, PeerName};
use crate::audit::Audit;
use crate::policy::user_store::UserPolicyStore;
use crate::state::Config;

pub mod credentials;

/// The Agent's state API as a D-Bus object.
pub struct AgentService {
    /// The request layer that decides every call.
    api: Api,
    /// When the service was made: the origin of the time the store's prompts are aged by.
    started: Instant,
}

impl AgentService {
    /// A service over an empty state store with the given settings.
    pub fn new(config: Config) -> Self {
        Self {
            api: Api::new(config),
            started: Instant::now(),
        }
    }

    /// Sends the `Closed` signal for every prompt that closed since the last call, to the peers
    /// that were subscribed to it and to nobody else.
    async fn flush(&mut self, connection: &Connection) {
        for note in self.api.take_closures() {
            send(connection, &note).await;
        }
    }

    /// Moves the Agent's clock forward and closes the prompts that have had no report for too
    /// long, before a call changes state.
    fn tick(&mut self) {
        self.api.advance(self.started.elapsed());
    }

    /// A service with a user policy store.
    pub fn with_user_policy_store(config: Config, user_policies: Option<UserPolicyStore>) -> Self {
        Self::with_audit(config, user_policies, Audit::none())
    }

    /// A service with a user policy store that records its refusals and policy changes in
    /// `audit`.
    pub fn with_audit(
        config: Config,
        user_policies: Option<UserPolicyStore>,
        audit: Audit,
    ) -> Self {
        Self {
            api: Api::new(config)
                .with_user_policy_store(user_policies)
                .with_audit(audit),
            started: Instant::now(),
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
    serve_with(builder, config, None).await
}

/// Serves the Agent's state API with an optional user policy store.
pub async fn serve_with(
    builder: connection::Builder<'_>,
    config: Config,
    user_policies: Option<UserPolicyStore>,
) -> zbus::Result<Connection> {
    serve_with_audit(builder, config, user_policies, Audit::none()).await
}

/// Serves the Agent's state API with an optional user policy store and an audit trail.
pub async fn serve_with_audit(
    builder: connection::Builder<'_>,
    config: Config,
    user_policies: Option<UserPolicyStore>,
    audit: Audit,
) -> zbus::Result<Connection> {
    let connection = builder
        .name(AGENT_BUS_NAME)
        .serve_at(
            AGENT_OBJECT_PATH,
            AgentService::with_audit(config, user_policies, audit),
        )
        .build()
        .await?;
    watch_departures(&connection).await?;
    Ok(connection)
}

/// Whether the Agent's bus loop answers: a `Peer.Ping` to its own name goes through the bus daemon
/// and back into the object server, and must be answered within `within`. The watchdog pings the
/// service manager only after this returns true, so a hung loop is a missed ping
/// (`a_bus_loop_that_answers_is_alive_and_an_absent_one_is_not`).
pub async fn bus_alive(connection: &Connection, within: std::time::Duration) -> bool {
    let ping = async {
        connection
            .call_method(
                Some(AGENT_BUS_NAME),
                AGENT_OBJECT_PATH,
                Some("org.freedesktop.DBus.Peer"),
                "Ping",
                &(),
            )
            .await
            .is_ok()
    };
    let timeout = async {
        async_io::Timer::after(within).await;
        false
    };
    futures_lite::future::or(ping, timeout).await
}

/// Asks the bus for `NameOwnerChanged` and, for every unique name that loses its owner, removes
/// the prompts that connection opened and its subscriptions
/// (`a_prompt_is_removed_when_its_opener_leaves_the_bus`). The leaving connection is the first
/// argument of the signal; the sender of the signal is the bus itself.
async fn watch_departures(connection: &Connection) -> zbus::Result<()> {
    let bus = fdo::DBusProxy::new(connection).await?;
    let mut changes = bus.receive_name_owner_changed().await?;
    let connection = connection.clone();
    // The bus connection drives its own I/O; this thread only waits for the signal. It ends
    // when the signal stream ends, that is when the connection is closed.
    std::thread::Builder::new()
        .name("linuxhello-agent-watch-departures".to_string())
        .spawn(move || {
            futures_lite::future::block_on(async move {
                while let Some(change) = changes.next().await {
                    let Ok(args) = change.args() else { continue };
                    let name = args.name().as_str();
                    if name.starts_with(':') && args.new_owner().is_none() {
                        if let Ok(service) = connection
                            .object_server()
                            .interface::<_, AgentService>(AGENT_OBJECT_PATH)
                            .await
                        {
                            let notes = {
                                let mut service = service.get_mut().await;
                                service.api.peer_left(name);
                                service.api.take_closures()
                            };
                            for note in &notes {
                                send(&connection, note).await;
                            }
                        }
                    }
                }
            });
        })
        .map_err(|e| zbus::Error::Failure(e.to_string()))?;
    Ok(())
}

/// The caller as the bus describes it: the uid of the sender's connection, or none when there is
/// no sender or the bus does not answer, and the sender's unique bus name from the message header
/// (the bus daemon sets it; the caller cannot).
async fn caller_of(connection: &Connection, sender: Option<&UniqueName<'_>>) -> Caller {
    let Some(sender) = sender else {
        return Caller {
            uid: None,
            peer: None,
        };
    };
    let peer = PeerName::new(sender.as_str());
    let Ok(bus) = fdo::DBusProxy::new(connection).await else {
        return Caller { uid: None, peer };
    };
    let credentials = bus
        .get_connection_credentials(BusName::from(sender.clone()))
        .await;
    Caller {
        uid: credentials.ok().and_then(|c| c.unix_user_id()),
        peer,
    }
}

/// The errors of the Agent's interface, under `io.github.LinuxHello.Error` (ADR-0014, amendment
/// 2026-11-17; the closed set is `linuxhello_dbus::ERRORS`). A client matches the name. The text
/// is fixed for every error except `InvalidPolicy`, whose text is the parser's message about the
/// caller's own policy text.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.github.LinuxHello.Error")]
pub enum AgentError {
    /// An error of the bus connection itself, such as a failed reply.
    #[zbus(error)]
    ZBus(zbus::Error),
    /// The caller may not do this.
    Denied(String),
    /// A limit of the state store is reached.
    LimitReached(String),
    /// An argument is not valid.
    InvalidArgument(String),
    /// The caller's own policy text does not follow the schema.
    InvalidPolicy(String),
    /// A service the request needs is not available.
    Unavailable(String),
    /// What the Agent stored for the caller cannot be read.
    Damaged(String),
}

/// The D-Bus error for a refusal of the request layer.
fn to_bus(error: ApiError) -> AgentError {
    match error {
        ApiError::Denied => AgentError::Denied("not allowed".to_string()),
        ApiError::LimitReached => AgentError::LimitReached("limit reached".to_string()),
        ApiError::InvalidArgument => AgentError::InvalidArgument("invalid argument".to_string()),
        ApiError::InvalidPolicy(message) => AgentError::InvalidPolicy(message),
        ApiError::Unavailable => AgentError::Unavailable("unavailable".to_string()),
        ApiError::Damaged => AgentError::Damaged("the stored policy is damaged".to_string()),
    }
}

/// Sends one notification as a unicast signal to its peer. A peer that has gone away does not
/// undo the report, so a failure to send is ignored.
async fn send(connection: &Connection, note: &Notification) {
    let peer = Some(note.peer.0.as_str());
    let prompt = note.prompt_id.as_str();
    let sent = if note.signal == "Closed" {
        connection
            .emit_signal(
                peer,
                AGENT_OBJECT_PATH,
                AGENT_INTERFACE,
                note.signal,
                &(prompt,),
            )
            .await
    } else if note.signal == "MethodsAvailable" || note.signal == "ActiveMethods" {
        connection
            .emit_signal(
                peer,
                AGENT_OBJECT_PATH,
                AGENT_INTERFACE,
                note.signal,
                &(prompt, &note.values),
            )
            .await
    } else if note.signal == "Result" {
        let value = |at: usize| note.values.get(at).map_or("", String::as_str);
        let seconds: u32 = value(2).parse().unwrap_or(0);
        connection
            .emit_signal(
                peer,
                AGENT_OBJECT_PATH,
                AGENT_INTERFACE,
                note.signal,
                &(prompt, value(0), value(1), seconds),
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
    ) -> Result<(), AgentError> {
        self.tick();
        let subject = match subject_uid {
            -1 => None,
            uid => Some(u32::try_from(uid).map_err(|_| to_bus(ApiError::InvalidArgument))?),
        };
        let caller = caller_of(connection, header.sender()).await;
        let opener = header
            .sender()
            .ok_or_else(|| to_bus(ApiError::Denied))?
            .as_str()
            .to_string();
        let result = self
            .api
            .open_prompt_from(caller, &opener, prompt_id, subject);
        self.flush(connection).await;
        result.map_err(to_bus)
    }

    /// Changes one part of a prompt's state and signals the subscribed peers. `signal` is one
    /// of `MethodsAvailable`, `ActiveMethods`, `State` and `Result`.
    async fn report_state(
        &mut self,
        prompt_id: &str,
        signal: &str,
        values: Vec<String>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), AgentError> {
        self.tick();
        let caller = caller_of(connection, header.sender()).await;
        let values: Vec<&str> = values.iter().map(String::as_str).collect();
        let result = self.api.report_state(caller, prompt_id, signal, &values);
        self.flush(connection).await;
        for note in &result.map_err(to_bus)? {
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
    ) -> Result<(Vec<String>, Vec<String>, String, String, String, u32), AgentError> {
        let caller = caller_of(connection, header.sender()).await;
        let reply = self.api.get_state(caller, prompt_id).map_err(to_bus)?;
        Ok((
            reply.methods,
            reply.active,
            reply.state,
            reply.result.unwrap_or_default(),
            reply.reason,
            reply.retry_after,
        ))
    }

    /// Returns the version of the interface and the names of the optional members this Agent
    /// supports, so that a client can tell what it may use. Any user may ask; the answer is the
    /// same for everyone and says nothing about a prompt, a user or a file.
    async fn get_capabilities(&self) -> (u32, Vec<String>) {
        (
            INTERFACE_VERSION,
            CAPABILITIES
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        )
    }

    /// Subscribes the calling connection to the prompt's signals.
    async fn subscribe(
        &mut self,
        prompt_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), AgentError> {
        self.tick();
        let caller = caller_of(connection, header.sender()).await;
        let sender = header
            .sender()
            .ok_or_else(|| to_bus(ApiError::Denied))?
            .as_str()
            .to_string();
        let result = self.api.subscribe(caller, &sender, prompt_id);
        self.flush(connection).await;
        result.map_err(to_bus)
    }

    /// Stops the signals of the prompt to the calling connection.
    async fn unsubscribe(
        &mut self,
        prompt_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), AgentError> {
        self.tick();
        let caller = caller_of(connection, header.sender()).await;
        let sender = header
            .sender()
            .ok_or_else(|| to_bus(ApiError::Denied))?
            .as_str()
            .to_string();
        let result = self.api.unsubscribe(caller, &sender, prompt_id);
        self.flush(connection).await;
        result.map_err(to_bus)
    }

    /// Closes a prompt opened by the caller.
    async fn close_prompt(
        &mut self,
        prompt_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), AgentError> {
        self.tick();
        let caller = caller_of(connection, header.sender()).await;
        let result = self.api.close_prompt(caller, prompt_id);
        self.flush(connection).await;
        result.map_err(to_bus)
    }

    /// Returns the caller's user policy as TOML text.
    async fn get_user_policy(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<String, AgentError> {
        let caller = caller_of(connection, header.sender()).await;
        self.api.get_user_policy(caller).map_err(to_bus)
    }

    /// Replaces the caller's user policy with the provided TOML text.
    async fn set_user_policy(
        &mut self,
        text: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), AgentError> {
        let caller = caller_of(connection, header.sender()).await;
        self.api.set_user_policy(caller, text).map_err(to_bus)
    }
}
