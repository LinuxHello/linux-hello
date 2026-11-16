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
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use futures_lite::StreamExt;
use linuxhello_dbus::{AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};
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

    /// Closes the prompts that have had no report for too long, before a call changes state.
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
                            service.get_mut().await.api.peer_left(name);
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

/// The D-Bus error for a refusal of the request layer.
fn to_fdo(error: ApiError) -> fdo::Error {
    match error {
        ApiError::Denied => fdo::Error::AccessDenied("not allowed".to_string()),
        ApiError::LimitReached => fdo::Error::LimitsExceeded("limit reached".to_string()),
        ApiError::InvalidArgument => fdo::Error::InvalidArgs("invalid argument".to_string()),
        ApiError::Unavailable => fdo::Error::Failed("unavailable".to_string()),
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
        self.tick();
        let subject = match subject_uid {
            -1 => None,
            uid => Some(u32::try_from(uid).map_err(|_| to_fdo(ApiError::InvalidArgument))?),
        };
        let caller = caller_of(connection, header.sender()).await;
        let opener = header
            .sender()
            .ok_or_else(|| to_fdo(ApiError::Denied))?
            .as_str()
            .to_string();
        self.api
            .open_prompt_from(caller, &opener, prompt_id, subject)
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
        self.tick();
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
        self.tick();
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
        self.tick();
        let caller = caller_of(connection, header.sender()).await;
        self.api.close_prompt(caller, prompt_id).map_err(to_fdo)
    }

    /// Returns the caller's user policy as TOML text.
    async fn get_user_policy(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<String> {
        let caller = caller_of(connection, header.sender()).await;
        self.api.get_user_policy(caller).map_err(to_fdo)
    }

    /// Replaces the caller's user policy with the provided TOML text.
    async fn set_user_policy(
        &mut self,
        text: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<()> {
        let caller = caller_of(connection, header.sender()).await;
        self.api.set_user_policy(caller, text).map_err(to_fdo)
    }
}
