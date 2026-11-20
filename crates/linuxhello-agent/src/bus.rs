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
//! `Subscribe`, `ClosePrompt`, `GetCapabilities`, `GetEffectivePolicy`, `GetPinRules`, `GetStatus`, `GetStatusDetails`, `ExpectPin`, and the signals `MethodsAvailable`, `ActiveMethods`, `State` and
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
    PromptId, PromptResult, AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH, CAPABILITIES,
    INTERFACE_VERSION,
};
use std::time::Instant;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;
use zbus::fdo;
use zbus::message::Header;
use zbus::names::{BusName, UniqueName};
use zbus::{connection, interface, Connection};

use crate::api::{Api, ApiError, Caller, Notification, PeerName};
use crate::audit::Audit;
use crate::methods::pin::enrol::{run_change, run_set, Job, PinEnrolment};
use crate::methods::pin::PinInbox;
use crate::orchestrator::{Method, Orchestrator, Reporter};
use crate::pinlock::service::{wall_clock_seconds, PinLockService};
use crate::pinsocket::PinSocket;
use crate::policy::user_store::UserPolicyStore;
use crate::state::{Config, Outcome, Update};

pub mod credentials;

/// How long an authentication may take before it fails with `timeout`.
const AUTH_DEADLINE: Duration = Duration::from_secs(60);

/// Makes the methods an authentication runs, for the user being authenticated. The Agent has
/// none yet (the fingerprint, face and PIN methods are later slices of #195), so the default makes
/// no method and every authentication fails at once with no methods offered.
pub type MethodFactory = Arc<dyn Fn(u32) -> Vec<Box<dyn Method>> + Send + Sync>;

/// A report of the orchestrator for the prompt that `uid` opened, on its way to the state store.
pub struct AgentUpdate {
    /// The user who opened the prompt, which keys it in the store.
    uid: u32,
    /// The prompt.
    prompt: PromptId,
    /// What happened.
    update: Update,
}

/// The reporter of an authentication: sends every update to the bus thread, which applies it.
struct ChannelReporter {
    /// Where the updates go.
    updates: Sender<AgentUpdate>,
    /// The user who opened the prompt.
    uid: u32,
    /// The prompt.
    prompt: PromptId,
}

impl Reporter for ChannelReporter {
    fn report(&mut self, update: Update) {
        let _ = self.updates.send(AgentUpdate {
            uid: self.uid,
            prompt: self.prompt.clone(),
            update,
        });
    }
}

/// The Agent's state API as a D-Bus object.
pub struct AgentService {
    /// The request layer that decides every call.
    api: Api,
    /// When the service was made: the origin of the time the store's prompts are aged by.
    started: Instant,
    /// The PIN socket that `ExpectPin` announces a PIN to, when the Agent has one.
    pin_socket: Option<Arc<PinSocket>>,
    /// Where the PIN socket hands PINs to `SetPin` and `ChangePin`, and what they call.
    pin_change: Option<PinChange>,
    /// The PIN lock, which `ChangePin` counts a wrong current PIN in.
    lock: Option<Arc<PinLockService>>,
    /// Makes the methods that an authentication runs, for the user being authenticated.
    methods: MethodFactory,
    /// How long an authentication may take before it fails with `timeout`.
    auth_deadline: Duration,
    /// Where the orchestrator's reports go, to be applied to the state store on the bus thread;
    /// `None` until the service is served.
    updates: Option<Sender<AgentUpdate>>,
}

impl AgentService {
    /// A service over an empty state store with the given settings.
    pub fn new(config: Config) -> Self {
        Self {
            api: Api::new(config),
            started: Instant::now(),
            pin_socket: None,
            pin_change: None,
            lock: None,
            methods: Arc::new(|_| Vec::new()),
            auth_deadline: AUTH_DEADLINE,
            updates: None,
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
            pin_socket: None,
            pin_change: None,
            lock: None,
            methods: Arc::new(|_| Vec::new()),
            auth_deadline: AUTH_DEADLINE,
            updates: None,
        }
    }

    /// The same service with the PIN lock that `GetStatus` reads.
    #[must_use]
    pub fn with_pin_lock(self, pin_lock: Option<Arc<PinLockService>>) -> Self {
        Self {
            lock: pin_lock.clone(),
            api: self.api.with_shared_pin_lock(pin_lock),
            ..self
        }
    }

    /// Starts the job of `SetPin` or `ChangePin` on a thread of its own.
    async fn start_pin_job(
        &mut self,
        prompt_id: &str,
        change: bool,
        header: &Header<'_>,
        connection: &Connection,
    ) -> Result<(), AgentError> {
        self.tick();
        let caller = caller_of(connection, header.sender()).await;
        let (Some(pin_change), Some(lock), Some(updates)) = (
            self.pin_change.clone(),
            self.lock.clone(),
            self.updates.clone(),
        ) else {
            return Err(to_bus(ApiError::Unavailable));
        };
        let has_pin = caller
            .uid
            .is_some_and(|uid| pin_change.enrolment.has_pin(uid));
        let start = self
            .api
            .begin_pin_change(caller, prompt_id, change, has_pin)
            .map_err(to_bus)?;
        // Registered before the call returns, so that a PIN sent right after it is not lost.
        let wait = pin_change.inbox.wait_for(start.subject);
        std::thread::spawn(move || {
            let job = Job {
                subject: start.subject,
                rules: &start.rules,
                wait: PIN_WAIT,
                lock: &lock,
                enrolment: &*pin_change.enrolment,
                clock: wall_clock_seconds,
            };
            let ran = catch_unwind(AssertUnwindSafe(|| {
                if change {
                    run_change(&job, &wait, &start.stop)
                } else {
                    run_set(&job, &wait, &start.stop)
                }
            }));
            // Whatever went wrong, the prompt must not stay "running" for ever.
            let outcome = ran.unwrap_or_else(|_| Outcome::new(PromptResult::Failure));
            let _ = updates.send(AgentUpdate {
                uid: start.opener_uid,
                prompt: start.prompt,
                update: Update::Result(outcome),
            });
        });
        Ok(())
    }

    /// The same service with the PIN socket that `ExpectPin` announces to.
    #[must_use]
    pub fn with_pin_socket(self, pin_socket: Option<Arc<PinSocket>>) -> Self {
        Self { pin_socket, ..self }
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
    serve_with_pin_socket(builder, config, user_policies, audit, None).await
}

/// Serves the Agent's state API with an optional user policy store, an audit trail and the PIN
/// socket that `ExpectPin` announces to. Without a socket `ExpectPin` is `Unavailable`.
pub async fn serve_with_pin_socket(
    builder: connection::Builder<'_>,
    config: Config,
    user_policies: Option<UserPolicyStore>,
    audit: Audit,
    pin_socket: Option<Arc<PinSocket>>,
) -> zbus::Result<Connection> {
    serve_with_pin_lock(builder, config, user_policies, audit, pin_socket, None).await
}

/// Serves the Agent's state API with everything the Agent has: a user policy store, an audit
/// trail, the PIN socket and the PIN lock that `GetStatus` reads.
pub async fn serve_with_pin_lock(
    builder: connection::Builder<'_>,
    config: Config,
    user_policies: Option<UserPolicyStore>,
    audit: Audit,
    pin_socket: Option<Arc<PinSocket>>,
    pin_lock: Option<PinLockService>,
) -> zbus::Result<Connection> {
    let extras = Extras {
        audit: Some(audit),
        pin_socket,
        pin_lock: pin_lock.map(Arc::new),
        ..Extras::default()
    };
    serve_with_extras(builder, config, user_policies, extras).await
}

/// What `SetPin` and `ChangePin` need: the inbox the PIN socket fills, and what makes the keys.
#[derive(Clone)]
pub struct PinChange {
    /// Where the PIN socket hands PINs.
    pub inbox: Arc<PinInbox>,
    /// What sets and changes a PIN.
    pub enrolment: Arc<dyn PinEnrolment>,
}

/// How long `SetPin` and `ChangePin` wait for each PIN after the call: the socket's own window and
/// a margin for the client to send it.
const PIN_WAIT: Duration = Duration::from_secs(60);

/// What the Agent has besides its configuration and its policy store.
#[derive(Default)]
pub struct Extras {
    /// The audit trail of refusals and policy changes.
    pub audit: Option<Audit>,
    /// The PIN socket that `ExpectPin` announces a PIN to.
    pub pin_socket: Option<Arc<PinSocket>>,
    /// The PIN lock that `GetStatus` reads.
    pub pin_lock: Option<Arc<PinLockService>>,
    /// What `SetPin` and `ChangePin` use; without it they are `Unavailable`.
    pub pin_change: Option<PinChange>,
    /// Makes the methods an authentication runs; none by default.
    pub methods: Option<MethodFactory>,
    /// How long an authentication may take; a minute by default.
    pub auth_deadline: Option<Duration>,
}

/// Serves the Agent's state API with everything in `extras`, and the thread that applies the
/// orchestrator's reports to the state store and sends the signals.
pub async fn serve_with_extras(
    builder: connection::Builder<'_>,
    config: Config,
    user_policies: Option<UserPolicyStore>,
    extras: Extras,
) -> zbus::Result<Connection> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut service = AgentService::with_audit(
        config,
        user_policies,
        extras.audit.unwrap_or_else(Audit::none),
    )
    .with_pin_socket(extras.pin_socket)
    .with_pin_lock(extras.pin_lock);
    service.pin_change = extras.pin_change;
    if let Some(methods) = extras.methods {
        service.methods = methods;
    }
    if let Some(deadline) = extras.auth_deadline {
        service.auth_deadline = deadline;
    }
    service.updates = Some(sender);
    let connection = builder
        .name(AGENT_BUS_NAME)
        .serve_at(AGENT_OBJECT_PATH, service)
        .build()
        .await?;
    watch_departures(&connection).await?;
    apply_updates(&connection, receiver)?;
    Ok(connection)
}

/// Applies the orchestrator's reports to the state store, one at a time, and sends the signals
/// they cause. It runs on a thread of its own, because the orchestrator runs on threads and the
/// store is behind the bus object; it ends when the service is dropped and the channel closes.
fn apply_updates(
    connection: &Connection,
    receiver: std::sync::mpsc::Receiver<AgentUpdate>,
) -> zbus::Result<()> {
    let connection = connection.clone();
    std::thread::Builder::new()
        .name("linuxhello-agent-updates".to_string())
        .spawn(move || {
            futures_lite::future::block_on(async move {
                while let Ok(report) = receiver.recv() {
                    let Ok(service) = connection
                        .object_server()
                        .interface::<_, AgentService>(AGENT_OBJECT_PATH)
                        .await
                    else {
                        continue;
                    };
                    let notes = {
                        let mut service = service.get_mut().await;
                        service
                            .api
                            .agent_report(report.uid, &report.prompt, report.update)
                    };
                    for note in &notes {
                        send(&connection, note).await;
                    }
                }
            });
        })
        .map_err(|e| zbus::Error::Failure(e.to_string()))?;
    Ok(())
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

/// The caller as [`caller_of`] finds it, and its process id as the bus reports it. The process id
/// is looked up only where it is needed (`ExpectPin`), and is `None` when the bus cannot give it.
async fn caller_and_process(
    connection: &Connection,
    sender: Option<&UniqueName<'_>>,
) -> (Caller, Option<u32>) {
    let caller = caller_of(connection, sender).await;
    let Some(sender) = sender else {
        return (caller, None);
    };
    let Ok(bus) = fdo::DBusProxy::new(connection).await else {
        return (caller, None);
    };
    let process = bus
        .get_connection_credentials(BusName::from(sender.clone()))
        .await
        .ok()
        .and_then(|c| c.process_id());
    (caller, process)
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

    /// Starts the authentication of a prompt for a context: the Agent runs the methods the
    /// context allows and reports by the signals and `GetState`. Returns at once.
    async fn authenticate(
        &mut self,
        prompt_id: &str,
        context: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), AgentError> {
        self.tick();
        let caller = caller_of(connection, header.sender()).await;
        let start = self
            .api
            .begin_authentication(caller, prompt_id, context)
            .map_err(to_bus)?;
        let Some(updates) = self.updates.clone() else {
            self.api.agent_report(
                start.opener_uid,
                &start.prompt,
                Update::Result(Outcome::new(PromptResult::Failure)),
            );
            return Err(to_bus(ApiError::Unavailable));
        };
        let methods = (self.methods)(start.subject);
        let deadline = self.auth_deadline;
        std::thread::spawn(move || {
            let mut reporter = ChannelReporter {
                updates: updates.clone(),
                uid: start.opener_uid,
                prompt: start.prompt.clone(),
            };
            let ran = catch_unwind(AssertUnwindSafe(|| {
                Orchestrator::run(&start.rule, methods, &mut reporter, deadline, &start.stop)
            }));
            if ran.is_err() {
                // Whatever went wrong, the prompt must not stay "running" for ever.
                reporter.report(Update::Result(Outcome::new(PromptResult::Failure)));
            }
        });
        Ok(())
    }

    /// Starts setting the caller's first PIN: the Agent waits for one PIN on the PIN socket and
    /// reports the outcome as the prompt's `Result`. Returns at once (ADR-0021, amendment
    /// 2026-11-20).
    async fn set_pin(
        &mut self,
        prompt_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), AgentError> {
        self.start_pin_job(prompt_id, false, &header, connection)
            .await
    }

    /// Starts changing the caller's PIN: the Agent waits for the current PIN and then the new one
    /// on the PIN socket and reports the outcome as the prompt's `Result`. Returns at once.
    async fn change_pin(
        &mut self,
        prompt_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), AgentError> {
        self.start_pin_job(prompt_id, true, &header, connection)
            .await
    }

    /// Announces that the caller, who opened the prompt, is about to send one PIN on the PIN
    /// socket. The call carries the prompt id and nothing secret.
    async fn expect_pin(
        &self,
        prompt_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), AgentError> {
        let (caller, process) = caller_and_process(connection, header.sender()).await;
        self.api
            .expect_pin(caller, process, prompt_id, self.pin_socket.as_deref())
            .map_err(to_bus)
    }

    /// Returns the conditions that affect the caller, each as code, severity and sentence.
    async fn get_status(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<Vec<(String, String, String)>, AgentError> {
        let caller = caller_of(connection, header.sender()).await;
        self.api.get_status(caller).map_err(to_bus)
    }

    /// Returns the same conditions with the loader's detail; only root may call it.
    async fn get_status_details(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<Vec<(String, String, String, String)>, AgentError> {
        let caller = caller_of(connection, header.sender()).await;
        self.api.get_status_details(caller).map_err(to_bus)
    }

    /// Returns the policy that applies to the caller as TOML text, and the paths an
    /// administrator manages.
    async fn get_effective_policy(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(String, Vec<String>), AgentError> {
        let caller = caller_of(connection, header.sender()).await;
        self.api.get_effective_policy(caller).map_err(to_bus)
    }

    /// Returns the shortest and longest PIN, and the character classes that are required and
    /// those that are disallowed.
    async fn get_pin_rules(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(u32, u32, Vec<String>, Vec<String>), AgentError> {
        let caller = caller_of(connection, header.sender()).await;
        self.api
            .get_pin_rules(caller)
            .map(|r| (r.min_length, r.max_length, r.required, r.disallowed))
            .map_err(to_bus)
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
