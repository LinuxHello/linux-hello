//! The Rust behind the `AgentLink` QML object: it reaches the Linux Hello Agent over the system
//! bus and keeps the state of one sign-in attempt for the Auth Prompt (ADR-0028).
//!
//! `ping()` asks whether the Agent answers. `watch()` registers with the Agent (`WatchPrompts`) and
//! follows each prompt the Agent says has started (`PromptStarted`); `follow(id)` follows a prompt
//! the screen already knows. Following means `Subscribe`, then `GetState`, then folding every state
//! signal into `fold::PromptView`, whose JSON becomes the `stateJson` property. The listening runs
//! on a thread of its own and hands each new state to Qt's thread. Only signals whose sender is the
//! connection that owns the Agent's bus name are read, so no other program can feed the screen a
//! state (`only_the_agents_signals_are_read`). It starts no program (ADR-0026).
//!
//! C4 component: `agentLink` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use core::pin::Pin;
use std::sync::mpsc;
use std::time::Duration;

use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::QString;
use futures_lite::StreamExt;
use linuxhello_dbus::{AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};
use zbus::{Connection, Message, MessageStream};

use crate::bridge::qobject::AgentLink;
use crate::fold::{Event, PromptView};

/// The Rust side of `AgentLink`.
#[derive(Default)]
pub struct AgentLinkRust {
    /// The state of the followed prompt as the Auth Prompt reads it (JSON).
    pub(crate) state_json: QString,
    /// Whether the Agent answered the last ping.
    pub(crate) reachable: bool,
    /// Whether a listening thread runs already; one per object.
    listening: bool,
    /// Whether a ping is waiting for the Agent; one at a time, so a hung bus cannot pile up
    /// threads.
    pinging: bool,
}

/// How long `ping` waits for the Agent before it says "not reachable". The call itself has no
/// limit of its own, and it never runs on the thread of the screen (R-26, #368).
const PING_LIMIT: Duration = Duration::from_secs(2);

/// The first wait before the listening thread tries again after the Agent or the bus was not
/// there, and the longest it grows to.
const RETRY_FIRST: Duration = Duration::from_secs(1);
/// The longest wait between two tries.
const RETRY_MAX: Duration = Duration::from_secs(30);

/// The wait after `previous`: twice as long, never above [`RETRY_MAX`].
fn next_delay(previous: Duration) -> Duration {
    (previous * 2).min(RETRY_MAX)
}

/// Runs `ask` on a thread of its own and returns its answer, or `false` when it has not answered
/// within `limit`. The thread is left to finish by itself: a bus that hangs costs one idle thread,
/// never the screen (`a_ping_that_is_not_answered_says_no_within_its_limit`).
fn answers_within(limit: Duration, ask: impl FnOnce() -> bool + Send + 'static) -> bool {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(ask());
    });
    receiver.recv_timeout(limit).unwrap_or(false)
}

/// What a listening thread follows.
enum Follow {
    /// Every prompt the Agent announces to this connection.
    Watch,
    /// One prompt, by its id.
    Prompt(String),
}

/// Whether the Agent answers `org.freedesktop.DBus.Peer.Ping` on the system bus.
async fn agent_answers() -> bool {
    let Ok(connection) = Connection::system().await else {
        return false;
    };
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
}

/// The unique name of the connection that owns the Agent's bus name now.
async fn agent_owner(connection: &Connection) -> Option<String> {
    let reply = connection
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetNameOwner",
            &(AGENT_BUS_NAME,),
        )
        .await
        .ok()?;
    reply.body().deserialize::<String>().ok()
}

/// Calls `member` of the Agent with `body`.
async fn call<B>(connection: &Connection, member: &str, body: &B) -> zbus::Result<Message>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    connection
        .call_method(
            Some(AGENT_BUS_NAME),
            AGENT_OBJECT_PATH,
            Some(AGENT_INTERFACE),
            member,
            body,
        )
        .await
}

/// Starts following `prompt`: forget the last one, subscribe, and read its state now.
async fn start(connection: &Connection, view: &mut PromptView, prompt: &str) {
    view.apply(Event::Started(prompt.to_string()));
    if call(connection, "Subscribe", &(prompt,)).await.is_err() {
        return;
    }
    if let Ok(reply) = call(connection, "GetState", &(prompt,)).await {
        if let Ok((available, active, state, result, reason, seconds)) = reply
            .body()
            .deserialize::<(Vec<String>, Vec<String>, String, String, String, u32)>()
        {
            view.apply(Event::Snapshot(
                available, active, state, result, reason, seconds,
            ));
        }
    }
}

/// The event of a signal of the Agent about the followed prompt, `None` for anything else.
fn event_of(message: &Message, prompt: Option<&str>) -> Option<Event> {
    let header = message.header();
    let member = header.member()?.as_str().to_string();
    let body = message.body();
    let mine = |id: &str| prompt == Some(id);
    match member.as_str() {
        "PromptStarted" => body
            .deserialize::<(String, String)>()
            .ok()
            .map(|(id, _context)| Event::Started(id)),
        "MethodsAvailable" => body
            .deserialize::<(String, Vec<String>)>()
            .ok()
            .filter(|(id, _)| mine(id))
            .map(|(_, list)| Event::Methods(list)),
        "ActiveMethods" => body
            .deserialize::<(String, Vec<String>)>()
            .ok()
            .filter(|(id, _)| mine(id))
            .map(|(_, list)| Event::Active(list)),
        "State" => body
            .deserialize::<(String, String)>()
            .ok()
            .filter(|(id, _)| mine(id))
            .map(|(_, state)| Event::State(state)),
        "Result" => body
            .deserialize::<(String, String, String, u32)>()
            .ok()
            .filter(|(id, ..)| mine(id))
            .map(|(_, result, reason, seconds)| Event::Result(result, reason, seconds)),
        "MethodEnded" => body
            .deserialize::<(String, String, String, String, u32)>()
            .ok()
            .filter(|(id, ..)| mine(id))
            .map(|(_, method, outcome, reason, seconds)| {
                Event::MethodEnded(method, outcome, reason, seconds)
            }),
        _ => None,
    }
}

/// Why one session of listening ended.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    /// The Agent is not on the bus, or did not accept the registration.
    NoAgent,
    /// The Agent's name changed owner or was released, so everything it sent before is stale.
    AgentChanged,
    /// The bus connection ended.
    BusClosed,
}

/// What the listening loop reads: a message of the bus, or the news that the Agent's name moved.
enum Heard {
    /// A message that reached the connection.
    Message(zbus::Result<Message>),
    /// The owner of the Agent's bus name changed.
    OwnerChanged,
}

/// One session of listening on `connection`: find the Agent, register or subscribe, then fold
/// every signal of the Agent into the view and hand each new state to `publish`. Returns when the
/// Agent leaves or changes (`a_new_agent_after_a_restart_is_followed`), because signals of an
/// earlier connection of the Agent are no longer the Agent's (R-26, #368).
async fn serve(connection: &Connection, follow: &Follow, publish: &impl Fn(String, bool)) -> Ended {
    let mut view = PromptView::default();
    let Some(owner) = agent_owner(connection).await else {
        publish(view.to_json(), false);
        return Ended::NoAgent;
    };
    // Watched before anything is asked, so a restart between the two is not missed.
    let Ok(proxy) = zbus::fdo::DBusProxy::new(connection).await else {
        return Ended::BusClosed;
    };
    let Ok(changes) = proxy
        .receive_name_owner_changed_with_args(&[(0, AGENT_BUS_NAME)])
        .await
    else {
        return Ended::BusClosed;
    };
    view.apply(Event::Reachable(true));
    let messages = MessageStream::from(connection).map(Heard::Message);
    let mut stream = messages.or(changes.map(|_| Heard::OwnerChanged));
    match follow {
        Follow::Watch => {
            if call(connection, "WatchPrompts", &()).await.is_err() {
                publish(view.to_json(), true);
                return Ended::NoAgent;
            }
        }
        Follow::Prompt(prompt) => start(connection, &mut view, prompt).await,
    }
    publish(view.to_json(), true);
    while let Some(heard) = stream.next().await {
        let message = match heard {
            Heard::OwnerChanged => return Ended::AgentChanged,
            Heard::Message(Ok(message)) => message,
            Heard::Message(Err(_)) => continue,
        };
        let header = message.header();
        if header.message_type() != zbus::message::Type::Signal
            || header.sender().map(|s| s.as_str()) != Some(owner.as_str())
            || header.interface().map(|i| i.as_str()) != Some(AGENT_INTERFACE)
        {
            continue;
        }
        match event_of(&message, view.prompt.as_deref()) {
            Some(Event::Started(prompt)) => start(connection, &mut view, &prompt).await,
            Some(event) => view.apply(event),
            None => continue,
        }
        publish(view.to_json(), true);
    }
    Ended::BusClosed
}

/// The listening loop, for as long as the object lives: connect with `connect`, run a session, and
/// when it ends say "not reachable" and try again after a wait that grows from [`RETRY_FIRST`] to
/// [`RETRY_MAX`]. An Agent that is not there at the first start, one that restarts, and a bus
/// that is gone for a while all end in the same place: the screen follows the Agent again as soon as
/// it can (`an_agent_that_is_not_there_at_the_start_is_followed_when_it_appears`).
async fn keep_listening<F, Fut>(
    connect: F,
    follow: Follow,
    publish: impl Fn(String, bool),
    first_delay: Duration,
) where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = zbus::Result<Connection>>,
{
    let mut delay = first_delay;
    loop {
        if let Ok(connection) = connect().await {
            let ended = serve(&connection, &follow, &publish).await;
            // A session that got as far as the Agent starts the waits again from the short one.
            if ended != Ended::NoAgent {
                delay = first_delay;
            }
        }
        publish(PromptView::default().to_json(), false);
        std::thread::sleep(delay);
        delay = next_delay(delay).max(first_delay);
    }
}

impl AgentLink {
    /// Asks whether the Agent answers and sets `reachable`. The question is asked on a thread of
    /// its own and gives up after [`PING_LIMIT`], so a bus that does not answer never freezes the
    /// screen; a ping that is still waiting makes a second call do nothing.
    pub fn ping(mut self: Pin<&mut Self>) {
        if self.rust().pinging {
            return;
        }
        self.as_mut().rust_mut().get_mut().pinging = true;
        let qt_thread = self.qt_thread();
        std::thread::spawn(move || {
            let answered = answers_within(PING_LIMIT, || {
                futures_lite::future::block_on(agent_answers())
            });
            let _ = qt_thread.queue(move |mut object| {
                object.as_mut().rust_mut().get_mut().pinging = false;
                object.as_mut().set_reachable(answered);
            });
        });
    }

    /// Follows every prompt the Agent announces to this screen (`WatchPrompts`, ADR-0014 amendment
    /// of 2026-11-22). Only the first call of `watch` or `follow` on an object has an effect.
    pub fn watch(self: Pin<&mut Self>) {
        self.listen_on_a_thread(Follow::Watch);
    }

    /// Follows the prompt `prompt_id`. Only the first call of `watch` or `follow` on an object has
    /// an effect.
    pub fn follow(self: Pin<&mut Self>, prompt_id: &QString) {
        self.listen_on_a_thread(Follow::Prompt(prompt_id.to_string()));
    }

    /// Starts the listening thread, once per object.
    fn listen_on_a_thread(mut self: Pin<&mut Self>, follow: Follow) {
        if self.rust().listening {
            return;
        }
        self.as_mut().rust_mut().get_mut().listening = true;
        let qt_thread = self.qt_thread();
        std::thread::spawn(move || {
            futures_lite::future::block_on(keep_listening(
                Connection::system,
                follow,
                |json, reachable| {
                    let _ = qt_thread.queue(move |mut object| {
                        object.as_mut().set_reachable(reachable);
                        object.as_mut().set_state_json(QString::from(&json));
                    });
                },
                RETRY_FIRST,
            ));
        });
    }
}

#[cfg(test)]
mod tests;
