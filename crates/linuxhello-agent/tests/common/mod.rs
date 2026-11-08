//! Helpers shared by the D-Bus integration tests: a private `dbus-daemon`, connections to it, and
//! small wrappers around calls and signals. Needs the `dbus-daemon` binary (package `dbus-daemon`).
#![allow(dead_code)]

use std::future::Future;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use futures_lite::StreamExt;
use linuxhello_dbus::{PromptId, AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};
use zbus::message::Type;
use zbus::DBusError;
use zbus::{connection::Builder, Connection, MatchRule, Message, MessageStream};

/// A private message bus that lives as long as this value.
pub struct Daemon {
    /// The `dbus-daemon` process.
    child: Child,
    /// Its address.
    pub address: String,
    /// A directory that must outlive the bus, such as its configuration files.
    pub scratch: Option<tempfile::TempDir>,
}

impl Daemon {
    /// Starts a private bus with the default session configuration.
    pub fn start() -> Self {
        Self::start_with(&["--session"])
    }

    /// Starts a private bus with the given `dbus-daemon` arguments and waits for its address.
    pub fn start_with(arguments: &[&str]) -> Self {
        let mut child = Command::new("dbus-daemon")
            .args(arguments)
            .args(["--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon must be installed (sudo apt install dbus-daemon)");
        let stdout = child.stdout.take().expect("the daemon's stdout is piped");
        let mut address = String::new();
        BufReader::new(stdout)
            .read_line(&mut address)
            .expect("the daemon prints its address");
        Self {
            child,
            address: address.trim().to_string(),
            scratch: None,
        }
    }
}

impl Drop for Daemon {
    /// Stops the bus.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs a future to completion.
pub fn run<F: Future>(future: F) -> F::Output {
    futures_lite::future::block_on(future)
}

/// A new connection to the private bus.
pub async fn connect(daemon: &Daemon) -> Connection {
    Builder::address(daemon.address.as_str())
        .build()
        .await
        .expect("connect to the private bus")
}

/// The uid of this test process.
pub fn my_uid() -> u32 {
    std::fs::metadata("/proc/self").expect("/proc/self").uid()
}

/// A valid prompt id as text.
pub fn pid(name: &str) -> String {
    PromptId::derive("test", name, "s1").as_str().to_string()
}

/// Calls a method of the Agent.
pub async fn call<B>(connection: &Connection, member: &str, body: &B) -> zbus::Result<Message>
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

/// A stream of the Agent's signals with the given member, as this connection receives them.
pub async fn signals(connection: &Connection, member: &str) -> MessageStream {
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .interface(AGENT_INTERFACE)
        .member(member)
        .build()
        .expect("a valid match rule");
    MessageStream::for_match_rule(rule, connection, None)
        .await
        .expect("match rule")
}

/// The next message of the stream, or none after `millis` milliseconds.
pub async fn next_within(stream: &mut MessageStream, millis: u64) -> Option<Message> {
    futures_lite::future::or(async { stream.next().await?.ok() }, async {
        async_io::Timer::after(Duration::from_millis(millis)).await;
        None
    })
    .await
}

/// Whether a failed call is the D-Bus error with this name. `zbus` returns the standard errors
/// as `Error::FDO` and any other as `Error::MethodError`.
pub fn is_error(result: &zbus::Result<Message>, name: &str) -> bool {
    match result {
        Err(zbus::Error::MethodError(n, _, _)) => n.as_str() == name,
        Err(zbus::Error::FDO(e)) => e.name().as_str() == name,
        _ => false,
    }
}
