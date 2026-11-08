//! The Agent's D-Bus glue against a real, private `dbus-daemon`: peers, credentials and unicast
//! delivery are the bus's, not a fake's. Needs the `dbus-daemon` binary (package `dbus-daemon`).

use std::future::Future;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use futures_lite::StreamExt;
use linuxhello_agent::bus::serve;
use linuxhello_agent::state::Config;
use linuxhello_dbus::{PromptId, AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};
use zbus::message::Type;
use zbus::DBusError;
use zbus::{connection::Builder, Connection, MatchRule, Message, MessageStream};

/// A private message bus that lives as long as this value.
struct Daemon {
    /// The `dbus-daemon` process.
    child: Child,
    /// Its address.
    address: String,
}

impl Daemon {
    /// Starts a private bus and waits for its address.
    fn start() -> Self {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
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
fn run<F: Future>(future: F) -> F::Output {
    futures_lite::future::block_on(future)
}

/// A new connection to the private bus.
async fn connect(daemon: &Daemon) -> Connection {
    Builder::address(daemon.address.as_str())
        .build()
        .await
        .expect("connect to the private bus")
}

/// The uid of this test process.
fn my_uid() -> u32 {
    std::fs::metadata("/proc/self").expect("/proc/self").uid()
}

/// A valid prompt id as text.
fn pid(name: &str) -> String {
    PromptId::derive("test", name, "s1").as_str().to_string()
}

/// Calls a method of the Agent.
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

/// A stream of the Agent's signals with the given member, as this connection receives them.
async fn signals(connection: &Connection, member: &str) -> MessageStream {
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
async fn next_within(stream: &mut MessageStream, millis: u64) -> Option<Message> {
    futures_lite::future::or(async { stream.next().await?.ok() }, async {
        async_io::Timer::after(Duration::from_millis(millis)).await;
        None
    })
    .await
}

/// Whether a failed call is the D-Bus error with this name. `zbus` returns the standard errors
/// as `Error::FDO` and any other as `Error::MethodError`.
fn is_error(result: &zbus::Result<Message>, name: &str) -> bool {
    match result {
        Err(zbus::Error::MethodError(n, _, _)) => n.as_str() == name,
        Err(zbus::Error::FDO(e)) => e.name().as_str() == name,
        _ => false,
    }
}

#[test]
fn signals_reach_only_the_subscribed_peer() {
    let daemon = Daemon::start();
    run(async {
        let _service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let (owner, subscriber, bystander) = (
            connect(&daemon).await,
            connect(&daemon).await,
            connect(&daemon).await,
        );
        let id = pid("p1");
        call(&owner, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");

        let mut heard = signals(&subscriber, "State").await;
        let mut overheard = signals(&bystander, "State").await;
        call(&subscriber, "Subscribe", &(id.as_str(),))
            .await
            .expect("subscribe");
        call(
            &owner,
            "ReportState",
            &(id.as_str(), "State", vec!["scanning"]),
        )
        .await
        .expect("report");

        let note = next_within(&mut heard, 3000)
            .await
            .expect("the subscribed peer is told");
        let (prompt, state): (String, String) = note.body().deserialize().expect("the body");
        assert_eq!((prompt.as_str(), state.as_str()), (id.as_str(), "scanning"));
        let to = subscriber.unique_name().expect("a unique name");
        assert_eq!(
            note.header().destination().map(|d| d.to_string()),
            Some(to.to_string())
        );
        assert!(
            next_within(&mut overheard, 400).await.is_none(),
            "a peer that did not subscribe must hear nothing"
        );
    });
}

#[test]
fn a_prompt_for_another_user_is_refused_with_access_denied() {
    let daemon = Daemon::start();
    run(async {
        let _service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let other = i64::from(my_uid()) + 1;
        let refused = call(&client, "OpenPrompt", &(pid("p1").as_str(), other)).await;
        if my_uid() == 0 {
            // Root may open a prompt for any user (the PAM module of a login does).
            assert!(refused.is_ok());
        } else {
            assert!(is_error(
                &refused,
                "org.freedesktop.DBus.Error.AccessDenied"
            ));
        }
    });
}

#[test]
fn malformed_requests_get_invalid_args_errors() {
    let daemon = Daemon::start();
    run(async {
        let _service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let id = pid("p1");
        call(&client, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");

        let bad_id = call(&client, "GetState", &("p1",)).await;
        assert!(is_error(&bad_id, "org.freedesktop.DBus.Error.InvalidArgs"));
        let bad_signal = call(&client, "ReportState", &(id.as_str(), "Bogus", vec!["x"])).await;
        assert!(is_error(
            &bad_signal,
            "org.freedesktop.DBus.Error.InvalidArgs"
        ));
        let bad_subject = call(&client, "OpenPrompt", &(pid("p2").as_str(), -7_i64)).await;
        assert!(is_error(
            &bad_subject,
            "org.freedesktop.DBus.Error.InvalidArgs"
        ));
    });
}

#[test]
fn get_state_returns_the_prompt_state_over_the_bus() {
    let daemon = Daemon::start();
    run(async {
        let _service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let id = pid("p1");
        call(&client, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");

        let fresh = call(&client, "GetState", &(id.as_str(),))
            .await
            .expect("get");
        let fresh: (Vec<String>, String, String, String) =
            fresh.body().deserialize().expect("the reply");
        assert_eq!(
            fresh,
            (vec![], String::new(), "idle".to_string(), String::new())
        );

        for (signal, values) in [
            ("MethodsAvailable", vec!["face", "pin"]),
            ("ActiveMethod", vec!["face"]),
            ("State", vec!["scanning"]),
            ("Result", vec!["failure"]),
        ] {
            call(&client, "ReportState", &(id.as_str(), signal, values))
                .await
                .expect("report");
        }
        let reply = call(&client, "GetState", &(id.as_str(),))
            .await
            .expect("get");
        let reply: (Vec<String>, String, String, String) =
            reply.body().deserialize().expect("the reply");
        let expected = (
            vec!["face".to_string(), "pin".to_string()],
            "face".to_string(),
            "scanning".to_string(),
            "failure".to_string(),
        );
        assert_eq!(reply, expected);
    });
}

#[test]
fn the_interface_is_the_one_registered_in_adr_0012() {
    let daemon = Daemon::start();
    run(async {
        let _service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let reply = client
            .call_method(
                Some(AGENT_BUS_NAME),
                AGENT_OBJECT_PATH,
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await
            .expect("introspect");
        let xml: String = reply.body().deserialize().expect("the XML");
        assert!(xml.contains(&format!("interface name=\"{AGENT_INTERFACE}\"")));
        for member in [
            "OpenPrompt",
            "ReportState",
            "GetState",
            "Subscribe",
            "ClosePrompt",
        ] {
            assert!(
                xml.contains(&format!("method name=\"{member}\"")),
                "{member}"
            );
        }
    });
}
