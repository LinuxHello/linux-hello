//! The Agent's D-Bus glue against a real, private `dbus-daemon`: peers, credentials and unicast
//! delivery are the bus's, not a fake's. Needs the `dbus-daemon` binary (package `dbus-daemon`).

mod common;

use common::{call, connect, is_error, my_uid, next_within, pid, run, signals, Daemon};
use linuxhello_agent::audit::{Audit, AuditSink, Event};
use linuxhello_agent::bus::{serve, serve_with, serve_with_audit};
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;
use linuxhello_dbus::{AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};
use zbus::connection::Builder;

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

#[test]
fn user_policy_is_set_and_read_over_the_bus() {
    let daemon = Daemon::start();
    let tmp = tempfile::TempDir::new().unwrap();
    let store = UserPolicyStore::new(tmp.path());
    run(async {
        let _service = serve_with(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
            Some(store),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let tighter = "[methods]\nbiometrics_allowed = false\n";

        call(&client, "SetUserPolicy", &tighter.to_string())
            .await
            .expect("set policy");
        let policy_msg = call(&client, "GetUserPolicy", &())
            .await
            .expect("get policy");
        let policy: String = policy_msg.body().deserialize().expect("the policy");
        assert_eq!(policy, tighter);

        let bad = call(&client, "SetUserPolicy", &"invalid = toml".to_string()).await;
        assert!(is_error(&bad, "org.freedesktop.DBus.Error.InvalidArgs"));
        let policy_msg = call(&client, "GetUserPolicy", &())
            .await
            .expect("get policy");
        let policy: String = policy_msg.body().deserialize().expect("the policy");
        assert_eq!(policy, tighter);
    });
}

#[test]
fn a_prompt_without_reports_is_closed_by_the_next_call() {
    let daemon = Daemon::start();
    run(async {
        let config = Config {
            max_idle: std::time::Duration::from_millis(300),
            ..Config::new(vec![])
        };
        let _service = serve(Builder::address(daemon.address.as_str()), config)
            .await
            .expect("serve the Agent");
        let client = connect(&daemon).await;
        let (stale, fresh) = (pid("stale"), pid("fresh"));
        call(
            &client,
            "OpenPrompt",
            &(stale.as_str(), i64::from(my_uid())),
        )
        .await
        .expect("open the prompt");
        call(&client, "GetState", &(stale.as_str(),))
            .await
            .expect("the prompt exists");
        async_io::Timer::after(std::time::Duration::from_millis(600)).await;
        // A call that changes state closes what is stale first.
        call(
            &client,
            "OpenPrompt",
            &(fresh.as_str(), i64::from(my_uid())),
        )
        .await
        .expect("open another prompt");
        let seen = call(&client, "GetState", &(stale.as_str(),)).await;
        assert!(is_error(&seen, "org.freedesktop.DBus.Error.AccessDenied"));
        call(&client, "GetState", &(fresh.as_str(),))
            .await
            .expect("the new prompt is open");
    });
}

/// An audit sink that keeps what it is given.
#[derive(Clone, Default)]
struct Recorder(std::sync::Arc<std::sync::Mutex<Vec<Event>>>);

impl AuditSink for Recorder {
    fn record(&self, event: &Event) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[test]
fn a_refusal_over_the_bus_is_audited_with_the_callers_unique_name() {
    let daemon = Daemon::start();
    run(async {
        let recorder = Recorder::default();
        let _service = serve_with_audit(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
            None,
            Audit::new(Box::new(recorder.clone())),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let refused = call(&client, "GetState", &(pid("unknown").as_str(),)).await;
        assert!(is_error(
            &refused,
            "org.freedesktop.DBus.Error.AccessDenied"
        ));
        let events = recorder.0.lock().unwrap().clone();
        assert_eq!(events.len(), 1);
        let name = client.unique_name().expect("a unique name").to_string();
        let peer = events[0]
            .fields()
            .into_iter()
            .find(|(n, _)| *n == "LH_PEER")
            .map(|(_, v)| v);
        assert_eq!(peer, Some(name));
    });
}

#[test]
fn a_prompt_is_removed_when_its_opener_leaves_the_bus() {
    let daemon = Daemon::start();
    run(async {
        let _service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let (opener, reader) = (connect(&daemon).await, connect(&daemon).await);
        let id = pid("p1");
        call(&opener, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");
        // While the opener is on the bus, another connection of the same user reads the prompt.
        call(&reader, "GetState", &(id.as_str(),))
            .await
            .expect("the prompt exists");
        opener.graceful_shutdown().await;
        // The bus tells the Agent asynchronously, so look for a while.
        let mut removed = false;
        for _ in 0..40 {
            let seen = call(&reader, "GetState", &(id.as_str(),)).await;
            if is_error(&seen, "org.freedesktop.DBus.Error.AccessDenied") {
                removed = true;
                break;
            }
            async_io::Timer::after(std::time::Duration::from_millis(100)).await;
        }
        assert!(removed, "the prompt of a connection that left must be gone");
    });
}

/// P-31: the PIN is not a message body on the bus. The Agent's introspected interface has no
/// method, signal or property whose name or argument names a PIN or another secret, so there is
/// nowhere on the bus to put one; the PIN has its own socket (ADR-0021, `pinsocket`).
#[test]
fn pin_is_never_a_dbus_message_body() {
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
            .expect("introspect the Agent");
        let xml: String = reply.body().deserialize().expect("the XML");
        // The interface must be there, or the test would pass on nothing.
        assert!(xml.contains(AGENT_INTERFACE));
        assert!(xml.contains("OpenPrompt"));
        for name in xml.split(['"', '\'']).skip(1).step_by(2) {
            for word in words_of(name) {
                assert!(
                    !["pin", "secret", "password", "passphrase", "credential"]
                        .contains(&word.as_str()),
                    "the bus interface names `{name}`: a secret has no place on the bus"
                );
            }
        }
    });
}

/// The words of a name in camel case or with separators, in lower case: `SetPin` is `set` and
/// `pin`, `Ping` is the one word `ping`, `PIN` is `pin`.
fn words_of(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut words = Vec::new();
    let mut word = String::new();
    for (i, &c) in chars.iter().enumerate() {
        let starts_word = c.is_uppercase()
            && i > 0
            && (!chars[i - 1].is_uppercase() || chars.get(i + 1).is_some_and(|n| n.is_lowercase()));
        if (!c.is_alphanumeric() || starts_word) && !word.is_empty() {
            words.push(std::mem::take(&mut word).to_lowercase());
        }
        if c.is_alphanumeric() {
            word.push(c);
        }
    }
    if !word.is_empty() {
        words.push(word.to_lowercase());
    }
    words
}

#[test]
fn names_are_split_into_words() {
    assert_eq!(words_of("SetPin"), ["set", "pin"]);
    assert_eq!(words_of("Ping"), ["ping"]);
    assert_eq!(words_of("PIN"), ["pin"]);
    assert_eq!(words_of("user_pin_code"), ["user", "pin", "code"]);
    assert_eq!(words_of("GetPINState"), ["get", "pin", "state"]);
}

#[test]
fn a_subscriber_is_told_over_the_bus_when_the_prompt_closes() {
    let daemon = Daemon::start();
    run(async {
        let _service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let (owner, follower, left, bystander) = (
            connect(&daemon).await,
            connect(&daemon).await,
            connect(&daemon).await,
            connect(&daemon).await,
        );
        let id = pid("p1");
        call(&owner, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");
        let mut heard = signals(&follower, "Closed").await;
        let mut stopped = signals(&left, "Closed").await;
        let mut overheard = signals(&bystander, "Closed").await;
        for client in [&follower, &left] {
            call(client, "Subscribe", &(id.as_str(),))
                .await
                .expect("subscribe");
        }
        call(&left, "Unsubscribe", &(id.as_str(),))
            .await
            .expect("unsubscribe");
        call(&owner, "ClosePrompt", &(id.as_str(),))
            .await
            .expect("close the prompt");

        let note = next_within(&mut heard, 3000)
            .await
            .expect("the subscriber is told");
        let (prompt,): (String,) = note.body().deserialize().expect("the body");
        assert_eq!(prompt, id.as_str());
        assert_eq!(
            note.header().destination().map(|d| d.to_string()),
            Some(follower.unique_name().expect("a unique name").to_string())
        );
        assert!(
            next_within(&mut stopped, 400).await.is_none(),
            "a peer that unsubscribed must hear nothing"
        );
        assert!(
            next_within(&mut overheard, 400).await.is_none(),
            "a peer that did not subscribe must hear nothing"
        );
    });
}

#[test]
fn a_subscriber_is_told_when_the_opener_leaves_the_bus() {
    let daemon = Daemon::start();
    run(async {
        let _service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let (owner, follower) = (connect(&daemon).await, connect(&daemon).await);
        let id = pid("p1");
        call(&owner, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");
        let mut heard = signals(&follower, "Closed").await;
        call(&follower, "Subscribe", &(id.as_str(),))
            .await
            .expect("subscribe");
        drop(owner);
        let note = next_within(&mut heard, 3000)
            .await
            .expect("the subscriber is told that the prompt is gone");
        let (prompt,): (String,) = note.body().deserialize().expect("the body");
        assert_eq!(prompt, id.as_str());
    });
}
