//! The Agent's D-Bus glue against a real, private `dbus-daemon`: peers, credentials and unicast
//! delivery are the bus's, not a fake's. Needs the `dbus-daemon` binary (package `dbus-daemon`).

mod common;

use common::{call, connect, error_text, is_error, my_uid, next_within, pid, run, signals, Daemon};
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
            assert!(is_error(&refused, "io.github.LinuxHello.Error.Denied"));
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
        assert!(is_error(
            &bad_id,
            "io.github.LinuxHello.Error.InvalidArgument"
        ));
        let bad_signal = call(&client, "ReportState", &(id.as_str(), "Bogus", vec!["x"])).await;
        assert!(is_error(
            &bad_signal,
            "io.github.LinuxHello.Error.InvalidArgument"
        ));
        let bad_subject = call(&client, "OpenPrompt", &(pid("p2").as_str(), -7_i64)).await;
        assert!(is_error(
            &bad_subject,
            "io.github.LinuxHello.Error.InvalidArgument"
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
        let fresh: (Vec<String>, Vec<String>, String, String, String, u32) =
            fresh.body().deserialize().expect("the reply");
        assert_eq!(
            fresh,
            (
                vec![],
                vec![],
                "idle".to_string(),
                String::new(),
                String::new(),
                0
            )
        );

        for (signal, values) in [
            ("MethodsAvailable", vec!["face", "pin"]),
            ("ActiveMethods", vec!["face", "fingerprint"]),
            ("State", vec!["scanning"]),
            ("Result", vec!["failure", "no-face"]),
        ] {
            call(&client, "ReportState", &(id.as_str(), signal, values))
                .await
                .expect("report");
        }
        let reply = call(&client, "GetState", &(id.as_str(),))
            .await
            .expect("get");
        let reply: (Vec<String>, Vec<String>, String, String, String, u32) =
            reply.body().deserialize().expect("the reply");
        let expected = (
            vec!["face".to_string(), "pin".to_string()],
            vec!["face".to_string(), "fingerprint".to_string()],
            "scanning".to_string(),
            "failure".to_string(),
            "no-face".to_string(),
            0,
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
    let tmp = private_tempdir();
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
        assert!(is_error(&bad, "io.github.LinuxHello.Error.InvalidPolicy"));
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
        assert!(is_error(&seen, "io.github.LinuxHello.Error.Denied"));
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
        assert!(is_error(&refused, "io.github.LinuxHello.Error.Denied"));
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
            if is_error(&seen, "io.github.LinuxHello.Error.Denied") {
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
        // Documentation comments are prose, not names. Two names say "pin" and are named here,
        // nothing else is: `GetPinRules` returns the rules a PIN must follow (length and character
        // classes), never a PIN (ADR-0014, amendment 2026-11-17, point 3), and `ExpectPin`
        // announces that the opener of a prompt is about to send one on the PIN socket; it carries
        // a prompt id and nothing secret (ADR-0021, amendment 2026-11-18); `SetPin` and `ChangePin`
        // start setting and changing the caller's PIN and carry a prompt id alone: the PINs go on
        // the socket (ADR-0021, amendment 2026-11-20).
        let names_only = {
            let mut text = xml.clone();
            while let (Some(start), Some(end)) = (text.find("<!--"), text.find("-->")) {
                text.replace_range(start..end + 3, "");
            }
            text
        };
        for name in names_only.split(['"', '\'']).skip(1).step_by(2) {
            if ["GetPinRules", "ExpectPin", "SetPin", "ChangePin"].contains(&name) {
                continue;
            }
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

/// The watchdog pings the service manager only when the Agent's own bus loop answers
/// (`bus_alive`): a bus where nobody owns the name is not alive, and a served Agent is.
#[test]
fn a_bus_loop_that_answers_is_alive_and_an_absent_one_is_not() {
    use linuxhello_agent::bus::bus_alive;
    use std::time::Duration;
    let daemon = Daemon::start();
    run(async {
        let observer = connect(&daemon).await;
        assert!(
            !bus_alive(&observer, Duration::from_secs(2)).await,
            "nobody owns the name yet"
        );
        let service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        assert!(bus_alive(&service, Duration::from_secs(5)).await);
    });
}

const ERROR_PREFIX: &str = "io.github.LinuxHello.Error.";

#[test]
fn every_error_has_a_fixed_name_and_text() {
    let daemon = Daemon::start();
    let tmp = private_tempdir();
    // A layer the store cannot read: not UTF-8. Same file layout as the store's own tests.
    let damaged = tmp.path().join(my_uid().to_string());
    std::fs::create_dir_all(&damaged).unwrap();
    std::fs::write(damaged.join("policy.toml"), [0xff, 0xfe, 0xfd]).unwrap();
    run(async {
        let mut config = Config::new(vec![]);
        config.max_prompts_per_reporter = 1;
        let _with_store = serve_with(
            Builder::address(daemon.address.as_str()),
            config,
            Some(UserPolicyStore::new(tmp.path())),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let one = |name: &str| format!("{ERROR_PREFIX}{name}");

        let id = pid("p1");
        call(&client, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");

        // LimitReached: a second prompt of the same opener.
        let limit = call(
            &client,
            "OpenPrompt",
            &(pid("p2").as_str(), i64::from(my_uid())),
        )
        .await;
        assert!(is_error(&limit, &one("LimitReached")), "{limit:?}");
        assert_eq!(error_text(&limit).as_deref(), Some("limit reached"));

        // InvalidArgument: a prompt id that is not one.
        let bad_id = call(&client, "GetState", &("p1",)).await;
        assert!(is_error(&bad_id, &one("InvalidArgument")), "{bad_id:?}");
        assert_eq!(error_text(&bad_id).as_deref(), Some("invalid argument"));

        // Damaged: the caller's stored layer cannot be read.
        let damaged = call(&client, "GetUserPolicy", &()).await;
        assert!(is_error(&damaged, &one("Damaged")), "{damaged:?}");
        assert_eq!(
            error_text(&damaged).as_deref(),
            Some("the stored policy is damaged")
        );

        // Denied: a prompt for another user (root may open one for anybody).
        if my_uid() != 0 {
            let other = i64::from(my_uid()) + 1;
            let denied = call(&client, "OpenPrompt", &(pid("p3").as_str(), other)).await;
            assert!(is_error(&denied, &one("Denied")), "{denied:?}");
            assert_eq!(error_text(&denied).as_deref(), Some("not allowed"));
        }
    });
    run(async {
        // Unavailable: no user policy store is configured.
        let _without_store = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let unavailable = call(&client, "GetUserPolicy", &()).await;
        assert!(
            is_error(&unavailable, &format!("{ERROR_PREFIX}Unavailable")),
            "{unavailable:?}"
        );
        assert_eq!(error_text(&unavailable).as_deref(), Some("unavailable"));
    });
}

#[test]
fn invalid_user_policy_names_the_offending_key() {
    let daemon = Daemon::start();
    let tmp = private_tempdir();
    run(async {
        let _service = serve_with(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
            Some(UserPolicyStore::new(tmp.path())),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let tighter = "[methods]\nbiometrics_allowed = false\n";
        call(&client, "SetUserPolicy", &tighter.to_string())
            .await
            .expect("set policy");

        let typo = "[methods]\nbiometrics_alowed = false\n";
        let refused = call(&client, "SetUserPolicy", &typo.to_string()).await;
        assert!(
            is_error(&refused, &format!("{ERROR_PREFIX}InvalidPolicy")),
            "{refused:?}"
        );
        let text = error_text(&refused).expect("the error carries a text");
        assert!(text.contains("biometrics_alowed"), "{text}");

        let kept: String = call(&client, "GetUserPolicy", &())
            .await
            .expect("get policy")
            .body()
            .deserialize()
            .expect("the policy");
        assert_eq!(kept, tighter, "the refused text changed the stored layer");
        call(&client, "SetUserPolicy", &tighter.to_string())
            .await
            .expect("valid text is accepted afterwards");
    });
}

#[test]
fn the_policy_readers_answer_over_the_bus() {
    let daemon = Daemon::start();
    let tmp = private_tempdir();
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
        call(
            &client,
            "SetUserPolicy",
            &"[methods]\nbiometrics_allowed = false\n".to_string(),
        )
        .await
        .expect("set policy");

        let reply = call(&client, "GetEffectivePolicy", &())
            .await
            .expect("the effective policy");
        let (text, managed): (String, Vec<String>) = reply.body().deserialize().expect("the reply");
        assert!(
            text.contains("methods.biometrics_allowed = false"),
            "{text}"
        );
        assert!(managed.is_empty());

        let reply = call(&client, "GetPinRules", &()).await.expect("PIN rules");
        let (min, max, required, disallowed): (u32, u32, Vec<String>, Vec<String>) =
            reply.body().deserialize().expect("the reply");
        assert!(min >= 1 && max >= min);
        assert!(required.iter().all(|c| !disallowed.contains(c)));
    });
}

#[test]
fn a_user_and_root_get_their_status_over_the_bus() {
    let daemon = Daemon::start();
    let tmp = private_tempdir();
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

        let reply = call(&client, "GetStatus", &()).await.expect("status");
        let status: Vec<(String, String, String)> = reply.body().deserialize().expect("the reply");
        assert!(status.is_empty(), "nothing is wrong: {status:?}");

        // The test's user is not root: the details are refused with the Agent's own error.
        if !is_root() {
            let refused = call(&client, "GetStatusDetails", &()).await;
            assert!(is_error(&refused, "io.github.LinuxHello.Error.Denied"));
        }
    });
}

/// Whether the test runs as root, whose uid the bus gives the Agent.
fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(|u| u == "0"))
        })
        .unwrap_or(false)
}

/// The reply byte of a client that sends one frame carrying `pin` on the socket at `path`.
fn send_pin(path: &std::path::Path, pin: &[u8]) -> u8 {
    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(path).expect("connect");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut bytes = u16::try_from(pin.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(pin);
    drop(stream.write_all(&bytes));
    drop(stream.shutdown(std::net::Shutdown::Write));
    let mut reply = [9_u8; 1];
    stream.read_exact(&mut reply).expect("one byte of reply");
    reply[0]
}

#[test]
fn a_pin_is_accepted_only_after_expect_pin_by_the_prompt_opener() {
    use linuxhello_agent::audit::Audit;
    use linuxhello_agent::bus::serve_with_pin_socket;
    use linuxhello_agent::pinsocket::{PinSocket, REPLY_ACCEPTED, REPLY_REFUSED};
    let daemon = Daemon::start();
    let dir = private_tempdir();
    let path = dir.path().join("pin.sock");
    let socket = std::sync::Arc::new(PinSocket::bind(&path, my_uid()).unwrap());
    let (sent, received) = std::sync::mpsc::channel();
    PinSocket::serve_forever(std::sync::Arc::clone(&socket), move |s| {
        sent.send((s.subject, s.pin.to_vec())).unwrap();
    });
    run(async {
        let _service = serve_with_pin_socket(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
            None,
            Audit::none(),
            Some(socket),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let id = pid("p1");
        call(&client, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");

        assert_eq!(send_pin(&path, b"1234"), REPLY_REFUSED, "no ExpectPin yet");

        call(&client, "ExpectPin", &(id.as_str(),))
            .await
            .expect("the opener may announce a PIN");
        assert_eq!(send_pin(&path, b"1234"), REPLY_ACCEPTED);
        let got = received
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("the sink got the PIN");
        assert_eq!(got, (my_uid(), b"1234".to_vec()));
        assert_eq!(
            send_pin(&path, b"1234"),
            REPLY_REFUSED,
            "the call is used up"
        );

        // Another connection of the same user did not open the prompt.
        let other = connect(&daemon).await;
        let refused = call(&other, "ExpectPin", &(id.as_str(),)).await;
        assert!(is_error(&refused, "io.github.LinuxHello.Error.Denied"));
        let malformed = call(&client, "ExpectPin", &("not an id",)).await;
        assert!(is_error(
            &malformed,
            "io.github.LinuxHello.Error.InvalidArgument"
        ));
    });
}

#[test]
fn expect_pin_without_a_socket_is_unavailable_over_the_bus() {
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
        let result = call(&client, "ExpectPin", &(id.as_str(),)).await;
        assert!(is_error(&result, "io.github.LinuxHello.Error.Unavailable"));
    });
}

/// A fake method for the bus tests: succeeds after a delay, or runs until it is cancelled.
struct Fake {
    /// Which method it plays.
    kind: linuxhello_dbus::AuthMethod,
    /// Succeed after this many milliseconds; `None` runs until cancelled.
    succeed_after: Option<u64>,
    /// Set when it saw the cancel flag.
    saw_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl linuxhello_agent::orchestrator::Method for Fake {
    fn kind(&self) -> linuxhello_dbus::AuthMethod {
        self.kind
    }

    fn available(&self) -> bool {
        true
    }

    fn run(
        &mut self,
        cancel: &linuxhello_agent::orchestrator::Cancel,
    ) -> linuxhello_agent::orchestrator::MethodEnd {
        use linuxhello_agent::orchestrator::MethodEnd;
        let until = self
            .succeed_after
            .map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms));
        loop {
            if cancel.is_cancelled() {
                self.saw_cancel
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return MethodEnd::Cancelled;
            }
            if until.is_some_and(|t| std::time::Instant::now() >= t) {
                return MethodEnd::Success;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

/// Serves the Agent with a policy store and a factory that makes one fake fingerprint method.
async fn serve_fakes(
    daemon: &Daemon,
    store: UserPolicyStore,
    succeed_after: Option<u64>,
    saw_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> zbus::Connection {
    use linuxhello_agent::bus::{serve_with_extras, Extras};
    let factory: linuxhello_agent::bus::MethodFactory = std::sync::Arc::new(move |_subject| {
        vec![Box::new(Fake {
            kind: linuxhello_dbus::AuthMethod::Fingerprint,
            succeed_after,
            saw_cancel: std::sync::Arc::clone(&saw_cancel),
        })]
    });
    serve_with_extras(
        Builder::address(daemon.address.as_str()),
        Config::new(vec![]),
        Some(store),
        Extras {
            methods: Some(factory),
            ..Extras::default()
        },
    )
    .await
    .expect("serve the Agent")
}

/// The result and reason of `GetState`, polled until a result is there or `seconds` pass.
async fn result_of(client: &zbus::Connection, id: &str, seconds: u64) -> Option<(String, String)> {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < until {
        let reply = call(client, "GetState", &(id,)).await.expect("get state");
        let state: (Vec<String>, Vec<String>, String, String, String, u32) =
            reply.body().deserialize().expect("the reply");
        if !state.3.is_empty() {
            return Some((state.3, state.4));
        }
        async_io::Timer::after(std::time::Duration::from_millis(20)).await;
    }
    None
}

#[test]
fn authenticate_starts_the_methods_of_the_context() {
    let daemon = Daemon::start();
    let dir = private_tempdir();
    run(async {
        let _service = serve_fakes(
            &daemon,
            UserPolicyStore::new(dir.path()),
            Some(50),
            std::sync::Arc::default(),
        )
        .await;
        let client = connect(&daemon).await;
        let id = pid("p1");
        call(&client, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");
        call(&client, "Subscribe", &(id.as_str(),))
            .await
            .expect("subscribe");
        let mut heard = signals(&client, "Result").await;

        call(&client, "Authenticate", &(id.as_str(), "login"))
            .await
            .expect("the opener may authenticate");
        let signal = next_within(&mut heard, 3_000)
            .await
            .expect("a Result signal");
        let (prompt, result, reason, seconds): (String, String, String, u32) =
            signal.body().deserialize().expect("the signal");
        assert_eq!(
            (prompt.as_str(), result.as_str(), reason.as_str(), seconds),
            (id.as_str(), "success", "", 0)
        );
        assert_eq!(
            result_of(&client, &id, 2).await,
            Some(("success".to_string(), String::new()))
        );
        // After the result the prompt can be authenticated again.
        call(&client, "Authenticate", &(id.as_str(), "sudo"))
            .await
            .expect("a second authentication after the first ended");
    });
}

#[test]
fn authenticate_refuses_what_it_should_over_the_bus() {
    let daemon = Daemon::start();
    let dir = private_tempdir();
    run(async {
        let _service = serve_fakes(
            &daemon,
            UserPolicyStore::new(dir.path()),
            None,
            std::sync::Arc::default(),
        )
        .await;
        let client = connect(&daemon).await;
        let id = pid("p1");
        call(&client, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");
        call(&client, "Authenticate", &(id.as_str(), "login"))
            .await
            .expect("start");
        let second = call(&client, "Authenticate", &(id.as_str(), "login")).await;
        assert!(is_error(&second, "io.github.LinuxHello.Error.LimitReached"));
        let context = call(&client, "Authenticate", &(id.as_str(), "root")).await;
        assert!(is_error(
            &context,
            "io.github.LinuxHello.Error.InvalidArgument"
        ));
        let other = connect(&daemon).await;
        let stranger = call(&other, "Authenticate", &(id.as_str(), "login")).await;
        assert!(is_error(&stranger, "io.github.LinuxHello.Error.Denied"));
    });
}

#[test]
fn closing_the_prompt_cancels_a_running_authentication() {
    let daemon = Daemon::start();
    let dir = private_tempdir();
    let saw_cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    run(async {
        let _service = serve_fakes(
            &daemon,
            UserPolicyStore::new(dir.path()),
            None,
            std::sync::Arc::clone(&saw_cancel),
        )
        .await;
        let client = connect(&daemon).await;
        let id = pid("p1");
        call(&client, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");
        call(&client, "Authenticate", &(id.as_str(), "login"))
            .await
            .expect("start");
        async_io::Timer::after(std::time::Duration::from_millis(100)).await;
        assert!(!saw_cancel.load(std::sync::atomic::Ordering::SeqCst));
        call(&client, "ClosePrompt", &(id.as_str(),))
            .await
            .expect("close");
        for _ in 0..100 {
            if saw_cancel.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            async_io::Timer::after(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            saw_cancel.load(std::sync::atomic::Ordering::SeqCst),
            "the method was cancelled"
        );
    });
}

#[test]
fn without_any_method_authenticate_ends_in_a_failure() {
    let daemon = Daemon::start();
    let dir = private_tempdir();
    run(async {
        let _service = serve_with(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
            Some(UserPolicyStore::new(dir.path())),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let id = pid("p1");
        call(&client, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");
        call(&client, "Authenticate", &(id.as_str(), "login"))
            .await
            .expect("start");
        assert_eq!(
            result_of(&client, &id, 3).await,
            Some(("failure".to_string(), String::new()))
        );
    });
}

#[test]
fn authenticate_is_listed_in_capabilities() {
    assert!(linuxhello_dbus::CAPABILITIES.contains(&"Authenticate"));
    assert_eq!(linuxhello_dbus::METHOD_AUTHENTICATE, "Authenticate");
}

#[test]
fn expect_pin_is_listed_in_capabilities() {
    assert!(linuxhello_dbus::CAPABILITIES.contains(&"ExpectPin"));
    assert_eq!(linuxhello_dbus::METHOD_EXPECT_PIN, "ExpectPin");
}

#[test]
fn capabilities_name_the_version() {
    let daemon = Daemon::start();
    run(async {
        let _service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;
        let reply = call(&client, "GetCapabilities", &())
            .await
            .expect("any user may ask");
        let (version, names): (u32, Vec<String>) = reply.body().deserialize().expect("the reply");
        assert_eq!(version, linuxhello_dbus::INTERFACE_VERSION);
        let wanted: Vec<String> = linuxhello_dbus::CAPABILITIES
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        assert_eq!(names, wanted);
    });
}

#[test]
fn a_result_signal_carries_the_reason_and_the_seconds() {
    let daemon = Daemon::start();
    run(async {
        let _service = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let (owner, subscriber) = (connect(&daemon).await, connect(&daemon).await);
        let id = pid("p1");
        call(&owner, "OpenPrompt", &(id.as_str(), i64::from(my_uid())))
            .await
            .expect("open the prompt");
        let mut heard = signals(&subscriber, "Result").await;
        let mut heard_methods = signals(&subscriber, "ActiveMethods").await;
        call(&subscriber, "Subscribe", &(id.as_str(),))
            .await
            .expect("subscribe");

        call(
            &owner,
            "ReportState",
            &(id.as_str(), "Result", vec!["locked-out", "", "300"]),
        )
        .await
        .expect("report");
        let note = next_within(&mut heard, 3000).await.expect("told");
        let body: (String, String, String, u32) = note.body().deserialize().expect("the body");
        assert_eq!(
            body,
            (id.clone(), "locked-out".to_string(), String::new(), 300)
        );

        call(
            &owner,
            "ReportState",
            &(id.as_str(), "ActiveMethods", vec!["face", "fingerprint"]),
        )
        .await
        .expect("report");
        let note = next_within(&mut heard_methods, 3000).await.expect("told");
        let body: (String, Vec<String>) = note.body().deserialize().expect("the body");
        assert_eq!(
            body,
            (id, vec!["face".to_string(), "fingerprint".to_string()])
        );
    });
}

/// A temporary directory that only its owner can use, whatever the umask of the shell that runs the
/// tests (the code under test refuses a directory that others can write).
fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("a temporary directory")
}
