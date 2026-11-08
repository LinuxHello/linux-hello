//! The Agent's D-Bus glue against a real, private `dbus-daemon`: peers, credentials and unicast
//! delivery are the bus's, not a fake's. Needs the `dbus-daemon` binary (package `dbus-daemon`).

mod common;

use common::{call, connect, is_error, my_uid, next_within, pid, run, signals, Daemon};
use linuxhello_agent::bus::{serve, serve_with};
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
