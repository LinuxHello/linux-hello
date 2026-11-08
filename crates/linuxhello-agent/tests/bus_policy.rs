//! The system-bus policy of the Agent (`security/dbus/io.github.LinuxHello.Agent1.conf`) enforced by
//! a real, private `dbus-daemon`. The bus runs with the default rules of the system bus (method
//! calls and name ownership denied, signals allowed) and the policy file included after them, as
//! `system.conf` does. The file names the user `linuxhello`; each test swaps that name for the
//! current user (the Agent's user) or for `nobody` (anyone else), so one uid plays both roles.
//! Needs the `dbus-daemon` binary (package `dbus-daemon`).

mod common;

use std::process::Command;

use common::{call, connect, is_error, my_uid, next_within, pid, run, signals, Daemon};
use linuxhello_agent::bus::serve;
use linuxhello_agent::state::Config;
use linuxhello_dbus::{AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};
use zbus::connection::Builder;

/// The policy file of the repository.
const POLICY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../security/dbus/io.github.LinuxHello.Agent1.conf"
);

/// The name of the current user.
fn my_name() -> String {
    let output = Command::new("id").arg("-un").output().expect("run id");
    String::from_utf8(output.stdout)
        .expect("a user name")
        .trim()
        .to_string()
}

/// Starts a private bus with the default rules of the system bus and the policy file included
/// after them. `agent_user` replaces `linuxhello` in the file. When `me_may_own` is set, the
/// current user may also own the Agent's name through a separate policy that grants nothing else,
/// so that user is otherwise subject to the default rules.
fn bus_with_policy(agent_user: &str, me_may_own: bool) -> Daemon {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let policy = std::fs::read_to_string(POLICY)
        .expect("the policy file")
        .replace("user=\"linuxhello\"", &format!("user=\"{agent_user}\""));
    let policy_path = scratch.path().join("agent.conf");
    std::fs::write(&policy_path, policy).expect("write the policy");
    let extra = if me_may_own {
        format!(
            "<policy user=\"{}\"><allow own=\"{AGENT_BUS_NAME}\"/></policy>",
            my_name()
        )
    } else {
        String::new()
    };
    let config = format!(
        r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <listen>unix:tmpdir={dir}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <deny own="*"/>
    <deny send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
    <allow send_destination="org.freedesktop.DBus"/>
  </policy>
  <include>{policy}</include>
  {extra}
</busconfig>
"#,
        dir = scratch.path().display(),
        policy = policy_path.display(),
    );
    let config_path = scratch.path().join("bus.conf");
    std::fs::write(&config_path, config).expect("write the bus configuration");
    let argument = format!("--config-file={}", config_path.display());
    let mut daemon = Daemon::start_with(&[argument.as_str()]);
    daemon.scratch = Some(scratch);
    daemon
}

#[test]
fn only_the_agents_user_may_own_the_name() {
    run(async {
        let agent_user = bus_with_policy(&my_name(), false);
        let served = serve(
            Builder::address(agent_user.address.as_str()),
            Config::new(vec![]),
        )
        .await;
        assert!(served.is_ok(), "the Agent's user owns the name: {served:?}");

        let someone_else = bus_with_policy("nobody", false);
        let refused = serve(
            Builder::address(someone_else.address.as_str()),
            Config::new(vec![]),
        )
        .await;
        assert!(refused.is_err(), "any other user must be refused the name");
    });
}

/// Whether a signal of the Agent's interface sent by this test process reaches a listener on a
/// bus whose policy names `agent_user` as the Agent's user.
async fn forged_signal_is_heard(agent_user: &str) -> bool {
    let daemon = bus_with_policy(agent_user, false);
    let (sender, listener) = (connect(&daemon).await, connect(&daemon).await);
    let mut heard = signals(&listener, "State").await;
    sender
        .emit_signal(
            None::<&str>,
            AGENT_OBJECT_PATH,
            AGENT_INTERFACE,
            "State",
            &("prompt", "scanning"),
        )
        .await
        .expect("send");
    next_within(&mut heard, 600).await.is_some()
}

#[test]
fn only_the_agents_user_can_send_the_agents_signals() {
    run(async {
        assert!(
            forged_signal_is_heard(&my_name()).await,
            "the Agent's user can send its signals"
        );
        assert!(
            !forged_signal_is_heard("nobody").await,
            "a forged signal of the Agent's interface must not reach anyone"
        );
    });
}

#[test]
fn any_user_can_call_the_agents_methods_but_not_its_other_interfaces() {
    run(async {
        // The Agent may own the name here, and the caller is the same uid, so both are subject
        // to the default rules plus the policy file for everyone else.
        let daemon = bus_with_policy("nobody", true);
        let _agent = serve(
            Builder::address(daemon.address.as_str()),
            Config::new(vec![]),
        )
        .await
        .expect("serve the Agent");
        let client = connect(&daemon).await;

        let introspect = client
            .call_method(
                Some(AGENT_BUS_NAME),
                AGENT_OBJECT_PATH,
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await;
        assert!(introspect.is_ok(), "introspection is allowed");

        // A bad id reaches the Agent, which answers InvalidArgs: the bus let the call through.
        let reached = call(&client, "GetState", &("not-a-prompt-id",)).await;
        assert!(is_error(&reached, "org.freedesktop.DBus.Error.InvalidArgs"));

        // Another interface of the same object is denied by the bus itself.
        let properties = client
            .call_method(
                Some(AGENT_BUS_NAME),
                AGENT_OBJECT_PATH,
                Some("org.freedesktop.DBus.Properties"),
                "GetAll",
                &(AGENT_INTERFACE,),
            )
            .await;
        assert!(is_error(
            &properties,
            "org.freedesktop.DBus.Error.AccessDenied"
        ));
    });
}

#[test]
fn a_subscriber_hears_the_agent_under_the_policy() {
    run(async {
        let daemon = bus_with_policy(&my_name(), false);
        let _agent = serve(
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
        let mut heard = signals(&subscriber, "State").await;
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
        assert!(
            next_within(&mut heard, 3000).await.is_some(),
            "the policy must not block the Agent's own unicast signal"
        );
    });
}
