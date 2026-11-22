//! The confinement files of the Agent: the systemd unit, its sysusers entry and its AppArmor
//! profile in `security/`. The property tests read the files and check what they grant and
//! refuse; the last test of each file also runs the real parser (`systemd-analyze verify`,
//! `apparmor_parser -Q`) when it is installed and says so when it is not.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use linuxhello_dbus::AGENT_BUS_NAME;

/// The directory `security/` of the repository.
const SECURITY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../security");

/// The text of a file under `security/`.
fn read(relative: &str) -> String {
    std::fs::read_to_string(Path::new(SECURITY).join(relative))
        .unwrap_or_else(|e| panic!("{relative}: {e}"))
}

/// Reads a file under `security/` and returns every value of each key in the named section.
fn settings_of(file: &str, section: &str) -> HashMap<String, Vec<String>> {
    let mut settings: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_section = false;
    for line in read(file).lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line == format!("[{}]", section);
        } else if in_section && !line.starts_with('#') && !line.is_empty() {
            if let Some((key, value)) = line.split_once('=') {
                settings
                    .entry(key.trim().to_string())
                    .or_default()
                    .push(value.trim().to_string());
            }
        }
    }
    settings
}

/// The `[Service]` settings of the unit: every value of each key, in order.
fn service_settings() -> HashMap<String, Vec<String>> {
    settings_of("systemd/linuxhello-agent.service", "Service")
}

/// The one value of a setting; fails if it is missing or set more than once.
fn only(settings: &HashMap<String, Vec<String>>, key: &str) -> String {
    match settings.get(key).map(Vec::as_slice) {
        Some([value]) => value.clone(),
        other => panic!("{key} must be set exactly once, found {other:?}"),
    }
}

/// The non-comment lines of the AppArmor profile, trimmed.
fn profile_rules() -> Vec<String> {
    read("apparmor/linuxhello-agent")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Runs a tool, or says it is not installed and returns none.
fn run_tool(tool: &str, arguments: &[&str]) -> Option<(bool, String)> {
    match Command::new(tool).args(arguments).output() {
        Ok(out) => Some((
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )),
        Err(_) => {
            eprintln!("SKIPPED: {tool} is not installed, so the file was not parsed by it");
            None
        }
    }
}

#[test]
fn agent_unit_runs_as_its_own_user_with_no_privileges() {
    let s = service_settings();
    assert_eq!(only(&s, "User"), "linuxhello");
    assert_eq!(only(&s, "Group"), "linuxhello");
    assert_eq!(only(&s, "NoNewPrivileges"), "yes");
    assert_eq!(
        only(&s, "CapabilityBoundingSet"),
        "",
        "no capability at all"
    );
    assert_eq!(only(&s, "AmbientCapabilities"), "");
}

#[test]
fn agent_unit_sandbox_is_strict() {
    let s = service_settings();
    for (key, value) in [
        ("ProtectSystem", "strict"),
        ("ProtectHome", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateNetwork", "yes"),
        ("IPAddressDeny", "any"),
        ("RemoveIPC", "yes"),
        ("RestrictAddressFamilies", "AF_UNIX"),
        ("RestrictNamespaces", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("MemoryDenyWriteExecute", "yes"),
        ("LockPersonality", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectKernelModules", "yes"),
        ("SystemCallArchitectures", "native"),
    ] {
        assert_eq!(only(&s, key), value, "{key}");
    }
}

#[test]
fn agent_unit_writes_no_core_dump() {
    // A core file of the Agent would put PINs and key material on disk (ADR-0021, decision 4).
    assert_eq!(only(&service_settings(), "LimitCORE"), "0");
}

#[test]
fn agent_unit_allows_no_device() {
    let s = service_settings();
    assert_eq!(only(&s, "DevicePolicy"), "closed");
    assert!(
        !s.contains_key("DeviceAllow"),
        "the Agent never opens a device itself: {:?}",
        s.get("DeviceAllow")
    );
}

#[test]
fn agent_unit_refuses_to_start_unless_apparmor_enforces_its_profile() {
    let s = service_settings();
    assert_eq!(only(&s, "AppArmorProfile"), "linuxhello-agent");
    let check = only(&s, "ExecStartPre");
    assert!(check.starts_with('+'), "the check needs full privileges");
    assert!(
        check.contains("linuxhello-agent (enforce)"),
        "the check must demand enforce mode, not just a loaded profile: {check}"
    );
    let profile = read("apparmor/linuxhello-agent");
    assert!(profile.contains("profile linuxhello-agent "));
}

/// A permanent fault (a profile that is not enforced, a TPM with an owner password) must not restart
/// the service every second for ever (review finding R-29, #371).
#[test]
fn agent_unit_backs_off_instead_of_restarting_every_second() {
    let s = service_settings();
    assert_eq!(only(&s, "Restart"), "on-failure");
    assert_eq!(only(&s, "RestartSec"), "1");
    assert_eq!(only(&s, "RestartSteps"), "5");
    assert_eq!(only(&s, "RestartMaxDelaySec"), "60");
}

#[test]
fn agent_unit_claims_the_registered_bus_name() {
    let s = service_settings();
    assert_eq!(only(&s, "Type"), "dbus");
    assert_eq!(only(&s, "BusName"), AGENT_BUS_NAME);
}

#[test]
fn agent_user_has_no_login_and_belongs_to_no_group_but_its_own() {
    let sysusers = read("systemd/linuxhello.sysusers");
    let lines: Vec<&str> = sysusers
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    let user = lines
        .iter()
        .find(|l| l.starts_with("u linuxhello "))
        .expect("a u line");
    assert!(user.ends_with("/usr/sbin/nologin"), "{user}");
    // No `m` line: the Agent is not in `tss` or any other group that owns a device (R-09, #351).
    assert!(
        !lines.iter().any(|l| l.starts_with("m linuxhello ")),
        "the Agent's user must be in no extra group: {lines:?}"
    );
}

/// The Agent reaches the TPM only through the provider's socket. It has no way to open the device
/// itself, in the unit, in the profile or through a group, so a compromised Agent, or the Howdy
/// child that inherits its profile, cannot send the chip a command of its own (R-09, #351).
#[test]
fn the_agent_cannot_open_the_tpm_device() {
    assert!(!read("systemd/linuxhello-agent.service").contains("tpmrm"));
    // The provider's user is in `tss`; the Agent's is not.
    assert!(!read("systemd/linuxhello.sysusers")
        .lines()
        .any(|l| l.starts_with("m linuxhello ") && l.contains("tss")));
    assert!(!profile_rules().iter().any(|r| r.contains("tpmrm")));
}

#[test]
fn agent_unit_passes_systemd_analyze_verify() {
    let unit = Path::new(SECURITY).join("systemd/linuxhello-agent.service");
    let Some((_, output)) = run_tool(
        "systemd-analyze",
        &["verify", "--man=no", unit.to_str().expect("a path")],
    ) else {
        return;
    };
    // The binary is not installed on the machine that runs the test; every other message about
    // this unit is a defect.
    let defects: Vec<&str> = output
        .lines()
        .filter(|l| l.contains("linuxhello-agent.service") && !l.contains("is not executable"))
        .collect();
    assert!(defects.is_empty(), "{defects:?}");
}

#[test]
fn agent_profile_grants_no_network_but_the_unix_socket() {
    let rules = profile_rules();
    assert!(rules.contains(&"network unix stream,".to_string()));
    assert!(rules.contains(&"deny network inet,".to_string()));
    assert!(rules.contains(&"deny network inet6,".to_string()));
    let allowed: Vec<&String> = rules.iter().filter(|r| r.starts_with("network")).collect();
    // The stream socket is the bus; the datagram socket is the watchdog's one message to the
    // service manager (`agent_profile_allows_the_notify_socket_and_no_other_datagram_path`).
    assert_eq!(
        allowed,
        ["network unix stream,", "network unix dgram,"],
        "no other network rule"
    );
}

/// Found by running the unit in the test VM: under systemd's mount namespace AppArmor sees the
/// path of the bus socket without its leading slash ("disconnected path"), so the rule for
/// `/run/dbus/system_bus_socket` never matches and the Agent cannot connect, unless the profile
/// attaches disconnected paths.
#[test]
fn agent_profile_attaches_disconnected_paths_so_the_bus_socket_rule_matches() {
    let header = profile_rules()
        .into_iter()
        .find(|r| r.starts_with("profile linuxhello-agent "))
        .expect("the profile line");
    assert!(header.contains("attach_disconnected"), "{header}");
    assert!(profile_rules().contains(&"/run/dbus/system_bus_socket rw,".to_string()));
}

#[test]
fn agent_profile_grants_no_capability_and_denies_tracing() {
    let rules = profile_rules();
    assert!(rules.contains(&"deny capability,".to_string()));
    assert!(rules.contains(&"deny ptrace,".to_string()));
    assert!(!rules.iter().any(|r| r.starts_with("capability")));
    assert!(rules.contains(&"deny @{PROC}/*/mem rw,".to_string()));
}

#[test]
fn agent_profile_grants_the_camera_and_no_other_device() {
    let rules = profile_rules();
    let devices: Vec<&String> = rules.iter().filter(|r| r.starts_with("/dev/")).collect();
    // The camera is for the face method (Howdy inherits this profile); the TPM is not here.
    assert_eq!(devices, ["/dev/video[0-9]* rw,"]);
}

/// The Agent starts the Python interpreter, for Howdy, and no other program; the child inherits the
/// profile, so everything the profile denies is denied to Howdy too.
#[test]
fn the_agent_may_start_python_for_howdy_and_no_other_program() {
    let rules = profile_rules();
    let executes: Vec<&String> = rules
        .iter()
        .filter(|r| {
            [" ix", " Cx", " Px", " Ux", " px", " cx", " ux"]
                .iter()
                .any(|m| r.contains(m))
        })
        .collect();
    assert_eq!(executes, ["/usr/bin/python3{,.[0-9]*} ix,"]);
    // Nothing that Howdy inherits lets it out: no network but the bus socket, no home directory.
    assert!(rules.contains(&"deny network inet,".to_string()));
    assert!(rules.iter().any(|r| r.starts_with("deny /home/**")));
    // The camera, and only the camera, among the devices: Howdy cannot reach the TPM.
    let devices: Vec<&String> = rules.iter().filter(|r| r.starts_with("/dev/")).collect();
    assert_eq!(devices, ["/dev/video[0-9]* rw,"]);
}

/// The statements of the AppArmor profile that begin with `prefix`, with their continuation
/// lines joined by one space. A statement ends at a comma outside braces: `member={A,B}` is one.
fn statements(prefix: &str) -> Vec<String> {
    // Not the line that opens the profile, nor the one that closes it.
    let body: Vec<String> = profile_rules()
        .into_iter()
        .filter(|r| !r.starts_with("profile ") && r != "}")
        .collect();
    let text = body.join(" ");
    let (mut found, mut current, mut depth) = (Vec::new(), String::new(), 0_u32);
    for c in text.chars() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                found.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    found.push(current);
    found
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with(prefix))
        .collect()
}

#[test]
fn agent_profile_receives_only_name_owner_changed_from_the_bus_and_the_scan_and_enrolment_steps_from_fprintd(
) {
    let received = statements("dbus receive");
    assert_eq!(received.len(), 2, "two receive rules: {received:?}");
    assert!(
        received
            .iter()
            .any(|r| r.contains("member=NameOwnerChanged")
                && r.contains("name=org.freedesktop.DBus")),
        "{received:?}"
    );
    assert!(
        // A signal carries the sender's unique name, so a peer given by its well-known name never
        // matches it (the real fprintd showed it: `make vm-test-fingerprint`); the peer is named by
        // its label, and the rule still names the one interface and the one member.
        received
            .iter()
            .any(|r| r.contains("member={VerifyStatus,EnrollStatus}")
                && r.contains("peer=(label=unconfined)")
                && r.contains("interface=net.reactivated.Fprint.Device")),
        "{received:?}"
    );
}

#[test]
fn agent_profile_talks_to_fprintd_and_polkit_and_to_no_other_service() {
    let sends = statements("dbus send");
    for rule in &sends {
        assert!(
            rule.contains("peer=(name=org.freedesktop.DBus)")
                || rule.contains("peer=(name=net.reactivated.Fprint)")
                || rule.contains("path=/io/github/LinuxHello/Agent1")
                || (rule.contains("peer=(name=org.freedesktop.PolicyKit1)")
                    && rule.contains("member=CheckAuthorization")),
            "a send rule with another peer: {rule}"
        );
    }
    assert!(sends
        .iter()
        .any(|r| r.contains("peer=(name=net.reactivated.Fprint)")
            && r.contains("interface=net.reactivated.Fprint.{Manager,Device}")));
    assert!(profile_rules().contains(&"/etc/passwd r,".to_string()));
}

/// The polkit rule that lets the Agent claim and scan a fingerprint reader for another user.
#[test]
fn the_polkit_rule_allows_the_agent_exactly_three_fingerprint_actions() {
    let rule = read("polkit/50-linuxhello-agent.rules");
    let code: String = rule
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(code.contains("subject.user == \"linuxhello\""));
    let actions: Vec<&str> = code
        .split('"')
        .filter(|s| s.starts_with("net.reactivated.fprint."))
        .collect();
    assert_eq!(
        actions,
        [
            "net.reactivated.fprint.device.verify",
            "net.reactivated.fprint.device.setusername",
            "net.reactivated.fprint.device.enroll"
        ],
        "verify, setusername and enroll, nothing more"
    );
    assert_eq!(code.matches("polkit.Result.YES").count(), 1);
    assert!(
        !code.contains("polkit.Result.AUTH"),
        "no other result is given"
    );
}

#[test]
fn agent_profile_parses() {
    let profile = Path::new(SECURITY).join("apparmor/linuxhello-agent");
    let Some((ok, output)) = run_tool(
        "apparmor_parser",
        &["-Q", "-K", profile.to_str().expect("a path")],
    ) else {
        return;
    };
    assert!(ok, "apparmor_parser refused the profile: {output}");
}

#[test]
fn agent_unit_is_dbus_activatable() {
    let s = settings_of("dbus/io.github.LinuxHello.Agent1.service", "D-BUS Service");
    assert_eq!(only(&s, "Name"), AGENT_BUS_NAME);
    assert_eq!(only(&s, "SystemdService"), "linuxhello-agent.service");
    assert_eq!(only(&s, "Exec"), "/bin/false");
    assert_eq!(only(&s, "User"), "root");
}

#[test]
fn activation_file_and_unit_name_the_same_bus_name() {
    let dbus_name = only(
        &settings_of("dbus/io.github.LinuxHello.Agent1.service", "D-BUS Service"),
        "Name",
    );
    let unit_bus_name = only(&service_settings(), "BusName");
    assert_eq!(dbus_name, unit_bus_name);
}

#[test]
fn agent_unit_orders_before_the_display_manager() {
    let s = settings_of("systemd/linuxhello-agent.service", "Unit");
    assert_eq!(only(&s, "Before"), "display-manager.service");
    assert_eq!(only(&s, "After"), "dbus.socket");
}

#[test]
fn agent_unit_restarts_after_a_pause_and_has_no_start_limit() {
    let s = service_settings();
    assert_eq!(only(&s, "Restart"), "on-failure");
    assert_eq!(only(&s, "RestartSec"), "1");

    let u = settings_of("systemd/linuxhello-agent.service", "Unit");
    assert_eq!(only(&u, "StartLimitIntervalSec"), "0");

    let s_keys: Vec<String> = s.keys().cloned().collect();
    assert!(
        !s_keys.contains(&"StartLimitIntervalSec".to_string()),
        "StartLimitIntervalSec should not be in [Service]"
    );
}

#[test]
fn agent_unit_has_a_watchdog_that_only_the_main_process_may_feed() {
    let s = service_settings();
    assert_eq!(only(&s, "WatchdogSec"), "30s");
    assert_eq!(only(&s, "NotifyAccess"), "main");
}

#[test]
fn agent_profile_allows_the_notify_socket_and_no_other_datagram_path() {
    let profile = read("apparmor/linuxhello-agent");
    let rules: Vec<&str> = profile
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();
    assert!(rules.contains(&"/run/systemd/notify w,"));
    assert!(rules.contains(&"network unix dgram,"));
    // Nothing else under /run is writable, and no other socket family is granted.
    let writes_to_run: Vec<&&str> = rules
        .iter()
        .filter(|l| l.starts_with("/run/") && l.ends_with(" w,"))
        .collect();
    assert_eq!(writes_to_run, [&"/run/systemd/notify w,"]);
    assert!(!rules.iter().any(|l| l.starts_with("network inet")));
}

#[test]
fn agent_unit_bounds_its_memory_tasks_and_open_files() {
    let s = service_settings();
    assert_eq!(only(&s, "MemoryMax"), "1G");
    assert_eq!(only(&s, "TasksMax"), "128");
    assert_eq!(only(&s, "LimitNOFILE"), "1024");
}

#[test]
fn agent_unit_shares_no_ipc_or_keyring_and_binds_no_internet_socket() {
    let s = service_settings();
    assert_eq!(only(&s, "PrivateIPC"), "yes");
    assert_eq!(only(&s, "KeyringMode"), "private");
    assert_eq!(only(&s, "SocketBindDeny"), "any");
    // Without the BPF security module, which Ubuntu does not enable, systemd refuses to start a
    // unit that restricts file systems; the Agent would never run.
    assert!(!s.contains_key("RestrictFileSystems"));
}

#[test]
fn agent_profile_denies_unix_sockets_in_the_abstract_namespace() {
    let rules = profile_rules();
    assert!(rules
        .iter()
        .any(|r| r == "deny unix (connect, send) peer=(addr=@**),"));
    assert!(rules.iter().any(|r| r == "deny unix (listen) addr=@**,"));
}

#[test]
fn agent_profile_lets_the_agent_read_its_own_label_and_nothing_else_of_proc() {
    let rules = profile_rules();
    assert!(rules
        .iter()
        .any(|r| r == "@{PROC}/@{pid}/attr/{,apparmor/}current r,"));
    // The rule names the label files only, not the process's other files.
    assert!(!rules
        .iter()
        .any(|r| r.starts_with("@{PROC}/@{pid}/") && r.contains("**")));
}

#[test]
fn the_reset_action_asks_for_the_persons_own_password_in_front_only() {
    let policy = read("polkit/io.github.LinuxHello.policy");
    assert!(policy.contains(r#"<action id="io.github.LinuxHello.reset">"#));
    assert!(policy.contains("<allow_any>no</allow_any>"));
    assert!(policy.contains("<allow_inactive>no</allow_inactive>"));
    assert!(policy.contains("<allow_active>auth_self</allow_active>"));
    assert!(policy.contains(
        r#"<annotate key="org.freedesktop.policykit.owner">unix-user:linuxhello</annotate>"#
    ));
    assert_eq!(policy.matches("<action ").count(), 1, "one action only");
}
