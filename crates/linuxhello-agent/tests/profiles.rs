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

/// The `[Service]` settings of the unit: every value of each key, in order.
fn service_settings() -> HashMap<String, Vec<String>> {
    let mut settings: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_service = false;
    for line in read("systemd/linuxhello-agent.service").lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_service = line == "[Service]";
        } else if in_service && !line.starts_with('#') {
            if let Some((key, value)) = line.split_once('=') {
                settings
                    .entry(key.to_string())
                    .or_default()
                    .push(value.to_string());
            }
        }
    }
    settings
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
fn agent_unit_allows_only_the_tpm_device() {
    let s = service_settings();
    assert_eq!(only(&s, "DevicePolicy"), "closed");
    assert_eq!(
        s.get("DeviceAllow").map(Vec::as_slice),
        Some(["/dev/tpmrm0 rw".to_string()].as_slice())
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

#[test]
fn agent_unit_claims_the_registered_bus_name() {
    let s = service_settings();
    assert_eq!(only(&s, "Type"), "dbus");
    assert_eq!(only(&s, "BusName"), AGENT_BUS_NAME);
}

#[test]
fn agent_user_has_no_login_and_belongs_to_the_tpm_group() {
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
    assert!(lines.contains(&"m linuxhello tss"));
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
    assert_eq!(allowed, ["network unix stream,"], "no other network rule");
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
fn agent_profile_grants_the_tpm_and_no_other_device() {
    let rules = profile_rules();
    let devices: Vec<&String> = rules.iter().filter(|r| r.starts_with("/dev/")).collect();
    assert_eq!(devices, ["/dev/tpmrm0 rw,"]);
}

#[test]
fn agent_profile_denies_home_directories_and_names_the_registered_bus_name() {
    let rules = profile_rules();
    assert!(rules.iter().any(|r| r.starts_with("deny /home/**")));
    assert!(rules.iter().any(|r| r.starts_with("deny /root/**")));
    let name = format!("name={AGENT_BUS_NAME}");
    assert!(rules
        .iter()
        .any(|r| r.starts_with("dbus bind") && r.contains(&name)));
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
