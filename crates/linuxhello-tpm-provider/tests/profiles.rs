//! The confinement files of the TPM provider in `security/`: its systemd unit, its AppArmor profile
//! and its user. The tests read the files and check what they grant and refuse; the last of each also
//! runs the real parser (`systemd-analyze verify`, `apparmor_parser -Q`) when it is installed.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// The directory `security/` of the repository.
const SECURITY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../security");

/// The text of a file under `security/`.
fn read(relative: &str) -> String {
    std::fs::read_to_string(Path::new(SECURITY).join(relative))
        .unwrap_or_else(|e| panic!("{relative}: {e}"))
}

/// The `[Service]` settings of the unit: every value of each key.
fn service() -> HashMap<String, Vec<String>> {
    let mut settings: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_section = false;
    for line in read("systemd/linuxhello-tpm-provider.service").lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line == "[Service]";
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

/// The one value of a setting; fails if it is missing or set more than once.
fn only(settings: &HashMap<String, Vec<String>>, key: &str) -> String {
    match settings.get(key).map(Vec::as_slice) {
        Some([value]) => value.clone(),
        other => panic!("{key} must be set exactly once, found {other:?}"),
    }
}

/// The non-comment lines of the AppArmor profile, trimmed.
fn rules() -> Vec<String> {
    read("apparmor/linuxhello-tpm-provider")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

#[test]
fn the_provider_runs_as_its_own_user_with_no_privileges() {
    let unit = service();
    assert_eq!(only(&unit, "User"), "linuxhello-tpm");
    assert_eq!(only(&unit, "NoNewPrivileges"), "yes");
    assert_eq!(only(&unit, "CapabilityBoundingSet"), "");
    assert_eq!(only(&unit, "AmbientCapabilities"), "");
    assert_eq!(only(&unit, "PrivateNetwork"), "yes");
    assert_eq!(only(&unit, "RestrictAddressFamilies"), "AF_UNIX");
    assert_eq!(only(&unit, "ProtectSystem"), "strict");
    assert_eq!(only(&unit, "ProtectHome"), "yes");
    assert_eq!(only(&unit, "MemoryDenyWriteExecute"), "yes");
    assert_eq!(only(&unit, "LimitCORE"), "0");
    // It is in the Agent's group, to give the socket to it, and in no other.
    assert_eq!(only(&unit, "SupplementaryGroups"), "linuxhello");
    // The Agent's user is not the provider's: a compromise of one is not the other.
    assert_ne!(only(&unit, "User"), "linuxhello");
}

#[test]
fn the_only_privileged_call_the_provider_gets_is_giving_its_socket_away() {
    let filters = service().get("SystemCallFilter").cloned().unwrap();
    assert_eq!(
        filters,
        [
            "@system-service",
            "~@privileged @resources",
            "fchownat chown fchown"
        ]
    );
}

#[test]
fn the_provider_may_open_the_tpm_and_no_other_device() {
    let unit = service();
    assert_eq!(only(&unit, "DevicePolicy"), "closed");
    assert_eq!(
        unit.get("DeviceAllow").unwrap(),
        &["/dev/tpmrm0 rw".to_string()]
    );
}

#[test]
fn the_provider_refuses_to_start_unless_apparmor_enforces_its_profile() {
    let pre = only(&service(), "ExecStartPre");
    assert!(pre.starts_with('+'), "runs as root: {pre}");
    assert!(pre.contains("linuxhello-tpm-provider (enforce)"), "{pre}");
    assert!(
        pre.contains("/sys/kernel/security/apparmor/profiles"),
        "{pre}"
    );
    assert_eq!(
        only(&service(), "AppArmorProfile"),
        "linuxhello-tpm-provider"
    );
}

/// A permanent fault (a profile that is not enforced, a TPM with an owner password) must not restart
/// a service every second for ever (review finding R-29, #371).
#[test]
fn the_unit_backs_off_instead_of_restarting_every_second() {
    let s = service();
    assert_eq!(only(&s, "Restart"), "on-failure");
    assert_eq!(only(&s, "RestartSec"), "1");
    assert_eq!(only(&s, "RestartSteps"), "5");
    assert_eq!(only(&s, "RestartMaxDelaySec"), "60");
}

#[test]
fn the_provider_unit_limits_its_memory_tasks_and_files() {
    let s = service();
    assert_eq!(only(&s, "MemoryMax"), "128M");
    assert_eq!(only(&s, "TasksMax"), "16");
    assert_eq!(only(&s, "LimitNOFILE"), "256");
}

#[test]
fn the_provider_has_a_runtime_directory_that_only_it_can_change() {
    let unit = service();
    assert_eq!(only(&unit, "RuntimeDirectory"), "linuxhello-tpm");
    assert_eq!(only(&unit, "RuntimeDirectoryMode"), "0755");
}

#[test]
fn the_profile_grants_the_tpm_its_socket_and_no_network_but_unix() {
    let rules = rules();
    let devices: Vec<&String> = rules.iter().filter(|r| r.starts_with("/dev/")).collect();
    assert_eq!(devices, ["/dev/tpmrm0 rw,"]);
    let network: Vec<&String> = rules.iter().filter(|r| r.starts_with("network")).collect();
    assert_eq!(network, ["network unix stream,"]);
    assert!(rules.contains(&"deny network inet,".to_string()));
    assert!(rules.contains(&"deny network inet6,".to_string()));
    assert!(rules.contains(&"/run/linuxhello-tpm/tpm.sock rw,".to_string()));
}

#[test]
fn the_profile_has_no_bus_no_capability_no_tracing_and_no_state_of_the_agent() {
    let rules = rules();
    assert!(!rules.iter().any(|r| r.starts_with("dbus")), "no bus");
    assert!(rules.contains(&"deny capability,".to_string()));
    assert!(!rules.iter().any(|r| r.starts_with("capability")));
    assert!(rules.contains(&"deny ptrace,".to_string()));
    assert!(rules.iter().any(|r| r.starts_with("deny /home/**")));
    assert!(rules
        .iter()
        .any(|r| r.starts_with("deny /var/lib/linuxhello/**")));
    // It executes nothing: no execute permission in any rule.
    assert!(!rules
        .iter()
        .any(|r| [" ix", " Px", " Cx", " Ux", " px", " cx", " ux"]
            .iter()
            .any(|m| r.contains(m))));
}

#[test]
fn the_sysusers_entry_makes_a_user_with_no_login_and_the_tss_group() {
    let text = read("systemd/linuxhello.sysusers");
    let line = text
        .lines()
        .find(|l| l.starts_with("u linuxhello-tpm "))
        .expect("the provider's user");
    assert!(line.contains("/usr/sbin/nologin"), "{line}");
    assert!(text.lines().any(|l| l.trim() == "m linuxhello-tpm tss"));
}

/// Runs a tool, or says it is not installed and returns none.
fn run_tool(tool: &str, arguments: &[&str]) -> Option<(bool, String)> {
    let output = Command::new(tool).args(arguments).output().ok()?;
    let text = String::from_utf8_lossy(&[output.stdout, output.stderr].concat()).to_string();
    Some((output.status.success(), text))
}

#[test]
fn the_unit_and_the_profile_pass_the_real_parsers() {
    let unit = Path::new(SECURITY).join("systemd/linuxhello-tpm-provider.service");
    match run_tool(
        "systemd-analyze",
        &["verify", "--man=no", unit.to_str().unwrap()],
    ) {
        Some((ok, text)) => {
            // Only what is said about this unit counts (the host's own units may complain), and
            // the binary is not installed where the unit says: that is the one allowed complaint.
            let others: Vec<&str> = text
                .lines()
                .filter(|l| {
                    l.contains("linuxhello-tpm-provider.service")
                        && !l.contains("is not executable")
                })
                .collect();
            assert!(others.is_empty(), "systemd-analyze: {others:?}");
            let _ = ok;
        }
        None => eprintln!("SKIPPED: systemd-analyze is not installed"),
    }
    let profile = Path::new(SECURITY).join("apparmor/linuxhello-tpm-provider");
    match run_tool("apparmor_parser", &["-Q", "-K", profile.to_str().unwrap()]) {
        Some((ok, text)) => assert!(ok, "apparmor_parser: {text}"),
        None => eprintln!("SKIPPED: apparmor_parser is not installed"),
    }
}
