//! The administrator's offline commands `status` and `doctor`: what is wrong with the policy files,
//! in the words the user and the administrator read.
//!
//! C4 component: `cliCommands` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))
//!
//! Both commands read the policy files on disk through the Agent's own loader and need no running
//! Agent. They probe nothing else (no TPM, no service, no bus) and never write
//! (`status_and_doctor_never_write`). ADR-0018 says that only the Agent reads and writes a user's
//! layer; like `policy show` and `policy reset`, these commands are the administrator's offline
//! exception to that sentence.
//!
//! Every condition has one code from a closed set, a severity and one fixed sentence
//! (`status_prints_one_line_per_condition_with_code_severity_and_sentence`). `status` never prints a
//! file name or a path (`status_never_prints_a_file_name`); `doctor` names the file in `detail`.
//! A fact that cannot be read is a condition of its own, never a clean result
//! (`doctor_reports_an_unreadable_state_directory_as_a_condition_not_a_clean_run`).
//!
//! `status` probes only the policy files. `doctor` probes the policy files and four machine facts:
//! the Agent unit, the AppArmor profile, the fingerprint service, and Howdy.

use std::io::{ErrorKind, Write};
use std::path::Path;

use crate::probe::Host;
use linuxhello_agent::policy::{load, Policy, UserPolicyStore};

/// The usage line printed on every usage error.
const USAGE: &str = "usage: linuxhello-ctl status --user <name|uid> | doctor";

/// A path that cannot exist, so that loading "the admin layers alone" finds no user layer.
const NO_USER_LAYER: &str = "/nonexistent/linuxhello/policy.toml";

/// The list of loaded AppArmor profiles and their modes.
const APPARMOR_PROFILES: &str = "/sys/kernel/security/apparmor/profiles";

/// Howdy's configuration file: present when Howdy is installed.
const HOWDY_CONFIG: &str = "/etc/howdy/config.ini";

/// The call that asks the fingerprint service for its default device; it fails when there is none.
const FPRINT_PROBE: [&str; 7] = [
    "--system",
    "--timeout=5",
    "call",
    "net.reactivated.Fprint",
    "/net/reactivated/Fprint/Manager",
    "net.reactivated.Fprint.Manager",
    "GetDefaultDevice",
];

/// How serious a condition is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A method or a context is lost, or a fact could not be established.
    Severe,
}

impl Severity {
    /// The word printed for the severity.
    fn word(self) -> &'static str {
        match self {
            Severity::Severe => "severe",
        }
    }
}

/// One thing that is wrong, as the user or the administrator reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    /// The stable code, one of the closed set.
    pub code: String,
    /// How serious the condition is.
    pub severity: Severity,
    /// The fixed user-level sentence for the code.
    pub sentence: String,
    /// What only an administrator sees: the loader's reason, which names the file.
    pub detail: Option<String>,
    /// The fixed fix sentence `doctor` prints.
    pub fix: &'static str,
}

/// The condition for a policy that failed to load.
fn pin_only(reason: &str) -> Condition {
    Condition {
        code: "policy-pin-only".to_string(),
        severity: Severity::Severe,
        sentence: "Biometric sign-in is off because a policy file failed to load.".to_string(),
        detail: Some(reason.to_string()),
        fix: "Fix or remove the file named above, then run doctor again.",
    }
}

/// The condition for a context that no method set can satisfy.
fn unsatisfiable(context: &str) -> Condition {
    Condition {
        code: format!("context-unsatisfiable: {context}"),
        severity: Severity::Severe,
        sentence: format!("{context} cannot be unlocked with the configured methods."),
        detail: None,
        fix: "Add a method to the context or lower its factors in the policy file.",
    }
}

/// The condition for the state directory when it cannot be listed.
fn state_directory_unreadable() -> Condition {
    Condition {
        code: "status-fact-unreadable: the state directory".to_string(),
        severity: Severity::Severe,
        sentence: "Could not read the state directory; see linuxhello-ctl doctor.".to_string(),
        detail: None,
        fix: "Run as root and check that the state directory exists.",
    }
}

/// A fact about the machine that `doctor` could not establish: a condition of its own, never a
/// clean result.
fn fact_unreadable(what: &str, fix: &'static str) -> Condition {
    Condition {
        code: format!("status-fact-unreadable: {what}"),
        severity: Severity::Severe,
        sentence: format!("Could not check {what}; see linuxhello-ctl doctor."),
        detail: None,
        fix,
    }
}

/// The four facts about the machine that `doctor` probes through `host`: the Agent unit, the
/// AppArmor profile, the fingerprint service and Howdy. A probe only reads, and the only commands
/// and files it uses are the ones named here (`doctor_probes_only_the_named_commands_and_files`).
fn machine_conditions(host: &dyn Host) -> Vec<Condition> {
    let mut found = Vec::new();

    match host.run("systemctl", &["is-active", "linuxhello-agent.service"]) {
        None => found.push(fact_unreadable(
            "the agent unit",
            "Run as root and check that systemctl works.",
        )),
        Some((0, stdout)) if stdout == "active" => {}
        Some(_) => found.push(Condition {
            code: "agent-unit-inactive".to_string(),
            severity: Severity::Severe,
            sentence: "The Linux Hello Agent is not running.".to_string(),
            detail: None,
            fix: "Run `systemctl status linuxhello-agent` and read why it stopped.",
        }),
    }

    match host.read(Path::new(APPARMOR_PROFILES)) {
        None => found.push(fact_unreadable(
            "the AppArmor profile list",
            "Run as root on a system with AppArmor enabled.",
        )),
        Some(list) => {
            let line = list.lines().find(|l| l.starts_with("linuxhello-agent ("));
            let detail = match line {
                Some(l) if l.ends_with("(enforce)") => None,
                Some(_) => Some("in complain mode"),
                None => Some("not loaded"),
            };
            if let Some(detail) = detail {
                found.push(Condition {
                    code: "agent-profile-not-enforcing".to_string(),
                    severity: Severity::Severe,
                    sentence: "The Agent's AppArmor profile is not in enforce mode, so the Agent will not start.".to_string(),
                    detail: Some(detail.to_string()),
                    fix: "Load the profile and set it to enforce mode (`aa-enforce`), then start the unit.",
                });
            }
        }
    }

    match host.run("busctl", &FPRINT_PROBE) {
        None => found.push(fact_unreadable(
            "the fingerprint service",
            "Install busctl (part of systemd) and run doctor as root.",
        )),
        Some((0, _)) => {}
        Some(_) => found.push(Condition {
            code: "method-unavailable: fingerprint".to_string(),
            severity: Severity::Severe,
            sentence: "Fingerprint sign-in is unavailable because the fingerprint service reports no device.".to_string(),
            detail: None,
            fix: "Install `fprintd` and check that the reader is listed by `fprintd-list`.",
        }),
    }

    if host.read(Path::new(HOWDY_CONFIG)).is_none() {
        found.push(Condition {
            code: "method-unavailable: face".to_string(),
            severity: Severity::Severe,
            sentence: "Face sign-in is unavailable because Howdy is not installed.".to_string(),
            detail: None,
            fix: "Install Howdy and enrol a face, or remove the face method from the policy.",
        });
    }

    found
}

/// The conditions of a loaded policy, in the fixed order: the PIN-only state first, then the
/// unsatisfiable contexts by name.
fn conditions_of(policy: &Policy) -> Vec<Condition> {
    let (layer, reason) = match policy {
        Policy::Effective(effective) => (&effective.layer, None),
        Policy::PinOnly(pin) => (&pin.layer, Some(pin.reason.as_str())),
    };
    let mut conditions: Vec<Condition> = reason.map(pin_only).into_iter().collect();
    let mut contexts: Vec<&String> = layer.context.keys().collect();
    contexts.sort();
    conditions.extend(
        contexts
            .into_iter()
            .filter(|context| policy.methods_for(context).unsatisfiable)
            .map(|context| unsatisfiable(context)),
    );
    conditions
}

/// Runs `status` or `doctor` on the policy files under `admin_dir` (owned by `admin_owner_uid`) and
/// the state directory `user_root`, resolving user names in `passwd` (the text of `/etc/passwd`).
///
/// Everything printed goes through `out` and `err`. The result is the exit code: 0 done, 1 `doctor`
/// found a failure, 2 usage error. `status` exits 0 also when it prints conditions: it informs, it
/// does not judge.
#[allow(clippy::too_many_arguments)]
pub fn run(
    args: &[String],
    host: &dyn Host,
    admin_dir: &Path,
    admin_owner_uid: u32,
    user_root: &Path,
    passwd: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["status", "--user", user] => {
            let Some(uid) = crate::policy::resolve_user(user, passwd) else {
                return usage(err, "not a number or a local account name");
            };
            let path = UserPolicyStore::new(user_root).path(uid);
            let conditions = conditions_of(&load(admin_dir, &path, admin_owner_uid));
            if conditions.is_empty() {
                let _ = writeln!(out, "no conditions");
            }
            for condition in &conditions {
                let _ = writeln!(out, "{}", line(condition));
            }
            0
        }
        ["doctor"] => doctor(host, admin_dir, admin_owner_uid, user_root, out),
        _ => usage(err, "expected: status --user <name|uid> or doctor"),
    }
}

/// The one line `status` prints for `condition`: code, severity, sentence.
fn line(condition: &Condition) -> String {
    format!(
        "{}  {}  {}",
        condition.code,
        condition.severity.word(),
        condition.sentence
    )
}

/// `doctor`: the admin layers, then every stored user layer in ascending uid order. A user layer
/// that fails only because the admin layers failed (the same code and detail) is not reported again.
/// It also probes four machine facts.
fn doctor(
    host: &dyn Host,
    admin_dir: &Path,
    admin_owner_uid: u32,
    user_root: &Path,
    out: &mut dyn Write,
) -> u8 {
    let admin = conditions_of(&load(admin_dir, Path::new(NO_USER_LAYER), admin_owner_uid));
    let mut reported: Vec<(String, Vec<Condition>)> = vec![("admin".to_string(), admin.clone())];
    match stored_uids(user_root) {
        Ok(uids) => {
            let store = UserPolicyStore::new(user_root);
            for uid in uids {
                let policy = load(admin_dir, &store.path(uid), admin_owner_uid);
                let own: Vec<Condition> = conditions_of(&policy)
                    .into_iter()
                    .filter(|c| {
                        !admin
                            .iter()
                            .any(|a| a.code == c.code && a.detail == c.detail)
                    })
                    .collect();
                reported.push((format!("uid {uid}"), own));
            }
        }
        Err(()) => reported.push(("state".to_string(), vec![state_directory_unreadable()])),
    }

    let machine_conditions = machine_conditions(host);
    let mut failures = 0_u32;
    for (scope, conditions) in &reported {
        for condition in conditions {
            failures += 1;
            let _ = writeln!(out, "[{scope}] {}", line(condition));
            if let Some(detail) = &condition.detail {
                let _ = writeln!(out, "  detail: {detail}");
            }
            let _ = writeln!(out, "  fix: {}", condition.fix);
        }
    }

    for condition in &machine_conditions {
        failures += 1;
        let _ = writeln!(out, "[machine] {}", line(condition));
        if let Some(detail) = &condition.detail {
            let _ = writeln!(out, "  detail: {detail}");
        }
        let _ = writeln!(out, "  fix: {}", condition.fix);
    }

    if failures == 0 {
        let _ = writeln!(out, "ok");
        0
    } else {
        1
    }
}

/// The uids that have a stored layer under `root`, ascending. A directory that does not exist has
/// none; one that cannot be listed is `Err`. An entry whose name is not a decimal `u32` is skipped.
fn stored_uids(root: &Path) -> Result<Vec<u32>, ()> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(()),
    };
    let store = UserPolicyStore::new(root);
    let mut uids: Vec<u32> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|uid| std::fs::symlink_metadata(store.path(*uid)).is_ok())
        .collect();
    uids.sort_unstable();
    Ok(uids)
}

/// Prints `why` and the usage line to `err` and returns the usage exit code, 2.
fn usage(err: &mut dyn Write, why: &str) -> u8 {
    let _ = writeln!(err, "{why}\n{USAGE}");
    2
}

#[cfg(test)]
mod tests;
