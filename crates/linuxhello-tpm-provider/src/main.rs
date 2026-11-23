//! linuxhello-tpm-provider: the daemon that does the TPM commands for the Agent.
//!
//! It opens the TPM (`/dev/tpmrm0`, the kernel's resource manager), listens on
//! `/run/linuxhello-tpm/tpm.sock` and serves one request per connection, only from the user the Agent
//! runs as (`linuxhello`, looked up in `/etc/passwd`). It keeps no key and no state of its own; see
//! the library for what it does and refuses. A TPM that is missing or a socket that cannot be bound is
//! an error and the daemon exits, so its unit restarts it and the Agent sees a provider that does not
//! answer, which is never a wrong PIN. It also exits when the TPM has failed several requests in a
//! row (a lost primary handle, which nothing inside the process repairs), and, like the Agent, it
//! refuses to start unless its AppArmor profile enforces it and marks itself not dumpable
//! (P-24, review finding R-29, #371).
//!
//! C4 container: `tpmProvider` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

use linuxhello_tpm_provider::keys::Tpm;
use linuxhello_tpm_provider::server::watchdog::{self, Notifier};
use linuxhello_tpm_provider::server::{ids_of, Server};

/// The socket the Agent connects to, in the runtime directory the unit creates.
const SOCKET: &str = "/run/linuxhello-tpm/tpm.sock";

/// The account the Agent runs as: the only user the provider serves.
const AGENT_USER: &str = "linuxhello";

/// The TPM: the kernel's resource manager, which shares the chip safely between processes.
const TPM: &str = "device:/dev/tpmrm0";

/// The AppArmor profile the provider must run under.
const PROFILE: &str = "linuxhello-tpm-provider";

/// Where the kernel gives a process its AppArmor label: the AppArmor file first, which is right
/// when several security modules are stacked, then the older shared one.
const LABEL_FILES: [&str; 2] = [
    "/proc/self/attr/apparmor/current",
    "/proc/self/attr/current",
];

/// Whether `label`, the text of a label file, says the provider's profile enforces this process:
/// `linuxhello-tpm-provider (enforce)`, or a stack of it with `unconfined`, as Ubuntu 26.04 starts
/// the unit. A complain-mode or mixed label, another profile, a child profile and `unconfined`
/// alone do not count (`only_the_providers_profile_in_enforce_mode_counts`, P-24).
fn enforced(label: &str) -> bool {
    let Some(stack) = label
        .trim_end_matches(['\n', '\0'])
        .strip_suffix(" (enforce)")
    else {
        return false;
    };
    let parts: Vec<&str> = stack.split("//&").collect();
    parts.contains(&PROFILE) && parts.iter().all(|p| *p == PROFILE || *p == "unconfined")
}

/// The process's own AppArmor label, from the first label file that can be read and is not empty;
/// `None` when there is none, which counts as not confined.
fn own_label() -> Option<String> {
    LABEL_FILES.iter().find_map(|path| {
        std::fs::read_to_string(path)
            .ok()
            .filter(|label| !label.trim().is_empty())
    })
}

/// Before anything holds a secret: makes the process not dumpable, so that neither a core file nor
/// another process of the provider's user can read its memory, and refuses to run unless the
/// provider's AppArmor profile enforces it. The unit checks the profile too, before the start; this
/// check also covers a start outside the unit (AGENTS.md invariant 3).
///
/// # Errors
///
/// The reason the provider must not run, for its standard error.
fn guard() -> Result<(), String> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| format!("cannot mark the process not dumpable: {e}"))?;
    match own_label() {
        Some(label) if enforced(&label) => Ok(()),
        label => Err(format!(
            "refusing to start: the AppArmor profile {PROFILE} does not enforce this process (its label is {:?})",
            label.as_deref().map_or("unknown", |l| l.trim_end_matches(['\n', '\0']))
        )),
    }
}

/// Under a unit with `WatchdogSec=`, starts the thread that tells systemd the provider is alive, and
/// only while it is not stuck in one request (R-29, #371). Without a watchdog it starts nothing.
fn start_watchdog(server: &Server) {
    let (Some(notifier), Some(interval)) = (Notifier::from_env(), watchdog::interval()) else {
        return;
    };
    let busy = server.busy();
    std::thread::spawn(move || loop {
        if watchdog::should_ping(&busy) {
            if let Err(error) = notifier.send(watchdog::WATCHDOG) {
                eprintln!("linuxhello-tpm-provider: the watchdog ping failed: {error}");
            }
        }
        std::thread::sleep(interval);
    });
}

/// Starts the server and returns only when starting fails or the TPM has failed for good.
fn run() -> Result<(), String> {
    let passwd = std::fs::read_to_string("/etc/passwd").map_err(|e| format!("/etc/passwd: {e}"))?;
    let (agent_uid, agent_gid) =
        ids_of(AGENT_USER, &passwd).ok_or_else(|| format!("no account named {AGENT_USER}"))?;
    let own = rustix::process::getuid().as_raw();
    let tpm = Tpm::open(TPM).map_err(|e| format!("the TPM is not available: {e:?}"))?;
    let server = Server::bind(Path::new(SOCKET), own, agent_uid, agent_gid, tpm)
        .map_err(|e| format!("the socket cannot be bound: {e}"))?;
    start_watchdog(&server);
    // Returns only when the TPM has failed request after request: the unit starts a new process.
    Err(server.serve_forever())
}

fn main() -> ExitCode {
    if let Err(reason) = guard().and_then(|()| run()) {
        eprintln!("linuxhello-tpm-provider: {reason}");
    }
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::enforced;

    #[test]
    fn only_the_providers_profile_in_enforce_mode_counts() {
        assert!(enforced("linuxhello-tpm-provider (enforce)\n"));
        assert!(enforced("linuxhello-tpm-provider//&unconfined (enforce)\n"));
        for label in [
            "",
            "unconfined",
            "linuxhello-tpm-provider (complain)\n",
            "linuxhello-agent (enforce)\n",
            "linuxhello-tpm-provider//child (enforce)\n",
            "linuxhello-tpm-provider//&other (enforce)\n",
            "linuxhello-tpm-provider//&unconfined (mixed)\n",
            "linuxhello-tpm-provider (enforce) extra",
        ] {
            assert!(!enforced(label), "{label:?}");
        }
    }
}
