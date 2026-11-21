//! linuxhello-agent: serves the Agent's state API on the system bus until it is stopped.
//!
//! It claims `io.github.LinuxHello.Agent1` and exports the object of ADR-0012 and ADR-0014. The
//! bus policy decides who may own the name, so a start by any user but the Agent's own fails.
//! It reads no configuration yet: the prompt hosts that may read any prompt are none, and the
//! TPM and the policy engine are not wired in. Users can store and read their own policy layer
//! (`GetUserPolicy`, `SetUserPolicy`). It binds the PIN socket of ADR-0021, and `ExpectPin` announces a PIN to it. `Api::policy_of` loads the admin layers and the user's layer
//! and audits a fall back to PIN-only; no method of the API answers from it yet.
//!
//! C4 container: `agent` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use linuxhello_agent::audit::Audit;
use linuxhello_agent::bus::{bus_alive, serve_with_extras, Extras, Fingerprints, PinChange};
use linuxhello_agent::methods::fingerprint::{FingerprintMethod, Fprintd};
use linuxhello_agent::methods::pin::tpm::TpmVerifier;
use linuxhello_agent::methods::pin::{PinInbox, PinMethod, PinVerifier};
use linuxhello_agent::methods::{face::FaceMethod, username_of};
use linuxhello_agent::notify::{watchdog_interval, Notifier};
use linuxhello_agent::orchestrator::Method;
use linuxhello_agent::pinlock::service::{wall_clock_seconds, Limits, PinLockService};
use linuxhello_agent::pinlock::store::PinLockFile;
use linuxhello_agent::pinrecord::PinRecordStore;
use linuxhello_agent::pinsocket::PinSocket;
use linuxhello_agent::policy::load;
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;
use linuxhello_tpm_provider::client::TpmClient;
use zbus::connection::Builder;

/// The root directory where user policy subdirectories are located.
const USER_POLICY_ROOT: &str = "/var/lib/linuxhello/users";

/// The directory of the admin policy layer, owned by root.
const ADMIN_POLICY_DIR: &str = "/etc/linuxhello/policy.d";

/// The PIN socket (ADR-0021), in the runtime directory the unit creates for the Agent's user.
const PIN_SOCKET: &str = "/run/linuxhello/pin.sock";

/// The methods an authentication of the user `subject` runs: face and fingerprint when the
/// account has a name in `/etc/passwd` (a method that is not installed reports itself unavailable
/// and is not offered), and the PIN. The PIN method is offered only when a verifier can check a PIN,
/// and none can yet: no user has a PIN record and the provider is not started by anything.
fn methods_of(
    subject: u32,
    inbox: &Arc<PinInbox>,
    lock: &Arc<PinLockService>,
    verifier: &Arc<dyn PinVerifier>,
) -> Vec<Box<dyn Method>> {
    let mut methods: Vec<Box<dyn Method>> = vec![Box::new(PinMethod::new(
        subject,
        Arc::clone(inbox),
        Arc::clone(lock),
        Arc::clone(verifier),
        wall_clock_seconds,
    ))];
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    if let Some(name) = username_of(subject, &passwd) {
        methods.push(Box::new(FaceMethod::new(&name)));
        methods.push(Box::new(FingerprintMethod::new(name)));
    }
    methods
}

/// The account name of `uid` for the finger calls of the settings page, read from `/etc/passwd`
/// at each call so that an account added since the Agent started is found. It is the same small
/// read of a local file that [`methods_of`] makes for every authentication; it runs on the bus
/// thread and does not wait on anything else.
fn account_name(uid: u32) -> Option<String> {
    username_of(
        uid,
        &std::fs::read_to_string("/etc/passwd").unwrap_or_default(),
    )
}

/// The socket of the TPM provider (ADR-0021): the Agent reaches the TPM through it and links no TPM
/// library. Nothing serves it yet, so a PIN cannot be checked until the provider runs; and until a
/// user has a record the PIN method is not offered to them at all.
const TPM_SOCKET: &str = "/run/linuxhello-tpm/tpm.sock";

/// The file that keeps the PIN lockout records across a restart, in the state directory.
const PIN_LOCK_FILE: &str = "/var/lib/linuxhello/pinlock.toml";

/// A path that cannot exist, so that loading "the admin layers alone" finds no user layer.
const NO_USER_LAYER: &str = "/nonexistent/linuxhello/policy.toml";

/// The Agent's PIN lock: the limits of the admin layers and the defaults (one set for the whole
/// machine; a stricter limit in a user's own layer is not honoured yet), and the records of the
/// lockout file. The policy is read once, here: a change applies at the next start.
fn pin_lock() -> PinLockService {
    let owner = rustix::process::getuid().as_raw();
    let policy = load(Path::new(ADMIN_POLICY_DIR), Path::new(NO_USER_LAYER), 0);
    // The TPM locks every key after its own number of wrong tries; the Agent keeps its limit below
    // it. Asked once, here: a provider that is not running yet leaves the policy's limit as it is.
    let tpm_tries = TpmClient::new(TPM_SOCKET)
        .limits()
        .ok()
        .map(|limits| limits.max_tries);
    PinLockService::start_capped(
        PinLockFile::new(PIN_LOCK_FILE, owner),
        Limits::from_policy(&policy),
        tpm_tries,
    )
}

/// Binds the PIN socket and serves it on a thread, and returns it so that `ExpectPin` can announce
/// PINs to it. A PIN is not used anywhere yet, so a socket that cannot be bound is reported on
/// standard error and the Agent goes on serving the bus (`ExpectPin` is then `Unavailable`); the
/// slice that wires the PIN verifier decides whether that stays so.
fn serve_pin_socket(inbox: Arc<PinInbox>) -> Option<Arc<PinSocket>> {
    let owner = rustix::process::getuid().as_raw();
    match PinSocket::bind(Path::new(PIN_SOCKET), owner) {
        Ok(socket) => {
            let socket = Arc::new(socket);
            // An accepted PIN goes to the PIN method that waits for its user; if none does, it is
            // wiped here.
            PinSocket::serve_forever(Arc::clone(&socket), move |submission| {
                inbox.deliver(submission.subject, submission.pin);
            });
            Some(socket)
        }
        Err(error) => {
            eprintln!("linuxhello-agent: the PIN socket is not available: {error}");
            None
        }
    }
}

/// Connects to the system bus, claims the Agent's name and serves until the process is stopped.
///
/// # Errors
///
/// Any error of connecting to the bus or claiming the name, such as the bus policy refusing it.
async fn run() -> zbus::Result<()> {
    let inbox = Arc::new(PinInbox::default());
    let lock = Arc::new(pin_lock());
    let tpm = Arc::new(TpmVerifier::new(
        PinRecordStore::new(USER_POLICY_ROOT, rustix::process::getuid().as_raw()),
        TPM_SOCKET,
    ));
    let verifier: Arc<dyn PinVerifier> = tpm.clone();
    let verifier_for_fingers = Arc::clone(&verifier);
    let pin_socket = serve_pin_socket(Arc::clone(&inbox));
    let store = UserPolicyStore::new(USER_POLICY_ROOT).with_admin_layer(ADMIN_POLICY_DIR, 0);
    let extras = Extras {
        audit: Some(Audit::journal()),
        pin_socket,
        pin_lock: Some(Arc::clone(&lock)),
        key_probe: Some(tpm.clone()),
        pin_change: Some(PinChange {
            inbox: Arc::clone(&inbox),
            enrolment: tpm,
        }),
        methods: Some(Arc::new(move |subject| {
            methods_of(subject, &inbox, &lock, &verifier)
        })),
        auth_deadline: None,
        // The finger calls of the settings page.
        fingerprints: Some(Fingerprints {
            fprintd: Fprintd::default(),
            username_of: Arc::new(account_name),
            verifier: verifier_for_fingers,
        }),
    };
    let connection = serve_with_extras(
        Builder::system(),
        Config::new(Vec::new()),
        Some(store),
        extras,
    )
    .await?;
    // Under a watchdog (WatchdogSec= in the unit) the Agent tells the service manager it is alive,
    // but only after its own bus loop has answered; without one it just serves.
    match (Notifier::from_env(), watchdog_interval()) {
        (Some(notifier), Some(interval)) => loop {
            if bus_alive(&connection, interval).await {
                if let Err(error) = notifier.watchdog() {
                    eprintln!("linuxhello-agent: the watchdog ping failed: {error}");
                }
            } else {
                eprintln!("linuxhello-agent: the bus loop did not answer; no watchdog ping");
            }
            async_io::Timer::after(interval).await;
        },
        _ => std::future::pending::<()>().await,
    }
    Ok(())
}

/// The AppArmor profile the Agent must run under.
const PROFILE: &str = "linuxhello-agent";

/// Where the kernel gives a process its AppArmor label: the AppArmor file first, which is right
/// when several security modules are stacked, then the older shared one.
const LABEL_FILES: [&str; 2] = [
    "/proc/self/attr/apparmor/current",
    "/proc/self/attr/current",
];

/// Whether `label`, the text of a label file, says the Agent's profile enforces this process:
/// `linuxhello-agent (enforce)`, or a stack of it with `unconfined`, as Ubuntu 26.04 starts the
/// unit (`linuxhello-agent//&unconfined (enforce)`), which enforces exactly the Agent's profile.
/// A complain-mode or mixed label, another profile, a child profile and `unconfined` alone do not
/// count (`only_the_agents_profile_in_enforce_mode_counts`, P-24).
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
/// another process of the Agent's user can read its memory, and refuses to run unless the Agent's
/// AppArmor profile enforces it. The unit checks the profile too, before the start; this check
/// also covers a start outside the unit (AGENTS.md invariant 3,
/// `agent_refuses_to_start_without_enforced_apparmor_profile`).
///
/// # Errors
///
/// The reason the Agent must not run, for its standard error.
fn guard() -> Result<(), String> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| format!("cannot mark the process not dumpable: {e}"))?;
    match own_label() {
        Some(label) if enforced(&label) => Ok(()),
        label => Err(format!(
            "refusing to start: the AppArmor profile linuxhello-agent does not enforce this process (its label is {:?})",
            label.as_deref().map_or("unknown", |l| l.trim_end_matches(['\n', '\0']))
        )),
    }
}

fn main() -> ExitCode {
    if let Err(reason) = guard() {
        eprintln!("linuxhello-agent: {reason}");
        return ExitCode::FAILURE;
    }
    match futures_lite::future::block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("linuxhello-agent: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::enforced;

    #[test]
    fn only_the_agents_profile_in_enforce_mode_counts() {
        assert!(enforced("linuxhello-agent (enforce)\n"));
        assert!(enforced("linuxhello-agent (enforce)"));
        assert!(enforced("linuxhello-agent//&unconfined (enforce)\n"));
        assert!(enforced("unconfined//&linuxhello-agent (enforce)\n"));
        for label in [
            "",
            "unconfined",
            "unconfined\n",
            "linuxhello-agent (complain)\n",
            "linuxhello-agent (kill)\n",
            "linuxhello-agent//howdy (enforce)\n",
            "linuxhello-tpm-provider (enforce)\n",
            "linuxhello-agent (enforce) extra",
            "linuxhello-agent//&unconfined (mixed)\n",
            "linuxhello-agent//&other (enforce)\n",
            "unconfined//&unconfined (enforce)\n",
            "linuxhello-agent//&linuxhello-agent//howdy (enforce)\n",
        ] {
            assert!(!enforced(label), "{label:?}");
        }
    }
}
