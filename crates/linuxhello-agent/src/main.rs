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
use linuxhello_agent::bus::{bus_alive, serve_with_extras, Extras};
use linuxhello_agent::methods::{fingerprint::FingerprintMethod, username_of};
use linuxhello_agent::notify::{watchdog_interval, Notifier};
use linuxhello_agent::orchestrator::Method;
use linuxhello_agent::pinlock::service::{Limits, PinLockService};
use linuxhello_agent::pinlock::store::PinLockFile;
use linuxhello_agent::pinsocket::PinSocket;
use linuxhello_agent::policy::load;
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;
use zbus::connection::Builder;

/// The root directory where user policy subdirectories are located.
const USER_POLICY_ROOT: &str = "/var/lib/linuxhello/users";

/// The directory of the admin policy layer, owned by root.
const ADMIN_POLICY_DIR: &str = "/etc/linuxhello/policy.d";

/// The PIN socket (ADR-0021), in the runtime directory the unit creates for the Agent's user.
const PIN_SOCKET: &str = "/run/linuxhello/pin.sock";

/// The methods an authentication of the user `subject` runs: the fingerprint method when the
/// account has a name in `/etc/passwd`. Face and PIN are later slices of #195.
fn methods_of(subject: u32) -> Vec<Box<dyn Method>> {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    username_of(subject, &passwd)
        .map(|name| vec![Box::new(FingerprintMethod::new(name)) as Box<dyn Method>])
        .unwrap_or_default()
}

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
    PinLockService::start(
        PinLockFile::new(PIN_LOCK_FILE, owner),
        Limits::from_policy(&policy),
    )
}

/// Binds the PIN socket and serves it on a thread, and returns it so that `ExpectPin` can announce
/// PINs to it. A PIN is not used anywhere yet, so a socket that cannot be bound is reported on
/// standard error and the Agent goes on serving the bus (`ExpectPin` is then `Unavailable`); the
/// slice that wires the PIN verifier decides whether that stays so.
fn serve_pin_socket() -> Option<Arc<PinSocket>> {
    let owner = rustix::process::getuid().as_raw();
    match PinSocket::bind(Path::new(PIN_SOCKET), owner) {
        Ok(socket) => {
            let socket = Arc::new(socket);
            PinSocket::serve_forever(Arc::clone(&socket), drop);
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
    let pin_socket = serve_pin_socket();
    let store = UserPolicyStore::new(USER_POLICY_ROOT).with_admin_layer(ADMIN_POLICY_DIR, 0);
    let extras = Extras {
        audit: Some(Audit::journal()),
        pin_socket,
        pin_lock: Some(pin_lock()),
        methods: Some(Arc::new(methods_of)),
        auth_deadline: None,
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

fn main() -> ExitCode {
    match futures_lite::future::block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("linuxhello-agent: {error}");
            ExitCode::FAILURE
        }
    }
}
