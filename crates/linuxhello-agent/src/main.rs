//! linuxhello-agent: serves the Agent's state API on the system bus until it is stopped.
//!
//! It claims `io.github.LinuxHello.Agent1` and exports the object of ADR-0012 and ADR-0014. The
//! bus policy decides who may own the name, so a start by any user but the Agent's own fails.
//! It reads no configuration yet: the prompt hosts that may read any prompt are none, and the
//! TPM and the policy engine are not wired in. Users can store and read their own policy layer
//! (`GetUserPolicy`, `SetUserPolicy`). It binds the PIN socket of ADR-0021 and refuses every connection to it for now. `Api::policy_of` loads the admin layers and the user's layer
//! and audits a fall back to PIN-only; no method of the API answers from it yet.
//!
//! C4 container: `agent` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use linuxhello_agent::audit::Audit;
use linuxhello_agent::bus::{bus_alive, serve_with_audit};
use linuxhello_agent::notify::{watchdog_interval, Notifier};
use linuxhello_agent::pinsocket::PinSocket;
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;
use zbus::connection::Builder;

/// The root directory where user policy subdirectories are located.
const USER_POLICY_ROOT: &str = "/var/lib/linuxhello/users";

/// The directory of the admin policy layer, owned by root.
const ADMIN_POLICY_DIR: &str = "/etc/linuxhello/policy.d";

/// The PIN socket (ADR-0021), in the runtime directory the unit creates for the Agent's user.
const PIN_SOCKET: &str = "/run/linuxhello/pin.sock";

/// Binds the PIN socket and serves it on a thread. A PIN is not used anywhere yet, so a socket
/// that cannot be bound is reported on standard error and the Agent goes on serving the bus; the
/// slice that wires the PIN path decides whether that stays so. Every connection is refused until
/// the control call exists.
fn serve_pin_socket() {
    let owner = rustix::process::getuid().as_raw();
    match PinSocket::bind(Path::new(PIN_SOCKET), owner) {
        Ok(socket) => {
            PinSocket::serve_forever(Arc::new(socket), drop);
        }
        Err(error) => eprintln!("linuxhello-agent: the PIN socket is not available: {error}"),
    }
}

/// Connects to the system bus, claims the Agent's name and serves until the process is stopped.
///
/// # Errors
///
/// Any error of connecting to the bus or claiming the name, such as the bus policy refusing it.
async fn run() -> zbus::Result<()> {
    serve_pin_socket();
    let store = UserPolicyStore::new(USER_POLICY_ROOT).with_admin_layer(ADMIN_POLICY_DIR, 0);
    let connection = serve_with_audit(
        Builder::system(),
        Config::new(Vec::new()),
        Some(store),
        Audit::journal(),
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
