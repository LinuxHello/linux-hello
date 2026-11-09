//! linuxhello-agent: serves the Agent's state API on the system bus until it is stopped.
//!
//! It claims `io.github.LinuxHello.Agent1` and exports the object of ADR-0012 and ADR-0014. The
//! bus policy decides who may own the name, so a start by any user but the Agent's own fails.
//! It reads no configuration yet: the prompt hosts that may read any prompt are none, and the
//! TPM and the policy engine are not wired in. Users can store and read their own policy layer
//! (`GetUserPolicy`, `SetUserPolicy`); the engine does not read it yet.
//!
//! C4 container: `agent` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

use std::process::ExitCode;

use linuxhello_agent::bus::serve_with;
use linuxhello_agent::policy::user_store::UserPolicyStore;
use linuxhello_agent::state::Config;
use zbus::connection::Builder;

/// The root directory where user policy subdirectories are located.
const USER_POLICY_ROOT: &str = "/var/lib/linuxhello/users";

/// The directory of the admin policy layer, owned by root.
const ADMIN_POLICY_DIR: &str = "/etc/linuxhello/policy.d";

/// Connects to the system bus, claims the Agent's name and serves until the process is stopped.
///
/// # Errors
///
/// Any error of connecting to the bus or claiming the name, such as the bus policy refusing it.
async fn run() -> zbus::Result<()> {
    let store = UserPolicyStore::new(USER_POLICY_ROOT).with_admin_layer(ADMIN_POLICY_DIR, 0);
    let _connection = serve_with(Builder::system(), Config::new(Vec::new()), Some(store)).await?;
    std::future::pending::<()>().await;
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
