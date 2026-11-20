//! linuxhello-tpm-provider: the daemon that does the TPM commands for the Agent.
//!
//! It opens the TPM (`/dev/tpmrm0`, the kernel's resource manager), listens on
//! `/run/linuxhello-tpm/tpm.sock` and serves one request per connection, only from the user the Agent
//! runs as (`linuxhello`, looked up in `/etc/passwd`). It keeps no key and no state of its own; see
//! the library for what it does and refuses. A TPM that is missing or a socket that cannot be bound is
//! an error and the daemon exits, so its unit restarts it and the Agent sees a provider that does not
//! answer, which is never a wrong PIN.
//!
//! C4 container: `tpmProvider` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![deny(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

use linuxhello_tpm_provider::keys::Tpm;
use linuxhello_tpm_provider::server::{ids_of, Server};

/// The socket the Agent connects to, in the runtime directory the unit creates.
const SOCKET: &str = "/run/linuxhello-tpm/tpm.sock";

/// The account the Agent runs as: the only user the provider serves.
const AGENT_USER: &str = "linuxhello";

/// The TPM: the kernel's resource manager, which shares the chip safely between processes.
const TPM: &str = "device:/dev/tpmrm0";

/// Starts the server and never returns unless starting fails.
fn run() -> Result<(), String> {
    let passwd = std::fs::read_to_string("/etc/passwd").map_err(|e| format!("/etc/passwd: {e}"))?;
    let (agent_uid, agent_gid) =
        ids_of(AGENT_USER, &passwd).ok_or_else(|| format!("no account named {AGENT_USER}"))?;
    let own = rustix::process::getuid().as_raw();
    let tpm = Tpm::open(TPM).map_err(|e| format!("the TPM is not available: {e:?}"))?;
    let server = Server::bind(Path::new(SOCKET), own, agent_uid, agent_gid, tpm)
        .map_err(|e| format!("the socket cannot be bound: {e}"))?;
    server.serve_forever();
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("linuxhello-tpm-provider: {error}");
            ExitCode::FAILURE
        }
    }
}
