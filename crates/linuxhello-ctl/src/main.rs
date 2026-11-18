//! linuxhello-ctl: skeleton. Implementation starts after Milestone 0.
//!
//! C4 container: `cli` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

mod ask;
mod policy;
mod probe;
mod status;

use crate::probe::RealHost;
use std::process::ExitCode;

/// The Agent's state directory for the user layers (the same value as `USER_POLICY_ROOT` in the
/// Agent's `main.rs`, which is private there).
const USER_POLICY_ROOT: &str = "/var/lib/linuxhello/users";

/// The Agent's admin policy directory (the same value as `ADMIN_POLICY_DIR` in the Agent's
/// `main.rs`, which is private there).
const ADMIN_POLICY_DIR: &str = "/etc/linuxhello/policy.d";

/// Without arguments prints the skeleton line; with arguments runs the command and exits with its
/// code (0 done, 1 failed, 2 usage error).
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        println!(
            "linuxhello-ctl {} (skeleton, bus name {})",
            env!("CARGO_PKG_VERSION"),
            linuxhello_dbus::AGENT_BUS_NAME
        );
        return ExitCode::SUCCESS;
    }
    // A missing /etc/passwd only means user names cannot be resolved; a numeric uid still works.
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let (state_root, mut out, mut err) = (
        std::path::Path::new(USER_POLICY_ROOT),
        std::io::stdout(),
        std::io::stderr(),
    );
    let host = RealHost;
    let code = if matches!(args[0].as_str(), "status" | "doctor") {
        status::run(
            &args,
            &host,
            std::path::Path::new(ADMIN_POLICY_DIR),
            0,
            state_root,
            &passwd,
            &mut out,
            &mut err,
        )
    } else {
        policy::run(&args, state_root, &passwd, &mut out, &mut err)
    };
    ExitCode::from(code)
}
