//! linuxhello-ctl: skeleton. Implementation starts after Milestone 0.
//!
//! C4 container: `cli` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

mod policy;

use std::process::ExitCode;

/// The Agent's state directory for the user layers (the same value as `USER_POLICY_ROOT` in the
/// Agent's `main.rs`, which is private there).
const USER_POLICY_ROOT: &str = "/var/lib/linuxhello/users";

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
    ExitCode::from(policy::run(
        &args,
        std::path::Path::new(USER_POLICY_ROOT),
        &passwd,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    ))
}
