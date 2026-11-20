//! linuxhello-ctl: skeleton. Implementation starts after Milestone 0.
//!
//! C4 container: `cli` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

mod agent_client;
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

/// The Agent's PIN socket (the same value as `PIN_SOCKET` in the Agent's `main.rs`, which is private
/// there).
const PIN_SOCKET: &str = "/run/linuxhello/pin.sock";

/// `pin set` and `pin change`: the caller's own PIN, through the Agent on the system bus.
fn pin_command(args: &[String], out: &mut dyn std::io::Write) -> u8 {
    let change = match args.get(1).map(String::as_str) {
        Some("set") => false,
        Some("change") => true,
        _ => {
            let _ = writeln!(out, "usage: linuxhello-ctl pin set | pin change");
            return 2;
        }
    };
    if args.len() > 2 {
        let _ = writeln!(out, "usage: linuxhello-ctl pin set | pin change");
        return 2;
    }
    let Ok(connection) = futures_lite::future::block_on(zbus::Connection::system()) else {
        let _ = writeln!(out, "The system bus is not available.");
        return 1;
    };
    agent_client::run(
        &connection,
        std::path::Path::new(PIN_SOCKET),
        rustix::process::getuid().as_raw(),
        change,
        &mut agent_client::Terminal,
        out,
    )
}

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
    let code = if matches!(args.first().map(String::as_str), Some("pin")) {
        pin_command(&args, &mut out)
    } else if matches!(args[0].as_str(), "status" | "doctor") {
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
