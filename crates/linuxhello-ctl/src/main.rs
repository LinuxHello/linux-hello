//! linuxhello-ctl: skeleton. Implementation starts after Milestone 0.
//!
//! C4 container: `cli` ([workspace.dsl](https://github.com/LinuxHello/linux-hello/blob/main/docs/architecture/workspace.dsl))

#![forbid(unsafe_code)]

fn main() {
    println!(
        "linuxhello-ctl {} (skeleton, bus name {})",
        env!("CARGO_PKG_VERSION"),
        linuxhello_dbus::AGENT_BUS_NAME
    );
}
