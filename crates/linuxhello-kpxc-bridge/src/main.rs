//! linuxhello-kpxc-bridge: skeleton. Implementation starts after Milestone 0.

#![forbid(unsafe_code)]

fn main() {
    println!(
        "linuxhello-kpxc-bridge {} (skeleton, bus name {})",
        env!("CARGO_PKG_VERSION"),
        linuxhello_dbus::AGENT_BUS_NAME
    );
}
