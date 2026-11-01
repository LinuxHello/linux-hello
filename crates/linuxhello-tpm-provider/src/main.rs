//! linuxhello-tpm-provider: skeleton. Implementation starts after Milestone 0.

fn main() {
    println!(
        "linuxhello-tpm-provider {} (skeleton, bus name {})",
        env!("CARGO_PKG_VERSION"),
        linuxhello_dbus::AGENT_BUS_NAME
    );
}
