//! linuxhello-tpm-provider: skeleton. Implementation starts after Milestone 0.
//!
//! TPM access may need FFI. If it does, that code lives in one small, audited module
//! that carries `#[allow(unsafe_code)]` and is listed in `scripts/ci/unsafe-allowlist.txt`;
//! everywhere else in this crate `unsafe` is denied.
//!
//! C4 container: `tpmProvider` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

#![deny(unsafe_code)]

fn main() {
    println!(
        "linuxhello-tpm-provider {} (skeleton, bus name {})",
        env!("CARGO_PKG_VERSION"),
        linuxhello_dbus::AGENT_BUS_NAME
    );
}
