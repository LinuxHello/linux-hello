//! linuxhello-tpm-provider: skeleton. Implementation starts after Milestone 0.
//!
//! TPM access may need FFI. If it does, that code lives in one small, audited module
//! that carries `#[allow(unsafe_code)]` and is listed in `scripts/ci/unsafe-allowlist.txt`;
//! everywhere else in this crate `unsafe` is denied.

#![deny(unsafe_code)]

fn main() {
    println!(
        "linuxhello-tpm-provider {} (skeleton, bus name {})",
        env!("CARGO_PKG_VERSION"),
        linuxhello_dbus::AGENT_BUS_NAME
    );
}
