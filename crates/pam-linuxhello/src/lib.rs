//! pam_linuxhello: skeleton. Implementation starts after Milestone 0.
//!
//! The PAM entry points (`pam_sm_authenticate`, `pam_sm_open_session`) need FFI and
//! therefore `unsafe`. They will live in one small, audited module that carries
//! `#[allow(unsafe_code)]` and is listed in `scripts/ci/unsafe-allowlist.txt`;
//! everywhere else in this crate `unsafe` is denied.

#![deny(unsafe_code)]
