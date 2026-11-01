//! pam_linuxhello: skeleton. Implementation starts after Milestone 0.
//!
//! The PAM entry points (`pam_sm_authenticate`, `pam_sm_open_session`) need FFI and
//! therefore `unsafe`. They will live in one small, audited module with a narrow
//! lint override; the rest of the crate stays `forbid(unsafe_code)`.
