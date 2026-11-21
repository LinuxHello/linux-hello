//! pam_linuxhello: the PAM module of Linux Hello, a thin synchronous client of the Agent
//! (ADR-0023).
//!
//! In plain words: Linux-PAM is the library that `sudo`, login screens and lock screens use to ask
//! "is this the user?". This crate builds `pam_linuxhello.so`, a module PAM loads into those
//! programs. The module does not check a fingerprint, a face or a PIN itself: it asks the Linux
//! Hello Agent (the system service that runs them) over the system bus, waits for the answer with
//! a hard deadline, and turns it into a PAM code. When Linux Hello cannot answer, the module says
//! *unavailable* and the shipped PAM lines (`pam.d/`) go on to the account password.
//!
//! It starts no thread, no async executor and no subprocess inside the program that loaded it. The
//! PAM entry points need C calls and so `unsafe`; they live in the one audited module `entry`,
//! listed in `scripts/ci/unsafe-allowlist.txt`. Everywhere else in this crate `unsafe` is denied.
//!
//! C4 container: `pamModule` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![deny(unsafe_code)]

pub mod client;
mod entry;
