//! The Agent Link: the QML plugin `io.github.LinuxHello.AgentLink` through which Linux Hello's
//! Plasma screens (the greeter, the part in KDE's lock screen) reach the Linux Hello Agent, because
//! QML cannot speak D-Bus itself (ADR-0028). It gives QML two objects: `AgentLink`, that follows a
//! sign-in attempt and hands the shared Auth Prompt its state as JSON, and `Greetd`, through which
//! Linux Hello's greeter talks to greetd, the login service that runs PAM and starts the desktop
//! (ADR-0028, amendment of 2026-11-22).
//!
//! Written in Rust with cxx-qt. One module, `bridge`, is allowed `unsafe` code: it holds only the
//! cxx-qt bridge declaration, which cxx-qt expands into glue between Rust and C++ (invariant 4,
//! `scripts/ci/unsafe-allowlist.txt`). Everything else is under `deny(unsafe_code)`.
//!
//! C4 container: `plasma` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))
#![deny(unsafe_code)]

mod bridge;
mod fold;
mod greetd;
mod greeter;
mod link;
mod sessions;
