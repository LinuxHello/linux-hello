//! The Linux Hello Agent as a library: the logic the `linuxhello-agent` daemon runs,
//! kept in a library so that tests and fuzz targets can reach it.
//!
//! C4 container: `agent` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

pub mod api;
pub mod audit;
pub mod bus;
pub mod methods;
pub mod notify;
pub mod orchestrator;
pub mod pinlock;
pub mod pinsocket;
pub mod policy;
pub mod state;
