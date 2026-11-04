//! The Linux Hello Agent as a library: the logic the `linuxhello-agent` daemon runs,
//! kept in a library so that tests and fuzz targets can reach it.
//!
//! C4 container: `agent` ([workspace.dsl](https://github.com/LinuxHello/linux-hello/blob/main/docs/architecture/workspace.dsl))

#![forbid(unsafe_code)]

pub mod policy;
