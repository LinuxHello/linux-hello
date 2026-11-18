//! What `doctor` reads and runs on the machine, behind a trait so that a test replaces it. The
//! probes only read; `Host` has no way to write.
//!
//! C4 component: `cliCommands` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::path::Path;

/// The machine as `doctor` sees it.
pub trait Host {
    /// Runs a program with arguments, no shell. `None` when it cannot be started.
    /// Otherwise its exit code (`-1` when a signal ended it) and its standard output.
    fn run(&self, program: &str, args: &[&str]) -> Option<(i32, String)>;
    /// Reads a file as text. `None` when it cannot be read.
    fn read(&self, path: &Path) -> Option<String>;
}

/// The real implementation using system commands and filesystem.
pub struct RealHost;

impl Host for RealHost {
    fn run(&self, program: &str, args: &[&str]) -> Option<(i32, String)> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .ok()?;

        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Some((exit_code, stdout))
    }

    fn read(&self, path: &Path) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }
}
