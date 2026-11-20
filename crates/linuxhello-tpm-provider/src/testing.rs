//! A software TPM (swtpm) for tests, here so that the Agent's tests can use the same one as the
//! provider's: a real TPM 2.0 implementation, started with an empty state for each test, so the
//! dictionary-attack counter of one test never reaches another. Without `swtpm` the tests say so and
//! return; set `LH_REQUIRE_SWTPM=1` (CI does) to make its absence a failure.
//!
//! Only with the cargo feature `testing`, which nothing but a test turns on.
//!
//! C4 component: `tpmKeys` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::keys::Tpm;

/// A running software TPM, stopped when dropped.
pub struct SoftTpm {
    /// The swtpm process.
    child: Child,
    /// The port of its data channel; the control channel is the next one.
    pub port: u16,
    /// Its state directory, removed with it.
    _state: tempfile::TempDir,
}

impl SoftTpm {
    /// Starts swtpm, or `None` (and a line saying so) when it is not installed. The tests run side by
    /// side and pick their ports one after another, so two can pick the same one; the one that loses
    /// finds its swtpm gone (the port is taken), and tries again with another port.
    pub fn start() -> Option<Self> {
        for _ in 0..8 {
            let state = tempfile::TempDir::new().unwrap();
            let port = free_port();
            let child = Command::new("swtpm")
                .args(["socket", "--tpm2", "--tpmstate"])
                .arg(format!("dir={}", state.path().display()))
                .arg("--server")
                .arg(format!("type=tcp,port={port}"))
                .arg("--ctrl")
                .arg(format!("type=tcp,port={}", port + 1))
                .args(["--flags", "not-need-init,startup-clear"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            let Ok(child) = child else {
                assert!(
                    std::env::var("LH_REQUIRE_SWTPM").is_err(),
                    "swtpm is required here (LH_REQUIRE_SWTPM) and is not installed"
                );
                eprintln!("SKIPPED: swtpm is not installed");
                return None;
            };
            let mut soft = Self {
                child,
                port,
                _state: state,
            };
            if soft.wait_until_listening() {
                return Some(soft);
            }
        }
        panic!("swtpm did not start listening on any of eight ports");
    }

    /// The TCTI string of this TPM.
    pub fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    /// Opens the key service on it.
    pub fn open(&self) -> Tpm {
        Tpm::open(&self.tcti()).expect("open the software TPM")
    }

    /// Waits until swtpm accepts connections on its data port. `false` when swtpm has already ended
    /// (it could not take its port), so that the caller tries another one.
    fn wait_until_listening(&mut self) -> bool {
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            if !matches!(self.child.try_wait(), Ok(None)) {
                return false;
            }
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                // It may be another test's swtpm that answered; ours is still running.
                return matches!(self.child.try_wait(), Ok(None));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

impl Drop for SoftTpm {
    fn drop(&mut self) {
        // Ask swtpm to shut down over its control channel (CMD_SHUTDOWN is 3), wait for it for a
        // moment, then stop it, and never wait for ever.
        if let Ok(mut control) = std::net::TcpStream::connect(("127.0.0.1", self.port + 1)) {
            let _ = std::io::Write::write_all(&mut control, &3_u32.to_be_bytes());
            let mut answer = [0_u8; 4];
            let _ = std::io::Read::read(&mut control, &mut answer);
        }
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
    }
}

/// A port that is free now, with the next one for the control channel.
fn free_port() -> u16 {
    loop {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if port < 65_000 && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
            return port;
        }
    }
}
