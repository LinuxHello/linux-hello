//! A software TPM (swtpm) for the tests: a real TPM 2.0 implementation, started with an empty state
//! for each test, so the TPM's dictionary-attack counter of one test never reaches another. Without
//! `swtpm` the tests say so and return; set `LH_REQUIRE_SWTPM=1` (CI does) to make its absence a
//! failure.
#![allow(dead_code)]

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use linuxhello_tpm_provider::keys::Tpm;

/// A running software TPM, stopped when dropped.
pub struct SoftTpm {
    child: Child,
    pub port: u16,
    _state: tempfile::TempDir,
}

impl SoftTpm {
    /// Starts swtpm, or `None` (and a line saying so) when it is not installed.
    pub fn start() -> Option<Self> {
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
        let soft = Self {
            child,
            port,
            _state: state,
        };
        soft.wait_until_listening();
        Some(soft)
    }

    /// The TCTI string of this TPM.
    pub fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    /// Opens the key service on it.
    pub fn open(&self) -> Tpm {
        Tpm::open(&self.tcti()).expect("open the software TPM")
    }

    fn wait_until_listening(&self) {
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("swtpm did not start listening");
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
