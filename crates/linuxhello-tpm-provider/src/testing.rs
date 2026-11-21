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
    ///
    /// swtpm is started through [`CLOSE_INHERITED`], so that it keeps none of the test process's
    /// descriptors: see there for why that matters.
    ///
    /// # Panics
    ///
    /// When `LH_REQUIRE_SWTPM` is set and swtpm is not installed, when `bash` cannot be started,
    /// and when swtpm does not answer on any of eight ports.
    pub fn start() -> Option<Self> {
        if !on_path("swtpm") {
            assert!(
                std::env::var("LH_REQUIRE_SWTPM").is_err(),
                "swtpm is required here (LH_REQUIRE_SWTPM) and is not installed"
            );
            eprintln!("SKIPPED: swtpm is not installed");
            return None;
        }
        for _ in 0..8 {
            let state = private_tempdir();
            let port = claim_port();
            let child = Command::new("bash")
                .args(["-c", CLOSE_INHERITED, "swtpm"])
                .args(["socket", "--tpm2", "--tpmstate"])
                .arg(format!("dir={}", state.path().display()))
                .arg("--server")
                .arg(format!("type=tcp,port={port}"))
                .arg("--ctrl")
                .arg(format!("type=tcp,port={}", port + 1))
                .args(["--flags", "not-need-init,startup-clear"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("start bash, which starts swtpm");
            let mut soft = Self {
                child,
                port,
                _state: state,
            };
            if soft.wait_until_listening() && soft.answers() {
                return Some(soft);
            }
            // Dropping `soft` gives the port back.
        }
        panic!("swtpm did not start listening on any of eight ports");
    }

    /// The process id of this swtpm.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The TCTI string of this TPM.
    pub fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    /// Opens the key service on it.
    pub fn open(&self) -> Tpm {
        open_when_ready(&self.tcti())
    }

    /// Whether this swtpm answers a real command within a few seconds. A connection that is accepted
    /// proves little: another listener on the port, a swtpm that is still starting and one that died a
    /// moment after it listened all accept. Asking for a property of the TPM proves that it is this
    /// TPM and that it works, and costs no key generation.
    fn answers(&mut self) -> bool {
        let Ok(tcti) = self.tcti().parse::<tss_esapi::TctiNameConf>() else {
            return false;
        };
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if !matches!(self.child.try_wait(), Ok(None)) {
                return false;
            }
            if let Ok(mut context) = tss_esapi::Context::new(tcti.clone()) {
                if context
                    .get_tpm_property(tss_esapi::constants::PropertyTag::Manufacturer)
                    .is_ok()
                {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
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
        // moment, then stop it, and never wait for ever. The port is given back last, once nothing
        // listens on it.
        if let Ok(mut control) = std::net::TcpStream::connect(("127.0.0.1", self.port + 1)) {
            let _ = std::io::Write::write_all(&mut control, &3_u32.to_be_bytes());
            let mut answer = [0_u8; 4];
            let _ = std::io::Read::read(&mut control, &mut answer);
        }
        let until = Instant::now() + Duration::from_secs(3);
        let mut ended = false;
        while Instant::now() < until {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                ended = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !ended {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        release_port(self.port);
    }
}

/// Opens the key service on the TPM at `tcti`, trying again for a few seconds. A software TPM accepts
/// connections a moment before it can answer commands, and under load that moment is long enough for
/// the first command to be refused with a code the TSS library has no name for ("response code not
/// recognized"); a TPM that is not there still fails, after the last try.
///
/// # Panics
///
/// When the TPM does not open within ten seconds.
pub fn open_when_ready(tcti: &str) -> Tpm {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match Tpm::open(tcti) {
            Ok(tpm) => return tpm,
            Err(error) if Instant::now() >= until => panic!("open the software TPM: {error:?}"),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// A bash script that closes every descriptor above 2 it was given and then runs swtpm with its own
/// arguments (`$@`).
///
/// The TSS library (libtss2) opens a new TCP connection to swtpm for every TPM command, without
/// close-on-exec (read in its source, versions 4.0.1 and 4.1.3). When one test starts its swtpm
/// while another test's command is under way, the new swtpm inherits that test's connection and
/// keeps it open after the library has closed its own copy. swtpm serves one connection at a time and
/// waits for the client to hang up before it takes the next, so the other test's next command waits
/// behind a connection that nobody will close, until its call times out or its swtpm is stopped and
/// the waiting connection is reset ("Connection reset by peer", TSS2 response code 0xA000A). Closing
/// the inherited descriptors before swtpm runs leaves every connection to its owner.
///
/// Test: `a_software_tpm_keeps_no_connection_of_the_test_process_open`.
const CLOSE_INHERITED: &str = r#"for fd in /proc/self/fd/*; do fd=${fd##*/}; if [ "$fd" -gt 2 ]; then exec {fd}>&-; fi; done; exec swtpm "$@""#;

/// Whether `program` is an executable file in one of the directories of `PATH`.
fn on_path(program: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            std::fs::metadata(dir.join(program))
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

/// The data ports that software TPMs of this process hold. Two tests that start a TPM side by side
/// must not pick the same free port: the loser's "is it listening" check would be answered by the
/// winner's swtpm, and the loser would then talk to a TPM that is not its own.
static CLAIMED: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());

/// A free port, with the next one for the control channel, that no other TPM of this process holds.
fn claim_port() -> u16 {
    loop {
        let port = free_port();
        let mut claimed = CLAIMED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !claimed.iter().any(|p| p.abs_diff(port) <= 1) {
            claimed.push(port);
            return port;
        }
    }
}

/// Gives a port back.
fn release_port(port: u16) {
    CLAIMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|p| *p != port);
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

/// A temporary directory that only its owner can use, whatever the umask of the shell that runs the
/// tests (the code under test refuses a directory that others can write).
fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("a temporary directory")
}
