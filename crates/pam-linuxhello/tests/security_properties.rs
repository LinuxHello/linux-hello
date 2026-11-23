//! Placeholder tests for the security properties that the PAM module (C4 container `pamModule`) owns.
//!
//! Each test is named after its property in `docs/security/properties.md` and is
//! `#[ignore]`d with the reason it cannot be written yet. A placeholder is not a passing
//! test: it panics if it is run. Remove the `#[ignore]`, write the test and watch it fail
//! before writing the code it tests.

/// P-12: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, not blocked: the verifier exists (the Agent's `methods/pin/tpm.rs`); no test of this property is written yet"]
fn pin_is_never_compared_outside_the_tpm() {
    unimplemented!("P-12: write this test");
}

/// P-20: see `docs/security/properties.md`. With no bus, or a bus on which nobody owns the Agent's
/// name, the module answers unavailable, never success.
#[test]
fn pam_never_succeeds_when_agent_is_unreachable() {
    use pam_linuxhello::client::{authenticate_at, Code, Conversation, Limits, Request};
    use zeroize::Zeroizing;

    struct Nobody;
    impl Conversation for Nobody {
        fn secret(&mut self, _: &str) -> Option<Zeroizing<String>> {
            Some(Zeroizing::new("1234".into()))
        }
        fn info(&mut self, _: &str) {}
        fn error(&mut self, _: &str) {}
    }
    let dir = tempfile::tempdir().unwrap();
    // A socket path where nothing listens, and a file that is not a socket.
    std::fs::write(dir.path().join("file"), b"").unwrap();
    for bus in ["none", "file"] {
        for context in ["login", "unlock", "sudo", "session"] {
            let request = Request {
                context: Some(context),
                service: "sudo",
                terminal: "/dev/pts/1",
                remote_host: "",
                uid: Some(1000),
            };
            let code = authenticate_at(
                &dir.path().join(bus),
                &dir.path().join("pin"),
                &Limits::DEFAULT,
                &request,
                &mut Nobody,
            );
            assert_eq!(code, Code::Unavailable, "{bus} {context}");
        }
    }
}

/// P-21: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, not blocked: the entry points exist (`src/entry.rs`); the test needs a PAM host and is not written yet"]
fn pam_success_for_another_user_is_not_success() {
    unimplemented!("P-21: write this test");
}

/// Every `.rs` file under `dir`.
fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// ADR-0026: the PAM module reaches the Agent over its own bus connection and the PIN socket, and
/// starts no program. A file named `tests.rs` is test code; any other file is read up to its first
/// `#[cfg(test)]`, which in this crate opens the test module at its end.
#[test]
fn the_pam_module_starts_no_program() {
    let mut files = Vec::new();
    sources(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() > 3, "the sources were found: {files:?}");
    for file in files {
        if file.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap();
        let code = text.split("#[cfg(test)]").next().unwrap_or_default();
        for forbidden in [
            "process::Command",
            "Command::new",
            "libc::system",
            "execv",
            "posix_spawn",
        ] {
            assert!(
                !code.contains(forbidden),
                "{} uses {forbidden} outside its tests (ADR-0026)",
                file.display()
            );
        }
    }
}
