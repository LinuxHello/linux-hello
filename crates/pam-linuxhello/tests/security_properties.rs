//! Placeholder tests for the security properties that the PAM module (C4 container `pamModule`) owns.
//!
//! Each test is named after its property in `docs/security/properties.md` and is
//! `#[ignore]`d with the reason it cannot be written yet. A placeholder is not a passing
//! test: it panics if it is run. Remove the `#[ignore]`, write the test and watch it fail
//! before writing the code it tests.

/// P-12: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the PIN verifier does not exist yet"]
fn pin_is_never_compared_outside_the_tpm() {
    unimplemented!("P-12: write this test when it is unblocked");
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
#[ignore = "placeholder, blocked: the PAM entry points do not exist yet"]
fn pam_success_for_another_user_is_not_success() {
    unimplemented!("P-21: write this test when it is unblocked");
}
