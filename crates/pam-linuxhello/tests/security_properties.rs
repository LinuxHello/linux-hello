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

/// P-20: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the PAM entry points do not exist yet"]
fn pam_never_succeeds_when_agent_is_unreachable() {
    unimplemented!("P-20: write this test when it is unblocked");
}

/// P-21: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the PAM entry points do not exist yet"]
fn pam_success_for_another_user_is_not_success() {
    unimplemented!("P-21: write this test when it is unblocked");
}
