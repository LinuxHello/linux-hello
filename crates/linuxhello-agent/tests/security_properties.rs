//! Placeholder tests for the security properties that the Agent (C4 container `agent`) owns.
//!
//! Each test is named after its property in `docs/security/properties.md` and is
//! `#[ignore]`d with the reason it cannot be written yet. A placeholder is not a passing
//! test: it panics if it is run. Remove the `#[ignore]`, write the test and watch it fail
//! before writing the code it tests.

/// P-01: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: origin verification and the Agent's D-Bus API are not designed yet"]
fn caller_from_other_origin_is_refused() {
    unimplemented!("P-01: write this test when it is unblocked");
}

/// P-02: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the Agent's D-Bus API does not exist yet"]
fn caller_without_peer_credentials_is_refused() {
    unimplemented!("P-02: write this test when it is unblocked");
}

/// P-04: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the Agent's bus and bus policy need an ADR (spike 0007)"]
fn unprivileged_process_cannot_publish_method_state_for_another_user() {
    unimplemented!("P-04: write this test when it is unblocked");
}

/// P-05: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the Agent's bus and bus policy need an ADR (spike 0007)"]
fn method_state_is_not_broadcast_to_other_users() {
    unimplemented!("P-05: write this test when it is unblocked");
}

/// P-07: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: how a match satisfies a TPM policy is undecided"]
fn unlock_requires_a_satisfied_tpm_policy_session() {
    unimplemented!("P-07: write this test when it is unblocked");
}

/// P-13: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the audit logger does not exist yet"]
fn secrets_never_appear_in_logs_errors_or_audit() {
    unimplemented!("P-13: write this test when it is unblocked");
}

/// P-14: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: whether the TPM lockout is shared is unchecked; the PIN manager does not exist yet"]
fn one_users_failed_pins_cannot_lock_out_another_user() {
    unimplemented!("P-14: write this test when it is unblocked");
}

/// P-15: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the unlock state manager does not exist yet"]
fn unlock_expires_after_the_configured_duration() {
    unimplemented!("P-15: write this test when it is unblocked");
}

/// P-15: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the unlock state manager does not exist yet"]
fn unlock_ends_when_the_session_locks() {
    unimplemented!("P-15: write this test when it is unblocked");
}

/// P-17: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the reset coordinator does not exist yet"]
fn account_password_never_unlocks_a_key() {
    unimplemented!("P-17: write this test when it is unblocked");
}

/// P-19: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the reset coordinator does not exist yet"]
fn reset_without_account_authentication_is_refused() {
    unimplemented!("P-19: write this test when it is unblocked");
}

/// P-24: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the Agent's start-up code does not exist yet"]
fn agent_refuses_to_start_without_enforced_apparmor_profile() {
    unimplemented!("P-24: write this test when it is unblocked");
}

/// P-27: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the audit logger does not exist yet"]
fn every_unlock_signature_pin_change_and_reset_is_audited() {
    unimplemented!("P-27: write this test when it is unblocked");
}
