//! Placeholder tests for the security properties that the TPM credential provider (C4 container `tpmProvider`) owns.
//!
//! Each test is named after its property in `docs/security/properties.md` and is
//! `#[ignore]`d with the reason it cannot be written yet. A placeholder is not a passing
//! test: it panics if it is run. Remove the `#[ignore]`, write the test and watch it fail
//! before writing the code it tests.

/// P-03: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the credentialsd provider interface does not exist (ADR-0005)"]
fn credential_for_another_relying_party_is_never_returned() {
    unimplemented!("P-03: write this test when it is unblocked");
}

/// P-06: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: how a match satisfies a TPM policy is undecided"]
fn biometric_match_alone_never_releases_a_key() {
    unimplemented!("P-06: write this test when it is unblocked");
}

/// P-08: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the TPM key service does not exist yet"]
fn tpm_keys_are_created_non_exportable() {
    unimplemented!("P-08: write this test when it is unblocked");
}

/// P-09: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the TPM key service does not exist yet"]
fn no_interface_returns_private_key_material() {
    unimplemented!("P-09: write this test when it is unblocked");
}

/// P-11: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the credentialsd provider interface does not exist (ADR-0005)"]
fn signature_without_user_presence_is_refused() {
    unimplemented!("P-11: write this test when it is unblocked");
}

/// P-16: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: spike #11: changing the root key's authorisation in place is unverified"]
fn pin_change_keeps_child_keys_loadable() {
    unimplemented!("P-16: write this test when it is unblocked");
}

/// P-16: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: spike #11: changing the root key's authorisation in place is unverified"]
fn old_pin_is_refused_after_a_change() {
    unimplemented!("P-16: write this test when it is unblocked");
}

/// P-18: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the TPM key service and the reset coordinator do not exist yet"]
fn reset_destroys_root_key_and_every_child_key() {
    unimplemented!("P-18: write this test when it is unblocked");
}

/// P-22: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the credentialsd provider interface does not exist (ADR-0005)"]
fn malformed_ctap_request_is_refused() {
    unimplemented!("P-22: write this test when it is unblocked");
}

/// P-24: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the provider's start-up code does not exist yet"]
fn tpm_provider_refuses_to_start_without_enforced_apparmor_profile() {
    unimplemented!("P-24: write this test when it is unblocked");
}
