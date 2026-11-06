//! Placeholder tests for the security properties that the KeePassXC provider bridge (C4 container `kpxcBridge`) owns.
//!
//! Each test is named after its property in `docs/security/properties.md` and is
//! `#[ignore]`d with the reason it cannot be written yet. A placeholder is not a passing
//! test: it panics if it is run. Remove the `#[ignore]`, write the test and watch it fail
//! before writing the code it tests.

/// P-03: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the credentialsd provider interface does not exist (ADR-0005)"]
fn kpxc_credential_for_another_relying_party_is_never_returned() {
    unimplemented!("P-03: write this test when it is unblocked");
}

/// P-10: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the bridge's protocol client does not exist yet"]
fn kpxc_bridge_never_receives_private_key_material() {
    unimplemented!("P-10: write this test when it is unblocked");
}

/// P-23: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the bridge's protocol client does not exist yet"]
fn malformed_kpxc_message_is_refused() {
    unimplemented!("P-23: write this test when it is unblocked");
}

/// P-24: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: the bridge's start-up code does not exist yet"]
fn kpxc_bridge_refuses_to_start_without_enforced_apparmor_profile() {
    unimplemented!("P-24: write this test when it is unblocked");
}
