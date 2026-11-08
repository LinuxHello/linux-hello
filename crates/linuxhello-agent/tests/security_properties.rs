//! Placeholder tests for the security properties that the Agent (C4 container `agent`) owns.
//!
//! Each test is named after its property in `docs/security/properties.md` and is
//! `#[ignore]`d with the reason it cannot be written yet. A placeholder is not a passing
//! test: it panics if it is run. Remove the `#[ignore]`, write the test and watch it fail
//! before writing the code it tests.

use linuxhello_agent::state::{Config, Error, Peer, StateStore, Update};
use linuxhello_dbus::{PromptId, PromptState};

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

/// P-04: see `docs/security/properties.md`. Store-level; the bus and its peer credentials come
/// with the D-Bus layer (ADR-0014).
#[test]
fn unprivileged_process_cannot_publish_method_state_for_another_user() {
    let mut store = StateStore::new(Config::new(vec![]));
    let for_other = PromptId::derive("test", "p1", "s1");
    let for_self = PromptId::derive("test", "p2", "s1");

    // An ordinary user cannot open a prompt for someone else, but can for themself.
    assert_eq!(store.open(1000, &for_other, Some(1001)), Err(Error::Denied));
    assert_eq!(store.open(1000, &for_self, Some(1000)), Ok(()));

    // Another user cannot publish on it, and not even root can: only the opener may.
    let scanning = Update::State(PromptState::Scanning);
    assert_eq!(
        store.report(1001, &for_self, scanning.clone()),
        Err(Error::Denied)
    );
    assert_eq!(store.report(0, &for_self, scanning), Err(Error::Denied));

    // Root, as the PAM module of a login, can open a prompt for a user.
    let login = PromptId::derive("test", "p3", "s1");
    assert_eq!(store.open(0, &login, Some(1000)), Ok(()));
}

/// P-05: see `docs/security/properties.md`. Store-level: the store names the peers to tell and
/// refuses everyone else; the D-Bus layer sends unicast signals to exactly those peers.
#[test]
fn method_state_is_not_broadcast_to_other_users() {
    let mut store = StateStore::new(Config::new(vec![990]));
    let id = PromptId::derive("test", "p1", "s1");
    assert_eq!(store.open(0, &id, Some(1000)), Ok(()));

    // The subject user and a prompt host may subscribe; another user may not.
    assert_eq!(store.subscribe(1000, Peer(":1.10".into()), &id), Ok(()));
    assert_eq!(store.subscribe(990, Peer(":1.20".into()), &id), Ok(()));
    assert_eq!(
        store.subscribe(1001, Peer(":1.30".into()), &id),
        Err(Error::Denied)
    );
    let refused = store.get(1001, &id);
    assert_eq!(refused, Err(Error::Denied));

    // An update goes to exactly the two authorised peers, in subscription order.
    let told = store
        .report(0, &id, Update::State(PromptState::Scanning))
        .unwrap();
    assert_eq!(told, vec![Peer(":1.10".into()), Peer(":1.20".into())]);

    // A refusal does not say whether the prompt exists.
    let never_opened = PromptId::derive("test", "none", "s1");
    assert_eq!(store.get(1001, &never_opened), refused);
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
