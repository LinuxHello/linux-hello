//! Placeholder tests for the security properties that the Agent (C4 container `agent`) owns.
//!
//! Each test is named after its property in `docs/security/properties.md` and is
//! `#[ignore]`d with the reason it cannot be written yet. A placeholder is not a passing
//! test: it panics if it is run. Remove the `#[ignore]`, write the test and watch it fail
//! before writing the code it tests.

use linuxhello_agent::api::{Api, ApiError, Caller};
use linuxhello_agent::pinlock::PinLock;
use linuxhello_agent::state::{Config, Error, Peer, StateStore, Update};
use linuxhello_dbus::{PromptId, PromptState};

/// P-01: see `docs/security/properties.md`.
#[test]
#[ignore = "placeholder, blocked: origin verification and the Agent's D-Bus API are not designed yet"]
fn caller_from_other_origin_is_refused() {
    unimplemented!("P-01: write this test when it is unblocked");
}

/// P-02: see `docs/security/properties.md`. Request-layer level; reading the credentials from
/// the bus is the D-Bus layer's job, which passes `Caller { uid: None }` when it cannot.
#[test]
fn caller_without_peer_credentials_is_refused() {
    let mut api = Api::new(Config::new(vec![990]));
    let id = PromptId::derive("test", "p1", "s1").as_str().to_string();
    let root = Caller { uid: Some(0) };
    let user = Caller { uid: Some(1000) };
    let nobody = Caller { uid: None };
    assert_eq!(api.open_prompt(root, &id, Some(1000)), Ok(()));

    // Every operation refuses a caller whose credentials could not be read.
    assert_eq!(
        api.open_prompt(nobody, &id, Some(1000)),
        Err(ApiError::Denied)
    );
    assert_eq!(
        api.report_state(nobody, &id, "State", &["scanning"]),
        Err(ApiError::Denied)
    );
    assert_eq!(api.get_state(nobody, &id), Err(ApiError::Denied));
    assert_eq!(api.subscribe(nobody, ":1.1", &id), Err(ApiError::Denied));
    assert_eq!(api.close_prompt(nobody, &id), Err(ApiError::Denied));

    // Nothing changed: the prompt is as it was and its opener still controls it.
    let reply = api.get_state(user, &id).unwrap();
    assert_eq!(reply.state, "idle");
    assert!(reply.methods.is_empty());
    assert_eq!(reply.result, None);
    assert_eq!(api.close_prompt(root, &id), Ok(()));
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

/// P-13: see `docs/security/properties.md`. Covers the five audit events that exist today (denied, limit
/// reached, invalid argument, user policy set and removed); it claims nothing about unlock, signature,
/// PIN change or reset.
#[test]
fn secrets_never_appear_in_logs_errors_or_audit() {
    use linuxhello_agent::audit::Event;

    // No `Event` constructor takes text from a caller, so a PIN, a policy text or an argument cannot
    // reach the journal: the only thing a caller can influence is the numeric uid. Two uids show it:
    // the records of one kind differ in `LH_UID` and nowhere else.
    let uid: u32 = 4_242_424;
    let other: u32 = 7;
    let pairs = [
        (Event::denied(Some(uid)), Event::denied(Some(other))),
        (
            Event::limit_reached(Some(uid)),
            Event::limit_reached(Some(other)),
        ),
        (
            Event::invalid_argument(Some(uid)),
            Event::invalid_argument(Some(other)),
        ),
        (Event::user_policy_set(uid), Event::user_policy_set(other)),
        (
            Event::user_policy_removed(uid),
            Event::user_policy_removed(other),
        ),
    ];
    let names = [
        "PRIORITY",
        "SYSLOG_IDENTIFIER",
        "MESSAGE_ID",
        "LH_EVENT",
        "LH_UID",
        "LH_OUTCOME",
        "MESSAGE",
    ];
    // Text a caller could send; none of it can be handed to an `Event`, so none of it may appear.
    let probes = [
        "1234",
        "caller-text",
        "pin=",
        "[context.",
        "methods",
        "reverify_after",
    ];

    for (event, same_kind) in &pairs {
        let fields = event.fields();
        for (name, value) in &fields {
            assert!(names.contains(name), "unexpected audit field {name}");
            assert!(!value.contains('\n'), "newline in audit field {name}");
            for probe in probes {
                assert!(
                    !value.contains(probe),
                    "caller text {probe:?} found in audit field {name}"
                );
            }
        }
        let without_uid = |fields: Vec<(&'static str, String)>| -> Vec<(&'static str, String)> {
            fields
                .into_iter()
                .filter(|(name, _)| *name != "LH_UID")
                .collect()
        };
        assert_eq!(
            without_uid(fields),
            without_uid(same_kind.fields()),
            "a record differs by more than the uid"
        );
    }
}

/// P-14: see `docs/security/properties.md`.
#[test]
fn one_users_failed_pins_cannot_lock_out_another_user() {
    let mut lock = PinLock::new(3, 60, 3600);
    assert_eq!(lock.record_failure(1000, 100), 0);
    assert_eq!(lock.record_failure(1000, 100), 0);
    assert_eq!(lock.record_failure(1000, 100), 60);
    assert!(lock.check(1000, 100).is_err());
    // Another user is not affected, and can record a failure of their own unrefused.
    assert_eq!(lock.check(2000, 100), Ok(()));
    assert_eq!(lock.record_failure(2000, 100), 0);
    assert_eq!(lock.check(2000, 100), Ok(()));
    // A correct PIN resets the locked user.
    lock.record_pin_success(1000);
    assert_eq!(lock.check(1000, 100), Ok(()));
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

/// P-27: see `docs/security/properties.md`. Partially unblocked: the events listed there that exist today
/// (denied, limit reached, invalid argument, user policy set and removed). The remaining events (unlock,
/// signature, PIN change, reset) are the "later" set of the original issue and are covered by no test here
/// until they exist.
#[test]
fn every_unlock_signature_pin_change_and_reset_is_audited() {
    use linuxhello_agent::audit::Event;

    let uid: u32 = 4_242_424;
    let events = [
        Event::denied(Some(uid)),
        Event::limit_reached(Some(uid)),
        Event::invalid_argument(Some(uid)),
        Event::user_policy_set(uid),
        Event::user_policy_removed(uid),
    ];
    let mut seen = Vec::new();
    for event in &events {
        let fields = event.fields();
        let get = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
        };
        let kind = get("LH_EVENT").expect("every record names its event");
        assert!(!kind.is_empty());
        assert!(get("LH_OUTCOME").is_some_and(|v| !v.is_empty()));
        assert_eq!(
            get("LH_UID"),
            Some(uid.to_string()),
            "{kind} does not carry the uid"
        );
        seen.push(kind);
    }
    // Each event is audited as itself: five different words.
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), events.len());
    // A record without a uid says so by omitting the field.
    assert!(Event::denied(None)
        .fields()
        .iter()
        .all(|(n, _)| *n != "LH_UID"));
}
