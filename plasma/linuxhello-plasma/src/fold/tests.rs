//! Tests of the folding of the Agent's signals into the Auth Prompt's state.

use super::*;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_string()).collect()
}

fn started() -> PromptView {
    let mut view = PromptView::default();
    view.apply(Event::Reachable(true));
    view.apply(Event::Started("p1".into()));
    view
}

#[test]
fn a_new_prompt_forgets_the_last() {
    let mut view = started();
    view.apply(Event::Active(s(&["pin"])));
    view.apply(Event::MethodEnded(
        "pin".into(),
        "failed".into(),
        "not-recognised".into(),
        0,
    ));
    view.apply(Event::Started("p2".into()));
    assert_eq!(view.prompt.as_deref(), Some("p2"));
    assert!(view.active.is_empty() && view.outcomes.is_empty());
    assert!(
        view.reachable,
        "whether the Agent answers is not the prompt's"
    );
}

#[test]
fn each_signal_changes_its_field() {
    let mut view = started();
    view.apply(Event::Snapshot(
        s(&["pin", "fingerprint", "face"]),
        s(&["pin", "fingerprint", "face"]),
        "scanning".into(),
        String::new(),
        String::new(),
        0,
    ));
    assert_eq!(view.available, s(&["pin", "fingerprint", "face"]));
    view.apply(Event::Active(s(&["fingerprint", "face"])));
    assert_eq!(view.active, s(&["fingerprint", "face"]));
    view.apply(Event::State("waiting-for-input".into()));
    assert_eq!(view.state, "waiting-for-input");
    view.apply(Event::Result("locked-out".into(), String::new(), 720));
    assert_eq!(
        (view.result.as_str(), view.retry_after),
        ("locked-out", 720)
    );
}

#[test]
fn how_a_method_ended_is_said_in_the_auth_prompts_words() {
    let mut view = started();
    for (method, outcome, seconds) in [
        ("pin", "failed", 0),
        ("fingerprint", "failed", 0),
        ("face", "unavailable", 0),
    ] {
        view.apply(Event::MethodEnded(
            method.into(),
            outcome.into(),
            String::new(),
            seconds,
        ));
    }
    assert_eq!(view.outcomes["pin"], "wrong-pin");
    assert_eq!(view.outcomes["fingerprint"], "not-recognised");
    assert_eq!(view.outcomes["face"], "unavailable");
    view.apply(Event::MethodEnded(
        "fingerprint".into(),
        "matched".into(),
        String::new(),
        0,
    ));
    assert_eq!(view.outcomes["fingerprint"], "matched");
    view.apply(Event::MethodEnded(
        "pin".into(),
        "locked-out".into(),
        String::new(),
        600,
    ));
    assert_eq!(
        (view.outcomes["pin"].as_str(), view.retry_after),
        ("locked", 600)
    );
    // An outcome the Agent adds later counts as a failure.
    view.apply(Event::MethodEnded(
        "face".into(),
        "something-new".into(),
        String::new(),
        0,
    ));
    assert_eq!(view.outcomes["face"], "not-recognised");
}

#[test]
fn a_method_outside_the_closed_set_is_ignored() {
    let mut view = started();
    view.apply(Event::Active(s(&["pin", "iris"])));
    assert_eq!(view.active, s(&["pin"]));
    view.apply(Event::MethodEnded(
        "iris".into(),
        "matched".into(),
        String::new(),
        0,
    ));
    assert!(view.outcomes.is_empty());
}

#[test]
fn the_json_is_the_auth_prompts_contract() {
    let mut view = started();
    view.apply(Event::Methods(s(&["pin"])));
    view.apply(Event::MethodEnded(
        "pin".into(),
        "failed".into(),
        "not-recognised".into(),
        0,
    ));
    let json: serde_json::Value = serde_json::from_str(&view.to_json()).unwrap();
    assert_eq!(json["reachable"], true);
    assert_eq!(json["available"], serde_json::json!(["pin"]));
    assert_eq!(json["outcomes"]["pin"], "wrong-pin");
    assert_eq!(json["retryAfter"], 0);
    assert_eq!(json["conditions"], serde_json::json!([]));
    for key in ["active", "state", "result", "reason"] {
        assert!(json.get(key).is_some(), "{key}");
    }
}
