//! The state of one sign-in attempt as the Auth Prompt reads it, folded from what the Agent says
//! about the prompt: its reply to `GetState` and its signals `MethodsAvailable`, `ActiveMethods`,
//! `State`, `Result` and `MethodEnded` (ADR-0014 and its amendments of 2026-11-22). The result is
//! the object documented at the top of the Auth Prompt's `prompt.js`, as JSON. No Qt and no bus
//! here, so the rules are tested on their own (`fold/tests.rs`).

use std::collections::BTreeMap;

use linuxhello_dbus::AuthMethod;

/// One thing the Agent said about the prompt, or about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The Agent answered `Ping`, or did not.
    Reachable(bool),
    /// A new prompt is followed: everything of the earlier one is forgotten.
    Started(String),
    /// The reply to `GetState`: available, active, state, result, reason, seconds.
    Snapshot(Vec<String>, Vec<String>, String, String, String, u32),
    /// `MethodsAvailable`.
    Methods(Vec<String>),
    /// `ActiveMethods`.
    Active(Vec<String>),
    /// `State`.
    State(String),
    /// `Result`: result, reason, seconds until another PIN may be tried.
    Result(String, String, u32),
    /// `MethodEnded`: method, outcome, reason, seconds of a lockout.
    MethodEnded(String, String, String, u32),
}

/// What the Auth Prompt shows for the followed prompt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PromptView {
    /// The followed prompt's id, once there is one.
    pub prompt: Option<String>,
    /// Whether the Agent answered its last ping.
    pub reachable: bool,
    /// The methods the attempt can use.
    pub available: Vec<String>,
    /// The methods running now.
    pub active: Vec<String>,
    /// `idle`, `scanning` or `waiting-for-input`.
    pub state: String,
    /// How each ended method ended, in the Auth Prompt's words.
    pub outcomes: BTreeMap<String, String>,
    /// How the attempt ended; empty while it runs.
    pub result: String,
    /// Why, from the Agent's closed set.
    pub reason: String,
    /// Seconds until another PIN may be tried, during a lockout.
    pub retry_after: u32,
}

/// Only the method names of the closed set (`pin`, `fingerprint`, `face`) pass.
fn methods(list: Vec<String>) -> Vec<String> {
    list.into_iter()
        .filter(|m| AuthMethod::from_wire(m).is_some())
        .collect()
}

/// The Auth Prompt's word for how `method` ended with `outcome` (see `prompt.js`): a failed PIN is
/// a wrong PIN, a failed fingerprint or face is not recognised. An outcome the Agent adds later is
/// a failure, as the ADR says a client must treat it.
fn outcome_word(method: &str, outcome: &str) -> &'static str {
    match (method, outcome) {
        (_, "matched") => "matched",
        (_, "unavailable") => "unavailable",
        (_, "locked-out") => "locked",
        ("pin", _) => "wrong-pin",
        _ => "not-recognised",
    }
}

impl PromptView {
    /// Applies one event (`a_new_prompt_forgets_the_last`, `each_signal_changes_its_field`).
    pub fn apply(&mut self, event: Event) {
        match event {
            Event::Reachable(answered) => self.reachable = answered,
            Event::Started(prompt) => {
                *self = Self {
                    prompt: Some(prompt),
                    reachable: self.reachable,
                    ..Self::default()
                }
            }
            Event::Snapshot(available, active, state, result, reason, seconds) => {
                self.available = methods(available);
                self.active = methods(active);
                self.state = state;
                self.result = result;
                self.reason = reason;
                self.retry_after = seconds;
            }
            Event::Methods(list) => self.available = methods(list),
            Event::Active(list) => self.active = methods(list),
            Event::State(state) => self.state = state,
            Event::Result(result, reason, seconds) => {
                self.result = result;
                self.reason = reason;
                self.retry_after = seconds;
            }
            Event::MethodEnded(method, outcome, _reason, seconds) => {
                if AuthMethod::from_wire(&method).is_none() {
                    return;
                }
                if outcome == "locked-out" {
                    self.retry_after = seconds;
                }
                let word = outcome_word(&method, &outcome);
                self.outcomes.insert(method, word.to_string());
            }
        }
    }

    /// The state object of the Auth Prompt, as JSON (`the_json_is_the_auth_prompts_contract`). The
    /// screen adds `purpose` and the conditions it knows.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "reachable": self.reachable,
            "available": self.available,
            "active": self.active,
            "state": self.state,
            "outcomes": self.outcomes,
            "result": self.result,
            "reason": self.reason,
            "retryAfter": self.retry_after,
            "conditions": [],
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests;
