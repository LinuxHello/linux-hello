//! What a client does when the Agent restarts.
//!
//! The Agent keeps its prompts in memory (ADR-0014). When it stops, every prompt and every
//! subscription is gone, and the bus tells clients with `NameOwnerChanged` for the Agent's name.
//! The one rule: **a client that sees the name appear again after it vanished, or change owner,
//! reopens its prompt (if it is the opener) and subscribes again**; it does not assume that
//! anything survived. [`Reconnect`] applies that rule to the signal and says which calls to make,
//! so every client does the same and tests it the same way
//! (`a_restart_of_the_agent_is_followed_by_a_reopen`). It makes no call and holds no connection.
//!
//! A subscriber cannot subscribe to a prompt that is not open yet: the opener reopens it first,
//! so a refused `Subscribe` is retried after [`retry_delay`] until the prompt is back or the
//! client gives up. The notes for client authors are in `docs/architecture/agent-restart.md`.
//!
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::time::Duration;

use crate::AGENT_BUS_NAME;

/// Which side of a prompt a client is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The client that opened the prompt, such as the PAM module.
    Opener,
    /// A client that only follows a prompt, such as the prompt component.
    Subscriber,
}

/// A call the client makes, in the order given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// `OpenPrompt` with the same prompt id and subject as the first time.
    Open,
    /// `Subscribe` to the prompt.
    Subscribe,
}

/// The restart rule for one prompt of one client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reconnect {
    /// The side of the prompt this client is.
    role: Role,
    /// Whether the client subscribed to the prompt.
    subscribed: bool,
    /// The Agent's name vanished and has not come back.
    lost: bool,
    /// The prompt ended; nothing is reopened.
    ended: bool,
}

impl Reconnect {
    /// The rule for a client in `role`, which has `subscribed` to the prompt or not.
    pub const fn new(role: Role, subscribed: bool) -> Self {
        Self {
            role,
            subscribed,
            lost: false,
            ended: false,
        }
    }

    /// The client subscribed to the prompt.
    pub fn note_subscribed(&mut self) {
        self.subscribed = true;
    }

    /// The prompt ended (closed by the client, or told `Closed`): a restart afterwards reopens
    /// nothing (`a_prompt_that_ended_is_not_reopened`).
    pub fn note_ended(&mut self) {
        self.ended = true;
    }

    /// Applies a `NameOwnerChanged(name, old_owner, new_owner)` signal; an empty owner is none.
    /// Returns the calls to make now, in order.
    pub fn on_name_owner_changed(&mut self, name: &str, old: &str, new: &str) -> Vec<Step> {
        if name != AGENT_BUS_NAME || self.ended {
            return Vec::new();
        }
        if new.is_empty() {
            // The Agent went away: whatever it held is gone.
            self.lost = true;
            return Vec::new();
        }
        // A new owner. It is a restart if the name vanished before, or changed hands directly;
        // the first appearance of the Agent is not (`the_first_appearance_of_the_agent_is_not_a_restart`).
        let restart = self.lost || !old.is_empty();
        self.lost = false;
        if !restart {
            return Vec::new();
        }
        match (self.role, self.subscribed) {
            (Role::Opener, true) => vec![Step::Open, Step::Subscribe],
            (Role::Opener, false) => vec![Step::Open],
            (Role::Subscriber, _) => vec![Step::Subscribe],
        }
    }
}

/// How long to wait before the `attempt`-th retry of a refused `Subscribe` (from 0): 250 ms,
/// doubling, at most five seconds (`retry_delay_grows_and_stops_at_five_seconds`).
pub fn retry_delay(attempt: u32) -> Duration {
    let millis = 250_u64.saturating_mul(1_u64 << attempt.min(5));
    Duration::from_millis(millis.min(5_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = ":1.7";
    const NEW: &str = ":1.9";

    #[test]
    fn a_restart_of_the_agent_is_followed_by_a_reopen() {
        let mut opener = Reconnect::new(Role::Opener, true);
        // The Agent stops: nothing to do yet, the name is gone.
        assert_eq!(
            opener.on_name_owner_changed(AGENT_BUS_NAME, OLD, ""),
            vec![]
        );
        // It comes back: open the prompt again, then subscribe again, in that order.
        assert_eq!(
            opener.on_name_owner_changed(AGENT_BUS_NAME, "", NEW),
            vec![Step::Open, Step::Subscribe]
        );
        // The next restart is handled the same way.
        assert_eq!(
            opener.on_name_owner_changed(AGENT_BUS_NAME, NEW, ""),
            vec![]
        );
        assert_eq!(
            opener.on_name_owner_changed(AGENT_BUS_NAME, "", OLD),
            vec![Step::Open, Step::Subscribe]
        );
        // An opener that never subscribed only reopens.
        let mut bare = Reconnect::new(Role::Opener, false);
        bare.on_name_owner_changed(AGENT_BUS_NAME, OLD, "");
        assert_eq!(
            bare.on_name_owner_changed(AGENT_BUS_NAME, "", NEW),
            vec![Step::Open]
        );
        bare.note_subscribed();
        bare.on_name_owner_changed(AGENT_BUS_NAME, NEW, "");
        assert_eq!(
            bare.on_name_owner_changed(AGENT_BUS_NAME, "", OLD),
            vec![Step::Open, Step::Subscribe]
        );
        // A change of owner without a gap in between is a restart too.
        let mut direct = Reconnect::new(Role::Opener, true);
        assert_eq!(
            direct.on_name_owner_changed(AGENT_BUS_NAME, OLD, NEW),
            vec![Step::Open, Step::Subscribe]
        );
    }

    #[test]
    fn a_subscriber_only_resubscribes() {
        let mut follower = Reconnect::new(Role::Subscriber, true);
        follower.on_name_owner_changed(AGENT_BUS_NAME, OLD, "");
        assert_eq!(
            follower.on_name_owner_changed(AGENT_BUS_NAME, "", NEW),
            vec![Step::Subscribe]
        );
    }

    #[test]
    fn the_first_appearance_of_the_agent_is_not_a_restart() {
        let mut opener = Reconnect::new(Role::Opener, true);
        assert_eq!(
            opener.on_name_owner_changed(AGENT_BUS_NAME, "", OLD),
            vec![]
        );
    }

    #[test]
    fn another_name_is_ignored() {
        let mut opener = Reconnect::new(Role::Opener, true);
        assert_eq!(
            opener.on_name_owner_changed("org.example.Other", OLD, ""),
            vec![]
        );
        assert_eq!(
            opener.on_name_owner_changed("org.example.Other", "", NEW),
            vec![]
        );
        // And it did not count as the Agent vanishing.
        assert_eq!(
            opener.on_name_owner_changed(AGENT_BUS_NAME, "", NEW),
            vec![]
        );
    }

    #[test]
    fn a_prompt_that_ended_is_not_reopened() {
        let mut opener = Reconnect::new(Role::Opener, true);
        opener.on_name_owner_changed(AGENT_BUS_NAME, OLD, "");
        opener.note_ended();
        assert_eq!(
            opener.on_name_owner_changed(AGENT_BUS_NAME, "", NEW),
            vec![]
        );
    }

    #[test]
    fn retry_delay_grows_and_stops_at_five_seconds() {
        let millis: Vec<u128> = (0..8).map(|n| retry_delay(n).as_millis()).collect();
        assert_eq!(millis, [250, 500, 1000, 2000, 4000, 5000, 5000, 5000]);
        assert_eq!(retry_delay(u32::MAX), Duration::from_secs(5));
    }
}
