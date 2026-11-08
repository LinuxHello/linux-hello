//! The Agent's per-prompt state store and the access rules around it.
//!
//! A prompt is one authentication attempt shown by one host (a login manager, the lock
//! screen, a `sudo` conversation). The PAM module opens it and reports the live state; the
//! prompt component reads it. The store decides who may do what, as ADR-0014 requires: only
//! the PAM module of the user being authenticated (root, or the user's own uid) can open a
//! prompt for that user; only the opener can change or close it; only the opener, the
//! subject user and the configured prompt-host users can read it or be told about changes;
//! a refusal looks the same whether the prompt exists or not; and no user can fill the store.
//!
//! The store takes the caller's uid as an argument. The D-Bus layer reads it from the bus
//! peer credentials; the store never trusts a uid that came inside a message. It sends
//! nothing itself: [`StateStore::report`] returns the peers that must be told, and the D-Bus
//! layer sends each one a unicast signal (no broadcast, see `linuxhello_dbus::SIGNALS`).
//!
//! Security properties: `unprivileged_process_cannot_publish_method_state_for_another_user`
//! (P-04) and `method_state_is_not_broadcast_to_other_users` (P-05).
//!
//! C4 component: `authState` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

use std::collections::HashMap;

use linuxhello_dbus::{AuthMethod, PromptId, PromptResult, PromptState};

/// Settings of a [`StateStore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Uids of the users that show prompts for others, such as the login manager's greeter
    /// user. They may read and subscribe to any prompt.
    pub prompt_hosts: Vec<u32>,
    /// How many prompts one opener may have open at the same time.
    pub max_prompts_per_reporter: usize,
    /// How many distinct peers may subscribe to one prompt.
    pub max_subscribers_per_prompt: usize,
}

impl Config {
    /// A configuration with the given prompt hosts and the default limits: 64 prompts per
    /// opener and 16 subscribers per prompt.
    pub fn new(prompt_hosts: Vec<u32>) -> Self {
        Self {
            prompt_hosts,
            max_prompts_per_reporter: 64,
            max_subscribers_per_prompt: 16,
        }
    }
}

/// A D-Bus peer that wants the signals of a prompt: its unique bus name, such as `:1.42`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Peer(pub String);

/// Why the store refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The caller may not do this, or the prompt is unknown. The two cases give the same
    /// value, so a refusal does not tell whether the prompt exists.
    Denied,
    /// A limit of the [`Config`] is reached.
    LimitReached,
}

/// One change to a prompt's state, in the terms of the signals of `linuxhello_dbus::SIGNALS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Update {
    /// The methods that can be used now.
    Methods(Vec<AuthMethod>),
    /// The method that is running, or none.
    Active(Option<AuthMethod>),
    /// What the prompt is doing.
    State(PromptState),
    /// How the attempt ended.
    Result(PromptResult),
}

/// The state of a prompt at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The methods that can be used now.
    pub methods: Vec<AuthMethod>,
    /// The method that is running, or none.
    pub active: Option<AuthMethod>,
    /// What the prompt is doing.
    pub state: PromptState,
    /// How the attempt ended, once it has.
    pub result: Option<PromptResult>,
}

impl Snapshot {
    /// The state of a prompt that has just been opened: nothing available, nothing running.
    fn initial() -> Self {
        Self {
            methods: Vec::new(),
            active: None,
            state: PromptState::Idle,
            result: None,
        }
    }
}

/// A prompt and who may do what with it.
struct Entry {
    /// The uid that opened the prompt. Only it may report on it or close it.
    owner: u32,
    /// The user being authenticated, when known.
    subject: Option<u32>,
    /// The current state.
    snapshot: Snapshot,
    /// The peers to tell about changes, each once, in subscription order.
    subscribers: Vec<Peer>,
}

/// The per-prompt state of the Agent, with the access rules of ADR-0014.
pub struct StateStore {
    /// The limits and the prompt hosts.
    config: Config,
    /// Every open prompt.
    prompts: HashMap<PromptId, Entry>,
}

impl StateStore {
    /// An empty store.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            prompts: HashMap::new(),
        }
    }

    /// Whether `uid` may read the prompt or be told about it: the opener, the subject user,
    /// or a configured prompt host.
    fn may_read(&self, entry: &Entry, uid: u32) -> bool {
        uid == entry.owner || Some(uid) == entry.subject || self.config.prompt_hosts.contains(&uid)
    }

    /// Opens a prompt for `subject_uid`, owned by `reporter_uid`.
    ///
    /// # Errors
    ///
    /// [`Error::Denied`] if `reporter_uid` is neither root nor the subject user, or if the
    /// prompt is already open (by anyone). [`Error::LimitReached`] if `reporter_uid` already
    /// owns `max_prompts_per_reporter` prompts.
    pub fn open(
        &mut self,
        reporter_uid: u32,
        prompt: &PromptId,
        subject_uid: Option<u32>,
    ) -> Result<(), Error> {
        if reporter_uid != 0 && Some(reporter_uid) != subject_uid {
            return Err(Error::Denied);
        }
        if self.prompts.contains_key(prompt) {
            return Err(Error::Denied);
        }
        let owned = self
            .prompts
            .values()
            .filter(|e| e.owner == reporter_uid)
            .count();
        if owned >= self.config.max_prompts_per_reporter {
            return Err(Error::LimitReached);
        }
        self.prompts.insert(
            prompt.clone(),
            Entry {
                owner: reporter_uid,
                subject: subject_uid,
                snapshot: Snapshot::initial(),
                subscribers: Vec::new(),
            },
        );
        Ok(())
    }

    /// Applies `update` to the prompt and returns the peers to tell, each once, in the order
    /// they subscribed. The caller sends each one a unicast signal.
    ///
    /// # Errors
    ///
    /// [`Error::Denied`] unless `reporter_uid` opened the prompt.
    pub fn report(
        &mut self,
        reporter_uid: u32,
        prompt: &PromptId,
        update: Update,
    ) -> Result<Vec<Peer>, Error> {
        let entry = match self.prompts.get_mut(prompt) {
            Some(entry) if entry.owner == reporter_uid => entry,
            _ => return Err(Error::Denied),
        };
        match update {
            Update::Methods(methods) => entry.snapshot.methods = methods,
            Update::Active(active) => entry.snapshot.active = active,
            Update::State(state) => entry.snapshot.state = state,
            Update::Result(result) => entry.snapshot.result = Some(result),
        }
        Ok(entry.subscribers.clone())
    }

    /// The current state of the prompt.
    ///
    /// # Errors
    ///
    /// [`Error::Denied`] unless `reader_uid` is the opener, the subject user or a prompt
    /// host, and also when the prompt does not exist.
    pub fn get(&self, reader_uid: u32, prompt: &PromptId) -> Result<Snapshot, Error> {
        match self.prompts.get(prompt) {
            Some(entry) if self.may_read(entry, reader_uid) => Ok(entry.snapshot.clone()),
            _ => Err(Error::Denied),
        }
    }

    /// Adds `peer` to the peers told about changes to the prompt. Subscribing the same peer
    /// again changes nothing.
    ///
    /// # Errors
    ///
    /// [`Error::Denied`] under the same rule as [`StateStore::get`]. [`Error::LimitReached`]
    /// if a new distinct peer would exceed `max_subscribers_per_prompt`.
    pub fn subscribe(
        &mut self,
        reader_uid: u32,
        peer: Peer,
        prompt: &PromptId,
    ) -> Result<(), Error> {
        let allowed = match self.prompts.get(prompt) {
            Some(entry) => self.may_read(entry, reader_uid),
            None => false,
        };
        if !allowed {
            return Err(Error::Denied);
        }
        let limit = self.config.max_subscribers_per_prompt;
        let entry = self.prompts.get_mut(prompt).ok_or(Error::Denied)?;
        if entry.subscribers.contains(&peer) {
            return Ok(());
        }
        if entry.subscribers.len() >= limit {
            return Err(Error::LimitReached);
        }
        entry.subscribers.push(peer);
        Ok(())
    }

    /// Closes the prompt and forgets its state and subscribers. The id can be opened again.
    ///
    /// # Errors
    ///
    /// [`Error::Denied`] unless `reporter_uid` opened the prompt.
    pub fn close(&mut self, reporter_uid: u32, prompt: &PromptId) -> Result<(), Error> {
        match self.prompts.get(prompt) {
            Some(entry) if entry.owner == reporter_uid => {
                self.prompts.remove(prompt);
                Ok(())
            }
            _ => Err(Error::Denied),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A prompt id for a test, from a short name.
    fn pid(name: &str) -> PromptId {
        PromptId::derive("test", name, "s1")
    }

    /// A configuration with the given limits and the prompt host 990.
    fn limited(prompts: usize, subscribers: usize) -> Config {
        let mut config = Config::new(vec![990]);
        config.max_prompts_per_reporter = prompts;
        config.max_subscribers_per_prompt = subscribers;
        config
    }

    #[test]
    fn prompt_cannot_be_hijacked_by_reopening() {
        let mut store = StateStore::new(Config::new(vec![]));
        let id = pid("p1");
        assert_eq!(store.open(1000, &id, Some(1000)), Ok(()));
        assert_eq!(store.open(1000, &id, Some(1000)), Err(Error::Denied));
        assert_eq!(store.open(1001, &id, Some(1001)), Err(Error::Denied));
        assert_eq!(store.open(0, &id, Some(1000)), Err(Error::Denied));
        // The first opener still controls it.
        assert!(store
            .report(1000, &id, Update::State(PromptState::Scanning))
            .is_ok());
        assert_eq!(
            store.report(1001, &id, Update::State(PromptState::Idle)),
            Err(Error::Denied)
        );
    }

    #[test]
    fn reporter_cannot_exceed_its_prompt_limit() {
        let mut store = StateStore::new(limited(2, 16));
        assert_eq!(store.open(1000, &pid("p1"), Some(1000)), Ok(()));
        assert_eq!(store.open(1000, &pid("p2"), Some(1000)), Ok(()));
        assert_eq!(
            store.open(1000, &pid("p3"), Some(1000)),
            Err(Error::LimitReached)
        );
        // Another opener is not affected.
        assert_eq!(store.open(1001, &pid("po"), Some(1001)), Ok(()));
        // Closing one makes room.
        assert_eq!(store.close(1000, &pid("p1")), Ok(()));
        assert_eq!(store.open(1000, &pid("p3"), Some(1000)), Ok(()));
    }

    #[test]
    fn subscriber_limit_is_enforced() {
        let mut store = StateStore::new(limited(64, 2));
        let id = pid("p1");
        store.open(1000, &id, Some(1000)).unwrap();
        assert_eq!(store.subscribe(1000, Peer(":1.1".into()), &id), Ok(()));
        assert_eq!(store.subscribe(1000, Peer(":1.2".into()), &id), Ok(()));
        assert_eq!(
            store.subscribe(1000, Peer(":1.3".into()), &id),
            Err(Error::LimitReached)
        );
        // A peer that is already subscribed is not a new one.
        assert_eq!(store.subscribe(1000, Peer(":1.2".into()), &id), Ok(()));
    }

    #[test]
    fn duplicate_subscription_notifies_once() {
        let mut store = StateStore::new(Config::new(vec![]));
        let id = pid("p1");
        store.open(1000, &id, Some(1000)).unwrap();
        let peer = Peer(":1.1".into());
        assert_eq!(store.subscribe(1000, peer.clone(), &id), Ok(()));
        assert_eq!(store.subscribe(1000, peer.clone(), &id), Ok(()));
        let told = store
            .report(1000, &id, Update::State(PromptState::Scanning))
            .unwrap();
        assert_eq!(told, vec![peer]);
    }

    #[test]
    fn closed_prompt_is_gone() {
        let mut store = StateStore::new(Config::new(vec![]));
        let id = pid("p1");
        store.open(1000, &id, Some(1000)).unwrap();
        assert_eq!(store.close(1001, &id), Err(Error::Denied));
        assert_eq!(store.close(1000, &id), Ok(()));
        assert_eq!(store.get(1000, &id), Err(Error::Denied));
        assert_eq!(store.close(1000, &id), Err(Error::Denied));
        // The id can be opened again, with a fresh state.
        assert_eq!(store.open(1000, &id, Some(1000)), Ok(()));
        assert_eq!(store.get(1000, &id).unwrap(), Snapshot::initial());
    }

    #[test]
    fn prompt_without_subject_is_visible_only_to_hosts_and_opener() {
        let mut store = StateStore::new(Config::new(vec![990]));
        let id = pid("p1");
        store.open(0, &id, None).unwrap();
        assert_eq!(store.get(1000, &id), Err(Error::Denied));
        assert!(store.get(990, &id).is_ok());
        assert!(store.get(0, &id).is_ok());
    }

    #[test]
    fn snapshot_follows_updates() {
        let mut store = StateStore::new(Config::new(vec![]));
        let id = pid("p1");
        store.open(1000, &id, Some(1000)).unwrap();
        assert_eq!(store.get(1000, &id).unwrap(), Snapshot::initial());
        let steps = [
            Update::Methods(vec![AuthMethod::Face, AuthMethod::Pin]),
            Update::Active(Some(AuthMethod::Face)),
            Update::State(PromptState::Scanning),
            Update::Result(PromptResult::Failure),
        ];
        for step in steps {
            store.report(1000, &id, step).unwrap();
        }
        let snapshot = store.get(1000, &id).unwrap();
        assert_eq!(snapshot.methods, vec![AuthMethod::Face, AuthMethod::Pin]);
        assert_eq!(snapshot.active, Some(AuthMethod::Face));
        assert_eq!(snapshot.state, PromptState::Scanning);
        assert_eq!(snapshot.result, Some(PromptResult::Failure));
    }
}
