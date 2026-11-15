//! The Agent's per-prompt state store and the access rules around it.
//!
//! A prompt is one authentication attempt shown by one host (a login manager, the lock
//! screen, a `sudo` conversation). The PAM module opens it and reports the live state; the
//! prompt component reads it. The store decides who may do what, as ADR-0014 requires: only
//! the PAM module of the user being authenticated (root, or the user's own uid) can open a
//! prompt for that user; only the opener can change or close it; only the opener, and for a
//! prompt that root opened the subject user and the configured prompt-host users, can read
//! it or be told about changes; a refusal looks the same whether the prompt exists or not;
//! and no user can fill the store.
//!
//! Prompts are kept per opener: the same id opened by two uids is two prompts. An
//! unprivileged user who guesses the id of a login prompt and opens it first therefore
//! neither blocks root's prompt nor is read by a prompt host, and learns nothing about
//! whether it exists (`user_cannot_block_roots_prompt_by_opening_its_id_first`,
//! `prompt_host_never_reads_state_published_by_an_unprivileged_squatter`,
//! `open_does_not_reveal_whether_a_prompt_exists`). Every process of one uid is the same
//! caller to the store: it cannot tell the PAM module from another process of that user.
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
    /// The user being authenticated, when known.
    subject: Option<u32>,
    /// The unique bus name of the connection that opened the prompt, when it was opened with
    /// [`StateStore::open_named`].
    opener: Option<Peer>,
    /// The current state.
    snapshot: Snapshot,
    /// The peers to tell about changes, each once, in subscription order.
    subscribers: Vec<Peer>,
}

/// The per-prompt state of the Agent, with the access rules of ADR-0014.
pub struct StateStore {
    /// The limits and the prompt hosts.
    config: Config,
    /// Every open prompt, by the uid that opened it and its id.
    prompts: HashMap<(u32, PromptId), Entry>,
}

impl StateStore {
    /// An empty store.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            prompts: HashMap::new(),
        }
    }

    /// The key of the prompt with this id that `uid` may read or be told about: its own,
    /// or else the one root opened if `uid` is its subject user or a configured prompt
    /// host. A prompt opened by another unprivileged user is never found.
    fn readable(&self, uid: u32, prompt: &PromptId) -> Option<(u32, PromptId)> {
        let own = (uid, prompt.clone());
        if self.prompts.contains_key(&own) {
            return Some(own);
        }
        let roots = (0, prompt.clone());
        let entry = self.prompts.get(&roots)?;
        (Some(uid) == entry.subject || self.config.prompt_hosts.contains(&uid)).then_some(roots)
    }

    /// Opens a prompt for `subject_uid`, owned by `reporter_uid`.
    ///
    /// # Errors
    ///
    /// [`Error::Denied`] if `reporter_uid` is neither root nor the subject user, or if
    /// `reporter_uid` itself already has this prompt open; a prompt with the same id opened
    /// by another uid makes no difference. [`Error::LimitReached`] if `reporter_uid` already
    /// owns `max_prompts_per_reporter` prompts.
    pub fn open(
        &mut self,
        reporter_uid: u32,
        prompt: &PromptId,
        subject_uid: Option<u32>,
    ) -> Result<(), Error> {
        self.open_entry(reporter_uid, None, prompt, subject_uid)
    }

    /// Opens a prompt as [`StateStore::open`] does, and remembers `opener`, the unique bus
    /// name of the caller, so that [`StateStore::drop_opener`] can remove the prompt when
    /// that connection leaves the bus.
    ///
    /// # Errors
    ///
    /// The same as [`StateStore::open`].
    pub fn open_named(
        &mut self,
        reporter_uid: u32,
        opener: Peer,
        prompt: &PromptId,
        subject_uid: Option<u32>,
    ) -> Result<(), Error> {
        self.open_entry(reporter_uid, Some(opener), prompt, subject_uid)
    }

    /// The work of [`StateStore::open`] and [`StateStore::open_named`]: the permission, the
    /// duplicate and the limit rules are the same for both.
    fn open_entry(
        &mut self,
        reporter_uid: u32,
        opener: Option<Peer>,
        prompt: &PromptId,
        subject_uid: Option<u32>,
    ) -> Result<(), Error> {
        if reporter_uid != 0 && Some(reporter_uid) != subject_uid {
            return Err(Error::Denied);
        }
        let key = (reporter_uid, prompt.clone());
        if self.prompts.contains_key(&key) {
            return Err(Error::Denied);
        }
        let owned = self
            .prompts
            .keys()
            .filter(|(owner, _)| *owner == reporter_uid)
            .count();
        if owned >= self.config.max_prompts_per_reporter {
            return Err(Error::LimitReached);
        }
        self.prompts.insert(
            key,
            Entry {
                subject: subject_uid,
                opener,
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
        let Some(entry) = self.prompts.get_mut(&(reporter_uid, prompt.clone())) else {
            return Err(Error::Denied);
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
    /// [`Error::Denied`] unless `reader_uid` opened the prompt, or root opened it and
    /// `reader_uid` is its subject user or a prompt host; also when the prompt does not exist.
    pub fn get(&self, reader_uid: u32, prompt: &PromptId) -> Result<Snapshot, Error> {
        self.readable(reader_uid, prompt)
            .and_then(|key| self.prompts.get(&key))
            .map(|entry| entry.snapshot.clone())
            .ok_or(Error::Denied)
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
        let key = self.readable(reader_uid, prompt).ok_or(Error::Denied)?;
        let limit = self.config.max_subscribers_per_prompt;
        let entry = self.prompts.get_mut(&key).ok_or(Error::Denied)?;
        if entry.subscribers.contains(&peer) {
            return Ok(());
        }
        if entry.subscribers.len() >= limit {
            return Err(Error::LimitReached);
        }
        entry.subscribers.push(peer);
        Ok(())
    }

    /// Removes every prompt whose recorded opener is `opener`, with its subscribers, whatever
    /// the uid that opened it. A prompt opened with [`StateStore::open`] has no recorded
    /// opener and is never removed. Returns how many prompts it removed.
    pub fn drop_opener(&mut self, opener: &Peer) -> usize {
        let before = self.prompts.len();
        self.prompts
            .retain(|_, entry| entry.opener.as_ref() != Some(opener));
        before - self.prompts.len()
    }

    /// Removes `peer` from the subscribers of every prompt, keeping the order of the others.
    /// No prompt is closed. Returns how many subscriptions it removed.
    pub fn drop_subscriber(&mut self, peer: &Peer) -> usize {
        let mut removed = 0;
        for entry in self.prompts.values_mut() {
            let before = entry.subscribers.len();
            entry.subscribers.retain(|subscriber| subscriber != peer);
            removed += before - entry.subscribers.len();
        }
        removed
    }

    /// Closes the prompt and forgets its state and subscribers. The id can be opened again.
    ///
    /// # Errors
    ///
    /// [`Error::Denied`] unless `reporter_uid` opened the prompt.
    pub fn close(&mut self, reporter_uid: u32, prompt: &PromptId) -> Result<(), Error> {
        self.prompts
            .remove(&(reporter_uid, prompt.clone()))
            .map(|_| ())
            .ok_or(Error::Denied)
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
        // Another uid gets a prompt of its own under the same id, never this one.
        assert_eq!(store.open(1001, &id, Some(1001)), Ok(()));
        store
            .report(1001, &id, Update::State(PromptState::WaitingForInput))
            .unwrap();
        assert_eq!(store.get(1000, &id).unwrap().state, PromptState::Idle);
        assert_eq!(store.close(1001, &id), Ok(()));
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
    fn user_cannot_block_roots_prompt_by_opening_its_id_first() {
        let mut store = StateStore::new(Config::new(vec![990]));
        let id = PromptId::derive("sddm", ":0", "c1");
        // An unprivileged user guesses the id of the login prompt and opens it first.
        assert_eq!(store.open(1000, &id, Some(1000)), Ok(()));
        // Root's PAM module still opens and reports the real prompt.
        assert_eq!(store.open(0, &id, Some(1001)), Ok(()));
        assert!(store
            .report(0, &id, Update::State(PromptState::Scanning))
            .is_ok());
        assert_eq!(store.get(1001, &id).unwrap().state, PromptState::Scanning);
        // Closing the squatter's prompt leaves root's in place, and the other way round.
        assert_eq!(store.close(1000, &id), Ok(()));
        assert_eq!(store.get(1001, &id).unwrap().state, PromptState::Scanning);
    }

    #[test]
    fn prompt_host_never_reads_state_published_by_an_unprivileged_squatter() {
        let mut store = StateStore::new(Config::new(vec![990]));
        let id = PromptId::derive("sddm", ":0", "c1");
        store.open(1000, &id, Some(1000)).unwrap();
        store
            .report(1000, &id, Update::Result(PromptResult::Success))
            .unwrap();
        // Without a prompt of root's, the host sees nothing, and cannot subscribe.
        assert_eq!(store.get(990, &id), Err(Error::Denied));
        assert_eq!(
            store.subscribe(990, Peer(":1.9".into()), &id),
            Err(Error::Denied)
        );
        // With root's prompt, the host reads root's state and is told only by root.
        store.open(0, &id, Some(1001)).unwrap();
        assert_eq!(store.get(990, &id).unwrap(), Snapshot::initial());
        store.subscribe(990, Peer(":1.9".into()), &id).unwrap();
        let told = store
            .report(1000, &id, Update::State(PromptState::Scanning))
            .unwrap();
        assert!(told.is_empty());
        let told = store
            .report(0, &id, Update::State(PromptState::Scanning))
            .unwrap();
        assert_eq!(told, vec![Peer(":1.9".into())]);
        // The squatter reads only its own prompt, never root's for another subject.
        assert_eq!(
            store.get(1000, &id).unwrap().result,
            Some(PromptResult::Success)
        );
    }

    #[test]
    fn open_does_not_reveal_whether_a_prompt_exists() {
        let mut store = StateStore::new(Config::new(vec![990]));
        let taken = PromptId::derive("sddm", ":0", "c1");
        let free = PromptId::derive("sddm", ":1", "c2");
        store.open(0, &taken, Some(1001)).unwrap();
        store.open(1000, &taken, Some(1000)).unwrap();
        // A third user gets the same answer for an id in use and a free one.
        assert_eq!(
            store.open(1002, &taken, Some(1002)),
            store.open(1002, &free, Some(1002))
        );
        assert_eq!(store.get(1002, &taken), store.get(1002, &free));
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

    /// A peer with the given unique bus name.
    fn peer(name: &str) -> Peer {
        Peer(name.to_string())
    }

    #[test]
    fn prompts_of_a_disconnected_opener_are_removed() {
        let mut store = StateStore::new(Config::new(vec![990]));
        let (a, b) = (pid("a"), pid("b"));
        store.open_named(0, peer(":1.5"), &a, Some(1000)).unwrap();
        store.open_named(0, peer(":1.6"), &b, Some(1001)).unwrap();
        // One peer can have several prompts; all of them go.
        let c = pid("c");
        store.open_named(0, peer(":1.5"), &c, Some(1002)).unwrap();
        store.subscribe(1000, peer(":1.2"), &a).unwrap();
        assert_eq!(store.drop_opener(&peer(":1.5")), 2);
        assert_eq!(store.get(1002, &c), Err(Error::Denied));
        assert_eq!(store.get(1000, &a), Err(Error::Denied));
        assert_eq!(store.open_named(0, peer(":1.7"), &a, Some(1000)), Ok(()));
        assert_eq!(store.get(1000, &a), Ok(Snapshot::initial()));
        let told = store
            .report(0, &a, Update::State(PromptState::Scanning))
            .unwrap();
        assert!(told.is_empty());
        // The other root caller's prompt is untouched.
        assert!(store.get(1001, &b).is_ok());
    }

    #[test]
    fn a_leaving_opener_frees_its_place_in_the_prompt_limit() {
        let mut store = StateStore::new(limited(1, 16));
        store
            .open_named(1000, peer(":1.1"), &pid("a"), Some(1000))
            .unwrap();
        assert_eq!(
            store.open_named(1000, peer(":1.1"), &pid("b"), Some(1000)),
            Err(Error::LimitReached)
        );
        assert_eq!(store.drop_opener(&peer(":1.1")), 1);
        assert_eq!(
            store.open_named(1000, peer(":1.2"), &pid("b"), Some(1000)),
            Ok(())
        );
    }

    #[test]
    fn subscriptions_of_a_disconnected_peer_are_removed() {
        let mut store = StateStore::new(Config::new(vec![]));
        let a = pid("a");
        store.open(0, &a, Some(1000)).unwrap();
        store.subscribe(1000, peer(":1.1"), &a).unwrap();
        store.subscribe(1000, peer(":1.2"), &a).unwrap();
        assert_eq!(store.drop_subscriber(&peer(":1.1")), 1);
        let update = Update::State(PromptState::Scanning);
        assert_eq!(store.report(0, &a, update.clone()), Ok(vec![peer(":1.2")]));
        assert!(store.get(1000, &a).is_ok());
        store.subscribe(1000, peer(":1.1"), &a).unwrap();
        assert_eq!(
            store.report(0, &a, update),
            Ok(vec![peer(":1.2"), peer(":1.1")])
        );
    }

    #[test]
    fn a_leaving_subscriber_frees_its_place_in_the_subscriber_limit() {
        let mut store = StateStore::new(limited(64, 1));
        let a = pid("a");
        store.open(1000, &a, Some(1000)).unwrap();
        store.subscribe(1000, peer(":1.1"), &a).unwrap();
        assert_eq!(
            store.subscribe(1000, peer(":1.2"), &a),
            Err(Error::LimitReached)
        );
        assert_eq!(store.drop_subscriber(&peer(":1.1")), 1);
        assert_eq!(store.subscribe(1000, peer(":1.2"), &a), Ok(()));
    }

    #[test]
    fn dropping_a_peer_that_was_never_named_changes_nothing() {
        let mut store = StateStore::new(Config::new(vec![]));
        let a = pid("a");
        store.open_named(0, peer(":1.1"), &a, Some(1000)).unwrap();
        store.subscribe(1000, peer(":1.2"), &a).unwrap();
        assert_eq!(store.drop_opener(&peer(":1.9")), 0);
        assert_eq!(store.drop_subscriber(&peer(":1.9")), 0);
        assert!(store.get(1000, &a).is_ok());
        let told = store
            .report(0, &a, Update::State(PromptState::Scanning))
            .unwrap();
        assert_eq!(told, vec![peer(":1.2")]);
    }

    #[test]
    fn a_prompt_opened_with_open_has_no_bus_name_to_drop() {
        let mut store = StateStore::new(Config::new(vec![]));
        let a = pid("a");
        store.open(0, &a, Some(1000)).unwrap();
        assert_eq!(store.drop_opener(&peer(":1.1")), 0);
        assert_eq!(store.drop_opener(&peer("")), 0);
        assert!(store.get(1000, &a).is_ok());
    }

    #[test]
    fn a_peer_that_is_opener_and_subscriber_loses_both() {
        let mut store = StateStore::new(Config::new(vec![]));
        let (a, b) = (pid("a"), pid("b"));
        store.open_named(0, peer(":1.1"), &a, Some(1000)).unwrap();
        store.open_named(0, peer(":1.2"), &b, Some(1000)).unwrap();
        store.subscribe(1000, peer(":1.1"), &b).unwrap();
        assert_eq!(store.drop_opener(&peer(":1.1")), 1);
        assert_eq!(store.drop_subscriber(&peer(":1.1")), 1);
        assert!(store.get(1000, &b).is_ok());
        let told = store
            .report(0, &b, Update::State(PromptState::Scanning))
            .unwrap();
        assert!(told.is_empty());
    }
}
