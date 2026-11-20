//! The Agent's request layer for the state API: what a caller may ask, and how it is asked.
//!
//! The D-Bus glue (a later change) reads the caller's uid from the bus peer credentials and
//! calls these methods with plain text arguments. Each method first refuses a caller whose uid
//! could not be read, then validates every argument as wire strings, and only then calls the
//! [`StateStore`], so a malformed request never changes state. Answers and notifications carry
//! canonical wire strings built from the store's values, never the caller's own text.
//!
//! Security property: `caller_without_peer_credentials_is_refused` (P-02).
//!
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::collections::HashMap;
use std::sync::Arc;

use linuxhello_dbus::{AuthMethod, PromptId, PromptReason, PromptResult, PromptState, SIGNALS};

use crate::audit::{Audit, Event};
use crate::orchestrator::Cancel;
use crate::pinlock::service::{wall_clock_seconds, LockStatus, PinLockService};
use crate::pinsocket::{PinSocket, Process};
use crate::policy::load::Policy;
use crate::policy::schema::parse_layer;
use crate::policy::user_store::{StoreError, UserPolicyStore, MAX_POLICY_BYTES};
use crate::policy::MethodRule;
use crate::state::{Config, Error as StateError, Outcome, Peer, StateStore, Update};

/// The longest D-Bus bus name, in bytes.
const MAX_PEER_NAME: usize = 255;

/// Who is calling, as the bus told us.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    /// The caller's uid from the bus peer credentials, or `None` when the bus could not give
    /// it. A caller without a uid is refused.
    pub uid: Option<u32>,
    /// The unique bus name of the caller's connection, such as `:1.42`, as the bus daemon gave
    /// it (never chosen by the caller), or `None` when the message had no sender. It tells two
    /// processes of one uid apart in the audit trail; it is not an identity and decides nothing.
    pub peer: Option<PeerName>,
}

/// The longest unique bus name kept, in bytes.
const PEER_NAME_BYTES: usize = 32;

/// A unique bus name such as `:1.42`: a colon, then digits and dots, at most 32 bytes. The bus
/// daemon assigns it, and a value of this type has no other form, so no text of a caller's own
/// can travel in it (`audit_peer_is_only_ever_a_unique_bus_name`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerName {
    /// The bytes of the name; only the first `len` are in use.
    bytes: [u8; PEER_NAME_BYTES],
    /// How many bytes of `bytes` are the name.
    len: u8,
}

impl PeerName {
    /// The name, or `None` when `name` does not have the form of a unique bus name.
    pub fn new(name: &str) -> Option<Self> {
        let rest = name.strip_prefix(':')?;
        let valid = name.len() <= PEER_NAME_BYTES
            && !rest.is_empty()
            && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.');
        if !valid {
            return None;
        }
        let mut bytes = [0_u8; PEER_NAME_BYTES];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Some(Self {
            bytes,
            len: u8::try_from(name.len()).ok()?,
        })
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}

/// Why the request layer refused a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiError {
    /// The caller may not do this, has no readable credentials, or the prompt is unknown.
    Denied,
    /// A limit of the state store is reached.
    LimitReached,
    /// An argument is not valid: a prompt id, signal name, value or peer name.
    InvalidArgument,
    /// The caller's own policy text does not follow the schema. The text is the parser's message
    /// about that text (the offending key or line and what is wrong with it); it is built from the
    /// caller's text alone, never from an admin layer or another user's layer.
    InvalidPolicy(String),
    /// The requested service (e.g. user policy store) is not available.
    Unavailable,
    /// What the Agent stored for the caller cannot be read: the caller can store a new layer.
    Damaged,
}

impl From<StoreError> for ApiError {
    /// A text the store refuses (it does not parse or is too long) is an invalid argument; a store
    /// that cannot read or write its files is unavailable.
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Invalid | StoreError::TooLarge => ApiError::InvalidArgument,
            StoreError::Unavailable | StoreError::Unsynced => ApiError::Unavailable,
            StoreError::Damaged => ApiError::Damaged,
        }
    }
}

impl From<StateError> for ApiError {
    /// Maps each refusal of the store to the same refusal of the API.
    fn from(error: StateError) -> Self {
        match error {
            StateError::Denied => ApiError::Denied,
            StateError::LimitReached => ApiError::LimitReached,
        }
    }
}

/// A signal to send to one subscribed peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    /// The peer to send it to, and nobody else.
    pub peer: Peer,
    /// The signal name, from `linuxhello_dbus::SIGNALS`.
    pub signal: &'static str,
    /// The prompt it is about.
    pub prompt_id: String,
    /// The signal's values as canonical wire strings; empty when no method is active.
    pub values: Vec<String>,
}

/// The state of a prompt as wire strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateReply {
    /// The methods that can be used now.
    pub methods: Vec<String>,
    /// The methods that are running, none when the list is empty.
    pub active: Vec<String>,
    /// What the prompt is doing.
    pub state: String,
    /// How the attempt ended, once it has.
    pub result: Option<String>,
    /// Why it ended so; empty when there is nothing to add or no result yet.
    pub reason: String,
    /// Seconds until another attempt may be made; zero unless the result is `locked-out`.
    pub retry_after: u32,
}

/// An authentication that may start: who opened the prompt, for whom, by which rule.
#[derive(Debug)]
pub struct AuthStart {
    /// The user who opened the prompt, which keys it in the store.
    pub opener_uid: u32,
    /// The prompt.
    pub prompt: PromptId,
    /// The user being authenticated.
    pub subject: u32,
    /// The methods the context allows for the subject, and how many must succeed.
    pub rule: MethodRule,
    /// Set when the prompt closes; the orchestrator stops at once.
    pub stop: Cancel,
}

/// One condition of `GetStatus`, with the detail only root sees.
struct StatusItem {
    /// The code, from the closed set of `linuxhello_dbus::status`.
    code: String,
    /// How serious it is.
    severity: linuxhello_dbus::status::Severity,
    /// The fixed sentence for the code.
    sentence: String,
    /// What the loader says, which names a file; for root only.
    detail: Option<String>,
}

/// The PIN rules a client shows in its dialog, as wire values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinRulesReply {
    /// Shortest allowed PIN.
    pub min_length: u32,
    /// Longest allowed PIN.
    pub max_length: u32,
    /// The character classes a PIN must contain: `digits`, `lowercase`, `uppercase`, `special`.
    pub required: Vec<String>,
    /// The character classes a PIN must not contain.
    pub disallowed: Vec<String>,
}

/// The request layer over a [`StateStore`].
pub struct Api {
    /// The per-prompt state and its access rules.
    store: StateStore,
    /// The user policy layer.
    user_policies: Option<UserPolicyStore>,
    /// The audit trail of refusals and policy changes.
    audit: Audit,
    /// The authentications that are running, by the user who opened the prompt and its id; the
    /// flag stops the orchestrator when the prompt closes.
    running: HashMap<(u32, PromptId), Cancel>,
    /// The PIN lock, when the Agent has one.
    pin_lock: Option<Arc<PinLockService>>,
    /// The time in seconds since the Unix epoch; the wall clock, replaced in tests.
    clock: fn() -> u64,
}

impl Api {
    /// An API over an empty store with the given settings.
    pub fn new(config: Config) -> Self {
        Self {
            store: StateStore::new(config),
            user_policies: None,
            audit: Audit::none(),
            running: HashMap::new(),
            pin_lock: None,
            clock: wall_clock_seconds,
        }
    }

    /// An API with the Agent's PIN lock, which `GetStatus` reads.
    #[must_use]
    pub fn with_pin_lock(self, pin_lock: Option<PinLockService>) -> Self {
        self.with_shared_pin_lock(pin_lock.map(Arc::new))
    }

    /// An API with a PIN lock that something else holds too, such as the PIN method.
    #[must_use]
    pub fn with_shared_pin_lock(self, pin_lock: Option<Arc<PinLockService>>) -> Self {
        Self { pin_lock, ..self }
    }

    /// An API that reads the time from `clock` (seconds since the Unix epoch) instead of the wall
    /// clock, for tests.
    #[must_use]
    pub fn with_clock(self, clock: fn() -> u64) -> Self {
        Self { clock, ..self }
    }

    /// An API that records its refusals and policy changes in `audit`.
    pub fn with_audit(self, audit: Audit) -> Self {
        Self { audit, ..self }
    }

    /// Records the refusal in `result`, if it is one, and returns the result unchanged. A
    /// refusal is recorded with the caller's uid and its reason only; an unavailable service is
    /// not a refusal of the caller.
    fn audited<T>(&self, caller: &Caller, result: Result<T, ApiError>) -> Result<T, ApiError> {
        let peer = caller.peer;
        match result {
            Err(ApiError::Denied) => self.audit.record(Event::denied(caller.uid).with_peer(peer)),
            Err(ApiError::LimitReached) => self
                .audit
                .record(Event::limit_reached(caller.uid).with_peer(peer)),
            Err(ApiError::InvalidArgument | ApiError::InvalidPolicy(_)) => {
                self.audit
                    .record(Event::invalid_argument(caller.uid).with_peer(peer));
            }
            Err(ApiError::Unavailable | ApiError::Damaged) | Ok(_) => {}
        }
        result
    }

    /// The effective policy of `uid`, read from the admin layers and the user's layer now. A
    /// policy that falls back to PIN-only is audited, with the uid and which layer was to blame,
    /// and is returned as the PIN-only state: the caller decides from it exactly as from a
    /// sound one (`pin_only_fallback_is_audited_with_its_reason`). The policy is read on every
    /// call; caching it is #151.
    ///
    /// # Errors
    ///
    /// [`ApiError::Unavailable`] when the Agent has no policy store.
    pub fn policy_of(&self, uid: u32) -> Result<Policy, ApiError> {
        let store = self.user_policies.as_ref().ok_or(ApiError::Unavailable)?;
        let policy = store.policy_of(uid);
        if let Policy::PinOnly(pin_only) = &policy {
            self.audit
                .record(Event::policy_pin_only(uid, pin_only.fault));
        }
        Ok(policy)
    }

    /// An API with a user policy store.
    pub fn with_user_policy_store(self, store: Option<UserPolicyStore>) -> Self {
        Self {
            user_policies: store,
            ..self
        }
    }

    /// Gives the request layer the time (a monotonic time, such as the time since the Agent
    /// started) and closes the prompts that have had no report for longer than the store's
    /// `max_idle`. Returns how many it closed. Not a request of a caller, so not audited.
    pub fn advance(&mut self, now: std::time::Duration) -> usize {
        let closed = self.store.advance(now);
        self.stop_orphans();
        closed
    }

    /// Opens a prompt owned by the caller.
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid or when the store refuses;
    /// [`ApiError::InvalidArgument`] for a prompt id that is not valid;
    /// [`ApiError::LimitReached`] when the caller has too many prompts open.
    pub fn open_prompt(
        &mut self,
        caller: Caller,
        prompt_id: &str,
        subject_uid: Option<u32>,
    ) -> Result<(), ApiError> {
        let result = self.open_prompt_unaudited(&caller, prompt_id, subject_uid);
        self.audited(&caller, result)
    }

    /// Opens a prompt owned by the caller and remembers `opener`, the unique bus name of the
    /// connection that asked, so that [`Api::peer_left`] can remove the prompt when that
    /// connection leaves the bus. The rules are those of [`Api::open_prompt`], and the opener may
    /// reopen its own prompt (`opener_can_reopen_its_own_prompt`).
    ///
    /// # Errors
    ///
    /// Those of [`Api::open_prompt`], and [`ApiError::InvalidArgument`] for an `opener` that is
    /// not a unique bus name.
    pub fn open_prompt_from(
        &mut self,
        caller: Caller,
        opener: &str,
        prompt_id: &str,
        subject_uid: Option<u32>,
    ) -> Result<(), ApiError> {
        let result = self.open_prompt_from_unaudited(&caller, opener, prompt_id, subject_uid);
        self.audited(&caller, result)
    }

    /// The work of [`Api::open_prompt_from`], without the audit record.
    fn open_prompt_from_unaudited(
        &mut self,
        caller: &Caller,
        opener: &str,
        prompt_id: &str,
        subject_uid: Option<u32>,
    ) -> Result<(), ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        if !opener.starts_with(':') || opener.len() > MAX_PEER_NAME {
            return Err(ApiError::InvalidArgument);
        }
        Ok(self
            .store
            .open_named(uid, Peer(opener.to_string()), &prompt, subject_uid)?)
    }

    /// The bus says the connection `peer` left: removes the prompts it opened and its
    /// subscriptions, and returns how many of each together. Not a request of a caller, so not
    /// audited.
    pub fn peer_left(&mut self, peer: &str) -> usize {
        let peer = Peer(peer.to_string());
        let removed = self.store.drop_opener(&peer) + self.store.drop_subscriber(&peer);
        self.stop_orphans();
        removed
    }

    /// The work of [`Api::open_prompt`], without the audit record.
    fn open_prompt_unaudited(
        &mut self,
        caller: &Caller,
        prompt_id: &str,
        subject_uid: Option<u32>,
    ) -> Result<(), ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        Ok(self.store.open(uid, &prompt, subject_uid)?)
    }

    /// Applies one change to a prompt and returns the notifications to send, one per
    /// subscribed peer, in the order they subscribed.
    ///
    /// `signal` is one of the names in `linuxhello_dbus::SIGNALS`. `MethodsAvailable` takes
    /// any number of different methods, `ActiveMethods` the same, `State` exactly one value and
    /// `Result` one to three: the result, its reason and the seconds to wait.
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid or when the store refuses;
    /// [`ApiError::InvalidArgument`] for a prompt id, signal name or value that is not valid.
    pub fn report_state(
        &mut self,
        caller: Caller,
        prompt_id: &str,
        signal: &str,
        values: &[&str],
    ) -> Result<Vec<Notification>, ApiError> {
        let result = self.report_state_unaudited(&caller, prompt_id, signal, values);
        self.audited(&caller, result)
    }

    /// The work of [`Api::report_state`], without the audit record.
    fn report_state_unaudited(
        &mut self,
        caller: &Caller,
        prompt_id: &str,
        signal: &str,
        values: &[&str],
    ) -> Result<Vec<Notification>, ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        let signal = SIGNALS
            .iter()
            .find(|spec| spec.name == signal)
            .map(|spec| spec.name)
            .ok_or(ApiError::InvalidArgument)?;
        let update = parse_update(signal, values)?;
        let wire = wire_values(&update);
        let peers = self.store.report(uid, &prompt, update)?;
        Ok(peers
            .into_iter()
            .map(|peer| Notification {
                peer,
                signal,
                prompt_id: prompt_id.to_string(),
                values: wire.clone(),
            })
            .collect())
    }

    /// The current state of a prompt, as wire strings.
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid, when the store refuses, and for an unknown
    /// prompt; [`ApiError::InvalidArgument`] for a prompt id that is not valid.
    pub fn get_state(&self, caller: Caller, prompt_id: &str) -> Result<StateReply, ApiError> {
        let result = self.get_state_unaudited(&caller, prompt_id);
        self.audited(&caller, result)
    }

    /// The work of [`Api::get_state`], without the audit record.
    fn get_state_unaudited(
        &self,
        caller: &Caller,
        prompt_id: &str,
    ) -> Result<StateReply, ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        let snapshot = self.store.get(uid, &prompt)?;
        Ok(StateReply {
            methods: snapshot
                .methods
                .iter()
                .map(|m| m.as_wire().to_string())
                .collect(),
            active: snapshot
                .active
                .iter()
                .map(|m| m.as_wire().to_string())
                .collect(),
            state: snapshot.state.as_wire().to_string(),
            result: snapshot.result.map(|o| o.result.as_wire().to_string()),
            reason: snapshot
                .result
                .map_or(String::new(), |o| o.reason.as_wire().to_string()),
            retry_after: snapshot.result.map_or(0, |o| o.retry_after),
        })
    }

    /// Subscribes a peer, given by its unique bus name such as `:1.7`, to a prompt.
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid or when the store refuses;
    /// [`ApiError::InvalidArgument`] for a prompt id or peer name that is not valid;
    /// [`ApiError::LimitReached`] when the prompt has too many subscribers.
    pub fn subscribe(
        &mut self,
        caller: Caller,
        peer: &str,
        prompt_id: &str,
    ) -> Result<(), ApiError> {
        let result = self.subscribe_unaudited(&caller, peer, prompt_id);
        self.audited(&caller, result)
    }

    /// The work of [`Api::subscribe`], without the audit record.
    fn subscribe_unaudited(
        &mut self,
        caller: &Caller,
        peer: &str,
        prompt_id: &str,
    ) -> Result<(), ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        if !peer.starts_with(':') || peer.len() > MAX_PEER_NAME {
            return Err(ApiError::InvalidArgument);
        }
        Ok(self.store.subscribe(uid, Peer(peer.to_string()), &prompt)?)
    }

    /// Stops the signals of a prompt to the caller's connection `peer`. A connection that was
    /// not subscribed is not an error. The prompt must be one the caller may read, as for
    /// [`Api::subscribe`].
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid or for a prompt the caller may not read;
    /// [`ApiError::InvalidArgument`] for a prompt id or a peer that is not valid.
    pub fn unsubscribe(
        &mut self,
        caller: Caller,
        peer: &str,
        prompt_id: &str,
    ) -> Result<(), ApiError> {
        let result = self.unsubscribe_unaudited(&caller, peer, prompt_id);
        self.audited(&caller, result)
    }

    /// The work of [`Api::unsubscribe`], without the audit record.
    fn unsubscribe_unaudited(
        &mut self,
        caller: &Caller,
        peer: &str,
        prompt_id: &str,
    ) -> Result<(), ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        if !peer.starts_with(':') || peer.len() > MAX_PEER_NAME {
            return Err(ApiError::InvalidArgument);
        }
        Ok(self
            .store
            .unsubscribe(uid, &Peer(peer.to_string()), &prompt)?)
    }

    /// The `Closed` signals owed to the peers of the prompts that closed since the last call:
    /// one per subscriber, each naming only the prompt (`a_subscriber_is_told_when_the_prompt_closes`).
    pub fn take_closures(&mut self) -> Vec<Notification> {
        self.store
            .take_closed()
            .into_iter()
            .flat_map(|closure| {
                let prompt_id = closure.prompt.as_str().to_string();
                closure
                    .subscribers
                    .into_iter()
                    .map(move |peer| Notification {
                        peer,
                        signal: "Closed",
                        prompt_id: prompt_id.clone(),
                        values: Vec::new(),
                    })
            })
            .collect()
    }

    /// Closes a prompt opened by the caller.
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid or unless the caller opened the prompt;
    /// [`ApiError::InvalidArgument`] for a prompt id that is not valid.
    pub fn close_prompt(&mut self, caller: Caller, prompt_id: &str) -> Result<(), ApiError> {
        let result = self.close_prompt_unaudited(&caller, prompt_id);
        self.audited(&caller, result)
    }

    /// The work of [`Api::close_prompt`], without the audit record.
    fn close_prompt_unaudited(&mut self, caller: &Caller, prompt_id: &str) -> Result<(), ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        self.store.close(uid, &prompt)?;
        self.stop_orphans();
        Ok(())
    }

    /// Returns the caller's user policy as TOML text.
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid;
    /// [`ApiError::Unavailable`] if the user policy store is not configured.
    pub fn get_user_policy(&self, caller: Caller) -> Result<String, ApiError> {
        let result = self.get_user_policy_unaudited(&caller);
        self.audited(&caller, result)
    }

    /// The work of [`Api::get_user_policy`], without the audit record.
    fn get_user_policy_unaudited(&self, caller: &Caller) -> Result<String, ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let store = self.user_policies.as_ref().ok_or(ApiError::Unavailable)?;
        store.get(uid).map_err(ApiError::from)
    }

    /// Starts the authentication of a prompt (`Authenticate`, ADR-0023 amendment 2026-11-19):
    /// checks that the caller opened the prompt, which user it is for and what the policy of that
    /// user allows in `context`, and records that one authentication is running. The caller then
    /// runs the orchestrator with what this returns and reports through
    /// [`Api::agent_report`]. Only the connection that opened the prompt may ask.
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid or connection name, for a prompt that is not the
    /// caller's, one that does not exist and one with no subject (one text for all);
    /// [`ApiError::InvalidArgument`] for a malformed id or a context that is not one of the four;
    /// [`ApiError::LimitReached`] while an authentication of this prompt runs;
    /// [`ApiError::Unavailable`] without a policy store.
    pub fn begin_authentication(
        &mut self,
        caller: Caller,
        prompt_id: &str,
        context: &str,
    ) -> Result<AuthStart, ApiError> {
        let result = self.begin_authentication_unaudited(&caller, prompt_id, context);
        self.audited(&caller, result)
    }

    /// The work of [`Api::begin_authentication`], without the audit record.
    fn begin_authentication_unaudited(
        &mut self,
        caller: &Caller,
        prompt_id: &str,
        context: &str,
    ) -> Result<AuthStart, ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        if !linuxhello_dbus::status::CONTEXTS.contains(&context) {
            return Err(ApiError::InvalidArgument);
        }
        let peer = Peer(caller.peer.ok_or(ApiError::Denied)?.as_str().to_string());
        let subject = self
            .store
            .subject_of(uid, &prompt, Some(&peer))?
            .ok_or(ApiError::Denied)?;
        if self.running.contains_key(&(uid, prompt.clone())) {
            return Err(ApiError::LimitReached);
        }
        let rule = self.policy_of(subject)?.methods_for(context);
        let stop = Cancel::default();
        self.running.insert((uid, prompt.clone()), stop.clone());
        Ok(AuthStart {
            opener_uid: uid,
            prompt,
            subject,
            rule,
            stop,
        })
    }

    /// Applies a report of the orchestrator to the prompt that `uid` opened, as the Agent and not
    /// as a caller, and returns the signals to send. A prompt that is gone changes nothing and
    /// gives no signals. The end of the authentication (`Update::Result`) frees the prompt for
    /// the next call of [`Api::begin_authentication`].
    pub fn agent_report(
        &mut self,
        uid: u32,
        prompt: &PromptId,
        update: Update,
    ) -> Vec<Notification> {
        let signal = match &update {
            Update::Methods(_) => "MethodsAvailable",
            Update::Active(_) => "ActiveMethods",
            Update::State(_) => "State",
            Update::Result(_) => "Result",
        };
        let wire = wire_values(&update);
        let ended = matches!(update, Update::Result(_));
        let peers = self.store.report(uid, prompt, update).unwrap_or_default();
        if ended {
            self.running.remove(&(uid, prompt.clone()));
        }
        peers
            .into_iter()
            .map(|peer| Notification {
                peer,
                signal,
                prompt_id: prompt.as_str().to_string(),
                values: wire.clone(),
            })
            .collect()
    }

    /// Stops the authentication of every prompt that no longer exists: it was closed, its opener
    /// left, or it was idle too long. The orchestrator then ends with the result `cancelled`.
    fn stop_orphans(&mut self) {
        let store = &self.store;
        for ((uid, prompt), stop) in &self.running {
            if store.subject_of(*uid, prompt, None).is_err() {
                stop.cancel();
            }
        }
    }

    /// Announces a PIN (`ExpectPin`, ADR-0021 amendment 2026-11-18): the connection that opened
    /// the prompt `prompt_id` is about to send one PIN on `socket`, for the user the prompt is
    /// for. `process` is the caller's process id as the bus reports it. The Agent then accepts
    /// one PIN from a connection of the same user and process, within 30 seconds
    /// (`an_expected_process_may_send_one_pin`).
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid, a connection name or a process id, for a
    /// prompt that is not the caller's or was opened by another connection, and for a prompt
    /// with no subject (one text for all, so nothing is told about other users' prompts);
    /// [`ApiError::InvalidArgument`] for a malformed id; [`ApiError::LimitReached`] when 64
    /// callers already wait; [`ApiError::Unavailable`] without a PIN socket.
    pub fn expect_pin(
        &self,
        caller: Caller,
        process: Option<u32>,
        prompt_id: &str,
        socket: Option<&PinSocket>,
    ) -> Result<(), ApiError> {
        let result = self.expect_pin_unaudited(&caller, process, prompt_id, socket);
        self.audited(&caller, result)
    }

    /// The work of [`Api::expect_pin`], without the audit record.
    fn expect_pin_unaudited(
        &self,
        caller: &Caller,
        process: Option<u32>,
        prompt_id: &str,
        socket: Option<&PinSocket>,
    ) -> Result<(), ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        let socket = socket.ok_or(ApiError::Unavailable)?;
        let peer = Peer(caller.peer.ok_or(ApiError::Denied)?.as_str().to_string());
        let subject = self
            .store
            .subject_of(uid, &prompt, Some(&peer))?
            .ok_or(ApiError::Denied)?;
        let pid = process.ok_or(ApiError::Denied)?;
        socket
            .expect(Process { uid, pid }, subject)
            .map_err(|_| ApiError::LimitReached)
    }

    /// The conditions that affect the caller, each as `(code, severity, sentence)`: its own
    /// policy layer and the faults of the machine that change what it can do. A fault is a
    /// condition, never an error. The list names no file, no path and no other user
    /// (`status_never_carries_a_file_name`, `status_is_scoped_to_the_caller`); ADR-0024.
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid;
    /// [`ApiError::Unavailable`] if the user policy store is not configured.
    pub fn get_status(&self, caller: Caller) -> Result<Vec<(String, String, String)>, ApiError> {
        let result = self.status_unaudited(&caller).map(|conditions| {
            conditions
                .into_iter()
                .map(|c| (c.code, c.severity.as_wire().to_string(), c.sentence))
                .collect()
        });
        self.audited(&caller, result)
    }

    /// The same conditions with the detail the loader gives, which names a file. Only root may
    /// ask; anyone else is refused as for any request that is not theirs (ADR-0024, point 6).
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] unless the caller's uid is 0;
    /// [`ApiError::Unavailable`] if the user policy store is not configured.
    pub fn get_status_details(
        &self,
        caller: Caller,
    ) -> Result<Vec<(String, String, String, String)>, ApiError> {
        let result = if caller.uid == Some(0) {
            self.status_unaudited(&caller).map(|conditions| {
                conditions
                    .into_iter()
                    .map(|c| {
                        (
                            c.code,
                            c.severity.as_wire().to_string(),
                            c.sentence,
                            c.detail.unwrap_or_default(),
                        )
                    })
                    .collect()
            })
        } else {
            Err(ApiError::Denied)
        };
        self.audited(&caller, result)
    }

    /// The work of [`Api::get_status`], with the detail kept.
    fn status_unaudited(&self, caller: &Caller) -> Result<Vec<StatusItem>, ApiError> {
        use linuxhello_dbus::status::{
            context_unsatisfiable_on_the_bus, pin_locked_sentence, tpm_limit_low_sentence,
            Severity, PIN_LOCKED, PIN_LOCK_DAMAGED, PIN_LOCK_DAMAGED_SENTENCE, POLICY_PIN_ONLY,
            POLICY_PIN_ONLY_SENTENCE, TPM_LIMIT_LOW,
        };
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let policy = self.policy_of(uid)?;
        let (layer, reason) = match &policy {
            Policy::Effective(effective) => (&effective.layer, None),
            Policy::PinOnly(pin) => (&pin.layer, Some(pin.reason.clone())),
        };
        let mut items = Vec::new();
        if let Some(reason) = reason {
            items.push(StatusItem {
                code: POLICY_PIN_ONLY.to_string(),
                severity: Severity::Severe,
                sentence: POLICY_PIN_ONLY_SENTENCE.to_string(),
                detail: Some(reason),
            });
        }
        let mut contexts: Vec<&String> = layer.context.keys().collect();
        contexts.sort();
        for context in contexts {
            if policy.methods_for(context).unsatisfiable {
                let (code, sentence) = context_unsatisfiable_on_the_bus(context);
                items.push(StatusItem {
                    code,
                    severity: Severity::Severe,
                    sentence,
                    detail: Some(format!("the context {context}")),
                });
            }
        }
        if let Some(cap) = self.pin_lock.as_ref().and_then(|lock| lock.tpm_cap()) {
            items.push(StatusItem {
                code: TPM_LIMIT_LOW.to_string(),
                severity: Severity::Warning,
                sentence: tpm_limit_low_sentence(cap.tpm_tries, cap.allowed),
                detail: None,
            });
        }
        if let Some(lock) = &self.pin_lock {
            match lock.status_of(uid, (self.clock)()) {
                LockStatus::Unlocked => {}
                LockStatus::LockedFor(seconds) => items.push(StatusItem {
                    code: PIN_LOCKED.to_string(),
                    severity: Severity::Warning,
                    sentence: pin_locked_sentence(seconds),
                    detail: None,
                }),
                LockStatus::Untrusted => items.push(StatusItem {
                    code: PIN_LOCK_DAMAGED.to_string(),
                    severity: Severity::Severe,
                    sentence: PIN_LOCK_DAMAGED_SENTENCE.to_string(),
                    detail: Some("the lockout file cannot be trusted".to_string()),
                }),
            }
        }
        Ok(items)
    }

    /// The policy that applies to the caller, as TOML text with one `path = value` line per key,
    /// and the paths an administrator manages (`GetEffectivePolicy`, ADR-0014 amendment
    /// 2026-11-17, point 3). It shows values only: no file name, no admin layer as such, and
    /// nothing of any other user (`a_user_reads_only_its_own_effective_policy`).
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid;
    /// [`ApiError::Unavailable`] if the user policy store is not configured.
    pub fn get_effective_policy(&self, caller: Caller) -> Result<(String, Vec<String>), ApiError> {
        let result = self.effective_policy_unaudited(&caller);
        self.audited(&caller, result)
    }

    /// The work of [`Api::get_effective_policy`], without the audit record.
    fn effective_policy_unaudited(
        &self,
        caller: &Caller,
    ) -> Result<(String, Vec<String>), ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let view = self.policy_of(uid)?.effective();
        let mut text = String::new();
        let mut managed = Vec::new();
        for setting in view.settings {
            text.push_str(&format!("{} = {}\n", setting.path, setting.value));
            if setting.managed {
                managed.push(setting.path);
            }
        }
        Ok((text, managed))
    }

    /// The PIN rules that apply to the caller, for the PIN dialog: the shortest and longest
    /// length, and the character classes that are required and those that are disallowed
    /// (`GetPinRules`, ADR-0014 amendment 2026-11-17, point 3).
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid;
    /// [`ApiError::Unavailable`] if the user policy store is not configured.
    pub fn get_pin_rules(&self, caller: Caller) -> Result<PinRulesReply, ApiError> {
        let result = self.pin_rules_unaudited(&caller);
        self.audited(&caller, result)
    }

    /// The work of [`Api::get_pin_rules`], without the audit record.
    fn pin_rules_unaudited(&self, caller: &Caller) -> Result<PinRulesReply, ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let rules = self.policy_of(uid)?.pin_rules();
        let classes = [
            ("digits", &rules.digits),
            ("lowercase", &rules.lowercase),
            ("uppercase", &rules.uppercase),
            ("special", &rules.special),
        ];
        let named = |wanted: &str| {
            classes
                .iter()
                .filter(|(_, rule)| rule.as_str() == wanted)
                .map(|(name, _)| (*name).to_string())
                .collect::<Vec<_>>()
        };
        Ok(PinRulesReply {
            min_length: rules.min_length,
            max_length: rules.max_length,
            required: named("required"),
            disallowed: named("disallowed"),
        })
    }

    /// Replaces the caller's user policy with the provided TOML text.
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid;
    /// [`ApiError::Unavailable`] if the user policy store is not configured;
    /// [`ApiError::InvalidPolicy`] with the parser's message if the text does not follow the
    /// schema; [`ApiError::InvalidArgument`] if it is too large or contradicts the admin layers.
    pub fn set_user_policy(&mut self, caller: Caller, text: &str) -> Result<(), ApiError> {
        let result = self.set_user_policy_unaudited(&caller, text);
        if let (Ok(()), Some(uid)) = (&result, caller.uid) {
            self.audit.record(if text.is_empty() {
                Event::user_policy_removed(uid)
            } else {
                Event::user_policy_set(uid)
            });
        }
        self.audited(&caller, result)
    }

    /// The work of [`Api::set_user_policy`], without the audit record.
    fn set_user_policy_unaudited(&mut self, caller: &Caller, text: &str) -> Result<(), ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let store = self.user_policies.as_ref().ok_or(ApiError::Unavailable)?;
        // A text the schema rejects is told apart from one the store refuses for another reason
        // (too large, contradicts the admin layers), so that the caller can see its own mistake.
        // The store parses the text again; both calls are the same function.
        if !text.is_empty() && text.len() <= MAX_POLICY_BYTES {
            parse_layer(text).map_err(ApiError::InvalidPolicy)?;
        }
        match store.set(uid, text) {
            // The layer is in place and reads back; a retry would write the same text.
            Ok(()) | Err(StoreError::Unsynced) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Parses a prompt id given as text.
fn parse_prompt(prompt_id: &str) -> Result<PromptId, ApiError> {
    PromptId::parse(prompt_id).ok_or(ApiError::InvalidArgument)
}

/// Parses the values of a signal into the store's update for it.
fn parse_update(signal: &str, values: &[&str]) -> Result<Update, ApiError> {
    match (signal, values) {
        ("MethodsAvailable", values) => Ok(Update::Methods(parse_methods(values)?)),
        ("ActiveMethods", values) => Ok(Update::Active(parse_methods(values)?)),
        ("State", [value]) => PromptState::from_wire(value)
            .map(Update::State)
            .ok_or(ApiError::InvalidArgument),
        ("Result", [result]) => parse_outcome(result, "", "0"),
        ("Result", [result, reason]) => parse_outcome(result, reason, "0"),
        ("Result", [result, reason, seconds]) => parse_outcome(result, reason, seconds),
        _ => Err(ApiError::InvalidArgument),
    }
}

/// Parses a list of different methods, in the order given.
fn parse_methods(values: &[&str]) -> Result<Vec<AuthMethod>, ApiError> {
    let mut methods = Vec::new();
    for value in values {
        let method = AuthMethod::from_wire(value).ok_or(ApiError::InvalidArgument)?;
        if methods.contains(&method) {
            return Err(ApiError::InvalidArgument);
        }
        methods.push(method);
    }
    Ok(methods)
}

/// Parses the values of a `Result`: the result, its reason (empty for none) and the seconds to
/// wait. The seconds are nonzero only for a locked-out result.
fn parse_outcome(result: &str, reason: &str, seconds: &str) -> Result<Update, ApiError> {
    let result = PromptResult::from_wire(result).ok_or(ApiError::InvalidArgument)?;
    let reason = PromptReason::from_wire(reason).ok_or(ApiError::InvalidArgument)?;
    let retry_after: u32 = seconds.parse().map_err(|_| ApiError::InvalidArgument)?;
    if retry_after != 0 && result != PromptResult::LockedOut {
        return Err(ApiError::InvalidArgument);
    }
    Ok(Update::Result(Outcome {
        result,
        reason,
        retry_after,
    }))
}

/// The canonical wire strings of an update's values.
fn wire_values(update: &Update) -> Vec<String> {
    match update {
        Update::Methods(methods) => methods.iter().map(|m| m.as_wire().to_string()).collect(),
        Update::Active(active) => active.iter().map(|m| m.as_wire().to_string()).collect(),
        Update::State(state) => vec![state.as_wire().to_string()],
        Update::Result(outcome) => vec![
            outcome.result.as_wire().to_string(),
            outcome.reason.as_wire().to_string(),
            outcome.retry_after.to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::user_store::UserPolicyStore;
    use tempfile::TempDir;

    /// A valid prompt id as text, from a short name.
    fn pid(name: &str) -> String {
        PromptId::derive("test", name, "s1").as_str().to_string()
    }

    /// An ordinary caller.
    const USER: Caller = Caller {
        uid: Some(1000),
        peer: None,
    };

    /// An `Api` with a prompt opened by `USER` for itself.
    fn api_with_prompt(id: &str) -> Api {
        let mut api = Api::new(Config::new(vec![990]));
        api.open_prompt(USER, id, Some(1000)).unwrap();
        api
    }

    #[test]
    fn peer_left_removes_what_that_peer_opened_and_subscribed() {
        let mut api = Api::new(Config::new(vec![]));
        let (opened, shared) = (pid("opened"), pid("shared"));
        api.open_prompt_from(USER, ":1.1", &opened, Some(1000))
            .unwrap();
        api.open_prompt_from(USER, ":1.1", &shared, Some(1000))
            .unwrap();
        api.subscribe(USER, ":1.2", &shared).unwrap();
        // A subscriber leaving removes only its subscription.
        assert_eq!(api.peer_left(":1.2"), 1);
        let told = api
            .report_state(USER, &shared, "State", &["scanning"])
            .unwrap();
        assert!(told.is_empty());
        // The opener leaving removes both prompts.
        assert_eq!(api.peer_left(":1.1"), 2);
        assert_eq!(api.get_state(USER, &opened), Err(ApiError::Denied));
        assert_eq!(api.get_state(USER, &shared), Err(ApiError::Denied));
        // A name that never opened or subscribed changes nothing.
        assert_eq!(api.peer_left(":1.9"), 0);
    }

    #[test]
    fn a_prompt_is_opened_from_a_unique_bus_name_only() {
        let mut api = Api::new(Config::new(vec![]));
        for opener in ["org.example.Name", "", "1.1"] {
            assert_eq!(
                api.open_prompt_from(USER, opener, &pid("p1"), Some(1000)),
                Err(ApiError::InvalidArgument)
            );
        }
        assert_eq!(
            api.open_prompt_from(
                Caller {
                    uid: None,
                    peer: None
                },
                ":1.1",
                &pid("p1"),
                Some(1000)
            ),
            Err(ApiError::Denied)
        );
    }

    #[test]
    fn malformed_prompt_id_is_an_invalid_argument() {
        let mut api = Api::new(Config::new(vec![]));
        let long_upper = "A".repeat(64);
        for id in ["", "p1", long_upper.as_str()] {
            let bad = Err(ApiError::InvalidArgument);
            assert_eq!(api.open_prompt(USER, id, None), bad);
            assert_eq!(api.get_state(USER, id), Err(ApiError::InvalidArgument));
            assert_eq!(
                api.report_state(USER, id, "State", &["idle"]),
                Err(ApiError::InvalidArgument)
            );
            assert_eq!(api.subscribe(USER, ":1.1", id), bad);
            assert_eq!(api.close_prompt(USER, id), bad);
        }
    }

    #[test]
    fn unknown_signal_name_is_an_invalid_argument() {
        let id = pid("p1");
        let mut api = api_with_prompt(&id);
        for signal in ["Bogus", "state", ""] {
            assert_eq!(
                api.report_state(USER, &id, signal, &[]),
                Err(ApiError::InvalidArgument)
            );
        }
    }

    #[test]
    fn bad_wire_values_are_refused_before_the_store_changes() {
        let id = pid("p1");
        let mut api = api_with_prompt(&id);
        let fresh = api.get_state(USER, &id).unwrap();
        let bad: [(&str, &[&str]); 14] = [
            ("State", &["bogus"]),
            ("State", &[]),
            ("State", &["idle", "idle"]),
            ("Result", &["bogus"]),
            ("Result", &[]),
            ("Result", &["failure", "bogus"]),
            ("Result", &["failure", "", "soon"]),
            ("Result", &["failure", "", "5"]),
            ("Result", &["locked-out", "", "-1"]),
            ("Result", &["failure", "", "0", "extra"]),
            ("ActiveMethods", &["face", "FACE"]),
            ("ActiveMethods", &["face", "face"]),
            ("ActiveMethod", &["face"]),
            ("MethodsAvailable", &["face", "FACE"]),
        ];
        for (signal, values) in bad {
            assert_eq!(
                api.report_state(USER, &id, signal, values),
                Err(ApiError::InvalidArgument)
            );
        }
        assert_eq!(api.get_state(USER, &id).unwrap(), fresh);
    }

    #[test]
    fn notifications_carry_only_canonical_wire_strings() {
        let id = pid("p1");
        let mut api = api_with_prompt(&id);
        api.subscribe(USER, ":1.1", &id).unwrap();
        api.subscribe(USER, ":1.2", &id).unwrap();

        let told = api
            .report_state(USER, &id, "MethodsAvailable", &["face", "pin"])
            .unwrap();
        assert_eq!(told.len(), 2);
        assert_eq!(told[0].peer, Peer(":1.1".into()));
        assert_eq!(told[1].peer, Peer(":1.2".into()));
        for note in &told {
            assert_eq!(note.signal, "MethodsAvailable");
            assert_eq!(note.prompt_id, id);
            assert_eq!(note.values, vec!["face".to_string(), "pin".to_string()]);
        }

        let told = api.report_state(USER, &id, "ActiveMethods", &[]).unwrap();
        assert!(told[0].values.is_empty());
        let told = api
            .report_state(USER, &id, "ActiveMethods", &["face", "fingerprint"])
            .unwrap();
        assert_eq!(
            told[0].values,
            vec!["face".to_string(), "fingerprint".to_string()]
        );
        let told = api.report_state(USER, &id, "State", &["scanning"]).unwrap();
        assert_eq!(told[0].values, vec!["scanning".to_string()]);
    }

    #[test]
    fn get_state_returns_wire_strings() {
        let id = pid("p1");
        let mut api = api_with_prompt(&id);
        let fresh = api.get_state(USER, &id).unwrap();
        assert!(fresh.methods.is_empty());
        assert!(fresh.active.is_empty());
        assert_eq!(fresh.state, "idle");
        assert_eq!(fresh.result, None);
        assert_eq!((fresh.reason.as_str(), fresh.retry_after), ("", 0));

        api.report_state(USER, &id, "MethodsAvailable", &["face"])
            .unwrap();
        api.report_state(USER, &id, "ActiveMethods", &["face", "fingerprint"])
            .unwrap();
        api.report_state(USER, &id, "State", &["scanning"]).unwrap();
        api.report_state(USER, &id, "Result", &["failure"]).unwrap();
        let reply = api.get_state(USER, &id).unwrap();
        assert_eq!(reply.methods, vec!["face".to_string()]);
        assert_eq!(
            reply.active,
            vec!["face".to_string(), "fingerprint".to_string()]
        );
        assert_eq!(reply.state, "scanning".to_string());
        assert_eq!(reply.result, Some("failure".to_string()));
    }

    #[test]
    fn active_methods_is_a_list() {
        let id = pid("p1");
        let mut api = api_with_prompt(&id);
        for (values, expected) in [
            (vec![], vec![]),
            (vec!["face"], vec!["face"]),
            (vec!["face", "pin"], vec!["face", "pin"]),
        ] {
            api.report_state(USER, &id, "ActiveMethods", &values)
                .unwrap();
            let reply = api.get_state(USER, &id).unwrap();
            assert_eq!(reply.active, expected);
        }
    }

    #[test]
    fn a_locked_out_result_carries_the_seconds() {
        let id = pid("p1");
        let mut api = api_with_prompt(&id);
        api.subscribe(USER, ":1.1", &id).unwrap();

        let told = api
            .report_state(USER, &id, "Result", &["locked-out", "", "300"])
            .unwrap();
        assert_eq!(
            told[0].values,
            vec!["locked-out".to_string(), String::new(), "300".to_string()]
        );
        let reply = api.get_state(USER, &id).unwrap();
        assert_eq!(reply.result.as_deref(), Some("locked-out"));
        assert_eq!((reply.reason.as_str(), reply.retry_after), ("", 300));

        // A reason and no seconds, and a bare result, fill in what is left out.
        let told = api
            .report_state(USER, &id, "Result", &["failure", "too-dark"])
            .unwrap();
        assert_eq!(
            told[0].values,
            vec![
                "failure".to_string(),
                "too-dark".to_string(),
                "0".to_string()
            ]
        );
        let told = api.report_state(USER, &id, "Result", &["success"]).unwrap();
        assert_eq!(
            told[0].values,
            vec!["success".to_string(), String::new(), "0".to_string()]
        );
        let reply = api.get_state(USER, &id).unwrap();
        assert_eq!((reply.reason.as_str(), reply.retry_after), ("", 0));
    }

    #[test]
    fn store_refusals_pass_through_unchanged() {
        let id = pid("p1");
        let mut api = api_with_prompt(&id);
        let other = Caller {
            uid: Some(1001),
            peer: None,
        };
        assert_eq!(
            api.report_state(other, &id, "State", &["scanning"]),
            Err(ApiError::Denied)
        );

        let mut config = Config::new(vec![]);
        config.max_prompts_per_reporter = 1;
        let mut limited = Api::new(config);
        assert_eq!(limited.open_prompt(USER, &pid("p1"), Some(1000)), Ok(()));
        assert_eq!(
            limited.open_prompt(USER, &pid("p2"), Some(1000)),
            Err(ApiError::LimitReached)
        );
    }

    #[test]
    fn invalid_peer_names_are_refused() {
        let id = pid("p1");
        let mut api = api_with_prompt(&id);
        let too_long = format!(":{}", "a".repeat(255));
        for peer in ["", "no-colon", too_long.as_str()] {
            assert_eq!(
                api.subscribe(USER, peer, &id),
                Err(ApiError::InvalidArgument)
            );
        }
        assert_eq!(api.subscribe(USER, ":1.7", &id), Ok(()));
    }

    #[test]
    fn user_cannot_set_another_users_policy() {
        let tmp = TempDir::new().unwrap();
        let store = UserPolicyStore::new(tmp.path());
        let mut api = Api::new(Config::new(vec![990])).with_user_policy_store(Some(store));

        let tighter = "[methods]\nbiometrics_allowed = false\n";
        let valid = "[methods]\nface_requires_ir = true\n";

        let uid1000 = Caller {
            uid: Some(1000),
            peer: None,
        };
        let uid1001 = Caller {
            uid: Some(1001),
            peer: None,
        };

        api.set_user_policy(uid1000, tighter).unwrap();
        assert_eq!(api.get_user_policy(uid1001).unwrap(), "");

        api.set_user_policy(uid1001, valid).unwrap();
        assert_eq!(api.get_user_policy(uid1000).unwrap(), tighter);
        assert_eq!(api.get_user_policy(uid1001).unwrap(), valid);
    }

    #[test]
    fn unparseable_user_policy_is_refused_on_write() {
        let tmp = TempDir::new().unwrap();
        let store = UserPolicyStore::new(tmp.path());
        let mut api = Api::new(Config::new(vec![990])).with_user_policy_store(Some(store));

        let tighter = "[methods]\nbiometrics_allowed = false\n";
        let uid = Caller {
            uid: Some(1000),
            peer: None,
        };

        api.set_user_policy(uid, tighter).unwrap();
        assert!(matches!(
            api.set_user_policy(uid, "invalid = toml"),
            Err(ApiError::InvalidPolicy(_))
        ));
        assert_eq!(api.get_user_policy(uid).unwrap(), tighter);
    }

    #[test]
    fn oversized_user_policy_is_refused_on_write() {
        let tmp = TempDir::new().unwrap();
        let store = UserPolicyStore::new(tmp.path());
        let mut api = Api::new(Config::new(vec![990])).with_user_policy_store(Some(store));

        let uid = Caller {
            uid: Some(1000),
            peer: None,
        };
        let valid = "[methods]\nface_requires_ir = true\n";
        api.set_user_policy(uid, valid).unwrap();

        let oversized = "a".repeat(64 * 1024 + 1);
        assert_eq!(
            api.set_user_policy(uid, &oversized),
            Err(ApiError::InvalidArgument)
        );
        assert_eq!(api.get_user_policy(uid).unwrap(), valid);
    }

    #[test]
    fn user_policy_without_peer_credentials_is_refused() {
        let tmp = TempDir::new().unwrap();
        let mut api = Api::new(Config::new(vec![990]))
            .with_user_policy_store(Some(UserPolicyStore::new(tmp.path())));
        let tighter = "[methods]\nbiometrics_allowed = false\n";
        let no_uid = Caller {
            uid: None,
            peer: None,
        };

        assert_eq!(api.get_user_policy(no_uid), Err(ApiError::Denied));
        assert_eq!(api.set_user_policy(no_uid, tighter), Err(ApiError::Denied));
        // Nothing was stored for anyone, and a caller with a uid can still use the store.
        assert_eq!(api.get_user_policy(USER), Ok(String::new()));
        assert_eq!(api.set_user_policy(USER, tighter), Ok(()));
        assert_eq!(api.get_user_policy(no_uid), Err(ApiError::Denied));
    }

    #[test]
    fn user_policy_is_unavailable_without_a_store() {
        let mut api = Api::new(Config::new(vec![990]));

        assert_eq!(api.get_user_policy(USER), Err(ApiError::Unavailable));
        assert_eq!(api.set_user_policy(USER, ""), Err(ApiError::Unavailable));
    }

    /// A sink that keeps the events it is given.
    #[derive(Clone, Default)]
    struct Recorder(std::sync::Arc<std::sync::Mutex<Vec<Event>>>);

    impl crate::audit::AuditSink for Recorder {
        fn record(&self, event: &Event) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    impl Recorder {
        /// The events recorded so far.
        fn events(&self) -> Vec<Event> {
            self.0.lock().unwrap().clone()
        }
    }

    /// An `Api` that audits into a recorder.
    fn audited_api(config: Config) -> (Api, Recorder) {
        let recorder = Recorder::default();
        let api = Api::new(config).with_audit(Audit::new(Box::new(recorder.clone())));
        (api, recorder)
    }

    /// A store with an admin directory, in a temporary folder owned by the test's user.
    fn store_with_admin(tmp: &TempDir) -> (UserPolicyStore, std::path::PathBuf) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let admin = tmp.path().join("policy.d");
        std::fs::create_dir(&admin).unwrap();
        std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let owner = std::fs::metadata(&admin).unwrap().uid();
        let store = UserPolicyStore::new(tmp.path().join("users")).with_admin_layer(&admin, owner);
        (store, admin)
    }

    #[test]
    fn pin_only_fallback_is_audited_with_its_reason() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let (store, admin) = store_with_admin(&tmp);
        let (api, recorder) = audited_api(Config::new(vec![]));
        let api = api.with_user_policy_store(Some(store));

        // A damaged admin file: PIN-only, blamed on the admin layer, one record.
        let file = admin.join("broken-secret-name.toml");
        std::fs::write(&file, "this is not a policy").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let Ok(Policy::PinOnly(pin_only)) = api.policy_of(1000) else {
            panic!("a damaged admin file must give the PIN-only state");
        };
        assert_eq!(pin_only.fault, crate::policy::Fault::AdminLayer);
        assert_eq!(
            recorder.events(),
            vec![Event::policy_pin_only(
                1000,
                crate::policy::Fault::AdminLayer
            )]
        );
        // The record carries the uid and a fixed word, never the file name or the reason text.
        let fields = recorder.events()[0].fields();
        assert!(fields.contains(&("LH_UID", "1000".to_string())));
        assert!(fields.contains(&("LH_FAULT", "admin_layer".to_string())));
        assert!(fields
            .iter()
            .all(|(_, v)| !v.contains("broken-secret-name")));

        // A damaged user layer with sound admin layers: blamed on the user layer.
        std::fs::remove_file(&file).unwrap();
        let user_dir = tmp.path().join("users").join("1000");
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(user_dir.join("policy.toml"), "also not a policy").unwrap();
        let Ok(Policy::PinOnly(pin_only)) = api.policy_of(1000) else {
            panic!("a damaged user layer must give the PIN-only state");
        };
        assert_eq!(pin_only.fault, crate::policy::Fault::UserLayer);
        assert_eq!(recorder.events().len(), 2);
        assert!(recorder.events()[1]
            .fields()
            .contains(&("LH_FAULT", "user_layer".to_string())));
    }

    /// ADR-0014 amendment, point 3: a caller reads what applies to them, and nothing else.
    #[test]
    fn a_user_reads_only_its_own_effective_policy() {
        let tmp = TempDir::new().unwrap();
        let (store, admin) = store_with_admin(&tmp);
        std::fs::write(admin.join("zz-site-layer.toml"), "[pin]\nmin_length = 10\n").unwrap();
        let mut api = Api::new(Config::new(vec![])).with_user_policy_store(Some(store));
        let user = |uid| Caller {
            uid: Some(uid),
            peer: None,
        };
        let layer = "[context.sudo]\nmethods = [\"pin\"]\nfactors = 1\nreverify_after = \"37m\"\n";
        assert_eq!(api.set_user_policy(user(1000), layer), Ok(()));

        let (own, managed) = api.get_effective_policy(user(1000)).unwrap();
        assert!(own.contains("\"37m\""), "{own}");
        assert!(own.contains("pin.min_length = 10"), "{own}");
        assert_eq!(managed, vec!["pin.min_length".to_string()]);

        let (other, managed) = api.get_effective_policy(user(1001)).unwrap();
        assert!(other.contains("pin.min_length = 10"), "{other}");
        assert_eq!(managed, vec!["pin.min_length".to_string()]);
        for hidden in ["37m", "1000", "zz-site-layer", "policy.d", "toml"] {
            assert!(
                !other.contains(hidden) && !managed.iter().any(|m| m.contains(hidden)),
                "user 1001 sees {hidden:?}: {other}"
            );
        }
    }

    #[test]
    fn the_pin_rules_name_the_required_and_disallowed_classes() {
        let tmp = TempDir::new().unwrap();
        let (store, admin) = store_with_admin(&tmp);
        std::fs::write(
            admin.join("pin.toml"),
            "[pin]\nmin_length = 10\nmax_length = 40\ndigits = \"required\"\nspecial = \"disallowed\"\n",
        )
        .unwrap();
        let api = Api::new(Config::new(vec![])).with_user_policy_store(Some(store));
        let caller = Caller {
            uid: Some(1000),
            peer: None,
        };
        let rules = api.get_pin_rules(caller).unwrap();
        assert_eq!(rules.min_length, 10);
        assert_eq!(rules.max_length, 40);
        assert_eq!(rules.required, vec!["digits".to_string()]);
        assert_eq!(rules.disallowed, vec!["special".to_string()]);
    }

    #[test]
    fn the_policy_readers_refuse_a_caller_without_a_uid_and_need_a_store() {
        let tmp = TempDir::new().unwrap();
        let (store, _admin) = store_with_admin(&tmp);
        let anonymous = || Caller {
            uid: None,
            peer: None,
        };
        let known = Caller {
            uid: Some(1000),
            peer: None,
        };
        let api = Api::new(Config::new(vec![])).with_user_policy_store(Some(store));
        assert_eq!(api.get_effective_policy(anonymous()), Err(ApiError::Denied));
        assert_eq!(api.get_pin_rules(anonymous()), Err(ApiError::Denied));
        let bare = Api::new(Config::new(vec![]));
        assert_eq!(bare.get_effective_policy(known), Err(ApiError::Unavailable));
        assert_eq!(bare.get_pin_rules(known), Err(ApiError::Unavailable));
    }

    /// A caller of user `uid`, as the bus gives it.
    fn status_caller(uid: u32) -> Caller {
        Caller {
            uid: Some(uid),
            peer: None,
        }
    }

    /// An admin file that makes a context unsatisfiable: two factors, one method.
    const TOO_STRICT: &str = "[context.sudo]\nmethods = [\"pin\"]\nfactors = 2\n";

    /// The time of the status tests: seconds since the Unix epoch.
    fn at_1000() -> u64 {
        1_000
    }

    #[test]
    fn status_tells_a_locked_user_the_minutes_left() {
        use crate::pinlock::service::{Limits, PinLockService};
        use crate::pinlock::store::PinLockFile;
        let tmp = TempDir::new().unwrap();
        let (store, _admin) = store_with_admin(&tmp);
        let uid = rustix::process::getuid().as_raw();
        // One wrong PIN starts a lockout of 7 minutes 10 seconds.
        let limits = Limits {
            max_attempts: 1,
            lockout_secs: 430,
            max_lockout_secs: 86_400,
        };
        let lock = PinLockService::start(
            PinLockFile::new(tmp.path().join("pinlock.toml"), uid),
            limits,
        );
        lock.record_failure(1000, 1_000).unwrap();
        let api = Api::new(Config::new(vec![]))
            .with_user_policy_store(Some(store))
            .with_pin_lock(Some(lock))
            .with_clock(at_1000);

        let locked = api.get_status(status_caller(1000)).unwrap();
        assert_eq!(
            locked,
            vec![(
                "pin-locked".to_string(),
                "warning".to_string(),
                "Your PIN is locked for 8 more minutes.".to_string()
            )]
        );
        // Another user sees nothing of it, and no number of seconds or user appears.
        assert_eq!(api.get_status(status_caller(1001)).unwrap(), vec![]);
        let all = format!("{locked:?}");
        for hidden in ["430", "1000"] {
            assert!(!all.contains(hidden), "the status shows {hidden}: {all}");
        }
    }

    #[test]
    fn status_reports_a_damaged_lock_file_to_everyone() {
        use crate::pinlock::service::{Limits, PinLockService};
        use crate::pinlock::store::PinLockFile;
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let (store, _admin) = store_with_admin(&tmp);
        let uid = rustix::process::getuid().as_raw();
        let file = tmp.path().join("pinlock.toml");
        std::fs::write(&file, "broken").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let limits = Limits {
            max_attempts: 5,
            lockout_secs: 900,
            max_lockout_secs: 86_400,
        };
        let lock = PinLockService::start(PinLockFile::new(&file, uid), limits);
        let api = Api::new(Config::new(vec![]))
            .with_user_policy_store(Some(store))
            .with_pin_lock(Some(lock))
            .with_clock(at_1000);
        for user in [1000, 1001] {
            let status = api.get_status(status_caller(user)).unwrap();
            assert_eq!(status.len(), 1, "{status:?}");
            assert_eq!(status[0].0, "pin-lock-damaged");
            assert_eq!(status[0].1, "severe");
            assert!(!format!("{status:?}").contains("pinlock"), "no file name");
        }
    }

    #[test]
    fn status_says_when_the_tpm_lowered_the_pin_limit() {
        use crate::pinlock::service::{Limits, PinLockService};
        use crate::pinlock::store::PinLockFile;
        let tmp = TempDir::new().unwrap();
        let (store, _admin) = store_with_admin(&tmp);
        let uid = rustix::process::getuid().as_raw();
        let limits = Limits {
            max_attempts: 5,
            lockout_secs: 900,
            max_lockout_secs: 86_400,
        };
        let lock = PinLockService::start_capped(
            PinLockFile::new(tmp.path().join("pinlock.toml"), uid),
            limits,
            Some(3),
        );
        let api = Api::new(Config::new(vec![]))
            .with_user_policy_store(Some(store))
            .with_pin_lock(Some(lock))
            .with_clock(at_1000);
        let status = api.get_status(status_caller(1000)).unwrap();
        assert_eq!(status.len(), 1, "{status:?}");
        assert_eq!(status[0].0, "tpm-dictionary-limit-low");
        assert_eq!(status[0].1, "warning");
        assert!(
            status[0].2.contains('3') && status[0].2.contains('1'),
            "{status:?}"
        );
    }

    #[test]
    fn status_is_scoped_to_the_caller() {
        let tmp = TempDir::new().unwrap();
        let (store, admin) = store_with_admin(&tmp);
        std::fs::write(admin.join("strict.toml"), TOO_STRICT).unwrap();
        // User 1001's own layer is damaged; user 1000's is fine.
        let damaged = store.path(1001);
        std::fs::create_dir_all(damaged.parent().unwrap()).unwrap();
        std::fs::write(&damaged, "not a policy").unwrap();
        let api = Api::new(Config::new(vec![])).with_user_policy_store(Some(store));

        let codes = |uid| -> Vec<String> {
            api.get_status(status_caller(uid))
                .unwrap()
                .into_iter()
                .map(|(code, _, _)| code)
                .collect()
        };
        assert_eq!(codes(1000), ["context-unsatisfiable: sudo"]);
        let theirs = codes(1001);
        assert!(
            theirs.contains(&"policy-pin-only".to_string()),
            "{theirs:?}"
        );
        assert!(!codes(1000).contains(&"policy-pin-only".to_string()));
        assert!(codes(1002).iter().all(|c| c != "policy-pin-only"));
    }

    #[test]
    fn status_never_carries_a_file_name() {
        let tmp = TempDir::new().unwrap();
        let (store, admin) = store_with_admin(&tmp);
        std::fs::write(admin.join("broken-file.toml"), "this is not a policy").unwrap();
        let api = Api::new(Config::new(vec![])).with_user_policy_store(Some(store));
        let status = api.get_status(status_caller(1000)).unwrap();
        assert!(status.iter().any(|(code, _, _)| code == "policy-pin-only"));
        let all = format!("{status:?}");
        for name in ["broken-file", "policy.d", ".toml", "/"] {
            assert!(!all.contains(name), "the status names {name:?}: {all}");
        }
    }

    #[test]
    fn status_details_are_for_root_only() {
        let tmp = TempDir::new().unwrap();
        let (store, admin) = store_with_admin(&tmp);
        std::fs::write(admin.join("broken-file.toml"), "this is not a policy").unwrap();
        let api = Api::new(Config::new(vec![])).with_user_policy_store(Some(store));

        let details = api.get_status_details(status_caller(0)).unwrap();
        assert!(
            details
                .iter()
                .any(|(_, _, _, detail)| detail.contains("broken-file")),
            "{details:?}"
        );
        assert_eq!(
            api.get_status_details(status_caller(1000)),
            Err(ApiError::Denied)
        );
        let anonymous = Caller {
            uid: None,
            peer: None,
        };
        assert_eq!(api.get_status_details(anonymous), Err(ApiError::Denied));
    }

    #[test]
    fn status_codes_are_a_closed_set() {
        use linuxhello_dbus::status::{Severity, CODES, CONTEXTS, OTHER_CONTEXT};
        let tmp = TempDir::new().unwrap();
        let (store, admin) = store_with_admin(&tmp);
        // The schema accepts only the four contexts of `CONTEXTS`, so a name from a file cannot
        // reach a client (`linuxhello_dbus::status` keeps `other` for one that ever could).
        std::fs::write(admin.join("odd.toml"), TOO_STRICT).unwrap();
        let api = Api::new(Config::new(vec![])).with_user_policy_store(Some(store));
        let status = api.get_status(status_caller(1000)).unwrap();
        assert!(!status.is_empty(), "{status:?}");
        for (code, severity, _sentence) in &status {
            let (base, parameter) = code
                .split_once(": ")
                .map_or((code.as_str(), None), |(b, p)| (b, Some(p)));
            assert!(CODES.contains(&base), "unknown code {code}");
            if let Some(parameter) = parameter {
                assert!(
                    CONTEXTS.contains(&parameter) || parameter == OTHER_CONTEXT,
                    "unknown parameter {code}"
                );
            }
            assert!(Severity::ALL.iter().any(|s| s.as_wire() == severity));
        }
        assert!(status
            .iter()
            .any(|(code, _, _)| code == "context-unsatisfiable: sudo"));
    }

    /// A caller of user `uid` on the bus connection `peer`.
    fn on_peer(uid: u32, peer: &str) -> Caller {
        Caller {
            uid: Some(uid),
            peer: PeerName::new(peer),
        }
    }

    /// An API with a recorder, and a PIN socket in a temporary directory.
    fn pin_setup() -> (Api, Recorder, PinSocket, std::path::PathBuf, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pin.sock");
        let uid = rustix::process::getuid().as_raw();
        let socket = PinSocket::bind(&path, uid).unwrap();
        let (api, recorder) = audited_api(Config::new(vec![]));
        (api, recorder, socket, path, dir)
    }

    /// A valid prompt id.
    fn prompt(name: &str) -> String {
        PromptId::derive("test", name, "s1").as_str().to_string()
    }

    #[test]
    fn expect_pin_for_another_users_prompt_is_denied() {
        let (mut api, recorder, socket, _path, _dir) = pin_setup();
        let id = prompt("p1");
        api.open_prompt_from(on_peer(1000, ":1.1"), ":1.1", &id, Some(1000))
            .unwrap();
        // The opener may; another user, another connection of the opener's user and a prompt
        // that does not exist all get the same refusal.
        assert_eq!(
            api.expect_pin(on_peer(1000, ":1.1"), Some(10), &id, Some(&socket)),
            Ok(())
        );
        let stranger = on_peer(1001, ":1.2");
        let other_connection = on_peer(1000, ":1.3");
        let nothing = prompt("nothing");
        for (caller, what) in [
            (stranger, &id),
            (other_connection, &id),
            (on_peer(1000, ":1.1"), &nothing),
        ] {
            assert_eq!(
                api.expect_pin(caller, Some(11), what, Some(&socket)),
                Err(ApiError::Denied)
            );
        }
        assert_eq!(recorder.events().len(), 3, "each refusal is audited once");
    }

    #[test]
    fn a_caller_without_a_process_id_is_denied() {
        let (mut api, _recorder, socket, _path, _dir) = pin_setup();
        let id = prompt("p1");
        api.open_prompt_from(on_peer(1000, ":1.1"), ":1.1", &id, Some(1000))
            .unwrap();
        assert_eq!(
            api.expect_pin(on_peer(1000, ":1.1"), None, &id, Some(&socket)),
            Err(ApiError::Denied)
        );
    }

    #[test]
    fn a_prompt_without_a_subject_is_denied() {
        let (mut api, _recorder, socket, _path, _dir) = pin_setup();
        let id = prompt("p1");
        api.open_prompt_from(on_peer(0, ":1.1"), ":1.1", &id, None)
            .unwrap();
        assert_eq!(
            api.expect_pin(on_peer(0, ":1.1"), Some(10), &id, Some(&socket)),
            Err(ApiError::Denied)
        );
    }

    #[test]
    fn a_malformed_prompt_id_is_invalid_argument() {
        let (api, _recorder, socket, _path, _dir) = pin_setup();
        assert_eq!(
            api.expect_pin(on_peer(1000, ":1.1"), Some(10), "not an id", Some(&socket)),
            Err(ApiError::InvalidArgument)
        );
    }

    #[test]
    fn expect_pin_without_a_pin_socket_is_unavailable() {
        let (mut api, recorder, _socket, _path, _dir) = pin_setup();
        let id = prompt("p1");
        api.open_prompt_from(on_peer(1000, ":1.1"), ":1.1", &id, Some(1000))
            .unwrap();
        assert_eq!(
            api.expect_pin(on_peer(1000, ":1.1"), Some(10), &id, None),
            Err(ApiError::Unavailable)
        );
        assert!(
            recorder.events().is_empty(),
            "an unavailable service is not a refusal"
        );
    }

    #[test]
    fn a_full_table_is_limit_reached() {
        let (mut api, _recorder, socket, _path, _dir) = pin_setup();
        let id = prompt("p1");
        api.open_prompt_from(on_peer(1000, ":1.1"), ":1.1", &id, Some(1000))
            .unwrap();
        for pid in 0..64 {
            assert_eq!(
                api.expect_pin(on_peer(1000, ":1.1"), Some(1000 + pid), &id, Some(&socket)),
                Ok(())
            );
        }
        assert_eq!(
            api.expect_pin(on_peer(1000, ":1.1"), Some(5000), &id, Some(&socket)),
            Err(ApiError::LimitReached)
        );
    }

    #[test]
    fn an_expected_process_may_send_one_pin() {
        use std::io::{Read, Write};
        let (mut api, _recorder, socket, path, _dir) = pin_setup();
        let (uid, pid) = (rustix::process::getuid().as_raw(), std::process::id());
        let id = prompt("p1");
        api.open_prompt_from(on_peer(uid, ":1.1"), ":1.1", &id, Some(uid))
            .unwrap();
        let send = |pin: &[u8]| {
            let mut stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = u16::try_from(pin.len()).unwrap().to_be_bytes().to_vec();
            bytes.extend_from_slice(pin);
            drop(stream.write_all(&bytes));
            drop(stream.shutdown(std::net::Shutdown::Write));
            let mut reply = [9_u8; 1];
            stream.read_exact(&mut reply).unwrap();
            reply[0]
        };
        let mut got = Vec::new();
        std::thread::scope(|scope| {
            // Before the call: refused. After it: accepted, once.
            let refused = scope.spawn(|| send(b"1234"));
            socket
                .serve_one(&mut |s| got.push((s.subject, s.pin.to_vec())))
                .unwrap();
            assert_eq!(refused.join().unwrap(), crate::pinsocket::REPLY_REFUSED);
            api.expect_pin(on_peer(uid, ":1.1"), Some(pid), &id, Some(&socket))
                .unwrap();
            let accepted = scope.spawn(|| send(b"1234"));
            socket
                .serve_one(&mut |s| got.push((s.subject, s.pin.to_vec())))
                .unwrap();
            assert_eq!(accepted.join().unwrap(), crate::pinsocket::REPLY_ACCEPTED);
            let again = scope.spawn(|| send(b"1234"));
            socket
                .serve_one(&mut |s| got.push((s.subject, s.pin.to_vec())))
                .unwrap();
            assert_eq!(again.join().unwrap(), crate::pinsocket::REPLY_REFUSED);
        });
        assert_eq!(got, vec![(uid, b"1234".to_vec())]);
    }

    /// An API with a policy store, a recorder, and a prompt of user 1000 on `:1.1` for 1000.
    fn authentication_setup() -> (Api, Recorder, TempDir, String) {
        let tmp = TempDir::new().unwrap();
        let (store, _admin) = store_with_admin(&tmp);
        let (api, recorder) = audited_api(Config::new(vec![]));
        let mut api = api.with_user_policy_store(Some(store));
        let id = prompt("p1");
        api.open_prompt_from(on_peer(1000, ":1.1"), ":1.1", &id, Some(1000))
            .unwrap();
        (api, recorder, tmp, id)
    }

    #[test]
    fn authenticate_for_another_users_prompt_is_denied() {
        let (mut api, recorder, _tmp, id) = authentication_setup();
        let other_user = on_peer(1001, ":1.2");
        let other_connection = on_peer(1000, ":1.3");
        let nothing = prompt("nothing");
        for (caller, what) in [
            (other_user, &id),
            (other_connection, &id),
            (on_peer(1000, ":1.1"), &nothing),
        ] {
            assert!(matches!(
                api.begin_authentication(caller, what, "login"),
                Err(ApiError::Denied)
            ));
        }
        assert_eq!(recorder.events().len(), 3, "each refusal is audited once");
        // A prompt opened for nobody in particular has no subject to authenticate.
        let none = prompt("none");
        api.open_prompt_from(on_peer(0, ":1.9"), ":1.9", &none, None)
            .unwrap();
        assert!(matches!(
            api.begin_authentication(on_peer(0, ":1.9"), &none, "login"),
            Err(ApiError::Denied)
        ));
    }

    #[test]
    fn authenticate_checks_its_arguments() {
        let (mut api, _recorder, _tmp, id) = authentication_setup();
        let opener = on_peer(1000, ":1.1");
        for context in ["", "Login", "root", "login ", "logins"] {
            assert!(matches!(
                api.begin_authentication(opener, &id, context),
                Err(ApiError::InvalidArgument)
            ));
        }
        assert!(matches!(
            api.begin_authentication(opener, "not an id", "login"),
            Err(ApiError::InvalidArgument)
        ));
        for context in ["login", "unlock", "sudo", "session"] {
            let (mut api, _recorder, _tmp, id) = authentication_setup();
            let start = api.begin_authentication(opener, &id, context).unwrap();
            assert_eq!(start.subject, 1000);
        }
    }

    #[test]
    fn a_second_authenticate_is_refused_while_one_runs() {
        let (mut api, _recorder, _tmp, id) = authentication_setup();
        let opener = on_peer(1000, ":1.1");
        let first = api.begin_authentication(opener, &id, "login").unwrap();
        assert!(matches!(
            api.begin_authentication(opener, &id, "sudo"),
            Err(ApiError::LimitReached)
        ));
        // The end of the first frees the prompt.
        let ended = Update::Result(Outcome::new(PromptResult::Failure));
        api.agent_report(1000, &first.prompt, ended);
        assert!(api.begin_authentication(opener, &id, "sudo").is_ok());
    }

    #[test]
    fn closing_the_prompt_stops_its_authentication() {
        let (mut api, _recorder, _tmp, id) = authentication_setup();
        let opener = on_peer(1000, ":1.1");
        let start = api.begin_authentication(opener, &id, "login").unwrap();
        assert!(!start.stop.is_cancelled());
        api.close_prompt(opener, &id).unwrap();
        assert!(start.stop.is_cancelled());

        // The opener leaving the bus does the same.
        let id2 = prompt("p2");
        api.open_prompt_from(on_peer(1000, ":1.5"), ":1.5", &id2, Some(1000))
            .unwrap();
        let start = api
            .begin_authentication(on_peer(1000, ":1.5"), &id2, "login")
            .unwrap();
        api.peer_left(":1.5");
        assert!(start.stop.is_cancelled());
    }

    #[test]
    fn authenticate_without_a_policy_store_is_unavailable() {
        let (mut api, _recorder) = audited_api(Config::new(vec![]));
        let id = prompt("p1");
        api.open_prompt_from(on_peer(1000, ":1.1"), ":1.1", &id, Some(1000))
            .unwrap();
        assert!(matches!(
            api.begin_authentication(on_peer(1000, ":1.1"), &id, "login"),
            Err(ApiError::Unavailable)
        ));
    }

    #[test]
    fn the_orchestrators_reports_become_signals_for_the_subscribers() {
        let (mut api, _recorder, _tmp, id) = authentication_setup();
        let opener = on_peer(1000, ":1.1");
        api.subscribe(on_peer(1000, ":1.1"), ":1.7", &id).unwrap();
        let start = api.begin_authentication(opener, &id, "login").unwrap();
        let notes = api.agent_report(
            1000,
            &start.prompt,
            Update::Active(vec![AuthMethod::Fingerprint]),
        );
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].signal, "ActiveMethods");
        assert_eq!(notes[0].values, vec!["fingerprint".to_string()]);
        // A report for a prompt that is gone changes nothing and sends nothing.
        let gone = PromptId::parse(&prompt("gone")).unwrap();
        assert!(api
            .agent_report(1000, &gone, Update::State(PromptState::Idle))
            .is_empty());
    }

    #[test]
    fn a_sound_policy_is_not_audited() {
        let tmp = TempDir::new().unwrap();
        let (store, _admin) = store_with_admin(&tmp);
        let (api, recorder) = audited_api(Config::new(vec![]));
        let api = api.with_user_policy_store(Some(store));
        assert!(matches!(api.policy_of(1000), Ok(Policy::Effective(_))));
        assert!(recorder.events().is_empty());
    }

    #[test]
    fn the_policy_is_unavailable_without_a_store() {
        let (api, recorder) = audited_api(Config::new(vec![]));
        assert_eq!(api.policy_of(1000), Err(ApiError::Unavailable));
        assert!(recorder.events().is_empty());
    }

    #[test]
    fn a_layer_that_is_stored_but_not_synced_counts_as_stored() {
        let tmp = TempDir::new().unwrap();
        let store = UserPolicyStore::new(tmp.path()).with_dir_sync(std::sync::Arc::new(|_| {
            Err(std::io::Error::other("the disk is gone"))
        }));
        let (api, recorder) = audited_api(Config::new(vec![]));
        let mut api = api.with_user_policy_store(Some(store));
        let tighter = "[methods]\nbiometrics_allowed = false\n";
        assert_eq!(api.set_user_policy(USER, tighter), Ok(()));
        assert_eq!(api.get_user_policy(USER), Ok(tighter.to_string()));
        assert_eq!(recorder.events(), vec![Event::user_policy_set(1000)]);
    }

    #[test]
    fn a_damaged_layer_is_reported_as_damaged_and_can_be_replaced() {
        let tmp = TempDir::new().unwrap();
        let store = UserPolicyStore::new(tmp.path());
        std::fs::create_dir_all(store.path(1000).parent().unwrap()).unwrap();
        std::fs::write(store.path(1000), [0xff, 0xfe]).unwrap();
        let (api, recorder) = audited_api(Config::new(vec![]));
        let mut api = api.with_user_policy_store(Some(store));
        assert_eq!(api.get_user_policy(USER), Err(ApiError::Damaged));
        // A damaged store is not a refusal of the caller: nothing is audited as one.
        assert!(recorder.events().is_empty());
        assert_eq!(
            api.set_user_policy(USER, "[methods]\nbiometrics_allowed = false\n"),
            Ok(())
        );
    }

    #[test]
    fn a_client_cannot_report_a_closed_signal() {
        let mut api = Api::new(Config::new(vec![]));
        api.open_prompt(USER, &pid("p1"), Some(1000)).unwrap();
        assert_eq!(
            api.report_state(USER, &pid("p1"), "Closed", &[]),
            Err(ApiError::InvalidArgument)
        );
    }

    #[test]
    fn closures_are_one_signal_per_subscriber_naming_only_the_prompt() {
        let mut api = Api::new(Config::new(vec![]));
        let id = pid("p1");
        api.open_prompt_from(USER, ":1.1", &id, Some(1000)).unwrap();
        api.subscribe(USER, ":1.5", &id).unwrap();
        api.subscribe(USER, ":1.6", &id).unwrap();
        api.unsubscribe(USER, ":1.6", &id).unwrap();
        api.close_prompt(USER, &id).unwrap();
        let notes = api.take_closures();
        assert_eq!(
            notes,
            vec![Notification {
                peer: Peer(":1.5".to_string()),
                signal: "Closed",
                prompt_id: id.clone(),
                values: vec![],
            }]
        );
        assert!(api.take_closures().is_empty());
    }

    #[test]
    fn unsubscribe_checks_its_arguments_like_subscribe() {
        let mut api = Api::new(Config::new(vec![]));
        let id = pid("p1");
        api.open_prompt(USER, &id, Some(1000)).unwrap();
        assert_eq!(
            api.unsubscribe(
                Caller {
                    uid: None,
                    peer: None
                },
                ":1.5",
                &id
            ),
            Err(ApiError::Denied)
        );
        assert_eq!(
            api.unsubscribe(USER, "not-a-unique-name", &id),
            Err(ApiError::InvalidArgument)
        );
        assert_eq!(
            api.unsubscribe(USER, ":1.5", "not a prompt id"),
            Err(ApiError::InvalidArgument)
        );
    }

    #[test]
    fn a_refusal_records_the_callers_bus_name() {
        let (api, recorder) = audited_api(Config::new(vec![]));
        let named = Caller {
            uid: Some(1000),
            peer: PeerName::new(":1.42"),
        };
        // An unknown prompt is refused as `Denied`, whoever asks.
        assert_eq!(api.get_state(named, &pid("unknown")), Err(ApiError::Denied));
        assert_eq!(api.get_state(USER, &pid("unknown")), Err(ApiError::Denied));
        assert_eq!(
            recorder.events(),
            vec![
                Event::denied(Some(1000)).with_peer(PeerName::new(":1.42")),
                Event::denied(Some(1000)),
            ]
        );
        assert!(recorder.events()[1]
            .fields()
            .iter()
            .all(|(n, _)| *n != "LH_PEER"));
    }

    #[test]
    fn refused_call_is_audited_with_uid_and_reason() {
        let mut config = Config::new(vec![]);
        config.max_prompts_per_reporter = 1;
        let (mut api, recorder) = audited_api(config);
        let no_uid = Caller {
            uid: None,
            peer: None,
        };

        assert_eq!(
            api.open_prompt(no_uid, &pid("a"), None),
            Err(ApiError::Denied)
        );
        assert_eq!(recorder.events(), vec![Event::denied(None)]);

        api.open_prompt(USER, &pid("a"), Some(1000)).unwrap();
        let other = Caller {
            uid: Some(1001),
            peer: None,
        };
        assert_eq!(api.get_state(other, &pid("a")), Err(ApiError::Denied));
        assert_eq!(recorder.events().last(), Some(&Event::denied(Some(1001))));

        assert_eq!(
            api.open_prompt(USER, &pid("b"), Some(1000)),
            Err(ApiError::LimitReached)
        );
        assert_eq!(
            recorder.events().last(),
            Some(&Event::limit_reached(Some(1000)))
        );

        assert_eq!(
            api.open_prompt(USER, "x", None),
            Err(ApiError::InvalidArgument)
        );
        assert_eq!(
            recorder.events().last(),
            Some(&Event::invalid_argument(Some(1000)))
        );
        assert_eq!(recorder.events().len(), 4);
    }

    #[test]
    fn successful_calls_are_not_audited() {
        let (mut api, recorder) = audited_api(Config::new(vec![]));
        let id = pid("a");

        api.open_prompt(USER, &id, Some(1000)).unwrap();
        api.report_state(USER, &id, "State", &["idle"]).unwrap();
        api.get_state(USER, &id).unwrap();
        api.subscribe(USER, ":1.7", &id).unwrap();
        api.close_prompt(USER, &id).unwrap();

        assert!(recorder.events().is_empty());
    }

    #[test]
    fn user_policy_change_is_audited_without_its_text() {
        let tmp = TempDir::new().unwrap();
        let (api, recorder) = audited_api(Config::new(vec![]));
        let mut api = api.with_user_policy_store(Some(UserPolicyStore::new(tmp.path())));
        let marker = "MARKER".repeat(3);
        let text = format!("# {marker}\n[methods]\nbiometrics_allowed = false\n");

        api.set_user_policy(USER, &text).unwrap();
        api.set_user_policy(USER, "").unwrap();
        assert_eq!(
            recorder.events(),
            vec![
                Event::user_policy_set(1000),
                Event::user_policy_removed(1000)
            ]
        );

        assert!(matches!(
            api.set_user_policy(USER, "invalid = toml"),
            Err(ApiError::InvalidPolicy(_))
        ));
        assert_eq!(
            recorder.events().last(),
            Some(&Event::invalid_argument(Some(1000)))
        );
        assert_eq!(recorder.events().len(), 3);

        for event in recorder.events() {
            for (_, value) in event.fields() {
                assert!(!value.contains(&marker));
                assert!(value.len() <= 64);
            }
        }
    }

    #[test]
    fn audit_events_are_rate_limited_per_uid() {
        let (mut api, recorder) = audited_api(Config::new(vec![]));
        let other = Caller {
            uid: Some(1001),
            peer: None,
        };

        for _ in 0..20 {
            let _ = api.open_prompt(USER, "x", None);
        }
        let _ = api.open_prompt(other, "x", None);

        let events = recorder.events();
        let count = |event: Event| events.iter().filter(|e| **e == event).count();
        assert_eq!(count(Event::invalid_argument(Some(1000))), 5);
        assert_eq!(count(Event::invalid_argument(Some(1001))), 1);

        let no_uid = Caller {
            uid: None,
            peer: None,
        };
        for _ in 0..20 {
            let _ = api.open_prompt(no_uid, "x", None);
        }
        let denied = recorder
            .events()
            .iter()
            .filter(|e| **e == Event::denied(None))
            .count();
        assert_eq!(denied, 20);
    }

    #[test]
    fn a_journal_that_cannot_be_written_does_not_change_the_answer() {
        let tmp = TempDir::new().unwrap();
        let audit = Audit::new(Box::new(crate::audit::JournalSink::at(
            "/nonexistent/journal",
        )));
        let mut api = Api::new(Config::new(vec![]))
            .with_user_policy_store(Some(UserPolicyStore::new(tmp.path())))
            .with_audit(audit);

        assert_eq!(
            api.open_prompt(
                Caller {
                    uid: None,
                    peer: None
                },
                &pid("a"),
                None
            ),
            Err(ApiError::Denied)
        );
        let text = "[methods]\nbiometrics_allowed = false\n";
        assert_eq!(api.set_user_policy(USER, text), Ok(()));
        assert_eq!(api.get_user_policy(USER).unwrap(), text);
    }
}
