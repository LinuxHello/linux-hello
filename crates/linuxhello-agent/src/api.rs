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
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

use linuxhello_dbus::{AuthMethod, PromptId, PromptResult, PromptState, SIGNALS};

use crate::state::{Config, Error as StateError, Peer, StateStore, Update};

/// The longest D-Bus bus name, in bytes.
const MAX_PEER_NAME: usize = 255;

/// Who is calling, as the bus told us.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    /// The caller's uid from the bus peer credentials, or `None` when the bus could not give
    /// it. A caller without a uid is refused.
    pub uid: Option<u32>,
}

/// Why the request layer refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiError {
    /// The caller may not do this, has no readable credentials, or the prompt is unknown.
    Denied,
    /// A limit of the state store is reached.
    LimitReached,
    /// An argument is not valid: a prompt id, signal name, value or peer name.
    InvalidArgument,
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
    /// The method that is running, if any.
    pub active: Option<String>,
    /// What the prompt is doing.
    pub state: String,
    /// How the attempt ended, once it has.
    pub result: Option<String>,
}

/// The request layer over a [`StateStore`].
pub struct Api {
    /// The per-prompt state and its access rules.
    store: StateStore,
}

impl Api {
    /// An API over an empty store with the given settings.
    pub fn new(config: Config) -> Self {
        Self {
            store: StateStore::new(config),
        }
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
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        Ok(self.store.open(uid, &prompt, subject_uid)?)
    }

    /// Applies one change to a prompt and returns the notifications to send, one per
    /// subscribed peer, in the order they subscribed.
    ///
    /// `signal` is one of the names in `linuxhello_dbus::SIGNALS`. `MethodsAvailable` takes
    /// any number of different methods, `ActiveMethod` none or one, `State` and `Result`
    /// exactly one value.
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
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        let snapshot = self.store.get(uid, &prompt)?;
        Ok(StateReply {
            methods: snapshot
                .methods
                .iter()
                .map(|m| m.as_wire().to_string())
                .collect(),
            active: snapshot.active.map(|m| m.as_wire().to_string()),
            state: snapshot.state.as_wire().to_string(),
            result: snapshot.result.map(|r| r.as_wire().to_string()),
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
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        if !peer.starts_with(':') || peer.len() > MAX_PEER_NAME {
            return Err(ApiError::InvalidArgument);
        }
        Ok(self.store.subscribe(uid, Peer(peer.to_string()), &prompt)?)
    }

    /// Closes a prompt opened by the caller.
    ///
    /// # Errors
    ///
    /// [`ApiError::Denied`] without a caller uid or unless the caller opened the prompt;
    /// [`ApiError::InvalidArgument`] for a prompt id that is not valid.
    pub fn close_prompt(&mut self, caller: Caller, prompt_id: &str) -> Result<(), ApiError> {
        let uid = caller.uid.ok_or(ApiError::Denied)?;
        let prompt = parse_prompt(prompt_id)?;
        Ok(self.store.close(uid, &prompt)?)
    }
}

/// Parses a prompt id given as text.
fn parse_prompt(prompt_id: &str) -> Result<PromptId, ApiError> {
    PromptId::parse(prompt_id).ok_or(ApiError::InvalidArgument)
}

/// Parses the values of a signal into the store's update for it.
fn parse_update(signal: &str, values: &[&str]) -> Result<Update, ApiError> {
    match (signal, values) {
        ("MethodsAvailable", values) => {
            let mut methods = Vec::new();
            for value in values {
                let method = AuthMethod::from_wire(value).ok_or(ApiError::InvalidArgument)?;
                if methods.contains(&method) {
                    return Err(ApiError::InvalidArgument);
                }
                methods.push(method);
            }
            Ok(Update::Methods(methods))
        }
        ("ActiveMethod", []) => Ok(Update::Active(None)),
        ("ActiveMethod", [value]) => AuthMethod::from_wire(value)
            .map(|method| Update::Active(Some(method)))
            .ok_or(ApiError::InvalidArgument),
        ("State", [value]) => PromptState::from_wire(value)
            .map(Update::State)
            .ok_or(ApiError::InvalidArgument),
        ("Result", [value]) => PromptResult::from_wire(value)
            .map(Update::Result)
            .ok_or(ApiError::InvalidArgument),
        _ => Err(ApiError::InvalidArgument),
    }
}

/// The canonical wire strings of an update's values.
fn wire_values(update: &Update) -> Vec<String> {
    match update {
        Update::Methods(methods) => methods.iter().map(|m| m.as_wire().to_string()).collect(),
        Update::Active(active) => active.iter().map(|m| m.as_wire().to_string()).collect(),
        Update::State(state) => vec![state.as_wire().to_string()],
        Update::Result(result) => vec![result.as_wire().to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid prompt id as text, from a short name.
    fn pid(name: &str) -> String {
        PromptId::derive("test", name, "s1").as_str().to_string()
    }

    /// An ordinary caller.
    const USER: Caller = Caller { uid: Some(1000) };

    /// An `Api` with a prompt opened by `USER` for itself.
    fn api_with_prompt(id: &str) -> Api {
        let mut api = Api::new(Config::new(vec![990]));
        api.open_prompt(USER, id, Some(1000)).unwrap();
        api
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
        let bad: [(&str, &[&str]); 6] = [
            ("State", &["bogus"]),
            ("State", &[]),
            ("State", &["idle", "idle"]),
            ("Result", &["bogus"]),
            ("ActiveMethod", &["face", "pin"]),
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

        let told = api.report_state(USER, &id, "ActiveMethod", &[]).unwrap();
        assert!(told[0].values.is_empty());
        let told = api.report_state(USER, &id, "State", &["scanning"]).unwrap();
        assert_eq!(told[0].values, vec!["scanning".to_string()]);
    }

    #[test]
    fn get_state_returns_wire_strings() {
        let id = pid("p1");
        let mut api = api_with_prompt(&id);
        let fresh = api.get_state(USER, &id).unwrap();
        assert!(fresh.methods.is_empty());
        assert_eq!(fresh.active, None);
        assert_eq!(fresh.state, "idle");
        assert_eq!(fresh.result, None);

        api.report_state(USER, &id, "MethodsAvailable", &["face"])
            .unwrap();
        api.report_state(USER, &id, "ActiveMethod", &["face"])
            .unwrap();
        api.report_state(USER, &id, "State", &["scanning"]).unwrap();
        api.report_state(USER, &id, "Result", &["failure"]).unwrap();
        let reply = api.get_state(USER, &id).unwrap();
        assert_eq!(reply.methods, vec!["face".to_string()]);
        assert_eq!(reply.active, Some("face".to_string()));
        assert_eq!(reply.state, "scanning");
        assert_eq!(reply.result, Some("failure".to_string()));
    }

    #[test]
    fn store_refusals_pass_through_unchanged() {
        let id = pid("p1");
        let mut api = api_with_prompt(&id);
        let other = Caller { uid: Some(1001) };
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
}
