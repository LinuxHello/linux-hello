//! The Agent's audit trail: one structured journald record for every refused request and for
//! every change of a user's policy layer.
//!
//! An [`Event`] holds only a kind, an optional uid and fixed words written in this file. It has
//! no field for text a caller sent, so a PIN, a policy text or an argument cannot reach the
//! journal. The journal is written through its native datagram socket, which needs no `unsafe`
//! and no library. Refusal records (denied, limit reached, invalid argument) are limited per uid
//! and kind ([`RateLimiter`]) so that one user cannot fill the journal and make it drop later
//! records; when a limit has dropped records, the next record that passes is preceded by one that
//! says how many were dropped (`refusals_of_every_kind_are_limited_and_the_drops_are_counted`).
//! Policy changes are never limited. A journal that cannot be written is ignored: an audit failure must not turn a
//! refusal into a different answer, and the Agent has nowhere else to report it.
//!
//! Security properties: `refused_call_is_audited_with_uid_and_reason`,
//! `user_policy_change_is_audited_without_its_text` and `audit_events_are_rate_limited_per_uid`
//! (P-13, partly: the events that exist so far). P-27 is covered by
//! `every_unlock_signature_pin_change_and_reset_is_audited` for the same events only.
//!
//! C4 component: `auditLog` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::collections::{HashMap, VecDeque};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::api::PeerName;
use crate::policy::load::Fault;
use linuxhello_dbus::PromptResult;

/// The socket the journal reads native records from.
const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// The identifier the records are filed under.
const IDENTIFIER: &str = "linuxhello-agent";

/// `MESSAGE_ID` of a denied request.
const ID_DENIED: &str = "5cf459c67dd74e038b68bdf2bd351737";
/// `MESSAGE_ID` of a request refused because a limit is reached.
const ID_LIMIT_REACHED: &str = "f85373d2e7914352b76b1b560ed72afd";
/// `MESSAGE_ID` of a request refused because an argument is not valid.
const ID_INVALID_ARGUMENT: &str = "f7764b2f857d4a7494efd1c62dc8099c";
/// `MESSAGE_ID` of a stored user policy layer.
const ID_USER_POLICY_SET: &str = "1afc7d18dd5441b4afe6088c4fe45cef";
/// `MESSAGE_ID` of a removed user policy layer.
const ID_USER_POLICY_REMOVED: &str = "a30a9a431e9f4e57bfc8dea8aaa2fe91";

/// `MESSAGE_ID` of a policy that fell back to PIN-only.
const ID_POLICY_PIN_ONLY: &str = "050c3a8220f349669c1a7111fad2fc6d";

/// How many uids the rate limiter remembers at most.
const MAX_TRACKED_UIDS: usize = 4096;

/// `MESSAGE_ID` of the end of a job: a sign-in, a PIN set or change, a reset or an enrolment.
const ID_JOB_ENDED: &str = "a1c4e7f2b3d84a6f9e0c5b7d2f813a46";

/// `MESSAGE_ID` of a record that says refusal records were dropped by the rate limit.
const ID_SUPPRESSED: &str = "7d3f2c1e9b8a4f60a5e1c2d3b4a59687";

/// How many refusal records one uid may cause per window, for each kind of refusal.
const REFUSAL_BURST: u32 = 5;

/// The window of the refusal limit.
const REFUSAL_WINDOW: Duration = Duration::from_secs(60);

/// What a job that ended did: the actions of the Agent that change what lets a person in, or that
/// let them in (review finding R-12, #354).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// A sign-in: the authentication of a prompt.
    SignIn,
    /// The first PIN was set.
    PinSet,
    /// The PIN was changed.
    PinChange,
    /// The destructive reset of ADR-0003.
    Reset,
    /// A fingerprint was enrolled.
    Enrolment,
}

impl Action {
    /// The fixed word that names the action in the record's `LH_EVENT`.
    const fn word(self) -> &'static str {
        match self {
            Self::SignIn => "sign_in",
            Self::PinSet => "pin_set",
            Self::PinChange => "pin_change",
            Self::Reset => "reset",
            Self::Enrolment => "enrolment",
        }
    }

    /// The fixed text of the record's `MESSAGE`.
    const fn message(self) -> &'static str {
        match self {
            Self::SignIn => "sign-in ended",
            Self::PinSet => "PIN set ended",
            Self::PinChange => "PIN change ended",
            Self::Reset => "reset ended",
            Self::Enrolment => "fingerprint enrolment ended",
        }
    }
}

/// What happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// The caller may not do this.
    Denied,
    /// A limit of the state store is reached.
    LimitReached,
    /// An argument is not valid.
    InvalidArgument,
    /// A user policy layer was stored.
    UserPolicySet,
    /// A user policy layer was removed.
    UserPolicyRemoved,
    /// A policy could not be loaded and the Agent fell back to PIN-only; the fault says which
    /// layer was to blame.
    PolicyPinOnly(Fault),
    /// A job of the Agent ended with `result` for the user the record's uid names.
    JobEnded {
        /// What the job did.
        action: Action,
        /// How it ended.
        result: PromptResult,
    },
    /// `count` records of the refusal kind named `of` were dropped by the rate limit.
    Suppressed {
        /// The event word of the dropped records.
        of: &'static str,
        /// How many were dropped.
        count: u32,
    },
}

/// One audit record: a kind and the uid it concerns. It carries no text from a caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// What happened.
    kind: Kind,
    /// The uid of the caller, when the bus gave one.
    uid: Option<u32>,
    /// The unique bus name of the caller's connection, when the bus gave one and it has the form
    /// of one (see [`Event::with_peer`]).
    peer: Option<PeerName>,
}

impl Event {
    /// A request the caller may not make; `uid` is none when the bus gave no credentials.
    pub fn denied(uid: Option<u32>) -> Self {
        Self {
            kind: Kind::Denied,
            uid,
            peer: None,
        }
    }

    /// A request refused because a limit is reached.
    pub fn limit_reached(uid: Option<u32>) -> Self {
        Self {
            kind: Kind::LimitReached,
            uid,
            peer: None,
        }
    }

    /// A request refused because an argument is not valid.
    pub fn invalid_argument(uid: Option<u32>) -> Self {
        Self {
            kind: Kind::InvalidArgument,
            uid,
            peer: None,
        }
    }

    /// The user's policy layer was stored.
    pub fn user_policy_set(uid: u32) -> Self {
        Self {
            kind: Kind::UserPolicySet,
            uid: Some(uid),
            peer: None,
        }
    }

    /// The user's policy layer was removed.
    pub fn user_policy_removed(uid: u32) -> Self {
        Self {
            kind: Kind::UserPolicyRemoved,
            uid: Some(uid),
            peer: None,
        }
    }

    /// The policy of `uid` could not be loaded and the Agent fell back to PIN-only. Only the
    /// fault (a fixed word) is recorded, never the reason text, which can name a file or a
    /// class of a policy (`pin_only_fallback_is_audited_with_its_reason`).
    pub fn policy_pin_only(uid: u32, fault: Fault) -> Self {
        Self {
            kind: Kind::PolicyPinOnly(fault),
            uid: Some(uid),
            peer: None,
        }
    }

    /// A job of `action` ended with `result`; `subject` is the user it was for. Only the action
    /// and the result (fixed words) are recorded, never anything the user or the job sent.
    pub fn job_ended(subject: u32, action: Action, result: PromptResult) -> Self {
        Self {
            kind: Kind::JobEnded { action, result },
            uid: Some(subject),
            peer: None,
        }
    }

    /// `count` refusal records of `uid` of the kind `of` were dropped by the rate limit.
    fn suppressed(uid: u32, of: &'static str, count: u32) -> Self {
        Self {
            kind: Kind::Suppressed { of, count },
            uid: Some(uid),
            peer: None,
        }
    }

    /// The same event for the connection `peer`, the unique bus name the bus daemon gave the
    /// caller (see [`PeerName`]: it has no form that could carry a caller's own text, P-13).
    #[must_use]
    pub fn with_peer(self, peer: Option<PeerName>) -> Self {
        Self { peer, ..self }
    }

    /// The journal fields of the record, in the order they are written: `PRIORITY`,
    /// `SYSLOG_IDENTIFIER`, `MESSAGE_ID`, `LH_EVENT`, `LH_UID` (only with a uid), `LH_PEER`
    /// (only with a bus name), `LH_OUTCOME` and `MESSAGE`. Names and words are fixed and contain no newline.
    pub fn fields(&self) -> Vec<(&'static str, String)> {
        let (priority, message_id, event, outcome, message) = match self.kind {
            Kind::Denied => ("4", ID_DENIED, "denied", "refused", "request denied"),
            Kind::LimitReached => (
                "4",
                ID_LIMIT_REACHED,
                "limit_reached",
                "refused",
                "request refused: limit reached",
            ),
            Kind::InvalidArgument => (
                "4",
                ID_INVALID_ARGUMENT,
                "invalid_argument",
                "refused",
                "request refused: invalid argument",
            ),
            Kind::UserPolicySet => (
                "5",
                ID_USER_POLICY_SET,
                "user_policy_set",
                "done",
                "user policy layer stored",
            ),
            Kind::UserPolicyRemoved => (
                "5",
                ID_USER_POLICY_REMOVED,
                "user_policy_removed",
                "done",
                "user policy layer removed",
            ),
            Kind::PolicyPinOnly(_) => (
                "4",
                ID_POLICY_PIN_ONLY,
                "policy_pin_only",
                "fallback",
                "policy fell back to PIN-only",
            ),
            Kind::JobEnded { action, result } => (
                match result {
                    PromptResult::Success => "5",
                    PromptResult::Cancelled => "6",
                    PromptResult::Failure | PromptResult::LockedOut => "4",
                },
                ID_JOB_ENDED,
                action.word(),
                result.as_wire(),
                action.message(),
            ),
            Kind::Suppressed { .. } => (
                "4",
                ID_SUPPRESSED,
                "suppressed",
                "limited",
                "refusal records dropped by the rate limit",
            ),
        };
        let mut fields = vec![
            ("PRIORITY", priority.to_string()),
            ("SYSLOG_IDENTIFIER", IDENTIFIER.to_string()),
            ("MESSAGE_ID", message_id.to_string()),
            ("LH_EVENT", event.to_string()),
        ];
        if let Some(uid) = self.uid {
            fields.push(("LH_UID", uid.to_string()));
        }
        if let Some(peer) = &self.peer {
            fields.push(("LH_PEER", peer.as_str().to_string()));
        }
        if let Kind::PolicyPinOnly(fault) = self.kind {
            fields.push(("LH_FAULT", fault.word().to_string()));
        }
        if let Kind::Suppressed { of, count } = self.kind {
            fields.push(("LH_SUPPRESSED_EVENT", of.to_string()));
            fields.push(("LH_SUPPRESSED_COUNT", count.to_string()));
        }
        fields.push(("LH_OUTCOME", outcome.to_string()));
        fields.push(("MESSAGE", message.to_string()));
        fields
    }
}

/// Where audit records go.
pub trait AuditSink: Send + Sync {
    /// Records one event. It cannot fail toward the caller: a sink drops what it cannot write.
    fn record(&self, event: &Event);
}

/// A sink that drops every event.
struct NullSink;

impl AuditSink for NullSink {
    /// Drops the event.
    fn record(&self, _event: &Event) {}
}

/// A sink that writes native journal records to the journal's datagram socket.
pub struct JournalSink {
    /// The socket to send to.
    path: PathBuf,
}

impl JournalSink {
    /// A sink for the system journal.
    pub fn journal() -> Self {
        Self::at(JOURNAL_SOCKET)
    }

    /// A sink for a datagram socket at `path`, for tests.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl AuditSink for JournalSink {
    /// Sends the fields as `KEY=value` lines in one datagram and ignores any error: an audit
    /// failure must not change the answer to the caller, and there is nowhere else to report it.
    fn record(&self, event: &Event) {
        let mut buffer = String::new();
        for (key, value) in event.fields() {
            buffer.push_str(key);
            buffer.push('=');
            buffer.push_str(&value);
            buffer.push('\n');
        }
        if let Ok(socket) = UnixDatagram::unbound() {
            drop(socket.send_to(buffer.as_bytes(), &self.path));
        }
    }
}

/// A per-uid limit on how many events pass in a window.
pub struct RateLimiter {
    /// How many events one uid may cause per window.
    max: u32,
    /// The length of the window.
    window: Duration,
    /// For each uid, the times of its allowed events inside the window.
    seen: HashMap<u32, VecDeque<Instant>>,
    /// For each uid, how many events were refused since one last passed.
    dropped: HashMap<u32, u32>,
}

impl RateLimiter {
    /// A limiter that allows `max` events per uid in any `window`.
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            seen: HashMap::new(),
            dropped: HashMap::new(),
        }
    }

    /// How many events of `uid` were refused since the last one passed; starts counting again from
    /// zero.
    pub fn take_dropped(&mut self, uid: u32) -> u32 {
        self.dropped.remove(&uid).unwrap_or(0)
    }

    /// Whether an event of `uid` at `now` may pass. Remembers at most 4096 uids: a new uid that
    /// finds the table full first evicts the uids whose events are all older than the window,
    /// and is refused when none is.
    pub fn allow(&mut self, uid: u32, now: Instant) -> bool {
        let window = self.window;
        let is_recent = |time: &Instant| now.saturating_duration_since(*time) < window;
        if !self.seen.contains_key(&uid) && self.seen.len() >= MAX_TRACKED_UIDS {
            self.seen
                .retain(|_, times| times.back().is_some_and(is_recent));
            if self.seen.len() >= MAX_TRACKED_UIDS {
                return false;
            }
            self.dropped
                .retain(|tracked, _| self.seen.contains_key(tracked));
        }
        let times = self.seen.entry(uid).or_default();
        while times.front().is_some_and(|time| !is_recent(time)) {
            times.pop_front();
        }
        if times.len() < self.max as usize {
            times.push_back(now);
            true
        } else {
            if self.dropped.len() < MAX_TRACKED_UIDS || self.dropped.contains_key(&uid) {
                let count = self.dropped.entry(uid).or_default();
                *count = count.saturating_add(1);
            }
            false
        }
    }
}

/// The audit trail of the request layer: a sink and the limits on refusal records.
pub struct Audit {
    /// Where the records go.
    sink: Box<dyn AuditSink>,
    /// The limit on refusal records per uid: denied, limit reached, invalid argument and a job
    /// that ended without success each have their own, so a flood of one kind does not hide
    /// another.
    limiters: Mutex<[RateLimiter; 4]>,
}

impl Audit {
    /// An audit trail that writes to `sink`.
    pub fn new(sink: Box<dyn AuditSink>) -> Self {
        Self {
            sink,
            limiters: Mutex::new(std::array::from_fn(|_| {
                RateLimiter::new(REFUSAL_BURST, REFUSAL_WINDOW)
            })),
        }
    }

    /// An audit trail that writes to the system journal.
    pub fn journal() -> Self {
        Self::new(Box::new(JournalSink::journal()))
    }

    /// An audit trail that records nothing.
    pub fn none() -> Self {
        Self::new(Box::new(NullSink))
    }

    /// Records an event. A refusal event, or the end of a job that did not succeed, with a uid
    /// passes only within the per-uid limit of its kind, and the first one that passes after some were dropped is preceded by a record that
    /// says how many; every other event is recorded.
    pub fn record(&self, event: Event) {
        let slot = match event.kind {
            Kind::Denied => Some((0, "denied")),
            Kind::LimitReached => Some((1, "limit_reached")),
            Kind::InvalidArgument => Some((2, "invalid_argument")),
            Kind::JobEnded { result, .. } if result != PromptResult::Success => {
                Some((3, "job_ended"))
            }
            _ => None,
        };
        if let (Some((index, word)), Some(uid)) = (slot, event.uid) {
            let mut limiters = self.limiters.lock().unwrap_or_else(PoisonError::into_inner);
            if !limiters[index].allow(uid, Instant::now()) {
                return;
            }
            let dropped = limiters[index].take_dropped(uid);
            drop(limiters);
            if dropped > 0 {
                self.sink.record(&Event::suppressed(uid, word, dropped));
            }
        }
        self.sink.record(&event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::tempdir;

    /// A sink that keeps the events it is given.
    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<Event>>>);

    impl AuditSink for Recorder {
        fn record(&self, event: &Event) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    #[test]
    fn journal_record_has_the_native_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal");
        let socket = UnixDatagram::bind(&path).unwrap();
        let sink = JournalSink::at(&path);

        sink.record(&Event::denied(Some(1000)));
        let mut buffer = [0u8; 2048];
        let size = socket.recv(&mut buffer).unwrap();
        let text = std::str::from_utf8(&buffer[..size]).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        assert!(lines.contains(&"PRIORITY=4"));
        assert!(lines.contains(&"SYSLOG_IDENTIFIER=linuxhello-agent"));
        assert!(lines.contains(&"LH_EVENT=denied"));
        assert!(lines.contains(&"LH_UID=1000"));
        assert!(lines.contains(&"LH_OUTCOME=refused"));
        assert!(lines.iter().any(|line| line.starts_with("MESSAGE=")));
        let id = lines
            .iter()
            .find_map(|line| line.strip_prefix("MESSAGE_ID="))
            .unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(lines.len(), text.matches('\n').count());

        sink.record(&Event::denied(None));
        let size = socket.recv(&mut buffer).unwrap();
        let text = std::str::from_utf8(&buffer[..size]).unwrap();
        assert!(!text.contains("LH_UID="));
    }

    #[test]
    fn rate_limiter_forgets_a_uid_after_the_window() {
        let mut limiter = RateLimiter::new(5, Duration::from_secs(60));
        let now = Instant::now();
        for _ in 0..5 {
            assert!(limiter.allow(1000, now));
        }
        assert!(!limiter.allow(1000, now));
        assert!(limiter.allow(1001, now));
        assert!(limiter.allow(1000, now + Duration::from_secs(61)));
    }

    #[test]
    fn refusals_of_every_kind_are_limited_and_the_drops_are_counted() {
        // R-12, #354: only invalid-argument records were limited, so a local user could fill the
        // journal with denied or limit-reached ones.
        let recorder = Recorder::default();
        let audit = Audit::new(Box::new(recorder.clone()));
        for _ in 0..50 {
            audit.record(Event::denied(Some(1000)));
            audit.record(Event::limit_reached(Some(1000)));
            audit.record(Event::invalid_argument(Some(1000)));
        }
        let seen = recorder.0.lock().unwrap().len();
        assert_eq!(seen, 3 * usize::try_from(REFUSAL_BURST).unwrap(), "{seen}");
        // Another user is not held back, and a record without a uid is not limited.
        audit.record(Event::denied(Some(1001)));
        for _ in 0..10 {
            audit.record(Event::denied(None));
        }
        assert_eq!(recorder.0.lock().unwrap().len(), seen + 11);
    }

    #[test]
    fn the_drop_count_comes_before_the_next_record_that_passes() {
        let mut limiter = RateLimiter::new(2, Duration::from_secs(60));
        let now = Instant::now();
        for _ in 0..2 {
            assert!(limiter.allow(7, now));
        }
        for _ in 0..4 {
            assert!(!limiter.allow(7, now));
        }
        assert!(limiter.allow(7, now + Duration::from_secs(61)));
        assert_eq!(limiter.take_dropped(7), 4);
        assert_eq!(limiter.take_dropped(7), 0, "counting starts again");
        let fields = Event::suppressed(7, "denied", 4).fields();
        assert!(fields.contains(&("LH_SUPPRESSED_COUNT", "4".to_string())));
        assert!(fields.contains(&("LH_SUPPRESSED_EVENT", "denied".to_string())));
    }

    #[test]
    fn events_are_recorded_by_the_audit_trail() {
        let recorder = Recorder::default();
        let audit = Audit::new(Box::new(recorder.clone()));
        audit.record(Event::denied(None));
        assert_eq!(*recorder.0.lock().unwrap(), vec![Event::denied(None)]);
    }
}
