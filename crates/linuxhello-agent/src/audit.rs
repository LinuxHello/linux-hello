//! The Agent's audit trail: one structured journald record for every refused request and for
//! every change of a user's policy layer.
//!
//! An [`Event`] holds only a kind, an optional uid and fixed words written in this file. It has
//! no field for text a caller sent, so a PIN, a policy text or an argument cannot reach the
//! journal. The journal is written through its native datagram socket, which needs no `unsafe`
//! and no library. Invalid-argument records are limited per uid ([`RateLimiter`]) so that one
//! user cannot fill the journal; refusals of the other kinds and policy changes are never
//! limited. A journal that cannot be written is ignored: an audit failure must not turn a
//! refusal into a different answer, and the Agent has nowhere else to report it.
//!
//! Security properties: `refused_call_is_audited_with_uid_and_reason`,
//! `user_policy_change_is_audited_without_its_text` and `audit_events_are_rate_limited_per_uid`
//! (P-13, partly: the events that exist so far).
//!
//! C4 component: `auditLog` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

use std::collections::{HashMap, VecDeque};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

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

/// How many uids the rate limiter remembers at most.
const MAX_TRACKED_UIDS: usize = 4096;

/// How many invalid-argument records one uid may cause per window.
const INVALID_ARGUMENT_BURST: u32 = 5;

/// The window of the invalid-argument limit.
const INVALID_ARGUMENT_WINDOW: Duration = Duration::from_secs(60);

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
}

/// One audit record: a kind and the uid it concerns. It carries no text from a caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// What happened.
    kind: Kind,
    /// The uid of the caller, when the bus gave one.
    uid: Option<u32>,
}

impl Event {
    /// A request the caller may not make; `uid` is none when the bus gave no credentials.
    pub fn denied(uid: Option<u32>) -> Self {
        Self {
            kind: Kind::Denied,
            uid,
        }
    }

    /// A request refused because a limit is reached.
    pub fn limit_reached(uid: Option<u32>) -> Self {
        Self {
            kind: Kind::LimitReached,
            uid,
        }
    }

    /// A request refused because an argument is not valid.
    pub fn invalid_argument(uid: Option<u32>) -> Self {
        Self {
            kind: Kind::InvalidArgument,
            uid,
        }
    }

    /// The user's policy layer was stored.
    pub fn user_policy_set(uid: u32) -> Self {
        Self {
            kind: Kind::UserPolicySet,
            uid: Some(uid),
        }
    }

    /// The user's policy layer was removed.
    pub fn user_policy_removed(uid: u32) -> Self {
        Self {
            kind: Kind::UserPolicyRemoved,
            uid: Some(uid),
        }
    }

    /// The journal fields of the record, in the order they are written: `PRIORITY`,
    /// `SYSLOG_IDENTIFIER`, `MESSAGE_ID`, `LH_EVENT`, `LH_UID` (only with a uid), `LH_OUTCOME`
    /// and `MESSAGE`. Names and words are fixed and contain no newline.
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
}

impl RateLimiter {
    /// A limiter that allows `max` events per uid in any `window`.
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            seen: HashMap::new(),
        }
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
        }
        let times = self.seen.entry(uid).or_default();
        while times.front().is_some_and(|time| !is_recent(time)) {
            times.pop_front();
        }
        if times.len() < self.max as usize {
            times.push_back(now);
            true
        } else {
            false
        }
    }
}

/// The audit trail of the request layer: a sink and the limit on invalid-argument records.
pub struct Audit {
    /// Where the records go.
    sink: Box<dyn AuditSink>,
    /// The limit on invalid-argument records per uid.
    limiter: Mutex<RateLimiter>,
}

impl Audit {
    /// An audit trail that writes to `sink`.
    pub fn new(sink: Box<dyn AuditSink>) -> Self {
        Self {
            sink,
            limiter: Mutex::new(RateLimiter::new(
                INVALID_ARGUMENT_BURST,
                INVALID_ARGUMENT_WINDOW,
            )),
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

    /// Records an event. An invalid-argument event with a uid passes only within the per-uid
    /// limit; every other event is recorded.
    pub fn record(&self, event: Event) {
        if let (Kind::InvalidArgument, Some(uid)) = (event.kind, event.uid) {
            let allowed = self
                .limiter
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .allow(uid, Instant::now());
            if !allowed {
                return;
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
    fn events_are_recorded_by_the_audit_trail() {
        let recorder = Recorder::default();
        let audit = Audit::new(Box::new(recorder.clone()));
        audit.record(Event::denied(None));
        assert_eq!(*recorder.0.lock().unwrap(), vec![Event::denied(None)]);
    }
}
