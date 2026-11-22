//! D-Bus names shared by every Linux Hello container.
//!
//! The well-known names below are a one-way door: clients, AppArmor profiles and
//! portals hard-code them. These names are decided by [ADR-0012](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0012-dbus-names.md) and change only by a new ADR.
//!
//! This crate is not a container of its own: it is the contract of the Agent's
//! D-Bus API, linked into every container that calls it.
//!
//! The state API follows [ADR-0014](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0014-agent-bus.md).
//!
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

pub mod restart;

/// Well-known bus name of the Agent.
pub const AGENT_BUS_NAME: &str = "io.github.LinuxHello.Agent1";
/// Object path of the Agent.
pub const AGENT_OBJECT_PATH: &str = "/io/github/LinuxHello/Agent1";
/// Interface of the Agent.
pub const AGENT_INTERFACE: &str = "io.github.LinuxHello.Agent1";

/// The prefix of every error name the Agent answers with (ADR-0014, amendment 2026-11-17).
pub const ERROR_PREFIX: &str = "io.github.LinuxHello.Error";

/// The closed set of error names after [`ERROR_PREFIX`]. A client matches the name, never the
/// text; the text of every error is fixed except `InvalidPolicy`'s, which is the parser's message
/// about the caller's own policy text.
pub const ERRORS: &[&str] = &[
    "Denied",
    "LimitReached",
    "InvalidArgument",
    "InvalidPolicy",
    "Unavailable",
    "Damaged",
];

/// The version of the Agent's interface. A change from version 1 on is additive (a new member, a
/// new optional field in a closed set); a change that is not is a new interface name served next
/// to the old one (ADR-0014, amendment 2026-11-17).
pub const INTERFACE_VERSION: u32 = 1;

/// The optional members of the interface that this Agent supports, as `GetCapabilities` names
/// them. A client that needs one of them checks the list first.
pub const CAPABILITIES: &[&str] = &[
    "ActiveMethods",
    "Authenticate",
    "ChangePin",
    "Closed",
    "DeleteFingerprint",
    "EnrolFingerprint",
    "EnrolProgress",
    "ExpectPin",
    "GetCapabilities",
    "GetEffectivePolicy",
    "GetPinRules",
    "GetPinState",
    "GetPromptStatus",
    "GetStatus",
    "GetStatusDetails",
    "GetUserPolicy",
    "ListFingerprints",
    "PromptStarted",
    "Reset",
    "SetPin",
    "SetUserPolicy",
    "Unsubscribe",
    "WatchPrompts",
];

/// What `GetStatus` reports (ADR-0024): conditions with a code from a closed set, a severity and
/// one fixed sentence. The offline `linuxhello-ctl` prints the same codes and sentences, so this
/// module is the one table for both.
pub mod status {
    /// How serious a condition is, as `GetStatus` names it on the wire.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Severity {
        /// Something to know that needs no action.
        Info,
        /// Something that reduces what works.
        Warning,
        /// A method or context is lost, or a fact could not be established.
        Severe,
    }

    impl Severity {
        /// Every severity.
        pub const ALL: [Self; 3] = [Self::Info, Self::Warning, Self::Severe];

        /// The word on the wire and in `linuxhello-ctl`.
        #[must_use]
        pub const fn as_wire(self) -> &'static str {
            match self {
                Self::Info => "info",
                Self::Warning => "warning",
                Self::Severe => "severe",
            }
        }
    }

    /// The code of a policy that failed to load and fell back to PIN-only.
    pub const POLICY_PIN_ONLY: &str = "policy-pin-only";
    /// The sentence of [`POLICY_PIN_ONLY`].
    pub const POLICY_PIN_ONLY_SENTENCE: &str =
        "Biometric sign-in is off because a policy file failed to load.";

    /// The base of the code of a context that no method set can satisfy; the code is this word,
    /// then `: ` and the context.
    pub const CONTEXT_UNSATISFIABLE: &str = "context-unsatisfiable";

    /// The contexts a code may name on the bus. A context of any other name is reported as
    /// [`OTHER_CONTEXT`], so that no word from a policy file reaches a client.
    pub const CONTEXTS: &[&str] = &["login", "session", "sudo", "unlock"];
    /// The parameter for a context that is not in [`CONTEXTS`].
    pub const OTHER_CONTEXT: &str = "other";

    /// The base codes `GetStatus` may return, a closed set. A code is never renamed; a new one is
    /// an additive change (ADR-0024, point 3).
    pub const CODES: &[&str] = &[
        POLICY_PIN_ONLY,
        CONTEXT_UNSATISFIABLE,
        PIN_LOCKED,
        PIN_LOCK_DAMAGED,
        TPM_LIMIT_LOW,
        TPM_CLEARED,
        PIN_EXPIRES_SOON,
        PIN_EXPIRED,
    ];

    /// The code of a user whose PIN is locked after too many wrong attempts.
    pub const PIN_LOCKED: &str = "pin-locked";

    /// The sentence of [`PIN_LOCKED`]: the whole minutes left, rounded up, are the one number
    /// the Agent computes (ADR-0024, point 5).
    #[must_use]
    pub fn pin_locked_sentence(seconds: u64) -> String {
        let minutes = seconds.div_ceil(60).max(1);
        if minutes == 1 {
            "Your PIN is locked for 1 more minute.".to_string()
        } else {
            format!("Your PIN is locked for {minutes} more minutes.")
        }
    }

    /// The code of a record of failed PIN attempts that cannot be trusted: nobody may try a PIN.
    pub const PIN_LOCK_DAMAGED: &str = "pin-lock-damaged";
    /// The sentence of [`PIN_LOCK_DAMAGED`].
    pub const PIN_LOCK_DAMAGED_SENTENCE: &str =
        "The record of failed PIN attempts cannot be trusted, so PIN sign-in is refused.";

    /// The code of a TPM that locks after fewer wrong tries than the Agent's own limit needs: the
    /// Agent lowered its limit so that its own lockout comes first (ADR-0021).
    pub const TPM_LIMIT_LOW: &str = "tpm-dictionary-limit-low";

    /// The sentence of [`TPM_LIMIT_LOW`]: the TPM's limit, and the number of wrong PINs the Agent
    /// allows instead.
    #[must_use]
    pub fn tpm_limit_low_sentence(tpm_tries: u32, allowed: u32) -> String {
        format!(
            "The TPM locks every PIN after {tpm_tries} wrong tries, so Linux Hello allows only {allowed} wrong PINs before its own lockout."
        )
    }

    /// The code of a PIN key that the TPM no longer holds: the TPM was cleared or replaced since the
    /// key was made, or the record is damaged. The PIN cannot be used until the enrolment is reset.
    pub const TPM_CLEARED: &str = "tpm-cleared";
    /// The sentence of [`TPM_CLEARED`].
    pub const TPM_CLEARED_SENTENCE: &str =
        "The TPM no longer holds the key that your PIN opens (it was cleared or replaced), so your PIN cannot be used until your enrolment is reset.";

    /// The code of a PIN that expires within 14 days (ADR-0021, amendment of 2026-11-21, point 6).
    pub const PIN_EXPIRES_SOON: &str = "pin-expires-soon";

    /// The code of [`PIN_EXPIRES_SOON`] on the bus: the base code, `: ` and the whole days left,
    /// rounded up, at least 1, so that a client reads the number without parsing the sentence
    /// (ADR-0024, amendment of 2026-11-22).
    #[must_use]
    pub fn pin_expires_soon_code(days_left: u64) -> String {
        format!("{PIN_EXPIRES_SOON}: {}", days_left.max(1))
    }

    /// A code split into its base code and its parameter, if it has one (ADR-0024, point 3 and
    /// the amendment of 2026-11-22): `context-unsatisfiable: login` is `("context-unsatisfiable",
    /// Some("login"))`, `tpm-cleared` is `("tpm-cleared", None)`.
    #[must_use]
    pub fn split_code(code: &str) -> (&str, Option<&str>) {
        code.split_once(": ")
            .map_or((code, None), |(base, parameter)| (base, Some(parameter)))
    }

    /// The days left of a `pin-expires-soon` code; `None` for any other code or a parameter that
    /// is not a whole number of at least 1 written in decimal digits.
    #[must_use]
    pub fn days_of_pin_expires_soon(code: &str) -> Option<u64> {
        match split_code(code) {
            (PIN_EXPIRES_SOON, Some(days))
                if !days.is_empty()
                    && !days.starts_with('0')
                    && days.bytes().all(|b| b.is_ascii_digit()) =>
            {
                days.parse().ok()
            }
            _ => None,
        }
    }

    /// The sentence of [`PIN_EXPIRES_SOON`]: the whole days left, rounded up, at least 1.
    #[must_use]
    pub fn pin_expires_soon_sentence(days_left: u64) -> String {
        let days = days_left.max(1);
        if days == 1 {
            "Your PIN expires in 1 day. Change it with linuxhello-ctl pin change.".to_string()
        } else {
            format!("Your PIN expires in {days} days. Change it with linuxhello-ctl pin change.")
        }
    }

    /// The code of a PIN whose `pin.expiry_days` have passed. The PIN still works (ADR-0021,
    /// amendment of 2026-11-21, point 1).
    pub const PIN_EXPIRED: &str = "pin-expired";
    /// The sentence of [`PIN_EXPIRED`].
    pub const PIN_EXPIRED_SENTENCE: &str =
        "Your PIN has expired. It still works, but change it now with linuxhello-ctl pin change.";

    /// The sentence for an unsatisfiable `context`.
    #[must_use]
    pub fn context_unsatisfiable_sentence(context: &str) -> String {
        format!("{context} cannot be unlocked with the configured methods.")
    }

    /// The code and the sentence for an unsatisfiable `context` as a client of the bus sees
    /// them: the context's own name if it is in [`CONTEXTS`], the parameter `other` and a
    /// sentence without a name if not.
    #[must_use]
    pub fn context_unsatisfiable_on_the_bus(context: &str) -> (String, String) {
        if CONTEXTS.contains(&context) {
            (
                format!("{CONTEXT_UNSATISFIABLE}: {context}"),
                context_unsatisfiable_sentence(context),
            )
        } else {
            (
                format!("{CONTEXT_UNSATISFIABLE}: {OTHER_CONTEXT}"),
                "A context cannot be unlocked with the configured methods.".to_string(),
            )
        }
    }
}

/// Method that starts the authentication of a prompt: the Agent runs the methods of a context and
/// reports by the `Result` signal (ADR-0023, amendment 2026-11-19).
pub const METHOD_AUTHENTICATE: &str = "Authenticate";

/// Method that announces a PIN: the opener of a prompt is about to send one on the PIN socket
/// (ADR-0021, amendment 2026-11-18).
pub const METHOD_EXPECT_PIN: &str = "ExpectPin";

/// Method that returns the interface version and the optional members the Agent supports.
pub const METHOD_GET_CAPABILITIES: &str = "GetCapabilities";

/// Method to report the current state.
pub const METHOD_REPORT_STATE: &str = "ReportState";
/// Method to retrieve the current state.
pub const METHOD_GET_STATE: &str = "GetState";

/// Authentication methods supported by the Agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// Face authentication.
    Face,
    /// Fingerprint authentication.
    Fingerprint,
    /// PIN authentication.
    Pin,
}

impl AuthMethod {
    /// Returns the wire string representation of the method.
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Face => "face",
            Self::Fingerprint => "fingerprint",
            Self::Pin => "pin",
        }
    }

    /// Parses an authentication method from a wire string.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "face" => Some(Self::Face),
            "fingerprint" => Some(Self::Fingerprint),
            "pin" => Some(Self::Pin),
            _ => None,
        }
    }
}

/// The current state of a prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptState {
    /// No active authentication attempt.
    Idle,
    /// Biometric sensor is active.
    Scanning,
    /// Waiting for user input (e.g., PIN).
    WaitingForInput,
}

impl PromptState {
    /// Returns the wire string representation of the state.
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Scanning => "scanning",
            Self::WaitingForInput => "waiting-for-input",
        }
    }

    /// Parses a prompt state from a wire string.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "idle" => Some(Self::Idle),
            "scanning" => Some(Self::Scanning),
            "waiting-for-input" => Some(Self::WaitingForInput),
            _ => None,
        }
    }
}

/// The result of an authentication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptResult {
    /// Authentication succeeded.
    Success,
    /// Authentication failed.
    Failure,
    /// User cancelled the attempt.
    Cancelled,
    /// Too many failed attempts.
    LockedOut,
}

impl PromptResult {
    /// Returns the wire string representation of the result.
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Cancelled => "cancelled",
            Self::LockedOut => "locked-out",
        }
    }

    /// Parses a prompt result from a wire string.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "success" => Some(Self::Success),
            "failure" => Some(Self::Failure),
            "cancelled" => Some(Self::Cancelled),
            "locked-out" => Some(Self::LockedOut),
            _ => None,
        }
    }
}

/// Why an attempt ended as it did, a closed set. Empty when there is nothing to add.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptReason {
    /// No reason given.
    None,
    /// The camera image was too dark to match a face.
    TooDark,
    /// No face was found in the image.
    NoFace,
    /// A finger or face was read but did not match.
    NotRecognised,
    /// The person cancelled.
    Cancelled,
    /// Nobody answered in time.
    Timeout,
    /// An enrolment found the finger already enrolled, for this user or another (ADR-0027,
    /// point 4).
    Duplicate,
    /// The reader has no room for another finger.
    StorageFull,
    /// The reader went away during an enrolment.
    DeviceGone,
}

impl PromptReason {
    /// Every reason, in wire order.
    pub const ALL: [Self; 9] = [
        Self::None,
        Self::TooDark,
        Self::NoFace,
        Self::NotRecognised,
        Self::Cancelled,
        Self::Timeout,
        Self::Duplicate,
        Self::StorageFull,
        Self::DeviceGone,
    ];

    /// Returns the wire string representation of the reason.
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::None => "",
            Self::TooDark => "too-dark",
            Self::NoFace => "no-face",
            Self::NotRecognised => "not-recognised",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::Duplicate => "duplicate",
            Self::StorageFull => "storage-full",
            Self::DeviceGone => "device-gone",
        }
    }

    /// Parses a reason from a wire string.
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.as_wire() == s)
    }
}

/// A step of an enrolment of a finger or a face, as the `EnrolProgress` signal names it: a closed
/// set, to which a new step is an additive change (ADR-0027, point 4). The end of an enrolment is
/// never a step; it is the `Result` signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolStep {
    /// Touch the sensor, or look at the camera.
    Waiting,
    /// One touch or picture was taken.
    Passed,
    /// Touch again, the same way.
    Retry,
    /// The swipe was too short.
    TooShort,
    /// Put the finger in the middle of the sensor.
    NotCentred,
    /// Lift the finger and touch again.
    Lift,
    /// The camera sees too little.
    TooDark,
    /// The camera sees no face.
    NoFace,
}

impl EnrolStep {
    /// Every step, in wire order.
    pub const ALL: [Self; 8] = [
        Self::Waiting,
        Self::Passed,
        Self::Retry,
        Self::TooShort,
        Self::NotCentred,
        Self::Lift,
        Self::TooDark,
        Self::NoFace,
    ];

    /// The wire word of the step.
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Passed => "passed",
            Self::Retry => "retry",
            Self::TooShort => "too-short",
            Self::NotCentred => "not-centred",
            Self::Lift => "lift",
            Self::TooDark => "too-dark",
            Self::NoFace => "no-face",
        }
    }

    /// Parses a step from its wire word.
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|step| step.as_wire() == s)
    }
}

/// An opaque identifier for a specific authentication prompt.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PromptId(String);

impl PromptId {
    /// Derives a unique identifier from the provided context.
    pub fn derive(pam_service: &str, display_or_tty: &str, session_id: &str) -> Self {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"io.github.LinuxHello.PromptId1");

        for arg in [pam_service, display_or_tty, session_id] {
            hasher.update((arg.len() as u64).to_be_bytes());
            hasher.update(arg.as_bytes());
        }

        use std::fmt::Write as _;

        let result = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in result.iter() {
            // Writing to a String cannot fail.
            let _ = write!(hex, "{byte:02x}");
        }
        Self(hex)
    }

    /// Parses a `PromptId` from its hexadecimal string representation.
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        // Ensure it is lowercase
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            return None;
        }
        Some(Self(s.to_string()))
    }

    /// Returns the hexadecimal string representation of the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The delivery method for a D-Bus signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Sent only to a specific peer.
    Unicast,
    /// Sent to all connected peers.
    Broadcast,
}

/// Specification for a D-Bus signal.
pub struct SignalSpec {
    /// The name of the signal.
    pub name: &'static str,
    /// How the signal is delivered.
    pub delivery: Delivery,
    /// The names of the arguments passed in the signal.
    pub args: &'static [&'static str],
}

/// The set of signals emitted by the Agent.
pub const SIGNALS: &[SignalSpec] = &[
    SignalSpec {
        name: "MethodsAvailable",
        delivery: Delivery::Unicast,
        args: &["prompt_id", "methods"],
    },
    SignalSpec {
        name: "ActiveMethods",
        delivery: Delivery::Unicast,
        args: &["prompt_id", "methods"],
    },
    SignalSpec {
        name: "State",
        delivery: Delivery::Unicast,
        args: &["prompt_id", "state"],
    },
    SignalSpec {
        name: "Result",
        delivery: Delivery::Unicast,
        args: &["prompt_id", "result", "reason", "retry_after"],
    },
    // Sent by the Agent when a prompt closes, never reported by a client.
    SignalSpec {
        name: "Closed",
        delivery: Delivery::Unicast,
        args: &["prompt_id"],
    },
    // Sent by the Agent for each step of an enrolment, never reported by a client (ADR-0027,
    // point 4).
    SignalSpec {
        name: "EnrolProgress",
        delivery: Delivery::Unicast,
        args: &["prompt_id", "step", "done", "needed"],
    },
    // Sent by the Agent to a watcher when a prompt it may read starts, never reported by a client
    // (ADR-0014, amendment of 2026-11-22).
    SignalSpec {
        name: "PromptStarted",
        delivery: Delivery::Unicast,
        args: &["prompt_id", "context"],
    },
];

#[cfg(test)]
mod tests {
    #[test]
    fn error_names_are_a_closed_set_without_duplicates() {
        let mut names: Vec<&str> = ERRORS.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ERRORS.len());
        assert_eq!(ERRORS.len(), 6);
    }

    use super::*;

    #[test]
    fn object_path_matches_bus_name() {
        let expected = format!("/{}", AGENT_BUS_NAME.replace('.', "/"));
        assert_eq!(AGENT_OBJECT_PATH, expected);
    }

    #[test]
    fn agent_names_use_the_reserved_prefix() {
        // Every Linux Hello D-Bus name lives under this prefix, spelled exactly like this (ADR-0012).
        assert!(AGENT_BUS_NAME.starts_with("io.github.LinuxHello."));
        // The Agent's interface is its bus name.
        assert_eq!(AGENT_INTERFACE, AGENT_BUS_NAME);
    }

    #[test]
    fn agent_names_are_the_ones_in_adr_0012() {
        assert_eq!(AGENT_BUS_NAME, "io.github.LinuxHello.Agent1");
        assert_eq!(AGENT_INTERFACE, "io.github.LinuxHello.Agent1");
        assert_eq!(AGENT_OBJECT_PATH, "/io/github/LinuxHello/Agent1");
    }

    #[test]
    fn prompt_id_is_the_same_on_both_sides() {
        let id1 = PromptId::derive("sddm", "tty3", "c12");
        let id2 = PromptId::derive("sddm", "tty3", "c12");
        assert_eq!(id1, id2);
    }

    #[test]
    fn prompt_id_is_the_lowercase_hex_sha256_of_the_framed_fields() {
        // Computed independently of this crate, so a change of the hash library cannot change
        // the identifier the PAM module and the Agent must agree on.
        let id = PromptId::derive("sddm", "tty3", "c12");
        assert_eq!(
            id.0,
            "f198fac0ed8dfed11c660e89234082f330d63a5969a5a47df51c01156d88e752"
        );
    }

    #[test]
    fn different_prompts_get_different_ids() {
        let base = PromptId::derive("sddm", "tty3", "c12");
        assert_ne!(base, PromptId::derive("other", "tty3", "c12"));
        assert_ne!(base, PromptId::derive("sddm", "other", "c12"));
        assert_ne!(base, PromptId::derive("sddm", "tty3", "other"));
    }

    #[test]
    fn field_boundaries_cannot_be_forged() {
        assert_ne!(
            PromptId::derive("a", "bc", "d"),
            PromptId::derive("ab", "c", "d")
        );
        assert_ne!(
            PromptId::derive("a", "b", "cd"),
            PromptId::derive("a", "bc", "d")
        );
    }

    #[test]
    fn prompt_id_reveals_no_input_field() {
        let id = PromptId::derive("sddm", "tty3", "c12");
        let s = id.as_str();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!s.contains("sddm"));
        assert!(!s.contains("tty3"));
        assert!(!s.contains("c12"));
    }

    #[test]
    fn prompt_id_parse_accepts_only_what_derive_makes() {
        let id = PromptId::derive("sddm", "tty3", "c12");
        let s = id.as_str();

        assert!(PromptId::parse(s).is_some());
        assert!(PromptId::parse("").is_none());
        assert!(PromptId::parse(&s[..63]).is_none());
        assert!(PromptId::parse(&format!("{s}0")).is_none());
        assert!(PromptId::parse(&s.to_uppercase()).is_none());
        assert!(PromptId::parse(&format!("g{}", "0".repeat(63))).is_none());
    }

    #[test]
    fn wire_strings_round_trip_and_unknown_fails_closed() {
        // AuthMethod
        for m in [AuthMethod::Face, AuthMethod::Fingerprint, AuthMethod::Pin] {
            assert_eq!(AuthMethod::from_wire(m.as_wire()), Some(m));
        }
        assert!(AuthMethod::from_wire("").is_none());
        assert!(AuthMethod::from_wire("FACE").is_none());
        assert!(AuthMethod::from_wire("unknown").is_none());

        // PromptState
        for s in [
            PromptState::Idle,
            PromptState::Scanning,
            PromptState::WaitingForInput,
        ] {
            assert_eq!(PromptState::from_wire(s.as_wire()), Some(s));
        }
        assert!(PromptState::from_wire("").is_none());
        assert!(PromptState::from_wire("SCANNING").is_none());
        assert!(PromptState::from_wire("unknown").is_none());

        // PromptResult
        for r in [
            PromptResult::Success,
            PromptResult::Failure,
            PromptResult::Cancelled,
            PromptResult::LockedOut,
        ] {
            assert_eq!(PromptResult::from_wire(r.as_wire()), Some(r));
        }
        assert!(PromptResult::from_wire("").is_none());
        assert!(PromptResult::from_wire("SUCCESS").is_none());
        assert!(PromptResult::from_wire("unknown").is_none());
    }

    #[test]
    fn reasons_are_a_closed_set() {
        let wire: Vec<&str> = PromptReason::ALL.iter().map(|r| r.as_wire()).collect();
        assert_eq!(
            wire,
            [
                "",
                "too-dark",
                "no-face",
                "not-recognised",
                "cancelled",
                "timeout",
                "duplicate",
                "storage-full",
                "device-gone"
            ]
        );
        for reason in PromptReason::ALL {
            assert_eq!(PromptReason::from_wire(reason.as_wire()), Some(reason));
        }
        assert_eq!(PromptReason::from_wire("TOO-DARK"), None);
        assert_eq!(PromptReason::from_wire("locked"), None);
    }

    #[test]
    fn progress_steps_are_a_closed_set() {
        use super::EnrolStep;
        let words: Vec<&str> = EnrolStep::ALL.iter().map(|s| s.as_wire()).collect();
        assert_eq!(
            words,
            [
                "waiting",
                "passed",
                "retry",
                "too-short",
                "not-centred",
                "lift",
                "too-dark",
                "no-face"
            ]
        );
        for step in EnrolStep::ALL {
            assert_eq!(EnrolStep::from_wire(step.as_wire()), Some(step));
        }
        assert_eq!(EnrolStep::from_wire("done"), None);
        assert_eq!(EnrolStep::from_wire("Waiting"), None);
    }

    #[test]
    fn a_context_outside_the_closed_set_is_named_other() {
        use super::status::{context_unsatisfiable_on_the_bus, CODES, CONTEXTS};
        let (code, sentence) = context_unsatisfiable_on_the_bus("weirdname");
        assert_eq!(code, "context-unsatisfiable: other");
        assert!(!sentence.contains("weirdname"));
        for context in CONTEXTS {
            let (code, _) = context_unsatisfiable_on_the_bus(context);
            assert!(CODES.contains(&code.split(": ").next().unwrap()));
            assert!(code.ends_with(context));
        }
    }

    #[test]
    fn a_client_reads_the_days_without_parsing_the_sentence() {
        use super::status::{
            days_of_pin_expires_soon, pin_expires_soon_code, split_code, CODES, PIN_EXPIRES_SOON,
        };
        assert_eq!(pin_expires_soon_code(5), "pin-expires-soon: 5");
        assert_eq!(pin_expires_soon_code(0), "pin-expires-soon: 1");
        assert_eq!(
            days_of_pin_expires_soon(&pin_expires_soon_code(14)),
            Some(14)
        );
        let code = pin_expires_soon_code(3);
        let (base, _) = split_code(&code);
        assert_eq!(base, PIN_EXPIRES_SOON);
        assert!(CODES.contains(&base));
        for odd in [
            "pin-expires-soon",
            "pin-expires-soon: ",
            "pin-expires-soon: 05",
            "pin-expires-soon: 0",
            "pin-expires-soon: -3",
            "pin-expires-soon: 3 days",
            "context-unsatisfiable: 3",
        ] {
            assert_eq!(days_of_pin_expires_soon(odd), None, "{odd}");
        }
        assert_eq!(split_code("tpm-cleared"), ("tpm-cleared", None));
    }

    #[test]
    fn the_expiry_sentences_are_the_adrs() {
        use super::status::{pin_expires_soon_sentence, PIN_EXPIRED_SENTENCE};
        assert_eq!(
            pin_expires_soon_sentence(14),
            "Your PIN expires in 14 days. Change it with linuxhello-ctl pin change."
        );
        assert_eq!(
            pin_expires_soon_sentence(0),
            "Your PIN expires in 1 day. Change it with linuxhello-ctl pin change."
        );
        assert!(PIN_EXPIRED_SENTENCE.contains("still works"));
    }

    #[test]
    fn capabilities_name_the_version() {
        assert_eq!(INTERFACE_VERSION, 1);
        assert!(CAPABILITIES.contains(&"GetCapabilities"));
        let mut sorted = CAPABILITIES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, CAPABILITIES, "sorted and without duplicates");
    }

    #[test]
    fn no_signal_is_a_broadcast() {
        for sig in SIGNALS {
            assert_eq!(sig.delivery, Delivery::Unicast);
        }
    }

    #[test]
    fn signals_carry_no_user_or_session_data() {
        assert_eq!(SIGNALS.len(), 7);
        let expected_names = [
            "MethodsAvailable",
            "ActiveMethods",
            "State",
            "Result",
            "Closed",
            "EnrolProgress",
            "PromptStarted",
        ];
        let expected_args: [&[&str]; 7] = [
            &["prompt_id", "methods"],
            &["prompt_id", "methods"],
            &["prompt_id", "state"],
            &["prompt_id", "result", "reason", "retry_after"],
            &["prompt_id"],
            &["prompt_id", "step", "done", "needed"],
            &["prompt_id", "context"],
        ];

        for (i, sig) in SIGNALS.iter().enumerate() {
            assert_eq!(sig.name, expected_names[i]);
            assert_eq!(sig.args, expected_args[i]);
        }
    }
}
