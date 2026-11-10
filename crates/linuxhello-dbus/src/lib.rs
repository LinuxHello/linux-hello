//! D-Bus names shared by every Linux Hello container.
//!
//! The well-known names below are a one-way door: clients, AppArmor profiles and
//! portals hard-code them. These names are decided by [ADR-0012](https://github.com/LinuxHello/architecture/blob/main/adr/0012-dbus-names.md) and change only by a new ADR.
//!
//! This crate is not a container of its own: it is the contract of the Agent's
//! D-Bus API, linked into every container that calls it.
//!
//! The state API follows [ADR-0014](https://github.com/LinuxHello/architecture/blob/main/adr/0014-agent-bus.md).
//!
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

/// Well-known bus name of the Agent.
pub const AGENT_BUS_NAME: &str = "io.github.LinuxHello.Agent1";
/// Object path of the Agent.
pub const AGENT_OBJECT_PATH: &str = "/io/github/LinuxHello/Agent1";
/// Interface of the Agent.
pub const AGENT_INTERFACE: &str = "io.github.LinuxHello.Agent1";

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
        name: "ActiveMethod",
        delivery: Delivery::Unicast,
        args: &["prompt_id", "method"],
    },
    SignalSpec {
        name: "State",
        delivery: Delivery::Unicast,
        args: &["prompt_id", "state"],
    },
    SignalSpec {
        name: "Result",
        delivery: Delivery::Unicast,
        args: &["prompt_id", "result"],
    },
];

#[cfg(test)]
mod tests {
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
    fn no_signal_is_a_broadcast() {
        for sig in SIGNALS {
            assert_eq!(sig.delivery, Delivery::Unicast);
        }
    }

    #[test]
    fn signals_carry_no_user_or_session_data() {
        assert_eq!(SIGNALS.len(), 4);
        let expected_names = ["MethodsAvailable", "ActiveMethod", "State", "Result"];
        let expected_args = [
            &["prompt_id", "methods"],
            &["prompt_id", "method"],
            &["prompt_id", "state"],
            &["prompt_id", "result"],
        ];

        for (i, sig) in SIGNALS.iter().enumerate() {
            assert_eq!(sig.name, expected_names[i]);
            assert_eq!(sig.args, expected_args[i]);
        }
    }
}
