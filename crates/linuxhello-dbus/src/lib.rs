//! D-Bus names shared by every Linux Hello container.
//!
//! The well-known names below are a one-way door: clients, AppArmor profiles and
//! portals hard-code them. These names are decided by [ADR-0012](https://github.com/LinuxHello/architecture/blob/main/adr/0012-dbus-names.md) and change only by a new ADR.
//!
//! This crate is not a container of its own: it is the contract of the Agent's
//! D-Bus API, linked into every container that calls it.
//!
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

/// Well-known bus name of the Agent.
pub const AGENT_BUS_NAME: &str = "io.github.LinuxHello.Agent1";
/// Object path of the Agent.
pub const AGENT_OBJECT_PATH: &str = "/io/github/LinuxHello/Agent1";
/// Interface of the Agent.
pub const AGENT_INTERFACE: &str = "io.github.LinuxHello.Agent1";

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
}
