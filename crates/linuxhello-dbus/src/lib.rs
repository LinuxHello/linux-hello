//! D-Bus names shared by every Linux Hello container.
//!
//! The well-known names below are a one-way door: clients, AppArmor profiles and
//! portals hard-code them. `io.github.LinuxHello` follows the reverse-DNS
//! convention for projects hosted at github.com/LinuxHello.

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
}
