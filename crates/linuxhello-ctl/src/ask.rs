//! `linuxhello-ctl status` without `--user`: what the running Agent says about the caller
//! (ADR-0024, point 7). The call goes over the tool's own bus connection, behind the [`Host`]
//! trait so that a test replaces it; no program is started for it (ADR-0026).
//!
//! C4 component: `cliCommands` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use crate::probe::Host;

/// The code of the condition the client computes when the Agent does not answer. The Agent never
/// reports it (ADR-0024, point 7).
pub const AGENT_UNREACHABLE: &str = "agent-unreachable";

/// The sentence of [`AGENT_UNREACHABLE`].
pub const AGENT_UNREACHABLE_SENTENCE: &str =
    "The Linux Hello Agent did not answer, so this status is read from the policy files.";

/// One condition as the Agent reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reported {
    /// The code.
    pub code: String,
    /// The severity word.
    pub severity: String,
    /// The fixed sentence.
    pub sentence: String,
}

/// Asks the Agent for the caller's conditions with `GetStatus`. `None` when the answer cannot be
/// had: the Agent does not answer, or its reply is not a list of three strings.
pub fn get_status(host: &dyn Host) -> Option<Vec<Reported>> {
    host.agent_status()
}

/// The uid of the process, from `/proc/self/status`. `None` when it cannot be read.
pub fn own_uid(host: &dyn Host) -> Option<u32> {
    let status = host.read(std::path::Path::new("/proc/self/status"))?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A machine whose Agent answers `reply` and whose `/proc/self/status` is `status_file`.
    struct Scripted {
        reply: Option<Vec<Reported>>,
        status_file: Option<String>,
    }

    impl Host for Scripted {
        fn agent_status(&self) -> Option<Vec<Reported>> {
            self.reply.clone()
        }
        fn unit_active(&self, _unit: &str) -> Option<bool> {
            panic!("status asks no unit")
        }
        fn fingerprint_reader(&self) -> Option<bool> {
            panic!("status asks no reader")
        }
        fn read(&self, path: &Path) -> Option<String> {
            assert_eq!(path, Path::new("/proc/self/status"));
            self.status_file.clone()
        }
    }

    #[test]
    fn the_agents_answer_is_passed_on_and_no_answer_is_none() {
        let one = vec![Reported {
            code: "policy-pin-only".into(),
            severity: "severe".into(),
            sentence: "x".into(),
        }];
        for reply in [None, Some(vec![]), Some(one)] {
            let host = Scripted {
                reply: reply.clone(),
                status_file: None,
            };
            assert_eq!(get_status(&host), reply);
        }
    }

    #[test]
    fn the_own_uid_is_the_first_number_of_the_uid_line() {
        let host = Scripted {
            reply: None,
            status_file: Some("Name:\tx\nUid:\t1000\t1001\t1002\t1003\n".to_string()),
        };
        assert_eq!(own_uid(&host), Some(1000));
        let none = Scripted {
            reply: None,
            status_file: Some("Name:\tx\n".to_string()),
        };
        assert_eq!(own_uid(&none), None);
    }
}
