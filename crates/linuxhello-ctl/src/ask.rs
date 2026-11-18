//! `linuxhello-ctl status` without `--user`: what the running Agent says about the caller
//! (ADR-0024, point 7). The call goes through `busctl` and the [`Host`] trait, so a test replaces
//! it and the tool needs no bus library.
//!
//! C4 component: `cliCommands` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use crate::probe::Host;
use linuxhello_dbus::{AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};

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
/// had or read: `busctl` is missing, the call fails, or the reply is not a list of three strings.
pub fn get_status(host: &dyn Host) -> Option<Vec<Reported>> {
    let (code, stdout) = host.run(
        "busctl",
        &[
            "--system",
            "--timeout=5",
            "call",
            AGENT_BUS_NAME,
            AGENT_OBJECT_PATH,
            AGENT_INTERFACE,
            "GetStatus",
        ],
    )?;
    if code != 0 {
        return None;
    }
    parse(&stdout)
}

/// Reads `busctl`'s text for a reply of type `a(sss)`: `a(sss) 2 "a" "b" "c" "d" "e" "f"`.
fn parse(text: &str) -> Option<Vec<Reported>> {
    let rest = text.trim().strip_prefix("a(sss) ")?;
    let (count, rest) = rest.split_once(' ').unwrap_or((rest, ""));
    let count: usize = count.parse().ok()?;
    let strings = quoted_strings(rest)?;
    if strings.len() != count.checked_mul(3)? {
        return None;
    }
    Some(
        strings
            .chunks(3)
            .map(|c| Reported {
                code: c[0].clone(),
                severity: c[1].clone(),
                sentence: c[2].clone(),
            })
            .collect(),
    )
}

/// The double-quoted strings of `text`, with `\"` and `\\` unescaped. `None` for anything else
/// between them.
fn quoted_strings(text: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut chars = text.trim().chars().peekable();
    while chars.peek().is_some() {
        if chars.next()? != '"' {
            return None;
        }
        let mut s = String::new();
        loop {
            match chars.next()? {
                '"' => break,
                '\\' => s.push(chars.next()?),
                c => s.push(c),
            }
        }
        out.push(s);
        while chars.peek() == Some(&' ') {
            chars.next();
        }
    }
    Some(out)
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

    /// A machine whose `busctl` answers `reply` to any call, or cannot run.
    struct Scripted {
        reply: Option<(i32, String)>,
        status_file: Option<String>,
    }

    impl Host for Scripted {
        fn run(&self, program: &str, _args: &[&str]) -> Option<(i32, String)> {
            assert_eq!(program, "busctl");
            self.reply.clone()
        }
        fn read(&self, path: &Path) -> Option<String> {
            assert_eq!(path, Path::new("/proc/self/status"));
            self.status_file.clone()
        }
    }

    fn answers(text: &str) -> Scripted {
        Scripted {
            reply: Some((0, text.to_string())),
            status_file: None,
        }
    }

    #[test]
    fn an_empty_list_is_no_conditions() {
        assert_eq!(get_status(&answers("a(sss) 0")), Some(vec![]));
    }

    #[test]
    fn conditions_are_read_with_their_three_fields() {
        let text = r#"a(sss) 2 "policy-pin-only" "severe" "Biometric \"off\"." "context-unsatisfiable: sudo" "severe" "sudo cannot be unlocked.""#;
        let got = get_status(&answers(text)).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].code, "policy-pin-only");
        assert_eq!(got[0].sentence, "Biometric \"off\".");
        assert_eq!(got[1].code, "context-unsatisfiable: sudo");
    }

    #[test]
    fn an_answer_that_cannot_be_read_is_no_answer() {
        for text in [
            "",
            "s \"x\"",
            "a(sss) 1 \"only\" \"two\"",
            "a(sss) 1 \"a\" \"b\" \"c\" \"d\"",
            "a(sss) x",
            "a(sss) 1 a b c",
            "a(sss) 1 \"a\" \"b\" \"unterminated",
        ] {
            assert_eq!(get_status(&answers(text)), None, "{text:?}");
        }
        let failed = Scripted {
            reply: Some((1, "a(sss) 0".to_string())),
            status_file: None,
        };
        assert_eq!(get_status(&failed), None);
        let absent = Scripted {
            reply: None,
            status_file: None,
        };
        assert_eq!(get_status(&absent), None);
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
