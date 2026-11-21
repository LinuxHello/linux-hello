//! The PAM snippets the packages ship (`pam.d/login`, `pam.d/unlock`, `pam.d/sudo`), read as text:
//! no PAM runtime is needed. ADR-0023, decision 2: `pam_unix` comes after `pam_linuxhello`, so the
//! account password still works when Linux Hello is unavailable, and nothing else falls through.

use std::path::Path;

/// The services whose snippets are shipped.
const SERVICES: [&str; 3] = ["login", "unlock", "sudo"];

/// The control field that makes "unavailable" fall through and every other failure final.
const CONTROL: &str = "[success=done authinfo_unavail=ignore default=die]";

/// The `auth` lines of a snippet as (control, module), in the order they are written.
fn auth_lines(service: &str) -> Vec<(String, String)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("pam.d")
        .join(service);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{service}: {e}"));
    text.lines()
        .map(str::trim)
        .filter(|line| line.starts_with("auth "))
        .map(|line| {
            let rest = line["auth ".len()..].trim_start();
            // The control is one word, or a bracketed list that may hold spaces.
            let (control, module) = if rest.starts_with('[') {
                let end = rest.find(']').expect("a closing bracket");
                (&rest[..=end], rest[end + 1..].trim_start())
            } else {
                rest.split_once(' ').expect("a module after the control")
            };
            let module = module.split_whitespace().next().expect("a module name");
            (control.to_string(), module.to_string())
        })
        .collect()
}

/// P-32: see `docs/security/properties.md`.
#[test]
fn login_falls_through_to_the_account_password_when_linux_hello_is_unavailable() {
    for service in SERVICES {
        let lines = auth_lines(service);
        let hello = lines
            .iter()
            .position(|(_, module)| module == "pam_linuxhello.so")
            .unwrap_or_else(|| panic!("{service}: no pam_linuxhello line"));
        let unix = lines
            .iter()
            .position(|(_, module)| module == "pam_unix.so")
            .unwrap_or_else(|| panic!("{service}: no pam_unix line"));
        assert!(
            hello < unix,
            "{service}: pam_unix must come after pam_linuxhello"
        );
        // "Unavailable" is ignored, success ends the stack, anything else is final: a wrong PIN
        // never reaches the password, and Linux Hello is never `sufficient` or `optional`.
        assert_eq!(
            lines[hello].0, CONTROL,
            "{service}: the control of pam_linuxhello"
        );
        // The password is the fall-through that decides.
        assert_eq!(
            lines[unix].0, "required",
            "{service}: the control of pam_unix"
        );
        // Nothing else is in the way between the two.
        assert_eq!(
            unix,
            hello + 1,
            "{service}: another module sits between them"
        );
    }
}

/// Each snippet names its own context as the module argument: without one the module answers
/// "unavailable" and Linux Hello would never be used (ADR-0023, amendment of 2026-11-21, point 4).
#[test]
fn every_snippet_names_its_context() {
    for service in SERVICES {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("pam.d")
            .join(service);
        let text = std::fs::read_to_string(&path).unwrap();
        let line = text
            .lines()
            .find(|l| l.starts_with("auth ") && l.contains("pam_linuxhello.so"))
            .unwrap_or_else(|| panic!("{service}: no pam_linuxhello line"));
        let args: Vec<&str> = line
            .split("pam_linuxhello.so")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .collect();
        assert_eq!(args, [format!("context={service}")], "{service}");
    }
}
