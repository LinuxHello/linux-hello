//! The real sign-in methods the orchestrator runs (ADR-0023, amendment 2026-11-19, second part).
//!
//! Each method is a [`crate::orchestrator::Method`]: it can be asked "try to recognise this user"
//! and "stop now". So far only the fingerprint method exists ([`fingerprint`]); face (Howdy) and
//! PIN are later slices of #195.
//!
//! C4 component: `methodOrch` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

pub mod face;
pub mod fingerprint;

/// The name of the account with user id `uid`, read from the text of `/etc/passwd`. `None` for a
/// uid that has no line (a name that only the name service knows is not found here).
pub fn username_of(uid: u32, passwd: &str) -> Option<String> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let id: u32 = fields.next()?.parse().ok()?;
        (id == uid && !name.is_empty()).then(|| name.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::username_of;

    #[test]
    fn a_uid_is_found_in_the_passwd_text() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nanna:x:1000:1000:Anna:/home/anna:/bin/sh\n# note\nbroken\n:x:7:7\n";
        assert_eq!(username_of(1000, passwd).as_deref(), Some("anna"));
        assert_eq!(username_of(0, passwd).as_deref(), Some("root"));
        assert_eq!(username_of(1001, passwd), None);
        assert_eq!(
            username_of(7, passwd),
            None,
            "a line without a name is skipped"
        );
        assert_eq!(username_of(1000, ""), None);
    }
}
