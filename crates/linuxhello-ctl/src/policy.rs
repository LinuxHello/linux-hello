//! The administrator's offline commands on a user's policy layer: `policy show` and `policy reset`.
//!
//! C4 component: `cliCommands` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))
//!
//! Both commands work on the Agent's state directory directly and need no running Agent, so root
//! can lift a lockout without it. The command touches only `<state root>/<uid>/policy.toml` for a
//! `uid` that is a number, so no argument can reach another path; `reset` removes exactly that one
//! file and never claims success when it could not; `show` never writes; both are safe to repeat
//! (`user_is_a_name_from_passwd_or_a_number`, `reset_removes_only_that_users_layer`,
//! `reset_reports_a_failure_instead_of_claiming_success`,
//! `show_without_a_layer_says_so_and_creates_nothing`).
//!
//! ADR-0018 says that only the Agent reads and writes a user's layer. These commands are the
//! administrator's offline exception to that sentence; the state directory is mode 0700 and owned
//! by `linuxhello`, so a caller without the right to enter it gets a permission error from the
//! operating system, which the commands report. They add no D-Bus method and do not talk to the bus.
//!
//! `show` prints the stored text without parsing it, so a damaged file can still be seen and
//! removed. A user is a decimal `u32` or the name of a local account in the text of `/etc/passwd`;
//! accounts from other sources (LDAP, SSSD) are not looked up.

use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags};

use linuxhello_agent::policy::UserPolicyStore;

/// The largest layer `show` reads, in bytes: the size the Agent itself accepts.
const MAX_LAYER_BYTES: u64 = 1024 * 1024;

/// The usage line printed on every usage error.
const USAGE: &str = "usage: linuxhello-ctl policy show|reset --user <name|uid>";

/// Runs the command given by `args` (the words after the program name) on the state directory
/// `root`, resolving user names in `passwd` (the text of `/etc/passwd`).
///
/// Everything printed goes through `out` and `err`. The result is the exit code: 0 done, 1 failed,
/// 2 usage error.
///
/// `reset` does not tell a running Agent: it removes the file, and the Agent reads a user's layer
/// from the file when it decides, so a change takes effect at the next decision after the file is
/// gone, not at a moment this command promises.
pub fn run(
    args: &[String],
    root: &Path,
    passwd: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let (command, user) = match words.as_slice() {
        ["policy", command @ ("show" | "reset"), "--user", user] => (*command, *user),
        _ => return usage(err, "expected: policy show|reset --user <name|uid>"),
    };
    let Some(uid) = resolve_user(user, passwd) else {
        return usage(err, "not a number or a local account name");
    };
    let path = UserPolicyStore::new(root).path(uid);
    // Both commands work through descriptors: the state directory, then the user's directory below
    // it, each opened without following a link, and the file relative to that one. A path that is
    // checked and then opened again can be swapped in between by the less privileged account that
    // owns these directories (review finding R-27, #369).
    let directory = match open_user_directory(root, uid) {
        Ok(directory) => Some(directory),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return fail_with(&path, err, &e),
    };
    let fail = |err: &mut dyn Write, e: io::Error| fail_with(&path, err, &e);
    let none = |err: &mut dyn Write| {
        let _ = writeln!(err, "no user layer stored for uid {uid}");
        0
    };
    if command == "show" {
        match directory
            .as_ref()
            .map_or_else(|| Err(ErrorKind::NotFound.into()), read_layer)
        {
            Ok(text) if out.write_all(printable(&text).as_bytes()).is_ok() => 0,
            Ok(_) => 1,
            Err(e) if e.kind() == ErrorKind::NotFound => none(err),
            Err(e) => fail(err, e),
        }
    } else {
        match directory.as_ref().map_or_else(
            || Err(ErrorKind::NotFound.into()),
            |directory| {
                rustix::fs::unlinkat(directory, LAYER_FILE, AtFlags::empty())
                    .map_err(io::Error::from)
            },
        ) {
            Ok(()) => {
                let _ = writeln!(out, "cleared the user layer of uid {uid}");
                0
            }
            Err(e) if e.kind() == ErrorKind::NotFound => none(err),
            Err(e) => fail(err, e),
        }
    }
}

/// Reports a failure on `path`.
fn fail_with(path: &Path, err: &mut dyn Write, e: &io::Error) -> u8 {
    let _ = writeln!(
        err,
        "{}: {e} (run as root if this is a permission error)",
        path.display()
    );
    1
}

/// The name of the layer in the user's directory.
const LAYER_FILE: &str = "policy.toml";

/// Opens `<root>/<uid>` for reading as a directory without following a link, relative to `root`,
/// which is itself opened without following a link. The state directory belongs to the less
/// privileged `linuxhello` user and these commands run as root: a link in place of either would
/// make root read or remove a file somewhere else.
///
/// # Errors
///
/// `NotFound` when there is no such directory; anything else when it is a link, not a directory,
/// or cannot be opened.
fn open_user_directory(root: &Path, uid: u32) -> io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root = rustix::fs::open(root, flags, Mode::empty())?;
    Ok(rustix::fs::openat(
        &root,
        uid.to_string(),
        flags,
        Mode::empty(),
    )?)
}

/// Reads the layer in `directory` as text: the file must be a regular file (it is opened without
/// following a link and without blocking, so a FIFO or a link is refused and cannot stall root),
/// of at most [`MAX_LAYER_BYTES`], and UTF-8.
fn read_layer(directory: &OwnedFd) -> io::Result<String> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(directory, LAYER_FILE, flags, Mode::empty())?;
    let file = File::from(fd);
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if meta.len() > MAX_LAYER_BYTES {
        return Err(io::Error::new(ErrorKind::InvalidInput, "too large to show"));
    }
    let mut text = String::new();
    file.take(MAX_LAYER_BYTES + 1).read_to_string(&mut text)?;
    Ok(text)
}

/// `text` with every character that could act on a terminal written as `\u{..}`: control
/// characters (also C1, which include U+009B, a one-character escape for control sequences), DEL,
/// and the characters that change the direction of text (U+202A to U+202E, U+2066 to U+2069, the
/// marks U+200E, U+200F and U+061C). Newline and tab stay. The file is the user's text and `show`
/// puts it on the administrator's terminal (R-27, #369).
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let unsafe_char = (c.is_control() && c != '\n' && c != '\t')
            || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
            || matches!(c, '\u{200E}' | '\u{200F}' | '\u{061C}');
        if unsafe_char {
            out.push_str(&format!("\\u{{{:04x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// Prints `why` and the usage line to `err` and returns the usage exit code, 2.
fn usage(err: &mut dyn Write, why: &str) -> u8 {
    let _ = writeln!(err, "{why}\n{USAGE}");
    2
}

/// The uid named by `user`: a decimal `u32` (digits only, no sign) or the first field of a line of
/// `passwd`. `None` when it is neither.
pub(crate) fn resolve_user(user: &str, passwd: &str) -> Option<u32> {
    if user.is_empty() {
        return None;
    }
    if user.bytes().all(|b| b.is_ascii_digit()) {
        return user.parse().ok();
    }
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(user))
            .then(|| fields.nth(1)?.parse().ok())
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// The text of a layer, built from short pieces.
    fn layer() -> String {
        format!("[{}]\n{} = false\n", "methods", "biometrics_allowed")
    }

    /// A passwd text with root (0) and anna (1000).
    fn passwd() -> String {
        let line = |name: &str, uid: u32| format!("{name}:x:{uid}:{uid}::/home/{name}:/bin/sh\n");
        line("root", 0) + &line("anna", 1000)
    }

    /// Runs the command and returns (exit code, stdout, stderr).
    fn go(root: &Path, words: &[&str]) -> (u8, String, String) {
        let args: Vec<String> = words.iter().map(|w| (*w).to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&args, root, &passwd(), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    /// Writes a layer for `uid` under `root`.
    fn store(root: &Path, uid: u32, text: &str) {
        let dir = root.join(uid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("policy.toml"), text).unwrap();
    }

    #[test]
    fn show_prints_the_stored_layer_unchanged() {
        let root = tempfile::tempdir().unwrap();
        store(root.path(), 1000, &layer());
        let (code, out, _) = go(root.path(), &["policy", "show", "--user", "anna"]);
        assert_eq!(code, 0);
        assert_eq!(out, layer());
        let file = root.path().join("1000").join("policy.toml");
        assert_eq!(fs::read_to_string(file).unwrap(), layer());
    }

    #[test]
    fn show_writes_control_and_direction_characters_as_escapes() {
        // R-27, #369: the TOML parser accepts U+009B and U+202E in a comment; they must not reach
        // the administrator's terminal as they are.
        let root = tempfile::tempdir().unwrap();
        store(
            root.path(),
            1000,
            "# a\u{9b}31m b\u{202e}c \u{7}\u{1b}[2J\nkey = \"v\"\t# ok\n",
        );
        let (code, out, _) = go(root.path(), &["policy", "show", "--user", "1000"]);
        assert_eq!(code, 0);
        assert!(out.contains("\\u{009b}31m"), "{out}");
        assert!(out.contains("b\\u{202e}c"), "{out}");
        assert!(out.contains("\\u{0007}\\u{001b}[2J"), "{out}");
        assert!(!out
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t'));
        assert!(
            out.contains("key = \"v\"\t# ok\n"),
            "newline and tab are kept"
        );
    }

    #[test]
    fn a_layer_that_is_a_link_a_fifo_or_too_large_is_refused() {
        // R-27, #369: root must not follow what the less privileged account put in its place.
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("1000");
        fs::create_dir_all(&dir).unwrap();
        let secret = root.path().join("secret.txt");
        fs::write(&secret, "not a policy").unwrap();
        std::os::unix::fs::symlink(&secret, dir.join("policy.toml")).unwrap();
        let (code, out, err) = go(root.path(), &["policy", "show", "--user", "1000"]);
        assert_eq!(code, 1, "a link to a file");
        assert!(out.is_empty() && !err.contains("not a policy"));

        fs::remove_file(dir.join("policy.toml")).unwrap();
        let fifo = std::ffi::CString::new(dir.join("policy.toml").to_str().unwrap()).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            fifo.as_c_str(),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_bits_truncate(0o600),
            0,
        )
        .unwrap();
        let (code, out, _) = go(root.path(), &["policy", "show", "--user", "1000"]);
        assert_eq!(
            (code, out.as_str()),
            (1, ""),
            "a FIFO neither blocks nor is read"
        );

        fs::remove_file(dir.join("policy.toml")).unwrap();
        let big = fs::File::create(dir.join("policy.toml")).unwrap();
        big.set_len(MAX_LAYER_BYTES + 1).unwrap();
        let (code, out, _) = go(root.path(), &["policy", "show", "--user", "1000"]);
        assert_eq!((code, out.as_str()), (1, ""), "too large");
    }

    #[test]
    fn a_user_directory_that_is_a_link_is_refused_by_show_and_reset() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        fs::write(elsewhere.path().join("policy.toml"), layer()).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), root.path().join("1000")).unwrap();
        for command in ["show", "reset"] {
            let (code, out, err) = go(root.path(), &["policy", command, "--user", "1000"]);
            assert_eq!(code, 1, "{command}");
            assert!(out.is_empty() && !err.is_empty(), "{command}: {err}");
        }
        assert!(elsewhere.path().join("policy.toml").exists());
    }

    #[test]
    fn show_without_a_layer_says_so_and_creates_nothing() {
        let root = tempfile::tempdir().unwrap();
        let (code, out, err) = go(root.path(), &["policy", "show", "--user", "1000"]);
        assert_eq!(code, 0);
        assert!(out.is_empty());
        assert!(err.contains("1000") && err.contains("no user layer stored"));
        assert!(!root.path().join("1000").exists());
    }

    #[test]
    fn reset_removes_only_that_users_layer() {
        let root = tempfile::tempdir().unwrap();
        store(root.path(), 1000, &layer());
        store(root.path(), 1001, &layer());
        let (code, out, _) = go(root.path(), &["policy", "reset", "--user", "1000"]);
        assert_eq!(code, 0);
        assert!(out.contains("cleared") && out.contains("1000"));
        assert!(!root.path().join("1000").join("policy.toml").exists());
        let other = root.path().join("1001").join("policy.toml");
        assert_eq!(fs::read_to_string(other).unwrap(), layer());
    }

    #[test]
    fn reset_without_a_layer_succeeds_and_creates_nothing() {
        let root = tempfile::tempdir().unwrap();
        for _ in 0..2 {
            let (code, out, err) = go(root.path(), &["policy", "reset", "--user", "1000"]);
            assert_eq!(code, 0);
            assert!(out.is_empty());
            assert!(err.contains("no user layer stored"));
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn user_is_a_name_from_passwd_or_a_number() {
        let root = tempfile::tempdir().unwrap();
        for (user, uid) in [("anna", 1000), ("1000", 1000), ("root", 0), ("0", 0)] {
            store(root.path(), uid, &layer());
            let (code, out, _) = go(root.path(), &["policy", "show", "--user", user]);
            assert_eq!((code, out), (0, layer()), "{user}");
        }
        let big = (u64::from(u32::MAX) + 1).to_string();
        let bad = [
            "nobody-here",
            "-1",
            "+1000",
            "1000x",
            "../1000",
            "",
            big.as_str(),
        ];
        for user in bad {
            for command in ["show", "reset"] {
                let (code, out, err) = go(root.path(), &["policy", command, "--user", user]);
                assert_eq!(code, 2, "{command} {user:?}");
                assert!(out.is_empty() && !err.is_empty());
            }
        }
        for uid in [0, 1000] {
            let file = root.path().join(uid.to_string()).join("policy.toml");
            assert_eq!(fs::read_to_string(file).unwrap(), layer());
        }
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
    }

    #[test]
    fn usage_errors_exit_2_and_touch_nothing() {
        let root = tempfile::tempdir().unwrap();
        store(root.path(), 1000, &layer());
        let cases: [&[&str]; 5] = [
            &["policy"],
            &["policy", "frobnicate", "--user", "1000"],
            &["policy", "show"],
            &["policy", "show", "--user"],
            &["policy", "show", "--user", "1000", "extra"],
        ];
        for words in cases {
            let (code, out, err) = go(root.path(), words);
            assert_eq!(code, 2, "{words:?}");
            assert!(out.is_empty() && err.contains("usage"));
        }
        let file = root.path().join("1000").join("policy.toml");
        assert_eq!(fs::read_to_string(file).unwrap(), layer());
    }

    #[test]
    fn reset_reports_a_failure_instead_of_claiming_success() {
        if fs::metadata("/proc/self").unwrap().uid() == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        store(root.path(), 1000, &layer());
        let dir = root.path().join("1000");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let (code, out, err) = go(root.path(), &["policy", "reset", "--user", "1000"]);
        let still_there = dir.join("policy.toml").exists();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(code, 1);
        assert!(!out.contains("cleared"));
        assert!(err.contains("policy.toml") && err.contains("ermission denied"));
        assert!(still_there);
    }
}
