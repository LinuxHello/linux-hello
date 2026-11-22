//! What the greeter offers to choose: the installed desktops and the people who can sign in, read
//! from files, without Qt (ADR-0028, amendment of 2026-11-22).
//!
//! A desktop is a *session file* in `/usr/share/wayland-sessions` or `/usr/share/xsessions`, the
//! files GDM and SDDM read too: its `Name` is shown, its `Exec` is the command greetd starts. A
//! desktop of the X window system needs an X server first, so an X session is offered only when
//! `startx` is installed and is started as `startx /usr/bin/env <command>`. A person is an account
//! in `/etc/passwd` with a user id in the range of `/etc/login.defs` (`UID_MIN`, `UID_MAX`) and a
//! shell that lets them in. Nothing here starts a program; greetd starts the desktop.
//!
//! C4 component: `agentLink` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::path::{Path, PathBuf};

use serde::Serialize;

/// One desktop the greeter can start.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Desktop {
    /// The name shown in the menu, such as "Plasma (Wayland)".
    pub name: String,
    /// The command greetd starts, split into its words.
    pub command: Vec<String>,
    /// `NAME=value` lines for the desktop's environment.
    pub env: Vec<String>,
}

/// One person who can sign in.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Person {
    /// The account name greetd needs.
    pub account: String,
    /// The name shown: the full name from `/etc/passwd`, or the account name.
    pub name: String,
}

/// The keys of the `[Desktop Entry]` group of a session file.
fn entry(text: &str) -> Vec<(String, String)> {
    let mut keys = Vec::new();
    let mut inside = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == "[Desktop Entry]";
        } else if inside {
            if let Some((key, value)) = line.split_once('=') {
                keys.push((key.trim().to_string(), value.trim().to_string()));
            }
        }
    }
    keys
}

/// The words of an `Exec` line: double quotes group words, and field codes such as `%f` are
/// dropped, as the Desktop Entry Specification says (`exec_lines_are_split_into_words`).
pub fn exec_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut started = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            '\\' if quoted => {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            c => {
                word.push(c);
                started = true;
            }
        }
    }
    if started {
        words.push(word);
    }
    words
        .into_iter()
        .filter(|w| !(w.len() == 2 && w.starts_with('%')))
        .collect()
}

/// Whether `program` exists: an absolute path, or a name in one of `path`'s directories.
fn installed(program: &str, path: &[PathBuf]) -> bool {
    if program.starts_with('/') {
        return Path::new(program).is_file();
    }
    path.iter().any(|dir| dir.join(program).is_file())
}

/// The desktop of one session file, `None` when it is hidden or its program is not installed
/// (`hidden_and_missing_desktops_are_left_out`). `x11` says it is an X session; `startx` is the
/// path of `startx` when it is installed.
pub fn desktop(
    text: &str,
    stem: &str,
    x11: bool,
    startx: Option<&str>,
    path: &[PathBuf],
) -> Option<Desktop> {
    let keys = entry(text);
    let get = |name: &str| {
        keys.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    if get("Hidden") == Some("true") || get("NoDisplay") == Some("true") {
        return None;
    }
    if let Some(program) = get("TryExec") {
        if !installed(program, path) {
            return None;
        }
    }
    let mut command = exec_words(get("Exec")?);
    let first = command.first()?;
    if !installed(first, path) {
        return None;
    }
    if x11 {
        let startx = startx?;
        command.splice(0..0, [startx.to_string(), "/usr/bin/env".to_string()]);
    }
    let names = get("DesktopNames").unwrap_or(stem).replace(';', ":");
    let names = names.trim_end_matches(':').to_string();
    let kind = if x11 { "x11" } else { "wayland" };
    Some(Desktop {
        name: get("Name").unwrap_or(stem).to_string(),
        command,
        env: vec![
            format!("XDG_SESSION_TYPE={kind}"),
            format!("XDG_SESSION_DESKTOP={stem}"),
            format!("XDG_CURRENT_DESKTOP={names}"),
        ],
    })
}

/// The installed desktops, Wayland sessions first, each group in the order of its file names.
pub fn desktops() -> Vec<Desktop> {
    let path: Vec<PathBuf> = ["/usr/local/bin", "/usr/bin", "/bin"]
        .iter()
        .map(PathBuf::from)
        .collect();
    let startx = Path::new("/usr/bin/startx")
        .is_file()
        .then_some("/usr/bin/startx");
    let mut found = Vec::new();
    for (dir, x11) in [
        ("/usr/share/wayland-sessions", false),
        ("/usr/share/xsessions", true),
    ] {
        let Ok(read) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = read
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "desktop"))
            .collect();
        files.sort();
        for file in files {
            let (Ok(text), Some(stem)) = (
                std::fs::read_to_string(&file),
                file.file_stem().and_then(|s| s.to_str()),
            ) else {
                continue;
            };
            if let Some(d) = desktop(&text, stem, x11, startx, &path) {
                found.push(d);
            }
        }
    }
    found
}

/// The range of user ids of people in `login.defs`, 1000 to 60000 when it says nothing.
pub fn uid_range(login_defs: &str) -> (u32, u32) {
    let value = |key: &str, default: u32| {
        login_defs
            .lines()
            .map(str::split_whitespace)
            .find_map(|mut words| {
                (words.next() == Some(key)).then(|| words.next()?.parse().ok())?
            })
            .unwrap_or(default)
    };
    (value("UID_MIN", 1000), value("UID_MAX", 60000))
}

/// The people of `passwd` whose id is in `range` and whose shell lets them in
/// (`only_people_who_can_sign_in_are_listed`).
pub fn people(passwd: &str, range: (u32, u32)) -> Vec<Person> {
    passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let [account, _, uid, _, gecos, _, shell] = fields.as_slice() else {
                return None;
            };
            let uid: u32 = uid.parse().ok()?;
            let closed = shell.ends_with("/nologin") || shell.ends_with("/false");
            if uid < range.0 || uid > range.1 || closed || account.is_empty() {
                return None;
            }
            let full = gecos.split(',').next().unwrap_or("").trim();
            Some(Person {
                account: (*account).to_string(),
                name: if full.is_empty() { account } else { full }.to_string(),
            })
        })
        .collect()
}

/// The people of this machine.
pub fn people_here() -> Vec<Person> {
    let defs = std::fs::read_to_string("/etc/login.defs").unwrap_or_default();
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    people(&passwd, uid_range(&defs))
}

#[cfg(test)]
mod tests;
