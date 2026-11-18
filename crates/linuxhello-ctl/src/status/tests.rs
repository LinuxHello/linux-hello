//! Tests of `status` and `doctor` on temporary policy trees.

use super::*;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Mutex;
use tempfile::TempDir;

/// The strict admin text of the loader tests: `sudo` needs two factors and has two methods.
const STRICT_ADMIN: &[u8] = b"[pin]\nmin_length = 12\n\
    [context.sudo]\nmethods = [\"pin\", \"fingerprint\"]\nfactors = 2\n\
    [rp_class.bank]\nmatch = [\"bank.example\"]\nfactors = 2\nrequire_second_credential = true\n";

/// A temporary tree: the admin directory, the state directory and the uid that owns them.
struct Tree {
    /// Keeps the directory alive.
    tmp: TempDir,
    /// The admin policy directory.
    admin: PathBuf,
    /// The state directory for the user layers.
    users: PathBuf,
    /// The uid of the test's own user, which owns the directories.
    uid: u32,
}

/// Builds the tree: parent 0755, admin directory 0755, state directory 0755.
fn tree() -> Tree {
    let tmp = TempDir::new().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let admin = tmp.path().join("admin.d");
    fs::create_dir(&admin).unwrap();
    fs::set_permissions(&admin, fs::Permissions::from_mode(0o755)).unwrap();
    let users = tmp.path().join("users");
    fs::create_dir(&users).unwrap();
    let uid = fs::metadata(&admin).unwrap().uid();
    Tree {
        tmp,
        admin,
        users,
        uid,
    }
}

/// Writes `content` to `path` with mode 0644.
fn write(path: &Path, content: &[u8]) {
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
}

/// Writes the layer of `uid` in the state directory.
fn store(tree: &Tree, uid: u32, content: &[u8]) {
    let dir = tree.users.join(uid.to_string());
    fs::create_dir_all(&dir).unwrap();
    write(&dir.join("policy.toml"), content);
}

/// A passwd text with anna (1000).
const PASSWD: &str = "anna:x:1000:1000::/home/anna:/bin/sh\n";

/// A machine that answers from a table and records every call. `all_ok` is a healthy one.
struct FakeHost {
    /// The answer for each program, by name; a program that is absent cannot be started.
    programs: HashMap<&'static str, (i32, String)>,
    /// The text of each readable file, by path; a path that is absent cannot be read.
    files: HashMap<&'static str, String>,
    /// Every call made, in order: `run <program> <arguments>` or `read <path>`.
    calls: Mutex<Vec<String>>,
}

impl FakeHost {
    /// The unit is active, the profile enforces, the fingerprint service has a device and Howdy
    /// is installed.
    fn all_ok() -> Self {
        Self {
            programs: HashMap::from([
                ("systemctl", (0, "active".to_string())),
                ("busctl", (0, String::new())),
            ]),
            files: HashMap::from([
                (
                    "/sys/kernel/security/apparmor/profiles",
                    "linuxhello-agent (enforce)\nother (enforce)\n".to_string(),
                ),
                ("/etc/howdy/config.ini", String::new()),
            ]),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The same machine, but `program` answers with `code` and `stdout`.
    fn with_program(mut self, program: &'static str, code: i32, stdout: &str) -> Self {
        self.programs.insert(program, (code, stdout.to_string()));
        self
    }

    /// The same machine, but `program` cannot be started.
    fn without_program(mut self, program: &'static str) -> Self {
        self.programs.remove(program);
        self
    }

    /// The same machine, but the file at `path` holds `text`.
    fn with_file(mut self, path: &'static str, text: &str) -> Self {
        self.files.insert(path, text.to_string());
        self
    }

    /// The same machine, but the file at `path` cannot be read.
    fn without_file(mut self, path: &'static str) -> Self {
        self.files.remove(path);
        self
    }

    /// The calls made so far.
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Host for FakeHost {
    fn run(&self, program: &str, args: &[&str]) -> Option<(i32, String)> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("run {program} {}", args.join(" ")));
        self.programs.get(program).cloned()
    }

    fn read(&self, path: &Path) -> Option<String> {
        let path = path.to_str().unwrap();
        self.calls.lock().unwrap().push(format!("read {path}"));
        self.files.get(path).cloned()
    }
}

/// Runs the command with `words` on a healthy machine and returns (exit code, stdout, stderr).
fn go(tree: &Tree, users: &Path, words: &[&str]) -> (u8, String, String) {
    go_on(&FakeHost::all_ok(), tree, users, words)
}

/// Runs the command with `words` on `host` and returns (exit code, stdout, stderr).
fn go_on(host: &FakeHost, tree: &Tree, users: &Path, words: &[&str]) -> (u8, String, String) {
    let args: Vec<String> = words.iter().map(|w| (*w).to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(
        &args,
        host,
        &tree.admin,
        tree.uid,
        users,
        PASSWD,
        &mut out,
        &mut err,
    );
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// The tree with the strict admin layer and a damaged layer for anna: PIN-only, `sudo` unsatisfiable.
fn damaged() -> Tree {
    let t = tree();
    write(&t.admin.join("10-site.toml"), STRICT_ADMIN);
    store(&t, 1000, b"invalid = toml");
    t
}

#[test]
fn status_prints_one_line_per_condition_with_code_severity_and_sentence() {
    let t = damaged();
    let (code, out, _) = go(&t, &t.users, &["status", "--user", "anna"]);
    assert_eq!(code, 0);
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        [
            "policy-pin-only  severe  Biometric sign-in is off because a policy file failed to load.",
            "context-unsatisfiable: sudo  severe  sudo cannot be unlocked with the configured methods.",
        ]
    );
}

#[test]
fn status_never_prints_a_file_name() {
    let t = damaged();
    let (_, out, err) = go(&t, &t.users, &["status", "--user", "1000"]);
    let tmp = t.tmp.path().to_str().unwrap();
    for text in [&out, &err] {
        assert!(!text.contains("10-site.toml"));
        assert!(!text.contains("policy.toml"));
        assert!(!text.contains(tmp));
    }
}

#[test]
fn status_with_no_conditions_says_so_and_exits_zero() {
    let t = tree();
    let (code, out, _) = go(&t, &t.users, &["status", "--user", "1000"]);
    assert_eq!((code, out.as_str()), (0, "no conditions\n"));
}

#[test]
fn doctor_exits_nonzero_and_names_the_file_for_a_policy_that_does_not_parse() {
    let t = tree();
    write(&t.admin.join("10-site.toml"), b"invalid = toml");
    let (code, out, _) = go(&t, &t.users, &["doctor"]);
    assert_eq!(code, 1);
    assert!(out.contains("[admin] policy-pin-only"));
    assert!(out.contains("10-site.toml"));
    assert!(out.contains("fix: Fix or remove the file named above, then run doctor again."));
}

#[test]
fn doctor_reports_an_unsatisfiable_context_by_name() {
    let t = damaged();
    let (code, out, _) = go(&t, &t.users, &["doctor"]);
    assert_eq!(code, 1);
    assert!(out.contains("[uid 1000] context-unsatisfiable: sudo"));
}

#[test]
fn doctor_with_a_clean_policy_prints_ok_and_exits_zero() {
    let t = tree();
    store(&t, 1000, b"[pin]\nlockout_attempts = 3");
    let (code, out, _) = go(&t, &t.users, &["doctor"]);
    assert_eq!((code, out.as_str()), (0, "ok\n"));
}

#[test]
fn doctor_reports_an_unreadable_state_directory_as_a_condition_not_a_clean_run() {
    let t = tree();
    let not_a_directory = t.tmp.path().join("file");
    write(&not_a_directory, b"");
    let (code, out, _) = go(&t, &not_a_directory, &["doctor"]);
    assert_eq!(code, 1);
    assert!(out.contains("status-fact-unreadable: the state directory"));
}

#[test]
fn conditions_come_in_the_fixed_order_not_discovery_order() {
    let t = tree();
    write(
        &t.admin.join("10-site.toml"),
        b"[context.unlock]\nmethods = [\"pin\"]\nfactors = 2\n\
          [context.login]\nmethods = [\"pin\"]\nfactors = 2\n",
    );
    store(&t, 1000, b"invalid = toml");
    let (_, out, _) = go(&t, &t.users, &["status", "--user", "1000"]);
    let codes: Vec<&str> = out.lines().map(|l| l.split("  ").next().unwrap()).collect();
    assert_eq!(
        codes,
        [
            "policy-pin-only",
            "context-unsatisfiable: login",
            "context-unsatisfiable: unlock"
        ]
    );
}

/// Every path under `dir` with its mode, size and modification time.
fn snapshot(dir: &Path, into: &mut Vec<(PathBuf, u32, u64, i64, i64)>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        let meta = fs::symlink_metadata(&path).unwrap();
        into.push((
            path.clone(),
            meta.mode(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
        ));
        if meta.is_dir() {
            snapshot(&path, into);
        }
    }
}

#[test]
fn status_and_doctor_never_write() {
    let t = damaged();
    let (mut before, mut after) = (Vec::new(), Vec::new());
    snapshot(t.tmp.path(), &mut before);
    go(&t, &t.users, &["status", "--user", "1000"]);
    go(&t, &t.users, &["doctor"]);
    snapshot(t.tmp.path(), &mut after);
    assert!(!before.is_empty());
    assert_eq!(before, after);
}

#[test]
fn status_with_a_name_that_does_not_resolve_is_a_usage_error() {
    let t = tree();
    let (code, out, err) = go(&t, &t.users, &["status", "--user", "nobody-like-this"]);
    assert_eq!(code, 2);
    assert!(out.is_empty());
    assert!(err.contains(USAGE));
}

/// A tree with a sound admin layer, so that only the machine's facts can fail.
fn sound_tree() -> Tree {
    let t = tree();
    write(&t.admin.join("10-sound.toml"), b"[pin]\nmin_length = 12\n");
    t
}

#[test]
fn doctor_is_ok_when_every_probe_is_fine() {
    let t = sound_tree();
    let (code, out, _) = go(&t, &t.users, &["doctor"]);
    assert_eq!((code, out.trim()), (0, "ok"));
}

#[test]
fn doctor_reports_an_inactive_agent_unit() {
    let t = sound_tree();
    let host = FakeHost::all_ok().with_program("systemctl", 3, "inactive");
    let (code, out, _) = go_on(&host, &t, &t.users, &["doctor"]);
    assert_eq!(code, 1);
    assert!(
        out.contains("agent-unit-inactive  severe  The Linux Hello Agent is not running."),
        "{out}"
    );
    assert!(
        out.contains("fix: Run `systemctl status linuxhello-agent` and read why it stopped."),
        "{out}"
    );
}

#[test]
fn doctor_reports_a_profile_that_is_not_enforcing() {
    let t = sound_tree();
    let complain = FakeHost::all_ok().with_file(
        "/sys/kernel/security/apparmor/profiles",
        "linuxhello-agent (complain)\n",
    );
    let (code, out, _) = go_on(&complain, &t, &t.users, &["doctor"]);
    assert_eq!(code, 1);
    assert!(out.contains("agent-profile-not-enforcing"), "{out}");
    assert!(out.contains("detail: in complain mode"), "{out}");

    let missing = FakeHost::all_ok().with_file(
        "/sys/kernel/security/apparmor/profiles",
        "other (enforce)\n",
    );
    let (code, out, _) = go_on(&missing, &t, &t.users, &["doctor"]);
    assert_eq!(code, 1);
    assert!(out.contains("detail: not loaded"), "{out}");
}

#[test]
fn doctor_reports_unavailable_methods() {
    let t = sound_tree();
    let host = FakeHost::all_ok()
        .with_program("busctl", 1, "")
        .without_file("/etc/howdy/config.ini");
    let (code, out, _) = go_on(&host, &t, &t.users, &["doctor"]);
    assert_eq!(code, 1);
    assert!(out.contains("method-unavailable: fingerprint"), "{out}");
    assert!(out.contains("method-unavailable: face"), "{out}");
}

#[test]
fn a_probe_that_cannot_run_is_a_condition_not_a_clean_result() {
    let t = sound_tree();
    let cases = [
        (
            FakeHost::all_ok().without_program("systemctl"),
            "status-fact-unreadable: the agent unit",
        ),
        (
            FakeHost::all_ok().without_file("/sys/kernel/security/apparmor/profiles"),
            "status-fact-unreadable: the AppArmor profile list",
        ),
        (
            FakeHost::all_ok().without_program("busctl"),
            "status-fact-unreadable: the fingerprint service",
        ),
    ];
    for (host, code_text) in cases {
        let (code, out, _) = go_on(&host, &t, &t.users, &["doctor"]);
        assert_eq!(code, 1, "{code_text}");
        assert!(out.contains(code_text), "{out}");
        assert!(!out.trim().ends_with("ok"), "{out}");
    }
}

#[test]
fn status_probes_nothing() {
    let t = sound_tree();
    let host = FakeHost::all_ok();
    let (code, _, _) = go_on(&host, &t, &t.users, &["status", "--user", "1000"]);
    assert_eq!(code, 0);
    assert_eq!(host.calls(), Vec::<String>::new());
}

#[test]
fn doctor_probes_only_the_named_commands_and_files() {
    let t = sound_tree();
    let host = FakeHost::all_ok();
    go_on(&host, &t, &t.users, &["doctor"]);
    assert_eq!(
        host.calls(),
        vec![
            "run systemctl is-active linuxhello-agent.service".to_string(),
            "read /sys/kernel/security/apparmor/profiles".to_string(),
            "run busctl --system --timeout=5 call net.reactivated.Fprint \
             /net/reactivated/Fprint/Manager net.reactivated.Fprint.Manager GetDefaultDevice"
                .to_string(),
            "read /etc/howdy/config.ini".to_string(),
        ]
    );
}
