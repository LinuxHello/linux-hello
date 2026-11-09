//! Reading the policy files from disk: every `*.toml` in the admin directory and
//! the user's file, merged by `merge`. It fails closed: an admin directory or
//! file that cannot be examined, is not owned by the admin owner or is writable
//! by group or others, a directory that cannot be listed, a file that is not a
//! regular file, is too large, cannot be read, is not UTF-8 or does not parse,
//! and a contradictory merge all give the PIN-only state (policy-semantics.md,
//! *Fail closed*; invariant 3). Only a path that does not exist counts as
//! absent.

use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::policy::defaults::default_layer;
use crate::policy::merge::{merge, Effective};
use crate::policy::restrict::Contradiction;
use crate::policy::schema::{parse_layer, Layer};
use crate::policy::schema::{RpPrompt, RpProvider};

/// The largest policy file the loader reads, in bytes. A larger file is refused.
pub const MAX_POLICY_FILE_BYTES: u64 = 1024 * 1024;

/// The result of a policy load attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// Every layer read and merged without contradiction.
    Effective(Effective),
    /// Fail closed: returns a minimal PIN-only policy.
    PinOnly(PinOnly),
}

/// The state returned when policy loading fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinOnly {
    /// The minimal PIN-only layer.
    pub layer: Layer,
    /// Always `RpProvider::Tpm`.
    pub rp_provider: RpProvider,
    /// Always `RpPrompt::Reverify`.
    pub rp_prompt: RpPrompt,
    /// Always 1.
    pub rp_factors: u32,
    /// Why the load failed (names the file, never its content).
    pub reason: String,
}

/// Loads the effective policy from the provided paths.
///
/// Admin files are all `*.toml` files in `admin_dir`, read in file-name order.
/// If `admin_dir` or `user_file` does not exist, it contributes nothing. Any
/// other failure to examine one of them is an error, never "absent"
/// (`admin_dir_that_cannot_be_examined_leaves_only_pin`).
///
/// Returns `PinOnly` if:
/// - [`admin_layers`] refuses the admin directory or one of its files.
/// - `user_file` exists but cannot be examined or read, is not a regular file,
///   is too large, is not UTF-8, or fails `parse_layer`.
/// - `merge` returns a contradiction.
///
/// The reason names the path and what is wrong, never the file's content
/// (`pin_only_reason_names_the_file_not_its_content`).
pub fn load(admin_dir: &Path, user_file: &Path, admin_owner_uid: u32) -> Policy {
    let admin = match admin_layers(admin_dir, admin_owner_uid) {
        Ok(layers) => layers,
        Err(reason) => return Policy::PinOnly(create_pin_only_state(reason)),
    };

    let user_layer = match read_optional_layer(user_file) {
        Ok(layer) => layer,
        Err(what) => return Policy::PinOnly(create_pin_only_state(describe(user_file, &what))),
    };

    match merge(&admin, user_layer.as_ref()) {
        Ok(effective) => Policy::Effective(effective),
        Err(contradiction) => {
            let reason = match contradiction {
                Contradiction::ClassConflict(name) => {
                    format!("merge: contradiction ClassConflict({name})")
                }
                Contradiction::MaxLengthBelowMinLength => {
                    "merge: contradiction MaxLengthBelowMinLength".to_string()
                }
                Contradiction::AllClassesDisallowed => {
                    "merge: contradiction AllClassesDisallowed".to_string()
                }
            };
            Policy::PinOnly(create_pin_only_state(reason))
        }
    }
}

/// Reads and parses every `*.toml` file of the admin directory, in file-name
/// order. A directory that does not exist gives no layers.
///
/// # Errors
///
/// A reason of the form `"<path>: <what is wrong>"` when the directory or its
/// parent cannot be examined, is not a directory, is not owned by
/// `admin_owner_uid` or is writable by group or others; when the directory
/// cannot be listed; and when a file is not a regular file (a symbolic link
/// included), has the wrong owner or mode, is larger than
/// [`MAX_POLICY_FILE_BYTES`], cannot be read, is not UTF-8 or does not parse.
pub fn admin_layers(admin_dir: &Path, admin_owner_uid: u32) -> Result<Vec<Layer>, String> {
    let metadata = match fs::metadata(admin_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(describe(admin_dir, "cannot be examined")),
    };
    if !metadata.is_dir() {
        return Err(describe(admin_dir, "is not a directory"));
    }
    check_owner_and_mode(&metadata, admin_owner_uid).map_err(|what| describe(admin_dir, &what))?;
    if let Some(parent) = admin_dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        let parent_metadata =
            fs::metadata(parent).map_err(|_| describe(parent, "cannot be examined"))?;
        check_owner_and_mode(&parent_metadata, admin_owner_uid)
            .map_err(|what| describe(parent, &what))?;
    }

    let entries = fs::read_dir(admin_dir).map_err(|_| describe(admin_dir, "cannot be listed"))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| describe(admin_dir, "cannot be listed"))?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut layers = Vec::new();
    for path in paths {
        let layer =
            read_layer(&path, Some(admin_owner_uid)).map_err(|what| describe(&path, &what))?;
        layers.push(layer);
    }
    Ok(layers)
}

/// Reads the layer at `path`, or `None` when nothing exists there.
///
/// # Errors
///
/// `"cannot be examined"` when the path cannot be looked at for any reason but
/// not existing, and every error of [`read_layer`].
fn read_optional_layer(path: &Path) -> Result<Option<Layer>, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_layer(path, None).map(Some),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err("cannot be examined".to_string()),
    }
}

/// Reads one policy file and parses it as a layer. The file is opened once and
/// every check after that is made on the open file, not on the path again. With
/// `owner`, the file must be owned by that uid and not writable by group or
/// others.
///
/// # Errors
///
/// What is wrong, without the file's content: `"is not a regular file"` (also for
/// a symbolic link, a FIFO or a device), `"cannot be read"`, the errors of
/// [`check_owner_and_mode`], `"is too large"`, `"is not UTF-8"` or
/// `"does not parse"` (never `parse_layer`'s message, which quotes the file).
fn read_layer(path: &Path, owner: Option<u32>) -> Result<Layer, String> {
    // Looked at before opening, so that a FIFO is never opened: opening one blocks.
    let link = fs::symlink_metadata(path).map_err(|_| "cannot be read".to_string())?;
    if !link.file_type().is_file() {
        return Err("is not a regular file".to_string());
    }
    let file = fs::File::open(path).map_err(|_| "cannot be read".to_string())?;
    let metadata = file.metadata().map_err(|_| "cannot be read".to_string())?;
    if !metadata.is_file() {
        return Err("is not a regular file".to_string());
    }
    if let Some(owner) = owner {
        check_owner_and_mode(&metadata, owner)?;
    }
    if metadata.len() > MAX_POLICY_FILE_BYTES {
        return Err("is too large".to_string());
    }
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot be read".to_string())?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_POLICY_FILE_BYTES) {
        return Err("is too large".to_string());
    }
    let text = String::from_utf8(bytes).map_err(|_| "is not UTF-8".to_string())?;
    parse_layer(&text).map_err(|_| "does not parse".to_string())
}

/// Checks that the file or directory behind `metadata` is owned by
/// `expected_uid` and has neither the group- nor the other-write bit (`0o022`) set.
///
/// # Errors
///
/// `"not owned by uid <n>"` or `"writable by group or others"`.
fn check_owner_and_mode(metadata: &fs::Metadata, expected_uid: u32) -> Result<(), String> {
    if metadata.uid() != expected_uid {
        return Err(format!("not owned by uid {expected_uid}"));
    }
    // Group (0o020) and other (0o002) write bits.
    if metadata.mode() & 0o022 != 0 {
        return Err("writable by group or others".to_string());
    }
    Ok(())
}

/// A reason of the form `"<path>: <what is wrong>"`.
fn describe(path: &Path, what: &str) -> String {
    format!("{}: {what}", path.to_string_lossy())
}

/// The PIN-only state: the default PIN rules; every context `pin` only with one
/// factor; biometrics off; no rp_class; relying parties `tpm`, `reverify`, one
/// factor (`pin_only_state_requires_tpm_and_reverify`).
fn create_pin_only_state(reason: String) -> PinOnly {
    let mut layer = default_layer();
    for context in layer.context.values_mut() {
        context.methods = vec!["pin".to_string()];
        context.factors = Some(1);
    }
    if let Some(methods) = layer.methods.as_mut() {
        methods.biometrics_allowed = Some(false);
    }
    layer.rp_class.clear();

    PinOnly {
        layer,
        rp_provider: RpProvider::Tpm,
        rp_prompt: RpPrompt::Reverify,
        rp_factors: 1,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::merge::merge;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// A temporary admin directory (mode 0o755) and a user file path outside it,
    /// and the current user's uid, which owns both.
    fn setup() -> (TempDir, PathBuf, PathBuf, u32) {
        let tmp = TempDir::new().unwrap();
        // The parent of the admin directory is checked too; a umask may leave it group-writable.
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let admin_dir = tmp.path().join("admin.d");
        fs::create_dir(&admin_dir).unwrap();
        fs::set_permissions(&admin_dir, fs::Permissions::from_mode(0o755)).unwrap();
        let user_file = tmp.path().join("user.toml");
        let uid = fs::metadata(&admin_dir).unwrap().uid();
        (tmp, admin_dir, user_file, uid)
    }

    fn write(path: &Path, content: &[u8], mode: u32) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn reason(policy: Policy) -> String {
        match policy {
            Policy::PinOnly(pin) => pin.reason,
            Policy::Effective(_) => panic!("expected the PIN-only state"),
        }
    }

    #[test]
    fn missing_files_use_defaults() {
        let (tmp, _, _, uid) = setup();
        let policy = load(
            &tmp.path().join("absent.d"),
            &tmp.path().join("absent.toml"),
            uid,
        );
        assert_eq!(policy, Policy::Effective(merge(&[], None).unwrap()));
    }

    #[test]
    fn readable_files_are_merged() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        write(
            &admin_dir.join("10-site.toml"),
            b"[pin]\nmin_length = 8",
            0o644,
        );
        write(&user_file, b"[pin]\nlockout_attempts = 3", 0o644);
        let Policy::Effective(effective) = load(&admin_dir, &user_file, uid) else {
            panic!("expected an effective policy");
        };
        let pin = effective.layer.pin.unwrap();
        assert_eq!((pin.min_length, pin.lockout_attempts), (Some(8), Some(3)));
    }

    #[test]
    fn unparseable_user_file_leaves_only_pin() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        write(&user_file, b"invalid = toml", 0o644);
        assert!(reason(load(&admin_dir, &user_file, uid)).ends_with("user.toml: does not parse"));
    }

    #[test]
    fn unparseable_admin_file_leaves_only_pin() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        write(&admin_dir.join("10-site.toml"), b"invalid = toml", 0o644);
        assert!(reason(load(&admin_dir, &user_file, uid)).ends_with("10-site.toml: does not parse"));
    }

    #[test]
    fn non_utf8_file_leaves_only_pin() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        write(&admin_dir.join("10-site.toml"), &[0xff, 0xfe], 0o644);
        assert!(reason(load(&admin_dir, &user_file, uid)).ends_with("10-site.toml: is not UTF-8"));
    }

    #[test]
    fn unlistable_admin_dir_leaves_only_pin() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        if uid == 0 {
            eprintln!("skipped: root can list a directory with mode 0o000");
            return;
        }
        fs::set_permissions(&admin_dir, fs::Permissions::from_mode(0o000)).unwrap();
        let policy = load(&admin_dir, &user_file, uid);
        fs::set_permissions(&admin_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(reason(policy).ends_with("admin.d: cannot be listed"));
    }

    #[test]
    fn admin_file_writable_by_others_leaves_only_pin() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        write(
            &admin_dir.join("10-site.toml"),
            b"[pin]\nmin_length = 8",
            0o666,
        );
        assert!(reason(load(&admin_dir, &user_file, uid))
            .ends_with("10-site.toml: writable by group or others"));
    }

    #[test]
    fn admin_dir_writable_by_others_leaves_only_pin() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        fs::set_permissions(&admin_dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(reason(load(&admin_dir, &user_file, uid))
            .ends_with("admin.d: writable by group or others"));
    }

    #[test]
    fn admin_file_with_wrong_owner_leaves_only_pin() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        write(
            &admin_dir.join("10-site.toml"),
            b"[pin]\nmin_length = 8",
            0o644,
        );
        let wrong = uid + 1;
        assert!(reason(load(&admin_dir, &user_file, wrong))
            .ends_with(&format!("admin.d: not owned by uid {wrong}")));
    }

    #[test]
    fn contradictory_merge_leaves_only_pin() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        write(
            &admin_dir.join("10-site.toml"),
            b"[pin]\nmax_length = 8",
            0o644,
        );
        write(&user_file, b"[pin]\nmin_length = 10", 0o644);
        assert_eq!(
            reason(load(&admin_dir, &user_file, uid)),
            "merge: contradiction MaxLengthBelowMinLength"
        );
    }

    #[test]
    fn pin_only_state_requires_tpm_and_reverify() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        write(&user_file, b"invalid = toml", 0o644);
        let Policy::PinOnly(pin) = load(&admin_dir, &user_file, uid) else {
            panic!("expected the PIN-only state");
        };
        assert_eq!(pin.rp_provider, RpProvider::Tpm);
        assert_eq!(pin.rp_prompt, RpPrompt::Reverify);
        assert_eq!(pin.rp_factors, 1);
        assert_eq!(pin.layer.pin, default_layer().pin);
        assert_eq!(
            pin.layer.methods.as_ref().unwrap().biometrics_allowed,
            Some(false)
        );
        assert_eq!(pin.layer.context.len(), 4);
        for ctx in pin.layer.context.values() {
            assert_eq!(ctx.methods, vec!["pin".to_string()]);
            assert_eq!(ctx.factors, Some(1));
        }
        assert!(pin.layer.rp_class.is_empty());
    }

    #[test]
    fn pin_only_reason_names_the_file_not_its_content() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        write(&admin_dir.join("10-site.toml"), b"secret_marker = 1", 0o644);
        let reason = reason(load(&admin_dir, &user_file, uid));
        assert!(reason.contains("10-site.toml"));
        assert!(!reason.contains("secret_marker"));
    }

    #[test]
    fn admin_dir_that_cannot_be_examined_leaves_only_pin() {
        let (tmp, admin_dir, user_file, uid) = setup();
        if uid == 0 {
            eprintln!("skipped: root can look into a directory with mode 0o000");
            return;
        }
        write(
            &admin_dir.join("10-site.toml"),
            b"[methods]\nbiometrics_allowed = false",
            0o644,
        );
        let outside = TempDir::new().unwrap();
        let user_file = outside.path().join(user_file.file_name().unwrap());
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o000)).unwrap();
        let policy = load(&admin_dir, &user_file, uid);
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(reason(policy.clone()).ends_with("admin.d: cannot be examined"));
        assert_eq!(policy.methods_for("login").methods, vec!["pin".to_string()]);
    }

    #[test]
    fn admin_dir_parent_writable_by_others_leaves_only_pin() {
        let (tmp, admin_dir, user_file, uid) = setup();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(reason(load(&admin_dir, &user_file, uid)).ends_with("writable by group or others"));
    }

    #[test]
    fn admin_file_that_is_not_a_regular_file_leaves_only_pin() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        fs::create_dir(admin_dir.join("10-site.toml")).unwrap();
        assert!(reason(load(&admin_dir, &user_file, uid))
            .ends_with("10-site.toml: is not a regular file"));
    }

    #[test]
    fn symlinked_admin_file_leaves_only_pin() {
        let (tmp, admin_dir, user_file, uid) = setup();
        let target = tmp.path().join("elsewhere.toml");
        write(&target, b"[pin]\nmin_length = 8", 0o644);
        std::os::unix::fs::symlink(&target, admin_dir.join("10-site.toml")).unwrap();
        assert!(reason(load(&admin_dir, &user_file, uid))
            .ends_with("10-site.toml: is not a regular file"));
    }

    #[test]
    fn oversized_admin_file_leaves_only_pin() {
        let (_tmp, admin_dir, user_file, uid) = setup();
        let size = usize::try_from(MAX_POLICY_FILE_BYTES).unwrap();
        let mut text = b"[pin]\nmin_length = 8\n#".to_vec();
        text.resize(size, b'a');
        write(&admin_dir.join("10-site.toml"), &text, 0o644);
        assert!(matches!(
            load(&admin_dir, &user_file, uid),
            Policy::Effective(_)
        ));
        text.push(b'a');
        write(&admin_dir.join("10-site.toml"), &text, 0o644);
        assert!(reason(load(&admin_dir, &user_file, uid)).ends_with("10-site.toml: is too large"));
    }
}
