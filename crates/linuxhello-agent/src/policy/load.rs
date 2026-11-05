//! Reading the policy files from disk: every `*.toml` in the admin directory and
//! the user's file, merged by `merge`. It fails closed: an admin directory or
//! file that is not owned by the admin owner or is writable by group or others,
//! a directory that cannot be listed, a file that cannot be read, is not UTF-8 or
//! does not parse, and a contradictory merge all give the PIN-only state
//! (policy-semantics.md, *Fail closed*; invariant 3).

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::policy::defaults::default_layer;
use crate::policy::merge::merge;
use crate::policy::restrict::Contradiction;
use crate::policy::schema::{parse_layer, Layer};
use crate::policy::schema::{RpPrompt, RpProvider};

/// The result of a policy load attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// Every layer read and merged without contradiction.
    Effective(crate::policy::merge::Effective),
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
/// If `admin_dir` or `user_file` is missing, they contribute nothing.
///
/// Returns `PinOnly` if:
/// - `admin_dir` or any admin file is not owned by `admin_owner_uid`, or has the
///   group- or other-write bit set (`admin_dir_writable_by_others_leaves_only_pin`).
/// - `admin_dir` exists but cannot be listed, entry by entry included
///   (`unlistable_admin_dir_leaves_only_pin`).
/// - Any file exists but cannot be read, is not UTF-8, or fails `parse_layer`.
/// - `merge` returns a contradiction.
///
/// The reason names the path and what is wrong, never the file's content
/// (`pin_only_reason_names_the_file_not_its_content`).
pub fn load(admin_dir: &Path, user_file: &Path, admin_owner_uid: u32) -> Policy {
    let mut admin_layers = Vec::new();
    if admin_dir.exists() {
        if let Err(reason) = check_security(admin_dir, admin_owner_uid) {
            return pin_only_error(admin_dir, &reason);
        }
        let Ok(entries) = fs::read_dir(admin_dir) else {
            return pin_only_error(admin_dir, "cannot be listed");
        };
        let mut paths = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else {
                return pin_only_error(admin_dir, "cannot be listed");
            };
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                paths.push(path);
            }
        }
        paths.sort();

        for path in paths {
            if let Err(reason) = check_security(&path, admin_owner_uid) {
                return pin_only_error(&path, &reason);
            }
            match read_layer(&path) {
                Ok(layer) => admin_layers.push(layer),
                Err(reason) => return pin_only_error(&path, reason),
            }
        }
    }

    let user_layer = if user_file.exists() {
        match read_layer(user_file) {
            Ok(layer) => Some(layer),
            Err(reason) => return pin_only_error(user_file, reason),
        }
    } else {
        None
    };

    match merge(&admin_layers, user_layer.as_ref()) {
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

/// Reads one policy file and parses it as a layer.
///
/// # Errors
///
/// What is wrong, without the file's content: `"cannot be read"`,
/// `"is not UTF-8"` or `"does not parse"` (never `parse_layer`'s message, which
/// quotes the file).
fn read_layer(path: &Path) -> Result<Layer, &'static str> {
    let bytes = fs::read(path).map_err(|_| "cannot be read")?;
    let text = String::from_utf8(bytes).map_err(|_| "is not UTF-8")?;
    parse_layer(&text).map_err(|_| "does not parse")
}

/// Checks that `path` is owned by `expected_uid` and has neither the group- nor
/// the other-write bit (`0o022`) set.
///
/// # Errors
///
/// `"cannot access metadata"`, `"not owned by uid <n>"` or
/// `"writable by group or others"`.
fn check_security(path: &Path, expected_uid: u32) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|_| "cannot access metadata".to_string())?;
    if metadata.uid() != expected_uid {
        return Err(format!("not owned by uid {expected_uid}"));
    }
    let mode = metadata.mode();
    // Check group (0o020) and other (0o002) write bits
    if mode & 0o022 != 0 {
        return Err("writable by group or others".to_string());
    }
    Ok(())
}

/// The PIN-only policy, with a reason of the form `"<path>: <what is wrong>"`.
fn pin_only_error(path: &Path, reason: &str) -> Policy {
    let path_str = path.to_string_lossy();
    Policy::PinOnly(create_pin_only_state(format!("{path_str}: {reason}")))
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
}
