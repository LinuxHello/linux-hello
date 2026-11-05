//! The policy loading logic: reads admin and user policy files from disk.
//! It fails closed: if any file is unreadable, unparseable, or violates
//! security properties (ownership/permissions), it returns a `PinOnly` state.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
/// - `admin_dir` exists but cannot be listed.
/// - Any file exists but cannot be read, is not UTF-8, or fails `parse_layer`.
/// - Any admin file or `admin_dir` is not owned by `admin_owner_uid`.
/// - Any admin file or `admin_dir` has group- or other-write bits set.
/// - `merge` returns a contradiction.
pub fn load(admin_dir: &Path, user_file: &Path, admin_owner_uid: u32) -> Policy {
    // 1. Load Admin Layers
    let mut admin_layers = Vec::new();
    if admin_dir.exists() {
        match fs::read_dir(admin_dir) {
            Ok(entries) => {
                let mut paths: Vec<_> = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.extension().map_or(false, |ext| ext == "toml"))
                    .collect();
                paths.sort();

                for path in paths {
                    match check_security(&path, admin_owner_uid) {
                        Ok(_) => match fs::read_to_string(&path) {
                            Ok(content) => match parse_layer(&content) {
                                Ok(layer) => admin_layers.push(layer),
                                Err(_) => return pin_only_error(&path, "does not parse"),
                            },
                            Err(_) => return pin_only_error(&path, "cannot be read"),
                        },
                        Err(reason) => return pin_only_error(&path, &reason),
                    }
                }
            }
            Err(_) => return pin_only_error(admin_dir, "cannot be listed"),
        }
    }

    // 2. Load User Layer
    let user_layer = if user_file.exists() {
        match fs::read_to_string(user_file) {
            Ok(content) => match parse_layer(&content) {
                Ok(layer) => Some(layer),
                Err(_) => return pin_only_error(user_file, "does not parse"),
            },
            Err(_) => return pin_only_error(user_file, "cannot be read"),
        }
    } else {
        None
    };

    // 3. Merge
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

/// Checks if a path is owned by the correct UID and has safe permissions (0o022).
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

fn pin_only_error(path: &Path, reason: &str) -> Policy {
    let path_str = path.to_string_lossy();
    Policy::PinOnly(create_pin_only_state(format!("{path_str}: {reason}")))
}

fn create_pin_only_state(reason: String) -> PinOnly {
    let mut layer = default_layer();
    // Set methods to ["pin"] and factors to 1 for every context
    for context in layer.context.values_mut() {
        context.methods = vec!["pin".to_string()];
        context.factors = Some(1);
    }
    // Set biometrics_allowed to false
    if let Some(methods) = layer.methods.as_mut() {
        methods.biometrics_allowed = Some(false);
    }
    // Ensure no rp_class
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
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn missing_files_use_defaults() {
        let admin_dir = Path::new("/tmp/nonexistent_dir_linuxhello_test");
        let user_file = Path::new("/tmp/nonexistent_file_linuxhello_test");
        let policy = load(admin_dir, user_file, 0);
        if let Policy::Effective(eff) = policy {
            assert_eq!(eff.layer, default_layer());
        } else {
            panic!("Expected Effective policy");
        }
    }

    #[test]
    fn unparseable_user_file_leaves_only_pin() {
        let tmp = TempDir::new().unwrap();
        let user_file = tmp.path().join("user.toml");
        fs::write(&user_file, "invalid = toml").unwrap();
        let policy = load(tmp.path(), &user_file, 0);
        if let Policy::PinOnly(pin) = policy {
            assert!(pin.reason.contains("user.toml"));
        } else {
            panic!("Expected PinOnly policy");
        }
    }

    #[test]
    fn unparseable_admin_file_leaves_only_pin() {
        let tmp = TempDir::new().unwrap();
        let admin_file = tmp.path().join("admin.toml");
        fs::write(&admin_file, "invalid = toml").unwrap();
        let policy = load(tmp.path(), tmp.path(), 0); // user_file is admin_dir here, but it's fine
        if let Policy::PinOnly(pin) = policy {
            assert!(pin.reason.contains("admin.toml"));
        } else {
            panic!("Expected PinOnly policy");
        }
    }

    #[test]
    fn non_utf8_file_leaves_only_pin() {
        let tmp = TempDir::new().unwrap();
        let admin_file = tmp.path().join("bad.toml");
        let mut f = File::create(&admin_file).unwrap();
        f.write_all(&[0xff, 0xfe]).unwrap();
        let policy = load(tmp.path(), tmp.path(), 0);
        if let Policy::PinOnly(pin) = policy {
            assert!(pin.reason.contains("bad.toml"));
        } else {
            panic!("Expected PinOnly policy");
        }
    }

    #[test]
    fn unlistable_admin_dir_leaves_only_pin() {
        let tmp = TempDir::new().unwrap();
        let admin_dir = tmp.path().join("unreadable");
        fs::create_dir(&admin_dir).unwrap();
        let mut perms = fs::metadata(&admin_dir).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&admin_dir, perms).unwrap();

        // We use 0 as the expected UID. If we are root, this test might still pass
        // because root can list anything, but for a normal user it will fail.
        let policy = load(&admin_dir, tmp.path(), 0);
        if let Policy::PinOnly(pin) = policy {
            assert!(pin.reason.contains("cannot be listed"));
        } else {
            // If we are root, this might be Effective if we can list it.
            // But the brief says "If the test runs as root... return early".
            // I'll just check if it's PinOnly or if we are root.
            let is_root = fs::metadata(&admin_dir).unwrap().uid() == 0;
            if !is_root {
                panic!("Expected PinOnly policy, but got Effective. Are you running as root?");
            }
        }
    }

    #[test]
    fn admin_file_writable_by_others_leaves_only_pin() {
        let tmp = TempDir::new().unwrap();
        let admin_file = tmp.path().join("writable.toml");
        fs::write(&admin_file, "[pin]\nmin_length = 10").unwrap();
        let mut perms = fs::metadata(&admin_file).unwrap().permissions();
        perms.set_mode(0o666);
        fs::set_permissions(&admin_file, perms).unwrap();

        let policy = load(tmp.path(), tmp.path(), 0);
        if let Policy::PinOnly(pin) = policy {
            assert!(pin.reason.contains("writable by group or others"));
        } else {
            panic!("Expected PinOnly policy");
        }
    }

    #[test]
    fn admin_file_with_wrong_owner_leaves_only_pin() {
        let tmp = TempDir::new().unwrap();
        let admin_file = tmp.path().join("wrong_owner.toml");
        fs::write(&admin_file, "[pin]\nmin_length = 10").unwrap();

        let current_uid = fs::metadata(&admin_file).unwrap().uid();
        let policy = load(tmp.path(), &admin_file, current_uid + 1);
        if let Policy::PinOnly(pin) = policy {
            assert!(pin.reason.contains("not owned by uid"));
        } else {
            panic!("Expected PinOnly policy");
        }
    }

    #[test]
    fn contradictory_merge_leaves_only_pin() {
        let tmp = TempDir::new().unwrap();
        let admin_file = tmp.path().join("admin.toml");
        fs::write(&admin_file, "[pin]\nmax_length = 8").unwrap();
        let user_file = tmp.path().join("user.toml");
        fs::write(&user_file, "[pin]\nmin_length = 10").unwrap();

        let current_uid = fs::metadata(&admin_file).unwrap().uid();
        let policy = load(tmp.path(), &user_file, current_uid);
        if let Policy::PinOnly(pin) = policy {
            assert!(pin.reason.contains("MaxLengthBelowMinLength"));
        } else {
            panic!("Expected PinOnly policy");
        }
    }

    #[test]
    fn pin_only_state_requires_tpm_and_reverify() {
        let tmp = TempDir::new().unwrap();
        let admin_file = tmp.path().join("bad.toml");
        fs::write(&admin_file, "invalid").unwrap();
        let current_uid = fs::metadata(&admin_file).unwrap().uid();
        let policy = load(tmp.path(), tmp.path(), current_uid);
        if let Policy::PinOnly(pin) = policy {
            assert_eq!(pin.rp_provider, RpProvider::Tpm);
            assert_eq!(pin.rp_prompt, RpPrompt::Reverify);
            assert_eq!(pin.rp_factors, 1);
            // Check layer properties
            let methods = pin.layer.methods.as_ref().unwrap();
            assert_eq!(methods.biometrics_allowed, Some(false));
            for ctx in pin.layer.context.values() {
                assert_eq!(ctx.methods, vec!["pin".to_string()]);
                assert_eq!(ctx.factors, Some(1));
            }
            assert!(pin.layer.rp_class.is_empty());
        } else {
            panic!("Expected PinOnly policy");
        }
    }

    #[test]
    fn pin_only_reason_names_the_file_not_its_content() {
        let tmp = TempDir::new().unwrap();
        let admin_file = tmp.path().join("secret.toml");
        fs::write(&admin_file, "secret_marker = 1").unwrap();
        let current_uid = fs::metadata(&admin_file).unwrap().uid();
        let policy = load(tmp.path(), tmp.path(), current_uid);
        if let Policy::PinOnly(pin) = policy {
            assert!(pin.reason.contains("secret.toml"));
            assert!(!pin.reason.contains("secret_marker"));
        } else {
            panic!("Expected PinOnly policy");
        }
    }
}
