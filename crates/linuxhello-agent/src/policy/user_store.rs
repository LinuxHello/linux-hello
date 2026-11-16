//! The user policy store: stores each user's policy layer in the Agent's state directory.
//! It ensures that a user policy the schema rejects is refused on write and the previous
//! layer stays (`unparseable_user_policy_is_refused_on_write`), a layer that contradicts
//! the layers it is merged with is refused on write
//! (`user_layer_contradicting_defaults_is_refused_on_write`), a layer that would leave a
//! context without enough methods is refused on write
//! (`user_policy_that_makes_a_context_unsatisfiable_is_refused_on_write`), a user policy over 64 KiB
//! is refused on write (`oversized_user_policy_is_refused_on_write`), one user's policy is
//! never visible under another uid (`user_policies_are_kept_apart_by_uid`), a write never
//! leaves a half-written or temporary file, and the files are private to the Agent
//! (`a_write_leaves_no_temporary_file_and_private_modes`), and the user layer is
//! available without a home directory (`user_policy_is_available_without_a_home_directory`).
//! A removal is synced like a write (`removing_a_layer_survives_a_crash`); a directory that cannot
//! be synced after the change is [`StoreError::Unsynced`], not an untouched layer
//! (`failed_directory_sync_is_not_reported_as_an_untouched_layer`); an error of the store is never
//! read as no policy (`store_error_is_not_read_as_an_empty_policy`); a stored file that is too
//! large or not UTF-8 is reported as damaged, and can be replaced
//! (`damaged_layer_is_reported_as_damaged`).

use crate::policy::load::{admin_layers, load, Policy};
use crate::policy::merge::merge;
use crate::policy::schema::{parse_layer, Layer};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The maximum size in bytes for a user policy file.
pub const MAX_POLICY_BYTES: usize = 64 * 1024;

/// A directory that does not exist: a store without an admin layer reads the defaults only.
const NO_ADMIN_DIR: &str = "/nonexistent/linuxhello/policy.d";

/// Errors that can occur when interacting with the user policy store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The text fails the policy schema, contradicts the layers it is merged with, or
    /// would leave a context without enough methods.
    Invalid,
    /// The text is longer than [`MAX_POLICY_BYTES`].
    TooLarge,
    /// The store could not read or write its files; the previous layer is untouched.
    Unavailable,
    /// The new layer is in place and can be read back, but the directory could not be synced to
    /// disk, so it may not survive a crash (`failed_directory_sync_is_not_reported_as_an_untouched_layer`).
    /// A retry would write the same text; the request layer counts it as stored.
    Unsynced,
    /// A layer is stored but cannot be read as one: it is not UTF-8 or it is larger than
    /// [`MAX_POLICY_BYTES`] (`damaged_layer_is_reported_as_damaged`). Storing a new layer replaces it.
    Damaged,
}

/// Makes a change of a directory durable.
type DirSync = Arc<dyn Fn(&Path) -> std::io::Result<()> + Send + Sync>;

/// Syncs the directory to disk.
fn sync_directory(path: &Path) -> std::io::Result<()> {
    fs::File::open(path)?.sync_all()
}

/// Removes what an earlier write left behind: the fixed name an older version used, and the
/// temporary files of processes that no longer exist. A temporary file of a live process is
/// left alone, so two writers never delete each other's work
/// (`a_write_leaves_no_temporary_file_and_private_modes`, `only_dead_writers_leave_stale_files`).
fn remove_stale_temporaries(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let stale = name == "policy.toml.tmp"
            || name
                .strip_prefix("policy.toml.")
                .and_then(|rest| rest.strip_suffix(".tmp"))
                .and_then(|rest| rest.split_once('.'))
                .and_then(|(pid, _)| pid.parse::<u32>().ok())
                .is_some_and(|pid| {
                    pid != std::process::id() && !Path::new(&format!("/proc/{pid}")).exists()
                });
        if stale {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Gives every temporary file its own name, so two writers never share one
/// (`temporary_names_are_never_shared`).
fn temporary_name() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "policy.toml.{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// A store for managing individual user policy layers in the Agent's state directory.
#[derive(Clone)]
pub struct UserPolicyStore {
    /// How a directory is made durable; the real sync, except in tests.
    sync_dir: DirSync,
    /// The root directory where user policy subdirectories are located.
    root: PathBuf,
    /// The admin policy directory and the uid that must own it, when a new layer is
    /// also checked against the admin layers. Without it, only the defaults are used.
    admin: Option<(PathBuf, u32)>,
}

impl std::fmt::Debug for UserPolicyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserPolicyStore")
            .field("root", &self.root)
            .field("admin", &self.admin)
            .finish_non_exhaustive()
    }
}

impl UserPolicyStore {
    /// Creates a new `UserPolicyStore` with the given root directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            sync_dir: Arc::new(sync_directory),
            root: root.into(),
            admin: None,
        }
    }

    /// The same store with another way to sync a directory, for tests that make it fail or count it.
    #[cfg(test)]
    pub(crate) fn with_dir_sync(self, sync_dir: DirSync) -> Self {
        Self { sync_dir, ..self }
    }

    /// The same store, checking every new layer against the admin layers in
    /// `admin_dir` (owned by `admin_owner_uid`) as well as the defaults.
    pub fn with_admin_layer(self, admin_dir: impl Into<PathBuf>, admin_owner_uid: u32) -> Self {
        Self {
            admin: Some((admin_dir.into(), admin_owner_uid)),
            ..self
        }
    }

    /// Checks that `layer` can be merged with the layers in force and locks nobody out.
    ///
    /// The admin layers are the ones on disk now; when they cannot be read or
    /// contradict each other the policy is PIN-only whatever the user stores, and
    /// the layer is checked against the defaults alone. A context that already
    /// lacks methods without the user's layer is not held against it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Invalid`] when the merge is contradictory
    /// (`user_layer_contradicting_defaults_is_refused_on_write`) or when a context
    /// would need more methods than it allows only because of this layer
    /// (`user_policy_that_makes_a_context_unsatisfiable_is_refused_on_write`).
    fn check_merge(&self, layer: &Layer) -> Result<(), StoreError> {
        let mut admin = self
            .admin
            .as_ref()
            .and_then(|(dir, owner)| admin_layers(dir, *owner).ok())
            .unwrap_or_default();
        let without = match merge(&admin, None) {
            Ok(effective) => effective,
            Err(_) => {
                admin.clear();
                merge(&admin, None).map_err(|_| StoreError::Unavailable)?
            }
        };
        let with = merge(&admin, Some(layer)).map_err(|_| StoreError::Invalid)?;
        let contexts: Vec<String> = with.layer.context.keys().cloned().collect();
        let (with, without) = (Policy::Effective(with), Policy::Effective(without));
        for context in contexts {
            if with.methods_for(&context).unsatisfiable
                && !without.methods_for(&context).unsatisfiable
            {
                return Err(StoreError::Invalid);
            }
        }
        Ok(())
    }

    /// The effective policy for `uid`: the admin layers (when the store has them), then the
    /// user's file. It fails closed like [`load`]: a fault gives the PIN-only state.
    pub fn policy_of(&self, uid: u32) -> Policy {
        let (admin_dir, owner) = self.admin.as_ref().map_or_else(
            || (PathBuf::from(NO_ADMIN_DIR), 0),
            |(dir, owner)| (dir.clone(), *owner),
        );
        load(&admin_dir, &self.path(uid), owner)
    }

    /// Returns the path to the policy file for the given `uid`.
    pub fn path(&self, uid: u32) -> PathBuf {
        self.root.join(uid.to_string()).join("policy.toml")
    }

    /// Retrieves the stored policy text for the given `uid`.
    ///
    /// Returns an empty string if no policy is stored: only a file that is not there counts as
    /// none, never a directory or file that cannot be examined
    /// (`store_error_is_not_read_as_an_empty_policy`).
    ///
    /// # Errors
    ///
    /// [`StoreError::Unavailable`] when the file cannot be examined or read;
    /// [`StoreError::Damaged`] when it is larger than [`MAX_POLICY_BYTES`] or not UTF-8
    /// (`damaged_layer_is_reported_as_damaged`).
    pub fn get(&self, uid: u32) -> Result<String, StoreError> {
        let file = match fs::File::open(self.path(uid)) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(String::new()),
            Err(_) => return Err(StoreError::Unavailable),
        };
        let mut bytes = Vec::new();
        let limit = u64::try_from(MAX_POLICY_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        file.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| StoreError::Unavailable)?;
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(StoreError::Damaged);
        }
        String::from_utf8(bytes).map_err(|_| StoreError::Damaged)
    }

    /// Stores the provided text as the policy layer for the given `uid`.
    ///
    /// If the text is empty, the existing policy file is removed. Both the new file and the
    /// removal are made durable by syncing the directory (`removing_a_layer_survives_a_crash`).
    ///
    /// # Errors
    ///
    /// [`StoreError::Invalid`] and [`StoreError::TooLarge`] for a text that is refused, with the
    /// previous layer untouched; [`StoreError::Unavailable`] when a file cannot be written, with
    /// the previous layer untouched; [`StoreError::Unsynced`] when the change is made but the
    /// directory could not be synced, so the new layer is in place.
    pub fn set(&self, uid: u32, text: &str) -> Result<(), StoreError> {
        if text.len() > MAX_POLICY_BYTES {
            return Err(StoreError::TooLarge);
        }

        if !text.is_empty() {
            let layer = parse_layer(text).map_err(|_| StoreError::Invalid)?;
            self.check_merge(&layer)?;
        }

        let user_dir = self.root.join(uid.to_string());
        let policy_path = user_dir.join("policy.toml");
        let tmp_path = user_dir.join(temporary_name());

        // The directory, private to the Agent; an existing one is left as it is.
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(&user_dir)
            .map_err(|_| StoreError::Unavailable)?;
        remove_stale_temporaries(&user_dir);

        if text.is_empty() {
            match fs::remove_file(&policy_path) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
                Err(_) => return Err(StoreError::Unavailable),
            }
            return self.make_durable(&user_dir);
        }

        // Atomic write: create tmp, write, sync, rename, sync dir
        {
            let mut options = std::fs::OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .truncate(true)
                .mode(0o600);

            let mut file = options
                .open(&tmp_path)
                .map_err(|_| StoreError::Unavailable)?;
            let written = file
                .write_all(text.as_bytes())
                .and_then(|()| file.sync_all());
            if written.is_err() {
                let _ = fs::remove_file(&tmp_path);
                return Err(StoreError::Unavailable);
            }
        }

        fs::rename(&tmp_path, &policy_path).map_err(|_| {
            let _ = fs::remove_file(&tmp_path);
            StoreError::Unavailable
        })?;

        self.make_durable(&user_dir)
    }

    /// Syncs `dir` after a change that is already made. A failure is [`StoreError::Unsynced`],
    /// not `Unavailable`: the layer is in place whatever the sync says.
    fn make_durable(&self, dir: &Path) -> Result<(), StoreError> {
        (self.sync_dir)(dir).map_err(|_| StoreError::Unsynced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{load, Policy};
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    const TIGHTER: &str = "[methods]\nbiometrics_allowed = false\n";
    const EXAMPLE: &str = include_str!("../../../../policy/policy.example.toml");

    /// A directory sync that always fails.
    fn failing_sync() -> DirSync {
        Arc::new(|_| Err(std::io::Error::other("the disk is gone")))
    }

    #[test]
    fn failed_directory_sync_is_not_reported_as_an_untouched_layer() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path()).with_dir_sync(failing_sync());
        // The new layer is in place, and the error says so instead of "untouched".
        assert_eq!(store.set(1000, TIGHTER), Err(StoreError::Unsynced));
        assert_eq!(store.get(1000).unwrap(), TIGHTER);
        assert_ne!(StoreError::Unsynced, StoreError::Unavailable);
    }

    #[test]
    fn removing_a_layer_survives_a_crash() {
        let root = tempdir().unwrap();
        let syncs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&syncs);
        let store = UserPolicyStore::new(root.path()).with_dir_sync(Arc::new(move |path| {
            counted.fetch_add(1, Ordering::SeqCst);
            sync_directory(path)
        }));
        store.set(1000, TIGHTER).unwrap();
        assert_eq!(
            syncs.load(Ordering::SeqCst),
            1,
            "a write syncs the directory"
        );
        store.set(1000, "").unwrap();
        assert_eq!(store.get(1000).unwrap(), "");
        assert_eq!(syncs.load(Ordering::SeqCst), 2, "a removal syncs it too");
        // Removing what is not there changes nothing and needs no sync.
        store.set(1000, "").unwrap();
        assert_eq!(syncs.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn store_error_is_not_read_as_an_empty_policy() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, TIGHTER).unwrap();
        let dir = root.path().join("1000");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
        let seen = store.get(1000);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        // A user that can ignore permissions (root) cannot show the failure; the test is for the rest.
        if rustix::process::getuid().as_raw() != 0 {
            assert_eq!(seen, Err(StoreError::Unavailable));
        }
        assert_eq!(store.get(1000).unwrap(), TIGHTER);
    }

    #[test]
    fn damaged_layer_is_reported_as_damaged() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        let path = store.path(1000);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Not UTF-8.
        fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(store.get(1000), Err(StoreError::Damaged));
        // Larger than the limit, and read only up to it.
        fs::write(&path, vec![b'#'; MAX_POLICY_BYTES + 1]).unwrap();
        assert_eq!(store.get(1000), Err(StoreError::Damaged));
        // At the limit it is a layer like any other.
        fs::write(&path, vec![b'#'; MAX_POLICY_BYTES]).unwrap();
        assert_eq!(store.get(1000).unwrap().len(), MAX_POLICY_BYTES);
        // The user can replace a damaged layer.
        fs::write(&path, [0xff]).unwrap();
        assert_eq!(store.set(1000, TIGHTER), Ok(()));
        assert_eq!(store.get(1000).unwrap(), TIGHTER);
    }

    #[test]
    fn only_dead_writers_leave_stale_files() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, TIGHTER).unwrap();
        let dir = store.path(1000).parent().unwrap().to_path_buf();
        // A writer that no longer exists left a file; process 1 is alive and its file stays.
        let dead = dir.join("policy.toml.4294967295.0.tmp");
        let alive = dir.join("policy.toml.1.0.tmp");
        fs::write(&dead, "x").unwrap();
        fs::write(&alive, "x").unwrap();
        store.set(1000, TIGHTER).unwrap();
        assert!(!dead.exists());
        assert!(alive.exists());
        assert_eq!(store.get(1000).unwrap(), TIGHTER);
    }

    #[test]
    fn temporary_names_are_never_shared() {
        let (a, b) = (temporary_name(), temporary_name());
        assert_ne!(a, b);
        for name in [a, b] {
            assert!(name.starts_with("policy.toml.") && name.ends_with(".tmp"));
            assert_ne!(name, "policy.toml");
        }
    }

    #[test]
    fn get_without_a_policy_is_empty() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        assert_eq!(store.get(1000).unwrap(), "");
    }

    #[test]
    fn set_then_get_returns_the_same_text() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, EXAMPLE).unwrap();
        assert_eq!(store.get(1000).unwrap(), EXAMPLE);
    }

    #[test]
    fn set_replaces_the_previous_layer() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, EXAMPLE).unwrap();
        store.set(1000, TIGHTER).unwrap();
        assert_eq!(store.get(1000).unwrap(), TIGHTER);
    }

    #[test]
    fn set_with_an_empty_text_removes_the_layer() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, TIGHTER).unwrap();
        store.set(1000, "").unwrap();
        assert_eq!(store.get(1000).unwrap(), "");
        assert!(!store.path(1000).exists());
        store.set(1000, "").unwrap();
    }

    #[test]
    fn unparseable_user_policy_is_refused_on_write() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, TIGHTER).unwrap();

        assert_eq!(store.set(1000, "invalid = toml"), Err(StoreError::Invalid));
        assert_eq!(
            store.set(1000, "[methods]\nbogus = 1\n"),
            Err(StoreError::Invalid)
        );
        assert_eq!(
            store.set(1000, "[methods]\nbiometrics_allowed = "),
            Err(StoreError::Invalid)
        );

        assert_eq!(store.get(1000).unwrap(), TIGHTER);
    }

    #[test]
    fn oversized_user_policy_is_refused_on_write() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, TIGHTER).unwrap();

        let too_big = format!("# {}\n", "a".repeat(MAX_POLICY_BYTES));
        assert_eq!(store.set(1000, &too_big), Err(StoreError::TooLarge));
        assert_eq!(store.get(1000).unwrap(), TIGHTER);

        // A valid file of exactly the limit: the layer, then a comment padded to the size.
        let padding = MAX_POLICY_BYTES - TIGHTER.len() - "#\n".len();
        let final_text = format!("{TIGHTER}#{}\n", "a".repeat(padding));
        assert_eq!(final_text.len(), MAX_POLICY_BYTES);
        assert_eq!(
            store.set(1000, &format!("{final_text}\n")),
            Err(StoreError::TooLarge),
            "one byte over the limit"
        );
        store.set(1000, &final_text).unwrap();
        assert_eq!(store.get(1000).unwrap().len(), MAX_POLICY_BYTES);
    }

    #[test]
    fn user_policies_are_kept_apart_by_uid() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, EXAMPLE).unwrap();
        store.set(1001, TIGHTER).unwrap();

        assert_eq!(store.get(1000).unwrap(), EXAMPLE);
        assert_eq!(store.get(1001).unwrap(), TIGHTER);
        assert!(store.path(1000) != store.path(1001));
        assert_eq!(store.get(1002).unwrap(), "");
    }

    #[test]
    fn a_write_leaves_no_temporary_file_and_private_modes() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, TIGHTER).unwrap();

        let user_dir = store.path(1000).parent().unwrap().to_path_buf();
        let entries: Vec<_> = fs::read_dir(&user_dir).unwrap().collect();
        assert_eq!(entries.len(), 1);

        let policy_file = store.path(1000);
        let file_perms = fs::metadata(&policy_file).unwrap().permissions();
        assert_eq!(file_perms.mode() & 0o777, 0o600);

        let dir_perms = fs::metadata(&user_dir).unwrap().permissions();
        assert_eq!(dir_perms.mode() & 0o777, 0o700);

        let stale_tmp = user_dir.join("policy.toml.tmp");
        fs::File::create(&stale_tmp).unwrap();
        store.set(1000, TIGHTER).unwrap();
        assert!(!stale_tmp.exists());
    }

    #[test]
    fn stored_user_policy_is_what_the_policy_engine_loads() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, TIGHTER).unwrap();

        let absent = root.path().join("absent.d");
        let policy = load(&absent, &store.path(1000), 0);
        assert!(matches!(policy, Policy::Effective(_)));
        let view = policy.effective();
        let find = |p: &str| view.settings.iter().find(|s| s.path == p);
        assert_eq!(find("methods.biometrics_allowed").unwrap().value, "false");
    }

    #[test]
    fn user_policy_is_available_without_a_home_directory() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, TIGHTER).unwrap();

        assert_eq!(store.get(1000).unwrap(), TIGHTER);

        let absent = root.path().join("absent.d");
        let policy = load(&absent, &store.path(1000), 0);
        assert!(matches!(policy, Policy::Effective(_)));
        let view = policy.effective();
        let find = |p: &str| view.settings.iter().find(|s| s.path == p);
        assert_eq!(find("methods.biometrics_allowed").unwrap().value, "false");

        let expected_path = root.path().join("1000").join("policy.toml");
        assert_eq!(store.path(1000), expected_path);
    }

    /// A store that also checks against an admin directory holding `admin`.
    fn store_with_admin(root: &std::path::Path, admin: &str) -> UserPolicyStore {
        fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
        let admin_dir = root.join("policy.d");
        fs::create_dir(&admin_dir).unwrap();
        fs::set_permissions(&admin_dir, fs::Permissions::from_mode(0o755)).unwrap();
        let file = admin_dir.join("10-site.toml");
        fs::write(&file, admin).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let owner = std::os::unix::fs::MetadataExt::uid(&fs::metadata(&admin_dir).unwrap());
        UserPolicyStore::new(root.join("users")).with_admin_layer(admin_dir, owner)
    }

    #[test]
    fn user_layer_contradicting_defaults_is_refused_on_write() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, TIGHTER).unwrap();
        // Each parses, and each contradicts the defaults when merged.
        for text in [
            "[pin]\ndigits = \"disallowed\"\n",
            "[pin]\nmax_length = 4\n",
        ] {
            assert_eq!(store.set(1000, text), Err(StoreError::Invalid), "{text}");
        }
        assert_eq!(store.get(1000).unwrap(), TIGHTER);
    }

    #[test]
    fn user_layer_contradicting_the_admin_layer_is_refused_on_write() {
        let root = tempdir().unwrap();
        let store = store_with_admin(root.path(), "[pin]\nmax_length = 8\n");
        assert_eq!(
            store.set(1000, "[pin]\nmin_length = 10\n"),
            Err(StoreError::Invalid)
        );
        store.set(1000, "[pin]\nmin_length = 8\n").unwrap();
    }

    #[test]
    fn user_policy_that_makes_a_context_unsatisfiable_is_refused_on_write() {
        let root = tempdir().unwrap();
        let store = UserPolicyStore::new(root.path());
        store.set(1000, TIGHTER).unwrap();
        for text in [
            "[context.login]\nmethods = [\"pin\"]\nfactors = 2\n",
            "[methods]\nbiometrics_allowed = false\n[context.sudo]\nmethods = [\"pin\", \"face\"]\nfactors = 2\n",
        ] {
            assert_eq!(store.set(1000, text), Err(StoreError::Invalid), "{text}");
        }
        assert_eq!(store.get(1000).unwrap(), TIGHTER);
        // Two factors with two methods left is a tightening the user may make.
        store
            .set(
                1000,
                "[context.sudo]\nmethods = [\"pin\", \"fingerprint\"]\nfactors = 2\n",
            )
            .unwrap();
    }

    #[test]
    fn context_the_admin_made_unsatisfiable_is_not_held_against_the_user() {
        let root = tempdir().unwrap();
        let store = store_with_admin(
            root.path(),
            "[context.sudo]\nmethods = [\"pin\"]\nfactors = 2\n",
        );
        store.set(1000, TIGHTER).unwrap();
        assert_eq!(
            store.set(1000, "[context.login]\nmethods = [\"pin\"]\nfactors = 2\n"),
            Err(StoreError::Invalid)
        );
    }

    #[test]
    fn unreadable_admin_layer_does_not_stop_a_valid_user_layer() {
        let root = tempdir().unwrap();
        let store = store_with_admin(root.path(), "not = a policy\n");
        store.set(1000, TIGHTER).unwrap();
        assert_eq!(
            store.set(1000, "[pin]\ndigits = \"disallowed\"\n"),
            Err(StoreError::Invalid)
        );
    }
}
