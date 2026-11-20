//! The Linux Hello Agent as a library: the logic the `linuxhello-agent` daemon runs,
//! kept in a library so that tests and fuzz targets can reach it.
//!
//! C4 container: `agent` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

pub mod api;
pub mod audit;
pub mod bus;
pub mod methods;
pub mod notify;
pub mod orchestrator;
pub mod pinkdf;
pub mod pinlock;
pub mod pinrecord;
pub mod pinsocket;
pub mod policy;
pub mod state;

/// A temporary directory that only its owner can use, whatever the umask of the shell that runs the
/// tests: the code under test refuses a directory that others can write, and a developer's default
/// umask (0002 on Ubuntu) would make every such test fail for a reason that says nothing about the
/// code.
#[cfg(test)]
pub(crate) fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("a temporary directory")
}

/// Makes `path` and its missing parents with mode 0700, whatever the umask, for the same reason as
/// [`private_tempdir`].
#[cfg(test)]
pub(crate) fn private_dirs(path: &std::path::Path) {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .expect("a directory");
}

/// Writes an admin policy file the way an administrator's tool would, mode 0644 whatever the umask:
/// the policy loader refuses an admin file that others can write.
#[cfg(test)]
pub(crate) fn write_admin_file(
    path: impl AsRef<std::path::Path>,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path.as_ref(), contents)?;
    std::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(0o644))
}
