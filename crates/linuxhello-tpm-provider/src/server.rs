//! The provider's end: listens on a socket, takes one request per connection from the Agent and
//! only from the Agent, and does it with the TPM.
//!
//! Who may ask is decided by the peer credentials of the connection (`SO_PEERCRED`: the kernel's
//! word), never by the request: only the user id the provider was started for (the Agent's) is
//! served, and every refusal is a closed connection, so a refusal does not say which rule failed.
//! The socket is in a directory only the provider's own user can change, so nobody can replace it.
//!
//! The provider keeps no key: the blobs come with each request and go back with each answer. It
//! keeps the TPM connection and the storage primary.
//!
//! C4 component: `tpmProviderApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::io::{self, ErrorKind};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use crate::keys::{Tpm, TpmError};
use crate::wire::{
    decode_request, encode_limits, encode_response, read_frame, write_frame, Blobs, Request,
    Response, STATUS_FAILED, STATUS_LOCKED, STATUS_OK, STATUS_WRONG,
};

/// How long a client may take to send its request: a slow or silent one is dropped.
const CLIENT_LIMIT: Duration = Duration::from_secs(2);

/// The provider's socket and the TPM behind it.
pub struct Server {
    /// The listening socket.
    listener: UnixListener,
    /// The TPM.
    tpm: Tpm,
    /// The only user id that is served.
    agent_uid: u32,
}

impl Server {
    /// Binds the socket at `path`, to serve the user `agent_uid` with `tpm`. The socket belongs to
    /// the group `agent_gid` (the Agent's) and is open to that group and its owner only (mode 0660),
    /// so that the kernel refuses every other user at the door, before the peer credentials are asked.
    /// The provider must be a member of that group. The directory that
    /// holds it must be owned by `owner_uid` and writable by nobody else; a stale socket of an
    /// earlier run is removed, and anything else at `path` is refused.
    ///
    /// # Errors
    ///
    /// An error when the directory is not safe, `path` holds something that is not a socket, or
    /// binding fails.
    pub fn bind(
        path: &Path,
        owner_uid: u32,
        agent_uid: u32,
        agent_gid: u32,
        tpm: Tpm,
    ) -> io::Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "no directory"))?;
        let dir = std::fs::symlink_metadata(parent)?;
        if !dir.is_dir() || dir.uid() != owner_uid || dir.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "the directory of the provider's socket is not private to the provider",
            ));
        }
        match std::fs::symlink_metadata(path) {
            Ok(old) if old.file_type().is_socket() && old.uid() == owner_uid => {
                std::fs::remove_file(path)?;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    "something that is not the provider's socket is in the way",
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(path)?;
        // The Agent's group and nobody else may connect; and of those only the Agent's user is
        // served, by the peer credentials.
        std::os::unix::fs::chown(path, None, Some(agent_gid))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(Self {
            listener,
            tpm,
            agent_uid,
        })
    }

    /// Takes one connection and handles it. A refused client is not an error.
    ///
    /// # Errors
    ///
    /// An error of accepting the connection.
    pub fn serve_one(&mut self) -> io::Result<()> {
        let (stream, _) = self.listener.accept()?;
        self.handle(stream);
        Ok(())
    }

    /// Serves until the process ends; an error of accepting is waited out for 100 ms.
    pub fn serve_forever(mut self) {
        loop {
            if self.serve_one().is_err() {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// Handles one connection: the user, the request, the TPM, the answer.
    fn handle(&mut self, mut stream: UnixStream) {
        let Some(uid) = peer_uid(&stream) else { return };
        if uid != self.agent_uid
            || stream.set_read_timeout(Some(CLIENT_LIMIT)).is_err()
            || stream.set_write_timeout(Some(CLIENT_LIMIT)).is_err()
        {
            return;
        }
        let Ok(Some(body)) = read_frame(&mut stream) else {
            return;
        };
        let Some(request) = decode_request(&body) else {
            return;
        };
        if matches!(request, Request::Limits) {
            let body = match self.tpm.limits() {
                Ok(limits) => encode_limits(&limits),
                Err(TpmError::Locked) => vec![STATUS_LOCKED],
                Err(TpmError::Failed(text)) => {
                    eprintln!("linuxhello-tpm-provider: the TPM refused a request: {text}");
                    vec![STATUS_FAILED]
                }
            };
            let _ = write_frame(&mut stream, &body);
            return;
        }
        let answer = self.answer(request);
        if let Some(body) = encode_response(&answer) {
            let _ = write_frame(&mut stream, &body);
        }
    }

    /// What the TPM says to a request.
    fn answer(&mut self, request: Request) -> Response {
        let outcome = match request {
            Request::Limits => Err(TpmError::Failed("limits are answered elsewhere".into())),
            Request::Loads { blobs } => self
                .tpm
                .root_key_loads(&blobs)
                .map(|loads| (if loads { STATUS_OK } else { STATUS_WRONG }, None::<Blobs>)),
            Request::Enrol { auth } => self.tpm.enrol(&auth).map(Some).map(|b| (STATUS_OK, b)),
            Request::Verify { blobs, auth } => self
                .tpm
                .verify(&blobs, &auth)
                .map(|right| (if right { STATUS_OK } else { STATUS_WRONG }, None::<Blobs>)),
            Request::ChangeAuth { blobs, old, new } => self
                .tpm
                .change_auth(&blobs, &old, &new)
                .map(|b| (STATUS_OK, Some(b))),
        };
        match outcome {
            Ok((status, blobs)) => Response { status, blobs },
            Err(TpmError::Locked) => Response {
                status: STATUS_LOCKED,
                blobs: None,
            },
            Err(TpmError::Failed(text)) => {
                // The text is the TPM stack's own and carries no PIN; the client only learns "failed".
                eprintln!("linuxhello-tpm-provider: the TPM refused a request: {text}");
                Response {
                    status: STATUS_FAILED,
                    blobs: None,
                }
            }
        }
    }
}

/// The user id and the group id of the account `name` in the text of `/etc/passwd`; `None` for a
/// name that has no line.
pub fn ids_of(name: &str, passwd: &str) -> Option<(u32, u32)> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let account = fields.next()?;
        let _password = fields.next()?;
        let uid: u32 = fields.next()?.parse().ok()?;
        let gid: u32 = fields.next()?.parse().ok()?;
        (account == name).then_some((uid, gid))
    })
}

/// The user id of the process at the other end of `stream`, as the kernel reports it.
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    Some(
        rustix::net::sockopt::socket_peercred(stream)
            .ok()?
            .uid
            .as_raw(),
    )
}

#[cfg(test)]
mod tests {
    use super::ids_of;

    #[test]
    fn an_account_is_found_by_name_in_the_passwd_text() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nlinuxhello:x:988:987:Agent:/var/lib/linuxhello:/usr/sbin/nologin\n# n\nbroken\n";
        assert_eq!(ids_of("linuxhello", passwd), Some((988, 987)));
        assert_eq!(ids_of("root", passwd), Some((0, 0)));
        assert_eq!(
            ids_of("linuxhell", passwd),
            None,
            "a prefix is not the name"
        );
        assert_eq!(ids_of("nobody", passwd), None);
        assert_eq!(ids_of("linuxhello", ""), None);
        assert_eq!(ids_of("linuxhello", "linuxhello:x:988\n"), None, "no group");
    }
}
