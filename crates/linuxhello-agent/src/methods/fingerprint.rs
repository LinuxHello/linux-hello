//! The fingerprint method: the Agent as a client of `fprintd`, the fingerprint service of the
//! desktop (ADR-0023, amendment 2026-11-19, second part).
//!
//! In plain words: to check a finger, the Agent asks `fprintd` for the fingerprint reader, claims
//! it for the user who is signing in, starts a scan, and listens for what `fprintd` says. A match is
//! a success; "does not match" is a failure; "try again" results keep the scan going; a reader that
//! goes away or breaks means the method is unavailable. When the orchestrator says stop, the Agent
//! stops the scan and gives the reader back.
//!
//! The results of `fprintd`'s `VerifyStatus` signal are mapped like this:
//!
//! | Result | Meaning here |
//! | :-- | :-- |
//! | `verify-match` | success |
//! | `verify-no-match` | failure, reason `not-recognised` |
//! | `verify-retry-scan`, `verify-swipe-too-short`, `verify-finger-not-centered`, `verify-remove-and-retry` | the scan goes on |
//! | `verify-disconnected`, `verify-unknown-error`, anything else that ends the scan | unavailable |
//!
//! The Agent claims the reader for the *subject* of the prompt, not for itself; `fprintd` only
//! allows that to a caller that polkit has allowed (`security/polkit/`). The method needs the
//! subject's account name, which the caller reads from `/etc/passwd`
//! ([`super::username_of`]); a user known only to a name service has no fingerprint method.
//!
//! Every wait has a limit: a call that `fprintd` does not answer within five seconds is a method
//! that is unavailable, and the scan is checked for a cancel every 100 milliseconds.
//!
//! C4 component: `methodOrch` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::future::Future;
use std::time::Duration;

use futures_lite::future;
use futures_lite::StreamExt;
use linuxhello_dbus::{AuthMethod, PromptReason};
use zbus::{connection::Builder, Connection, OwnedObjectPath, Proxy};

use crate::orchestrator::{Cancel, Method, MethodEnd};

/// The bus name of `fprintd`.
const FPRINT_NAME: &str = "net.reactivated.Fprint";

/// The object of `fprintd`'s manager.
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";

/// The interface of `fprintd`'s manager.
const MANAGER_INTERFACE: &str = "net.reactivated.Fprint.Manager";

/// The interface of a fingerprint reader.
const DEVICE_INTERFACE: &str = "net.reactivated.Fprint.Device";

/// How long a call to `fprintd` may take before the method gives up.
const CALL_LIMIT: Duration = Duration::from_secs(5);

/// How often a running scan looks at the cancel flag.
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// The fingerprint method for one user.
pub struct FingerprintMethod {
    /// The name of the account that signs in; the reader is claimed for it.
    username: String,
    /// The address of the bus to use, or `None` for the system bus; tests give their own.
    address: Option<String>,
}

impl FingerprintMethod {
    /// The method for the account `username` on the system bus.
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            address: None,
        }
    }

    /// The same method on the bus at `address`, for tests.
    #[must_use]
    pub fn on_bus(self, address: impl Into<String>) -> Self {
        Self {
            address: Some(address.into()),
            ..self
        }
    }

    /// Connects to the bus.
    async fn connect(&self) -> Option<Connection> {
        let builder = match &self.address {
            Some(address) => Builder::address(address.as_str()),
            None => Builder::system(),
        };
        within(builder.build()).await?.ok()
    }

    /// The default reader of `fprintd` that has a fingerprint of the user enrolled; `None` when
    /// `fprintd` is not there, has no reader, or the user has no finger enrolled.
    async fn reader(&self, connection: &Connection) -> Option<OwnedObjectPath> {
        let manager = Proxy::new(connection, FPRINT_NAME, MANAGER_PATH, MANAGER_INTERFACE)
            .await
            .ok()?;
        let path: OwnedObjectPath = within(manager.call("GetDefaultDevice", &())).await?.ok()?;
        let device = Proxy::new(connection, FPRINT_NAME, path.clone(), DEVICE_INTERFACE)
            .await
            .ok()?;
        let fingers: Vec<String> =
            within(device.call("ListEnrolledFingers", &(self.username.as_str(),)))
                .await?
                .ok()?;
        (!fingers.is_empty()).then_some(path)
    }

    /// Claims the reader, scans, and always stops the scan and releases the reader.
    async fn verify(&self, cancel: &Cancel) -> MethodEnd {
        let Some(connection) = self.connect().await else {
            return MethodEnd::Unavailable;
        };
        let Some(path) = self.reader(&connection).await else {
            return MethodEnd::Unavailable;
        };
        let Ok(device) = Proxy::new(&connection, FPRINT_NAME, path, DEVICE_INTERFACE).await else {
            return MethodEnd::Unavailable;
        };
        let claimed: Option<zbus::Result<()>> =
            within(device.call("Claim", &(self.username.as_str(),))).await;
        if !matches!(claimed, Some(Ok(()))) {
            return MethodEnd::Unavailable;
        }
        let (end, scanning) = self.scan(&device, cancel).await;
        if scanning {
            let _ = within(device.call::<_, _, ()>("VerifyStop", &())).await;
        }
        let _ = within(device.call::<_, _, ()>("Release", &())).await;
        end
    }

    /// Starts a scan on the claimed reader and waits for its end. Returns how it ended and whether
    /// `fprintd` still has a scan running (it has not after a result that ends it).
    async fn scan(&self, device: &Proxy<'_>, cancel: &Cancel) -> (MethodEnd, bool) {
        let Ok(mut statuses) = device.receive_signal("VerifyStatus").await else {
            return (MethodEnd::Unavailable, false);
        };
        let started: Option<zbus::Result<()>> = within(device.call("VerifyStart", &("any",))).await;
        if !matches!(started, Some(Ok(()))) {
            return (MethodEnd::Unavailable, false);
        }
        loop {
            if cancel.is_cancelled() {
                return (MethodEnd::Cancelled, true);
            }
            let next = future::or(async { Some(statuses.next().await) }, async {
                async_io::Timer::after(CANCEL_POLL).await;
                None
            })
            .await;
            let message = match next {
                None => continue,
                Some(None) => return (MethodEnd::Unavailable, true),
                Some(Some(message)) => message,
            };
            let Ok((result, done)) = message.body().deserialize::<(String, bool)>() else {
                continue;
            };
            match result.as_str() {
                "verify-match" => return (MethodEnd::Success, false),
                "verify-no-match" => {
                    return (MethodEnd::Failure(PromptReason::NotRecognised), false)
                }
                "verify-retry-scan"
                | "verify-swipe-too-short"
                | "verify-finger-not-centered"
                | "verify-remove-and-retry" => {}
                _ if done => return (MethodEnd::Unavailable, false),
                _ => {}
            }
        }
    }
}

impl Method for FingerprintMethod {
    fn kind(&self) -> AuthMethod {
        AuthMethod::Fingerprint
    }

    fn available(&self) -> bool {
        future::block_on(async {
            match self.connect().await {
                Some(connection) => self.reader(&connection).await.is_some(),
                None => false,
            }
        })
    }

    fn run(&mut self, cancel: &Cancel) -> MethodEnd {
        future::block_on(self.verify(cancel))
    }
}

/// The result of `future`, or `None` when it takes longer than [`CALL_LIMIT`].
async fn within<T>(future: impl Future<Output = T>) -> Option<T> {
    future::or(async { Some(future.await) }, async {
        async_io::Timer::after(CALL_LIMIT).await;
        None
    })
    .await
}
