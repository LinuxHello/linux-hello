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
use linuxhello_dbus::{AuthMethod, EnrolStep, PromptReason, PromptResult};
use zbus::{connection::Builder, Connection, OwnedObjectPath, Proxy};

use crate::orchestrator::{Cancel, Method, MethodEnd};
use crate::state::Outcome;

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

/// The names of the fingers `fprintd` knows, a closed set of ten in the order the settings page
/// lists them (ADR-0027, point 2). Any other name is refused.
pub const FINGERS: [&str; 10] = [
    "left-thumb",
    "left-index-finger",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    "right-thumb",
    "right-index-finger",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
];

/// The name of `fprintd`'s error for a user who has no finger enrolled; `ListEnrolledFingers`
/// answers with it instead of an empty list.
const NO_ENROLLED_PRINTS: &str = "net.reactivated.Fprint.Error.NoEnrolledPrints";

/// Why managing a user's fingers failed: `fprintd` or a reader is not there, or it refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FprintdUnavailable;

/// The Agent's management of a user's enrolled fingers through `fprintd`, for the settings page
/// (`ListFingerprints`, `DeleteFingerprint`, ADR-0027 point 2). It claims the default reader for
/// the user's account name, as the fingerprint method does, and always releases it.
#[derive(Clone, Debug, Default)]
pub struct Fprintd {
    /// The address of the bus to use, or `None` for the system bus; tests give their own.
    address: Option<String>,
}

impl Fprintd {
    /// `fprintd` on the bus at `address`, for tests.
    #[must_use]
    pub fn on_bus(address: impl Into<String>) -> Self {
        Self {
            address: Some(address.into()),
        }
    }

    /// The default reader's device proxy on a new connection.
    async fn device(&self) -> Result<(Connection, OwnedObjectPath), FprintdUnavailable> {
        let builder = match &self.address {
            Some(address) => Builder::address(address.as_str()),
            None => Builder::system(),
        };
        let connection = within(builder.build())
            .await
            .and_then(Result::ok)
            .ok_or(FprintdUnavailable)?;
        let manager = Proxy::new(&connection, FPRINT_NAME, MANAGER_PATH, MANAGER_INTERFACE)
            .await
            .map_err(|_| FprintdUnavailable)?;
        let path: OwnedObjectPath = within(manager.call("GetDefaultDevice", &()))
            .await
            .and_then(Result::ok)
            .ok_or(FprintdUnavailable)?;
        Ok((connection, path))
    }

    /// The fingers `username` has enrolled, in the order of [`FINGERS`]; a name `fprintd` gives
    /// that is not one of them is left out.
    ///
    /// # Errors
    ///
    /// [`FprintdUnavailable`] when `fprintd` or a reader is not there or does not answer in time.
    pub async fn list(&self, username: &str) -> Result<Vec<String>, FprintdUnavailable> {
        let (connection, path) = self.device().await?;
        let device = Proxy::new(&connection, FPRINT_NAME, path, DEVICE_INTERFACE)
            .await
            .map_err(|_| FprintdUnavailable)?;
        let reply: zbus::Result<Vec<String>> =
            within(device.call("ListEnrolledFingers", &(username,)))
                .await
                .ok_or(FprintdUnavailable)?;
        let enrolled = match reply {
            Ok(fingers) => fingers,
            Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == NO_ENROLLED_PRINTS => {
                Vec::new()
            }
            Err(_) => return Err(FprintdUnavailable),
        };
        Ok(FINGERS
            .iter()
            .filter(|finger| enrolled.iter().any(|e| e == *finger))
            .map(|finger| (*finger).to_string())
            .collect())
    }

    /// Deletes `finger` of `username`: claims the reader for the account, deletes, and always
    /// releases it. A finger that is not enrolled is not an error.
    ///
    /// # Errors
    ///
    /// [`FprintdUnavailable`] when `fprintd` or a reader is not there, the reader cannot be
    /// claimed, or `fprintd` refuses the deletion.
    pub async fn delete(&self, username: &str, finger: &str) -> Result<(), FprintdUnavailable> {
        let (connection, path) = self.device().await?;
        let device = Proxy::new(&connection, FPRINT_NAME, path, DEVICE_INTERFACE)
            .await
            .map_err(|_| FprintdUnavailable)?;
        let claimed: Option<zbus::Result<()>> = within(device.call("Claim", &(username,))).await;
        if !matches!(claimed, Some(Ok(()))) {
            return Err(FprintdUnavailable);
        }
        let deleted: Option<zbus::Result<()>> =
            within(device.call("DeleteEnrolledFinger", &(finger,))).await;
        let _ = within(device.call::<_, _, ()>("Release", &())).await;
        match deleted {
            Some(Ok(())) => Ok(()),
            Some(Err(zbus::Error::MethodError(name, _, _)))
                if name.as_str() == NO_ENROLLED_PRINTS =>
            {
                Ok(())
            }
            _ => Err(FprintdUnavailable),
        }
    }
}

/// How long an enrolment may take, from the first touch to the last, before it ends as a timeout.
const ENROL_LIMIT: Duration = Duration::from_secs(120);

impl Fprintd {
    /// Enrols `finger` of `username`: claims the reader for the account, starts `fprintd`'s
    /// enrolment, tells `progress` each step with the touches done so far, and always stops the
    /// enrolment and releases the reader (ADR-0027, points 2 and 4). The caller has checked the
    /// person's PIN before (`enrolment_asks_for_the_pin_first`).
    ///
    /// | `fprintd` says | Here |
    /// | :-- | :-- |
    /// | `enroll-stage-passed` | step `passed`, then `waiting` |
    /// | `enroll-retry-scan`, `enroll-swipe-too-short`, `enroll-finger-not-centered`, `enroll-remove-and-retry` | step `retry`, `too-short`, `not-centred`, `lift` |
    /// | `enroll-completed` | success |
    /// | `enroll-duplicate`, `enroll-data-full`, `enroll-disconnected` | failure, reason `duplicate`, `storage-full`, `device-gone` |
    /// | anything else that ends the enrolment | failure |
    pub async fn enrol(
        &self,
        username: &str,
        finger: &str,
        cancel: &Cancel,
        progress: &mut (dyn FnMut(EnrolStep, u32) + Send),
    ) -> Outcome {
        let fail = |reason| Outcome {
            reason,
            ..Outcome::new(PromptResult::Failure)
        };
        let Ok((connection, path)) = self.device().await else {
            return fail(PromptReason::None);
        };
        let Ok(device) = Proxy::new(&connection, FPRINT_NAME, path, DEVICE_INTERFACE).await else {
            return fail(PromptReason::None);
        };
        let claimed: Option<zbus::Result<()>> = within(device.call("Claim", &(username,))).await;
        if !matches!(claimed, Some(Ok(()))) {
            return fail(PromptReason::None);
        }
        let outcome = Self::run_enrolment(&device, finger, cancel, progress).await;
        let _ = within(device.call::<_, _, ()>("EnrollStop", &())).await;
        let _ = within(device.call::<_, _, ()>("Release", &())).await;
        outcome
    }

    /// Starts the enrolment on the claimed reader and follows `EnrollStatus` to its end.
    async fn run_enrolment(
        device: &Proxy<'_>,
        finger: &str,
        cancel: &Cancel,
        progress: &mut (dyn FnMut(EnrolStep, u32) + Send),
    ) -> Outcome {
        let fail = |reason| Outcome {
            reason,
            ..Outcome::new(PromptResult::Failure)
        };
        let Ok(mut statuses) = device.receive_signal("EnrollStatus").await else {
            return fail(PromptReason::None);
        };
        let started: Option<zbus::Result<()>> =
            within(device.call("EnrollStart", &(finger,))).await;
        if !matches!(started, Some(Ok(()))) {
            return fail(PromptReason::None);
        }
        let end = std::time::Instant::now() + ENROL_LIMIT;
        let mut done = 0_u32;
        progress(EnrolStep::Waiting, done);
        loop {
            if cancel.is_cancelled() {
                return Outcome::new(PromptResult::Cancelled);
            }
            if std::time::Instant::now() >= end {
                return fail(PromptReason::Timeout);
            }
            let next = future::or(async { Some(statuses.next().await) }, async {
                async_io::Timer::after(CANCEL_POLL).await;
                None
            })
            .await;
            let message = match next {
                None => continue,
                Some(None) => return fail(PromptReason::DeviceGone),
                Some(Some(message)) => message,
            };
            let Ok((result, finished)) = message.body().deserialize::<(String, bool)>() else {
                continue;
            };
            match result.as_str() {
                "enroll-completed" => return Outcome::new(PromptResult::Success),
                "enroll-stage-passed" => {
                    done = done.saturating_add(1);
                    progress(EnrolStep::Passed, done);
                    progress(EnrolStep::Waiting, done);
                }
                "enroll-retry-scan" => progress(EnrolStep::Retry, done),
                "enroll-swipe-too-short" => progress(EnrolStep::TooShort, done),
                "enroll-finger-not-centered" => progress(EnrolStep::NotCentred, done),
                "enroll-remove-and-retry" => progress(EnrolStep::Lift, done),
                "enroll-duplicate" => return fail(PromptReason::Duplicate),
                "enroll-data-full" => return fail(PromptReason::StorageFull),
                "enroll-disconnected" => return fail(PromptReason::DeviceGone),
                _ if finished => return fail(PromptReason::None),
                _ => {}
            }
        }
    }
}

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
