//! Whether a caller is at this machine, asked of logind: the Agent's own check that a `sudo` or
//! `session` caller sits in a session with a seat, not remote, and in front, before it starts the
//! camera or the fingerprint reader (ADR-0023, amendment of 2026-11-23; review finding R-04, #347).
//!
//! In plain words: logind is the systemd service that keeps one record per login session, with its
//! seat (the set of screen, keyboard and sensors that belong together) and whether the session came
//! in over the network. The PAM module already looks at that record for itself, but it runs inside
//! the caller's process. The Agent asks logind about the process id the bus daemon names, which the
//! caller cannot forge, and offers the PIN only when the answer is anything but "a seat at this
//! machine". It uses the system bus, never `/proc` or logind's files: the Agent's unit hides other
//! users' processes (`ProtectProc=invisible`) and its profile does not allow those files.
//!
//! The question is asked on the job's own thread and has a limit, so a slow or silent logind never
//! holds up a bus handler or another caller (finding R-20). Every answer that is not a clear "local"
//! is a refusal of the sensors, and a missing logind is one too ([fail closed]).
//!
//! C4 component: `dbusApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))
//!
//! [fail closed]: https://github.com/LinuxHello/linux-hello-architecture/blob/main/arc42/12-glossary.md#fail-closed

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

use zbus::Connection;
use zbus::{OwnedObjectPath, OwnedVariant};

use crate::audit::SensorsRefusal;

/// How long logind has to answer before the answer is "unknown": the limit of the amendment.
pub const ASK_LIMIT: Duration = Duration::from_millis(500);

/// The contexts in which the caller must be at this machine for a sensor to start. The login screen
/// has no session of the person yet, and the lock screen is left for later (the amendment's "Not
/// decided").
pub const NEEDS_LOCAL_SEAT: [&str; 2] = ["sudo", "session"];

/// Whether a prompt of `context` needs the caller to be at this machine.
pub fn needs_local_seat(context: &str) -> bool {
    NEEDS_LOCAL_SEAT.contains(&context)
}

/// Where the caller is, as far as logind says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locality {
    /// In a session with a seat, not remote, in front.
    Local,
    /// In a remote session.
    Remote,
    /// In a session without a seat, or in no session at all.
    NoSeat,
    /// In a session that is not the one in front.
    Inactive,
    /// logind did not say: not there, too slow, or not understood.
    Unknown,
}

impl Locality {
    /// Why the sensors are refused, `None` for [`Locality::Local`].
    pub fn refusal(self) -> Option<SensorsRefusal> {
        match self {
            Self::Local => None,
            Self::Remote => Some(SensorsRefusal::Remote),
            Self::NoSeat => Some(SensorsRefusal::NoSeat),
            Self::Inactive => Some(SensorsRefusal::Inactive),
            Self::Unknown => Some(SensorsRefusal::Unknown),
        }
    }
}

/// The verdict for a session's three facts, the first reason that applies: remote, then no seat, then
/// not in front (`a_session_is_local_only_when_it_has_a_seat_is_not_remote_and_is_in_front`).
pub fn judge(remote: bool, seat: &str, active: bool) -> Locality {
    if remote {
        Locality::Remote
    } else if seat.is_empty() {
        Locality::NoSeat
    } else if !active {
        Locality::Inactive
    } else {
        Locality::Local
    }
}

/// Something that says where the process `pid` is.
pub trait SessionProbe: Send + Sync {
    /// The locality of the process; [`Locality::Unknown`] when it cannot be told.
    fn locality(&self, pid: u32) -> Locality;
}

/// The probe that asks logind over the system bus.
pub struct LogindProbe {
    /// The bus to ask on: the system bus, or another address in a test.
    address: Option<String>,
    /// How long logind has to answer.
    limit: Duration,
}

impl LogindProbe {
    /// The probe of the Agent: the system bus and the limit of [`ASK_LIMIT`].
    pub fn system() -> Self {
        Self {
            address: None,
            limit: ASK_LIMIT,
        }
    }

    /// A probe that asks on the bus at `address`, with its own `limit`, for a test with a fake logind.
    pub fn at(address: &str, limit: Duration) -> Self {
        Self {
            address: Some(address.to_string()),
            limit,
        }
    }
}

impl SessionProbe for LogindProbe {
    fn locality(&self, pid: u32) -> Locality {
        let address = self.address.clone();
        // The question runs on a thread of its own so that the limit holds even when logind never
        // answers; such a thread is left to end by itself.
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(futures_lite::future::block_on(ask(address, pid)));
        });
        receiver
            .recv_timeout(self.limit)
            .unwrap_or(Locality::Unknown)
    }
}

/// The name logind owns on the system bus.
const LOGIND: &str = "org.freedesktop.login1";

/// Asks logind for the session of `pid` and its three facts.
async fn ask(address: Option<String>, pid: u32) -> Locality {
    let connection = match address {
        Some(address) => {
            zbus::connection::Builder::address(address.as_str())
                .build()
                .await
        }
        None => Connection::system().await,
    };
    let Ok(connection) = connection else {
        return Locality::Unknown;
    };
    let session = match connection
        .call_method(
            Some(LOGIND),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "GetSessionByPID",
            &(pid,),
        )
        .await
    {
        Ok(reply) => match reply.body().deserialize::<OwnedObjectPath>() {
            Ok(path) => path,
            Err(_) => return Locality::Unknown,
        },
        // A process that is in no session is not at a seat of this machine.
        Err(zbus::Error::MethodError(name, _, _))
            if name.as_str() == "org.freedesktop.login1.NoSessionForPID" =>
        {
            return Locality::NoSeat
        }
        Err(_) => return Locality::Unknown,
    };
    let Ok(reply) = connection
        .call_method(
            Some(LOGIND),
            session.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "GetAll",
            &("org.freedesktop.login1.Session",),
        )
        .await
    else {
        return Locality::Unknown;
    };
    let Ok(properties) = reply.body().deserialize::<HashMap<String, OwnedVariant>>() else {
        return Locality::Unknown;
    };
    match facts_of(&properties) {
        Some((remote, seat, active)) => judge(remote, &seat, active),
        None => Locality::Unknown,
    }
}

/// `Remote`, the id of `Seat` and `Active` from the properties of a session, `None` when one is
/// missing or has another type (`a_session_without_the_three_facts_is_unknown`).
fn facts_of(properties: &HashMap<String, OwnedVariant>) -> Option<(bool, String, bool)> {
    let remote = bool::try_from(properties.get("Remote")?).ok()?;
    let active = bool::try_from(properties.get("Active")?).ok()?;
    let (seat, _path): (String, OwnedObjectPath) =
        properties.get("Seat")?.try_clone().ok()?.try_into().ok()?;
    Some((remote, seat, active))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_sudo_and_session_need_a_seat() {
        assert!(needs_local_seat("sudo") && needs_local_seat("session"));
        assert!(!needs_local_seat("login") && !needs_local_seat("unlock"));
        assert!(!needs_local_seat("") && !needs_local_seat("Sudo"));
    }

    #[test]
    fn a_session_without_the_three_facts_is_unknown() {
        assert_eq!(facts_of(&HashMap::new()), None);
        let mut properties = HashMap::new();
        properties.insert("Remote".to_string(), OwnedVariant::from(false));
        assert_eq!(facts_of(&properties), None, "Active and Seat are missing");
    }

    #[test]
    fn every_verdict_but_local_is_a_refusal_with_its_word() {
        assert_eq!(Locality::Local.refusal(), None);
        for locality in [
            Locality::Remote,
            Locality::NoSeat,
            Locality::Inactive,
            Locality::Unknown,
        ] {
            assert!(locality.refusal().is_some(), "{locality:?}");
        }
    }
}
