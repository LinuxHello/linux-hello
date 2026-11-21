//! What `status` and `doctor` ask of the machine, behind a trait so that a test replaces it. Every
//! question goes to a service over the system bus or reads a file; nothing starts a program
//! (ADR-0026, `the_cli_starts_no_program`). The probes only read; `Host` has no way to write.
//!
//! C4 component: `cliCommands` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use linuxhello_dbus::{AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};
use zbus::Connection;

use crate::ask::Reported;

/// The longest a service may take to answer one question.
const ANSWER_WAIT: Duration = Duration::from_secs(5);

/// systemd's bus name, its manager object and the manager's interface.
const SYSTEMD: (&str, &str, &str) = (
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
);

/// fprintd's bus name, its manager object and the manager's interface.
const FPRINTD: (&str, &str, &str) = (
    "net.reactivated.Fprint",
    "/net/reactivated/Fprint/Manager",
    "net.reactivated.Fprint.Manager",
);

/// The machine as `status` and `doctor` see it.
pub trait Host {
    /// The caller's conditions from the Agent's `GetStatus`. `None` when the Agent cannot be asked
    /// or its answer is not a list of three strings.
    fn agent_status(&self) -> Option<Vec<Reported>>;
    /// Whether systemd reports the unit `unit` as active. `None` when systemd cannot be asked.
    fn unit_active(&self, unit: &str) -> Option<bool>;
    /// Whether fprintd has a fingerprint reader: `Some(false)` when it says it has none or is not
    /// installed, `None` when the bus cannot be asked.
    fn fingerprint_reader(&self) -> Option<bool>;
    /// Reads a file as text. `None` when it cannot be read.
    fn read(&self, path: &Path) -> Option<String>;
}

/// The real machine: one connection to the system bus, made at the first question.
#[derive(Default)]
pub struct RealHost {
    /// The connection, or `None` when the bus could not be reached.
    bus: OnceLock<Option<Connection>>,
}

impl RealHost {
    /// The connection to the system bus, connecting once.
    fn bus(&self) -> Option<&Connection> {
        self.bus
            .get_or_init(|| {
                futures_lite::future::block_on(async {
                    zbus::connection::Builder::system()
                        .method_timeout(ANSWER_WAIT)
                        .build()
                        .await
                        .ok()
                })
            })
            .as_ref()
    }

    /// Calls `member` of `service` (bus name, object, interface) with `body`; `None` when the bus
    /// cannot be reached.
    fn call<B>(
        &self,
        service: (&str, &str, &str),
        member: &str,
        body: &B,
    ) -> Option<Result<zbus::Message, zbus::Error>>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        let bus = self.bus()?;
        let (name, path, interface) = service;
        Some(futures_lite::future::block_on(bus.call_method(
            Some(name),
            path,
            Some(interface),
            member,
            body,
        )))
    }
}

impl Host for RealHost {
    fn agent_status(&self) -> Option<Vec<Reported>> {
        let reply = self
            .call(
                (AGENT_BUS_NAME, AGENT_OBJECT_PATH, AGENT_INTERFACE),
                "GetStatus",
                &(),
            )?
            .ok()?;
        let items: Vec<(String, String, String)> = reply.body().deserialize().ok()?;
        Some(
            items
                .into_iter()
                .map(|(code, severity, sentence)| Reported {
                    code,
                    severity,
                    sentence,
                })
                .collect(),
        )
    }

    fn unit_active(&self, unit: &str) -> Option<bool> {
        let unit_path: zbus::OwnedObjectPath = match self.call(SYSTEMD, "GetUnit", &(unit,))? {
            Ok(reply) => reply.body().deserialize().ok()?,
            // A unit systemd has not loaded is not active.
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
            {
                return Some(false)
            }
            Err(_) => return None,
        };
        let reply = self
            .call(
                (
                    SYSTEMD.0,
                    unit_path.as_str(),
                    "org.freedesktop.DBus.Properties",
                ),
                "Get",
                &("org.freedesktop.systemd1.Unit", "ActiveState"),
            )?
            .ok()?;
        let state: zbus::OwnedVariant = reply.body().deserialize().ok()?;
        let state = String::try_from(state).ok()?;
        Some(state == "active")
    }

    fn fingerprint_reader(&self) -> Option<bool> {
        match self.call(FPRINTD, "GetDefaultDevice", &())? {
            Ok(_) => Some(true),
            // No device, or no fprintd on the bus: no reader to use.
            Err(zbus::Error::MethodError(..)) => Some(false),
            Err(_) => None,
        }
    }

    fn read(&self, path: &Path) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }
}

#[cfg(test)]
mod tests;
