//! Setting and changing the caller's PIN through the Agent: `linuxhello-ctl pin set` and
//! `linuxhello-ctl pin change` (ADR-0021, amendment 2026-11-20).
//!
//! A person who has never used PINs may read this as: the command asks for the PIN, then talks to
//! the Agent in the steps the Agent requires. It opens a *prompt* (the Agent's word for one
//! attempt), starts the job, and for each PIN first says over the bus "a PIN is coming" and then
//! sends it on a private socket, because a PIN must never be a bus message. It then waits for the
//! prompt's outcome. The prompt belongs to the bus connection that opened it, so every step uses
//! one connection; that is why this does not run `busctl` as the status command does.
//!
//! The PINs are read without echo from the terminal and wiped after use. Typing the new PIN twice
//! and comparing the two is done here, before anything is sent.
//!
//! C4 component: `cliAgentClient` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use futures_lite::StreamExt;
use linuxhello_dbus::{PromptId, AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};
use zbus::message::Type;
use zbus::{Connection, MatchRule, MessageStream};
use zeroize::Zeroizing;

/// How long to wait for the outcome after the last PIN was sent. A change stretches two PINs and
/// asks the TPM, which takes well under a second; a lockout reply is as quick.
const OUTCOME_WAIT: Duration = Duration::from_secs(20);

/// The reply byte of the PIN socket for an accepted PIN (`REPLY_ACCEPTED` of the Agent).
const REPLY_ACCEPTED: u8 = 0;

/// Where the PINs come from: the terminal in production, a script in a test.
pub trait Pins {
    /// One PIN, asked with `label` and read without echo; `None` when none can be read.
    fn read(&mut self, label: &str) -> Option<Zeroizing<Vec<u8>>>;
}

/// Reads PINs from the terminal without echo.
pub struct Terminal;

impl Pins for Terminal {
    fn read(&mut self, label: &str) -> Option<Zeroizing<Vec<u8>>> {
        use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions};
        let stdin = std::io::stdin();
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "{label}: ");
        let _ = stderr.flush();
        // Without echo while the PIN is typed; the old setting is put back whatever happens.
        let saved = tcgetattr(&stdin).ok();
        if let Some(saved) = &saved {
            let mut quiet = saved.clone();
            quiet.local_modes.remove(LocalModes::ECHO);
            let _ = tcsetattr(&stdin, OptionalActions::Now, &quiet);
        }
        let mut line = Zeroizing::new(String::new());
        let read = std::io::stdin().read_line(&mut line);
        if let Some(saved) = &saved {
            let _ = tcsetattr(&stdin, OptionalActions::Now, saved);
            let _ = writeln!(stderr);
        }
        read.ok()?;
        let text = line.trim_end_matches(['\n', '\r']);
        Some(Zeroizing::new(text.as_bytes().to_vec()))
    }
}

/// What the person is told when the job ends, and the exit code: 0 done, 1 failed.
fn describe(result: &str, reason: &str, seconds: u32) -> (String, u8) {
    match (result, reason) {
        ("success", _) => ("Done.".to_string(), 0),
        ("locked-out", _) => (
            format!(
                "Too many wrong PINs. Try again in {} minutes.",
                seconds.div_ceil(60).max(1)
            ),
            1,
        ),
        ("failure", "not-recognised") => ("The current PIN is wrong.".to_string(), 1),
        ("failure", "timeout") => ("No PIN arrived in time.".to_string(), 1),
        _ => (
            "The PIN was not accepted. It may be too short or too long (see the PIN rules), \
             or the TPM did not answer."
                .to_string(),
            1,
        ),
    }
}

/// Sends one PIN on the socket and says whether the Agent accepted it.
fn send_pin(socket: &Path, pin: &[u8]) -> Result<bool, String> {
    let length = u16::try_from(pin.len()).map_err(|_| "The PIN is too long.".to_string())?;
    let mut stream = UnixStream::connect(socket)
        .map_err(|_| "The Agent's PIN socket is not available.".to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let mut frame = Zeroizing::new(length.to_be_bytes().to_vec());
    frame.extend_from_slice(pin);
    stream
        .write_all(&frame)
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|_| "The PIN could not be sent.".to_string())?;
    let mut reply = [1_u8; 1];
    stream
        .read_exact(&mut reply)
        .map_err(|_| "The Agent did not answer.".to_string())?;
    Ok(reply[0] == REPLY_ACCEPTED)
}

/// One call of the Agent on `connection`.
async fn call<B>(connection: &Connection, member: &str, body: &B) -> Result<zbus::Message, String>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    connection
        .call_method(
            Some(AGENT_BUS_NAME),
            AGENT_OBJECT_PATH,
            Some(AGENT_INTERFACE),
            member,
            body,
        )
        .await
        .map_err(|e| match e {
            zbus::Error::MethodError(name, _, _) => format!("The Agent refused ({name})."),
            other => format!("The Agent did not answer: {other}."),
        })
}

/// Sets (`change` false) or changes (`change` true) the PIN of the user `uid` through the Agent on
/// `connection`, with the PINs from `pins` sent on `socket`. Writes what happened to `out` and
/// returns the exit code.
pub fn run(
    connection: &Connection,
    socket: &Path,
    uid: u32,
    change: bool,
    pins: &mut dyn Pins,
    out: &mut dyn Write,
) -> u8 {
    // The PINs are read first, so that a typing mistake costs no prompt and no wrong-PIN count.
    let current = if change {
        let Some(pin) = pins.read("Current PIN") else {
            let _ = writeln!(out, "No PIN was read.");
            return 1;
        };
        Some(pin)
    } else {
        None
    };
    let Some(new) = pins.read("New PIN") else {
        let _ = writeln!(out, "No PIN was read.");
        return 1;
    };
    let Some(again) = pins.read("New PIN again") else {
        let _ = writeln!(out, "No PIN was read.");
        return 1;
    };
    if *new != *again {
        let _ = writeln!(
            out,
            "The two new PINs are not the same. Nothing was changed."
        );
        return 1;
    }
    match futures_lite::future::block_on(flow(connection, socket, uid, change, current, new)) {
        Ok((result, reason, seconds)) => {
            let (text, code) = describe(&result, &reason, seconds);
            let _ = writeln!(out, "{text}");
            code
        }
        Err(text) => {
            let _ = writeln!(out, "{text}");
            1
        }
    }
}

/// The steps with the Agent; returns the prompt's `(result, reason, seconds)`.
async fn flow(
    connection: &Connection,
    socket: &Path,
    uid: u32,
    change: bool,
    current: Option<Zeroizing<Vec<u8>>>,
    new: Zeroizing<Vec<u8>>,
) -> Result<(String, String, u32), String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let session = format!("{}-{nanos}", std::process::id());
    let prompt = PromptId::derive("linuxhello-ctl", "pin", &session);
    let id = prompt.as_str();

    // Listen before anything starts, so that the outcome cannot be missed.
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .interface(AGENT_INTERFACE)
        .member("Result")
        .build()
        .map_err(|e| format!("Cannot listen to the Agent: {e}."))?;
    let mut heard = MessageStream::for_match_rule(rule, connection, None)
        .await
        .map_err(|e| format!("Cannot listen to the Agent: {e}."))?;

    call(connection, "OpenPrompt", &(id, i64::from(uid))).await?;
    let outcome = async {
        call(connection, "Subscribe", &(id,)).await?;
        call(
            connection,
            if change { "ChangePin" } else { "SetPin" },
            &(id,),
        )
        .await?;
        let mut to_send = Vec::new();
        to_send.extend(current);
        to_send.push(new);
        for pin in &to_send {
            call(connection, "ExpectPin", &(id,)).await?;
            if !send_pin(socket, pin)? {
                return Err("The Agent did not accept the PIN.".to_string());
            }
        }
        let waiting = async {
            while let Some(Ok(message)) = heard.next().await {
                if let Ok((prompt, result, reason, seconds)) =
                    message
                        .body()
                        .deserialize::<(String, String, String, u32)>()
                {
                    if prompt == id {
                        return Some((result, reason, seconds));
                    }
                }
            }
            None
        };
        let timeout = async {
            async_io::Timer::after(OUTCOME_WAIT).await;
            None
        };
        futures_lite::future::or(waiting, timeout)
            .await
            .ok_or_else(|| "The Agent gave no answer in time.".to_string())
    }
    .await;
    let _ = call(connection, "ClosePrompt", &(id,)).await;
    outcome
}

#[cfg(test)]
mod tests;
