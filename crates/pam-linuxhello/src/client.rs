//! The Agent client: one authentication from start to PAM code (ADR-0023, decisions 1 to 3 and the
//! amendments of 2026-11-19 and 2026-11-21).
//!
//! In plain words: when `sudo` or a login screen asks "is this the user?", this module opens a
//! *prompt* (the Agent's word for one attempt) for the user, asks the Agent to start the methods the
//! policy allows (fingerprint, face, PIN), and waits for the Agent's answer. When the PIN is one of
//! the methods it asks the person for the PIN through the PAM conversation (the question the
//! program running PAM shows), and sends the PIN to the Agent on the Agent's PIN socket, never on
//! the bus. When the person uses the sensor or the camera instead, they press Enter on an empty
//! PIN and the module waits for that method. The answer becomes a PAM code.
//!
//! Fail closed for login, as ADR-0023 decision 2 defines it: whenever Linux Hello cannot give a
//! clear answer (the bus or the Agent is not there or hangs, the context is not named, the person
//! gives no answer in time) the module returns *unavailable*, so the PAM stack goes on to the
//! account password. It never returns success for that case (`pam_never_succeeds_when_agent_is_unreachable`,
//! property P-20). Every step has a deadline (`pam_returns_within_its_deadline_when_the_agent_hangs`).
//!
//! Only safe code is here; the PAM entry points that call it are in the crate's `entry` module.
//!
//! C4 component: `agentClient` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

mod bus;
pub mod wire;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use linuxhello_dbus::{PromptId, AGENT_BUS_NAME, AGENT_INTERFACE, AGENT_OBJECT_PATH};
use zeroize::Zeroizing;

use bus::{Bus, BusError};
use wire::{Arg, Value};

/// The system bus socket. Never taken from the environment: `sudo` runs PAM with the invoking
/// user's environment, and a bus of the user's own could answer "success".
pub const SYSTEM_BUS: &str = "/run/dbus/system_bus_socket";

/// The Agent's PIN socket (`PIN_SOCKET` in the Agent's `main.rs`, ADR-0021).
pub const PIN_SOCKET: &str = "/run/linuxhello/pin.sock";

/// The reply byte of the PIN socket for an accepted PIN (`REPLY_ACCEPTED` of the Agent).
const REPLY_ACCEPTED: u8 = 0;

/// The line shown when Linux Hello cannot answer because the bus or the Agent failed, so that the
/// person knows the account password comes next (`an_unreachable_agent_is_announced`).
pub const UNAVAILABLE_LINE: &str = "Linux Hello is not available. Use your account password.";

/// The contexts a module argument may name (the policy schema's contexts, ADR-0023 amendment of
/// 2026-11-19, point 3).
pub const CONTEXTS: [&str; 4] = ["login", "unlock", "sudo", "session"];

/// What the module answers PAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// The user is authenticated (`PAM_SUCCESS`).
    Success,
    /// The user was not authenticated: a wrong PIN, a finger or face that did not match, a lockout
    /// (`PAM_AUTH_ERR`).
    Denied,
    /// Linux Hello could not answer; the stack goes on to the password (`PAM_AUTHINFO_UNAVAIL`).
    Unavailable,
    /// No such user (`PAM_USER_UNKNOWN`).
    UserUnknown,
}

/// The deadlines of one authentication (ADR-0023, amendment of 2026-11-21, point 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// To connect to the bus and finish `Hello`.
    pub connect: Duration,
    /// For each method call, and for the Agent's first report of the methods.
    pub call: Duration,
    /// For the answer after the PIN was sent or an empty answer was given.
    pub wait: Duration,
    /// For the whole authentication, whatever the person does.
    pub total: Duration,
}

impl Limits {
    /// The limits of ADR-0023: 250 ms, 2 s, 30 s, 120 s.
    pub const DEFAULT: Self = Self {
        connect: Duration::from_millis(250),
        call: Duration::from_secs(2),
        wait: Duration::from_secs(30),
        total: Duration::from_secs(120),
    };
}

/// The PAM conversation: how the module asks the person and tells them things.
pub trait Conversation {
    /// Asks `question` without echo; `None` when the application gives no answer (it was
    /// cancelled, or it cannot ask).
    fn secret(&mut self, question: &str) -> Option<Zeroizing<String>>;
    /// Shows `text` as information.
    fn info(&mut self, text: &str);
    /// Shows `text` as an error.
    fn error(&mut self, text: &str);
}

/// One authentication's inputs, as the PAM entry point read them.
pub struct Request<'a> {
    /// The value of the `context=` module argument, if there was one.
    pub context: Option<&'a str>,
    /// The PAM service (`sudo`, `sddm`, ...), for the prompt id.
    pub service: &'a str,
    /// The terminal or display, for the prompt id.
    pub terminal: &'a str,
    /// The machine the person signs in from (`PAM_RHOST`); empty for a session at this machine.
    pub remote_host: &'a str,
    /// The user being authenticated; `None` when the name is not a user.
    pub uid: Option<u32>,
}

/// Why a step failed: there is no clear answer, so the module answers unavailable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault;

impl From<BusError> for Fault {
    fn from(_: BusError) -> Self {
        Self
    }
}

/// What the Agent said about the prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// The methods running now (`ActiveMethods`).
    Active(Vec<String>),
    /// The outcome (`Result`): result, reason, seconds until another try.
    Result(String, String, u32),
    /// The prompt was closed (`Closed`).
    Closed,
}

/// The Agent as the flow uses it, so that the flow can be tested without a bus.
pub trait Agent {
    /// Calls `member` of the Agent's interface with `args`.
    ///
    /// # Errors
    ///
    /// [`Fault`] when the call fails or is refused.
    fn call(&mut self, member: &str, args: &[Arg<'_>]) -> Result<(), Fault>;
    /// The next signal about `prompt`; `None` when none came before `deadline`.
    ///
    /// # Errors
    ///
    /// [`Fault`] when the connection fails.
    fn signal(&mut self, prompt: &str, deadline: Instant) -> Result<Option<Signal>, Fault>;
    /// The conditions of the prompt's user that may be shown at the prompt in `context`, each as
    /// code, severity and sentence (`GetPromptStatus`, ADR-0024 amendment of 2026-11-21).
    ///
    /// # Errors
    ///
    /// [`Fault`] when the call fails, is refused or the reply has another shape.
    fn conditions(
        &mut self,
        prompt: &str,
        context: &str,
    ) -> Result<Vec<(String, String, String)>, Fault>;
}

/// The PIN socket as the flow uses it.
pub trait PinPost {
    /// Sends `pin`; whether the Agent accepted it for checking (not whether it is right).
    ///
    /// # Errors
    ///
    /// [`Fault`] when it cannot be sent.
    fn send(&mut self, pin: &[u8]) -> Result<bool, Fault>;
}

/// The Agent on the system bus.
struct BusAgent {
    /// The connection.
    bus: Bus,
    /// The unique name of the connection that owns the Agent's name; signals from anyone else are
    /// ignored.
    owner: String,
    /// The deadline of each call.
    call_limit: Duration,
}

impl BusAgent {
    /// Connects to the bus at `path` and finds the Agent's connection.
    fn connect(path: &Path, limits: &Limits) -> Result<Self, Fault> {
        let mut bus = Bus::connect(path, limits.connect)?;
        let reply = bus.call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetNameOwner",
            &[Arg::Str(AGENT_BUS_NAME)],
            Instant::now() + limits.call,
        )?;
        let Some(Value::Str(owner)) = reply.into_iter().next() else {
            return Err(Fault);
        };
        // From here on only the Agent's own signals are read at all (R-03, #346).
        bus.trust_signals_from(owner.clone());
        Ok(Self {
            bus,
            owner,
            call_limit: limits.call,
        })
    }
}

impl Agent for BusAgent {
    fn call(&mut self, member: &str, args: &[Arg<'_>]) -> Result<(), Fault> {
        self.bus.call(
            AGENT_BUS_NAME,
            AGENT_OBJECT_PATH,
            AGENT_INTERFACE,
            member,
            args,
            Instant::now() + self.call_limit,
        )?;
        Ok(())
    }

    fn conditions(
        &mut self,
        prompt: &str,
        context: &str,
    ) -> Result<Vec<(String, String, String)>, Fault> {
        let body = self.bus.call(
            AGENT_BUS_NAME,
            AGENT_OBJECT_PATH,
            AGENT_INTERFACE,
            "GetPromptStatus",
            &[Arg::Str(prompt), Arg::Str(context)],
            Instant::now() + self.call_limit,
        )?;
        match <[Value; 1]>::try_from(body) {
            Ok([Value::Triples(items)]) => Ok(items),
            _ => Err(Fault),
        }
    }

    fn signal(&mut self, prompt: &str, deadline: Instant) -> Result<Option<Signal>, Fault> {
        loop {
            let Some(message) = self.bus.next_signal(deadline)? else {
                return Ok(None);
            };
            if message.sender.as_deref() != Some(self.owner.as_str())
                || message.interface.as_deref() != Some(AGENT_INTERFACE)
            {
                continue;
            }
            if let Some(signal) = read_signal(message.member.as_deref(), &message.body, prompt) {
                return Ok(Some(signal));
            }
        }
    }
}

/// The signal of `member` with `body`, when it is about `prompt` and has the expected shape.
fn read_signal(member: Option<&str>, body: &[Value], prompt: &str) -> Option<Signal> {
    match (member?, body) {
        ("ActiveMethods", [Value::Str(id), Value::Strs(methods)]) if id == prompt => {
            Some(Signal::Active(methods.clone()))
        }
        ("Result", [Value::Str(id), Value::Str(result), Value::Str(reason), Value::U32(secs)])
            if id == prompt =>
        {
            Some(Signal::Result(result.clone(), reason.clone(), *secs))
        }
        ("Closed", [Value::Str(id)]) if id == prompt => Some(Signal::Closed),
        _ => None,
    }
}

/// The Agent's PIN socket at a path.
struct SocketPin<'a>(&'a Path);

impl PinPost for SocketPin<'_> {
    fn send(&mut self, pin: &[u8]) -> Result<bool, Fault> {
        let length = u16::try_from(pin.len()).map_err(|_| Fault)?;
        let mut stream = UnixStream::connect(self.0).map_err(|_| Fault)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| Fault)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| Fault)?;
        let mut frame = Zeroizing::new(length.to_be_bytes().to_vec());
        frame.extend_from_slice(pin);
        stream.write_all(&frame).map_err(|_| Fault)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| Fault)?;
        let mut reply = [1_u8; 1];
        stream.read_exact(&mut reply).map_err(|_| Fault)?;
        Ok(reply[0] == REPLY_ACCEPTED)
    }
}

/// Whether `host`, the `PAM_RHOST` of a session, names this machine: nothing, or the loopback
/// address, as `sudo` and a display manager at this machine leave it. Anything else is a person at
/// another machine, for whom no sensor or camera here may answer (review finding R-04, #347).
pub fn is_local_host(host: &str) -> bool {
    matches!(host, "" | "localhost" | "127.0.0.1" | "::1")
}

/// Where the kernel names the logind session of this process (the audit session id), and where
/// systemd-logind keeps one small file per session, readable by everyone.
const SESSION_ID_FILE: &str = "/proc/self/sessionid";
/// The directory of those files.
const SESSIONS_DIR: &str = "/run/systemd/sessions";

/// The contexts in which the person may be anywhere: `sudo` runs inside whatever session the
/// program was started from, an SSH session included. At the login and lock screens the person is
/// at the machine by the nature of the service.
const NEEDS_LOCAL_SEAT: [&str; 2] = ["sudo", "session"];

/// Whether the process `session_id_file` belongs to is in a logind session that is at this machine:
/// a session of a seat, which is not remote, and in front. A session of nobody (a process outside
/// logind), a missing file and anything unreadable are "no": the answer is never a guess. The
/// facts are logind's, set by the service that made the session (sshd marks its sessions remote
/// through `PAM_RHOST`), and not by anything a program in the session can change, unlike its
/// environment (R-04, #347, `a_session_is_at_this_machine_only_when_logind_says_so`).
pub fn session_at_this_machine(session_id_file: &Path, sessions_dir: &Path) -> bool {
    let Ok(id) = std::fs::read_to_string(session_id_file) else {
        return false;
    };
    let id = id.trim();
    // 4294967295 is "no session".
    if id.is_empty() || id == "4294967295" || !id.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(sessions_dir.join(id)) else {
        return false;
    };
    let value = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
    };
    value("REMOTE") == Some("0")
        && value("ACTIVE") == Some("1")
        && value("SEAT").is_some_and(|seat| !seat.is_empty())
}

/// Authenticates `request` against the Agent on the system bus, asking through `conversation`.
/// For `sudo` and `session` the process must be in a logind session at this machine
/// ([`session_at_this_machine`]); otherwise nothing is asked of the Agent and the answer is
/// "unavailable", so that a shell reached over SSH asks for the password.
pub fn authenticate(request: &Request<'_>, conversation: &mut dyn Conversation) -> Code {
    if request
        .context
        .is_some_and(|context| NEEDS_LOCAL_SEAT.contains(&context))
        && !session_at_this_machine(Path::new(SESSION_ID_FILE), Path::new(SESSIONS_DIR))
    {
        return Code::Unavailable;
    }
    authenticate_at(
        Path::new(SYSTEM_BUS),
        Path::new(PIN_SOCKET),
        &Limits::DEFAULT,
        request,
        conversation,
    )
}

/// [`authenticate`] with the bus, the PIN socket and the limits given, for tests.
pub fn authenticate_at(
    bus: &Path,
    pin_socket: &Path,
    limits: &Limits,
    request: &Request<'_>,
    conversation: &mut dyn Conversation,
) -> Code {
    let start = Instant::now();
    let Some(context) = request.context.filter(|c| CONTEXTS.contains(c)) else {
        return Code::Unavailable;
    };
    // A name that is no user is "unavailable", not "unknown": `PAM_USER_UNKNOWN` ends the stack under
    // `default=die` without a password prompt, which would tell an observer at the console which
    // names exist; "unavailable" lets `pam_unix` ask for a password for every name alike (#359).
    let Some(uid) = request.uid else {
        return Code::Unavailable;
    };
    // A person at another machine (sudo inside an SSH session) is not at the sensor or the camera
    // here: the fingerprint of whoever sits at this machine must not answer for them. Nothing is
    // asked of the Agent, and the stack goes on to the password (`a_remote_session_never_reaches_the_agent`).
    if !is_local_host(request.remote_host) {
        return Code::Unavailable;
    }
    let Ok(mut agent) = BusAgent::connect(bus, limits) else {
        conversation.info(UNAVAILABLE_LINE);
        return Code::Unavailable;
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let session = format!("{}-{nanos}", std::process::id());
    let prompt = PromptId::derive(request.service, request.terminal, &session);
    run(
        &mut agent,
        &mut SocketPin(pin_socket),
        conversation,
        prompt.as_str(),
        uid,
        context,
        limits,
        start,
    )
}

/// The flow on an `agent`: open the prompt, start, ask, wait, close. The prompt is always closed
/// once it was opened (`the_prompt_is_always_closed`). When a call to the Agent or the bus fails
/// the person is told that Linux Hello is not available (`an_unreachable_agent_is_announced`);
/// an answer of *unavailable* the person chose (an empty PIN) or a timeout is not announced.
#[allow(clippy::too_many_arguments)]
pub fn run(
    agent: &mut dyn Agent,
    pins: &mut dyn PinPost,
    conversation: &mut dyn Conversation,
    prompt: &str,
    uid: u32,
    context: &str,
    limits: &Limits,
    start: Instant,
) -> Code {
    if agent
        .call("OpenPrompt", &[Arg::Str(prompt), Arg::I64(i64::from(uid))])
        .is_err()
    {
        conversation.info(UNAVAILABLE_LINE);
        return Code::Unavailable;
    }
    let mut told = Vec::new();
    tell(agent, conversation, prompt, context, &mut told);
    let code =
        steps(agent, pins, conversation, prompt, context, limits, start).unwrap_or_else(|Fault| {
            conversation.info(UNAVAILABLE_LINE);
            Code::Unavailable
        });
    if code == Code::Success {
        tell(agent, conversation, prompt, context, &mut told);
    }
    let _ = agent.call("ClosePrompt", &[Arg::Str(prompt)]);
    code
}

/// The most conditions shown at one prompt; the Agent's closed set of codes is smaller.
const MAX_CONDITIONS: usize = 8;

/// Shows the Agent's conditions for the prompt's user as PAM messages, an error for `severe` and
/// a text otherwise, each code once (`told` holds those already shown). A call that fails is
/// ignored: the status never changes the answer and never asks anything
/// (`the_conditions_are_shown_as_pam_messages`, `a_failed_status_call_changes_nothing`).
fn tell(
    agent: &mut dyn Agent,
    conversation: &mut dyn Conversation,
    prompt: &str,
    context: &str,
    told: &mut Vec<String>,
) {
    let Ok(conditions) = agent.conditions(prompt, context) else {
        return;
    };
    for (code, severity, sentence) in conditions {
        if told.len() >= MAX_CONDITIONS {
            return;
        }
        if told.contains(&code) {
            continue;
        }
        if severity == "severe" {
            conversation.error(&sentence);
        } else {
            conversation.info(&sentence);
        }
        told.push(code);
    }
}

/// The question for the PIN when `methods` run (ADR-0023, amendment of 2026-11-21, point 3).
fn question(methods: &[String]) -> &'static str {
    let finger = methods.iter().any(|m| m == "fingerprint");
    let face = methods.iter().any(|m| m == "face");
    match (finger, face) {
        (true, true) => "PIN (or use the fingerprint sensor or the camera, then press Enter): ",
        (true, false) => "PIN (or touch the fingerprint sensor and press Enter): ",
        (false, true) => "PIN (or look at the camera and press Enter): ",
        (false, false) => "PIN: ",
    }
}

/// What the person is told to do when `methods` run without the PIN
/// (`both_sensor_and_camera_are_named`).
fn announcement(methods: &[String]) -> &'static str {
    let finger = methods.iter().any(|m| m == "fingerprint");
    let face = methods.iter().any(|m| m == "face");
    match (finger, face) {
        (true, true) => "Touch the fingerprint sensor or look at the camera.",
        (true, false) => "Touch the fingerprint sensor.",
        _ => "Look at the camera.",
    }
}

/// The steps between opening and closing the prompt.
fn steps(
    agent: &mut dyn Agent,
    pins: &mut dyn PinPost,
    conversation: &mut dyn Conversation,
    prompt: &str,
    context: &str,
    limits: &Limits,
    start: Instant,
) -> Result<Code, Fault> {
    let end = start + limits.total;
    let soon = |limit: Duration| (Instant::now() + limit).min(end);
    agent.call("Subscribe", &[Arg::Str(prompt)])?;
    agent.call("Authenticate", &[Arg::Str(prompt), Arg::Str(context)])?;
    let mut until = soon(limits.call);
    let mut answered: Option<Vec<String>> = None;
    let mut pin_sent = false;
    // The PIN was sent and the Agent then dropped it from the running methods: it was wrong. From
    // then on nothing may end in the password, not even a reader that never answers
    // (`a_wrong_pin_then_a_silent_reader_never_falls_through_to_the_password`, P-32).
    let mut pin_refused = false;
    let refused = |conversation: &mut dyn Conversation| {
        conversation.error("Wrong PIN.");
        Code::Denied
    };
    loop {
        let heard = match agent.signal(prompt, until) {
            Ok(heard) => heard,
            // Once a PIN was refused, nothing that goes wrong afterwards may turn that into "unavailable",
            // which would go on to the password prompt (P-32, review finding R-03, #346).
            Err(Fault) if pin_refused => return Ok(refused(conversation)),
            Err(fault) => return Err(fault),
        };
        let Some(signal) = heard else {
            return Ok(if pin_refused {
                refused(conversation)
            } else {
                Code::Unavailable
            });
        };
        match signal {
            // A result before any method ran means none could (no PIN set, no finger enrolled, an
            // unsatisfiable context): not a refusal of the person, so the password
            // (`no_method_that_can_run_is_unavailable_not_denied`).
            Signal::Result(result, _, _) if answered.is_none() && result != "success" => {
                return Ok(Code::Unavailable)
            }
            Signal::Result(result, reason, _)
                if pin_refused && result == "failure" && reason == "timeout" =>
            {
                return Ok(refused(conversation))
            }
            Signal::Result(result, reason, seconds) => {
                return Ok(outcome(&result, &reason, seconds, pin_sent, conversation))
            }
            Signal::Closed if pin_refused => return Ok(refused(conversation)),
            Signal::Closed => return Ok(Code::Unavailable),
            Signal::Active(methods) => {
                if pin_sent && !methods.iter().any(|m| m == "pin") {
                    pin_refused = true;
                }
                if methods.is_empty() || answered.as_ref() == Some(&methods) {
                    continue;
                }
                answered = Some(methods.clone());
                let other = methods.iter().any(|m| m == "fingerprint" || m == "face");
                if methods.iter().any(|m| m == "pin") {
                    let Some(pin) = conversation.secret(question(&methods)) else {
                        return Ok(Code::Unavailable);
                    };
                    if pin.is_empty() {
                        if !other {
                            // Only the PIN can be used and the person gave none: they want the
                            // password.
                            return Ok(Code::Unavailable);
                        }
                    } else {
                        agent.call("ExpectPin", &[Arg::Str(prompt)])?;
                        if !pins.send(pin.as_bytes())? {
                            return Ok(Code::Unavailable);
                        }
                        pin_sent = true;
                    }
                } else if other {
                    conversation.info(announcement(&methods));
                }
                until = soon(limits.wait);
            }
        }
    }
}

/// The PAM code of the Agent's `result`, telling the person what happened (ADR-0023, amendment of
/// 2026-11-21, point 5).
fn outcome(
    result: &str,
    reason: &str,
    seconds: u32,
    pin_sent: bool,
    conversation: &mut dyn Conversation,
) -> Code {
    match (result, reason) {
        ("success", _) => Code::Success,
        ("locked-out", _) => {
            let minutes = seconds.div_ceil(60).max(1);
            conversation.error(&format!(
                "Too many wrong PINs. Linux Hello is locked for {minutes} more minute{}.",
                if minutes == 1 { "" } else { "s" }
            ));
            Code::Denied
        }
        // Nobody answered before the Agent's own deadline: no clear answer, so the password.
        ("failure", "timeout") | ("cancelled", _) => Code::Unavailable,
        ("failure", _) => {
            conversation.error(if pin_sent {
                "Wrong PIN."
            } else {
                "Not recognised."
            });
            Code::Denied
        }
        _ => Code::Unavailable,
    }
}

#[cfg(test)]
mod tests;
