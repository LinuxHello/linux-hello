//! Tests of the flow: with a scripted Agent for every path, and end to end over a fake bus for the
//! deadline and the check of the signals' sender.

use std::collections::VecDeque;
use std::os::unix::net::UnixListener;
use std::thread;
use std::time::{Duration, Instant};

use super::bus::tests::{listen, signal, unreadable_signal, Peer};
use super::wire::Value;
use super::*;

/// A scripted Agent: records the calls, refuses the members in `refuse`, and gives the signals in
/// order (`None` is "nothing before the deadline").
#[derive(Default)]
struct Script {
    calls: Vec<String>,
    refuse: Vec<&'static str>,
    signals: VecDeque<Option<Signal>>,
    /// The answers to `GetPromptStatus`, one per call; `None` is a failed call. Calls are counted
    /// in `asked_status`, not in `calls`.
    status: VecDeque<Option<Vec<(String, String, String)>>>,
    asked_status: Vec<String>,
    /// When the signals are used up the connection fails, instead of "nothing before the deadline".
    then_fail: bool,
}

impl Agent for Script {
    fn call(&mut self, member: &str, args: &[Arg<'_>]) -> Result<(), Fault> {
        let shown: Vec<String> = args
            .iter()
            .map(|a| match a {
                Arg::Str(s) => (*s).to_string(),
                Arg::I64(v) => v.to_string(),
            })
            .collect();
        self.calls.push(format!("{member}({})", shown.join(",")));
        if self.refuse.contains(&member) {
            Err(Fault)
        } else {
            Ok(())
        }
    }

    fn signal(&mut self, _prompt: &str, _deadline: Instant) -> Result<Option<Signal>, Fault> {
        match self.signals.pop_front() {
            None if self.then_fail => Err(Fault),
            next => Ok(next.flatten()),
        }
    }

    fn conditions(
        &mut self,
        prompt: &str,
        context: &str,
    ) -> Result<Vec<(String, String, String)>, Fault> {
        self.asked_status.push(format!("{prompt},{context}"));
        self.status.pop_front().flatten().ok_or(Fault)
    }
}

/// The PINs sent on the socket.
#[derive(Default)]
struct Socket {
    sent: Vec<Vec<u8>>,
    accept: bool,
}

impl PinPost for Socket {
    fn send(&mut self, pin: &[u8]) -> Result<bool, Fault> {
        self.sent.push(pin.to_vec());
        Ok(self.accept)
    }
}

/// A person who answers each question with the next text, and what they were shown.
#[derive(Default)]
struct Person {
    answers: VecDeque<Option<&'static str>>,
    asked: Vec<String>,
    shown: Vec<String>,
}

impl Conversation for Person {
    fn secret(&mut self, question: &str) -> Option<Zeroizing<String>> {
        self.asked.push(question.to_string());
        self.answers
            .pop_front()
            .flatten()
            .map(|a| Zeroizing::new(a.to_string()))
    }
    fn info(&mut self, text: &str) {
        self.shown.push(format!("info: {text}"));
    }
    fn error(&mut self, text: &str) {
        self.shown.push(format!("error: {text}"));
    }
}

fn active(methods: &[&str]) -> Option<Signal> {
    Some(Signal::Active(
        methods.iter().map(|m| (*m).to_string()).collect(),
    ))
}

fn result(result: &str, reason: &str, seconds: u32) -> Option<Signal> {
    Some(Signal::Result(result.into(), reason.into(), seconds))
}

const FAST: Limits = Limits {
    connect: Duration::from_millis(200),
    call: Duration::from_millis(200),
    wait: Duration::from_millis(300),
    total: Duration::from_secs(2),
};

fn go(agent: &mut Script, socket: &mut Socket, person: &mut Person) -> Code {
    run(
        agent,
        socket,
        person,
        "p1",
        1000,
        "sudo",
        &FAST,
        Instant::now(),
    )
}

#[test]
fn a_right_pin_is_announced_then_sent_on_the_socket_and_succeeds() {
    let mut agent = Script {
        signals: [active(&["pin"]), result("success", "", 0)].into(),
        ..Script::default()
    };
    let mut socket = Socket {
        accept: true,
        ..Socket::default()
    };
    let mut person = Person {
        answers: [Some("2468")].into(),
        ..Person::default()
    };
    assert_eq!(go(&mut agent, &mut socket, &mut person), Code::Success);
    assert_eq!(
        agent.calls,
        [
            "OpenPrompt(p1,1000)",
            "Subscribe(p1)",
            "Authenticate(p1,sudo)",
            "ExpectPin(p1)",
            "ClosePrompt(p1)"
        ]
    );
    assert_eq!(socket.sent, [b"2468".to_vec()]);
    assert_eq!(person.asked, ["PIN: "]);
    // The PIN is in no bus call.
    assert!(agent.calls.iter().all(|c| !c.contains("2468")));
}

#[test]
fn an_empty_answer_sends_no_pin_and_waits_for_the_result() {
    let mut agent = Script {
        signals: [active(&["fingerprint", "pin"]), result("success", "", 0)].into(),
        ..Script::default()
    };
    let mut socket = Socket::default();
    let mut person = Person {
        answers: [Some("")].into(),
        ..Person::default()
    };
    assert_eq!(go(&mut agent, &mut socket, &mut person), Code::Success);
    assert!(socket.sent.is_empty());
    assert!(!agent.calls.iter().any(|c| c.starts_with("ExpectPin")));
    assert_eq!(
        person.asked,
        ["PIN (or touch the fingerprint sensor and press Enter): "]
    );
    // With nothing but the PIN, an empty answer means the password: no waiting.
    let mut agent = Script {
        signals: [active(&["pin"]), result("success", "", 0)].into(),
        ..Script::default()
    };
    let mut person = Person {
        answers: [Some("")].into(),
        ..Person::default()
    };
    assert_eq!(
        go(&mut agent, &mut Socket::default(), &mut person),
        Code::Unavailable
    );
}

#[test]
fn a_sensor_alone_is_announced_and_not_asked() {
    let mut agent = Script {
        signals: [active(&["fingerprint"]), result("success", "", 0)].into(),
        ..Script::default()
    };
    let mut person = Person::default();
    assert_eq!(
        go(&mut agent, &mut Socket::default(), &mut person),
        Code::Success
    );
    assert!(person.asked.is_empty());
    assert_eq!(person.shown, ["info: Touch the fingerprint sensor."]);
}

#[test]
fn every_result_maps_to_its_pam_code() {
    type Case = (
        Option<Signal>,
        Option<&'static str>,
        Code,
        &'static [&'static str],
    );
    let cases: [Case; 7] = [
        (result("success", "", 0), Some("1"), Code::Success, &[]),
        (
            result("failure", "not-recognised", 0),
            Some("1"),
            Code::Denied,
            &["error: Wrong PIN."],
        ),
        (
            result("failure", "not-recognised", 0),
            Some(""),
            Code::Denied,
            &["error: Not recognised."],
        ),
        (
            result("locked-out", "", 61),
            Some("1"),
            Code::Denied,
            &["error: Too many wrong PINs. Linux Hello is locked for 2 more minutes."],
        ),
        (
            result("failure", "timeout", 0),
            Some(""),
            Code::Unavailable,
            &[],
        ),
        (
            result("cancelled", "", 0),
            Some("1"),
            Code::Unavailable,
            &[],
        ),
        (
            result("something-new", "", 0),
            Some("1"),
            Code::Unavailable,
            &[],
        ),
    ];
    for (outcome, answer, code, shown) in cases {
        let mut agent = Script {
            signals: [active(&["face", "pin"]), outcome.clone()].into(),
            ..Script::default()
        };
        let mut socket = Socket {
            accept: true,
            ..Socket::default()
        };
        let mut person = Person {
            answers: [answer].into(),
            ..Person::default()
        };
        assert_eq!(
            go(&mut agent, &mut socket, &mut person),
            code,
            "{outcome:?}"
        );
        assert_eq!(person.shown, shown, "{outcome:?}");
    }
}

#[test]
fn no_method_that_can_run_is_unavailable_not_denied() {
    // The Agent ends at once when nothing can run (no PIN set, no finger enrolled): the password
    // must still be asked, so this is never a refusal.
    for methods in [None, active(&[])] {
        let mut signals: VecDeque<Option<Signal>> = VecDeque::new();
        if let Some(m) = methods {
            signals.push_back(Some(m));
        }
        signals.push_back(result("failure", "", 0));
        let mut agent = Script {
            signals,
            ..Script::default()
        };
        assert_eq!(
            go(&mut agent, &mut Socket::default(), &mut Person::default()),
            Code::Unavailable
        );
    }
}

#[test]
fn the_prompt_is_always_closed() {
    // Whichever step fails after the prompt was opened, ClosePrompt is the last call.
    for refused in ["Subscribe", "Authenticate", "ExpectPin"] {
        let mut agent = Script {
            refuse: vec![refused],
            signals: [active(&["pin"])].into(),
            ..Script::default()
        };
        let mut person = Person {
            answers: [Some("1234")].into(),
            ..Person::default()
        };
        assert_eq!(
            go(&mut agent, &mut Socket::default(), &mut person),
            Code::Unavailable
        );
        assert_eq!(
            agent.calls.last().map(String::as_str),
            Some("ClosePrompt(p1)")
        );
    }
    // No answer in time, a cancelled conversation, a PIN the socket refused, a closed prompt.
    let endings: [(VecDeque<Option<Signal>>, Option<&'static str>); 4] = [
        ([None].into(), None),
        ([active(&["pin"])].into(), None),
        ([active(&["pin"])].into(), Some("1")),
        ([Some(Signal::Closed)].into(), None),
    ];
    for (signals, answer) in endings {
        let mut agent = Script {
            signals,
            ..Script::default()
        };
        let mut person = Person {
            answers: [answer].into(),
            ..Person::default()
        };
        assert_eq!(
            go(&mut agent, &mut Socket::default(), &mut person),
            Code::Unavailable
        );
        assert_eq!(
            agent.calls.last().map(String::as_str),
            Some("ClosePrompt(p1)")
        );
    }
    // A prompt that could not be opened is not closed.
    let mut agent = Script {
        refuse: vec!["OpenPrompt"],
        ..Script::default()
    };
    assert_eq!(
        go(&mut agent, &mut Socket::default(), &mut Person::default()),
        Code::Unavailable
    );
    assert_eq!(agent.calls, ["OpenPrompt(p1,1000)"]);
}

#[test]
fn a_remote_session_never_reaches_the_agent() {
    // sudo inside an SSH session: the person is not at the sensor or the camera of this machine.
    // The module answers "unavailable" (so the password follows) without a word to the bus (R-04, #347).
    for host in ["203.0.113.7", "laptop.example", "::2", "localhost.example"] {
        let (dir, path, listener) = listen();
        listener.set_nonblocking(true).unwrap();
        let request = Request {
            context: Some("sudo"),
            service: "sudo",
            terminal: "/dev/pts/1",
            remote_host: host,
            uid: Some(1000),
        };
        let code = authenticate_at(
            &path,
            &dir.path().join("pin"),
            &FAST,
            &request,
            &mut Person::default(),
        );
        assert_eq!(code, Code::Unavailable, "{host}");
        assert!(listener.accept().is_err(), "{host}: the bus was contacted");
    }
}

/// A session file of logind as `sessions` holds it, and the file of this process's session id.
fn logind(id: &str, session: &str) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let sessions = dir.path().join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    std::fs::write(sessions.join("2"), session).unwrap();
    let own = dir.path().join("sessionid");
    std::fs::write(&own, format!("{id}\n")).unwrap();
    (dir, own, sessions)
}

#[test]
fn a_session_is_at_this_machine_only_when_logind_says_so() {
    let local = "UID=1000\nACTIVE=1\nREMOTE=0\nSEAT=seat0\nVTNR=2\nTYPE=tty\n";
    let (_d, own, dir) = logind("2", local);
    assert!(session_at_this_machine(&own, &dir));
    // Each way a session is not at this machine, or cannot be shown to be.
    for (what, id, text) in [
        ("an SSH session", "2", "ACTIVE=1\nREMOTE=1\nTYPE=tty\n"),
        (
            "a remote session that names a seat",
            "2",
            "ACTIVE=1\nREMOTE=1\nSEAT=seat0\n",
        ),
        (
            "a session without a seat",
            "2",
            "ACTIVE=1\nREMOTE=0\nTYPE=tty\n",
        ),
        (
            "a session behind another one",
            "2",
            "ACTIVE=0\nREMOTE=0\nSEAT=seat0\n",
        ),
        (
            "a session with no remote flag",
            "2",
            "ACTIVE=1\nSEAT=seat0\n",
        ),
        ("a process outside any session", "4294967295", local),
        ("a session logind does not know", "7", local),
        ("an id that is not a number", "../2", local),
        ("an empty id", "", local),
    ] {
        let (_d, own, dir) = logind(id, text);
        assert!(!session_at_this_machine(&own, &dir), "{what}");
    }
    // No logind at all.
    let (dir, _, _) = logind("2", local);
    assert!(!session_at_this_machine(
        &dir.path().join("no-sessionid"),
        &dir.path().join("sessions")
    ));
}

#[test]
fn a_session_at_this_machine_is_not_remote() {
    for host in ["", "localhost", "127.0.0.1", "::1"] {
        assert!(is_local_host(host), "{host}");
    }
    for host in ["203.0.113.7", "10.0.0.1", "example.org", " ", "localhost "] {
        assert!(!is_local_host(host), "{host}");
    }
}

#[test]
fn a_missing_or_unknown_context_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    // No bus at all: the context is refused before anything is reached, and a valid one then
    // fails on the missing bus; both are unavailable.
    for context in [None, Some(""), Some("ssh"), Some("SUDO"), Some("sudo ")] {
        let request = Request {
            context,
            service: "sudo",
            terminal: "/dev/pts/1",
            remote_host: "",
            uid: Some(1000),
        };
        assert_eq!(
            authenticate_at(
                &dir.path().join("bus"),
                &dir.path().join("pin"),
                &FAST,
                &request,
                &mut Person::default()
            ),
            Code::Unavailable,
            "{context:?}"
        );
    }
    let request = Request {
        context: Some("sudo"),
        service: "sudo",
        terminal: "",
        remote_host: "",
        uid: None,
    };
    assert_eq!(
        authenticate_at(
            &dir.path().join("bus"),
            &dir.path().join("pin"),
            &FAST,
            &request,
            &mut Person::default()
        ),
        // Not "unknown": that would end the stack with no password prompt for a name that is no
        // user, which tells an observer at the console which names exist (#359).
        Code::Unavailable
    );
}

/// Serves the bus side up to the Agent's name owner, then runs `then` on the connection.
fn fake_agent(
    listener: UnixListener,
    then: impl FnOnce(&mut Peer) + Send + 'static,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut peer = Peer::new(stream);
        peer.accept_auth();
        peer.hello();
        let owner = peer.read();
        assert_eq!(owner.member.as_deref(), Some("GetNameOwner"));
        peer.reply(&owner, vec![Value::Str(":1.5".into())]);
        then(&mut peer);
    })
}

#[test]
fn pam_returns_within_its_deadline_when_the_agent_hangs() {
    let (dir, path, listener) = listen();
    // The Agent's name is owned, but OpenPrompt is never answered.
    let server = fake_agent(listener, |peer| {
        let _open = peer.read();
        thread::sleep(Duration::from_millis(800));
    });
    let request = Request {
        context: Some("sudo"),
        service: "sudo",
        terminal: "/dev/pts/1",
        remote_host: "",
        uid: Some(1000),
    };
    let started = Instant::now();
    let code = authenticate_at(
        &path,
        &dir.path().join("pin"),
        &FAST,
        &request,
        &mut Person::default(),
    );
    let took = started.elapsed();
    assert_eq!(code, Code::Unavailable);
    // One call limit for OpenPrompt and one for the ClosePrompt that follows, nothing more.
    assert!(took < FAST.call * 3, "{took:?}");
    server.join().unwrap();
}

#[test]
fn a_signal_from_another_sender_is_ignored() {
    let (dir, path, listener) = listen();
    let server = fake_agent(listener, |peer| {
        // OpenPrompt, GetPromptStatus (nothing to tell), Subscribe, Authenticate.
        for _ in 0..4 {
            let call = peer.read();
            let body = if call.member.as_deref() == Some("GetPromptStatus") {
                vec![Value::Triples(vec![])]
            } else {
                vec![]
            };
            peer.reply(&call, body);
        }
        let prompt = |id: &str| Value::Str(id.to_string());
        // A forged success from a connection that is not the Agent, then the real refusal.
        peer.send(&signal(
            "ActiveMethods",
            ":1.5",
            vec![prompt("PROMPT"), Value::Strs(vec!["fingerprint".into()])],
        ));
        peer.send(&signal(
            "Result",
            ":1.99",
            vec![
                prompt("PROMPT"),
                prompt("success"),
                prompt(""),
                Value::U32(0),
            ],
        ));
        peer.send(&signal(
            "Result",
            ":1.5",
            vec![
                prompt("PROMPT"),
                prompt("failure"),
                prompt("not-recognised"),
                Value::U32(0),
            ],
        ));
        let close = peer.read();
        assert_eq!(close.member.as_deref(), Some("ClosePrompt"));
        peer.reply(&close, vec![]);
    });
    // `authenticate_at` derives a fresh prompt id; the fake answers for "PROMPT", so the flow runs
    // through `run` with the real bus Agent and that id.
    let mut agent = BusAgent::connect(&path, &FAST).unwrap();
    let mut person = Person::default();
    let code = run(
        &mut agent,
        &mut SocketPin(&dir.path().join("pin")),
        &mut person,
        "PROMPT",
        1000,
        "sudo",
        &FAST,
        Instant::now(),
    );
    assert_eq!(code, Code::Denied);
    assert_eq!(
        person.shown,
        [
            "info: Touch the fingerprint sensor.",
            "error: Not recognised."
        ]
    );
    server.join().unwrap();
}

fn condition(code: &str, severity: &str, sentence: &str) -> (String, String, String) {
    (code.into(), severity.into(), sentence.into())
}

#[test]
fn the_conditions_are_shown_as_pam_messages() {
    let mut agent = Script {
        signals: [active(&["pin"]), result("success", "", 0)].into(),
        status: [
            Some(vec![
                condition("tpm-cleared", "severe", "The TPM lost the key."),
                condition(
                    "context-unsatisfiable: sudo",
                    "warning",
                    "sudo cannot be unlocked.",
                ),
            ]),
            // After the success: the expiry, and one already shown, which is not repeated.
            Some(vec![
                condition("tpm-cleared", "severe", "The TPM lost the key."),
                condition("pin-expired", "warning", "Your PIN has expired."),
            ]),
        ]
        .into(),
        ..Script::default()
    };
    let mut socket = Socket {
        accept: true,
        ..Socket::default()
    };
    let mut person = Person {
        answers: [Some("2468")].into(),
        ..Person::default()
    };
    assert_eq!(go(&mut agent, &mut socket, &mut person), Code::Success);
    assert_eq!(
        person.shown,
        [
            "error: The TPM lost the key.",
            "info: sudo cannot be unlocked.",
            "info: Your PIN has expired."
        ]
    );
    assert_eq!(agent.asked_status, ["p1,sudo", "p1,sudo"]);
}

#[test]
fn the_conditions_after_sign_in_are_asked_only_after_a_success() {
    let mut agent = Script {
        signals: [active(&["pin"]), result("failure", "", 0)].into(),
        status: [
            Some(vec![]),
            Some(vec![condition("pin-expired", "warning", "x")]),
        ]
        .into(),
        ..Script::default()
    };
    let mut socket = Socket {
        accept: true,
        ..Socket::default()
    };
    let mut person = Person {
        answers: [Some("1111")].into(),
        ..Person::default()
    };
    assert_eq!(go(&mut agent, &mut socket, &mut person), Code::Denied);
    assert_eq!(agent.asked_status.len(), 1);
    assert_eq!(person.shown, ["error: Wrong PIN."]);
}

#[test]
fn a_failed_status_call_changes_nothing() {
    // The same sign-in, with the status call failing both times and with it answering nothing.
    for status in [[None, None], [Some(vec![]), Some(vec![])]] {
        let mut agent = Script {
            signals: [active(&["pin"]), result("success", "", 0)].into(),
            status: status.into(),
            ..Script::default()
        };
        let mut socket = Socket {
            accept: true,
            ..Socket::default()
        };
        let mut person = Person {
            answers: [Some("2468")].into(),
            ..Person::default()
        };
        assert_eq!(go(&mut agent, &mut socket, &mut person), Code::Success);
        assert!(person.shown.is_empty());
        assert_eq!(person.asked, ["PIN: "]);
        assert_eq!(
            agent.calls,
            [
                "OpenPrompt(p1,1000)",
                "Subscribe(p1)",
                "Authenticate(p1,sudo)",
                "ExpectPin(p1)",
                "ClosePrompt(p1)"
            ]
        );
    }
}

#[test]
fn no_more_than_eight_conditions_are_shown() {
    let many: Vec<_> = (0..20)
        .map(|i| condition(&format!("c{i}"), "info", &format!("s{i}")))
        .collect();
    let mut agent = Script {
        signals: [active(&["pin"]), result("success", "", 0)].into(),
        status: [Some(many.clone()), Some(many)].into(),
        ..Script::default()
    };
    let mut socket = Socket {
        accept: true,
        ..Socket::default()
    };
    let mut person = Person {
        answers: [Some("2468")].into(),
        ..Person::default()
    };
    assert_eq!(go(&mut agent, &mut socket, &mut person), Code::Success);
    assert_eq!(person.shown.len(), 8);
}

/// A sign-in where the PIN `1111` is typed while the fingerprint reader also runs, the Agent then
/// drops the PIN (it was wrong) and `end` is what follows.
fn wrong_pin_with_the_reader_running(end: Option<Signal>) -> (Code, Person) {
    let mut agent = Script {
        signals: [
            active(&["fingerprint", "pin"]),
            active(&["fingerprint"]),
            end,
        ]
        .into(),
        ..Script::default()
    };
    let mut socket = Socket {
        accept: true,
        ..Socket::default()
    };
    let mut person = Person {
        answers: [Some("1111")].into(),
        ..Person::default()
    };
    let code = go(&mut agent, &mut socket, &mut person);
    (code, person)
}

#[test]
fn a_wrong_pin_then_a_silent_reader_never_falls_through_to_the_password() {
    // Nothing more from the Agent before the deadline, the Agent's own timeout, or a closed prompt.
    for end in [None, result("failure", "timeout", 0), Some(Signal::Closed)] {
        let (code, person) = wrong_pin_with_the_reader_running(end.clone());
        assert_eq!(code, Code::Denied, "{end:?}");
        assert_eq!(
            person.shown.last().map(String::as_str),
            Some("error: Wrong PIN.")
        );
    }
}

#[test]
fn a_connection_fault_after_a_wrong_pin_stays_denied() {
    // The PIN was refused; whatever goes wrong with the bus afterwards must not turn that into
    // "unavailable", which goes on to the password prompt (P-32, R-03, #346).
    let mut agent = Script {
        signals: [active(&["fingerprint", "pin"]), active(&["fingerprint"])].into(),
        then_fail: true,
        ..Script::default()
    };
    let mut socket = Socket {
        accept: true,
        ..Socket::default()
    };
    let mut person = Person {
        answers: [Some("1111")].into(),
        ..Person::default()
    };
    assert_eq!(go(&mut agent, &mut socket, &mut person), Code::Denied);
    assert_eq!(
        person.shown.last().map(String::as_str),
        Some("error: Wrong PIN.")
    );
    // Before any PIN, the same fault is still "unavailable".
    let mut agent = Script {
        signals: [active(&["fingerprint", "pin"])].into(),
        then_fail: true,
        ..Script::default()
    };
    let mut person = Person {
        answers: [Some("")].into(),
        ..Person::default()
    };
    assert_eq!(
        go(&mut agent, &mut Socket::default(), &mut person),
        Code::Unavailable
    );
}

#[test]
fn a_hostile_signal_cannot_switch_linux_hello_off() {
    // R-03 (#346) end to end on a fake bus: a connection that is not the Agent sends a signal the
    // codec cannot read, and the Agent itself sends one with a type it does not know, in the middle
    // of a sign-in. The sign-in still ends as the Agent says.
    let (dir, path, listener) = listen();
    let server = fake_agent(listener, |peer| {
        for _ in 0..4 {
            let call = peer.read();
            let body = if call.member.as_deref() == Some("GetPromptStatus") {
                vec![Value::Triples(vec![])]
            } else {
                vec![]
            };
            peer.reply(&call, body);
        }
        let prompt = |id: &str| Value::Str(id.to_string());
        peer.send_raw(&unreadable_signal("Result", ":1.99"));
        peer.send(&signal(
            "ActiveMethods",
            ":1.5",
            vec![prompt("PROMPT"), Value::Strs(vec!["fingerprint".into()])],
        ));
        peer.send_raw(&unreadable_signal("Result", ":1.99"));
        peer.send_raw(&unreadable_signal("MethodEnded", ":1.5"));
        peer.send(&signal(
            "Result",
            ":1.5",
            vec![
                prompt("PROMPT"),
                prompt("failure"),
                prompt("not-recognised"),
                Value::U32(0),
            ],
        ));
        let close = peer.read();
        assert_eq!(close.member.as_deref(), Some("ClosePrompt"));
        peer.reply(&close, vec![]);
    });
    let mut agent = BusAgent::connect(&path, &FAST).unwrap();
    let mut person = Person::default();
    let code = run(
        &mut agent,
        &mut SocketPin(&dir.path().join("pin")),
        &mut person,
        "PROMPT",
        1000,
        "sudo",
        &FAST,
        Instant::now(),
    );
    assert_eq!(code, Code::Denied, "{:?}", person.shown);
    server.join().unwrap();
}

#[test]
fn a_wrong_pin_then_a_finger_that_matches_still_signs_in() {
    let (code, _) = wrong_pin_with_the_reader_running(result("success", "", 0));
    assert_eq!(code, Code::Success);
}

#[test]
fn a_silent_reader_without_a_pin_typed_is_still_unavailable() {
    // An empty answer: no PIN was sent, so a reader that never answers gives the password.
    let mut agent = Script {
        signals: [active(&["fingerprint", "pin"]), None].into(),
        ..Script::default()
    };
    let mut person = Person {
        answers: [Some("")].into(),
        ..Person::default()
    };
    assert_eq!(
        go(&mut agent, &mut Socket::default(), &mut person),
        Code::Unavailable
    );
}

#[test]
fn both_sensor_and_camera_are_named() {
    let mut agent = Script {
        signals: [active(&["fingerprint", "face"]), result("success", "", 0)].into(),
        ..Script::default()
    };
    let mut person = Person::default();
    assert_eq!(
        go(&mut agent, &mut Socket::default(), &mut person),
        Code::Success
    );
    assert_eq!(
        person.shown,
        ["info: Touch the fingerprint sensor or look at the camera."]
    );
}

#[test]
fn an_unreachable_agent_is_announced() {
    // The Agent refuses to open the prompt.
    let mut agent = Script {
        refuse: vec!["OpenPrompt"],
        ..Script::default()
    };
    let mut person = Person::default();
    assert_eq!(
        go(&mut agent, &mut Socket::default(), &mut person),
        Code::Unavailable
    );
    assert_eq!(person.shown, [format!("info: {UNAVAILABLE_LINE}")]);

    // A call fails half way.
    let mut agent = Script {
        refuse: vec!["Authenticate"],
        ..Script::default()
    };
    let mut person = Person::default();
    assert_eq!(
        go(&mut agent, &mut Socket::default(), &mut person),
        Code::Unavailable
    );
    assert_eq!(person.shown, [format!("info: {UNAVAILABLE_LINE}")]);

    // No bus at all.
    let dir = tempfile::tempdir().unwrap();
    let request = Request {
        context: Some("sudo"),
        service: "sudo",
        terminal: "/dev/pts/1",
        remote_host: "",
        uid: Some(1000),
    };
    let mut person = Person::default();
    let code = authenticate_at(
        &dir.path().join("none"),
        &dir.path().join("pin"),
        &FAST,
        &request,
        &mut person,
    );
    assert_eq!(code, Code::Unavailable);
    assert_eq!(person.shown, [format!("info: {UNAVAILABLE_LINE}")]);
}

#[test]
fn an_unavailable_answer_the_person_chose_is_not_announced() {
    let mut agent = Script {
        signals: [active(&["pin"])].into(),
        ..Script::default()
    };
    let mut person = Person {
        answers: [Some("")].into(),
        ..Person::default()
    };
    assert_eq!(
        go(&mut agent, &mut Socket::default(), &mut person),
        Code::Unavailable
    );
    assert!(person.shown.is_empty());
}
