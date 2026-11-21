//! Tests of the flow: with a scripted Agent for every path, and end to end over a fake bus for the
//! deadline and the check of the signals' sender.

use std::collections::VecDeque;
use std::os::unix::net::UnixListener;
use std::thread;
use std::time::{Duration, Instant};

use super::bus::tests::{listen, signal, Peer};
use super::wire::Value;
use super::*;

/// A scripted Agent: records the calls, refuses the members in `refuse`, and gives the signals in
/// order (`None` is "nothing before the deadline").
#[derive(Default)]
struct Script {
    calls: Vec<String>,
    refuse: Vec<&'static str>,
    signals: VecDeque<Option<Signal>>,
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
        Ok(self.signals.pop_front().flatten())
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
fn a_missing_or_unknown_context_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    // No bus at all: the context is refused before anything is reached, and a valid one then
    // fails on the missing bus; both are unavailable.
    for context in [None, Some(""), Some("ssh"), Some("SUDO"), Some("sudo ")] {
        let request = Request {
            context,
            service: "sudo",
            terminal: "/dev/pts/1",
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
        Code::UserUnknown
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
        for _ in 0..3 {
            let call = peer.read();
            peer.reply(&call, vec![]);
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
