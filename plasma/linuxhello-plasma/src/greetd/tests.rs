//! Tests of the greetd conversation against a fake greetd on the other end of a socket pair.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::thread::JoinHandle;

use serde_json::{json, Value};

use super::{talk, Conversation, Line, Request, Step};

/// A fake greetd: reads each request and answers with the next reply of `script`. Returns the
/// requests it read.
fn fake_greetd(script: Vec<Value>) -> (UnixStream, JoinHandle<Vec<Value>>) {
    let (ours, mut theirs) = UnixStream::pair().expect("socket pair");
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for reply in script {
            let mut head = [0_u8; 4];
            if theirs.read_exact(&mut head).is_err() {
                break;
            }
            let mut body = vec![0_u8; u32::from_ne_bytes(head) as usize];
            theirs.read_exact(&mut body).expect("request body");
            seen.push(serde_json::from_slice(&body).expect("request is JSON"));
            let out = serde_json::to_vec(&reply).expect("reply");
            let length = u32::try_from(out.len()).expect("short reply");
            theirs.write_all(&length.to_ne_bytes()).expect("write");
            theirs.write_all(&out).expect("write");
        }
        seen
    });
    (ours, handle)
}

/// A PAM message from greetd.
fn message(kind: &str, text: &str) -> Value {
    json!({"type": "auth_message", "auth_message_type": kind, "auth_message": text})
}

#[test]
fn requests_are_greetds_json() {
    let (mut stream, fake) = fake_greetd(vec![json!({"type": "success"})]);
    talk(
        &mut stream,
        &Request::StartSession {
            cmd: vec!["startplasma-wayland".into()],
            env: vec!["XDG_SESSION_TYPE=wayland".into()],
        },
    )
    .expect("talk");
    assert_eq!(
        fake.join().expect("fake")[0],
        json!({"type": "start_session", "cmd": ["startplasma-wayland"], "env": ["XDG_SESSION_TYPE=wayland"]})
    );
}

#[test]
fn a_question_stops_the_conversation() {
    let (stream, fake) = fake_greetd(vec![message("secret", "PIN:"), json!({"type": "success"})]);
    let mut talk = Conversation::new(stream);
    let step = talk.begin("alex", |_| {}).expect("begin");
    assert_eq!(
        step,
        Step::Question {
            text: "PIN:".into(),
            secret: true
        }
    );
    assert_eq!(talk.answer("1234", |_| {}).expect("answer"), Step::SignedIn);
    let seen = fake.join().expect("fake");
    assert_eq!(
        seen[0],
        json!({"type": "create_session", "username": "alex"})
    );
    assert_eq!(
        seen[1],
        json!({"type": "post_auth_message_response", "response": "1234"})
    );
}

#[test]
fn lines_are_answered_and_kept() {
    let (stream, fake) = fake_greetd(vec![
        message("info", "Touch the fingerprint sensor."),
        message("error", "The TPM was cleared."),
        message("visible", "Name:"),
    ]);
    let mut lines = Vec::new();
    let step = Conversation::new(stream)
        .begin("alex", |line| lines.push(line))
        .expect("begin");
    assert_eq!(
        step,
        Step::Question {
            text: "Name:".into(),
            secret: false
        }
    );
    assert_eq!(
        lines,
        vec![
            Line {
                kind: "info".into(),
                text: "Touch the fingerprint sensor.".into()
            },
            Line {
                kind: "error".into(),
                text: "The TPM was cleared.".into()
            },
        ]
    );
    // An info or error line is answered without a response.
    assert_eq!(
        fake.join().expect("fake")[1],
        json!({"type": "post_auth_message_response"})
    );
}

#[test]
fn a_refusal_cancels_the_session() {
    let (stream, fake) = fake_greetd(vec![
        message("error", "Wrong PIN."),
        json!({"type": "error", "error_type": "auth_error", "description": "pam_authenticate: AUTH_ERR"}),
        json!({"type": "success"}),
    ]);
    let step = Conversation::new(stream)
        .begin("alex", |_| {})
        .expect("begin");
    assert_eq!(step, Step::Refused("pam_authenticate: AUTH_ERR".into()));
    assert_eq!(
        fake.join().expect("fake")[2],
        json!({"type": "cancel_session"})
    );
}

#[test]
fn a_reply_too_long_is_refused() {
    let (mut ours, mut theirs) = UnixStream::pair().expect("socket pair");
    let fake = std::thread::spawn(move || {
        let mut sink = [0_u8; 64];
        let _ = theirs.read(&mut sink);
        theirs.write_all(&(u32::MAX).to_ne_bytes()).expect("write");
    });
    assert!(talk(&mut ours, &Request::CancelSession).is_err());
    fake.join().expect("fake");
}
