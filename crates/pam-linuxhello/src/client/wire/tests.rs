//! Tests of the codec: what it writes is a valid message, and what it reads is exactly what the bus
//! and the Agent send, refusing anything else.

use super::*;

/// A test-only writer of any message the module reads, independent of the module's own writer, so
/// that a mistake in one is not repeated in the other. `fields` are (code, type, value) with the
/// type `s`, `o`, `g` or `u`; `body` is written with `signature`.
struct Build {
    bytes: Vec<u8>,
}

impl Build {
    fn pad(&mut self, n: usize) {
        while self.bytes.len() % n != 0 {
            self.bytes.push(0);
        }
    }
    fn u32(&mut self, v: u32) {
        self.pad(4);
        self.bytes.extend_from_slice(&v.to_le_bytes());
    }
    fn s(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
    }
    fn g(&mut self, s: &str) {
        self.bytes.push(s.len() as u8);
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
    }
}

enum F<'a> {
    S(u8, &'a str),
    O(u8, &'a str),
    G(u8, &'a str),
    U(u8, u32),
}

fn message(kind: u8, serial: u32, fields: &[F<'_>], body: &[Value]) -> Vec<u8> {
    let mut b = Build { bytes: Vec::new() };
    let mut sig = String::new();
    for v in body {
        match v {
            Value::Str(s) => {
                sig.push('s');
                b.s(s);
            }
            Value::U32(u) => {
                sig.push('u');
                b.u32(*u);
            }
            Value::I64(v) => {
                sig.push('x');
                b.pad(8);
                b.bytes.extend_from_slice(&v.to_le_bytes());
            }
            Value::Strs(items) => {
                sig.push_str("as");
                b.u32(0);
                let at = b.bytes.len();
                for item in items {
                    b.s(item);
                }
                let n = (b.bytes.len() - at) as u32;
                b.bytes[at - 4..at].copy_from_slice(&n.to_le_bytes());
            }
            Value::Triples(items) => {
                sig.push_str("a(sss)");
                b.u32(0);
                let length = b.bytes.len() - 4;
                b.pad(8);
                let at = b.bytes.len();
                for (x, y, z) in items {
                    b.pad(8);
                    b.s(x);
                    b.s(y);
                    b.s(z);
                }
                let n = (b.bytes.len() - at) as u32;
                b.bytes[length..length + 4].copy_from_slice(&n.to_le_bytes());
            }
        }
    }
    let body_bytes = b.bytes;
    let mut h = Build {
        bytes: vec![b'l', kind, 0, 1],
    };
    h.u32(body_bytes.len() as u32);
    h.u32(serial);
    h.u32(0);
    let start = h.bytes.len();
    let mut all: Vec<&F<'_>> = fields.iter().collect();
    let sig_field = F::G(8, &sig);
    if !sig.is_empty() {
        all.push(&sig_field);
    }
    for f in all {
        h.pad(8);
        match f {
            F::S(c, v) => {
                h.bytes.push(*c);
                h.g("s");
                h.s(v);
            }
            F::O(c, v) => {
                h.bytes.push(*c);
                h.g("o");
                h.s(v);
            }
            F::G(c, v) => {
                h.bytes.push(*c);
                h.g("g");
                h.g(v);
            }
            F::U(c, v) => {
                h.bytes.push(*c);
                h.g("u");
                h.u32(*v);
            }
        }
    }
    let n = (h.bytes.len() - start) as u32;
    h.bytes[12..16].copy_from_slice(&n.to_le_bytes());
    h.pad(8);
    h.bytes.extend_from_slice(&body_bytes);
    h.bytes
}

fn head(bytes: &[u8]) -> [u8; 16] {
    bytes[..16].try_into().unwrap()
}

#[test]
fn a_method_call_is_a_valid_message_with_its_arguments() {
    let bytes = method_call(
        7,
        "io.github.LinuxHello.Agent1",
        "/io/github/LinuxHello/Agent1",
        "io.github.LinuxHello.Agent1",
        "OpenPrompt",
        &[Arg::Str("abc"), Arg::I64(-1)],
    )
    .unwrap();
    assert_eq!(total_length(&head(&bytes)), Ok(bytes.len()));
    assert_eq!(&bytes[..4], &[b'l', 1, 0, 1]);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 7);
    // The body: "abc" (4 + 3 + 1 bytes), padding to 8, then -1 as eight bytes.
    let body = &bytes[bytes.len() - 16..];
    assert_eq!(&body[..8], &[3, 0, 0, 0, b'a', b'b', b'c', 0]);
    assert_eq!(&body[8..], &(-1_i64).to_le_bytes());
    // Its header reads back with the module's own reader.
    let read = parse(&bytes).unwrap();
    assert_eq!(read.kind, Kind::Call);
    assert_eq!(read.member.as_deref(), Some("OpenPrompt"));
    assert_eq!(
        read.interface.as_deref(),
        Some("io.github.LinuxHello.Agent1")
    );
    assert_eq!(read.body, vec![Value::Str("abc".into()), Value::I64(-1)]);
}

#[test]
fn a_call_without_arguments_has_no_signature_and_no_body() {
    let bytes = method_call(
        1,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "Hello",
        &[],
    )
    .unwrap();
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 0);
    assert_eq!(bytes.len() % 8, 0);
    assert_eq!(parse(&bytes).unwrap().body, Vec::<Value>::new());
}

#[test]
fn the_agents_signals_are_read() {
    let active = message(
        4,
        9,
        &[
            F::O(1, "/io/github/LinuxHello/Agent1"),
            F::S(2, "io.github.LinuxHello.Agent1"),
            F::S(3, "ActiveMethods"),
            F::S(7, ":1.5"),
        ],
        &[
            Value::Str("p1".into()),
            Value::Strs(vec!["fingerprint".into(), "pin".into()]),
        ],
    );
    let m = parse(&active).unwrap();
    assert_eq!(m.kind, Kind::Signal);
    assert_eq!(m.member.as_deref(), Some("ActiveMethods"));
    assert_eq!(m.sender.as_deref(), Some(":1.5"));
    assert_eq!(
        m.body,
        vec![
            Value::Str("p1".into()),
            Value::Strs(vec!["fingerprint".into(), "pin".into()])
        ]
    );
    let result = message(
        4,
        10,
        &[F::S(2, "io.github.LinuxHello.Agent1"), F::S(3, "Result")],
        &[
            Value::Str("p1".into()),
            Value::Str("locked-out".into()),
            Value::Str(String::new()),
            Value::U32(540),
        ],
    );
    assert_eq!(
        parse(&result).unwrap().body,
        vec![
            Value::Str("p1".into()),
            Value::Str("locked-out".into()),
            Value::Str(String::new()),
            Value::U32(540)
        ]
    );
    // An empty list of methods.
    let none = message(
        4,
        11,
        &[F::S(3, "ActiveMethods")],
        &[Value::Str("p".into()), Value::Strs(vec![])],
    );
    assert_eq!(parse(&none).unwrap().body[1], Value::Strs(vec![]));
}

#[test]
fn replies_and_errors_carry_the_serial_they_answer() {
    let reply = message(
        2,
        3,
        &[F::U(5, 42), F::S(7, "org.freedesktop.DBus")],
        &[Value::Str(":1.9".into())],
    );
    let m = parse(&reply).unwrap();
    assert_eq!((m.kind, m.reply_serial), (Kind::Return, Some(42)));
    let error = message(
        3,
        4,
        &[
            F::U(5, 43),
            F::S(4, "io.github.LinuxHello.Agent1.Error.Denied"),
        ],
        &[Value::Str("denied".into())],
    );
    let m = parse(&error).unwrap();
    assert_eq!(m.kind, Kind::Error);
    assert_eq!(m.reply_serial, Some(43));
    assert_eq!(
        m.error_name.as_deref(),
        Some("io.github.LinuxHello.Agent1.Error.Denied")
    );
}

#[test]
fn a_big_endian_message_is_read() {
    // A reply with no body, serial 5, answering 6: written by hand in big-endian order.
    let mut bytes = vec![b'B', 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 8];
    bytes.extend_from_slice(&[5, 1, b'u', 0, 0, 0, 0, 6]);
    let m = parse(&bytes).unwrap();
    assert_eq!(
        (m.kind, m.serial, m.reply_serial),
        (Kind::Return, 5, Some(6))
    );
}

#[test]
fn anything_else_is_malformed_and_never_a_panic() {
    let good = message(
        4,
        1,
        &[F::S(3, "Result")],
        &[Value::Str("p".into()), Value::U32(1)],
    );
    assert!(parse(&good).is_ok());
    // Every truncation and every single-byte change is either read or refused, never a panic.
    for n in 0..good.len() {
        let _ = parse(&good[..n]);
        let _ = total_length(&{
            let mut h = [0_u8; 16];
            for (i, b) in good.iter().take(16).enumerate() {
                h[i] = *b;
            }
            h
        });
    }
    for at in 0..good.len() {
        for value in [0_u8, 1, 0x7f, 0x80, 0xff] {
            let mut bad = good.clone();
            bad[at] = value;
            let _ = parse(&bad);
        }
    }
    // Unknown byte order, protocol version and message type.
    let mut bad = good.clone();
    bad[0] = b'x';
    assert_eq!(parse(&bad), Err(Malformed));
    let mut bad = good.clone();
    bad[3] = 2;
    assert_eq!(parse(&bad), Err(Malformed));
    let mut bad = good.clone();
    bad[1] = 9;
    assert_eq!(parse(&bad), Err(Malformed));
    // A body type the module does not read (an unsigned 64-bit number).
    let mut odd = message(4, 1, &[F::S(3, "Result")], &[]);
    odd = {
        let mut m = odd;
        // Build a message with signature "t" directly.
        m.clear();
        let mut h = Build {
            bytes: vec![b'l', 4, 0, 1],
        };
        h.u32(8);
        h.u32(1);
        h.u32(0);
        let start = h.bytes.len();
        h.bytes.push(8);
        h.g("g");
        h.g("t");
        let n = (h.bytes.len() - start) as u32;
        h.bytes[12..16].copy_from_slice(&n.to_le_bytes());
        h.pad(8);
        h.bytes.extend_from_slice(&[0; 8]);
        h.bytes
    };
    assert_eq!(parse(&odd), Err(Malformed));
}

#[test]
fn a_length_above_the_limit_is_refused_before_reading() {
    let mut h = [0_u8; 16];
    h[0] = b'l';
    h[1] = 4;
    h[3] = 1;
    h[4..8].copy_from_slice(&(MAX_MESSAGE as u32).to_le_bytes());
    assert_eq!(total_length(&h), Err(Malformed));
    h[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    h[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(total_length(&h), Err(Malformed));
}

#[test]
fn a_string_with_a_zero_byte_or_bad_utf8_is_malformed() {
    let good = message(4, 1, &[F::S(3, "Result")], &[Value::Str("ab".into())]);
    let at = good.len() - 3; // the "a" of the body string
    let mut zero = good.clone();
    zero[at] = 0;
    assert_eq!(parse(&zero), Err(Malformed));
    let mut utf8 = good.clone();
    utf8[at] = 0xff;
    assert_eq!(parse(&utf8), Err(Malformed));
}

fn triple(a: &str, b: &str, c: &str) -> (String, String, String) {
    (a.into(), b.into(), c.into())
}

#[test]
fn a_list_of_conditions_is_read() {
    for items in [
        vec![],
        vec![triple(
            "tpm-cleared",
            "severe",
            "The TPM no longer holds the key.",
        )],
        // The first element ends off an 8-byte boundary, so the second starts after padding.
        vec![
            triple("a", "b", "c"),
            triple(
                "context-unsatisfiable: sudo",
                "severe",
                "sudo cannot be unlocked.",
            ),
        ],
    ] {
        let reply = message(2, 5, &[F::U(5, 9)], &[Value::Triples(items.clone())]);
        assert_eq!(
            parse(&reply).unwrap().body,
            vec![Value::Triples(items.clone())]
        );
        // The module's own test writer gives the same bytes.
        let mine = encode_for_tests(&parse(&reply).unwrap());
        assert_eq!(parse(&mine).unwrap().body, vec![Value::Triples(items)]);
    }
}

#[test]
fn a_list_of_conditions_that_does_not_add_up_is_malformed_and_never_a_panic() {
    let good = message(
        2,
        5,
        &[F::U(5, 9)],
        &[Value::Triples(vec![
            triple("a", "b", "c"),
            triple("dd", "e", "f"),
        ])],
    );
    assert!(parse(&good).is_ok());
    for at in 0..good.len() {
        for value in [0_u8, 1, 3, 0x7f, 0xff] {
            let mut bad = good.clone();
            bad[at] = value;
            let _ = parse(&bad);
        }
    }
    // The array's length is the first four bytes of the body, which is the end of the message.
    let body_at = good.len() - (u32::from_le_bytes(good[4..8].try_into().unwrap()) as usize);
    for wrong in [0_u32, 1, 15, 1000] {
        let mut bad = good.clone();
        bad[body_at..body_at + 4].copy_from_slice(&wrong.to_le_bytes());
        assert_eq!(parse(&bad), Err(Malformed), "length {wrong}");
    }
}

#[test]
fn the_prompt_status_seed_is_a_valid_reply() {
    let seed = include_bytes!("../../../fuzz/seeds/bus_message/prompt_status_reply");
    let m = parse(seed).unwrap();
    assert_eq!((m.kind, m.reply_serial), (Kind::Return, Some(3)));
    let [Value::Triples(items)] = m.body.as_slice() else {
        panic!("{:?}", m.body)
    };
    assert_eq!(items.len(), 2);
    assert_eq!(items[1].0, "context-unsatisfiable: login");
}
