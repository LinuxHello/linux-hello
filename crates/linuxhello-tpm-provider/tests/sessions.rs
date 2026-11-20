//! The authorisation value never crosses the TPM interface in clear (ADR-0021, decision 3).
//!
//! A recording proxy sits between the key service and a software TPM and keeps every byte the
//! service sends. A control first shows that the method sees what it should: a plain password
//! session puts the value into the stream. Then enrolling, checking and changing a PIN through the
//! key service must leave neither the old nor the new value in it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use linuxhello_tpm_provider::keys::{Tpm, AUTH_BYTES};
use linuxhello_tpm_provider::testing::SoftTpm;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{Auth, RsaExponent, SymmetricDefinitionObject};
use tss_esapi::utils::create_restricted_decryption_rsa_public;
use tss_esapi::{Context, TctiNameConf};

/// A proxy to the software TPM that records what the client sends on the data channel.
struct Recorder {
    /// The `swtpm:` TCTI string that points at the proxy.
    tcti: String,
    /// Every byte the client sent so far.
    sent: Arc<Mutex<Vec<u8>>>,
}

/// Copies `from` to `to` until either ends, handing every chunk to `record`.
fn pump(mut from: TcpStream, mut to: TcpStream, record: impl Fn(&[u8]) + Send + 'static) {
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        while let Ok(n) = from.read(&mut buffer) {
            // Recorded before it is forwarded, so that the TPM's answer cannot be read by the test
            // before the request is in the log.
            record(&buffer[..n]);
            if n == 0 || to.write_all(&buffer[..n]).is_err() {
                break;
            }
        }
        let _ = to.shutdown(std::net::Shutdown::Both);
    });
}

/// Accepts connections on `listener` and forwards each to `target`.
fn forward(listener: TcpListener, target: u16, record: impl Fn(&[u8]) + Send + Clone + 'static) {
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let Ok(server) = TcpStream::connect(("127.0.0.1", target)) else {
                continue;
            };
            pump(
                client.try_clone().unwrap(),
                server.try_clone().unwrap(),
                record.clone(),
            );
            pump(server, client, |_| {});
        }
    });
}

impl Recorder {
    /// A proxy in front of `soft` on two adjacent free ports, data and control.
    fn start(soft: &SoftTpm) -> Self {
        let sent = Arc::new(Mutex::new(Vec::new()));
        loop {
            let data = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = data.local_addr().unwrap().port();
            let Ok(control) = TcpListener::bind(("127.0.0.1", port + 1)) else {
                continue;
            };
            let log = Arc::clone(&sent);
            forward(data, soft.port, move |bytes| {
                log.lock().unwrap().extend_from_slice(bytes);
            });
            forward(control, soft.port + 1, |_| {});
            return Self {
                tcti: format!("swtpm:host=127.0.0.1,port={port}"),
                sent,
            };
        }
    }

    /// Whether `needle` is anywhere in what was sent.
    fn saw(&self, needle: &[u8]) -> bool {
        self.sent
            .lock()
            .unwrap()
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// How many bytes were sent.
    fn size(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

#[test]
fn a_plain_password_session_puts_the_value_in_the_stream() {
    let Some(soft) = SoftTpm::start() else { return };
    let recorder = Recorder::start(&soft);
    let value = [0xA5_u8; AUTH_BYTES];
    let mut context = Context::new(recorder.tcti.parse::<TctiNameConf>().unwrap()).unwrap();
    let template = || {
        create_restricted_decryption_rsa_public(
            SymmetricDefinitionObject::AES_128_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .unwrap()
    };
    context
        .execute_with_session(Some(AuthSession::Password), |c| {
            let primary = c
                .create_primary(Hierarchy::Owner, template(), None, None, None, None)?
                .key_handle;
            c.create(
                primary,
                template(),
                Some(Auth::try_from(value.to_vec())?),
                None,
                None,
                None,
            )
        })
        .unwrap();
    assert!(
        recorder.saw(&value),
        "the control: the recorder must see a value sent in clear, or this test proves nothing"
    );
}

/// The key service with a recorder in front of its TPM, and three distinct values.
fn world() -> Option<(SoftTpm, Recorder, Tpm)> {
    let soft = SoftTpm::start()?;
    let recorder = Recorder::start(&soft);
    let tpm = Tpm::open(&recorder.tcti).unwrap();
    Some((soft, recorder, tpm))
}

const OLD: [u8; AUTH_BYTES] = [0x5A; AUTH_BYTES];
const NEW: [u8; AUTH_BYTES] = [0x3C; AUTH_BYTES];
const WRONG: [u8; AUTH_BYTES] = [0xC3; AUTH_BYTES];

#[test]
fn tpm_sessions_encrypt_the_value_of_a_new_key() {
    let Some((_soft, recorder, mut tpm)) = world() else {
        return;
    };
    tpm.enrol(&OLD).unwrap();
    assert!(recorder.size() > 200, "the recorder saw almost nothing");
    assert!(
        !recorder.saw(&OLD),
        "the value of a new key crossed the TPM interface in clear"
    );
}

#[test]
fn tpm_sessions_keep_the_value_of_a_check_off_the_interface() {
    let Some((_soft, recorder, mut tpm)) = world() else {
        return;
    };
    let blobs = tpm.enrol(&OLD).unwrap();
    assert_eq!(tpm.verify(&blobs, &OLD), Ok(true));
    assert_eq!(tpm.verify(&blobs, &WRONG), Ok(false));
    for value in [&OLD, &WRONG] {
        assert!(
            !recorder.saw(value),
            "a value checked against the key crossed in clear"
        );
    }
}

#[test]
fn tpm_sessions_keep_both_values_of_a_change_off_the_interface() {
    let Some((_soft, recorder, mut tpm)) = world() else {
        return;
    };
    let blobs = tpm.enrol(&OLD).unwrap();
    let changed = tpm.change_auth(&blobs, &OLD, &NEW).unwrap();
    assert_eq!(tpm.verify(&changed, &NEW), Ok(true));
    for (name, value) in [("current", &OLD), ("new", &NEW)] {
        assert!(
            !recorder.saw(value),
            "the {name} value of a change crossed in clear"
        );
    }
}
