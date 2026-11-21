//! The TPM key service against a software TPM (swtpm): a real TPM 2.0 implementation, so the
//! authorisation checks, the in-place change and the dictionary-attack lockout are the TPM's own.
//!
//! Each test starts its own swtpm with an empty state, so the dictionary-attack counter of one test
//! never reaches another. Without `swtpm` the tests say so and return; set
//! `LH_REQUIRE_SWTPM=1` (CI does) to make its absence a failure. There is no hardware TPM here:
//! what a real chip does is not tested.

use std::process::{Command, Stdio};

use linuxhello_tpm_provider::keys::{Blobs, TpmError, AUTH_BYTES};
use linuxhello_tpm_provider::testing::SoftTpm;
use linuxhello_tpm_provider::wire::TpmLimits;

/// An authorisation value of 32 bytes made of `b`.
fn auth(b: u8) -> [u8; AUTH_BYTES] {
    [b; AUTH_BYTES]
}

#[test]
fn the_right_pin_opens_the_root_key_and_a_wrong_one_does_not() {
    let Some(soft) = SoftTpm::start() else { return };
    let mut tpm = soft.open();
    let blobs = tpm.enrol(&auth(7)).unwrap();
    assert_eq!(tpm.verify(&blobs, &auth(7)), Ok(true));
    assert_eq!(tpm.verify(&blobs, &auth(8)), Ok(false));
    // And the right one still works afterwards: a wrong try changes nothing in the key.
    assert_eq!(tpm.verify(&blobs, &auth(7)), Ok(true));
}

#[test]
fn the_blobs_survive_a_new_connection() {
    let Some(soft) = SoftTpm::start() else { return };
    let blobs = soft.open().enrol(&auth(7)).unwrap();
    // A new connection makes the primary again, identically, and the stored blobs open under it.
    assert_eq!(soft.open().verify(&blobs, &auth(7)), Ok(true));
}

#[test]
fn another_users_key_does_not_open_with_this_users_pin() {
    let Some(soft) = SoftTpm::start() else { return };
    let mut tpm = soft.open();
    let anna = tpm.enrol(&auth(1)).unwrap();
    let ben = tpm.enrol(&auth(2)).unwrap();
    assert_ne!(anna, ben, "two keys, two sets of blobs");
    assert_eq!(tpm.verify(&anna, &auth(1)), Ok(true));
    assert_eq!(tpm.verify(&ben, &auth(1)), Ok(false));
    assert_eq!(tpm.verify(&ben, &auth(2)), Ok(true));
}

#[test]
fn the_pin_changes_in_place() {
    let Some(soft) = SoftTpm::start() else { return };
    let mut tpm = soft.open();
    let old = tpm.enrol(&auth(1)).unwrap();
    let new = tpm.change_auth(&old, &auth(1), &auth(2)).unwrap();
    assert_eq!(tpm.verify(&new, &auth(2)), Ok(true));
    assert_eq!(
        tpm.verify(&new, &auth(1)),
        Ok(false),
        "the old PIN does not open the new blobs"
    );
    // No revocation: the old blobs still open with the old PIN, until they are deleted (spike 0011).
    assert_eq!(tpm.verify(&old, &auth(1)), Ok(true));
}

#[test]
fn changing_the_pin_needs_the_old_one() {
    let Some(soft) = SoftTpm::start() else { return };
    let mut tpm = soft.open();
    let blobs = tpm.enrol(&auth(1)).unwrap();
    assert!(matches!(
        tpm.change_auth(&blobs, &auth(9), &auth(2)),
        Err(TpmError::Failed(_))
    ));
    assert_eq!(tpm.verify(&blobs, &auth(1)), Ok(true), "nothing changed");
}

#[test]
fn damaged_blobs_are_an_error_and_not_a_wrong_pin() {
    let Some(soft) = SoftTpm::start() else { return };
    let mut tpm = soft.open();
    let good = tpm.enrol(&auth(1)).unwrap();
    for damaged in [
        Blobs {
            public: Vec::new(),
            ..good.clone()
        },
        Blobs {
            private: vec![1, 2, 3],
            ..good.clone()
        },
        Blobs {
            private: good.private.iter().rev().copied().collect(),
            ..good.clone()
        },
    ] {
        assert!(matches!(
            tpm.verify(&damaged, &auth(1)),
            Err(TpmError::Failed(_))
        ));
    }
}

/// Sets the dictionary-attack parameters of the TPM to `tries`, `interval` and `recovery` with the
/// tools of tpm2-tools; `None` when they are not installed or refuse.
fn set_limits(soft: &SoftTpm, tries: u32, interval: u32, recovery: u32) -> Option<()> {
    let status = Command::new("tpm2_dictionarylockout")
        .args([
            "--setup-parameters".to_string(),
            format!("--max-tries={tries}"),
            format!("--recovery-time={interval}"),
            format!("--lockout-recovery-time={recovery}"),
        ])
        .env(
            "TPM2TOOLS_TCTI",
            format!("swtpm:host=127.0.0.1,port={}", soft.port),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    status.success().then_some(())
}

#[test]
fn the_tpm_reports_its_own_dictionary_attack_limits() {
    let Some(soft) = SoftTpm::start() else { return };
    if set_limits(&soft, 7, 111, 222).is_none() {
        assert!(
            std::env::var("LH_REQUIRE_SWTPM").is_err(),
            "tpm2-tools are required here"
        );
        eprintln!("SKIPPED: tpm2_dictionarylockout is not installed or refused");
        return;
    }
    let mut tpm = soft.open();
    assert_eq!(
        tpm.limits(),
        Ok(TpmLimits {
            max_tries: 7,
            interval_secs: 111,
            recovery_secs: 222
        })
    );
}

/// Sets the dictionary-attack parameters of the TPM so that three wrong authorisations lock it, with
/// the tools of tpm2-tools; `None` when they are not installed.
fn lock_after_three(soft: &SoftTpm) -> Option<()> {
    let status = Command::new("tpm2_dictionarylockout")
        .args([
            "--setup-parameters",
            "--max-tries=3",
            "--recovery-time=1000",
            "--lockout-recovery-time=1000",
        ])
        .env(
            "TPM2TOOLS_TCTI",
            format!("swtpm:host=127.0.0.1,port={}", soft.port),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    status.success().then_some(())
}

#[test]
fn the_tpms_lockout_is_told_apart_from_a_wrong_pin() {
    let Some(soft) = SoftTpm::start() else { return };
    if lock_after_three(&soft).is_none() {
        assert!(
            std::env::var("LH_REQUIRE_SWTPM").is_err(),
            "tpm2-tools are required here"
        );
        eprintln!("SKIPPED: tpm2_dictionarylockout is not installed or refused");
        return;
    }
    let mut tpm = soft.open();
    let blobs = tpm.enrol(&auth(1)).unwrap();
    for _ in 0..3 {
        assert_eq!(tpm.verify(&blobs, &auth(9)), Ok(false));
    }
    // The TPM is now in lockout: even the right PIN gets no answer, and that is not "wrong".
    assert_eq!(tpm.verify(&blobs, &auth(1)), Err(TpmError::Locked));
}

#[test]
fn a_key_from_a_tpm_that_was_cleared_is_told_apart_from_a_wrong_pin() {
    let Some(first) = SoftTpm::start() else {
        return;
    };
    let Some(second) = SoftTpm::start() else {
        return;
    };
    let blobs = first.open().enrol(&auth(1)).unwrap();
    // The same TPM still loads it; another TPM state (a cleared one has a new seed) does not.
    assert_eq!(first.open().root_key_loads(&blobs), Ok(true));
    assert_eq!(second.open().root_key_loads(&blobs), Ok(false));
    // That is not a wrong PIN and not a lockout: nothing was counted.
    let mut other = second.open();
    assert!(matches!(
        other.verify(&blobs, &auth(1)),
        Err(TpmError::Failed(_))
    ));
}

#[test]
fn a_damaged_blob_is_not_a_cleared_tpm_but_does_not_load_either() {
    let Some(soft) = SoftTpm::start() else { return };
    let mut tpm = soft.open();
    let mut blobs = tpm.enrol(&auth(1)).unwrap();
    let last = blobs.private.len() - 1;
    blobs.private[last] ^= 0xff;
    // The check cannot tell the two apart, and says so by answering "does not load".
    assert_eq!(tpm.root_key_loads(&blobs), Ok(false));
}

#[test]
fn a_software_tpm_keeps_no_connection_of_the_test_process_open() {
    use std::io::Read;
    // A connection whose client end children inherit, as libtss2 opens its connections to swtpm.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    rustix::io::fcntl_setfd(&client, rustix::io::FdFlags::empty()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    // A software TPM started (and answering) while the connection is open...
    let Some(soft) = SoftTpm::start() else { return };
    // ...does not keep it open once its owner closes it: the other end reads the end of the stream.
    drop(client);
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    assert_eq!(
        server.read(&mut [0_u8; 1]).map_err(|e| e.kind()),
        Ok(0),
        "swtpm {} holds the test's connection",
        soft.pid()
    );
}
