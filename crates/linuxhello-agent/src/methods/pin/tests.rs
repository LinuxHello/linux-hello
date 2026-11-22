//! Tests of the PIN method with a verifier whose answers are scripted and a real lock on disk.

use std::sync::atomic::{AtomicU32, Ordering};

use tempfile::TempDir;

use super::*;
use crate::pinlock::service::Limits;
use crate::pinlock::store::PinLockFile;
use crate::pinsocket::PinTarget;

/// A verifier that says whether the PIN is `1234`, and counts how often it was asked.
struct Scripted {
    asked: AtomicU32,
    broken: bool,
}

impl PinVerifier for Scripted {
    fn available(&self, _uid: u32) -> bool {
        true
    }

    fn verify(&self, _uid: u32, pin: &[u8]) -> Result<bool, VerifyError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.broken {
            Err(VerifyError)
        } else {
            Ok(pin == b"1234")
        }
    }
}

/// Two wrong PINs start a lockout of ten minutes.
const LIMITS: Limits = Limits {
    max_attempts: 2,
    lockout_secs: 600,
    max_lockout_secs: 86_400,
};

/// The time of every test: second 1000.
fn at_1000() -> u64 {
    1_000
}

/// Everything a test needs: the method, its inbox, the verifier's counter and the lock.
struct Setup {
    method: PinMethod,
    inbox: Arc<PinInbox>,
    verifier: Arc<Scripted>,
    lock: Arc<PinLockService>,
    _dir: TempDir,
}

fn setup(broken: bool) -> Setup {
    let dir = crate::private_tempdir();
    let uid = std::fs::metadata(dir.path())
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap();
    let lock = Arc::new(PinLockService::start(
        PinLockFile::new(dir.path().join("pinlock.toml"), uid),
        LIMITS,
    ));
    let inbox = Arc::new(PinInbox::default());
    let verifier = Arc::new(Scripted {
        asked: AtomicU32::new(0),
        broken,
    });
    let method = PinMethod::new(
        1000,
        Arc::clone(&inbox),
        Arc::clone(&lock),
        Arc::clone(&verifier) as Arc<dyn PinVerifier>,
        at_1000,
    );
    Setup {
        method,
        inbox,
        verifier,
        lock,
        _dir: dir,
    }
}

/// Runs the method on a thread, delivers `pins` one after another (each to a fresh method), and
/// returns how each attempt ended.
fn attempt(setup: &mut Setup, pin: &[u8]) -> MethodEnd {
    let inbox = Arc::clone(&setup.inbox);
    let pin = Zeroizing::new(pin.to_vec());
    std::thread::scope(|scope| {
        let run = scope.spawn(|| setup.method.run(&Cancel::default()));
        // The method is registered from the moment it is made, so the PIN can go at once.
        assert!(inbox.deliver(1000, pin.clone()));
        run.join().unwrap()
    })
}

#[test]
fn a_correct_pin_is_a_success_and_clears_the_record() {
    let mut s = setup(false);
    s.lock.record_failure(1000, 1_000).unwrap();
    assert_eq!(attempt(&mut s, b"1234"), MethodEnd::Success);
    // The one earlier failure is forgotten: one more wrong PIN does not start a lockout.
    assert_eq!(
        attempt(&mut s, b"0000"),
        MethodEnd::Failure(PromptReason::NotRecognised)
    );
}

#[test]
fn a_wrong_pin_is_a_failure_that_counts_until_it_locks() {
    let mut s = setup(false);
    assert_eq!(
        attempt(&mut s, b"0000"),
        MethodEnd::Failure(PromptReason::NotRecognised)
    );
    assert_eq!(attempt(&mut s, b"0000"), MethodEnd::LockedOut(600));
    assert_eq!(s.verifier.asked.load(Ordering::SeqCst), 2);
}

#[test]
fn a_locked_user_is_refused_without_reaching_the_verifier() {
    let mut s = setup(false);
    s.lock.record_failure(1000, 1_000).unwrap();
    s.lock.record_failure(1000, 1_000).unwrap();
    // Even the right PIN is refused while locked, and the verifier is never asked.
    assert_eq!(attempt(&mut s, b"1234"), MethodEnd::LockedOut(600));
    assert_eq!(s.verifier.asked.load(Ordering::SeqCst), 0);
}

#[test]
fn an_untrusted_lock_makes_the_method_unavailable_and_the_verifier_is_not_asked() {
    let dir = crate::private_tempdir();
    let path = dir.path().join("pinlock.toml");
    std::fs::write(&path, "broken").unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(dir.path()).unwrap());
    let lock = Arc::new(PinLockService::start(PinLockFile::new(&path, uid), LIMITS));
    let verifier = Arc::new(Scripted {
        asked: AtomicU32::new(0),
        broken: false,
    });
    let inbox = Arc::new(PinInbox::default());
    let method = PinMethod::new(
        1000,
        Arc::clone(&inbox),
        lock,
        Arc::clone(&verifier) as Arc<dyn PinVerifier>,
        at_1000,
    );
    let mut s = Setup {
        method,
        inbox,
        verifier: Arc::clone(&verifier),
        lock: Arc::new(PinLockService::start(
            PinLockFile::new(dir.path().join("x.toml"), uid),
            LIMITS,
        )),
        _dir: dir,
    };
    assert_eq!(attempt(&mut s, b"1234"), MethodEnd::Unavailable);
    assert_eq!(verifier.asked.load(Ordering::SeqCst), 0);
}

#[test]
fn a_verifier_that_cannot_check_is_unavailable_and_counts_nothing() {
    let mut s = setup(true);
    assert_eq!(attempt(&mut s, b"1234"), MethodEnd::Unavailable);
    // Not a wrong PIN: no record was made.
    assert_eq!(
        s.lock.status_of(1000, 1_000),
        crate::pinlock::service::LockStatus::Unlocked
    );
    assert_eq!(s.lock.check(1000, 1_000), Ok(()));
}

#[test]
fn cancelling_ends_the_wait_and_the_registration() {
    let mut s = setup(false);
    let cancel = Cancel::default();
    let flag = cancel.clone();
    let inbox = Arc::clone(&s.inbox);
    let end = std::thread::scope(|scope| {
        let run = scope.spawn(|| s.method.run(&flag));
        std::thread::sleep(Duration::from_millis(150));
        cancel.cancel();
        run.join().unwrap()
    });
    assert_eq!(end, MethodEnd::Cancelled);
    // The registration lasts as long as the method does.
    drop(s);
    assert!(
        !inbox.deliver(1000, Zeroizing::new(b"1234".to_vec())),
        "nobody waits any more"
    );
}

#[test]
fn a_pin_for_nobody_who_waits_is_dropped_and_a_pin_for_another_user_is_not_taken() {
    let inbox = Arc::new(PinInbox::default());
    assert!(!inbox.deliver(1000, Zeroizing::new(b"1234".to_vec())));
    let (_waiting, receiver) = inbox.expect(1000);
    assert!(
        !inbox.deliver(1001, Zeroizing::new(b"1234".to_vec())),
        "another user's PIN"
    );
    assert!(receiver.try_recv().is_err());
    assert!(inbox.deliver(1000, Zeroizing::new(b"1234".to_vec())));
    assert_eq!(receiver.try_recv().unwrap().as_slice(), b"1234");
}

#[test]
fn the_default_verifier_checks_nothing_and_is_never_available() {
    let verifier = NoVerifier;
    assert!(!verifier.available(1000));
    assert_eq!(verifier.verify(1000, b"1234"), Err(VerifyError));
}

#[test]
fn a_pin_sent_before_the_method_runs_is_kept_for_it() {
    let mut s = setup(false);
    // Delivered at once, before `run` has even started.
    assert!(s.inbox.deliver(1000, Zeroizing::new(b"1234".to_vec())));
    assert_eq!(s.method.run(&Cancel::default()), MethodEnd::Success);
}

/// The prompt `n` of the user `opener`: 64 hexadecimal characters made from `n`.
fn target(opener: u32, n: u8) -> PinTarget {
    PinTarget {
        opener,
        prompt: linuxhello_dbus::PromptId::parse(&format!("{n:064x}")).unwrap(),
    }
}

/// What is waiting on `receiver`, if anything.
fn received(receiver: &Receiver<Zeroizing<Vec<u8>>>) -> Option<Vec<u8>> {
    receiver.try_recv().ok().map(|pin| pin.to_vec())
}

#[test]
fn a_pin_goes_only_to_the_wait_of_its_prompt() {
    let inbox = Arc::new(PinInbox::default());
    let (_wait_x, receiver_x) = inbox.expect_for(target(1000, 1)).unwrap();
    // A PIN announced for another prompt, of the same user, is not taken by this wait.
    assert!(!inbox.deliver_to(&target(1000, 2), Zeroizing::new(b"1234".to_vec())));
    assert_eq!(received(&receiver_x), None);
    // A prompt opened by another user with the same identifier is another prompt.
    assert!(!inbox.deliver_to(&target(1001, 1), Zeroizing::new(b"1234".to_vec())));
    assert_eq!(received(&receiver_x), None);
    // The prompt it waits for gets it.
    assert!(inbox.deliver_to(&target(1000, 1), Zeroizing::new(b"1234".to_vec())));
    assert_eq!(received(&receiver_x), Some(b"1234".to_vec()));
}

#[test]
fn two_prompts_of_one_user_each_get_their_own_pin() {
    let inbox = Arc::new(PinInbox::default());
    let (_wait_x, receiver_x) = inbox.expect_for(target(1000, 1)).unwrap();
    let (_wait_y, receiver_y) = inbox.expect_for(target(1000, 2)).unwrap();
    assert!(inbox.deliver_to(&target(1000, 2), Zeroizing::new(b"2222".to_vec())));
    assert!(inbox.deliver_to(&target(1000, 1), Zeroizing::new(b"1111".to_vec())));
    assert_eq!(received(&receiver_x), Some(b"1111".to_vec()));
    assert_eq!(received(&receiver_y), Some(b"2222".to_vec()));
}

#[test]
fn a_second_wait_for_a_prompt_is_refused_and_the_first_keeps_its_pin() {
    let inbox = Arc::new(PinInbox::default());
    let (_first, receiver) = inbox.expect_for(target(1000, 1)).unwrap();
    assert!(inbox.expect_for(target(1000, 1)).is_none());
    assert!(inbox.deliver_to(&target(1000, 1), Zeroizing::new(b"1234".to_vec())));
    assert_eq!(received(&receiver), Some(b"1234".to_vec()));
}

#[test]
fn a_wait_that_ends_removes_only_itself() {
    // By prompt: a refused second wait that ends takes nothing from the first.
    let inbox = Arc::new(PinInbox::default());
    let (first, receiver) = inbox.expect_for(target(1000, 1)).unwrap();
    assert!(inbox.expect_for(target(1000, 1)).is_none());
    assert!(inbox.deliver_to(&target(1000, 1), Zeroizing::new(b"1234".to_vec())));
    assert_eq!(received(&receiver), Some(b"1234".to_vec()));
    // And a wait that ends is gone: its prompt can be waited for again, and no PIN reaches it.
    drop(first);
    assert!(!inbox.deliver_to(&target(1000, 1), Zeroizing::new(b"1234".to_vec())));
    assert!(inbox.expect_for(target(1000, 1)).is_some());

    // By user: an older wait that is dropped after a newer one replaced it must not remove the
    // newer one, which still receives its PIN.
    let inbox = Arc::new(PinInbox::default());
    let (older, _older_receiver) = inbox.expect(1000);
    let (_newer, newer_receiver) = inbox.expect(1000);
    drop(older);
    assert!(inbox.deliver(1000, Zeroizing::new(b"1234".to_vec())));
    assert_eq!(received(&newer_receiver), Some(b"1234".to_vec()));
}

#[test]
fn a_method_for_a_prompt_gets_only_the_pin_announced_for_it() {
    let dir = crate::private_tempdir();
    let uid = std::fs::metadata(dir.path())
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap();
    let lock = Arc::new(PinLockService::start(
        PinLockFile::new(dir.path().join("pinlock.toml"), uid),
        LIMITS,
    ));
    let verifier = Arc::new(Scripted {
        asked: AtomicU32::new(0),
        broken: false,
    });
    let inbox = Arc::new(PinInbox::default());
    let mut method = PinMethod::for_prompt(
        1000,
        target(1000, 1),
        &inbox,
        Arc::clone(&lock),
        Arc::clone(&verifier) as Arc<dyn PinVerifier>,
        at_1000,
    )
    .unwrap();
    // A second method for the same prompt is refused.
    assert!(PinMethod::for_prompt(
        1000,
        target(1000, 1),
        &inbox,
        lock,
        verifier as Arc<dyn PinVerifier>,
        at_1000,
    )
    .is_none());
    assert!(!inbox.deliver_to(&target(1000, 2), Zeroizing::new(b"1234".to_vec())));
    assert!(inbox.deliver_to(&target(1000, 1), Zeroizing::new(b"1234".to_vec())));
    assert_eq!(method.run(&Cancel::default()), MethodEnd::Success);
}
