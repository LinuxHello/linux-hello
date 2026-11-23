//! Tests of the notification socket.

use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use super::*;

#[test]
fn a_watchdog_ping_is_one_datagram_to_the_notify_socket() {
    let dir = crate::private_tempdir();
    let path = dir.path().join("notify");
    let server = UnixDatagram::bind(&path).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let notifier = Notifier::parse(path.to_str().unwrap()).unwrap();
    notifier.watchdog().unwrap();
    let mut buffer = [0_u8; 64];
    let length = server.recv(&mut buffer).unwrap();
    assert_eq!(&buffer[..length], b"WATCHDOG=1");
}

#[test]
fn an_abstract_notify_socket_receives_the_ping() {
    use std::os::linux::net::SocketAddrExt;
    let name = format!("linuxhello-test-notify-{}", std::process::id());
    let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let server = UnixDatagram::bind_addr(&address).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    Notifier::parse(&format!("@{name}"))
        .unwrap()
        .watchdog()
        .unwrap();
    let mut buffer = [0_u8; 64];
    let length = server.recv(&mut buffer).unwrap();
    assert_eq!(&buffer[..length], b"WATCHDOG=1");
}

#[test]
fn a_missing_socket_is_an_error_not_a_panic() {
    let notifier = Notifier::parse("/nonexistent/linuxhello/notify").unwrap();
    assert!(notifier.watchdog().is_err());
}

#[test]
fn notify_socket_names_are_a_path_or_an_abstract_name() {
    assert!(Notifier::parse("/run/systemd/notify").is_some());
    assert!(Notifier::parse("@/org/freedesktop/systemd1/notify").is_some());
    for bad in ["", "@", "relative/path", "notify", "vsock:1:2"] {
        assert_eq!(Notifier::parse(bad), None, "{bad:?}");
    }
}

#[test]
fn the_ping_interval_is_half_the_watchdog_time() {
    assert_eq!(interval_from("30000000"), Some(Duration::from_secs(15)));
    assert_eq!(interval_from(" 2000000\n"), Some(Duration::from_secs(1)));
    for bad in ["", "0", "1", "-5", "abc", "1.5"] {
        assert_eq!(interval_from(bad), None, "{bad:?}");
    }
}
