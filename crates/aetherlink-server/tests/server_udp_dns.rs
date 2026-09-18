//! TDD RED: server UDP relay + DNS upstream resolve.
//!
//! The server turns UDP flows (incl. virtual-DNS queries) into plain UDP
//! towards the target/upstream and relays the reply back. No external
//! network: fake local UDP echo + canned DNS answer.

use std::net::UdpSocket;
use std::time::Duration;

use aetherlink_server::{dns, relay};

const TIMEOUT: Duration = Duration::from_secs(2);

/// Local UDP echo helper: replies every datagram back to sender.
fn echo_server() -> (u16, std::thread::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind echo");
    let port = sock.local_addr().expect("addr").port();
    let h = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let (n, from) = sock.recv_from(&mut buf).expect("echo recv");
        sock.send_to(&buf[..n], from).expect("echo send");
    });
    (port, h)
}

#[test]
fn udp_relay_echoes_payload() {
    // Given: local UDP echo target
    let (port, h) = echo_server();
    // When: relaying one datagram
    let back = relay::relay_udp("127.0.0.1", port, b"datagram-1", TIMEOUT).expect("relay");
    // Then: transparent roundtrip
    assert_eq!(back, b"datagram-1");
    h.join().expect("echo thread");
}

#[test]
fn udp_relay_times_out_on_silence() {
    // Given: unroutable TEST-NET target (RFC 5737, nothing answers)
    // When: relaying with a short timeout
    // Then: bounded Err, never hangs the mux
    let err = relay::relay_udp("192.0.2.1", 53, b"q", Duration::from_millis(200));
    assert!(err.is_err());
}

#[test]
fn dns_resolve_returns_upstream_answer_verbatim() {
    // Given: fake upstream answering a canned DNS response
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind dns");
    let port = sock.local_addr().expect("addr").port();
    let query = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00".to_vec();
    let answer = b"\xab\xcd\x81\x80\x00\x01\x00\x01".to_vec();
    let h = std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (n, from) = sock.recv_from(&mut buf).expect("dns recv");
        assert_eq!(&buf[..n], query.as_slice(), "query must arrive verbatim");
        sock.send_to(&answer, from).expect("dns send");
    });
    // When: server resolves through it
    let upstream = format!("127.0.0.1:{port}");
    let back = dns::resolve(
        b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        &upstream,
        TIMEOUT,
    )
    .expect("resolve");
    // Then: upstream answer relayed byte-identical
    assert_eq!(back, b"\xab\xcd\x81\x80\x00\x01\x00\x01");
    h.join().expect("dns thread");
}

#[test]
fn dns_resolve_times_out_on_silence() {
    // Given: silent upstream
    // When: resolving with a short timeout
    // Then: bounded Err
    let err = dns::resolve(b"q", "192.0.2.1:53", Duration::from_millis(200));
    assert!(err.is_err());
}
