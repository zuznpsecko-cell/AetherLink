//! exchange_stream: one payload in, full reply flight out.
//!
//! A single read strands multi-chunk flights (TLS handshakes) in the
//! socket buffer and the peer stalls forever (seen live:
//! ERR_SSL_PROTOCOL_ERROR in the browser). The exchange therefore drains
//! until the target goes idle.

use aetherlink_server::relay;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn pair() -> (std::net::TcpStream, std::net::TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || listener.accept().expect("accept").0);
    let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    (client, server.join().expect("join"))
}

#[test]
fn two_chunks_with_gap_arrive_whole() {
    let (mut client, mut server) = pair();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).expect("srv read");
        assert_eq!(&buf[..n], b"GET");
        server.write_all(b"AB").expect("w1");
        std::thread::sleep(Duration::from_millis(150));
        server.write_all(b"CD").expect("w2");
    });
    let t = Instant::now();
    let reply = relay::exchange_stream(
        &mut client,
        b"GET",
        Duration::from_secs(2),
        Duration::from_millis(300),
    )
    .expect("exchange");
    assert_eq!(reply, b"ABCD");
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "must not wait out first timeout"
    );
}

#[test]
fn idle_open_connection_returns_what_arrived() {
    let (mut client, mut server) = pair();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).expect("srv read");
        assert_eq!(&buf[..n], b"GET");
        server.write_all(b"XY").expect("w1");
        // Hold open, send nothing more: idle timeout must release the reply.
        std::thread::sleep(Duration::from_secs(5));
    });
    let t = Instant::now();
    let reply = relay::exchange_stream(
        &mut client,
        b"GET",
        Duration::from_secs(2),
        Duration::from_millis(300),
    )
    .expect("exchange");
    assert_eq!(reply, b"XY");
    assert!(
        t.elapsed() < Duration::from_millis(1500),
        "idle must release, not stall"
    );
}
