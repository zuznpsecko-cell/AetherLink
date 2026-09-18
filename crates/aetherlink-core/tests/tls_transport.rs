//! TDD RED: TLS 1.3-only transport with ALPN (G1).
//!
//! Localhost handshake over `aetherlink_core::tls`: version must be TLS 1.3,
//! ALPN must negotiate `h2`, bytes must flow. Negative paths (TLS 1.2-only
//! client, plaintext probe) must fail the handshake, never yield a tunnel.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use aetherlink_core::tls;

mod tls_common;
use tls_common::{client_tls_config, localhost_cert, server_tls_config, AcceptAll};

#[test]
fn tls13_handshake_negotiates_h2_and_echoes() {
    // Given: TLS1.3-only server + accepting client
    let (chain, key_der) = localhost_cert();
    let server_cfg = Arc::new(tls::server_config(chain, &key_der).expect("server cfg"));
    let client_cfg = Arc::new(tls::client_config(Arc::new(AcceptAll)).expect("client cfg"));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut tls = tls::accept_tls(sock, &server_cfg).expect("server handshake");
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).expect("server read");
        tls.write_all(&buf).expect("server echo");
    });

    // When: client connects with SNI localhost
    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let name = tls::server_name("localhost").expect("sni");
    let mut tls = tls::connect_tls(sock, name, &client_cfg).expect("client handshake");

    // Then: TLS 1.3, ALPN h2, transparent bytes
    assert_eq!(
        tls.conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(tls.conn.alpn_protocol(), Some(b"h2".as_slice()));
    tls.write_all(b"ping").expect("write");
    let mut back = [0u8; 4];
    tls.read_exact(&mut back).expect("read");
    assert_eq!(&back, b"ping");
    server.join().expect("server thread");
}

#[test]
fn tls12_only_client_is_rejected() {
    // Given: TLS1.3-only server
    let (chain, key_der) = localhost_cert();
    let server_cfg = Arc::new(tls::server_config(chain, &key_der).expect("server cfg"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        // When: TLS1.2-only client offers handshake
        // Then: server must fail it (TLS 1.3 ONLY)
        assert!(tls::accept_tls(sock, &server_cfg).is_err());
    });

    let legacy_cfg =
        Arc::new(tls::client_config_tls12(Arc::new(AcceptAll)).expect("legacy client cfg"));
    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let name = tls::server_name("localhost").expect("sni");
    assert!(tls::connect_tls(sock, name, &legacy_cfg).is_err());
    server.join().expect("server thread");
}

#[test]
fn plaintext_probe_is_rejected() {
    // Given: TLS server
    let (chain, key_der) = localhost_cert();
    let server_cfg = Arc::new(tls::server_config(chain, &key_der).expect("server cfg"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        // When: browser-lookalike plaintext arrives instead of ClientHello
        // Then: handshake fails, no tunnel is ever yielded
        assert!(tls::accept_tls(sock, &server_cfg).is_err());
    });

    let mut raw = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    raw.write_all(b"GET / HTTP/1.0\r\n\r\n").expect("probe");
    server.join().expect("server thread");
}
