//! TDD RED: client transport connect — TCP + TLS + AUTH handshake (Phase I3).
//!
//! `lifecycle::connect` resolves once, connects TLS with SNI, handshakes,
//! and returns the live stream plus session (mux + keys). A custom verifier
//! can be injected for tests; production passes `None` (system roots).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use aetherlink_client::config::ClientConfig;
use aetherlink_client::lifecycle;
use aetherlink_crypto::auth::NonceCache;

mod tls_accept_all;

use tls_accept_all::AcceptAll;

const PSK: &[u8] = b"phase-i3-test-psk-32-bytes-long!!!";

fn test_config(addr: &str) -> ClientConfig {
    ClientConfig::parse(&serde_json::json!({
        "server_addr": addr,
        "psk": String::from_utf8_lossy(PSK),
        "dns_mode": "tunnel",
    }))
    .expect("test config")
}

#[test]
fn connect_handshakes_and_exchanges_data() {
    // Given: TLS server answering handshake + one DATA echo
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let chain = vec![rustls::pki_types::CertificateDer::from(
        key.cert.der().to_vec(),
    )];
    let key_der = key.key_pair.serialize_der();
    let server_cfg =
        Arc::new(aetherlink_core::tls::server_config(chain, &key_der).expect("server cfg"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let cache = NonceCache::new();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut stream = aetherlink_core::tls::accept_tls(sock, &server_cfg).expect("server tls");
        let mut sess = aetherlink_core::session::handshake_server(&mut stream, PSK, &cache)
            .expect("server hs");
        sess.mux.open_tcp("10.9.9.9", 80).expect("server open");
        // Read one sealed frame, open it, seal the echo back.
        let mut hb = [0u8; aetherlink_frame::FRAME_HEADER_SIZE];
        stream.read_exact(&mut hb).expect("read header");
        let mut hbuf = bytes::BytesMut::from(&hb[..]);
        let header =
            aetherlink_frame::codec::FrameHeader::decode(&mut hbuf).expect("decode header");
        let mut ct = vec![0u8; header.length as usize];
        stream.read_exact(&mut ct).expect("read ct");
        let pt = sess
            .mux
            .open_data(sess.keys.rx_key(), &header, &ct)
            .expect("server open");
        let sealed = sess
            .mux
            .seal_data(sess.keys.tx_key(), 1, &pt, 128)
            .expect("server seal");
        let mut out = bytes::BytesMut::new();
        sealed.header.encode(&mut out);
        stream.write_all(&out).expect("write header");
        stream.write_all(&sealed.ciphertext).expect("write ct");
        stream.flush().expect("flush");
    });

    // When: lifecycle connect with a test verifier
    let mut up = lifecycle::connect(
        &test_config(&format!("127.0.0.1:{port}")),
        Some(Arc::new(AcceptAll)),
    )
    .expect("connect");
    let id = up.sess.mux.open_tcp("10.9.9.9", 80).expect("open");
    let sealed = up
        .sess
        .mux
        .seal_data(up.sess.keys.tx_key(), id, b"ping", 128)
        .expect("seal");
    let mut out = bytes::BytesMut::new();
    sealed.header.encode(&mut out);
    up.stream.write_all(&out).expect("write header");
    up.stream.write_all(&sealed.ciphertext).expect("write ct");
    up.stream.flush().expect("flush");
    // Then: echo returns through the live transport.
    let mut hb = [0u8; aetherlink_frame::FRAME_HEADER_SIZE];
    up.stream.read_exact(&mut hb).expect("read header");
    let mut hbuf = bytes::BytesMut::from(&hb[..]);
    let header = aetherlink_frame::codec::FrameHeader::decode(&mut hbuf).expect("decode");
    let mut ct = vec![0u8; header.length as usize];
    up.stream.read_exact(&mut ct).expect("read ct");
    let back = up
        .sess
        .mux
        .open_data(up.sess.keys.rx_key(), &header, &ct)
        .expect("open");
    assert_eq!(back, b"ping");
    drop(up);
    server.join().expect("server thread");
}

#[test]
fn connect_fails_fast_on_refused_port() {
    // Given: a port nothing listens on (bound then released)
    let probe = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);
    // When: connecting → Then: fast Err, no hang.
    let started = std::time::Instant::now();
    assert!(lifecycle::connect(
        &test_config(&format!("127.0.0.1:{port}")),
        Some(Arc::new(AcceptAll)),
    )
    .is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[test]
fn connections_get_isolated_keys() {
    // Given: one server, one shared replay cache
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let chain = vec![rustls::pki_types::CertificateDer::from(
        key.cert.der().to_vec(),
    )];
    let key_der = key.key_pair.serialize_der();
    let server_cfg =
        Arc::new(aetherlink_core::tls::server_config(chain, &key_der).expect("server cfg"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let cache = NonceCache::new();
    // Server side: handshake twice, keep both sessions' keys.
    let server = std::thread::spawn(move || {
        let mut keys = Vec::new();
        for _ in 0..2 {
            let (sock, _) = listener.accept().expect("accept");
            let mut stream =
                aetherlink_core::tls::accept_tls(sock, &server_cfg).expect("server tls");
            let sess = aetherlink_core::session::handshake_server(&mut stream, PSK, &cache)
                .expect("server hs");
            keys.push(sess.keys.tx_key().to_vec());
        }
        keys
    });

    // When: client connects twice (fresh random nonce each time)
    let mut up1 = lifecycle::connect(
        &test_config(&format!("127.0.0.1:{port}")),
        Some(Arc::new(AcceptAll)),
    )
    .expect("connect 1");
    let mut up2 = lifecycle::connect(
        &test_config(&format!("127.0.0.1:{port}")),
        Some(Arc::new(AcceptAll)),
    )
    .expect("connect 2");
    let server_keys = server.join().expect("server thread");

    // Then: traffic keys differ per connection...
    assert_ne!(up1.sess.keys.tx_key(), up2.sess.keys.tx_key());
    assert_eq!(server_keys.len(), 2);
    assert_ne!(server_keys[0], server_keys[1]);
    // ...and a frame sealed under conn-1 does not open under conn-2 keys.
    let id = up1.sess.mux.open_tcp("10.9.9.9", 80).expect("open");
    let sealed = up1
        .sess
        .mux
        .seal_data(up1.sess.keys.tx_key(), id, b"secret", 128)
        .expect("seal");
    up2.sess.mux.open_tcp("10.9.9.9", 80).expect("open");
    assert!(
        up2.sess
            .mux
            .open_data(up2.sess.keys.rx_key(), &sealed.header, &sealed.ciphertext)
            .is_err(),
        "cross-connection open must fail"
    );
    drop(up1);
    drop(up2);
}
