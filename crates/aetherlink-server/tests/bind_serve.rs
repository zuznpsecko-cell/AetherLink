//! TDD RED: server bind + serve-once over a live listener (Phase I2).
//!
//! No pre-registered routes: the server learns dial targets from the
//! client's OPEN frames, serves static from the configured root file,
//! and fails bind fast on bad address or missing static root.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use aetherlink_frame::codec::FrameHeader;
use aetherlink_protocol::{FrameType, PROTOCOL_VERSION};
use bytes::BytesMut;

use aetherlink_server::accept::Path;

mod wire_help;

const PSK: &[u8] = b"phase-i2-test-psk-32-bytes-long!!!";

/// Test server with real PEM files + static root in a temp dir.
fn test_server(listen: &str, static_body: &[u8]) -> aetherlink_server::Server {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aether-i2-{nanos}"));
    std::fs::create_dir_all(&dir).expect("static dir");
    std::fs::write(dir.join("index.html"), static_body).expect("static file");
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, key.cert.pem()).expect("cert");
    std::fs::write(&key_path, key.key_pair.serialize_pem()).expect("key");
    let doc = serde_json::json!({
        "listen": listen,
        "psk": String::from_utf8_lossy(PSK),
        "local_static_root": dir.to_str().expect("utf8"),
        "tls_cert": cert_path.to_str().expect("utf8"),
        "tls_key": key_path.to_str().expect("utf8"),
    });
    let mut server = aetherlink_server::Server::new(doc).expect("server new");
    // Keep the temp dir alive for the test duration via the config path.
    let _ = &server.config.local_static_root;
    server
}

fn client_tls(port: u16) -> aetherlink_core::tls::ClientTlsStream {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

    #[derive(Debug)]
    struct AcceptAll;
    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end: &CertificateDer<'_>,
            _mid: &[CertificateDer<'_>],
            _name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ECDSA_NISTP256_SHA256]
        }
    }

    let cfg =
        Arc::new(aetherlink_core::tls::client_config(Arc::new(AcceptAll)).expect("client cfg"));
    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let name = aetherlink_core::tls::server_name("localhost").expect("sni");
    aetherlink_core::tls::connect_tls(sock, name, &cfg).expect("client tls")
}

#[test]
fn bind_serves_open_driven_tcp_echo() {
    // Given: echo target + bound server learning routes from OPEN frames
    let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
    let echo_port = echo.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let (mut sock, _) = echo.accept().expect("echo accept");
        let mut buf = [0u8; 5];
        sock.read_exact(&mut buf).expect("echo read");
        sock.write_all(&buf).expect("echo write");
    });
    let server = test_server("127.0.0.1:0", b"<html><body>parking</body></html>");
    let bound = server.bind().expect("bind");
    let port = bound.local_addr().expect("local addr").port();
    let server = std::thread::spawn(move || {
        // Then: valid AUTH over a live listener yields the tunnel path.
        assert_eq!(bound.serve_once(), Path::Tunnel);
    });

    // When: handshake + OPEN + DATA, no pre-registered routes anywhere
    let mut stream = client_tls(port);
    let nonce = [0xE2u8; 32];
    let mut sess =
        aetherlink_core::session::handshake_client(&mut stream, PSK, &nonce).expect("client hs");
    let id = sess.mux.open_tcp("127.0.0.1", echo_port).expect("open");
    let open = sess
        .mux
        .seal_open_tcp(sess.keys.tx_key(), id, 128)
        .expect("seal open");
    wire_help::write_frame(&mut stream, &open.header, &open.ciphertext);
    let sealed = sess
        .mux
        .seal_data(sess.keys.tx_key(), id, b"hello", 128)
        .expect("seal data");
    wire_help::write_frame(&mut stream, &sealed.header, &sealed.ciphertext);
    // Then: echo returns through the learned route.
    let (header, ct) = wire_help::read_frame(&mut stream);
    let back = sess
        .mux
        .open_data(sess.keys.rx_key(), &header, &ct)
        .expect("open reply");
    assert_eq!(back, b"hello");
    drop(stream);
    server.join().expect("server thread");
}

#[test]
fn background_serve_echo_then_stop() {
    // Given: echo target + background-serving bound server
    let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
    let echo_port = echo.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let (mut sock, _) = echo.accept().expect("echo accept");
        let mut buf = [0u8; 5];
        sock.read_exact(&mut buf).expect("echo read");
        sock.write_all(&buf).expect("echo write");
    });
    let server = test_server("127.0.0.1:0", b"<html><body>parking</body></html>");
    let bound = server.bind().expect("bind");
    let port = bound.local_addr().expect("local addr").port();
    // When: serving in background while the test drives a full exchange
    let mut guard = bound.serve_background();
    let mut stream = client_tls(port);
    let nonce = [0xE3u8; 32];
    let mut sess =
        aetherlink_core::session::handshake_client(&mut stream, PSK, &nonce).expect("client hs");
    let id = sess.mux.open_tcp("127.0.0.1", echo_port).expect("open");
    let open = sess
        .mux
        .seal_open_tcp(sess.keys.tx_key(), id, 128)
        .expect("seal open");
    wire_help::write_frame(&mut stream, &open.header, &open.ciphertext);
    let sealed = sess
        .mux
        .seal_data(sess.keys.tx_key(), id, b"hello", 128)
        .expect("seal data");
    wire_help::write_frame(&mut stream, &sealed.header, &sealed.ciphertext);
    let (header, ct) = wire_help::read_frame(&mut stream);
    let back = sess
        .mux
        .open_data(sess.keys.rx_key(), &header, &ct)
        .expect("open reply");
    assert_eq!(back, b"hello");
    // Then: orderly stop joins promptly (no wedged accept loop).
    drop(stream);
    guard.request_stop();
    let started = std::time::Instant::now();
    guard.join();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "stop must join fast"
    );
}

#[test]
fn bind_serves_static_body_from_file() {
    // Given: static root holding a marker page
    let server = test_server("127.0.0.1:0", b"<html><body>MARKER-42</body></html>");
    let bound = server.bind().expect("bind");
    let port = bound.local_addr().expect("local addr").port();
    let server = std::thread::spawn(move || {
        // Then: bad AUTH over a live listener yields the file body.
        assert_eq!(bound.serve_once(), Path::Static);
    });

    // When: well-formed AUTH frame with a bad token over valid TLS
    let mut stream = client_tls(port);
    stream.write_all(&[PROTOCOL_VERSION]).expect("preface");
    let mut hb = BytesMut::new();
    FrameHeader {
        length: 64,
        frame_type: FrameType::Auth,
        flags: 0,
        stream_id: 0,
        sequence: 0,
    }
    .encode(&mut hb);
    stream.write_all(&hb).expect("header");
    stream.write_all(&[0xABu8; 64]).expect("bad auth body");
    stream.flush().expect("flush");
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).expect("read static");
    let text = String::from_utf8_lossy(&resp);
    // Then: the marker page from the configured root, no banner.
    assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
    assert!(text.contains("MARKER-42"));
    let lower = text.to_lowercase();
    for banned in ["tunnel", "proxy", "vpn"] {
        assert!(!lower.contains(banned), "banner leak: {banned}");
    }
    drop(stream);
    server.join().expect("server thread");
}

#[test]
fn bind_rejects_bad_listen_addr() {
    // Given: unbindable address → Then: fast Err, no panic.
    let server = test_server("256.256.256.256:443", b"x");
    assert!(server.bind().is_err());
}

#[test]
fn bind_rejects_missing_static_root() {
    // Given: static root without index.html → Then: fast Err (G2 needs it).
    let mut server = test_server("127.0.0.1:0", b"x");
    server.config.local_static_root = "/nonexistent-aether-root".to_string();
    assert!(server.bind().is_err());
}
