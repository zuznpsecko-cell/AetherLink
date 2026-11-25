//! TDD RED: server bind + serve-once over a live listener (Phase I2).
//!
//! No pre-registered routes: the server learns dial targets from the
//! client's OPEN frames, serves static from the configured root file,
//! and fails bind fast on bad address or missing static root.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use aetherlink_frame::codec::FrameHeader;
use aetherlink_protocol::{FrameType, PROTOCOL_VERSION};
use bytes::BytesMut;

use aetherlink_server::accept::Path;

mod wire_help;

const PSK: &[u8] = b"phase-i2-test-psk-32-bytes-long!!!";

/// How the test writes `key.pem`.
#[derive(Clone, Copy)]
enum KeyPem {
    /// `BEGIN PRIVATE KEY` (what rcgen emits).
    Pkcs8,
    /// `BEGIN EC PRIVATE KEY` (RFC 5915), as written by
    /// `openssl ecparam -genkey` and many ACME clients.
    Sec1,
}

/// Test server with real PEM files + static root in a temp dir.
fn test_server(listen: &str, static_body: &[u8]) -> aetherlink_server::Server {
    test_server_with_key(listen, static_body, KeyPem::Pkcs8)
}

/// Read one DER TLV: `(tag, contents, rest)`. Test-only, trusts its input.
fn der_tlv(buf: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = buf[0];
    let (len, hdr) = if buf[1] & 0x80 == 0 {
        (buf[1] as usize, 2)
    } else {
        let n = (buf[1] & 0x7F) as usize;
        let len = buf[2..2 + n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (len, 2 + n)
    };
    (tag, &buf[hdr..hdr + len], &buf[hdr + len..])
}

/// Encode one DER TLV (definite length; short or long form).
fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(contents);
    out
}

/// Turn a PKCS#8 EC key into the standalone SEC1 `ECPrivateKey` that
/// `openssl ec` / `openssl ecparam -genkey` write.
///
/// PKCS#8 = SEQUENCE { version, algorithm SEQUENCE { id-ecPublicKey,
/// namedCurve OID }, privateKey OCTET STRING { ECPrivateKey } }. Inside
/// PKCS#8 the ECPrivateKey usually omits its `[0] parameters` (the curve is in
/// the algorithm identifier); a standalone SEC1 file carries it, so it is
/// re-inserted here: ECPrivateKey = SEQUENCE { version, privateKey,
/// [0] namedCurve, [1] publicKey }.
fn pkcs8_to_sec1(pkcs8: &[u8]) -> Vec<u8> {
    let (tag, info, _) = der_tlv(pkcs8);
    assert_eq!(tag, 0x30, "PrivateKeyInfo must be a SEQUENCE");
    let (tag, _version, rest) = der_tlv(info);
    assert_eq!(tag, 0x02, "version must be an INTEGER");
    let (tag, algorithm, rest) = der_tlv(rest);
    assert_eq!(tag, 0x30, "algorithm must be a SEQUENCE");
    let (tag, _ec_public_key, curve_oid) = der_tlv(algorithm);
    assert_eq!(tag, 0x06, "algorithm id must be an OID");
    assert_eq!(curve_oid[0], 0x06, "namedCurve must be an OID");
    let (tag, embedded, _) = der_tlv(rest);
    assert_eq!(tag, 0x04, "privateKey must be an OCTET STRING");

    let (tag, ec_key, _) = der_tlv(embedded);
    assert_eq!(tag, 0x30, "ECPrivateKey must be a SEQUENCE");
    let (_, _, after_version) = der_tlv(ec_key);
    let (_, _, after_private) = der_tlv(after_version);
    if after_private.first() == Some(&0xA0) {
        return embedded.to_vec(); // parameters already present
    }
    let head = &ec_key[..ec_key.len() - after_private.len()];
    let mut body = head.to_vec();
    body.extend_from_slice(&der(0xA0, curve_oid));
    body.extend_from_slice(after_private);
    der(0x30, &body)
}

/// Minimal PEM armour (standard base64, 64-column lines).
fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | (u32::from(b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                b64.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Test server whose `key.pem` uses the requested encoding.
fn test_server_with_key(
    listen: &str,
    static_body: &[u8],
    key_pem: KeyPem,
) -> aetherlink_server::Server {
    // Unique temp dir: wall-clock nanos collide between parallel tests
    // (same tick -> same dir -> concurrently written cert files read back
    // partial -> bind fails). pid + thread + counter makes it collision-free.
    static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let n = CTR.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "aether-i2-{}-{nanos}-{n}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("static dir");
    std::fs::write(dir.join("index.html"), static_body).expect("static file");
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, key.cert.pem()).expect("cert");
    let key_text = match key_pem {
        KeyPem::Pkcs8 => key.key_pair.serialize_pem(),
        KeyPem::Sec1 => pem(
            "EC PRIVATE KEY",
            &pkcs8_to_sec1(&key.key_pair.serialize_der()),
        ),
    };
    std::fs::write(&key_path, key_text).expect("key");
    let doc = serde_json::json!({
        "listen": listen,
        "psk": String::from_utf8_lossy(PSK),
        "local_static_root": dir.to_str().expect("utf8"),
        "tls_cert": cert_path.to_str().expect("utf8"),
        "tls_key": key_path.to_str().expect("utf8"),
        // The echo targets in this file are 127.0.0.1, which the default
        // egress policy refuses (DEC-021). Relaying to a loopback target is
        // exactly what these tests assert, so the operator opt-out is set
        // here the same way a LAN-relaying deployment would set it.
        "egress": { "deny_private": false },
    });
    let server = aetherlink_server::Server::new(doc).expect("server new");
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
    let guard = bound.serve_background();
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
        generation: 0,
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

#[test]
fn bind_accepts_a_sec1_ec_private_key() {
    // Given: key.pem in SEC1 form (`BEGIN EC PRIVATE KEY`), not PKCS#8. The
    // server used to re-label the SEC1 body as PKCS#8 and fail at startup.
    let server = test_server_with_key(
        "127.0.0.1:0",
        b"<html><body>SEC1-OK</body></html>",
        KeyPem::Sec1,
    );
    // When: bind loads it
    let bound = server.bind().expect("bind must accept a SEC1 key");
    let port = bound.local_addr().expect("local addr").port();
    let server = std::thread::spawn(move || bound.serve_once());

    // Then: a real TLS handshake completes with that key (a bad preface
    // afterwards just routes to the static page).
    let mut stream = client_tls(port);
    stream.write_all(&[0xFF]).expect("bad preface");
    stream.flush().expect("flush");
    let mut resp = Vec::new();
    let _ = stream.read_to_end(&mut resp);
    assert!(
        String::from_utf8_lossy(&resp).contains("SEC1-OK"),
        "static page over a SEC1-keyed TLS session"
    );
    assert_eq!(server.join().expect("server thread"), Path::Static);
}

#[test]
fn test_pem_helper_matches_rcgen_pkcs8_armour() {
    // Guard for the helper above: re-armouring rcgen's own PKCS#8 DER must
    // reproduce rcgen's PEM, so the SEC1 test fails on the server, not on a
    // broken base64 encoder.
    let key = rcgen::KeyPair::generate().expect("key");
    let ours = pem("PRIVATE KEY", &key.serialize_der());
    let theirs = key.serialize_pem().replace("\r\n", "\n");
    assert_eq!(ours.trim(), theirs.trim());
}
