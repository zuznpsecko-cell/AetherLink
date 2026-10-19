//! Phase T (DEC-012), T3: fallback shape gates.
//!
//! Unauthenticated probes (bad AUTH, wrong SNI) receive byte-comparable
//! generic static answers — statuses, headers, close semantics versus the
//! canonical reference static-server shape (byte-exact modulo the Date
//! value); plaintext probes stay TLS-silent. No tunnel markers in body,
//! headers, or status classes.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use aetherlink_crypto::auth::NonceCache;
use aetherlink_server::accept::{serve_connection, Path, ServerCtx};
use bytes::BytesMut;

const PSK: &[u8] = b"phase-t-fallback-psk-32-bytes-long!";
const STATIC_BODY: &[u8] = b"<html><body>Welcome to our site</body></html>";

/// Reference static server identity (generic, no tunnel specifics).
const SERVER_IDENTITY: &str = "static-httpd/1.0";

fn ctx() -> ServerCtx {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let chain = vec![rustls::pki_types::CertificateDer::from(
        key.cert.der().to_vec(),
    )];
    let key_der = key.key_pair.serialize_der();
    let tls_cfg = Arc::new(aetherlink_core::tls::server_config(chain, &key_der).expect("tls cfg"));
    ServerCtx {
        tls: tls_cfg,
        psk: PSK.to_vec(),
        cache: NonceCache::new(),
        static_body: STATIC_BODY.to_vec(),
        dns_upstream: vec!["1.1.1.1:53".to_string()],
        blocklist: aetherlink_server::blocklist::Blocklist::default(),
    }
}

/// Client TLS stream trusting anything (test-only, self-signed localhost),
/// with an explicit SNI so the wrong-SNI probe can deviate on purpose.
fn client_tls_named(port: u16, sni_host: &str) -> aetherlink_core::tls::ClientTlsStream {
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
    let name = aetherlink_core::tls::server_name(sni_host).expect("sni");
    aetherlink_core::tls::connect_tls(sock, name, &cfg).expect("client tls")
}

/// Well-formed AUTH preface with an invalid token: TLS succeeds, the
/// session gate rejects → static fallback path.
fn bad_auth_probe(mut stream: aetherlink_core::tls::ClientTlsStream) -> Vec<u8> {
    use aetherlink_frame::codec::FrameHeader;
    use aetherlink_protocol::{FrameType, PROTOCOL_VERSION};
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
    stream.read_to_end(&mut resp).expect("read until EOF");
    resp
}

/// Byte-comparable-to-reference assertion: canonically ordered generic
/// static head, byte-exact body, no tunnel markers anywhere.
fn assert_generic_static(resp: &[u8], ctx: &str) {
    let text = String::from_utf8_lossy(resp);
    let text = &*text;

    // Status: generic 200 class.
    assert!(
        text.starts_with("HTTP/1.1 200 OK\r\n"),
        "{ctx}: status not generic: {text}"
    );

    // Head/body split.
    let split = text
        .find("\r\n\r\n")
        .ok_or_else(|| format!("{ctx}: no head/body separator: {text}"))
        .expect("separator");
    let head = &text[..split + 4];
    let body = text[split + 4..].as_bytes();
    assert_eq!(body, STATIC_BODY, "{ctx}: body must be byte-exact");

    // Headers in canonical order, byte-exact modulo the Date value.
    let lines: Vec<&str> = head.trim_end_matches("\r\n").split("\r\n").collect();
    let mut it = lines.iter();
    assert_eq!(it.next(), Some(&"HTTP/1.1 200 OK"), "{ctx}: {head}");
    assert_eq!(
        it.next(),
        Some(&&format!("Server: {SERVER_IDENTITY}")[..]),
        "{ctx}: generic Server header missing/wrong order: {head}"
    );
    let date = it.next().expect("{ctx}: Date header missing").to_string();
    assert!(
        date.starts_with("Date: ") && date.len() >= 35 && date.ends_with(" GMT"),
        "{ctx}: Date not IMF-fixdate class: {date}"
    );
    assert_eq!(
        it.next(),
        Some(&&format!("Content-Length: {}", STATIC_BODY.len())[..]),
        "{ctx}: {head}"
    );
    assert_eq!(it.next(), Some(&"Content-Type: text/html"), "{ctx}: {head}");
    assert_eq!(it.next(), Some(&"Connection: close"), "{ctx}: {head}");
    assert!(
        it.next().is_none(),
        "{ctx}: extra headers after canonical set: {head}"
    );

    // No tunnel markers anywhere in head or body.
    let lower = text.to_lowercase();
    for banned in [
        "tunnel",
        "proxy",
        "vpn",
        "aetherlink",
        "auth",
        "psk",
        "mux",
        "nonce",
    ] {
        assert!(!lower.contains(banned), "{ctx}: marker leak: {banned}");
    }
}

#[test]
fn bad_auth_static_response_matches_reference_shape() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        assert_eq!(
            serve_connection(sock, &ctx(), &mut HashMap::new()),
            Path::Static
        );
    });

    let stream = client_tls_named(port, "localhost");
    let resp = bad_auth_probe(stream);
    server.join().expect("server thread");
    assert_generic_static(&resp, "bad-auth");
}

#[test]
fn wrong_sni_static_response_matches_reference_shape() {
    // Wrong SNI must behave exactly like bad AUTH: TLS completes (generic
    // TLS servers do not gate on SNI), static fallback serves the same
    // canonical shape.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        assert_eq!(
            serve_connection(sock, &ctx(), &mut HashMap::new()),
            Path::Static
        );
    });

    let stream = client_tls_named(port, "wrong.example.com");
    let resp = bad_auth_probe(stream);
    server.join().expect("server thread");
    assert_generic_static(&resp, "wrong-sni");
}

#[test]
fn plaintext_probe_stays_tls_silent() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        assert_eq!(
            serve_connection(sock, &ctx(), &mut HashMap::new()),
            Path::Closed
        );
    });

    let mut raw = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    raw.write_all(b"GET / HTTP/1.0\r\n\r\n").expect("probe");
    let mut buf = Vec::new();
    raw.read_to_end(&mut buf).expect("read");
    let text = String::from_utf8_lossy(&buf);
    // No HTTP status/class or body ever leaks outside TLS.
    assert!(!text.contains("HTTP/1."), "plaintext status leak: {text}");
    assert!(
        !text.to_lowercase().contains("welcome"),
        "plaintext body leak"
    );
    server.join().expect("server thread");
}
