//! TDD RED: server accept-loop — TLS accept → AUTH gate → tunnel/static/closed (Phase B).
//!
//! * valid AUTH → `Path::Tunnel`, TCP DATA reaches the dial target and back;
//! * bad AUTH → `Path::Static`: plain static HTTP over the same TLS conn,
//!   no tunnel/proxy/vpn banner anywhere (G2);
//! * plaintext probe → `Path::Closed`, nothing served;
//! * UDP datagram → relayed via `relay_udp`, transparent roundtrip.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;

use aetherlink_crypto::auth::NonceCache;
use aetherlink_frame::codec::FrameHeader;
use aetherlink_protocol::{FrameType, PROTOCOL_VERSION};
use bytes::BytesMut;

use aetherlink_server::accept::{serve_connection, Path, ServerCtx};

mod wire_help;

const PSK: &[u8] = b"phase-b-test-psk-32-bytes-long!!!!";
const STATIC_BODY: &[u8] = b"<html><body>parking</body></html>";

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
    }
}

/// Client TLS stream trusting anything (test-only, self-signed localhost).
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
fn valid_auth_reaches_tunnel_tcp_echo() {
    // Given: local TCP echo target + route for stream 1
    let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
    let echo_port = echo.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let (mut sock, _) = echo.accept().expect("echo accept");
        let mut buf = [0u8; 5];
        use std::io::{Read, Write};
        sock.read_exact(&mut buf).expect("echo read");
        sock.write_all(&buf).expect("echo write");
    });
    let mut routes = HashMap::new();
    routes.insert(
        1u16,
        format!("127.0.0.1:{echo_port}").parse().expect("sockaddr"),
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        // Then: valid AUTH yields the tunnel path.
        assert_eq!(serve_connection(sock, &ctx(), &routes), Path::Tunnel);
    });

    // When: full client handshake + DATA for stream 1
    let mut stream = client_tls(port);
    let nonce = [0xD1u8; 32];
    let mut sess =
        aetherlink_core::session::handshake_client(&mut stream, PSK, &nonce).expect("client hs");
    let id = sess.mux.open_tcp("127.0.0.1", echo_port).expect("open");
    let sealed = sess
        .mux
        .seal_data(sess.keys.tx_key(), id, b"hello", 128)
        .expect("seal");
    wire_help::write_frame(&mut stream, &sealed.header, &sealed.ciphertext);
    // Then: echo comes back through the tunnel.
    let (header, ct) = wire_help::read_frame(&mut stream);
    let back = sess
        .mux
        .open_data(sess.keys.rx_key(), &header, &ct)
        .expect("open reply");
    assert_eq!(back, b"hello");
    // Dropping the client stream lets the server loop observe EOF and return.
    drop(stream);
    server.join().expect("server thread");
}

#[test]
fn bad_auth_gets_static_without_banner() {
    // Given: server with static body
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        // Then: bad AUTH yields the static path.
        assert_eq!(
            serve_connection(sock, &ctx(), &HashMap::new()),
            Path::Static
        );
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
    // Then: plain static HTTP, no tunnel/proxy/vpn banner.
    assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
    assert!(text.contains("parking"));
    let lower = text.to_lowercase();
    for banned in ["tunnel", "proxy", "vpn"] {
        assert!(!lower.contains(banned), "banner leak: {banned}");
    }
    server.join().expect("server thread");
}

#[test]
fn plaintext_probe_is_closed() {
    // Given: server listener
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        // Then: non-TLS bytes are closed, nothing served.
        assert_eq!(
            serve_connection(sock, &ctx(), &HashMap::new()),
            Path::Closed
        );
    });

    // When: browser-lookalike plaintext probe
    let mut raw = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    raw.write_all(b"GET / HTTP/1.0\r\n\r\n").expect("probe");
    let mut buf = Vec::new();
    // Then: connection terminates without serving anything (a TLS alert
    // before close is standard server behavior, not content).
    raw.read_to_end(&mut buf).expect("read");
    let text = String::from_utf8_lossy(&buf);
    assert!(!text.contains("200 OK"), "nothing served, got: {text}");
    assert!(!text.contains("parking"), "nothing served, got: {text}");
    server.join().expect("server thread");
}

#[test]
fn udp_datagram_relayed_transparently() {
    // Given: local UDP echo target + route for flow 1
    let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
    let echo_port = echo.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        let (n, from) = echo.recv_from(&mut buf).expect("echo recv");
        echo.send_to(&buf[..n], from).expect("echo send");
    });
    let mut routes = HashMap::new();
    routes.insert(
        1u16,
        format!("127.0.0.1:{echo_port}").parse().expect("sockaddr"),
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        assert_eq!(serve_connection(sock, &ctx(), &routes), Path::Tunnel);
    });

    // When: handshake + UDP datagram for flow 1
    let mut stream = client_tls(port);
    let nonce = [0xD2u8; 32];
    let mut sess =
        aetherlink_core::session::handshake_client(&mut stream, PSK, &nonce).expect("client hs");
    let id = sess
        .mux
        .open_udp("127.0.0.1", echo_port)
        .expect("open flow");
    let sealed = sess
        .mux
        .seal_datagram(sess.keys.tx_key(), id, b"ping-udp", 128)
        .expect("seal");
    wire_help::write_frame(&mut stream, &sealed.header, &sealed.ciphertext);
    // Then: echo returns byte-identical.
    let (header, ct) = wire_help::read_frame(&mut stream);
    let back = sess
        .mux
        .open_datagram(sess.keys.rx_key(), &header, &ct)
        .expect("open reply");
    assert_eq!(back, b"ping-udp");
    // Dropping the client stream lets the server loop observe EOF and return.
    drop(stream);
    server.join().expect("server thread");
}
