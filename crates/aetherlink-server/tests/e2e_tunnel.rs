//! E2E: one session, two TCP streams + one UDP flow + DNS resolve (Phase G1).
//!
//! Assembled path with no privileges: handshake → mux → accept-loop →
//! local echo targets + fake DNS upstream.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use aetherlink_crypto::auth::NonceCache;

use aetherlink_server::accept::{serve_connection, Path, ServerCtx};

mod wire_help;

const PSK: &[u8] = b"phase-g-test-psk-32-bytes-long!!!!!";
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
        dns_upstream: "1.1.1.1:53".to_string(),
    }
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

fn tcp_echo() -> u16 {
    let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
    let port = echo.local_addr().expect("addr").port();
    std::thread::spawn(move || loop {
        let (mut sock, _) = match echo.accept() {
            Ok(s) => s,
            Err(_) => break,
        };
        let mut buf = [0u8; 64];
        let mut n = match sock.read(&mut buf) {
            Ok(0) | Err(_) => continue,
            Ok(n) => n,
        };
        while n > 0 {
            if sock.write_all(&buf[..n]).is_err() {
                break;
            }
            n = match sock.read(&mut buf) {
                Ok(n) => n,
                Err(_) => break,
            };
        }
    });
    port
}

#[test]
fn e2e_two_streams_one_flow_plus_dns() {
    // Given: two TCP echo targets, one UDP echo target, one fake DNS upstream
    let echo1 = tcp_echo();
    let echo2 = tcp_echo();
    let udp = UdpSocket::bind("127.0.0.1:0").expect("udp echo bind");
    let udp_port = udp.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (n, from) = udp.recv_from(&mut buf).expect("udp recv");
        udp.send_to(&buf[..n], from).expect("udp send");
    });
    let dns_sock = UdpSocket::bind("127.0.0.1:0").expect("dns bind");
    let dns_port = dns_sock.local_addr().expect("addr").port();
    let dns_answer = b"\xab\xcd\x81\x80\x00\x01\x00\x01".to_vec();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (_, from) = dns_sock.recv_from(&mut buf).expect("dns recv");
        dns_sock.send_to(&dns_answer, from).expect("dns send");
    });

    let mut routes = HashMap::new();
    routes.insert(1u16, format!("127.0.0.1:{echo1}").parse().expect("sa"));
    routes.insert(3u16, format!("127.0.0.1:{echo2}").parse().expect("sa"));
    routes.insert(5u16, format!("127.0.0.1:{udp_port}").parse().expect("sa"));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        assert_eq!(serve_connection(sock, &ctx(), &mut routes), Path::Tunnel);
    });

    // When: one handshake, two streams, one flow, all at once
    let mut stream = client_tls(port);
    let nonce = [0xE1u8; 32];
    let mut sess =
        aetherlink_core::session::handshake_client(&mut stream, PSK, &nonce).expect("client hs");
    let s1 = sess.mux.open_tcp("127.0.0.1", echo1).expect("open s1");
    let s2 = sess.mux.open_tcp("127.0.0.1", echo2).expect("open s2");
    let f5 = sess.mux.open_udp("127.0.0.1", udp_port).expect("open f5");
    assert_eq!((s1, s2, f5), (1, 3, 5));
    for (id, payload) in [(s1, b"one".as_slice()), (s2, b"two".as_slice())] {
        let sealed = sess
            .mux
            .seal_data(sess.keys.tx_key(), id, payload, 128)
            .expect("seal");
        wire_help::write_frame(&mut stream, &sealed.header, &sealed.ciphertext);
    }
    let sealed = sess
        .mux
        .seal_datagram(sess.keys.tx_key(), f5, b"datagram", 128)
        .expect("seal dgram");
    wire_help::write_frame(&mut stream, &sealed.header, &sealed.ciphertext);

    // Then: all three replies arrive (server answers in frame order).
    let (h1, c1) = wire_help::read_frame(&mut stream);
    let (h2, c2) = wire_help::read_frame(&mut stream);
    let (h3, c3) = wire_help::read_frame(&mut stream);
    let mut got = vec![
        sess.mux
            .open_data(sess.keys.rx_key(), &h1, &c1)
            .expect("open r1"),
        sess.mux
            .open_data(sess.keys.rx_key(), &h2, &c2)
            .expect("open r2"),
        sess.mux
            .open_datagram(sess.keys.rx_key(), &h3, &c3)
            .expect("open r3"),
    ];
    got.sort();
    assert_eq!(
        got,
        vec![b"datagram".to_vec(), b"one".to_vec(), b"two".to_vec()]
    );

    // And: DNS resolves through the fake upstream on the server policy path.
    let answer = aetherlink_server::dns::resolve(
        b"\xab\xcd\x01\x00",
        &format!("127.0.0.1:{dns_port}"),
        Duration::from_secs(2),
    )
    .expect("dns resolve");
    assert_eq!(answer, b"\xab\xcd\x81\x80\x00\x01\x00\x01");

    drop(stream);
    server.join().expect("server thread");
}

#[test]
fn virtual_dns_open_resolves_via_upstream() {
    // Given: fake DNS upstream answering canned bytes + server learning
    // routes from OPEN frames (no pre-registered routes, like production)
    let dns_sock = UdpSocket::bind("127.0.0.1:0").expect("dns bind");
    let dns_port = dns_sock.local_addr().expect("addr").port();
    let dns_answer = b"\xab\xcd\x81\x80\x00\x01\x00\x01".to_vec();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (_, from) = dns_sock.recv_from(&mut buf).expect("dns recv");
        dns_sock.send_to(&dns_answer, from).expect("dns send");
    });

    let mut base = ctx();
    base.dns_upstream = format!("127.0.0.1:{dns_port}");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut routes = HashMap::new();
        assert_eq!(serve_connection(sock, &base, &mut routes), Path::Tunnel);
    });

    // When: handshake, OPEN_UDP to the virtual resolver, one query
    let mut stream = client_tls(port);
    let nonce = [0xE2u8; 32];
    let mut sess =
        aetherlink_core::session::handshake_client(&mut stream, PSK, &nonce).expect("client hs");
    let id = sess
        .mux
        .open_udp("10.255.0.1", 53)
        .expect("open virtual dns");
    let open = sess
        .mux
        .seal_open_udp(sess.keys.tx_key(), id, 128)
        .expect("seal open");
    wire_help::write_frame(&mut stream, &open.header, &open.ciphertext);
    let query = sess
        .mux
        .seal_datagram(sess.keys.tx_key(), id, b"\xab\xcd\x01\x00", 128)
        .expect("seal query");
    wire_help::write_frame(&mut stream, &query.header, &query.ciphertext);
    // Then: the upstream answer comes back on the same flow.
    let (h, c) = wire_help::read_frame(&mut stream);
    let answer = sess
        .mux
        .open_datagram(sess.keys.rx_key(), &h, &c)
        .expect("open answer");
    assert_eq!(answer, b"\xab\xcd\x81\x80\x00\x01\x00\x01");

    drop(stream);
    server.join().expect("server thread");
}

#[test]
fn dead_flow_does_not_kill_healthy_flows() {
    // Given: one TCP echo target + one certainly-closed port
    let echo = tcp_echo();
    let probe = TcpListener::bind("127.0.0.1:0").expect("bind");
    let dead_port = probe.local_addr().expect("addr").port();
    drop(probe);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut routes = HashMap::new();
        assert_eq!(serve_connection(sock, &ctx(), &mut routes), Path::Tunnel);
    });

    // When: handshake, OPEN+DATA to the dead port first, then a healthy flow
    let mut stream = client_tls(port);
    let nonce = [0xE3u8; 32];
    let mut sess =
        aetherlink_core::session::handshake_client(&mut stream, PSK, &nonce).expect("client hs");
    let dead = sess
        .mux
        .open_tcp("127.0.0.1", dead_port)
        .expect("open dead");
    let sealed_open = sess
        .mux
        .seal_open_tcp(sess.keys.tx_key(), dead, 128)
        .expect("seal open");
    wire_help::write_frame(&mut stream, &sealed_open.header, &sealed_open.ciphertext);
    let sealed_data = sess
        .mux
        .seal_data(sess.keys.tx_key(), dead, b"void", 128)
        .expect("seal data");
    wire_help::write_frame(&mut stream, &sealed_data.header, &sealed_data.ciphertext);

    let live = sess.mux.open_tcp("127.0.0.1", echo).expect("open live");
    let sealed_open = sess
        .mux
        .seal_open_tcp(sess.keys.tx_key(), live, 128)
        .expect("seal open");
    wire_help::write_frame(&mut stream, &sealed_open.header, &sealed_open.ciphertext);
    let sealed_data = sess
        .mux
        .seal_data(sess.keys.tx_key(), live, b"alive", 128)
        .expect("seal data");
    wire_help::write_frame(&mut stream, &sealed_data.header, &sealed_data.ciphertext);
    // Then: the healthy flow still answers (dead flow isolated, loop lives).
    let (h, c) = wire_help::read_frame(&mut stream);
    let back = sess
        .mux
        .open_data(sess.keys.rx_key(), &h, &c)
        .expect("open answer");
    assert_eq!(back, b"alive");

    drop(stream);
    server.join().expect("server thread");
}

#[test]
fn multicast_datagram_skipped_loop_lives() {
    // Given: one TCP echo target
    let echo = tcp_echo();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut routes = HashMap::new();
        assert_eq!(serve_connection(sock, &ctx(), &mut routes), Path::Tunnel);
    });

    // When: multicast datagram first (would stall 5s on relay), then healthy flow
    let mut stream = client_tls(port);
    let nonce = [0xE4u8; 32];
    let mut sess =
        aetherlink_core::session::handshake_client(&mut stream, PSK, &nonce).expect("client hs");
    let noise = sess.mux.open_udp("224.0.0.251", 5353).expect("open noise");
    let sealed_open = sess
        .mux
        .seal_open_udp(sess.keys.tx_key(), noise, 128)
        .expect("seal open");
    wire_help::write_frame(&mut stream, &sealed_open.header, &sealed_open.ciphertext);
    let sealed_data = sess
        .mux
        .seal_datagram(sess.keys.tx_key(), noise, b"mdns?", 128)
        .expect("seal data");
    wire_help::write_frame(&mut stream, &sealed_data.header, &sealed_data.ciphertext);

    let live = sess.mux.open_tcp("127.0.0.1", echo).expect("open live");
    let sealed_open = sess
        .mux
        .seal_open_tcp(sess.keys.tx_key(), live, 128)
        .expect("seal open");
    wire_help::write_frame(&mut stream, &sealed_open.header, &sealed_open.ciphertext);
    let sealed_data = sess
        .mux
        .seal_data(sess.keys.tx_key(), live, b"alive", 128)
        .expect("seal data");
    wire_help::write_frame(&mut stream, &sealed_data.header, &sealed_data.ciphertext);
    // Then: healthy flow answers promptly (no 5s multicast stall in the way).
    let started = std::time::Instant::now();
    let (h, c) = wire_help::read_frame(&mut stream);
    let back = sess
        .mux
        .open_data(sess.keys.rx_key(), &h, &c)
        .expect("open answer");
    assert_eq!(back, b"alive");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(4),
        "multicast must not stall the loop"
    );

    drop(stream);
    server.join().expect("server thread");
}
