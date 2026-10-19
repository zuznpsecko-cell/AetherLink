//! Phase T (DEC-012), T2: handshake-level gates for the canonical TLS profile.
//!
//! The protocol crate freezes the profile constants; the core constructors
//! in `aetherlink_core::tls` must apply exactly them. These probes fail on
//! any deviation: ciphers, ALPN orders, or resumption policy.

mod tls_common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use aetherlink_core::tls;
use aetherlink_protocol::tls_profile as p;
use rustls::crypto::aws_lc_rs;
use rustls::crypto::aws_lc_rs::cipher_suite as cs;
use rustls::server::ProducesTickets;
use rustls::version::TLS13;
use rustls::ClientConfig;
use std::sync::atomic::{AtomicUsize, Ordering};

use tls_common::AcceptAll;

/// Ticketer wrapper counting `encrypt`/`decrypt` at the wire level:
/// `encrypt` runs when the server issues a NewSessionTicket; `decrypt`
/// runs when a ClientHello carries a PSK identity (resumption offer).
#[derive(Debug)]
struct CountingTicketer {
    inner: Arc<dyn ProducesTickets>,
    encrypts: Arc<AtomicUsize>,
    decrypts: Arc<AtomicUsize>,
}

impl ProducesTickets for CountingTicketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.inner.lifetime()
    }

    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.encrypts.fetch_add(1, Ordering::SeqCst);
        self.inner.encrypt(message)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.decrypts.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt(ciphertext)
    }
}

fn suite_for(id: u16) -> rustls::SupportedCipherSuite {
    match id {
        0x1301 => cs::TLS13_AES_128_GCM_SHA256,
        0x1303 => cs::TLS13_CHACHA20_POLY1305_SHA256,
        0x1302 => cs::TLS13_AES_256_GCM_SHA384,
        _ => panic!("gate test: unhandled profile suite id {id:#06x}"),
    }
}

/// Client config restricted to exactly one suite (profile allowlist probe).
fn restricted_client(id: u16) -> Arc<ClientConfig> {
    let mut prov = aws_lc_rs::default_provider();
    prov.cipher_suites.retain(|s| *s == suite_for(id));
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(prov))
        .with_protocol_versions(&[&TLS13])
        .expect("profile versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    cfg.alpn_protocols = p::CLIENT_ALPN_ORDER.iter().map(|a| a.to_vec()).collect();
    Arc::new(cfg)
}

#[test]
fn profile_negotiates_exactly_each_allowed_suite() {
    for (id, name) in p::ALLOWED_13_CIPHERS {
        // Server with the canonical profile.
        let (chain, key_der) = tls_common::localhost_cert();
        let server_cfg = Arc::new(tls::server_config(chain, &key_der).expect("server cfg"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accept");
            let server_tls = tls::accept_tls(sock, &server_cfg).expect("server handshake");
            let neg = server_tls
                .conn
                .negotiated_cipher_suite()
                .expect("server suite");
            assert_eq!(neg, suite_for(id), "server suite mismatch for {name}");
        });

        // Client restricted to exactly this suite.
        let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let sni = tls::server_name("localhost").expect("sni");
        let client_tls =
            tls::connect_tls(sock, sni, &restricted_client(id)).expect("client handshake");
        assert_eq!(
            client_tls
                .conn
                .negotiated_cipher_suite()
                .expect("client suite"),
            suite_for(id),
            "client suite mismatch for {name}"
        );
        // Server accepts only ALPN http/1.1.
        assert_eq!(
            client_tls.conn.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        server.join().expect("server thread");
    }
}

#[test]
fn config_alpn_orders_match_profile() {
    let (chain, key_der) = tls_common::localhost_cert();

    let server_cfg = tls::server_config(chain, &key_der).expect("server cfg");
    let want_server: Vec<Vec<u8>> = p::SERVER_ALPN_ORDER.iter().map(|a| a.to_vec()).collect();
    assert_eq!(server_cfg.alpn_protocols, want_server);

    let client_cfg = tls::client_config(Arc::new(AcceptAll)).expect("client cfg");
    let want_client: Vec<Vec<u8>> = p::CLIENT_ALPN_ORDER.iter().map(|a| a.to_vec()).collect();
    assert_eq!(client_cfg.alpn_protocols, want_client);

    let system_cfg = tls::system_client_config().expect("system cfg");
    assert_eq!(system_cfg.alpn_protocols, want_client);
}

#[test]
fn second_handshake_resumes_ticket() {
    let (chain, key_der) = tls_common::localhost_cert();
    let mut server_cfg0 = tls::server_config(chain, &key_der).expect("server cfg");
    let encrypts = Arc::new(AtomicUsize::new(0));
    let decrypts = Arc::new(AtomicUsize::new(0));
    server_cfg0.ticketer = Arc::new(CountingTicketer {
        inner: aws_lc_rs::Ticketer::new().expect("ticketer"),
        encrypts: Arc::clone(&encrypts),
        decrypts: Arc::clone(&decrypts),
    });
    let server_cfg = Arc::new(server_cfg0);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (sock, _) = listener.accept().expect("accept");
            let mut server_tls = tls::accept_tls(sock, &server_cfg).expect("server handshake");
            // Byte exchange forces both sides to process post-handshake
            // records (NewSessionTicket included) before the next step.
            server_tls.write_all(b"y").expect("server write");
            let mut buf = [0u8; 1];
            server_tls.read_exact(&mut buf).expect("server read");
        }
    });

    // One shared client config: its in-memory session store survives both
    // handshakes (RESUMPTION_POLICY: tickets-in-memory-both-sides).
    let client_cfg = restricted_client(0x1301);
    let sni = tls::server_name("localhost").expect("sni");

    // First connection: full handshake — key exchange must happen.
    let first_sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut first =
        tls::connect_tls(first_sock, sni.clone(), &client_cfg).expect("first handshake");
    assert!(
        first.conn.negotiated_key_exchange_group().is_some(),
        "first handshake must be full (ECDHE key exchange)"
    );
    first.write_all(b"x").expect("client write");
    let mut buf = [0u8; 1];
    first.read_exact(&mut buf).expect("client read");

    // Wire-level resumption evidence, part 1: the server issued a ticket
    // (NewSessionTicket), and the first ClientHello carried no PSK
    // identity to decrypt.
    assert!(
        encrypts.load(Ordering::SeqCst) >= 1,
        "server must issue session tickets (RESUMPTION_POLICY: tickets)"
    );
    assert_eq!(
        decrypts.load(Ordering::SeqCst),
        0,
        "first ClientHello must not carry a PSK identity"
    );

    // Second connection with the same config: TLS 1.3 resumption rides a
    // PSK identity built from the issued ticket. rustls resumes in
    // psk_dhe_ke mode (ECDHE still runs), so the wire-level proof is that
    // the server actually decrypts a PSK identity.
    let second_sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut second = tls::connect_tls(second_sock, sni, &client_cfg).expect("second handshake");
    second.write_all(b"x").expect("client write");
    second.read_exact(&mut buf).expect("client read");

    server.join().expect("server thread");

    // Happens-after join: all server-side counter writes are visible.
    assert!(
        decrypts.load(Ordering::SeqCst) >= 1,
        "second ClientHello must offer the issued ticket (PSK resumption)"
    );
}
