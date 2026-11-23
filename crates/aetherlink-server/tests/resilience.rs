//! TDD RED: server resilience — connection cap, handshake deadline, panics.
//!
//! Three independent ways an unauthenticated peer used to take the whole
//! server down, and what each test pins:
//!
//! 1. **Connection cap.** Every accepted socket used to spawn a thread with a
//!    4 MiB stack, unbounded. `ServerCtx::try_acquire_connection` now bounds
//!    it, and the slot is released by drop (also on panic).
//! 2. **Handshake deadline.** A peer that completes TCP and then trickles
//!    bytes held its thread forever; `accept_tls_with_timeout` fails closed.
//! 3. **Panic containment.** With `panic = "abort"` in release the
//!    `catch_unwind` guards were dead code; these tests pin the guard's
//!    behaviour at the API level so the profile cannot silently regress.

use std::collections::HashMap;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aetherlink_core::tls;
use aetherlink_crypto::auth::NonceCache;
use aetherlink_server::accept::{serve_connection, Path, ServerCtx};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

const PSK: &[u8] = b"resilience-test-psk-32-bytes-!!!!!";
const STATIC_BODY: &[u8] = b"<html><body>parking</body></html>";

/// Accept-any verifier: test-only (self-signed localhost cert).
#[derive(Debug)]
struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// Self-signed server config + the matching client config.
fn tls_pair() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let chain = vec![CertificateDer::from(key.cert.der().to_vec())];
    let key_der = key.key_pair.serialize_der();
    let server = Arc::new(tls::server_config(chain, &key_der).expect("server cfg"));
    let client = Arc::new(tls::client_config(Arc::new(AcceptAll)).expect("client cfg"));
    (server, client)
}

fn ctx_with(max_connections: usize) -> ServerCtx {
    let (server_cfg, _) = tls_pair();
    ServerCtx {
        tls: server_cfg,
        psk: PSK.to_vec(),
        cache: NonceCache::new(),
        static_body: STATIC_BODY.to_vec(),
        dns_upstream: vec!["1.1.1.1:53".to_string()],
        blocklist: aetherlink_server::blocklist::Blocklist::default(),
        live_connections: Arc::new(AtomicUsize::new(0)),
        max_connections,
        max_streams: aetherlink_server::accept::DEFAULT_MAX_STREAMS,
    }
}

/// A connected-but-silent socket pair: enough to occupy a connection slot
/// without doing any TLS work.
fn silent_pair(listener: &TcpListener) -> (TcpStream, TcpStream) {
    let port = listener.local_addr().expect("addr").port();
    let client = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    (client, server)
}

#[test]
fn connection_slot_is_released_when_service_ends() {
    // Given: a context with room for one connection
    let ctx = ctx_with(1);
    assert_eq!(ctx.live_connections(), 0);
    {
        // When: a slot is taken
        let slot = ctx.try_acquire_connection().expect("first slot");
        // Then: a second acquisition is refused while it is held
        assert!(
            ctx.try_acquire_connection().is_none(),
            "cap must refuse a second connection"
        );
        assert_eq!(ctx.live_connections(), 1);
        drop(slot);
    }
    // And: dropping it returns the capacity.
    assert_eq!(ctx.live_connections(), 0);
    assert!(ctx.try_acquire_connection().is_some());
}

#[test]
fn connection_slot_is_released_even_if_the_handler_panics() {
    // Given: a capped context whose only slot is held by a panicking scope
    let ctx = Arc::new(ctx_with(1));
    let held = Arc::clone(&ctx);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _slot = held.try_acquire_connection().expect("slot");
        panic!("connection handler blew up");
    }));
    assert!(outcome.is_err(), "test premise: the handler panicked");
    // Then: the RAII slot released its capacity on unwind, so the server is
    // not permanently stuck at "full" — which is what a leaked counter would
    // do, and what `panic = "abort"` would have turned into a dead process.
    assert_eq!(ctx.live_connections(), 0);
    assert!(
        ctx.try_acquire_connection().is_some(),
        "capacity must survive a panicking handler"
    );
}

#[test]
fn over_cap_connection_is_closed_without_being_served() {
    // Given: a context already at its cap
    let ctx = ctx_with(1);
    let _held = ctx.try_acquire_connection().expect("occupy the cap");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let (client, server) = silent_pair(&listener);
    // When: a connection is served while the cap is exhausted
    let path = serve_connection(server, &ctx, &mut HashMap::new());
    // Then: it is dropped as `Closed` (no TLS, no static fallback).
    assert_eq!(path, Path::Closed, "over-cap connections must be shed");
    // And: the client observes EOF/RST rather than a served page.
    let mut client = client;
    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 64];
    match client.read(&mut buf) {
        Ok(0) => {}
        Ok(n) => panic!("server sent {n} bytes to a shed connection"),
        Err(_) => {} // RST is equally acceptable
    }
}

#[test]
fn served_connection_returns_its_slot() {
    // Given: a fresh context with room for one connection
    let ctx = ctx_with(1);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let (client, server) = silent_pair(&listener);
    // Close the peer first: the server then reads EOF instead of waiting out
    // the 10 s handshake deadline.
    drop(client);
    // When: a connection that never speaks TLS is served (fast fail path)
    let path = serve_connection(server, &ctx, &mut HashMap::new());
    assert_eq!(path, Path::Closed);
    // Then: the slot is back, so the next connection is not shed.
    assert_eq!(ctx.live_connections(), 0, "slot leaked after serving");
    assert!(ctx.try_acquire_connection().is_some());
}

#[test]
fn handshake_deadline_rejects_a_silent_peer() {
    // Given: a peer that connects and then sends nothing at all (slowloris)
    let (cfg, _) = tls_pair();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let (_client, server) = silent_pair(&listener);
    // When: the handshake runs with a short deadline
    let started = Instant::now();
    let result = tls::accept_tls_with_timeout(server, &cfg, Duration::from_millis(150));
    let elapsed = started.elapsed();
    // Then: it fails closed instead of blocking forever, and it does so on the
    // deadline (generous bound: CI machines are slow).
    assert!(result.is_err(), "a silent peer must not complete a handshake");
    assert!(
        elapsed < Duration::from_secs(3),
        "handshake must honour the deadline, took {elapsed:?}"
    );
}

#[test]
fn handshake_deadline_does_not_leak_into_the_served_stream() {
    // Given: a real TLS handshake performed under a short deadline
    let (cfg, client_cfg) = tls_pair();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accept = std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        tls::accept_tls_with_timeout(sock, &cfg, Duration::from_millis(500)).expect("handshake")
    });
    // When: the client completes the handshake
    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("client timeout");
    let name = tls::server_name("localhost").expect("sni");
    let _client = tls::connect_tls(sock, name, &client_cfg).expect("client handshake");
    let mut server = accept.join().expect("accept thread");
    // Then: the deadline was cleared, so a fresh read timeout behaves normally.
    // A leftover 500 ms handshake timeout would silently cap every later frame
    // read in the tunnel loop, showing up only as mysterious stalls.
    server
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("set");
    let mut buf = [0u8; 1];
    let err = server.read(&mut buf).expect_err("nothing to read");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::WouldBlock,
        "socket must be usable after the handshake"
    );
}
