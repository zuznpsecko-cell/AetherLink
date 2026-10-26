//! P1-R5: Android must `protect()` its transport socket *before* connecting.
//!
//! `VpnService.protect(fd)` keeps the tunnel's own TCP connection outside the
//! tunnel (otherwise the server address would route back into the TUN and
//! loop). Rust owns the socket and cannot call Kotlin from a host test, so
//! `connect_protected` takes a protector closure and calls it on the raw
//! socket handle before `connect()`. A refused protection must abort before a
//! single SYN leaves the process.
//!
//! L0: real loopback sockets and TLS, no device.

use std::io::ErrorKind;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aetherlink_client::config::ClientConfig;
use aetherlink_client::lifecycle::{connect, connect_protected, SocketHandle};
use aetherlink_client::ClientError;
use aetherlink_crypto::auth::NonceCache;

mod tls_accept_all;

use tls_accept_all::AcceptAll;

const PSK: &[u8] = b"phase-p1r5-test-psk-32-bytes-long!!!";

fn test_config(addr: &str) -> ClientConfig {
    ClientConfig::parse(&serde_json::json!({
        "server_addr": addr,
        "psk": String::from_utf8_lossy(PSK),
        "dns_mode": "tunnel",
    }))
    .expect("test config")
}

/// Spawn a one-shot TLS server that answers only the TLS + AUTH handshake.
fn spawn_handshake_server(listener: TcpListener) -> std::thread::JoinHandle<()> {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let chain = vec![rustls::pki_types::CertificateDer::from(
        key.cert.der().to_vec(),
    )];
    let key_der = key.key_pair.serialize_der();
    let server_cfg =
        Arc::new(aetherlink_core::tls::server_config(chain, &key_der).expect("server cfg"));
    std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let mut stream = aetherlink_core::tls::accept_tls(sock, &server_cfg).expect("server tls");
        let cache = NonceCache::new();
        aetherlink_core::session::handshake_server(&mut stream, PSK, &cache)
            .expect("server handshake");
    })
}

/// The whole point of `protect()`: it runs before `connect()`, so a refused
/// protection means the server never sees a connection attempt at all.
#[test]
fn refused_protection_aborts_before_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let offered = Arc::new(Mutex::new(Vec::<SocketHandle>::new()));

    let err = connect_protected(
        &test_config(&format!("127.0.0.1:{port}")),
        Some(Arc::new(AcceptAll)),
        Duration::from_secs(5),
        {
            let offered = Arc::clone(&offered);
            move |handle| {
                offered.lock().expect("lock").push(handle);
                false
            }
        },
    )
    .err()
    .expect("a refused protect() must fail the connect");

    assert!(
        matches!(err, ClientError::PermissionDenied(_)),
        "refused protection must be PermissionDenied, got: {err}"
    );
    let offered = offered.lock().expect("lock");
    assert_eq!(
        offered.len(),
        1,
        "the protector sees the socket exactly once: {offered:?}"
    );
    assert_ne!(offered[0], 0, "protector must get a real socket handle");
    assert!(
        matches!(listener.accept(), Err(e) if e.kind() == ErrorKind::WouldBlock),
        "no SYN may leave the process when protect() is refused"
    );
}

/// `true` from the protector is a pass-through: the protected socket is the
/// one that completes TLS + AUTH.
#[test]
fn protected_socket_completes_the_tls_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = spawn_handshake_server(listener);
    let offered = Arc::new(Mutex::new(Vec::<SocketHandle>::new()));

    let tunnel = connect_protected(
        &test_config(&addr.to_string()),
        Some(Arc::new(AcceptAll)),
        Duration::from_secs(5),
        {
            let offered = Arc::clone(&offered);
            move |handle| {
                offered.lock().expect("lock").push(handle);
                true
            }
        },
    )
    .expect("protected connect must handshake");

    let offered = offered.lock().expect("lock");
    assert_eq!(offered.len(), 1, "one socket, one protect(): {offered:?}");
    drop(tunnel);
    server.join().expect("server thread");
}

/// A black-holed peer must not hold the call past the budget: `protect()`
/// happens per attempt, so a hung attempt hangs the VPN bring-up.
#[test]
fn protected_connect_honours_the_deadline() {
    // 192.0.2.0/24 is TEST-NET-1: black-holed or unreachable from the host, so
    // this either times out or fails immediately — but never hangs.
    let started = Instant::now();
    let err = connect_protected(
        &test_config("192.0.2.1:443"),
        Some(Arc::new(AcceptAll)),
        Duration::from_millis(300),
        |_| true,
    )
    .err()
    .expect("TEST-NET-1 must not accept");

    assert!(
        matches!(err, ClientError::PlatformError(_)),
        "unreachable peer must be a PlatformError, got: {err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "connect budget ignored: took {:?}",
        started.elapsed()
    );
}

/// Desktop keeps the old entry point: protecting is an Android concern and
/// must not become mandatory for Windows/Linux callers.
#[test]
fn desktop_connect_needs_no_protector() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = spawn_handshake_server(listener);

    let tunnel = connect(&test_config(&addr.to_string()), Some(Arc::new(AcceptAll)))
        .expect("plain connect must still work");

    drop(tunnel);
    server.join().expect("server thread");
}
