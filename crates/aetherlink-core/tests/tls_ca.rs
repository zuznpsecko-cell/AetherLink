//! P1-R9: inline CA PEM for hosts without a usable system trust store.
//!
//! The Android app ships the server's CA in the config document
//! (`client.tls.ca_pem`) because the FFI build cannot read the platform store.
//! The CA is *added* to the usual roots — never a replacement, and never a
//! reason to disable verification. A handshake with a certificate from a
//! different CA must still fail.
//!
//! L0: real loopback TLS, private test CAs.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use aetherlink_core::tls;
use aetherlink_core::CoreError;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

/// A private CA that no system store knows about.
struct TestCa {
    cert: rcgen::Certificate,
    key: KeyPair,
    pem: String,
}

impl TestCa {
    fn new(common_name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().expect("ca key");
        let cert = params.self_signed(&key).expect("self-signed ca");
        let pem = cert.pem();
        Self { cert, key, pem }
    }

    /// A server certificate for `localhost` signed by this CA.
    fn issue_server(&self) -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("srv params");
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        let key = KeyPair::generate().expect("srv key");
        let cert = params
            .signed_by(&key, &self.cert, &self.key)
            .expect("signed server cert");
        (cert, key)
    }
}

/// One-shot TLS server: handshake, then "ok". A rejected client just ends the
/// thread early, which is exactly what the negative test expects.
fn spawn_server(
    listener: TcpListener,
    cert: rcgen::Certificate,
    key: KeyPair,
) -> std::thread::JoinHandle<()> {
    let chain = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
    let cfg = Arc::new(tls::server_config(chain, &key.serialize_der()).expect("server cfg"));
    std::thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        if let Ok(mut stream) = tls::accept_tls(sock, &cfg) {
            let _ = stream.write_all(b"ok");
        }
    })
}

fn listen() -> (TcpListener, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    (listener, addr)
}

#[test]
fn inline_ca_verifies_a_private_server() {
    let ca = TestCa::new("AetherLink Test CA");
    let (cert, key) = ca.issue_server();
    let (listener, addr) = listen();
    let server = spawn_server(listener, cert, key);

    let cfg =
        Arc::new(tls::system_client_config_with_ca(Some(&ca.pem)).expect("config with inline ca"));
    let sock = TcpStream::connect(addr).expect("connect");
    let mut stream = tls::connect_tls(sock, tls::server_name("localhost").expect("sni"), &cfg)
        .expect("the inline CA must be trusted");

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).expect("read");
    assert_eq!(&buf, b"ok");

    server.join().expect("server thread");
}

/// The point of a *CA* rather than a verifier bypass: a certificate from any
/// other CA is still rejected.
#[test]
fn a_different_private_ca_is_rejected() {
    let trusted = TestCa::new("Trusted CA");
    let rogue = TestCa::new("Rogue CA");
    let (cert, key) = rogue.issue_server();
    let (listener, addr) = listen();
    let server = spawn_server(listener, cert, key);

    let cfg = Arc::new(
        tls::system_client_config_with_ca(Some(&trusted.pem)).expect("config with inline ca"),
    );
    let sock = TcpStream::connect(addr).expect("connect");
    let err = match tls::connect_tls(sock, tls::server_name("localhost").expect("sni"), &cfg) {
        Ok(_) => panic!("a cert from another CA must not verify"),
        Err(e) => e,
    };
    assert!(
        matches!(err, CoreError::TlsError(_)),
        "handshake must fail as a TLS error, got: {err}"
    );

    let _ = server.join();

    // And the desktop default (no inline CA) does not trust it either.
    let (cert, key) = rogue.issue_server();
    let (listener, addr) = listen();
    let server = spawn_server(listener, cert, key);
    let sock = TcpStream::connect(addr).expect("connect");
    let default_cfg = Arc::new(tls::system_client_config().expect("system config"));
    assert!(
        tls::connect_tls(
            sock,
            tls::server_name("localhost").expect("sni"),
            &default_cfg
        )
        .is_err(),
        "a private CA must not be trusted without ca_pem"
    );
    let _ = server.join();
}

#[test]
fn bad_pem_is_a_config_error() {
    for bad in [
        "not a pem at all",
        "",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
    ] {
        match tls::system_client_config_with_ca(Some(bad)) {
            Ok(_) => panic!("broken ca_pem must not build a config: {bad:?}"),
            Err(CoreError::ConfigError(_)) => {}
            Err(other) => panic!("broken ca_pem must be ConfigError, got: {other}"),
        }
    }
}

/// Desktop passes no `ca_pem` and must keep the old behavior exactly.
#[test]
fn desktop_config_without_ca_is_unchanged() {
    assert_eq!(
        tls::system_client_config_with_ca(None).is_ok(),
        tls::system_client_config().is_ok(),
        "no inline CA must be the desktop path"
    );
}
