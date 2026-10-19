//! TLS 1.3 transport (G1): rustls, frozen canonical profile (DEC-012 Phase T), sync I/O.
//!
//! One composition for every data-plane connection: TLS 1.3 ONLY, only the
//! three mainstream TLS 1.3 cipher suites (allowlist from
//! `aetherlink_protocol::tls_profile`), frozen ALPN orders, in-memory
//! ticket resumption. The constants live in the protocol crate; the
//! constructors here are the only place they are applied, and the golden
//! handshake probes in `tests/tls_profile.rs` fail on any deviation (for
//! example when a future rustls upgrade silently adds suites or flakes
//! ALPN defaults).
//!
//! The server deliberately does NOT offer `h2`: the static fallback speaks
//! raw HTTP/1.1, and browsers enforce the negotiated framing — an `h2`
//! negotiation followed by HTTP/1.1 bytes is a protocol error, so every
//! modern browser would fail the decoy page. The tunnel treats the TLS
//! stream as an opaque byte pipe and is unaffected by the ALPN choice.

use std::net::TcpStream;
use std::sync::Arc;

use aetherlink_protocol::{tls_profile, ALPN_H2, ALPN_HTTP11};
use rustls::client::danger::ServerCertVerifier;
use rustls::client::Resumption;
use rustls::crypto::aws_lc_rs;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};

use crate::{CoreError, Result};

/// Server-side TLS stream (owns connection + socket).
pub type ServerTlsStream = StreamOwned<ServerConnection, TcpStream>;

/// Client-side TLS stream (owns connection + socket).
pub type ClientTlsStream = StreamOwned<ClientConnection, TcpStream>;

/// IANA codepoint of a provider suite; unknown suites map to 0 (dropped).
fn suite_iana(s: &rustls::SupportedCipherSuite) -> u16 {
    use rustls::crypto::aws_lc_rs::cipher_suite as cs;
    if *s == cs::TLS13_AES_128_GCM_SHA256 {
        0x1301
    } else if *s == cs::TLS13_CHACHA20_POLY1305_SHA256 {
        0x1303
    } else if *s == cs::TLS13_AES_256_GCM_SHA384 {
        0x1302
    } else {
        0
    }
}

/// Crypto provider restricted to the canonical profile cipher allowlist
/// (DEC-012): anything a future rustls upgrade adds to the provider
/// backend is dropped here before it can appear on the wire.
fn profile_provider() -> CryptoProvider {
    let mut prov = aws_lc_rs::default_provider();
    prov.cipher_suites.retain(|s| {
        tls_profile::ALLOWED_13_CIPHERS
            .iter()
            .any(|(allowed, _)| *allowed == suite_iana(s))
    });
    prov
}

/// Wire ALPN order from the frozen profile.
fn profile_alpn(order: &[&[u8]]) -> Vec<Vec<u8>> {
    order.iter().map(|a| a.to_vec()).collect()
}

/// Parse PEM cert chain + private key (server `tls_cert`/`tls_key` files).
pub fn load_cert_key(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<std::result::Result<Vec<_>, std::io::Error>>()
        .map_err(|e| CoreError::TlsError(format!("bad cert pem: {e}")))?;
    if chain.is_empty() {
        return Err(CoreError::TlsError("empty cert chain".to_string()));
    }
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| CoreError::TlsError(format!("bad key pem: {e}")))?
        .ok_or_else(|| CoreError::TlsError("no private key found".to_string()))?;
    Ok((chain, key))
}

/// Canonical-profile server config (DEC-012): TLS 1.3 only, profile
/// cipher allowlist only, ALPN `http/1.1`.
///
/// No `h2`: browsers enforce negotiated framing, and the static fallback
/// answers in raw HTTP/1.1 — offering `h2` would break the decoy page in
/// every modern browser while gaining nothing (the tunnel ignores ALPN).
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key_der: &[u8],
) -> Result<ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(profile_provider()))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| CoreError::TlsError(format!("profile versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| CoreError::TlsError(format!("bad cert/key: {e}")))?;
    // RESUMPTION_POLICY (DEC-012): uniform tickets-in-memory on both sides.
    // The rustls default is `NeverProducesTickets` (resumption off), so the
    // rotating ticketer is wired explicitly.
    cfg.ticketer =
        aws_lc_rs::Ticketer::new().map_err(|e| CoreError::TlsError(format!("ticketer: {e}")))?;
    cfg.alpn_protocols = profile_alpn(tls_profile::SERVER_ALPN_ORDER.as_slice());
    Ok(cfg)
}

/// Canonical-profile client config (DEC-012) with a caller-provided verifier:
/// TLS 1.3 only, profile cipher allowlist only, frozen ALPN order
/// (`h2`, then `http/1.1`), in-memory ticket resumption.
pub fn client_config(verifier: Arc<dyn ServerCertVerifier>) -> Result<ClientConfig> {
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(profile_provider()))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| CoreError::TlsError(format!("profile versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.resumption = Resumption::in_memory_sessions(256);
    cfg.alpn_protocols = profile_alpn(tls_profile::CLIENT_ALPN_ORDER.as_slice());
    Ok(cfg)
}

/// TLS1.2-only client config (negative-test/back-compat hook, never default).
pub fn client_config_tls12(verifier: Arc<dyn ServerCertVerifier>) -> Result<ClientConfig> {
    let mut cfg = ClientConfig::builder_with_protocol_versions(&[&TLS12])
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
    Ok(cfg)
}

/// Canonical-profile client config against the platform system roots.
///
/// Platform (Windows/macOS/Linux) trust stores are honored first, with the
/// Mozilla bundle as fallback — private/test CAs installed by the operator
/// (e.g. a smoke-test CA in LocalMachine\Root) verify correctly, and public
/// chains keep working with no platform store involved.
pub fn system_client_config() -> Result<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let bundle = rustls_native_certs::load_native_certs();
    if bundle.certs.is_empty() && !bundle.errors.is_empty() {
        return Err(CoreError::TlsError(format!(
            "native roots: {:?}",
            bundle.errors.first()
        )));
    }
    for cert in bundle.certs {
        // Duplicates across stores are harmless: keep the first.
        let _ = roots.add(cert);
    }
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(profile_provider()))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| CoreError::TlsError(format!("profile versions: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.resumption = Resumption::in_memory_sessions(256);
    cfg.alpn_protocols = profile_alpn(tls_profile::CLIENT_ALPN_ORDER.as_slice());
    Ok(cfg)
}

/// Parse SNI host name.
pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host)
        .map(|n| n.to_owned())
        .map_err(|e| CoreError::TlsError(format!("bad sni: {e}")))
}

/// Accept a TCP socket into a server TLS stream (handshake eager).
pub fn accept_tls(sock: TcpStream, cfg: &Arc<ServerConfig>) -> Result<ServerTlsStream> {
    let conn =
        ServerConnection::new(Arc::clone(cfg)).map_err(|e| CoreError::TlsError(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, sock);
    stream
        .conn
        .complete_io(&mut stream.sock)
        .map_err(|e| CoreError::TlsError(format!("server handshake: {e}")))?;
    Ok(stream)
}

/// Connect a TCP socket into a client TLS stream (handshake eager).
pub fn connect_tls(
    sock: TcpStream,
    name: ServerName<'static>,
    cfg: &Arc<ClientConfig>,
) -> Result<ClientTlsStream> {
    let conn = ClientConnection::new(Arc::clone(cfg), name)
        .map_err(|e| CoreError::TlsError(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, sock);
    stream
        .conn
        .complete_io(&mut stream.sock)
        .map_err(|e| CoreError::TlsError(format!("client handshake: {e}")))?;
    Ok(stream)
}
