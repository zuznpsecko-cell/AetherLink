//! TLS 1.3 transport (G1): rustls, ALPN `h2,http/1.1`, sync I/O.
//!
//! The server offers TLS 1.3 ONLY; older versions fail the handshake.
//! Async (`tokio-rustls`) migration is a later transport task; the cipher
//! contract (versions, ALPN) is version-agnostic and locked by tests here.

use std::net::TcpStream;
use std::sync::Arc;

use aetherlink_protocol::{ALPN_H2, ALPN_HTTP11};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};

use crate::{CoreError, Result};

/// Server-side TLS stream (owns connection + socket).
pub type ServerTlsStream = StreamOwned<ServerConnection, TcpStream>;

/// Client-side TLS stream (owns connection + socket).
pub type ClientTlsStream = StreamOwned<ClientConnection, TcpStream>;

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

/// TLS1.3-only server config with ALPN `h2,http/1.1`.
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key_der: &[u8],
) -> Result<ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| CoreError::TlsError(format!("bad cert/key: {e}")))?;
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
    Ok(cfg)
}

/// TLS1.3-only client config with a caller-provided verifier + ALPN.
pub fn client_config(verifier: Arc<dyn ServerCertVerifier>) -> Result<ClientConfig> {
    let mut cfg = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
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

/// TLS1.3-only client config against the platform system roots.
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
    let mut cfg = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
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
