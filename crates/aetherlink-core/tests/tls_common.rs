//! Shared localhost-TLS helpers for core integration tests.
#![allow(dead_code)]

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// Accept-all verifier: test-only (self-signed localhost cert).
#[derive(Debug)]
pub struct AcceptAll;

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

/// Self-signed localhost cert (DER) for tests.
pub fn localhost_cert() -> (Vec<CertificateDer<'static>>, Vec<u8>) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert_der = key.cert.der().to_vec();
    let key_der = key.key_pair.serialize_der();
    (vec![CertificateDer::from(cert_der)], key_der)
}

/// TLS1.3-only server config for tests.
pub fn server_tls_config() -> Arc<rustls::ServerConfig> {
    let (chain, key_der) = localhost_cert();
    Arc::new(aetherlink_core::tls::server_config(chain, &key_der).expect("server cfg"))
}

/// TLS1.3-only accepting client config for tests.
pub fn client_tls_config() -> Arc<rustls::ClientConfig> {
    Arc::new(aetherlink_core::tls::client_config(Arc::new(AcceptAll)).expect("client cfg"))
}
