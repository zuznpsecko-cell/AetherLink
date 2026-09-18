//! AetherLink crypto primitives
//!
//! This crate provides the canonical cryptographic primitives for AetherLink v1.5:
//! - HMAC-SHA256 based authentication tokens
//! - ChaCha20-Poly1305 AEAD encryption
//! - HKDF-SHA256 key derivation

pub mod aead;
pub mod auth;
pub mod keys;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Protocol version constant
pub const PROTOCOL_VERSION: u8 = 1;

/// Authentication prefix used in HMAC
pub const AUTH_PREFIX: &[u8] = b"aetherlink-auth-v1";

/// AEAD tag length for ChaCha20-Poly1305
pub const AEAD_TAG_LEN: usize = 16;

/// AEAD nonce length for ChaCha20-Poly1305
pub const AEAD_NONCE_LEN: usize = 12;

/// AEAD key length for ChaCha20-Poly1305
pub const AEAD_KEY_SIZE: usize = 32;

/// Client nonce length (32 bytes)
pub const NONCE_SIZE: usize = 32;

/// Authentication token length (SHA256 output)
pub const AUTH_TOKEN_SIZE: usize = 32;

/// HKDF salt prefix
pub const HKDF_SALT: &[u8] = b"aetherlink-v1";

/// HKDF label for TX direction
pub const HKDF_TX_LABEL: &[u8] = b"tx";

/// HKDF label for RX direction
pub const HKDF_RX_LABEL: &[u8] = b"rx";

/// Default nonce replay cache TTL (5 minutes)
pub const DEFAULT_NONCE_TTL_SECS: u64 = 300;

/// Maximum frame payload size (16MB)
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// Default padding multiple
pub const DEFAULT_PAD_MULTIPLE: usize = 128;
