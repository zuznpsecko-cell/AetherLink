//! AetherLink core protocol
//!
//! This crate orchestrates the full protocol: TLS transport, session management,
//! authentication, and integration with multiplexing and network stack.

pub mod config;
pub mod session;
pub mod tls;

use aetherlink_crypto::CryptoError;
use aetherlink_frame::FrameError;
use aetherlink_mux::MuxError;
use aetherlink_netstack::NetstackError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Frame error: {0}")]
    Frame(#[from] FrameError),

    #[error("Mux error: {0}")]
    Mux(#[from] MuxError),

    #[error("Netstack error: {0}")]
    Netstack(#[from] NetstackError),

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
