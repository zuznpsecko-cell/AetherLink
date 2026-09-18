//! AetherLink server library
//!
//! Provides server-side functionality: authentication, static fallback,
//! TCP/UDP relay, and DNS upstream resolution.

pub mod accept;
pub mod auth;
pub mod config;
pub mod dns;
pub mod fallback;
pub mod relay;

use aetherlink_core::CoreError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Core error: {0}")]
    Core(#[from] CoreError),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Relay error: {0}")]
    RelayError(String),

    #[error("DNS error: {0}")]
    DnsError(String),

    #[error("Fallback error: {0}")]
    FallbackError(String),

    #[error("Config error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, ServerError>;

/// Server handle: validated config (network starts in `serve_*`).
pub struct Server {
    /// Validated configuration.
    pub config: config::ServerConfig,
}

impl Server {
    /// Create from a config document (validated once, at the boundary).
    pub fn new(doc: serde_json::Value) -> Result<Self> {
        Ok(Self {
            config: config::ServerConfig::parse(&doc)?,
        })
    }
}
