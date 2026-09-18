//! TCP stream descriptors and target validation.

use thiserror::Error;

/// Stream failures (no secrets).
#[derive(Debug, Error)]
pub enum StreamError {
    /// Port must be 1..=65535.
    #[error("bad port")]
    BadPort,
    /// Address must be 1..=255 bytes.
    #[error("bad address")]
    BadAddr,
}

/// Opened TCP stream descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpStream {
    /// Stream id (client odd).
    pub id: u16,
    /// Destination address.
    pub addr: String,
    /// Destination port.
    pub port: u16,
}

impl TcpStream {
    /// Build + validate descriptor.
    pub fn new(id: u16, addr: &str, port: u16) -> Result<Self, StreamError> {
        validate_target(addr, port)?;
        Ok(Self {
            id,
            addr: addr.to_string(),
            port,
        })
    }
}

/// Validate TCP dial target.
pub fn validate_target(addr: &str, port: u16) -> Result<(), StreamError> {
    if port == 0 {
        return Err(StreamError::BadPort);
    }
    if addr.is_empty() || addr.len() > 255 {
        return Err(StreamError::BadAddr);
    }
    Ok(())
}
