//! UDP flow descriptors and target validation.

use thiserror::Error;

/// Flow failures (no secrets).
#[derive(Debug, Error)]
pub enum FlowError {
    /// Port must be 1..=65535.
    #[error("bad port")]
    BadPort,
    /// Address must be 1..=255 bytes.
    #[error("bad address")]
    BadAddr,
}

/// Opened UDP flow descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpFlow {
    /// Flow id (client odd).
    pub id: u16,
    /// Destination address.
    pub addr: String,
    /// Destination port.
    pub port: u16,
}

impl UdpFlow {
    /// Build + validate descriptor.
    pub fn new(id: u16, addr: &str, port: u16) -> Result<Self, FlowError> {
        validate_target(addr, port)?;
        Ok(Self {
            id,
            addr: addr.to_string(),
            port,
        })
    }
}

/// Validate UDP dial target.
pub fn validate_target(addr: &str, port: u16) -> Result<(), FlowError> {
    if port == 0 {
        return Err(FlowError::BadPort);
    }
    if addr.is_empty() || addr.len() > 255 {
        return Err(FlowError::BadAddr);
    }
    Ok(())
}
