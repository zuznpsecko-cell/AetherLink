//! AetherLink userspace network stack
//!
//! This crate provides TUN device management, smoltcp integration,
//! and packet processing for the full tunnel data plane.

pub mod debug;
pub mod manager;
pub mod smoltcp_wrapper;
pub mod sockets;
pub mod tun;

pub use debug::{debug_enabled, debug_log};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetstackError {
    #[error("TUN device error: {0}")]
    TunError(String),

    #[error("smoltcp error: {0}")]
    SmoltcpError(String),

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Interface not configured")]
    InterfaceNotConfigured,

    #[error("Route error: {0}")]
    RouteError(String),

    #[error("DNS error: {0}")]
    DnsError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, NetstackError>;

/// Default TUN MTU
pub const DEFAULT_MTU: usize = 1400;

/// Default TUN subnet for virtual interfaces (10.255.0.0/30)
/// Virtual DNS resolver will be at 10.255.0.1
pub const DEFAULT_TUN_SUBNET: &str = "10.255.0.0/30";
pub const VIRTUAL_DNS_IP: &str = "10.255.0.1";
pub const VIRTUAL_GATEWAY_IP: &str = "10.255.0.1";
