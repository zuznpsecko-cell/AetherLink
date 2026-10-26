//! Android interface plan: the document Kotlin applies to `VpnService.Builder`.
//!
//! The Rust core owns *what* the tunnel looks like; the thin host only knows
//! *how* to build it. Everything here is pure logic so it can be tested on the
//! host (L0) without a device.

use serde::{Deserialize, Serialize};

use crate::config::ClientConfig;
use crate::{ClientError, Result};

/// Session name shown by Android in the VPN dialog.
pub const SESSION: &str = "AetherLink";
/// Tunnel address handed to `Builder.addAddress`.
pub const TUNNEL_IP: &str = "10.255.0.2";
/// Tunnel prefix: `10.255.0.0/30`.
pub const TUNNEL_PREFIX: u8 = 30;
/// Virtual DNS gateway; also the `source` address the netstack answers for.
pub const DNS_IP: &str = "10.255.0.1";

/// One IPv4 prefix in the plan (`Builder.addRoute(ip, prefix)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpPrefix {
    /// Dotted-quad address.
    pub ip: String,
    /// Prefix length, 0..=32.
    pub prefix: u8,
}

impl IpPrefix {
    /// Build a prefix entry.
    #[must_use]
    pub fn new(ip: &str, prefix: u8) -> Self {
        Self {
            ip: ip.to_string(),
            prefix,
        }
    }
}

/// Tunnel address (`Builder.addAddress`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelAddress {
    /// Tunnel interface address.
    pub ip: String,
    /// Prefix length.
    pub prefix: u8,
}

/// How per-app routing is applied. Kotlin applies exactly one list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppsMode {
    /// Every app goes through the tunnel.
    All,
    /// Only `packages` go through the tunnel.
    Allow,
    /// Every app except `packages` goes through the tunnel.
    Deny,
}

/// `apps` section of the plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppsSpec {
    /// Which list `packages` means.
    pub mode: AppsMode,
    /// Package names (empty for `all`).
    pub packages: Vec<String>,
}

/// Complete interface plan (`clientPlan`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidPlan {
    /// VPN session name.
    pub session: String,
    /// Interface MTU.
    pub mtu: u32,
    /// Tunnel address.
    pub address: TunnelAddress,
    /// DNS servers pushed into the tunnel.
    pub dns: Vec<String>,
    /// IPv4 routes.
    pub routes: Vec<IpPrefix>,
    /// Per-app routing.
    pub apps: AppsSpec,
    /// Kotlin adds an IPv6 black hole; Rust drops non-IPv4 from the TUN.
    pub block_ipv6: bool,
}

impl AndroidPlan {
    /// Build the plan for a validated client config.
    #[must_use]
    pub fn from_config(config: &ClientConfig) -> Self {
        Self {
            session: SESSION.to_string(),
            mtu: config.mtu,
            address: TunnelAddress {
                ip: TUNNEL_IP.to_string(),
                prefix: TUNNEL_PREFIX,
            },
            dns: vec![DNS_IP.to_string()],
            routes: vec![IpPrefix::new("0.0.0.0", 0), IpPrefix::new(DNS_IP, 32)],
            apps: AppsSpec {
                mode: AppsMode::All,
                packages: Vec::new(),
            },
            block_ipv6: true,
        }
    }
}

/// Serialize the plan for `AetherCore.clientPlan`.
pub fn plan_json(config: &ClientConfig) -> Result<String> {
    serde_json::to_string(&AndroidPlan::from_config(config))
        .map_err(|e| ClientError::ConfigError(format!("android plan serialization failed: {e}")))
}
