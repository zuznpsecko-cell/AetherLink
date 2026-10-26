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
    /// Build the plan for a validated client config (no per-app split).
    pub fn from_config(config: &ClientConfig) -> Result<Self> {
        Self::from_split(config, &config.android_split)
    }

    /// Build the plan for a config plus an explicit split selection.
    ///
    /// Fails with [`ClientError::ConfigError`] when the split selection is
    /// inconsistent (empty allow list, `0.0.0.0/0` in `subnets`, bad package
    /// name, malformed CIDR).
    pub fn from_split(config: &ClientConfig, split: &AndroidSplit) -> Result<Self> {
        validate_split(split)?;
        let apps = AppsSpec {
            mode: match split.mode {
                SplitMode::All => AppsMode::All,
                SplitMode::Allow => AppsMode::Allow,
                SplitMode::Deny => AppsMode::Deny,
                // `subnets` filters by destination, not by app.
                SplitMode::Subnets => AppsMode::All,
            },
            packages: match split.mode {
                SplitMode::Allow | SplitMode::Deny => split.apps.clone(),
                SplitMode::All | SplitMode::Subnets => Vec::new(),
            },
        };
        Ok(Self {
            session: SESSION.to_string(),
            mtu: config.mtu,
            address: TunnelAddress {
                ip: TUNNEL_IP.to_string(),
                prefix: TUNNEL_PREFIX,
            },
            dns: vec![DNS_IP.to_string()],
            routes: routes_for(config, split)?,
            apps,
            block_ipv6: true,
        })
    }
}

/// Split-tunnel selection as it arrives from config or the app picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidSplit {
    /// Which routing rule applies.
    pub mode: SplitMode,
    /// Package names for `allow` / `deny`.
    pub apps: Vec<String>,
    /// CIDR strings for `subnets`.
    pub subnets: Vec<String>,
}

impl Default for AndroidSplit {
    fn default() -> Self {
        Self {
            mode: SplitMode::All,
            apps: Vec::new(),
            subnets: Vec::new(),
        }
    }
}

/// Split mode as it arrives from config (UI only offers `all` and `allow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitMode {
    /// Everything through the tunnel.
    All,
    /// Only `apps`.
    Allow,
    /// Everything except `apps`.
    Deny,
    /// Only `subnets`.
    Subnets,
}

/// Validate a split selection: package names, mode/list consistency, CIDRs.
pub fn validate_split(split: &AndroidSplit) -> Result<()> {
    for pkg in &split.apps {
        if !is_valid_package(pkg) {
            return Err(ClientError::ConfigError(format!(
                "invalid package name: {pkg:?}"
            )));
        }
    }
    match split.mode {
        SplitMode::All => {
            if !split.apps.is_empty() {
                return Err(ClientError::ConfigError(
                    "all mode does not take a package list".to_string(),
                ));
            }
            if !split.subnets.is_empty() {
                return Err(ClientError::ConfigError(
                    "all mode does not take subnet list".to_string(),
                ));
            }
        }
        SplitMode::Allow | SplitMode::Deny => {
            let label = if split.mode == SplitMode::Allow {
                "allow"
            } else {
                "deny"
            };
            if split.apps.is_empty() {
                return Err(ClientError::ConfigError(format!(
                    "{label} mode needs at least one package"
                )));
            }
            if !split.subnets.is_empty() {
                return Err(ClientError::ConfigError(format!(
                    "{label} mode does not take subnet list"
                )));
            }
        }
        SplitMode::Subnets => {
            if !split.apps.is_empty() {
                return Err(ClientError::ConfigError(
                    "subnets mode does not take a package list".to_string(),
                ));
            }
            if split.subnets.is_empty() {
                return Err(ClientError::ConfigError(
                    "subnets mode needs at least one subnet".to_string(),
                ));
            }
            for cidr in &split.subnets {
                parse_cidr(cidr)?;
            }
        }
    }
    Ok(())
}

/// Package names Android accepts in `addAllowedApplication`.
fn is_valid_package(pkg: &str) -> bool {
    !pkg.is_empty()
        && pkg.split('.').all(|part| !part.is_empty())
        && pkg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
}

/// Parse `a.b.c.d/len` into a route, rejecting host bits and `/0`.
fn parse_cidr(cidr: &str) -> Result<IpPrefix> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| ClientError::ConfigError(format!("cidr must be ip/prefix: {cidr:?}")))?;
    let ip: std::net::Ipv4Addr = addr
        .parse()
        .map_err(|_| ClientError::ConfigError(format!("invalid cidr address: {cidr:?}")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ClientError::ConfigError(format!("invalid cidr prefix: {cidr:?}")))?;
    if prefix > 32 {
        return Err(ClientError::ConfigError(format!(
            "invalid cidr prefix: {cidr:?}"
        )));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    if u32::from(ip) & !mask != 0 {
        return Err(ClientError::ConfigError(format!(
            "cidr has host bits set: {cidr:?}"
        )));
    }
    if prefix == 0 {
        return Err(ClientError::ConfigError(
            "0.0.0.0/0 is not a subnet split; use mode: all".to_string(),
        ));
    }
    Ok(IpPrefix::new(&ip.to_string(), prefix))
}

fn routes_for(config: &ClientConfig, split: &AndroidSplit) -> Result<Vec<IpPrefix>> {
    let mut routes = match split.mode {
        SplitMode::Subnets => split
            .subnets
            .iter()
            .map(|cidr| parse_cidr(cidr))
            .collect::<Result<Vec<_>>>()?,
        _ if config.android_lan_direct => {
            // Full tunnel minus LAN, then re-add the tunnel network: the
            // netstack lives inside 10.255.0.0/30, which 10/8 excludes.
            let mut kept = subtract_prefixes(&[IpPrefix::new("0.0.0.0", 0)], &rfc1918());
            kept.push(IpPrefix::new(TUNNEL_NETWORK, TUNNEL_PREFIX));
            kept
        }
        _ => vec![IpPrefix::new("0.0.0.0", 0)],
    };
    let dns = IpPrefix::new(DNS_IP, 32);
    if !routes.contains(&dns) {
        routes.push(dns);
    }
    Ok(sort_routes(routes))
}

/// `10.255.0.0/30` вЂ” the tunnel network the client itself occupies.
pub const TUNNEL_NETWORK: &str = "10.255.0.0";

fn rfc1918() -> Vec<IpPrefix> {
    vec![
        IpPrefix::new("10.0.0.0", 8),
        IpPrefix::new("172.16.0.0", 12),
        IpPrefix::new("192.168.0.0", 16),
    ]
}

/// Sort deterministically by network address, then prefix length. Containment
/// (a `/32` inside a `/30`) is preserved: Android accepts more specific routes,
/// and the DNS route must stay explicit in the plan.
fn sort_routes(routes: Vec<IpPrefix>) -> Vec<IpPrefix> {
    let mut routes = routes;
    routes.sort_by_key(|route| {
        let addr = route
            .ip
            .parse::<std::net::Ipv4Addr>()
            .map(u32::from)
            .unwrap_or(u32::MAX);
        (addr, route.prefix)
    });
    routes
}

/// One inclusive IPv4 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Range {
    start: u32,
    end: u32,
}

fn prefix_range(prefix: &IpPrefix) -> Option<Range> {
    if prefix.prefix > 32 {
        return None;
    }
    let addr = prefix.ip.parse::<std::net::Ipv4Addr>().ok()?;
    let size = 1u64 << (32 - u32::from(prefix.prefix));
    let network = u64::from(u32::from(addr)) & !(size - 1);
    let start = u32::try_from(network).ok()?;
    let end = u32::try_from(network + size - 1).ok()?;
    Some(Range { start, end })
}

/// Merge overlapping or adjacent ranges into a sorted, disjoint list.
fn merge_ranges(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort();
    let mut merged: Vec<Range> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if u64::from(range.start) <= u64::from(last.end) + 1 => {
                last.end = last.end.max(range.end);
            }
            _ => merged.push(range),
        }
    }
    merged
}

fn ranges_to_prefixes(ranges: &[Range]) -> Vec<IpPrefix> {
    let mut out = Vec::new();
    for range in ranges {
        let mut current = u64::from(range.start);
        let end = u64::from(range.end);
        while current <= end {
            let span = if current == 0 {
                1u64 << 32
            } else {
                let low_bit = current & current.wrapping_neg();
                low_bit.min(1u64 << 32)
            };
            let remaining = end - current + 1;
            let mut size = span;
            while size > remaining {
                size >>= 1;
            }
            let prefix = 32 - size.trailing_zeros().min(32);
            // `current` is a u64 view of a u32 range, so this cast is exact.
            let addr = std::net::Ipv4Addr::from(current as u32);
            out.push(IpPrefix::new(
                &addr.to_string(),
                u8::try_from(prefix).unwrap_or(32),
            ));
            current += size;
        }
    }
    out
}

/// Subtract `exclude` from `include`, returning the minimal CIDR cover of
/// what remains: sorted, merged, no overlaps.
///
/// Invalid [`IpPrefix`] values are ignored (the plan builds them from
/// validated config and canonical constants), so a malformed entry can never
/// turn into a silently wider route.
#[must_use]
pub fn subtract_prefixes(include: &[IpPrefix], exclude: &[IpPrefix]) -> Vec<IpPrefix> {
    let includes = merge_ranges(include.iter().filter_map(prefix_range).collect());
    let excludes = merge_ranges(exclude.iter().filter_map(prefix_range).collect());

    let mut remaining = includes;
    for cut in excludes {
        let mut next = Vec::with_capacity(remaining.len() + 1);
        for range in remaining {
            if cut.end < range.start || cut.start > range.end {
                next.push(range);
                continue;
            }
            if range.start < cut.start {
                next.push(Range {
                    start: range.start,
                    end: cut.start - 1,
                });
            }
            if cut.end < range.end {
                next.push(Range {
                    start: cut.end + 1,
                    end: range.end,
                });
            }
        }
        remaining = next;
    }
    ranges_to_prefixes(&merge_ranges(remaining))
}

/// Subtract the RFC1918 ranges from full-tunnel routes.
#[must_use]
pub fn subtract_rfc1918(include: &[IpPrefix]) -> Vec<IpPrefix> {
    subtract_prefixes(include, &rfc1918())
}

/// Serialize the plan for `AetherCore.clientPlan`.
pub fn plan_json(config: &ClientConfig) -> Result<String> {
    plan_json_for(config, &config.android_split)
}

/// Serialize the plan for an explicit split selection.
pub fn plan_json_for(config: &ClientConfig, split: &AndroidSplit) -> Result<String> {
    serde_json::to_string(&AndroidPlan::from_split(config, split)?)
        .map_err(|e| ClientError::ConfigError(format!("android plan serialization failed: {e}")))
}
