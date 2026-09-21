//! Windows network capture/apply helpers: pure parsers + thin executors.
//!
//! `route print -4` and `ipconfig` outputs are parsed without privileges;
//! mutations go through `route`/`netsh` and fail gracefully without admin.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

use aetherlink_netstack::tun::Route;

use crate::{ClientError, Result};

/// Parsed IPv4 routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTable {
    /// All captured rows (default stored as `"default"`).
    pub routes: Vec<Route>,
    /// Default gateway, if a default row parsed.
    pub default_gateway: Option<Ipv4Addr>,
    /// Interface IP of the default row, if present.
    pub default_iface_ip: Option<Ipv4Addr>,
}

impl RouteTable {
    /// Default gateway, if captured.
    #[must_use]
    pub fn default_gateway(&self) -> Option<Ipv4Addr> {
        self.default_gateway
    }

    /// Interface IP carrying the default route, if captured.
    #[must_use]
    pub fn default_iface_ip(&self) -> Option<Ipv4Addr> {
        self.default_iface_ip
    }
}

/// Count mask bits (`255.255.255.0` → 24).
fn mask_prefix(mask: Ipv4Addr) -> u32 {
    u32::from(mask).count_ones()
}

/// Parse `route print -4` output.
///
/// Locale-independent by design: section headers are localized
/// (`Active Routes:` vs `Активные маршруты:`), but data rows always look
/// like `dest mask gateway iface metric`. Any line matching that shape is
/// a row; persistent routes doubling as regular rows is harmless because
/// restore is best-effort and re-adding an existing route is a no-op error.
pub fn parse_route_print(output: &str) -> Result<RouteTable> {
    let mut routes = Vec::new();
    let mut default_gateway = None;
    let mut default_iface_ip = None;
    for line in output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 {
            continue;
        }
        let Ok(dest_ip) = cols[0].parse::<Ipv4Addr>() else {
            continue;
        };
        let Ok(mask_ip) = cols[1].parse::<Ipv4Addr>() else {
            continue;
        };
        let Ok(iface_ip) = cols[3].parse::<Ipv4Addr>() else {
            continue;
        };
        let prefix = mask_prefix(mask_ip);
        let dest = if dest_ip.is_unspecified() && prefix == 0 {
            "default".to_string()
        } else {
            format!("{dest_ip}/{prefix}")
        };
        let via = if cols[2].eq_ignore_ascii_case("on-link") {
            iface_ip.to_string()
        } else {
            if cols[2].parse::<Ipv4Addr>().is_err() {
                continue;
            }
            cols[2].to_string()
        };
        if dest == "default" {
            default_gateway = cols[2].parse().ok();
            default_iface_ip = Some(iface_ip);
        }
        routes.push(Route { dest, via });
    }
    Ok(RouteTable {
        routes,
        default_gateway,
        default_iface_ip,
    })
}

/// Parse `ipconfig /all` output into `(dns_servers, adapter_name → ipv4)`.
///
/// Locale-independent: matches on technical tokens (`DNS`, `IPv4`, absence
/// of dots in header lines) instead of translated labels. Handles DNS
/// continuation lines and `(Preferred)` suffixes.
pub fn parse_ipconfig(output: &str) -> (Vec<String>, HashMap<String, String>) {
    let mut dns = Vec::new();
    let mut ifaces = HashMap::new();
    let mut adapter: Option<String> = None;
    let mut in_dns = false;
    for raw in output.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            in_dns = false;
            continue;
        }
        if let Some((label, value)) = trimmed.split_once(':') {
            let upper = label.to_uppercase();
            in_dns = upper.contains("DNS");
            // Header lines carry no dots ("Ethernet adapter X:" in any language).
            if trimmed.ends_with(':') && !label.contains('.') {
                let lower = label.to_lowercase();
                let name = if let Some(pos) = lower.find(" adapter ") {
                    label[pos + " adapter ".len()..].trim().to_string()
                } else {
                    label
                        .split_whitespace()
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                if !name.is_empty() {
                    adapter = Some(name);
                }
                continue;
            }
            let value = value
                .trim()
                .trim_end_matches("(Preferred)")
                .trim()
                .to_string();
            if in_dns {
                if !value.is_empty() && value.parse::<Ipv4Addr>().is_ok() {
                    dns.push(value);
                }
            } else if upper.contains("IPV4") {
                if let (Some(name), Ok(_)) = (adapter.clone(), value.parse::<Ipv4Addr>()) {
                    ifaces.insert(name, value);
                }
            }
            continue;
        }
        // Bare continuation line: only meaningful inside a DNS block.
        if in_dns && trimmed.parse::<Ipv4Addr>().is_ok() {
            dns.push(trimmed.to_string());
        } else {
            in_dns = false;
        }
    }
    (dns, ifaces)
}

/// Prefix length → dotted mask (`24` → `255.255.255.0`).
pub fn prefix_to_mask(prefix: u8) -> Result<String> {
    if prefix > 32 {
        return Err(ClientError::RoutingError(format!("bad prefix {prefix}")));
    }
    let mask = if prefix == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(!0u32 << (32 - prefix))
    };
    Ok(mask.to_string())
}

/// Validate a `base/prefix` destination for `route` commands.
fn split_cidr(dest: &str) -> Result<(String, String)> {
    let (base, prefix) = dest
        .split_once('/')
        .ok_or_else(|| ClientError::RoutingError(format!("bad dest {dest}")))?;
    base.parse::<Ipv4Addr>()
        .map_err(|_| ClientError::RoutingError(format!("bad dest {dest}")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ClientError::RoutingError(format!("bad dest {dest}")))?;
    Ok((base.to_string(), prefix_to_mask(prefix)?))
}

fn check_gateway(gateway: &str) -> Result<()> {
    gateway
        .parse::<Ipv4Addr>()
        .map(|_| ())
        .map_err(|_| ClientError::RoutingError(format!("bad gateway {gateway}")))
}

/// Arg vector for `route add <dest> mask <mask> <gw>`.
pub fn route_add_args(dest_cidr: &str, gateway: &str) -> Result<Vec<String>> {
    let (base, mask) = split_cidr(dest_cidr)?;
    check_gateway(gateway)?;
    Ok(vec![
        "add".to_string(),
        base,
        "mask".to_string(),
        mask,
        gateway.to_string(),
    ])
}

/// Arg vector for `route delete <dest> mask <mask> <gw>`.
pub fn route_delete_args(dest_cidr: &str, gateway: &str) -> Result<Vec<String>> {
    let (base, mask) = split_cidr(dest_cidr)?;
    check_gateway(gateway)?;
    Ok(vec![
        "delete".to_string(),
        base,
        "mask".to_string(),
        mask,
        gateway.to_string(),
    ])
}

/// Arg vector for `netsh interface ip set dnsservers <iface> static <dns>`.
#[must_use]
pub fn dns_set_args(iface: &str, dns: &str) -> Vec<String> {
    vec![
        "interface".to_string(),
        "ip".to_string(),
        "set".to_string(),
        "dnsservers".to_string(),
        iface.to_string(),
        "static".to_string(),
        dns.to_string(),
    ]
}

/// Run `route print -4` and parse it (read-only, no privileges needed).
pub fn read_route_table() -> Result<RouteTable> {
    let out = Command::new("route")
        .args(["print", "-4"])
        .output()
        .map_err(|e| ClientError::PlatformError(format!("route print: {e}")))?;
    if !out.status.success() {
        return Err(ClientError::PlatformError("route print failed".to_string()));
    }
    parse_route_print(&String::from_utf8_lossy(&out.stdout))
}

/// Run `ipconfig /all` and return DNS servers (read-only, no privileges).
pub fn read_dns() -> Result<Vec<String>> {
    let out = Command::new("ipconfig")
        .args(["/all"])
        .output()
        .map_err(|e| ClientError::PlatformError(format!("ipconfig: {e}")))?;
    if !out.status.success() {
        return Err(ClientError::PlatformError("ipconfig failed".to_string()));
    }
    Ok(parse_ipconfig(&String::from_utf8_lossy(&out.stdout)).0)
}
