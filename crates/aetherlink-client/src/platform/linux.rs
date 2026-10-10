//! Linux network capture/apply helpers: pure parsers + thin executors.
//!
//! `ip route` output and resolv.conf text are parsed without privileges;
//! mutations go through `ip` (iproute2) and `resolvectl` (systemd-resolved,
//! the Ubuntu 24.04 default) with a `/etc/resolv.conf` fallback, failing
//! gracefully without root/CAP_NET_ADMIN. Target: Ubuntu 24.04.
//!
//! The pure parsers and arg builders compile everywhere (unit-tested on any
//! host); the real [`LinuxPlatform`] is Linux-only.

use std::net::{IpAddr, Ipv4Addr};

use aetherlink_netstack::tun::Route;

#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use aetherlink_netstack::tun::{rollback_plan, RestoreOp, Snapshot};
#[cfg(target_os = "linux")]
use crate::{ClientError, Result};

/// Client-side TUN address prefix, matching `lifecycle::CLIENT_TUN_IP`.
#[cfg(target_os = "linux")]
const TUN_PREFIX: u8 = 30;

/// Crash-recovery dir (the state file from `default_state_path` lives here).
#[cfg(target_os = "linux")]
const STATE_DIR: &str = "/var/lib/aetherlink";

/// Backup of the replaced `/etc/resolv.conf` contents (fallback DNS path).
#[cfg(target_os = "linux")]
const RESOLV_BACKUP: &str = "/var/lib/aetherlink/resolv.conf.bak";

/// Marker describing what `/etc/resolv.conf` was before we replaced it:
/// `symlink\t<target>`, `file`, or `missing`. Without it restore is a no-op
/// (never guess about system files).
#[cfg(target_os = "linux")]
const RESOLV_MODE: &str = "/var/lib/aetherlink/resolv.conf.mode";

/// Parsed `ip -4 route` table (only rows with a gateway are kept: the
/// snapshot feeds `previous_gateway`; connected routes restore themselves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRouteTable {
    /// Rows with a `via` gateway (`default` normalized as `"default"`).
    pub routes: Vec<Route>,
    /// Gateway of the effective default row, if any.
    pub default_via: Option<Ipv4Addr>,
    /// Device of the effective default row, if any (the DNS-forcing target).
    pub default_dev: Option<String>,
    /// Metric of the effective default row (lowest wins among several).
    pub default_metric: Option<u32>,
}

/// Parse `ip -4 route` output.
///
/// Locale-independent: rows are keyword-shaped
/// (`default via 192.168.1.1 dev wlan0 proto dhcp metric 600`), never
/// localized. Unknown row shapes (blackhole, unreachable, v6 leftovers) are
/// skipped, not errors.
#[must_use]
pub fn parse_ip_route(output: &str) -> IpRouteTable {
    let mut table = IpRouteTable {
        routes: Vec::new(),
        default_via: None,
        default_dev: None,
        default_metric: None,
    };
    for line in output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        // Destination token: `default` or a CIDR; anything else (table
        // markers, v6, throwaway rows) is not a main-table v4 route.
        let dest = if cols[0] == "default" {
            "default".to_string()
        } else if cols[0].contains('/')
            && cols[0].split_once('/').is_some_and(|(ip, p)| {
                ip.parse::<Ipv4Addr>().is_ok() && p.parse::<u8>().is_ok()
            })
        {
            cols[0].to_string()
        } else {
            continue;
        };
        let mut via: Option<String> = None;
        let mut dev: Option<String> = None;
        let mut metric: Option<u32> = None;
        let mut i = 1;
        while i < cols.len() {
            match cols.get(i) {
                Some(&"via") => {
                    if let Some(v) = cols.get(i + 1) {
                        if v.parse::<IpAddr>().is_ok() {
                            via = Some(v.to_string());
                        }
                        i += 2;
                        continue;
                    }
                }
                Some(&"dev") => {
                    if let Some(d) = cols.get(i + 1) {
                        dev = Some(d.to_string());
                    }
                    i += 2;
                    continue;
                }
                Some(&"metric") => {
                    if let Some(m) = cols.get(i + 1).and_then(|m| m.parse::<u32>().ok()) {
                        metric = Some(m);
                    }
                    i += 2;
                    continue;
                }
                _ => {}
            }
            i += 1;
        }
        if dest == "default" {
            // Several defaults (multi-homed box): the kernel routes traffic
            // through the lowest metric one — bind DNS/pinning to that.
            let better = table.default_via.is_none()
                && table.default_dev.is_none()
                || metric.zip(table.default_metric).is_some_and(|(m, cur)| m < cur);
            if better {
                table.default_via = via.as_ref().and_then(|v| v.parse().ok());
                table.default_dev = dev;
                table.default_metric = metric;
            }
        }
        if let Some(via) = via {
            table.routes.push(Route { dest, via });
        }
    }
    table
}

/// Parse `resolvectl dns <iface>` output:
/// `Link 2 (wlan0): 192.168.1.1 10.255.0.1`.
#[must_use]
pub fn parse_resolvectl_dns(output: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in output.lines() {
        // Everything after the first `:` is the server list; lines without
        // one (continuations) are scanned whole.
        let body = line.split_once(':').map_or(line, |(_, rest)| rest);
        for token in body.split_whitespace() {
            if token.parse::<IpAddr>().is_ok() {
                out.push(token.to_string());
            }
        }
    }
    out
}

/// Parse `/etc/resolv.conf` `nameserver` lines.
#[must_use]
pub fn parse_resolv_conf(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(char::is_whitespace))
        .filter(|(key, _)| key.trim() == "nameserver")
        .filter_map(|(_, value)| {
            let value = value.trim();
            value.parse::<IpAddr>().ok().map(|_| value.to_string())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Command argument builders (pure; tested without privileges).
// ---------------------------------------------------------------------------

/// `ip addr add <cidr> dev <iface>`.
#[must_use]
pub fn ip_addr_add_args(iface: &str, cidr: &str) -> Vec<String> {
    ["addr", "add", cidr, "dev", iface]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// `ip link set dev <iface> mtu <mtu> up`.
#[must_use]
pub fn ip_link_up_args(iface: &str, mtu: u32) -> Vec<String> {
    ["link", "set", "dev", iface, "mtu", &mtu.to_string(), "up"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// `ip link del <iface>` (crash-recovery teardown; non-persistent TUNs are
/// usually already gone when their owner dies).
#[must_use]
pub fn ip_link_del_args(iface: &str) -> Vec<String> {
    ["link", "del", iface].iter().map(|s| s.to_string()).collect()
}

/// `ip route add <dest> via <gateway>`.
#[must_use]
pub fn ip_route_add_via_args(dest: &str, via: &Ipv4Addr) -> Vec<String> {
    ["route", "add", dest, "via", &via.to_string()]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// `ip route add <dest> via <gateway> dev <iface>` (def1 halves). The
/// gateway is the virtual DNS/gateway IP on our /30, so it is on-link on the
/// TUN and the kernel hands the packet straight to the fd (TUN is NOARP).
#[must_use]
pub fn ip_route_add_via_dev_args(dest: &str, via: &Ipv4Addr, iface: &str) -> Vec<String> {
    ["route", "add", dest, "via", &via.to_string(), "dev", iface]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// `ip route del <dest>`.
#[must_use]
pub fn ip_route_del_args(dest: &str) -> Vec<String> {
    ["route", "del", dest].iter().map(|s| s.to_string()).collect()
}

/// `resolvectl dns <iface> <server>` (per-link override; Ubuntu 24.04 uses
/// systemd-resolved, so this retargets every stub query into the tunnel).
#[must_use]
pub fn resolvectl_dns_args(iface: &str, dns: &Ipv4Addr) -> Vec<String> {
    ["dns", iface, &dns.to_string()]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// `resolvectl dns <iface>` without servers = query the current set.
#[must_use]
pub fn resolvectl_dns_query_args(iface: &str) -> Vec<String> {
    ["dns", iface].iter().map(|s| s.to_string()).collect()
}

/// `resolvectl domain <iface> ~.` (route ALL domains to this link's DNS).
#[must_use]
pub fn resolvectl_domain_args(iface: &str) -> Vec<String> {
    ["domain", iface, "~."].iter().map(|s| s.to_string()).collect()
}

/// `resolvectl revert <iface>` (drop our per-link override; resolved falls
/// back to whatever the link owner — DHCP/NM — provides).
#[must_use]
pub fn resolvectl_revert_args(iface: &str) -> Vec<String> {
    ["revert", iface].iter().map(|s| s.to_string()).collect()
}

/// Normalize a rule destination to `ip route` form (`ip` → `ip/32`).
/// Ranges (`lo-hi`) have no iproute2 form and come back as `None`.
#[must_use]
pub fn route_dest_cidr(dest: &str) -> Option<String> {
    if dest.contains('/') {
        Some(dest.to_string())
    } else if dest.parse::<Ipv4Addr>().is_ok() {
        Some(format!("{dest}/32"))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Executor plumbing + the platform (Linux only).
// ---------------------------------------------------------------------------

/// Run a command, returning stdout or a named error.
#[cfg(target_os = "linux")]
fn run(prog: &str, args: &[String]) -> Result<String> {
    aetherlink_netstack::debug_log(&format!("run: {prog} {}", args.join(" ")));
    let out = std::process::Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| ClientError::PlatformError(format!("spawn {prog}: {e}")))?;
    if !out.status.success() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        aetherlink_netstack::debug_log(&format!(
            "run failed: {prog} status={} out={} err={}",
            out.status,
            stdout.trim(),
            stderr.trim()
        ));
        return Err(ClientError::PlatformError(format!(
            "{prog} failed: {}",
            stderr.trim().lines().next().unwrap_or_default()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn ip(args: &[String]) -> Result<String> {
    run("ip", args)
}

/// Treat "route already exists" as success (stale state converges).
/// iproute2: `RTNETLINK answers: File exists`.
#[cfg(target_os = "linux")]
fn tolerate_exists<T>(r: Result<T>, what: &str) -> Result<()> {
    match r {
        Ok(_) => Ok(()),
        Err(ClientError::PlatformError(msg))
            if msg.contains("exists") || msg.contains("существует") =>
        {
            aetherlink_netstack::debug_log(&format!("route {what} exists, keeping"));
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Treat "route not there" as success (idempotent deletes during replay).
#[cfg(target_os = "linux")]
fn tolerate_missing<T>(r: Result<T>, what: &str) -> Result<()> {
    match r {
        Ok(_) => Ok(()),
        Err(ClientError::PlatformError(msg))
            if msg.contains("No such process") || msg.contains("No such device") =>
        {
            aetherlink_netstack::debug_log(&format!("del {what}: not there, ok"));
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Probe whether systemd-resolved is answering (`resolvectl status`).
#[cfg(target_os = "linux")]
fn resolved_available() -> bool {
    std::process::Command::new("resolvectl")
        .arg("status")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Snapshot what `/etc/resolv.conf` is (symlink target / file / missing) so
/// restore can recreate exactly that. Idempotent: a marker from an earlier
/// force wins (we must never back up our own replacement file).
#[cfg(target_os = "linux")]
fn backup_resolv_conf() -> Result<()> {
    if PathBuf::from(RESOLV_MODE).exists() {
        return Ok(());
    }
    let path = PathBuf::from("/etc/resolv.conf");
    let mode = match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let target = std::fs::read_link(&path).map_err(|e| {
                ClientError::PlatformError(format!("readlink /etc/resolv.conf: {e}"))
            })?;
            format!("symlink\t{}", target.display())
        }
        Ok(_) => {
            let content = std::fs::read_to_string(&path).map_err(|e| {
                ClientError::PlatformError(format!("read /etc/resolv.conf: {e}"))
            })?;
            std::fs::write(RESOLV_BACKUP, content).map_err(|e| {
                ClientError::PlatformError(format!("backup /etc/resolv.conf: {e}"))
            })?;
            "file".to_string()
        }
        Err(_) => "missing".to_string(),
    };
    std::fs::write(RESOLV_MODE, mode)
        .map_err(|e| ClientError::PlatformError(format!("write resolv mode marker: {e}")))
}

/// Recreate `/etc/resolv.conf` exactly as recorded by the marker. Without a
/// marker this is a no-op (never guess about system files). `servers` is
/// last-resort content when the backup itself is unreadable.
#[cfg(target_os = "linux")]
fn restore_resolv_conf(servers: &[String]) {
    let path = PathBuf::from("/etc/resolv.conf");
    let mode = match std::fs::read_to_string(RESOLV_MODE) {
        Ok(mode) => mode,
        Err(_) => {
            aetherlink_netstack::debug_log("resolv.conf restore: no marker, no-op");
            return;
        }
    };
    let result = if let Some(target) = mode.strip_prefix("symlink\t") {
        let _ = std::fs::remove_file(&path);
        std::os::unix::fs::symlink(target.trim(), &path).map_err(|e| {
            ClientError::PlatformError(format!("restore resolv.conf symlink: {e}"))
        })
    } else if mode.trim() == "file" {
        let content = std::fs::read_to_string(RESOLV_BACKUP).unwrap_or_else(|_| {
            servers
                .iter()
                .map(|s| format!("nameserver {s}\n"))
                .collect::<String>()
        });
        std::fs::write(&path, content)
            .map_err(|e| ClientError::PlatformError(format!("restore resolv.conf: {e}")))
    } else {
        // "missing": we created the file, put the world back to no file.
        std::fs::remove_file(&path).map_err(|e| {
            ClientError::PlatformError(format!("remove created resolv.conf: {e}"))
        })
    };
    match result {
        Ok(()) => {
            let _ = std::fs::remove_file(RESOLV_MODE);
            let _ = std::fs::remove_file(RESOLV_BACKUP);
            aetherlink_netstack::debug_log("resolv.conf restored");
        }
        Err(e) => aetherlink_netstack::debug_log(&format!("resolv.conf restore: {e}")),
    }
}

/// Which DNS override method `force_dns` applied (restore mirrors it).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum DnsBackend {
    #[default]
    Unset,
    /// `resolvectl` per-link override (Ubuntu 24.04 default).
    Resolved,
    /// `/etc/resolv.conf` rewrite (resolved-less fallback).
    ResolvConf,
}

/// Real Linux backend: iproute2 + `/dev/net/tun` + systemd-resolved.
///
/// Needs root/CAP_NET_ADMIN for mutations; every step fails with a named
/// error otherwise. Mirrors the Windows `RealPlatform` contract exactly, so
/// `lifecycle::up/down` and crash recovery are shared verbatim.
#[cfg(target_os = "linux")]
pub struct LinuxPlatform {
    /// Destinations this instance added (legacy `restore`).
    added_routes: Vec<String>,
    /// Physical default interface captured at `snapshot` time.
    default_iface: Option<String>,
    /// Granted TUN name (the kernel may rename on collision).
    tun_name: Option<String>,
    /// DNS override method in use (restore mirrors it).
    dns_backend: DnsBackend,
    /// Live TUN handle, shared with pump threads after attach.
    tun: Option<Arc<Mutex<aetherlink_netstack::tun::TunInterface>>>,
}

#[cfg(target_os = "linux")]
impl Default for LinuxPlatform {
    fn default() -> Self {
        Self {
            added_routes: Vec::new(),
            default_iface: None,
            tun_name: None,
            dns_backend: DnsBackend::Unset,
            tun: None,
        }
    }
}

#[cfg(target_os = "linux")]
impl LinuxPlatform {
    /// Fresh real backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Shared handle to the live TUN device, if up (for pump attach).
    #[must_use]
    pub fn tun_handle(&self) -> Option<Arc<Mutex<aetherlink_netstack::tun::TunInterface>>> {
        self.tun.clone()
    }

    /// Drop the held TUN handle: the last owner closing the fd deletes the
    /// non-persistent device. Without a handle (crash recovery) do a
    /// best-effort `ip link del` in case something still carries the name.
    fn drop_tun(&mut self, name: &str) -> Result<()> {
        match self.tun.take() {
            Some(tun) => match Arc::try_unwrap(tun) {
                Ok(mutex) => {
                    let iface = mutex
                        .into_inner()
                        .map_err(|_| ClientError::PlatformError("tun lock poisoned".to_string()))?;
                    iface.delete().map_err(|e| {
                        let e = ClientError::PlatformError(format!("tun down: {e}"));
                        aetherlink_netstack::debug_log(&format!("{e}"));
                        e
                    })
                }
                Err(_) => {
                    aetherlink_netstack::debug_log("tun_down: handle shared, ownership dropped");
                    Ok(())
                }
            },
            None => {
                match ip(&ip_link_del_args(name)) {
                    Ok(_) => aetherlink_netstack::debug_log(&format!("tun_down: {name} deleted")),
                    Err(e) => aetherlink_netstack::debug_log(&format!(
                        "tun_down: {name} already gone ({e})"
                    )),
                }
                Ok(())
            }
        }
    }

    /// Read current DNS servers: `resolvectl dns <iface>` when resolved is
    /// up, else `/etc/resolv.conf`.
    fn read_dns_servers(iface: Option<&str>) -> Vec<String> {
        if resolved_available() {
            if let Some(iface) = iface {
                if let Ok(out) = run("resolvectl", &resolvectl_dns_query_args(iface)) {
                    let servers = parse_resolvectl_dns(&out);
                    if !servers.is_empty() {
                        return servers;
                    }
                }
            }
        }
        match std::fs::read_to_string("/etc/resolv.conf") {
            Ok(text) => parse_resolv_conf(&text),
            Err(_) => Vec::new(),
        }
    }

    /// Restore DNS. Source of truth is the `/etc/resolv.conf` marker: if it
    /// exists, an earlier run rewrote resolv.conf and we replay that exactly
    /// (this is what makes crash recovery correct even when `dns_backend`
    /// was lost — fresh instance — or resolved restarted meanwhile). Only
    /// without a marker do we `resolvectl revert` the persisted interface.
    /// Best-effort, traced.
    fn restore_dns(&self, iface: &str, servers: &[String]) -> Result<()> {
        if PathBuf::from(RESOLV_MODE).exists() {
            restore_resolv_conf(servers);
            return Ok(());
        }
        if self.dns_backend != DnsBackend::ResolvConf && !iface.is_empty() && resolved_available()
        {
            match run("resolvectl", &resolvectl_revert_args(iface)) {
                Ok(_) => {
                    aetherlink_netstack::debug_log(&format!("dns restored: revert {iface}"));
                    return Ok(());
                }
                Err(e) => aetherlink_netstack::debug_log(&format!(
                    "dns revert {iface} failed ({e}), trying resolv.conf"
                )),
            }
        }
        restore_resolv_conf(servers);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl super::Platform for LinuxPlatform {
    fn resolve_host(&mut self, host: &str) -> Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs as _;
        let addrs: Vec<IpAddr> = format!("{host}:443")
            .to_socket_addrs()
            .map(|it| it.map(|a| a.ip()).collect())
            .unwrap_or_default();
        if addrs.is_empty() {
            return Err(ClientError::PlatformError(format!(
                "resolve failed: {host}"
            )));
        }
        Ok(addrs)
    }

    fn snapshot(&mut self) -> Result<Snapshot> {
        let out = ip(&["-4".to_string(), "route".to_string(), "show".to_string()])?;
        let table = parse_ip_route(&out);
        let dns = Self::read_dns_servers(table.default_dev.as_deref());
        aetherlink_netstack::debug_log(&format!(
            "snapshot: default_dev={:?} via={:?} dns={:?}",
            table.default_dev, table.default_via, dns
        ));
        self.default_iface = table.default_dev.clone();
        Ok(Snapshot {
            routes: table.routes,
            dns_servers: dns,
        })
    }

    fn tun_up(&mut self, name: &str, addr: Ipv4Addr, mtu: u32) -> Result<()> {
        // State dir first: the journal persists right after this step.
        std::fs::create_dir_all(STATE_DIR)
            .map_err(|e| ClientError::PlatformError(format!("create {STATE_DIR}: {e} (root?)")))?;
        let iface = aetherlink_netstack::tun::TunInterface::open(name)
            .map_err(|e| ClientError::PlatformError(format!("tun open: {e}")))?;
        let dev = iface.name.clone();
        // Address the point-to-link (/30: .1 = virtual gateway/DNS,
        // .2 = us), then bring it up with the negotiated MTU.
        let cidr = format!("{addr}/{TUN_PREFIX}");
        tolerate_exists(ip(&ip_addr_add_args(&dev, &cidr)), &cidr)?;
        ip(&ip_link_up_args(&dev, mtu))?;
        self.tun_name = Some(dev.clone());
        self.tun = Some(Arc::new(Mutex::new(iface)));
        aetherlink_netstack::debug_log(&format!("tun_up: {dev} up (mtu {mtu})"));
        Ok(())
    }

    fn tun_down(&mut self) -> Result<()> {
        let name = self
            .tun_name
            .clone()
            .unwrap_or_else(|| "aether0".to_string());
        self.drop_tun(&name)
    }

    fn captured_iface(&self) -> Option<String> {
        self.default_iface.clone()
    }

    fn tun_ifindex(&self) -> Option<u32> {
        self.tun
            .as_ref()
            .and_then(|t| t.lock().ok())
            .and_then(|g| g.adapter_index().ok())
    }

    fn pin_route(&mut self, dest: IpAddr, via: Ipv4Addr) -> Result<()> {
        let dest = match dest {
            IpAddr::V4(ip) => format!("{ip}/32"),
            IpAddr::V6(_) => {
                return Err(ClientError::PlatformError(
                    "ipv6 pin routes pending".to_string(),
                ));
            }
        };
        let args = ip_route_add_via_args(&dest, &via);
        tolerate_exists(ip(&args), &format!("pin {dest}"))?;
        self.added_routes.push(dest);
        Ok(())
    }

    fn add_route(&mut self, dest: &str, via: Ipv4Addr) -> Result<()> {
        // `dest` arrives as `ip`, `base/prefix`, or `lo-hi`; ranges are
        // rejected (iproute2 has no range routes) instead of misapplied.
        let Some(cidr) = route_dest_cidr(dest) else {
            return Err(ClientError::PlatformError(format!(
                "ip ranges unsupported, split it: {dest}"
            )));
        };
        let args = ip_route_add_via_args(&cidr, &via);
        tolerate_exists(ip(&args), &format!("route {cidr}"))?;
        self.added_routes.push(cidr);
        Ok(())
    }

    fn default_via_tun(&mut self) -> Result<()> {
        // OpenVPN-style def1: two /1 routes beat the existing default without
        // touching it (no metric wars, instant rollback). The gateway is the
        // virtual DNS/gateway IP on our /30, on-link on the TUN (NOARP),
        // mirroring the Windows def1 gateway.
        let dev = self.tun_name.clone().ok_or_else(|| {
            ClientError::PlatformError("no live TUN for default route".to_string())
        })?;
        let gw = crate::lifecycle::VIRTUAL_DNS_IP;
        for dest in ["0.0.0.0/1", "128.0.0.0/1"] {
            let args = ip_route_add_via_dev_args(dest, &gw, &dev);
            tolerate_exists(ip(&args), &format!("default-via-tun {dest}"))?;
            self.added_routes.push(dest.to_string());
        }
        Ok(())
    }

    fn force_dns(&mut self, dns_ip: Ipv4Addr) -> Result<()> {
        let iface = self.default_iface.clone().ok_or_else(|| {
            ClientError::PlatformError("no captured interface for DNS forcing".to_string())
        })?;
        if resolved_available() {
            // Ubuntu 24.04 default: per-link override on the physical iface.
            // Queries go to the virtual resolver and are routed over the TUN
            // (10.255.0.0/30 is on-link there), so DNS cannot leak while up.
            aetherlink_netstack::debug_log(&format!("force_dns: resolved on {iface} -> {dns_ip}"));
            run("resolvectl", &resolvectl_dns_args(&iface, &dns_ip))?;
            run("resolvectl", &resolvectl_domain_args(&iface))?;
            self.dns_backend = DnsBackend::Resolved;
            return Ok(());
        }
        // Fallback (no systemd-resolved): replace /etc/resolv.conf, keeping
        // a marker + backup for exact restore.
        aetherlink_netstack::debug_log(&format!("force_dns: resolv.conf rewrite -> {dns_ip}"));
        backup_resolv_conf()?;
        std::fs::write("/etc/resolv.conf", format!("nameserver {dns_ip}\n"))
            .map_err(|e| ClientError::PlatformError(format!("write /etc/resolv.conf: {e}")))?;
        self.dns_backend = DnsBackend::ResolvConf;
        Ok(())
    }

    fn restore(&mut self, snap: &Snapshot) -> Result<()> {
        let mut added = std::mem::take(&mut self.added_routes);
        added.reverse();
        for dest in added {
            match tolerate_missing(ip(&ip_route_del_args(&dest)), &dest) {
                Ok(()) => aetherlink_netstack::debug_log(&format!("restore: del {dest} ok")),
                Err(e) => aetherlink_netstack::debug_log(&format!("restore: del {dest}: {e}")),
            }
        }
        self.restore_dns(
            self.default_iface.as_deref().unwrap_or_default(),
            &snap.dns_servers,
        )
    }

    /// Replay a persisted applied-change log (crash recovery: per-instance
    /// state is empty, the file is the only truth). Best-effort per op;
    /// joined issues come back as `Err`.
    fn restore_applied(&mut self, state: &aetherlink_netstack::tun::UpState) -> Result<()> {
        let mut issues: Vec<String> = Vec::new();
        for op in rollback_plan(&state.applied) {
            let r = match &op {
                RestoreOp::RemoveDefaultViaTun => {
                    let mut last = Ok(());
                    for dest in ["0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/0"] {
                        match tolerate_missing(ip(&ip_route_del_args(dest)), dest) {
                            Ok(()) => aetherlink_netstack::debug_log(&format!(
                                "replay: del default {dest} ok"
                            )),
                            Err(e) => {
                                aetherlink_netstack::debug_log(&format!(
                                    "replay: del default {dest}: {e}"
                                ));
                                last = Err(e);
                            }
                        }
                    }
                    last.map(|_| ())
                }
                RestoreOp::RemovePinnedRoute(dest) => match route_dest_cidr(dest) {
                    Some(cidr) => tolerate_missing(ip(&ip_route_del_args(&cidr)), &cidr),
                    None => {
                        issues.push(format!("skip unparsable route {dest}"));
                        continue;
                    }
                },
                RestoreOp::TunDown(name) => self.drop_tun(name),
                RestoreOp::RestoreDns(servers) => {
                    // DNS returns on the persisted up-time interface; legacy
                    // states without it try a live lookup.
                    let iface = if state.dns_iface.is_empty() {
                        self.default_iface.clone().unwrap_or_default()
                    } else {
                        state.dns_iface.clone()
                    };
                    self.restore_dns(&iface, servers)
                }
            };
            match r {
                Ok(()) => aetherlink_netstack::debug_log(&format!("replay: {op:?} ok")),
                Err(e) => {
                    aetherlink_netstack::debug_log(&format!("replay: {op:?}: {e}"));
                    issues.push(format!("{op:?}: {e}"));
                }
            }
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(ClientError::PlatformError(issues.join("; ")))
        }
    }
}
