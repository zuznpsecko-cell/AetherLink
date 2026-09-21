//! Platform abstraction: real ioctls behind a trait, fake backend for tests.
//!
//! Bring-up policy (`lifecycle::up`) programs against [`Platform`], so the
//! ordering, rollback and idempotency proofs run without privileges on a
//! [`FakePlatform`]. [`RealPlatform`] implements what needs no privileges
//! today (DNS resolution) and fails the rest with an explicit pending error
//! instead of silently no-op'ing.

/// Windows capture/apply helpers (pure parsers + thin `route`/`netsh` builders).
pub mod windows;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use aetherlink_netstack::tun::{Route, Snapshot};

use crate::{ClientError, Result};

/// Bring-up step, for fault injection in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Hostname resolution.
    Resolve,
    /// TUN device creation.
    TunUp,
    /// Server-IP pin route.
    PinRoute,
    /// Custom direct rules.
    DirectRules,
    /// Default route switch.
    DefaultViaTun,
    /// DNS forcing.
    DnsForce,
}

fn pending(what: &str) -> ClientError {
    ClientError::PlatformError(format!("platform apply pending: {what}"))
}

/// Default crash-recovery state file path per OS.
#[must_use]
pub fn default_state_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\AetherLink\state.json")
    } else {
        PathBuf::from("/var/lib/aetherlink/state.json")
    }
}

/// Privileged network operations behind one seam.
pub trait Platform: Send {
    /// Resolve a hostname (system DNS, once, pre-tunnel).
    fn resolve_host(&mut self, host: &str) -> Result<Vec<IpAddr>>;

    /// Capture pre-up routes + DNS.
    fn snapshot(&mut self) -> Result<Snapshot>;

    /// Create + address the TUN device.
    fn tun_up(&mut self, name: &str, addr: Ipv4Addr, mtu: u32) -> Result<()>;

    /// Destroy the TUN device (default: pending).
    fn tun_down(&mut self) -> Result<()> {
        Err(pending("tun_down"))
    }

    /// Pin a route via a gateway (default: pending).
    fn pin_route(&mut self, _dest: IpAddr, _via: Ipv4Addr) -> Result<()> {
        Err(pending("pin_route"))
    }

    /// Install a direct route (default: pending).
    fn add_route(&mut self, _dest: &str, _via: Ipv4Addr) -> Result<()> {
        Err(pending("add_route"))
    }

    /// Switch the default route into TUN (default: pending).
    fn default_via_tun(&mut self) -> Result<()> {
        Err(pending("default_via_tun"))
    }

    /// Force system DNS to the tunnel resolver (default: pending).
    fn force_dns(&mut self, _dns_ip: Ipv4Addr) -> Result<()> {
        Err(pending("force_dns"))
    }

    /// Restore a snapshot (default: pending).
    fn restore(&mut self, _snap: &Snapshot) -> Result<()> {
        Err(pending("restore"))
    }

    /// Crash-recovery state file path.
    fn state_path(&self) -> PathBuf {
        default_state_path()
    }
}

/// Real platform: genuinely privilege-free operations only.
#[derive(Debug, Default)]
pub struct RealPlatform {
    /// Routes this instance added (for `restore`).
    added_routes: Vec<(String, String)>,
}

impl RealPlatform {
    /// Fresh real backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Run a command, returning stdout or a named error (stderr snippet kept short).
fn run(prog: &str, args: &[String]) -> Result<String> {
    let out = std::process::Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| ClientError::PlatformError(format!("spawn {prog}: {e}")))?;
    if !out.status.success() {
        let tail = String::from_utf8_lossy(&out.stderr);
        let tail: String = tail.chars().take(200).collect();
        return Err(ClientError::PlatformError(format!("{prog} failed: {tail}")));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Resolve the local interface name owning `iface_ip` via ipconfig.
fn iface_name_for(iface_ip: Ipv4Addr) -> Result<String> {
    let out = run("ipconfig", &["/all".to_string()])?;
    let (_, ifaces) = windows::parse_ipconfig(&out);
    let want = iface_ip.to_string();
    ifaces
        .into_iter()
        .find(|(_, ip)| *ip == want)
        .map(|(name, _)| name)
        .ok_or_else(|| ClientError::PlatformError("interface name not found".to_string()))
}

impl RealPlatform {
    /// Interface name owning the default route (for `netsh` DNS targeting).
    fn default_iface(&self) -> Result<String> {
        let table = windows::read_route_table()?;
        let ip = table
            .default_iface_ip()
            .ok_or_else(|| ClientError::PlatformError("no default route".to_string()))?;
        iface_name_for(ip)
    }
}

impl Platform for RealPlatform {
    fn resolve_host(&mut self, host: &str) -> Result<Vec<IpAddr>> {
        // Port is irrelevant; resolution is the goal (also covers IP literals).
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
        let table = windows::read_route_table()?;
        let dns = windows::read_dns()?;
        Ok(Snapshot {
            routes: table.routes,
            dns_servers: dns,
        })
    }

    fn tun_up(&mut self, name: &str, _addr: Ipv4Addr, _mtu: u32) -> Result<()> {
        aetherlink_netstack::tun::TunInterface::open(name)
            .map(|_| ())
            .map_err(|e| ClientError::PlatformError(format!("tun open: {e}")))
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
        let args = windows::route_add_args(&dest, &via.to_string())?;
        run("route", &args)?;
        self.added_routes.push((dest, via.to_string()));
        Ok(())
    }

    fn add_route(&mut self, dest: &str, via: Ipv4Addr) -> Result<()> {
        // `dest` arrives as `ip`, `base/prefix`, or `lo-hi`; ranges are
        // rejected (Windows has no range routes) instead of misapplied.
        let cidr = if dest.contains('/') || dest.parse::<Ipv4Addr>().is_ok() {
            if dest.contains('/') {
                dest.to_string()
            } else {
                format!("{dest}/32")
            }
        } else {
            return Err(ClientError::PlatformError(format!(
                "ip ranges unsupported, split it: {dest}"
            )));
        };
        let args = windows::route_add_args(&cidr, &via.to_string())?;
        run("route", &args)?;
        self.added_routes.push((cidr, via.to_string()));
        Ok(())
    }

    fn default_via_tun(&mut self) -> Result<()> {
        let gw = crate::lifecycle::VIRTUAL_DNS_IP;
        let args = windows::route_add_args("0.0.0.0/0", &gw.to_string())?;
        run("route", &args)?;
        self.added_routes
            .push(("0.0.0.0/0".to_string(), gw.to_string()));
        Ok(())
    }

    fn force_dns(&mut self, dns_ip: Ipv4Addr) -> Result<()> {
        let iface = self.default_iface()?;
        let args = windows::dns_set_args(&iface, &dns_ip.to_string());
        run("netsh", &args)?;
        Ok(())
    }

    fn restore(&mut self, snap: &Snapshot) -> Result<()> {
        // Remove what we added, strict reverse; best-effort per op so one
        // stuck route cannot block DNS restoration.
        let mut added = std::mem::take(&mut self.added_routes);
        added.reverse();
        for (dest, gw) in added {
            if let Ok(args) = windows::route_delete_args(&dest, &gw) {
                let _ = run("route", &args);
            }
        }
        // Restore captured DNS explicitly (covers static origins too).
        if let Ok(iface) = self.default_iface() {
            for (i, server) in snap.dns_servers.iter().enumerate() {
                // `set ... static <dns>` for the primary,
                // `add ... <dns> index=N` for the rest.
                let mut args = windows::dns_set_args(&iface, server);
                if i > 0 {
                    args[2] = "add".to_string();
                    args.remove(5);
                    args.push(format!("index={}", i + 1));
                }
                let _ = run("netsh", &args);
            }
        }
        Ok(())
    }
}

/// In-memory fake backend: records every call, injects step failures.
pub struct FakePlatform {
    routes: HashMap<String, String>,
    dns: Vec<String>,
    tun: bool,
    pinned: Vec<String>,
    log: Vec<String>,
    fail_at: Option<Step>,
    state_path: PathBuf,
}

impl FakePlatform {
    /// Backend whose TUN open always fails (unprivileged simulation).
    #[must_use]
    pub fn no_privilege(state_path: PathBuf) -> Self {
        Self::failing_at(Step::TunUp, state_path)
    }

    /// Fully working backend.
    #[must_use]
    pub fn working(state_path: PathBuf) -> Self {
        Self {
            routes: [("default".to_string(), "192.168.1.1".to_string())].into(),
            dns: vec!["192.168.1.1".to_string()],
            tun: false,
            pinned: Vec::new(),
            log: Vec::new(),
            fail_at: None,
            state_path,
        }
    }

    /// Backend failing exactly at `step`.
    #[must_use]
    pub fn failing_at(step: Step, state_path: PathBuf) -> Self {
        let mut fake = Self::working(state_path);
        fake.fail_at = Some(step);
        fake
    }

    fn fail(&mut self, step: Step) -> Result<()> {
        self.log.push(format!("attempt:{step:?}"));
        if self.fail_at == Some(step) {
            return Err(ClientError::PlatformError(format!(
                "injected failure at {step:?}"
            )));
        }
        Ok(())
    }

    /// Current routing table view.
    #[must_use]
    pub fn routes(&self) -> &HashMap<String, String> {
        &self.routes
    }

    /// Current DNS servers view.
    #[must_use]
    pub fn dns(&self) -> &Vec<String> {
        &self.dns
    }

    /// Whether the TUN device exists.
    #[must_use]
    pub fn tun_exists(&self) -> bool {
        self.tun
    }

    /// Whether `ip` was pinned direct.
    #[must_use]
    pub fn has_pinned(&self, ip: &str) -> bool {
        self.pinned.iter().any(|p| p == ip)
    }

    /// Ordered call log (`apply:*` = mutations).
    #[must_use]
    pub fn call_log(&self) -> &[String] {
        &self.log
    }

    /// Number of applied mutations.
    #[must_use]
    pub fn applied_count(&self) -> usize {
        self.log.iter().filter(|c| c.starts_with("apply:")).count()
    }
}

impl Platform for FakePlatform {
    fn resolve_host(&mut self, host: &str) -> Result<Vec<IpAddr>> {
        self.fail(Step::Resolve)?;
        self.log.push(format!("resolve {host}"));
        // Deterministic TEST-NET documentation address.
        Ok(vec!["93.184.216.34".parse().expect("fixed test ip")])
    }

    fn snapshot(&mut self) -> Result<Snapshot> {
        self.log.push("snapshot".to_string());
        Ok(Snapshot {
            routes: self
                .routes
                .iter()
                .map(|(dest, via)| Route {
                    dest: dest.clone(),
                    via: via.clone(),
                })
                .collect(),
            dns_servers: self.dns.clone(),
        })
    }

    fn tun_up(&mut self, name: &str, _addr: Ipv4Addr, _mtu: u32) -> Result<()> {
        self.fail(Step::TunUp)?;
        self.tun = true;
        self.log.push(format!("apply:tun_up {name}"));
        Ok(())
    }

    fn tun_down(&mut self) -> Result<()> {
        self.tun = false;
        self.log.push("apply:tun_down".to_string());
        Ok(())
    }

    fn pin_route(&mut self, dest: IpAddr, via: Ipv4Addr) -> Result<()> {
        self.fail(Step::PinRoute)?;
        self.pinned.push(dest.to_string());
        self.routes.insert(dest.to_string(), via.to_string());
        self.log.push(format!("apply:pin_route {dest} via {via}"));
        Ok(())
    }

    fn add_route(&mut self, dest: &str, via: Ipv4Addr) -> Result<()> {
        self.fail(Step::DirectRules)?;
        self.routes.insert(dest.to_string(), via.to_string());
        self.log.push(format!("apply:route {dest} via {via}"));
        Ok(())
    }

    fn default_via_tun(&mut self) -> Result<()> {
        self.fail(Step::DefaultViaTun)?;
        self.routes.insert("default".to_string(), "tun".to_string());
        self.log.push("apply:default_via_tun".to_string());
        Ok(())
    }

    fn force_dns(&mut self, dns_ip: Ipv4Addr) -> Result<()> {
        self.fail(Step::DnsForce)?;
        self.dns = vec![dns_ip.to_string()];
        self.log.push(format!("apply:force_dns {dns_ip}"));
        Ok(())
    }

    fn restore(&mut self, snap: &Snapshot) -> Result<()> {
        self.routes = snap
            .routes
            .iter()
            .map(|r| (r.dest.clone(), r.via.clone()))
            .collect();
        self.dns.clone_from(&snap.dns_servers);
        self.tun = false;
        self.pinned.clear();
        self.log.push("restore".to_string());
        Ok(())
    }

    fn state_path(&self) -> PathBuf {
        self.state_path.clone()
    }
}
