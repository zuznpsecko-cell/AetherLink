//! Platform abstraction: real ioctls behind a trait, fake backend for tests.
//!
//! Bring-up policy (`lifecycle::up`) programs against [`Platform`], so the
//! ordering, rollback and idempotency proofs run without privileges on a
//! [`FakePlatform`]. [`RealPlatform`] implements what needs no privileges
//! today (DNS resolution) and fails the rest with an explicit pending error
//! instead of silently no-op'ing.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use aetherlink_netstack::tun::{Route, Snapshot};

use crate::ClientError;

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
    fn resolve_host(&mut self, host: &str) -> Result<Vec<IpAddr>, ClientError>;

    /// Capture pre-up routes + DNS.
    fn snapshot(&mut self) -> Result<Snapshot, ClientError>;

    /// Create + address the TUN device.
    fn tun_up(&mut self, name: &str, addr: Ipv4Addr, mtu: u32) -> Result<(), ClientError>;

    /// Destroy the TUN device (default: pending).
    fn tun_down(&mut self) -> Result<(), ClientError> {
        Err(pending("tun_down"))
    }

    /// Pin a route via a gateway (default: pending).
    fn pin_route(&mut self, _dest: IpAddr, _via: Ipv4Addr) -> Result<(), ClientError> {
        Err(pending("pin_route"))
    }

    /// Install a direct route (default: pending).
    fn add_route(&mut self, _dest: &str, _via: Ipv4Addr) -> Result<(), ClientError> {
        Err(pending("add_route"))
    }

    /// Switch the default route into TUN (default: pending).
    fn default_via_tun(&mut self) -> Result<(), ClientError> {
        Err(pending("default_via_tun"))
    }

    /// Force system DNS to the tunnel resolver (default: pending).
    fn force_dns(&mut self, _dns_ip: Ipv4Addr) -> Result<(), ClientError> {
        Err(pending("force_dns"))
    }

    /// Restore a snapshot (default: pending).
    fn restore(&mut self, _snap: &Snapshot) -> Result<(), ClientError> {
        Err(pending("restore"))
    }

    /// Crash-recovery state file path.
    fn state_path(&self) -> PathBuf {
        default_state_path()
    }
}

/// Real platform: genuinely privilege-free operations only.
pub struct RealPlatform;

impl Platform for RealPlatform {
    fn resolve_host(&mut self, host: &str) -> Result<Vec<IpAddr>, ClientError> {
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

    fn snapshot(&mut self) -> Result<Snapshot, ClientError> {
        Err(pending("route capture"))
    }

    fn tun_up(&mut self, name: &str, _addr: Ipv4Addr, _mtu: u32) -> Result<(), ClientError> {
        aetherlink_netstack::tun::TunInterface::open(name)
            .map(|_| ())
            .map_err(|e| ClientError::PlatformError(format!("tun open: {e}")))
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

    fn fail(&mut self, step: Step) -> Result<(), ClientError> {
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
    fn resolve_host(&mut self, host: &str) -> Result<Vec<IpAddr>, ClientError> {
        self.fail(Step::Resolve)?;
        self.log.push(format!("resolve {host}"));
        // Deterministic TEST-NET documentation address.
        Ok(vec!["93.184.216.34".parse().expect("fixed test ip")])
    }

    fn snapshot(&mut self) -> Result<Snapshot, ClientError> {
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

    fn tun_up(&mut self, name: &str, _addr: Ipv4Addr, _mtu: u32) -> Result<(), ClientError> {
        self.fail(Step::TunUp)?;
        self.tun = true;
        self.log.push(format!("apply:tun_up {name}"));
        Ok(())
    }

    fn tun_down(&mut self) -> Result<(), ClientError> {
        self.tun = false;
        self.log.push("apply:tun_down".to_string());
        Ok(())
    }

    fn pin_route(&mut self, dest: IpAddr, via: Ipv4Addr) -> Result<(), ClientError> {
        self.fail(Step::PinRoute)?;
        self.pinned.push(dest.to_string());
        self.routes.insert(dest.to_string(), via.to_string());
        self.log.push(format!("apply:pin_route {dest} via {via}"));
        Ok(())
    }

    fn add_route(&mut self, dest: &str, via: Ipv4Addr) -> Result<(), ClientError> {
        self.fail(Step::DirectRules)?;
        self.routes.insert(dest.to_string(), via.to_string());
        self.log.push(format!("apply:route {dest} via {via}"));
        Ok(())
    }

    fn default_via_tun(&mut self) -> Result<(), ClientError> {
        self.fail(Step::DefaultViaTun)?;
        self.routes.insert("default".to_string(), "tun".to_string());
        self.log.push("apply:default_via_tun".to_string());
        Ok(())
    }

    fn force_dns(&mut self, dns_ip: Ipv4Addr) -> Result<(), ClientError> {
        self.fail(Step::DnsForce)?;
        self.dns = vec![dns_ip.to_string()];
        self.log.push(format!("apply:force_dns {dns_ip}"));
        Ok(())
    }

    fn restore(&mut self, snap: &Snapshot) -> Result<(), ClientError> {
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
