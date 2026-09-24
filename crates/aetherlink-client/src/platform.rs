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
use std::sync::{Arc, Mutex};

use aetherlink_netstack::tun::{previous_gateway, RestoreOp};
use aetherlink_netstack::tun::{rollback_plan, AppliedChange, Route, Snapshot};

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

/// Treat "route already exists" as success (stale/duplicate state converges).
///
/// Narrow match on purpose: only "already exists" (EN) / "уже существует"
/// (RU) pass; every other failure still aborts `up`.
fn tolerate_exists<T>(r: Result<T>, what: &str) -> Result<()> {
    match r {
        Ok(_) => Ok(()),
        Err(ClientError::PlatformError(msg))
            if msg.contains("already exists") || msg.contains("уже существует") =>
        {
            aetherlink_netstack::debug_log(&format!("route {what} exists, keeping"));
            Ok(())
        }
        Err(e) => Err(e),
    }
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

    /// Replay a persisted applied-change log against its snapshot.
    ///
    /// Crash-recovery path (`down` after a crash uses a fresh platform, so
    /// per-instance state like `added_routes` is empty — the file is the
    /// only truth). DNS goes back to `state.dns_iface` (persisted at `up`,
    /// never re-derived: the default route may point elsewhere by now).
    /// Default: legacy full restore, ignoring the log.
    fn restore_applied(&mut self, state: &aetherlink_netstack::tun::UpState) -> Result<()> {
        self.restore(&state.snapshot)
    }

    /// Physical interface captured at snapshot (DNS was/will be forced here).
    fn captured_iface(&self) -> Option<String> {
        None
    }

    /// Live TUN adapter Win32 ifIndex, if held (egress binding + persist).
    fn tun_ifindex(&self) -> Option<u32> {
        None
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
    /// Physical default interface captured at `snapshot` time (before any
    /// mutation moves the default route into TUN).
    default_iface: Option<String>,
    /// Live TUN session, held for the whole `up` (dropping it ends the
    /// wintun session and the device goes dark, so it must outlive `up`).
    /// Shared (`Arc<Mutex>`) so pump threads can borrow it after attach.
    tun: Option<Arc<Mutex<aetherlink_netstack::tun::TunInterface>>>,
}

impl RealPlatform {
    /// Fresh real backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Run a command, returning stdout or a named error (both streams kept short).
fn run(prog: &str, args: &[String]) -> Result<String> {
    aetherlink_netstack::debug_log(&format!("run: {prog} {}", args.join(" ")));
    let out = std::process::Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| ClientError::PlatformError(format!("spawn {prog}: {e}")))?;
    if !out.status.success() {
        // netsh diagnostics go to stdout in the OEM page (cp866 here):
        // decode properly or the message is mojibake.
        let tail = |b: &[u8]| {
            windows::decode_cmd_output(b)
                .chars()
                .take(500)
                .collect::<String>()
        };
        aetherlink_netstack::debug_log(&format!(
            "run failed: {prog} status={} out={} err={}",
            out.status,
            tail(&out.stdout),
            tail(&out.stderr)
        ));
        return Err(ClientError::PlatformError(format!(
            "{prog} failed: out={} err={}",
            tail(&out.stdout),
            tail(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Resolve the local interface name owning `iface_ip` via ipconfig.
fn iface_name_for(iface_ip: Ipv4Addr) -> Result<String> {
    let out = windows::read_ipconfig_text()?;
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
        if let Some(name) = self.default_iface.clone() {
            return Ok(name);
        }
        let table = windows::read_route_table()?;
        let ip = table
            .default_iface_ip()
            .ok_or_else(|| ClientError::PlatformError("no default route".to_string()))?;
        iface_name_for(ip)
    }

    /// Physical default interface name right now (pre-mutation calls only).
    fn capture_default_iface() -> Result<String> {
        let table = windows::read_route_table()?;
        let ip = table
            .default_iface_ip()
            .ok_or_else(|| ClientError::PlatformError("no default route".to_string()))?;
        iface_name_for(ip)
    }

    /// Shared handle to the live TUN device, if up (for pump attach).
    #[must_use]
    pub fn tun_handle(&self) -> Option<Arc<Mutex<aetherlink_netstack::tun::TunInterface>>> {
        self.tun.clone()
    }

    /// Drop the held TUN device, deleting the adapter when we are its last
    /// owner (pump stopped beforehand in the normal path; a shared handle
    /// just ends our ownership and reports it).
    fn drop_tun(&mut self) -> Result<()> {
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
            None => Ok(()),
        }
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
        // Capture the physical default interface BEFORE any mutation moves
        // the default route into TUN (post-switch lookup finds no iface).
        let iface = Self::capture_default_iface()?;
        aetherlink_netstack::debug_log(&format!("snapshot: default_iface={iface} dns={dns:?}"));
        self.default_iface = Some(iface);
        Ok(Snapshot {
            routes: table.routes,
            dns_servers: dns,
        })
    }
    fn tun_up(&mut self, name: &str, addr: Ipv4Addr, _mtu: u32) -> Result<()> {
        // Open first: the session must be alive while netsh works below,
        // and the handle is stored (not dropped) so the device stays up.
        let iface = aetherlink_netstack::tun::TunInterface::open(name)
            .map_err(|e| ClientError::PlatformError(format!("tun open: {e}")))?;
        // A newborn wintun adapter is disabled: enable first, then address
        // it (/30 so pin/default-via-TUN resolve). A half-addressed adapter
        // is reused by the next open-or-create, so just report. The OS
        // registers newborn interfaces asynchronously: retry ~5s per step.
        let enable_args = windows::iface_admin_args(name, true)?;
        let metric_args = windows::iface_metric_args(name, windows::TUN_IFACE_METRIC)?;
        let addr_args = windows::tun_addr_args(name, &addr.to_string(), 30)?;
        for args in [&enable_args, &metric_args, &addr_args] {
            let mut last_err = ClientError::PlatformError("tun bring-up: no attempts".to_string());
            let mut done = false;
            for _ in 0..10 {
                match run("netsh", args).map(|_| ()) {
                    Ok(()) => {
                        done = true;
                        break;
                    }
                    Err(e) => {
                        last_err = e;
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
            if !done {
                return Err(ClientError::PlatformError(format!(
                    "tun {name}: {last_err}"
                )));
            }
        }
        self.tun = Some(Arc::new(Mutex::new(iface)));
        aetherlink_netstack::debug_log(&format!("tun_up: {name} session held"));
        Ok(())
    }

    fn tun_down(&mut self) -> Result<()> {
        // Same as replay TunDown: end session + delete our adapter.
        // Best-effort by contract (callers ignore the result), traced here.
        self.drop_tun()
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
        let args = windows::route_add_args(&dest, &via.to_string())?;
        tolerate_exists(run("route", &args), &format!("pin {dest}"))?;
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
        tolerate_exists(run("route", &args), &format!("route {cidr}"))?;
        self.added_routes.push((cidr, via.to_string()));
        Ok(())
    }

    fn default_via_tun(&mut self) -> Result<()> {
        // OpenVPN-style def1: two /1 routes beat the default without touching
        // it and without metric wars. Bound to the TUN ifIndex: without `if`
        // Windows pins the gateway to the physical NIC (seen live).
        let gw = crate::lifecycle::VIRTUAL_DNS_IP;
        let ifindex = self.tun_ifindex().ok_or_else(|| {
            ClientError::PlatformError("no live TUN for default route".to_string())
        })?;
        for dest in ["0.0.0.0/1", "128.0.0.0/1"] {
            let args = windows::route_add_if_args(dest, &gw.to_string(), ifindex)?;
            tolerate_exists(run("route", &args), &format!("default-via-tun {dest}"))?;
            self.added_routes.push((dest.to_string(), gw.to_string()));
        }
        Ok(())
    }

    fn force_dns(&mut self, dns_ip: Ipv4Addr) -> Result<()> {
        let iface = self.default_iface()?;
        aetherlink_netstack::debug_log(&format!("force_dns: {dns_ip} on {iface}"));
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
                match run("route", &args) {
                    Ok(_) => aetherlink_netstack::debug_log(&format!("restore: del {dest} ok")),
                    Err(e) => aetherlink_netstack::debug_log(&format!("restore: del {dest}: {e}")),
                }
            }
        }
        // Restore captured DNS explicitly (covers static origins too).
        let _ = self.restore_dns(&snap.dns_servers);
        Ok(())
    }

    /// Replay a persisted applied-change log (crash recovery: per-instance
    /// `added_routes` is empty, the file is the only truth). Best-effort per
    /// op, but every outcome is traced; joined issues come back as `Err` so
    /// `down` can log them instead of swallowing silently.
    fn restore_applied(&mut self, state: &aetherlink_netstack::tun::UpState) -> Result<()> {
        let snap = &state.snapshot;
        let mut issues: Vec<String> = Vec::new();
        for op in rollback_plan(&state.applied) {
            let r = match &op {
                RestoreOp::RemoveDefaultViaTun => {
                    // Current shape (two /1s, if-bound) plus the legacy 0.0.0.0/0 shape
                    // (pre-/1 clients and manual runs): delete best-effort.
                    // The ifIndex rides from the state file (crash path has no
                    // live handle) with a live-handle fallback.
                    let gw = crate::lifecycle::VIRTUAL_DNS_IP.to_string();
                    let ifindex = state.tun_ifindex.or_else(|| self.tun_ifindex());
                    let mut last = Ok(());
                    for dest in ["0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/0"] {
                        let built = match ifindex {
                            Some(idx) => windows::route_delete_if_args(dest, &gw, idx),
                            None => windows::route_delete_args(dest, &gw),
                        };
                        match built {
                            Ok(args) => match run("route", &args) {
                                Ok(_) => {
                                    aetherlink_netstack::debug_log(&format!(
                                        "replay: del default {dest} ok"
                                    ));
                                }
                                Err(e) => {
                                    aetherlink_netstack::debug_log(&format!(
                                        "replay: del default {dest}: {e}"
                                    ));
                                    last = Err(e);
                                }
                            },
                            Err(e) => {
                                last = Err(e);
                            }
                        }
                    }
                    last.map(|_| ())
                }
                RestoreOp::RemovePinnedRoute(dest) => {
                    // `dest` is `ip` (pin) or `base/prefix` (direct rule);
                    // removals go via the same previous gateway as apply.
                    match previous_gateway(snap) {
                        Some(gw) => {
                            let cidr = if dest.contains('/') {
                                dest.clone()
                            } else if dest.parse::<Ipv4Addr>().is_ok() {
                                format!("{dest}/32")
                            } else {
                                issues.push(format!("skip unparsable route {dest}"));
                                continue;
                            };
                            match windows::route_delete_args(&cidr, &gw.to_string()) {
                                Ok(args) => run("route", &args).map(|_| ()),
                                Err(e) => Err(e),
                            }
                        }
                        None => {
                            issues.push(format!("no previous gateway for {dest}"));
                            continue;
                        }
                    }
                }
                RestoreOp::TunDown(_name) => {
                    // End the session AND delete the adapter we opened.
                    // (Crash recovery holds no handle — drop_tun reports
                    // shared/missing and the adapter stays for reuse.)
                    self.drop_tun()
                }
                RestoreOp::RestoreDns(servers) => {
                    // Target the persisted up-time interface; only legacy
                    // states without it fall back to a live lookup.
                    if state.dns_iface.is_empty() {
                        self.restore_dns(servers)
                    } else {
                        self.restore_dns_on(&state.dns_iface, servers)
                    }
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

impl RealPlatform {
    /// Restore captured DNS servers explicitly (covers static origins too).
    /// Best-effort per server; joined failures come back as `Err`.
    fn restore_dns(&self, servers: &[String]) -> Result<()> {
        match self.default_iface() {
            Ok(iface) => self.restore_dns_on(&iface, servers),
            Err(e) => Err(e),
        }
    }

    /// Restore DNS on an explicitly named interface (replay path: the
    /// interface was persisted at `up`, never re-derived).
    fn restore_dns_on(&self, iface: &str, servers: &[String]) -> Result<()> {
        let mut issues: Vec<String> = Vec::new();
        {
            for (i, server) in servers.iter().enumerate() {
                // `set ... static <dns>` for the primary,
                // `add ... <dns> index=N` for the rest.
                let mut args = windows::dns_set_args(&iface, server);
                if i > 0 {
                    args[2] = "add".to_string();
                    args.remove(5);
                    args.push(format!("index={}", i + 1));
                }
                match run("netsh", &args) {
                    Ok(_) => aetherlink_netstack::debug_log(&format!("restore_dns: {server} ok")),
                    Err(e) => {
                        aetherlink_netstack::debug_log(&format!("restore_dns: {server}: {e}"));
                        issues.push(format!("dns {server}: {e}"));
                    }
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

    /// Backend with preset DNS servers (stale-state simulations).
    #[must_use]
    pub fn with_dns(mut self, dns: Vec<String>) -> Self {
        self.dns = dns;
        self
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
