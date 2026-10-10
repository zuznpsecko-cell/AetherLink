//! AetherLink WiFi hotspot: share the tunnel with WiFi clients.
//!
//! The box becomes a WPA2 access point; client traffic is forwarded into
//! the tunnel interface (`aether0`) and fail-closed when the tunnel is down
//! (DEC-014): nothing leaks direct. Two backends behind one entry point:
//!
//! * NetworkManager (`nmcli`, `ipv4.method shared`) — Ubuntu Desktop;
//! * `hostapd` + `dnsmasq` — headless/server installs.
//!
//! DNS of connected clients follows the host resolver, which the client
//! forces into the tunnel while up (DNS_NO_LEAK).

pub mod config;
pub mod firewall;
pub mod hostapd;
pub mod nm;
pub mod proc;
pub mod state;

pub use config::{BackendChoice, BackendKind, HotspotConfig, SubnetPlan};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum HotspotError {
    #[error("hotspot config: {0}")]
    Config(String),

    #[error("hotspot: {0}")]
    Tool(String),

    #[error("hotspot state: {0}")]
    State(String),
}

pub type Result<T> = std::result::Result<T, HotspotError>;

/// `apt` package owning a tool we shell out to (for actionable errors).
fn package_hint(prog: &str) -> &'static str {
    match prog {
        "nft" => "nftables",
        "nmcli" => "network-manager",
        "hostapd" => "hostapd",
        "dnsmasq" => "dnsmasq",
        "ip" => "iproute2",
        "resolvectl" => "systemd-resolved",
        _ => "the corresponding package",
    }
}

/// Run a command, returning stdout or a named error (first stderr line).
pub(crate) fn run(prog: &str, args: &[String]) -> Result<String> {
    log(&format!("run: {prog} {}", args.join(" ")));
    let out = std::process::Command::new(prog).args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            HotspotError::Tool(format!(
                "{prog} not found — install it: `apt install {}`",
                package_hint(prog)
            ))
        } else {
            HotspotError::Tool(format!("spawn {prog}: {e}"))
        }
    })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let msg = stderr.trim().lines().next().unwrap_or_default();
        let msg = if msg.is_empty() {
            stdout.trim().lines().next().unwrap_or_default()
        } else {
            msg
        };
        return Err(HotspotError::Tool(format!(
            "{prog} failed: {msg}"
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Best-effort command: failure is logged, never propagated (teardown).
pub(crate) fn run_quiet(prog: &str, args: &[String]) {
    if let Err(e) = run(prog, args) {
        log(&format!("quiet: {e}"));
    }
}

fn log(msg: &str) {
    if std::env::var_os("AETHERLINK_DEBUG").is_some() {
        eprintln!("[aetherlink-hotspot] {msg}");
    }
}

/// Bring the hotspot up (idempotent: leftovers are cleaned first).
///
/// Order matters: the fail-closed nftables guard is applied BEFORE the AP
/// comes up (a client that associates early must already be restricted),
/// then `ip_forward`, then the backend AP, then the state file. Any
/// failure rolls back whatever was applied.
pub fn up(cfg: &HotspotConfig) -> Result<state::HotspotState> {
    let plan = cfg.validate_up()?;
    // Leftovers from a crashed run: clean before re-applying.
    down_quiet();

    let iface = match cfg.backend {
        BackendChoice::Auto => {
            if nm::available(cfg.interface.as_deref()) {
                nm::resolve_iface(cfg.interface.as_deref())?
            } else {
                hostapd::resolve_iface(cfg.interface.as_deref())?
            }
        }
        BackendChoice::NetworkManager => nm::resolve_iface(cfg.interface.as_deref())?,
        BackendChoice::Hostapd => hostapd::resolve_iface(cfg.interface.as_deref())?,
    };

    let backend = match cfg.backend {
        BackendChoice::NetworkManager => BackendKind::NetworkManager,
        BackendChoice::Hostapd => BackendKind::Hostapd,
        BackendChoice::Auto => {
            if nm::available(Some(&iface)) {
                BackendKind::NetworkManager
            } else {
                BackendKind::Hostapd
            }
        }
    };

    // Fail-closed guard before any client can associate: wlan traffic may
    // only leave through the tunnel interface; everything else drops.
    // Returns the tunnel name it was bound to (kernel renames tolerated).
    let tun_iface = firewall::apply(&iface)?;

    let prev_ip_forward = match proc::ensure_ip_forward() {
        Ok(prev) => prev,
        Err(e) => {
            let _ = firewall::remove();
            return Err(e);
        }
    };

    let up_result = match backend {
        BackendKind::NetworkManager => nm::up(cfg, &iface, &plan),
        BackendKind::Hostapd => hostapd::up(cfg, &iface, &plan),
    };
    let nm_unmanaged = match up_result {
        Ok(flag) => flag,
        Err(e) => {
            // Roll everything back: no half-AP with traffic blocked or leaked.
            match backend {
                BackendKind::NetworkManager => nm::down_quiet(),
                BackendKind::Hostapd => hostapd::down_quiet(),
            }
            let _ = firewall::remove();
            let _ = proc::ip_forward_set(&prev_ip_forward);
            return Err(e);
        }
    };

    let st = state::HotspotState {
        backend,
        interface: iface.clone(),
        ssid: cfg.ssid.clone(),
        subnet: cfg.subnet.clone(),
        prev_ip_forward,
        nm_unmanaged,
        tun_iface,
    };
    state::save(&st)?;
    log(&format!(
        "hotspot up: backend={:?} iface={iface} ssid={} subnet={}",
        st.backend, st.ssid, st.subnet
    ));
    Ok(st)
}

/// Bring the hotspot down (idempotent; safe after a crash).
pub fn down() -> Result<()> {
    down_quiet();
    Ok(())
}

/// Teardown that never fails (used by `up` cleanup and CLI `cleanup`).
pub fn down_quiet() {
    let st = state::load().ok().flatten();
    match st.as_ref().map(|s| s.backend) {
        Some(BackendKind::NetworkManager) => nm::down_quiet(),
        Some(BackendKind::Hostapd) => hostapd::down_quiet(),
        None => {
            // No state: still sweep both backends' leftovers (crash before
            // the state file was written).
            nm::down_quiet();
            hostapd::down_quiet();
        }
    }
    let _ = firewall::remove();
    if let Some(st) = &st {
        let _ = proc::ip_forward_set(&st.prev_ip_forward);
    }
    state::remove_quiet();
}

/// One-line status JSON (no secrets).
pub fn status() -> String {
    let st = state::load().ok().flatten();
    let Some(st) = st else {
        return serde_json::json!({ "hotspot": "down" }).to_string();
    };
    let alive = match st.backend {
        BackendKind::NetworkManager => nm::is_active(),
        BackendKind::Hostapd => hostapd::is_alive(),
    };
    serde_json::json!({
        "hotspot": if alive { "up" } else { "degraded" },
        "backend": st.backend,
        "interface": st.interface,
        "ssid": st.ssid,
        "subnet": st.subnet,
        "tunnel_iface": st.tun_iface,
    })
    .to_string()
}
