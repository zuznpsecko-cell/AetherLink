//! NetworkManager backend: a `shared`-mode WiFi AP connection via `nmcli`
//! (Ubuntu Desktop default). NM runs its own dnsmasq for the clients and
//! NATs them out; our nftables guard restricts that egress to the tunnel.

use crate::config::{HotspotConfig, SubnetPlan};
use crate::{run, run_quiet, HotspotError, Result};

/// Connection name we own (created/deleted by us; never a user profile).
pub const CON_NAME: &str = "aetherlink-hotspot";

/// `nmcli` argument builder for creating the shared AP connection (pure;
/// tested without NM). `autoconnect no`: the AP lifecycle is ours.
#[must_use]
pub fn add_args(cfg: &HotspotConfig, iface: &str, plan: &SubnetPlan) -> Vec<String> {
    let psk = cfg.password.clone().unwrap_or_default();
    let mut args: Vec<String> = [
        "con",
        "add",
        "type",
        "wifi",
        "con-name",
        CON_NAME,
        "ifname",
        iface,
        "autoconnect",
        "no",
        "ssid",
        &cfg.ssid,
        "--",
        "wifi.mode",
        "ap",
        "wifi-sec.key-mgmt",
        "wpa-psk",
        "wifi-sec.psk",
        &psk,
        "ipv4.method",
        "shared",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // Explicit pool: NM shared defaults to 10.42.0.0/24, which collides
    // with the LAN-direct rules; our subnet is picked clear of them.
    args.push("ipv4.addresses".to_string());
    args.push(format!("{}/{}", plan.network, plan.prefix));
    args.push("ipv6.method".to_string());
    args.push("ignore".to_string());
    args
}

/// `nmcli con up` for our connection.
#[must_use]
pub fn up_args(iface: &str) -> Vec<String> {
    ["con", "up", CON_NAME, "ifname", iface]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// `nmcli con down` for our connection.
#[must_use]
pub fn down_args() -> Vec<String> {
    ["con", "down", CON_NAME].iter().map(|s| s.to_string()).collect()
}

/// `nmcli con delete` for our connection.
#[must_use]
pub fn delete_args() -> Vec<String> {
    ["con", "delete", CON_NAME].iter().map(|s| s.to_string()).collect()
}

/// Is NetworkManager running and usable?
#[must_use]
pub fn nm_running() -> bool {
    std::process::Command::new("nmcli")
        .args(["-g", "RUNNING", "general"])
        .output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout).trim() == "running"
        })
        .unwrap_or(false)
}

/// WiFi devices NM sees (`nmcli -t -f DEVICE,TYPE device`).
#[must_use]
pub fn wifi_devices_from(nmcli_devices_output: &str) -> Vec<String> {
    nmcli_devices_output
        .lines()
        .filter_map(|line| {
            // -t output: DEVICE:TYPE:... (colons in names are escaped by
            // NM with backslashes; device names never contain one anyway).
            let mut parts = line.splitn(3, ':');
            let device = parts.next()?;
            let typ = parts.next()?;
            (typ == "wifi").then(|| device.to_string())
        })
        .collect()
}

/// WiFi devices on this box via NM.
#[must_use]
pub fn wifi_devices() -> Vec<String> {
    run("nmcli", &["-t".to_string(), "-f".to_string(), "DEVICE,TYPE".to_string(), "device".to_string()])
        .map(|out| wifi_devices_from(&out))
        .unwrap_or_default()
}

/// Backend availability probe: NM running AND the requested (or any) WiFi
/// device is NM-managed.
#[must_use]
pub fn available(iface: Option<&str>) -> bool {
    if !nm_running() {
        return false;
    }
    match iface {
        Some(want) => wifi_devices().iter().any(|d| d == want),
        None => !wifi_devices().is_empty(),
    }
}

/// Resolve which interface to use: explicit one (validated against NM) or
/// the first WiFi device.
pub fn resolve_iface(iface: Option<&str>) -> Result<String> {
    let devices = wifi_devices();
    if devices.is_empty() {
        return Err(HotspotError::Tool(
            "no NM-managed WiFi device found (nmcli device)".to_string(),
        ));
    }
    match iface {
        Some(want) => {
            if devices.iter().any(|d| d == want) {
                Ok(want.to_string())
            } else {
                Err(HotspotError::Config(format!(
                    "WiFi interface '{want}' not managed by NetworkManager (have: {})",
                    devices.join(", ")
                )))
            }
        }
        None => Ok(devices
            .into_iter()
            .next()
            .expect("checked non-empty above")),
    }
}

/// Create + activate the shared AP connection. Returns the
/// NetworkManager-unmanaged flag for parity with the hostapd backend
/// (always false here — NM owns the device itself).
pub fn up(cfg: &HotspotConfig, iface: &str, plan: &SubnetPlan) -> Result<bool> {
    // A stale connection with our name (crash) would make `con add` fail.
    run_quiet("nmcli", &delete_args());
    run("nmcli", &add_args(cfg, iface, plan))?;
    if let Err(e) = run("nmcli", &up_args(iface)) {
        run_quiet("nmcli", &delete_args());
        return Err(e);
    }
    Ok(false)
}

/// Deactivate + delete our connection (best-effort, traced).
pub fn down_quiet() {
    // `con down` fails when it is not active; deletion is the goal.
    run_quiet("nmcli", &down_args());
    run_quiet("nmcli", &delete_args());
}

/// Is our connection active right now?
#[must_use]
pub fn is_active() -> bool {
    run(
        "nmcli",
        &[
            "-g".to_string(),
            "GENERAL.STATE".to_string(),
            "con".to_string(),
            "show".to_string(),
            CON_NAME.to_string(),
        ],
    )
    .map(|out| out.contains("activated"))
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HotspotConfig {
        HotspotConfig {
            password: Some("12345678".to_string()),
            ssid: "AetherLink".to_string(),
            subnet: "192.168.243.0/24".to_string(),
            ..HotspotConfig::default()
        }
    }

    fn plan() -> SubnetPlan {
        crate::config::subnet_plan("192.168.243.0/24").expect("plan")
    }

    #[test]
    fn add_command_is_shared_ap_with_our_pool() {
        let args = add_args(&cfg(), "wlan0", &plan());
        let joined = args.join(" ");
        assert!(joined.starts_with("con add type wifi con-name aetherlink-hotspot"));
        assert!(joined.contains("ifname wlan0"));
        assert!(joined.contains("autoconnect no"));
        assert!(joined.contains("ssid AetherLink"));
        assert!(joined.contains("wifi.mode ap"));
        assert!(joined.contains("wifi-sec.key-mgmt wpa-psk"));
        assert!(joined.contains("wifi-sec.psk 12345678"));
        assert!(joined.contains("ipv4.method shared"));
        assert!(joined.contains("ipv4.addresses 192.168.243.0/24"));
        assert!(joined.contains("ipv6.method ignore"));
    }

    #[test]
    fn device_listing_parses_wifi_only() {
        let out = "wlan0:wifi:connected\neth0:ethernet:unavailable\nwlp2s0:wifi:disconnected\n";
        assert_eq!(wifi_devices_from(out), vec!["wlan0", "wlp2s0"]);
    }
}
