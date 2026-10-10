//! Hotspot runtime state: which backend is up, on which interface, and the
//! `ip_forward` value to restore. Lives in `/run` (tmpfs: a reboot clears
//! it together with the AP itself).

use serde::{Deserialize, Serialize};

use crate::config::BackendKind;
use crate::{HotspotError, Result};

/// Runtime state file.
pub const STATE_PATH: &str = "/run/aetherlink/hotspot.json";

/// Persisted hotspot state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotState {
    /// Backend that brought the AP up.
    pub backend: BackendKind,
    /// WiFi interface.
    pub interface: String,
    /// SSID (for status display only).
    pub ssid: String,
    /// Client subnet CIDR.
    pub subnet: String,
    /// `/proc/sys/net/ipv4/ip_forward` before we touched it.
    pub prev_ip_forward: String,
    /// hostapd backend only: we set the WiFi device unmanaged in
    /// NetworkManager for the AP's lifetime; `down` flips it back.
    #[serde(default)]
    pub nm_unmanaged: bool,
}

fn dir() -> &'static str {
    "/run/aetherlink"
}

/// Persist the state (dir created on demand).
pub fn save(st: &HotspotState) -> Result<()> {
    std::fs::create_dir_all(dir())
        .map_err(|e| HotspotError::State(format!("create {}: {e}", dir())))?;
    let raw = serde_json::to_string_pretty(st)
        .map_err(|e| HotspotError::State(format!("state encode: {e}")))?;
    std::fs::write(STATE_PATH, raw)
        .map_err(|e| HotspotError::State(format!("state write: {e}")))
}

/// Load persisted state: `Ok(None)` when absent, `Err` when unreadable.
pub fn load() -> Result<Option<HotspotState>> {
    match std::fs::read(STATE_PATH) {
        Ok(raw) => {
            let st = serde_json::from_slice(&raw)
                .map_err(|e| HotspotError::State(format!("state decode: {e}")))?;
            Ok(Some(st))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(HotspotError::State(format!("state read: {e}"))),
    }
}

/// Consume the state file (idempotent).
pub fn remove_quiet() {
    let _ = std::fs::remove_file(STATE_PATH);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip through a temp path (the real one needs /run access).
    #[test]
    fn state_round_trip_shape() {
        let st = HotspotState {
            backend: BackendKind::Hostapd,
            interface: "wlan0".to_string(),
            ssid: "AetherLink".to_string(),
            subnet: "192.168.243.0/24".to_string(),
            prev_ip_forward: "0".to_string(),
            nm_unmanaged: true,
        };
        let raw = serde_json::to_string(&st).expect("encode");
        let back: HotspotState = serde_json::from_str(&raw).expect("decode");
        assert_eq!(back.backend, BackendKind::Hostapd);
        assert_eq!(back.prev_ip_forward, "0");
        assert!(back.nm_unmanaged);
        // The on-disk format pins backend spellings other tools rely on.
        assert!(raw.contains("\"backend\":\"hostapd\""));
    }

    /// Older state files without `nm_unmanaged` must still load (defaults
    /// false — no device to hand back).
    #[test]
    fn state_old_format_back_compat() {
        let old = r#"{"backend":"network-manager","interface":"wlan0",
                      "ssid":"s","subnet":"192.168.243.0/24",
                      "prev_ip_forward":"0"}"#;
        let back: HotspotState = serde_json::from_str(old).expect("decode old");
        assert!(!back.nm_unmanaged);
    }
}
