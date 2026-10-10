//! `/proc` knobs: IPv4 forwarding (with exact restore).

use crate::{HotspotError, Result};

const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

/// Read the current `ip_forward` value (`"0"`/`"1"`).
pub fn ip_forward_get() -> Result<String> {
    let raw = std::fs::read_to_string(IP_FORWARD)
        .map_err(|e| HotspotError::Tool(format!("read {IP_FORWARD}: {e}")))?;
    Ok(raw.trim().to_string())
}

/// Write `ip_forward` (needs root).
pub fn ip_forward_set(value: &str) -> Result<()> {
    std::fs::write(IP_FORWARD, format!("{value}\n"))
        .map_err(|e| HotspotError::Tool(format!("set {IP_FORWARD}={value}: {e} (root?)")))?;
    Ok(())
}

/// Ensure forwarding is on; returns the previous value so `down` can
/// restore exactly what was there (never unconditionally "0").
pub fn ensure_ip_forward() -> Result<String> {
    let prev = ip_forward_get()?;
    if prev != "1" {
        ip_forward_set("1")?;
    }
    Ok(prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only probe: on any Linux box the file exists and is 0/1; the
    /// write path is exercised live with root only.
    #[cfg(target_os = "linux")]
    #[test]
    fn ip_forward_is_readable() {
        match ip_forward_get() {
            Ok(v) => assert!(v == "0" || v == "1", "unexpected value {v}"),
            Err(e) => {
                // Containers without the proc knob: named error, not panic.
                assert!(e.to_string().contains("ip_forward"));
            }
        }
    }
}
