//! Hotspot configuration (§7 Linux client, DEC-014).
//!
//! Parsed from the `hotspot:` section of the client config or from CLI
//! flags. Everything is validated before any system tool is touched.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::{HotspotError, Result};

/// Default hotspot subnet: RFC1918, but far from the common home-router
/// /24s (0/1/100/17/42/200) so the direct-LAN rules rarely shadow it.
pub const DEFAULT_SUBNET: &str = "192.168.243.0/24";

/// Default SSID.
pub const DEFAULT_SSID: &str = "AetherLink";

/// Which backend brings the AP up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind {
    /// NetworkManager (`nmcli`, shared-mode connection): Ubuntu Desktop.
    #[serde(rename = "network-manager")]
    NetworkManager,
    /// `hostapd` + `dnsmasq`: headless/server installs.
    #[serde(rename = "hostapd")]
    Hostapd,
}

/// Backend selection in config (`auto` probes NetworkManager first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum BackendChoice {
    /// NM when it runs and sees the WiFi device, else hostapd.
    #[default]
    Auto,
    /// Force NetworkManager.
    NetworkManager,
    /// Force hostapd.
    Hostapd,
}

impl BackendChoice {
    /// Parse the config spelling (`auto`/`network-manager`/`hostapd`/`nm`).
    pub fn parse(raw: &str) -> Result<Self> {
        Ok(match raw {
            "auto" => Self::Auto,
            "network-manager" | "nm" | "networkmanager" => Self::NetworkManager,
            "hostapd" => Self::Hostapd,
            other => {
                return Err(HotspotError::Config(format!(
                    "hotspot.backend must be auto|network-manager|hostapd, got {other}"
                )))
            }
        })
    }
}

/// Validated hotspot configuration.
#[derive(Debug, Clone)]
pub struct HotspotConfig {
    /// Present + true in the config (used by `up` to auto-start it).
    pub enabled: bool,
    /// WiFi interface; `None` = autodetect the first wireless device.
    pub interface: Option<String>,
    /// SSID (1..=32 bytes).
    pub ssid: String,
    /// WPA2 passphrase (8..=63 chars); required to bring the AP up.
    pub password: Option<String>,
    /// Client subnet (`CIDR`).
    pub subnet: String,
    /// Backend selection.
    pub backend: BackendChoice,
}

impl Default for HotspotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            ssid: DEFAULT_SSID.to_string(),
            password: None,
            subnet: DEFAULT_SUBNET.to_string(),
            backend: BackendChoice::Auto,
        }
    }
}

/// Derived addressing for a validated subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubnetPlan {
    /// Network address.
    pub network: Ipv4Addr,
    /// Prefix length.
    pub prefix: u8,
    /// Gateway handed to clients (first usable address; ours).
    pub gateway: Ipv4Addr,
    /// DHCP range start (inclusive).
    pub dhcp_start: Ipv4Addr,
    /// DHCP range end (inclusive).
    pub dhcp_end: Ipv4Addr,
    /// Broadcast.
    pub broadcast: Ipv4Addr,
}

/// Parse `a.b.c.d/p` into a plan: gateway = first usable, DHCP range sized
/// to the prefix (a /28 cannot host the default 100-address pool).
pub fn subnet_plan(subnet: &str) -> Result<SubnetPlan> {
    let (addr, prefix) = subnet
        .split_once('/')
        .ok_or_else(|| HotspotError::Config(format!("hotspot.subnet needs CIDR: {subnet}")))?;
    let base: Ipv4Addr = addr
        .parse()
        .map_err(|_| HotspotError::Config(format!("hotspot.subnet bad address: {addr}")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| HotspotError::Config(format!("hotspot.subnet bad prefix: {subnet}")))?;
    if !(16..=29).contains(&prefix) {
        return Err(HotspotError::Config(format!(
            "hotspot.subnet prefix must be 16..=29, got {prefix}"
        )));
    }
    let mask = u32::MAX << (32 - prefix);
    let net = u32::from(base) & mask;
    let broadcast = net | !mask;
    let hosts = broadcast - net - 1; // usable count
    if hosts < 4 {
        return Err(HotspotError::Config(
            "hotspot.subnet too small (need >= 4 usable addresses)".to_string(),
        ));
    }
    let gateway = net + 1;
    // Default pool .100-.199 on /24 and bigger; everything but gateway +
    // broadcast on tiny subnets.
    let (start, end) = if hosts >= 200 {
        (net + 100, net + 199)
    } else {
        (net + 2, broadcast - 1)
    };
    Ok(SubnetPlan {
        network: net.into(),
        prefix,
        gateway: gateway.into(),
        dhcp_start: start.into(),
        dhcp_end: end.into(),
        broadcast: broadcast.into(),
    })
}

impl HotspotConfig {
    /// Parse the `hotspot:` section of a client config document.
    pub fn from_doc(doc: &serde_json::Value) -> Result<Self> {
        let Some(hs) = doc.get("hotspot") else {
            return Ok(Self::default());
        };
        if !hs.is_object() {
            return Err(HotspotError::Config(
                "hotspot section must be a mapping".to_string(),
            ));
        }
        let mut cfg = Self::default();
        if let Some(v) = hs.get("enabled").and_then(serde_json::Value::as_bool) {
            cfg.enabled = v;
        }
        if let Some(v) = hs.get("interface").and_then(serde_json::Value::as_str) {
            if !v.is_empty() {
                cfg.interface = Some(v.to_string());
            }
        }
        if let Some(v) = hs.get("ssid").and_then(serde_json::Value::as_str) {
            cfg.ssid = v.to_string();
        }
        if let Some(v) = hs.get("password").and_then(serde_json::Value::as_str) {
            if !v.is_empty() {
                cfg.password = Some(v.to_string());
            }
        }
        if let Some(v) = hs.get("subnet").and_then(serde_json::Value::as_str) {
            if !v.is_empty() {
                cfg.subnet = v.to_string();
            }
        }
        if let Some(v) = hs.get("backend").and_then(serde_json::Value::as_str) {
            cfg.backend = BackendChoice::parse(v)?;
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate everything an `up` needs (except the password, which is
    /// only mandatory at bring-up time: a config may pre-stage the rest).
    pub fn validate(&self) -> Result<()> {
        if self.ssid.is_empty() || self.ssid.len() > 32 {
            return Err(HotspotError::Config(
                "hotspot.ssid must be 1..=32 bytes".to_string(),
            ));
        }
        if let Some(psk) = &self.password {
            if !(8..=63).contains(&psk.len()) {
                return Err(HotspotError::Config(
                    "hotspot.password must be 8..=63 chars (WPA2-PSK)".to_string(),
                ));
            }
        }
        if let Some(iface) = &self.interface {
            if iface.is_empty() || iface.len() > 15 {
                return Err(HotspotError::Config(
                    "hotspot.interface must be 1..=15 chars".to_string(),
                ));
            }
        }
        subnet_plan(&self.subnet)?;
        Ok(())
    }

    /// Bring-up validation: password is mandatory here.
    pub fn validate_up(&self) -> Result<SubnetPlan> {
        self.validate()?;
        if self.password.is_none() {
            return Err(HotspotError::Config(
                "hotspot.password required (8..=63 chars)".to_string(),
            ));
        }
        subnet_plan(&self.subnet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_plan_is_243_subnet() {
        let plan = subnet_plan(DEFAULT_SUBNET).expect("default subnet parses");
        assert_eq!(plan.network, "192.168.243.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(plan.gateway, "192.168.243.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            plan.dhcp_start,
            "192.168.243.100".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            plan.dhcp_end,
            "192.168.243.199".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            plan.broadcast,
            "192.168.243.255".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn host_bits_are_normalized() {
        let plan = subnet_plan("10.99.0.5/24").expect("host bits ok");
        assert_eq!(plan.network, "10.99.0.0".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn tiny_subnet_gets_full_range() {
        // /28: 14 usable -> gateway .1, pool .2-.14
        let plan = subnet_plan("172.20.10.0/28").expect("parses");
        assert_eq!(plan.gateway, "172.20.10.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            plan.dhcp_start,
            "172.20.10.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            plan.dhcp_end,
            "172.20.10.14".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn bad_prefixes_rejected() {
        assert!(subnet_plan("192.168.1.0/30").is_err());
        assert!(subnet_plan("192.168.1.0/8").is_err());
        assert!(subnet_plan("192.168.1.0").is_err());
        assert!(subnet_plan("junk/24").is_err());
    }

    #[test]
    fn doc_parse_defaults_and_overrides() {
        let empty = HotspotConfig::from_doc(&serde_json::json!({})).expect("empty ok");
        assert!(!empty.enabled);
        assert_eq!(empty.ssid, DEFAULT_SSID);

        let cfg = HotspotConfig::from_doc(&serde_json::json!({
            "hotspot": {
                "enabled": true,
                "interface": "wlan0",
                "ssid": "MyVPN",
                "password": "12345678",
                "subnet": "192.168.50.0/24",
                "backend": "hostapd"
            }
        }))
        .expect("full section parses");
        assert!(cfg.enabled);
        assert_eq!(cfg.interface.as_deref(), Some("wlan0"));
        assert_eq!(cfg.backend, BackendChoice::Hostapd);
    }

    #[test]
    fn short_password_rejected_at_up() {
        let cfg = HotspotConfig::from_doc(&serde_json::json!({
            "hotspot": { "password": "short" }
        }));
        assert!(cfg.is_err(), "WPA2 needs 8+ chars");
    }

    #[test]
    fn up_without_password_is_named() {
        let cfg = HotspotConfig::default();
        let err = cfg.validate_up().expect_err("password mandatory at up");
        assert!(err.to_string().contains("password"));
    }
}
