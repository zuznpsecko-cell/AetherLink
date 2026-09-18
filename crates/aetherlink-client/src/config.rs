//! Client configuration: §8 schema with required-field validation.
//!
//! Parsed once at the boundary (`Client::new`); interior code receives the
//! typed value and never re-validates.

use crate::routing::Ruleset;
use crate::{ClientError, Result};

/// Validated client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// `host:port` of the server.
    pub server_addr: String,
    /// SNI presented outside (defaults to the host part).
    pub outer_sni: String,
    /// Pre-shared key (required, non-empty; never logged).
    pub psk: String,
    /// Frame padding multiple.
    pub pad_multiple: usize,
    /// Keepalive interval, seconds.
    pub keepalive_s: u64,
    /// TUN MTU.
    pub mtu: u32,
    /// Kill-switch (complex behavior lands in the platform task).
    pub kill_switch: bool,
    /// Restore network on exit.
    pub restore_on_exit: bool,
    /// RFC1918 direct without explicit rules.
    pub include_private_lan_direct: bool,
    /// FIXED `tunnel`: any other value is rejected.
    pub dns_mode: String,
    /// Routing rules (default LAN rules included).
    pub rules: Ruleset,
}

fn required_str(doc: &serde_json::Value, field: &str) -> Result<String> {
    doc.get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| ClientError::ConfigError(format!("missing {field}")))
}

fn parse_port(server_addr: &str) -> Result<(String, u16)> {
    let (host, port) = server_addr
        .rsplit_once(':')
        .ok_or_else(|| ClientError::ConfigError("server_addr must be host:port".to_string()))?;
    if host.is_empty() {
        return Err(ClientError::ConfigError(
            "server_addr host empty".to_string(),
        ));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| ClientError::ConfigError("server_addr port invalid".to_string()))?;
    if port == 0 {
        return Err(ClientError::ConfigError(
            "server_addr port invalid".to_string(),
        ));
    }
    Ok((host.to_string(), port))
}

impl ClientConfig {
    /// Parse + validate a client config document from a JSON value.
    ///
    /// Accepts both the §8 nested shape (`{client: {...}}`) and a flat
    /// table (FFI callers passing pre-extracted sections).
    pub fn parse(root: &serde_json::Value) -> Result<Self> {
        let doc = root.get("client").unwrap_or(root);
        Self::parse_flat(doc)
    }

    /// Parse + validate a flat client config table.
    pub fn parse_flat(doc: &serde_json::Value) -> Result<Self> {
        let server_addr = required_str(doc, "server_addr")?;
        let (host, _port) = parse_port(&server_addr)?;
        let psk = required_str(doc, "psk")?;
        let dns_mode = doc
            .get("dns_mode")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("tunnel")
            .to_string();
        if dns_mode != "tunnel" {
            return Err(ClientError::ConfigError(
                "dns_mode must be tunnel (v1.5 only supports tunnel)".to_string(),
            ));
        }
        let outer_sni = doc
            .get("outer_sni")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(&host)
            .to_string();
        let pad_multiple = doc
            .get("pad_multiple")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(128) as usize;
        if pad_multiple == 0 {
            return Err(ClientError::ConfigError(
                "pad_multiple must be > 0".to_string(),
            ));
        }
        let full = doc.get("full_tunnel");
        let get_bool = |obj: Option<&serde_json::Value>, key: &str, def: bool| {
            obj.and_then(|o| o.get(key))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(def)
        };
        let mtu = full
            .and_then(|o| o.get("mtu"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1400) as u32;
        let mut rules = Ruleset::new();
        rules.include_private_lan_direct = get_bool(full, "include_private_lan_direct", true);
        if let Some(rule_docs) = doc
            .get("routing")
            .and_then(|r| r.get("rules"))
            .and_then(serde_json::Value::as_array)
        {
            for rule_doc in rule_docs {
                parse_rule(&mut rules, rule_doc)?;
            }
        }
        Ok(ClientConfig {
            server_addr,
            outer_sni,
            psk,
            pad_multiple,
            keepalive_s: doc
                .get("keepalive_s")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(15),
            mtu,
            kill_switch: get_bool(full, "kill_switch", false),
            restore_on_exit: get_bool(full, "restore_on_exit", true),
            include_private_lan_direct: rules.include_private_lan_direct,
            dns_mode,
            rules,
        })
    }
} // impl ClientConfig

/// Parse one routing rule document into the ruleset (via `Rule::from_doc`).
fn parse_rule(rules: &mut Ruleset, doc: &serde_json::Value) -> Result<()> {
    let rule = crate::routing::Rule::from_doc(doc).map_err(|e| match e {
        ClientError::RoutingError(msg) => ClientError::ConfigError(msg),
        other => other,
    })?;
    rules.add_rule(&rule.name, rule.action, rule.matcher, rule.priority);
    Ok(())
}
