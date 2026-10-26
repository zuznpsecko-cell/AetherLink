//! Client configuration: §8 schema with required-field validation.
//!
//! Parsed once at the boundary (`Client::new`); interior code receives the
//! typed value and never re-validates.

use crate::android_plan::{validate_split, AndroidSplit, SplitMode};
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
    /// Inline PEM CA for Android: the app cannot read the system trust store.
    pub tls_ca_pem: Option<String>,
    /// Android per-app / per-destination split selection.
    pub android_split: AndroidSplit,
    /// Android: carve RFC1918 out of `0.0.0.0/0` (defaults to
    /// `full_tunnel.include_private_lan_direct`).
    pub android_lan_direct: bool,
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
        let inner = root.get("client").unwrap_or(root);
        // Section inheritance: file-level `full_tunnel`/`routing` apply when
        // the `client:` section does not define them (the shipped example
        // layout). Without this, root sections are silently dropped.
        let mut doc = inner.clone();
        if let Some(map) = doc.as_object_mut() {
            for key in ["full_tunnel", "routing"] {
                if !map.contains_key(key) {
                    if let Some(section) = root.get(key) {
                        map.insert(key.to_string(), section.clone());
                    }
                }
            }
        }
        Self::parse_flat(&doc)
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
        let android = parse_android(doc.get("android"), rules.include_private_lan_direct)?;
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
            tls_ca_pem: parse_tls_ca(doc.get("tls"))?,
            android_split: android.0,
            android_lan_direct: android.1,
            rules,
        })
    }
} // impl ClientConfig

/// Optional `client.tls.ca_pem`: validated as PEM, kept verbatim.
fn parse_tls_ca(tls: Option<&serde_json::Value>) -> Result<Option<String>> {
    let Some(pem) = tls.and_then(|section| section.get("ca_pem")) else {
        return Ok(None);
    };
    let text = pem.as_str().ok_or_else(|| {
        ClientError::ConfigError("client.tls.ca_pem must be a string".to_string())
    })?;
    let mut reader = std::io::Cursor::new(text.as_bytes());
    match rustls_pemfile::certs(&mut reader) {
        Ok(certs) if !certs.is_empty() => Ok(Some(text.to_string())),
        _ => Err(ClientError::ConfigError(
            "client.tls.ca_pem is not a valid PEM certificate".to_string(),
        )),
    }
}

/// `android.split` + `android.use_full_tunnel_lan_direct`.
fn parse_android(
    android: Option<&serde_json::Value>,
    default_lan_direct: bool,
) -> Result<(AndroidSplit, bool)> {
    let Some(section) = android else {
        return Ok((AndroidSplit::default(), default_lan_direct));
    };
    let split = match section.get("split") {
        Some(split) if !split.is_null() => {
            let mode = match split
                .get("mode")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("all")
            {
                "all" => SplitMode::All,
                "allow" => SplitMode::Allow,
                "deny" => SplitMode::Deny,
                "subnets" => SplitMode::Subnets,
                other => {
                    return Err(ClientError::ConfigError(format!(
                        "android.split.mode must be all|allow|deny|subnets, got {other:?}"
                    )))
                }
            };
            AndroidSplit {
                mode,
                apps: string_list(split.get("apps"), "android.split.apps")?,
                subnets: string_list(split.get("subnets"), "android.split.subnets")?,
            }
        }
        _ => AndroidSplit::default(),
    };
    validate_split(&split)?;
    let lan_direct = section
        .get("use_full_tunnel_lan_direct")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(default_lan_direct);
    Ok((split, lan_direct))
}

fn string_list(value: Option<&serde_json::Value>, field: &str) -> Result<Vec<String>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_string).ok_or_else(|| {
                    ClientError::ConfigError(format!("{field} must contain strings"))
                })
            })
            .collect(),
        Some(_) => Err(ClientError::ConfigError(format!(
            "{field} must be an array"
        ))),
    }
}

/// Parse one routing rule document into the ruleset (via `Rule::from_doc`).
fn parse_rule(rules: &mut Ruleset, doc: &serde_json::Value) -> Result<()> {
    let rule = crate::routing::Rule::from_doc(doc).map_err(|e| match e {
        ClientError::RoutingError(msg) => ClientError::ConfigError(msg),
        other => other,
    })?;
    rules.add_rule(&rule.name, rule.action, rule.matcher, rule.priority);
    Ok(())
}
