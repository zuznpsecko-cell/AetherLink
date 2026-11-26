//! Server configuration: §8 schema with required-field validation.
//!
//! Parsed once at the boundary (`Server::new`); interior code receives the
//! typed value and never re-validates.

use crate::{Result, ServerError};

/// Validated server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Listen address (`host:port`).
    pub listen: String,
    /// TLS certificate path.
    pub tls_cert: String,
    /// TLS key path.
    pub tls_key: String,
    /// Pre-shared key (required, at least `MIN_PSK_LEN` bytes; never logged).
    pub psk: String,
    /// Static web root for the G2 fallback.
    pub local_static_root: String,
    /// DNS upstreams, primary first.
    pub dns_upstream: Vec<String>,
    /// Max concurrent streams per connection.
    pub max_streams: usize,
    /// Max concurrently served connections (DoS bound: one thread each).
    pub max_connections: usize,
    /// Inline blocked suffixes (`full:` prefix = exact host).
    pub blocked_domains: Vec<String>,
    /// Optional path to a flat blocklist file (category-ads-all format).
    pub blocked_domains_file: Option<String>,
    /// Master switch (default true). False = no blocking at all.
    pub blocklist_enabled: bool,
    /// Which resolved addresses the relay may dial (DEC-021).
    pub egress: crate::egress::EgressPolicy,
}

fn required_str(doc: &serde_json::Value, field: &str) -> Result<String> {
    doc.get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| ServerError::ConfigError(format!("missing {field}")))
}

impl ServerConfig {
    /// Parse + validate from a JSON value.
    ///
    /// Accepts both the §8 nested shape (`{server: {...}}`) and a flat table.
    pub fn parse(root: &serde_json::Value) -> Result<Self> {
        let doc = root.get("server").unwrap_or(root);
        let listen = required_str(doc, "listen")?;
        let psk = required_str(doc, "psk")?;
        // Length only — the value itself never goes into an error or a log.
        if psk.len() < aetherlink_crypto::MIN_PSK_LEN {
            return Err(ServerError::ConfigError(format!(
                "psk too short: need at least {} bytes",
                aetherlink_crypto::MIN_PSK_LEN
            )));
        }
        let local_static_root = required_str(doc, "local_static_root")?;
        let tls_cert = doc
            .get("tls_cert")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        let tls_key = doc
            .get("tls_key")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        let dns_upstream = doc
            .get("dns_upstream")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_else(|| vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()]);
        if dns_upstream.is_empty() {
            return Err(ServerError::ConfigError("empty dns_upstream".to_string()));
        }
        let blocked_domains = doc
            .get("blocked_domains")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let blocked_domains_file = doc
            .get("blocked_domains_file")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let blocklist_enabled = doc
            .get("blocklist_enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let egress = parse_egress(doc.get("egress"))?;
        Ok(Self {
            listen,
            tls_cert,
            tls_key,
            psk,
            local_static_root,
            dns_upstream,
            blocked_domains,
            blocked_domains_file,
            blocklist_enabled,
            egress,
            // Zero would refuse every stream; clamp like `max_connections`.
            max_streams: (doc
                .get("max_streams")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(crate::accept::DEFAULT_MAX_STREAMS as u64)
                as usize)
                .max(1),
            max_connections: doc
                .get("max_connections")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(crate::accept::DEFAULT_MAX_CONNECTIONS as u64)
                .max(1) as usize,
        })
    }
}

/// Parse + validate a server config document (shared JSON→YAML boundary).
pub fn parse(raw: &str) -> Result<()> {
    let doc = aetherlink_core::config::parse_document(raw)
        .map_err(|e| ServerError::ConfigError(e.to_string()))?;
    ServerConfig::parse(&doc).map(|_| ())
}

/// Parse the optional `egress` block (DEC-021).
///
/// Defaults matter here: a server started from a config that predates this
/// block must still be protected, so `deny_private` is `true` unless the
/// operator writes `false`. A malformed CIDR is a hard error — silently
/// ignoring it would widen the policy without anyone noticing.
fn parse_egress(doc: Option<&serde_json::Value>) -> Result<crate::egress::EgressPolicy> {
    let Some(doc) = doc else {
        return Ok(crate::egress::EgressPolicy::new(
            true,
            Vec::new(),
            Vec::new(),
        ));
    };
    let deny_private = doc
        .get("deny_private")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let allow = parse_cidrs(doc.get("allow"), "egress.allow")?;
    let deny = parse_cidrs(doc.get("deny"), "egress.deny")?;
    Ok(crate::egress::EgressPolicy::new(deny_private, allow, deny))
}

/// Parse a CIDR list; every entry must be a valid range.
fn parse_cidrs(doc: Option<&serde_json::Value>, field: &str) -> Result<Vec<crate::egress::Cidr>> {
    let Some(arr) = doc.and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };
    arr.iter()
        .map(|v| {
            let spec = v
                .as_str()
                .ok_or_else(|| ServerError::ConfigError(format!("{field}: not a string")))?;
            crate::egress::Cidr::parse(spec)
                .ok_or_else(|| ServerError::ConfigError(format!("{field}: bad CIDR {spec:?}")))
        })
        .collect()
}
