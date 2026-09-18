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
    /// Pre-shared key (required, non-empty; never logged).
    pub psk: String,
    /// Static web root for the G2 fallback.
    pub local_static_root: String,
    /// DNS upstreams, primary first.
    pub dns_upstream: Vec<String>,
    /// Max concurrent streams.
    pub max_streams: usize,
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
        Ok(Self {
            listen,
            tls_cert,
            tls_key,
            psk,
            local_static_root,
            dns_upstream,
            max_streams: doc
                .get("max_streams")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(4096) as usize,
        })
    }
}

/// Parse + validate a server config document (shared JSON→YAML boundary).
pub fn parse(raw: &str) -> Result<()> {
    let doc = aetherlink_core::config::parse_document(raw)
        .map_err(|e| ServerError::ConfigError(e.to_string()))?;
    ServerConfig::parse(&doc).map(|_| ())
}
