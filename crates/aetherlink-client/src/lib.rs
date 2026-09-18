//! AetherLink client library
//!
//! Provides client-side functionality: full tunnel lifecycle, routing rules,
//! DNS override, crash recovery, and platform-specific implementations.

pub mod cleanup;
pub mod config;
pub mod dns;
pub mod lifecycle;
pub mod platform;
pub mod routing;

use aetherlink_core::CoreError;
use aetherlink_netstack::NetstackError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Core error: {0}")]
    Core(#[from] CoreError),

    #[error("Netstack error: {0}")]
    Netstack(#[from] NetstackError),

    #[error("Routing error: {0}")]
    RoutingError(String),

    #[error("DNS error: {0}")]
    DnsError(String),

    #[error("Cleanup error: {0}")]
    CleanupError(String),

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("Platform error: {0}")]
    PlatformError(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Client handle: validated config + lifecycle state.
pub struct Client {
    config: config::ClientConfig,
    up: bool,
}

impl Client {
    /// Create from a config document (validated once, at the boundary).
    pub fn new(doc: serde_json::Value) -> Result<Self> {
        Ok(Self {
            config: config::ClientConfig::parse(&doc)?,
            up: false,
        })
    }

    /// Create from an already-validated config (tests, embeds).
    #[must_use]
    pub fn new_config(config: config::ClientConfig) -> Self {
        Self { config, up: false }
    }

    /// Bring the tunnel up against the real platform (idempotent).
    pub fn up(&mut self) -> Result<()> {
        let mut platform = platform::RealPlatform;
        self.up_on(&mut platform)
    }

    /// Bring the tunnel up against an explicit platform (tests).
    pub fn up_on(&mut self, platform: &mut dyn platform::Platform) -> Result<()> {
        if self.up {
            return Ok(());
        }
        lifecycle::up(platform, &self.config)?;
        self.up = true;
        Ok(())
    }

    /// Bring the tunnel down (safe no-op when not up).
    pub fn down(&mut self) -> Result<()> {
        lifecycle::down(&mut platform::RealPlatform)?;
        self.up = false;
        Ok(())
    }

    /// Whether the tunnel is up.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.up
    }

    /// Status snapshot as a JSON document (no secrets).
    pub fn status(&self) -> Result<String> {
        serde_json::to_string(&serde_json::json!({
            "up": self.up,
            "server": self.config.server_addr,
            "dns_mode": self.config.dns_mode,
        }))
        .map_err(|e| ClientError::PlatformError(format!("status encode: {e}")))
    }

    /// Serialize the current rule list as JSON (FFI `rules_list`).
    pub fn rules_json(&self) -> Result<String> {
        serde_json::to_string(&self.config.rules.rules())
            .map_err(|e| ClientError::RoutingError(format!("rules encode: {e}")))
    }

    /// Replace the complete rule list from rule documents
    /// (`{rules: [...]}`); validated atomically before replacing.
    pub fn set_rules(&mut self, doc: &serde_json::Value) -> Result<()> {
        let arr = doc
            .get("rules")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| ClientError::RoutingError("rules needs a rules array".to_string()))?;
        let mut rules = Vec::with_capacity(arr.len());
        for rule_doc in arr {
            rules.push(routing::Rule::from_doc(rule_doc)?);
        }
        self.config.rules.replace_rules(rules)
    }

    /// Revalidate the current rule list (FFI `rules_reload`).
    pub fn reload_rules(&self) -> Result<()> {
        for rule in self.config.rules.rules() {
            rule.validate()?;
        }
        Ok(())
    }
}
