//! AetherLink client library
//!
//! Provides client-side functionality: full tunnel lifecycle, routing rules,
//! DNS override, crash recovery, and platform-specific implementations.

pub mod cleanup;
pub mod config;
pub mod dns;
pub mod lifecycle;
pub mod platform;
pub mod pump;
pub mod routing;
pub mod threads;

use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use aetherlink_core::CoreError;
use aetherlink_mux::MuxError;
use aetherlink_netstack::tun::TunPackets;
use aetherlink_netstack::NetstackError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Core error: {0}")]
    Core(#[from] CoreError),

    #[error("Netstack error: {0}")]
    Netstack(#[from] NetstackError),

    #[error("Mux error: {0}")]
    Mux(#[from] MuxError),

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
    pump: Option<threads::PumpHandle>,
    platform: platform::RealPlatform,
}

impl Client {
    /// Create from a config document (validated once, at the boundary).
    pub fn new(doc: serde_json::Value) -> Result<Self> {
        Ok(Self {
            config: config::ClientConfig::parse(&doc)?,
            up: false,
            pump: None,
            platform: platform::RealPlatform::new(),
        })
    }

    /// Create from an already-validated config (tests, embeds).
    #[must_use]
    pub fn new_config(config: config::ClientConfig) -> Self {
        Self {
            config,
            up: false,
            pump: None,
            platform: platform::RealPlatform::new(),
        }
    }

    /// Bring the tunnel up against the real platform (idempotent).
    pub fn up(&mut self) -> Result<()> {
        if self.up {
            return Ok(());
        }
        lifecycle::up(&mut self.platform, &self.config)?;
        self.up = true;
        Ok(())
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
        self.stop_pump();
        lifecycle::down(&mut self.platform)?;
        self.up = false;
        Ok(())
    }

    /// Attach pump threads over an established stream (W4).
    ///
    /// `tun` is shared with the caller; `tx` seals TUN->wire, `rx` opens
    /// wire->TUN (session traffic keys). Idempotent: second call is a no-op
    /// until `stop_pump`/`down`.
    pub fn start_pump<T>(
        &mut self,
        tun: Arc<Mutex<T>>,
        stream: TcpStream,
        tx: [u8; 32],
        rx: [u8; 32],
    ) -> Result<()>
    where
        T: TunPackets + Send + 'static,
    {
        if self.pump.is_some() {
            return Ok(());
        }
        let pad = self.config.pad_multiple;
        let handle = threads::spawn_pump(tun, stream, tx, rx, pad)
            .map_err(|e| ClientError::PlatformError(format!("pump spawn: {e}")))?;
        self.pump = Some(handle);
        Ok(())
    }

    /// Stop pump threads, if running (idempotent).
    pub fn stop_pump(&mut self) {
        if let Some(mut handle) = self.pump.take() {
            handle.stop();
        }
    }

    /// Attach the live transport: connect (TLS+AUTH) and pump TUN<->session.
    ///
    /// Requires a prior `up()` holding the TUN handle. Fails closed (no
    /// bytes move) when the server is unreachable or AUTH rejects us.
    pub fn attach_transport(
        &mut self,
        verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
    ) -> Result<()> {
        let tun = self
            .platform
            .tun_handle()
            .ok_or_else(|| ClientError::PlatformError("no live TUN (up first)".to_string()))?;
        let tunnel = lifecycle::connect(&self.config, verifier)?;
        self.start_pump_tls(tun, tunnel)
    }

    /// Full bring-up: platform `up` + transport attach; rolls the platform
    /// back down when the transport fails so no half-tunnel survives.
    pub fn up_full(
        &mut self,
        verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
    ) -> Result<()> {
        if self.up {
            return Ok(());
        }
        lifecycle::up(&mut self.platform, &self.config)?;
        if let Err(e) = self.attach_transport(verifier) {
            let _ = lifecycle::down(&mut self.platform);
            self.up = false;
            return Err(e);
        }
        self.up = true;
        Ok(())
    }

    /// Attach the pump inside an established TLS session (production path).
    ///
    /// Takes a `lifecycle::connect` tunnel: session mux/keys move into the
    /// pump thread. Idempotent like `start_pump`.
    pub fn start_pump_tls<T>(
        &mut self,
        tun: Arc<Mutex<T>>,
        tunnel: lifecycle::ConnectedTunnel,
    ) -> Result<()>
    where
        T: TunPackets + Send + 'static,
    {
        if self.pump.is_some() {
            return Ok(());
        }
        let pad = self.config.pad_multiple;
        let handle = threads::spawn_pump_tls(tun, tunnel, pad)
            .map_err(|e| ClientError::PlatformError(format!("tls pump spawn: {e}")))?;
        self.pump = Some(handle);
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
