//! AetherLink server library
//!
//! Provides server-side functionality: authentication, static fallback,
//! TCP/UDP relay, and DNS upstream resolution.

pub mod accept;
pub mod auth;
pub mod config;
pub mod debug;
pub mod dns;
pub mod fallback;
pub mod relay;

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use aetherlink_core::tls;
use aetherlink_core::CoreError;
use aetherlink_crypto::auth::NonceCache;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Core error: {0}")]
    Core(#[from] CoreError),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Relay error: {0}")]
    RelayError(String),

    #[error("DNS error: {0}")]
    DnsError(String),

    #[error("Fallback error: {0}")]
    FallbackError(String),

    #[error("Config error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, ServerError>;

/// Server handle: validated config (network starts in `serve_*`).
pub struct Server {
    /// Validated configuration.
    pub config: config::ServerConfig,
}

impl Server {
    /// Create from a config document (validated once, at the boundary).
    pub fn new(doc: serde_json::Value) -> Result<Self> {
        Ok(Self {
            config: config::ServerConfig::parse(&doc)?,
        })
    }

    /// Bind the listen address and load TLS + static state (fail fast).
    ///
    /// No socket serves until `serve_once`/`serve_forever` runs: `bind`
    /// only proves the config works (address, cert files, static root).
    pub fn bind(&self) -> Result<ServerListener> {
        let addr: SocketAddr = self
            .config
            .listen
            .to_socket_addrs()
            .map_err(|e| ServerError::ConfigError(format!("bad listen: {e}")))?
            .next()
            .ok_or_else(|| ServerError::ConfigError("unresolvable listen".to_string()))?;
        let listener =
            TcpListener::bind(addr).map_err(|e| ServerError::ConfigError(format!("bind: {e}")))?;
        let cert_pem = std::fs::read(&self.config.tls_cert)
            .map_err(|e| ServerError::ConfigError(format!("read tls_cert: {e}")))?;
        let key_pem = std::fs::read(&self.config.tls_key)
            .map_err(|e| ServerError::ConfigError(format!("read tls_key: {e}")))?;
        let (chain, key) = tls::load_cert_key(&cert_pem, &key_pem).map_err(ServerError::Core)?;
        let key_der = match &key {
            rustls::pki_types::PrivateKeyDer::Pkcs8(key) => key.secret_pkcs8_der().to_vec(),
            rustls::pki_types::PrivateKeyDer::Pkcs1(key) => key.secret_pkcs1_der().to_vec(),
            rustls::pki_types::PrivateKeyDer::Sec1(key) => key.secret_sec1_der().to_vec(),
            _ => {
                return Err(ServerError::ConfigError("unsupported key type".to_string()));
            }
        };
        let tls_cfg = Arc::new(tls::server_config(chain, &key_der).map_err(ServerError::Core)?);
        let mut index = std::path::PathBuf::from(&self.config.local_static_root);
        index.push("index.html");
        let static_body = std::fs::read(&index)
            .map_err(|e| ServerError::ConfigError(format!("read static root: {e}")))?;
        Ok(ServerListener {
            listener,
            ctx: accept::ServerCtx {
                tls: tls_cfg,
                psk: self.config.psk.as_bytes().to_vec(),
                cache: NonceCache::new(),
                static_body,
                dns_upstream: {
                    let mut list = self.config.dns_upstream.clone();
                    if list.is_empty() {
                        list.push(crate::dns::upstream().to_string());
                    }
                    list
                },
            },
        })
    }
}

/// Bound server: listener + shared per-listener context.
pub struct ServerListener {
    listener: TcpListener,
    ctx: accept::ServerCtx,
}

impl ServerListener {
    /// Local address actually bound (useful with port 0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept exactly one connection and serve it to a path decision.
    pub fn serve_once(&self) -> accept::Path {
        let sock = match self.listener.accept() {
            Ok((sock, _)) => sock,
            Err(_) => return accept::Path::Closed,
        };
        let mut routes = HashMap::new();
        accept::serve_connection(sock, &self.ctx, &mut routes)
    }

    /// Serve in background: accept loop on a worker thread, one thread per
    /// connection. Returns immediately with a guard; `request_stop` + `join`
    /// shuts it down. Connection count is unbounded (DoS hardening is a
    /// follow-up; `max_streams` bounds mux state per connection).
    pub fn serve_background(self) -> ServerGuard {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        // Nonblocking accept lets the loop observe the stop flag promptly.
        self.listener.set_nonblocking(true).ok();
        let thread = std::thread::spawn(move || {
            let ctx = Arc::new(self.ctx);
            loop {
                if flag.load(Ordering::Relaxed) {
                    break;
                }
                match self.listener.accept() {
                    Ok((sock, _)) => {
                        // Accepted sockets inherit nonblocking mode: restore
                        // blocking I/O, the whole serve path depends on it.
                        sock.set_nonblocking(false).ok();
                        let ctx = Arc::clone(&ctx);
                        std::thread::spawn(move || {
                            let mut routes = HashMap::new();
                            accept::serve_connection(sock, &ctx, &mut routes);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
        });
        ServerGuard {
            stop,
            thread: Some(thread),
        }
    }
}

/// Background accept loop; stops promptly on request.
pub struct ServerGuard {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ServerGuard {
    /// Ask the loop to stop (in-flight connections drain on their own).
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Wait for the loop thread (bounded: poll slice is 25ms).
    pub fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
