//! AetherLink server library
//!
//! Provides server-side functionality: authentication, static fallback,
//! TCP/UDP relay, and DNS upstream resolution.

pub mod accept;
pub mod auth;
pub mod blocklist;
pub mod config;
pub mod debug;
pub mod dns;
pub mod egress;
pub mod fallback;
pub mod pool;
pub mod relay;

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

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
        // Hand the typed key over as-is: PKCS#1 (`BEGIN RSA PRIVATE KEY`) and
        // SEC1 (`BEGIN EC PRIVATE KEY`) bodies are not PKCS#8, and labelling
        // them so made rustls reject valid keys at startup.
        let tls_cfg = Arc::new(tls::server_config_with_key(chain, key).map_err(ServerError::Core)?);
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
                egress: self.config.egress.clone(),
                blocklist: if !self.config.blocklist_enabled {
                    crate::blocklist::Blocklist::default()
                } else {
                    // Seed + config + optional file, merged (file missing =
                    // seed+config only, logged, never fatal).
                    let mut entries: Vec<&str> = crate::blocklist::seed_entries().to_vec();
                    entries.extend(self.config.blocked_domains.iter().map(String::as_str));
                    let file_text = self
                        .config
                        .blocked_domains_file
                        .as_deref()
                        .map(std::fs::read_to_string);
                    let owned;
                    match file_text {
                        Some(Ok(text)) => {
                            owned = text;
                            entries.extend(owned.lines());
                        }
                        Some(Err(e)) => {
                            crate::debug::debug_log(&format!(
                                "blocklist file unreadable ({e}), seed+config only"
                            ));
                        }
                        None => {}
                    }
                    crate::blocklist::Blocklist::from_entries(entries)
                },
                live_connections: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                max_connections: self.config.max_connections,
                max_streams: self.config.max_streams,
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
    /// shuts it down.
    ///
    /// Concurrency is bounded twice on purpose: `server.max_connections` caps
    /// live connections (each costs a 4 MiB stack thread), and `max_streams`
    /// caps mux state per connection. Past the connection cap new sockets are
    /// dropped immediately — shedding, never queueing.
    ///
    /// The loop survives per-peer and resource errors from `accept()` (see
    /// [`classify_accept_error`]); only a broken listener ends it, and then
    /// [`ServerGuard::is_running`] turns false and [`ServerGuard::failure`]
    /// carries the reason, so the host can exit and be restarted instead of
    /// idling with a dead listener.
    pub fn serve_background(self) -> ServerGuard {
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let flag = Arc::clone(&stop);
        let failure_slot = Arc::clone(&failure);
        // Nonblocking accept lets the loop observe the stop flag promptly.
        self.listener.set_nonblocking(true).ok();
        let thread = std::thread::spawn(move || {
            let ctx = Arc::new(self.ctx);
            let listener = self.listener;
            let outcome = run_accept_loop(
                &flag,
                || listener.accept().map(|(sock, _)| sock),
                |sock| spawn_connection(sock, &ctx),
                std::thread::sleep,
            );
            if let Err(e) = outcome {
                eprintln!("[aetherlink] accept loop stopped: listener failed: {e}");
                *failure_slot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(format!("listener failed: {e}"));
            }
        });
        ServerGuard {
            stop,
            failure,
            thread: Some(thread),
        }
    }
}

/// Hand one accepted socket to its own connection thread.
fn spawn_connection(sock: std::net::TcpStream, ctx: &Arc<accept::ServerCtx>) {
    // Accepted sockets inherit nonblocking mode: restore blocking I/O, the
    // whole serve path depends on it.
    sock.set_nonblocking(false).ok();
    // Shed before spawning a thread: the cap is enforced again inside
    // `serve_connection` (which owns the RAII slot), this early check just
    // avoids spawning a thread only to have it bounce.
    if ctx.live_connections() >= ctx.max_connections {
        drop(sock);
        return;
    }
    let ctx = Arc::clone(ctx);
    let spawned = std::thread::Builder::new()
        .name("tunnel-conn".to_string())
        .stack_size(4 * 1024 * 1024)
        .spawn(move || {
            // Containment, not error handling: a panic in ONE connection must
            // not take the process. This only works because the release
            // profile unwinds (see `panic = "unwind"` in the root Cargo.toml)
            // — with `panic = "abort"` this guard is dead code and the server
            // dies.
            let contained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let mut routes = HashMap::new();
                accept::serve_connection(sock, &ctx, &mut routes);
            }));
            if contained.is_err() {
                crate::debug::debug_log("accept: connection panicked, socket dropped");
            }
        });
    if let Err(e) = spawned {
        // The OS refused a thread (memory / RLIMIT_NPROC). The socket went
        // down with the closure, i.e. the peer gets a reset. Say so loudly and
        // give the host a moment instead of accept-and-drop spinning.
        eprintln!("[aetherlink] accept: cannot spawn connection thread ({e}), socket dropped");
        std::thread::sleep(SPAWN_FAILURE_PAUSE);
    }
}

/// Pause after a failed connection-thread spawn.
const SPAWN_FAILURE_PAUSE: Duration = Duration::from_millis(50);

/// Idle poll interval of the nonblocking accept loop.
pub const ACCEPT_IDLE_POLL: Duration = Duration::from_millis(25);

/// Consecutive per-peer errors tolerated before the loop starts backing off.
///
/// A burst of aborted handshakes is normal; an endless one means the kernel
/// keeps handing us the same failure and retrying without a pause would spin
/// a core.
pub const ACCEPT_RETRY_BURST: u32 = 16;

/// Upper bound of the accept backoff.
pub const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// What the accept loop does after `accept()` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptErrorAction {
    /// Nothing pending on the nonblocking listener: idle briefly, poll again.
    Idle,
    /// The failure belonged to one peer (reset/aborted before we accepted it,
    /// a signal, a network error Linux reports through `accept`): retry now.
    Retry,
    /// Resource exhaustion (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`) or an
    /// unknown error: back off, then retry. Connections finishing free the
    /// resources, so giving up here would turn a load spike into an outage.
    Backoff,
    /// The listener itself is unusable (`EBADF`, `ENOTSOCK`, `EINVAL`):
    /// retrying cannot help, stop and report it.
    Fatal,
}

/// Classify an `accept()` error.
///
/// The previous loop treated *every* error other than `WouldBlock` as the
/// end: a single `ECONNABORTED` (peer reset before accept) or `EMFILE` under
/// load silently stopped accepting forever while the process stayed alive.
#[must_use]
pub fn classify_accept_error(e: &std::io::Error) -> AcceptErrorAction {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::WouldBlock => return AcceptErrorAction::Idle,
        ErrorKind::Interrupted
        | ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionRefused
        | ErrorKind::TimedOut => return AcceptErrorAction::Retry,
        // EINVAL / WSAEINVAL: the socket is not listening any more.
        ErrorKind::InvalidInput => return AcceptErrorAction::Fatal,
        _ => {}
    }
    match e.raw_os_error() {
        Some(code) if os::is_fatal(code) => AcceptErrorAction::Fatal,
        Some(code) if os::is_per_peer(code) => AcceptErrorAction::Retry,
        _ => AcceptErrorAction::Backoff,
    }
}

#[cfg(unix)]
mod os {
    /// The listener descriptor itself is broken.
    pub(super) fn is_fatal(code: i32) -> bool {
        matches!(
            code,
            libc::EBADF | libc::ENOTSOCK | libc::EINVAL | libc::EFAULT
        )
    }

    /// Errors `accept(2)` reports on behalf of the *pending peer*. The Linux
    /// man page asks callers to treat these like `EAGAIN` and retry.
    pub(super) fn is_per_peer(code: i32) -> bool {
        is_enonet(code)
            || matches!(
                code,
                libc::ECONNABORTED
                    | libc::EPROTO
                    | libc::ENOPROTOOPT
                    | libc::EHOSTDOWN
                    | libc::EHOSTUNREACH
                    | libc::EOPNOTSUPP
                    | libc::ENETDOWN
                    | libc::ENETUNREACH
            )
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn is_enonet(code: i32) -> bool {
        code == libc::ENONET
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn is_enonet(_code: i32) -> bool {
        false
    }
}

#[cfg(windows)]
mod os {
    const WSAEBADF: i32 = 10009;
    const WSAEFAULT: i32 = 10014;
    const WSAEINVAL: i32 = 10022;
    const WSAENOTSOCK: i32 = 10038;
    const WSAENETDOWN: i32 = 10050;
    const WSAENETUNREACH: i32 = 10051;
    const WSAECONNABORTED: i32 = 10053;
    const WSAEHOSTUNREACH: i32 = 10065;

    /// The listener socket itself is broken.
    pub(super) fn is_fatal(code: i32) -> bool {
        matches!(code, WSAEBADF | WSAEFAULT | WSAEINVAL | WSAENOTSOCK)
    }

    /// Errors that belong to the pending peer, not to the listener.
    pub(super) fn is_per_peer(code: i32) -> bool {
        matches!(
            code,
            WSAECONNABORTED | WSAENETDOWN | WSAENETUNREACH | WSAEHOSTUNREACH
        )
    }
}

#[cfg(not(any(unix, windows)))]
mod os {
    pub(super) fn is_fatal(_code: i32) -> bool {
        false
    }

    pub(super) fn is_per_peer(_code: i32) -> bool {
        false
    }
}

/// Backoff for the `streak`-th consecutive accept failure: 10 ms doubling,
/// capped at [`ACCEPT_BACKOFF_MAX`].
#[must_use]
pub fn accept_backoff(streak: u32) -> Duration {
    let exp = streak.saturating_sub(1).min(7);
    Duration::from_millis(10u64 << exp).min(ACCEPT_BACKOFF_MAX)
}

/// Drive an accept loop until `stop` is set (`Ok`) or the listener fails
/// fatally (`Err`).
///
/// Generic over the accepted value and the sleeper so the policy is testable
/// without a kernel that misbehaves on cue. Per-peer errors retry at once
/// (backing off only after [`ACCEPT_RETRY_BURST`] in a row); resource errors
/// back off exponentially; see [`classify_accept_error`].
pub fn run_accept_loop<T>(
    stop: &AtomicBool,
    mut accept: impl FnMut() -> std::io::Result<T>,
    mut on_conn: impl FnMut(T),
    mut sleep: impl FnMut(Duration),
) -> std::io::Result<()> {
    let mut streak: u32 = 0;
    while !stop.load(Ordering::Relaxed) {
        match accept() {
            Ok(conn) => {
                streak = 0;
                on_conn(conn);
            }
            Err(e) => match classify_accept_error(&e) {
                AcceptErrorAction::Idle => {
                    streak = 0;
                    sleep(ACCEPT_IDLE_POLL);
                }
                AcceptErrorAction::Retry => {
                    streak = streak.saturating_add(1);
                    if streak > ACCEPT_RETRY_BURST {
                        sleep(accept_backoff(streak - ACCEPT_RETRY_BURST));
                    }
                }
                AcceptErrorAction::Backoff => {
                    streak = streak.saturating_add(1);
                    // One line per doubling: loud enough to notice, bounded
                    // enough not to flood the journal during a long EMFILE.
                    if streak.is_power_of_two() {
                        eprintln!(
                            "[aetherlink] accept: {e} (failure #{streak} in a row), backing off"
                        );
                    }
                    sleep(accept_backoff(streak));
                }
                AcceptErrorAction::Fatal => return Err(e),
            },
        }
    }
    Ok(())
}

/// Background accept loop; stops promptly on request.
pub struct ServerGuard {
    stop: Arc<AtomicBool>,
    /// Why the loop ended on its own (fatal listener error), if it did.
    failure: Arc<Mutex<Option<String>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ServerGuard {
    /// Ask the loop to stop (in-flight connections drain on their own).
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Is the accept loop still serving?
    ///
    /// False once it has ended — after `request_stop`, or on its own because
    /// the listener failed (see [`ServerGuard::failure`]). Hosts poll this so
    /// a dead listener ends the process (and systemd restarts it) instead of
    /// leaving a server that is "running" but accepts nothing.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Reason the loop stopped by itself, if it did.
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Wait for the loop thread (bounded: the longest sleep is
    /// [`ACCEPT_BACKOFF_MAX`]).
    pub fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
