//! Client tunnel lifecycle up/down (§5).
//!
//! `up` resolves the server once (system DNS, pre-tunnel), snapshots,
//! creates TUN, pins the server route via the previous gateway, installs
//! IP-family direct rules, switches default into TUN and forces DNS —
//! rolling everything back on the first error, leaving no traces.
//! `down` is a safe no-op when the tunnel is not up. One global mutex
//! serializes reconfiguration.

use std::net::{Ipv4Addr, TcpStream};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use rustls::client::danger::ServerCertVerifier;

use crate::config::ClientConfig;
use crate::platform::Platform;
use crate::routing::Matcher;
use crate::{ClientError, Result};
use aetherlink_core::{session, tls};

/// Client TUN address inside `10.255.0.0/30` (DECISIONS D2).
pub const CLIENT_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 2);

/// Virtual DNS gateway forced while up (DNS_NO_LEAK).
pub const VIRTUAL_DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 1);

/// Reconfiguration mutex: up/down never interleave.
static RECONFIGURE: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Bring the tunnel up against `platform`. Idempotent only via `Client`;
/// calling `up` twice without `down` re-applies (platforms dedupe).
pub fn up(platform: &mut dyn Platform, config: &ClientConfig) -> Result<()> {
    let _guard = RECONFIGURE.lock().expect("reconfigure mutex");
    let (host, _port) = config
        .server_addr
        .rsplit_once(':')
        .ok_or_else(|| ClientError::ConfigError("server_addr must be host:port".to_string()))?;
    // 1. Resolve once, pre-tunnel (a single system-DNS use is allowed here).
    let ips = platform.resolve_host(host)?;
    let server_ip = ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| ips.first())
        .copied()
        .ok_or_else(|| ClientError::PlatformError("no server address".to_string()))?;
    // 2. Snapshot before touching anything.
    let snap = platform.snapshot()?;
    let state_path = platform.state_path();
    let failed = |platform: &mut dyn Platform| {
        let _ = platform.restore(&snap);
        let _ = std::fs::remove_file(&state_path);
    };
    // 3. TUN device.
    if let Err(e) = platform.tun_up("aether0", CLIENT_TUN_IP, config.mtu) {
        failed(platform);
        return Err(e);
    }
    // 4. Persist the snapshot: crash recovery starts being possible here.
    if let Err(e) = snap.save(&state_path) {
        failed(platform);
        return Err(ClientError::from(e));
    }
    // 5. Pin the server IP via the previous default gateway.
    if let Some(gateway) = previous_gateway(&snap) {
        if let Err(e) = platform.pin_route(server_ip, gateway) {
            failed(platform);
            return Err(e);
        }
    }
    // 6. IP-family direct rules (domain/suffix enforced at dial time).
    for rule in config.rules.rules() {
        let dest = match &rule.matcher {
            Matcher::Ip(ip) => ip.to_string(),
            Matcher::Cidr(base, prefix) => format!("{base}/{prefix}"),
            Matcher::IpRange(lo, hi) => format!("{lo}-{hi}"),
            Matcher::Domain(_) | Matcher::Suffix(_) => continue,
        };
        if let Some(gateway) = previous_gateway(&snap) {
            if let Err(e) = platform.add_route(&dest, gateway) {
                failed(platform);
                return Err(e);
            }
        }
    }
    // 7. Default into the tunnel.
    if let Err(e) = platform.default_via_tun() {
        failed(platform);
        return Err(e);
    }
    // 8. DNS into the tunnel.
    if let Err(e) = platform.force_dns(VIRTUAL_DNS_IP) {
        failed(platform);
        return Err(e);
    }
    Ok(())
}

/// Previous default gateway from a snapshot, if one was captured.
fn previous_gateway(snap: &aetherlink_netstack::tun::Snapshot) -> Option<Ipv4Addr> {
    snap.routes
        .iter()
        .find(|r| r.dest == "default")
        .and_then(|r| r.via.parse().ok())
}

/// Down: restore the snapshot, consume the state file, destroy TUN.
///
/// Safe no-op when not up; every step is best-effort so teardown never
/// fails its caller (idempotent by contract).
pub fn down(platform: &mut dyn Platform) -> Result<()> {
    let _guard = RECONFIGURE.lock().expect("reconfigure mutex");
    let path = platform.state_path();
    if let Ok(snap) = aetherlink_netstack::tun::Snapshot::load(&path) {
        let _ = platform.restore(&snap);
        let _ = std::fs::remove_file(&path);
    }
    let _ = platform.tun_down();
    Ok(())
}

/// Live transport: connected TLS stream plus established session.
pub struct ConnectedTunnel {
    /// TLS stream (caller pumps mux frames through it).
    pub stream: tls::ClientTlsStream,
    /// Session: fresh mux plus traffic keys (`tx` = client→server).
    pub sess: session::ClientSession,
}

/// Connect transport: TCP + TLS (SNI from config) + AUTH handshake.
///
/// Resolution happens once here, over system DNS, pre-tunnel. Pass `None`
/// for the production system-roots verifier, `Some(..)` for tests.
pub fn connect(
    config: &ClientConfig,
    verifier: Option<Arc<dyn ServerCertVerifier>>,
) -> Result<ConnectedTunnel> {
    let (host, port) = config
        .server_addr
        .rsplit_once(':')
        .ok_or_else(|| ClientError::ConfigError("server_addr must be host:port".to_string()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| ClientError::ConfigError("server_addr port invalid".to_string()))?;
    let sock = TcpStream::connect((host, port))
        .map_err(|e| ClientError::PlatformError(format!("tcp connect: {e}")))?;
    let name = tls::server_name(&config.outer_sni).map_err(ClientError::Core)?;
    let tls_cfg = Arc::new(match verifier {
        Some(verifier) => tls::client_config(verifier).map_err(ClientError::Core)?,
        None => tls::system_client_config().map_err(ClientError::Core)?,
    });
    let mut stream = tls::connect_tls(sock, name, &tls_cfg).map_err(ClientError::Core)?;
    let nonce = aetherlink_crypto::auth::generate_nonce();
    let sess = session::handshake_client(&mut stream, config.psk.as_bytes(), &nonce)
        .map_err(ClientError::Core)?;
    Ok(ConnectedTunnel { stream, sess })
}
