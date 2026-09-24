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
use aetherlink_netstack::tun::{previous_gateway, AppliedChange, UpState};

/// Client TUN address inside `10.255.0.0/30` (DECISIONS D2).
pub const CLIENT_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 2);

/// Virtual DNS gateway forced while up (DNS_NO_LEAK).
pub const VIRTUAL_DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 1);

/// Reconfiguration mutex: up/down never interleave.
static RECONFIGURE: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Bring the tunnel up against `platform`. Idempotent only via `Client`;
/// calling `up` twice without `down` re-applies (platforms dedupe).
///
/// Refuses when a state file already exists (a previous `up` is live or died
/// without cleanup): run `down`/`force_cleanup` first, never stack tunnels.
pub fn up(platform: &mut dyn Platform, config: &ClientConfig) -> Result<()> {
    let _guard = RECONFIGURE.lock().expect("reconfigure mutex");
    let (host, _port) = config
        .server_addr
        .rsplit_once(':')
        .ok_or_else(|| ClientError::ConfigError("server_addr must be host:port".to_string()))?;
    let state_path = platform.state_path();
    if state_path.exists() {
        return Err(ClientError::PlatformError(
            "tunnel already up or stale state file: run down/cleanup first".to_string(),
        ));
    }
    // 1. Resolve once, pre-tunnel (a single system-DNS use is allowed here).
    let ips = platform.resolve_host(host)?;
    let server_ip = ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| ips.first())
        .copied()
        .ok_or_else(|| ClientError::PlatformError("no server address".to_string()))?;
    aetherlink_netstack::debug_log(&format!("up: server {host} -> {server_ip}"));
    // 2. Snapshot before touching anything.
    let snap = platform.snapshot()?;
    // Stale tunnel DNS means a previous teardown never finished: refuse to
    // stack on it (snapshot would canonize the tunnel address as "previous").
    if snap
        .dns_servers
        .iter()
        .any(|s| s == &VIRTUAL_DNS_IP.to_string())
    {
        return Err(ClientError::PlatformError(
            "stale tunnel DNS in snapshot: run down/cleanup first".to_string(),
        ));
    }
    aetherlink_netstack::debug_log("up: snapshot ok");
    // Applied-change log, persisted after every mutation so a crash mid-up
    // still leaves a replayable state file (DNS target = up-time iface,
    // ifIndex = up-time adapter for egress-bound deletes).
    let mut applied: Vec<AppliedChange> = Vec::new();
    let dns_iface = platform.captured_iface().unwrap_or_default();
    let mut tun_ifindex: Option<u32> = None;
    let persist = |applied: &[AppliedChange], tun_ifindex: Option<u32>| -> Result<()> {
        UpState {
            snapshot: snap.clone(),
            applied: applied.to_vec(),
            dns_iface: dns_iface.clone(),
            tun_ifindex,
        }
        .save(&state_path)
        .map_err(ClientError::from)
    };
    let failed = |platform: &mut dyn Platform, applied: &[AppliedChange]| {
        let state = UpState {
            snapshot: snap.clone(),
            applied: applied.to_vec(),
            dns_iface: platform.captured_iface().unwrap_or_default(),
            tun_ifindex: platform.tun_ifindex(),
        };
        let _ = platform.restore_applied(&state);
        let _ = std::fs::remove_file(&state_path);
    };
    // 3. TUN device.
    if let Err(e) = platform.tun_up("aether0", CLIENT_TUN_IP, config.mtu) {
        failed(platform, &applied);
        return Err(e);
    }
    applied.push(AppliedChange::TunUp("aether0".to_string()));
    tun_ifindex = platform.tun_ifindex();
    if let Err(e) = persist(&applied, tun_ifindex) {
        failed(platform, &applied);
        return Err(e);
    }
    aetherlink_netstack::debug_log("up: tun ok");
    // 5. Pin the server IP via the previous default gateway.
    if let Some(gateway) = previous_gateway(&snap) {
        if let Err(e) = platform.pin_route(server_ip, gateway) {
            failed(platform, &applied);
            return Err(e);
        }
        applied.push(AppliedChange::PinnedRoute(server_ip.to_string()));
        if let Err(e) = persist(&applied, tun_ifindex) {
            failed(platform, &applied);
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
                failed(platform, &applied);
                return Err(e);
            }
            applied.push(AppliedChange::DirectRoute(dest));
            if let Err(e) = persist(&applied, tun_ifindex) {
                failed(platform, &applied);
                return Err(e);
            }
        }
    }
    // 7. Default into the tunnel.
    if let Err(e) = platform.default_via_tun() {
        failed(platform, &applied);
        return Err(e);
    }
    applied.push(AppliedChange::DefaultViaTun);
    if let Err(e) = persist(&applied, tun_ifindex) {
        failed(platform, &applied);
        return Err(e);
    }
    aetherlink_netstack::debug_log("up: default-via-tun ok");
    // 8. DNS into the tunnel.
    if let Err(e) = platform.force_dns(VIRTUAL_DNS_IP) {
        failed(platform, &applied);
        return Err(e);
    }
    applied.push(AppliedChange::DnsOverride(snap.dns_servers.clone()));
    if let Err(e) = persist(&applied, tun_ifindex) {
        failed(platform, &applied);
        return Err(e);
    }
    aetherlink_netstack::debug_log("up: dns ok");
    Ok(())
}

/// Down: replay the applied-change log, consume the state file, destroy TUN.
///
/// Safe no-op when not up; every step is best-effort so teardown never
/// fails its caller (idempotent by contract). Replay outcomes are traced
/// (never silent) under `AETHERLINK_DEBUG`.
pub fn down(platform: &mut dyn Platform) -> Result<()> {
    let _guard = RECONFIGURE.lock().expect("reconfigure mutex");
    let path = platform.state_path();
    match UpState::load(&path) {
        Ok(state) => {
            match platform.restore_applied(&state) {
                Ok(()) => aetherlink_netstack::debug_log("down: replay ok"),
                Err(e) => aetherlink_netstack::debug_log(&format!("down: replay issues: {e}")),
            }
            let _ = std::fs::remove_file(&path);
        }
        Err(e) => {
            aetherlink_netstack::debug_log(&format!("down: no state ({e}), tun teardown only"));
        }
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
    aetherlink_netstack::debug_log(&format!("connect: tcp {host}:{port} ok"));
    let name = tls::server_name(&config.outer_sni).map_err(ClientError::Core)?;
    let tls_cfg = Arc::new(match verifier {
        Some(verifier) => tls::client_config(verifier).map_err(ClientError::Core)?,
        None => tls::system_client_config().map_err(ClientError::Core)?,
    });
    let mut stream = tls::connect_tls(sock, name, &tls_cfg).map_err(ClientError::Core)?;
    aetherlink_netstack::debug_log("connect: tls ok");
    let nonce = aetherlink_crypto::auth::generate_nonce();
    let sess = session::handshake_client(&mut stream, config.psk.as_bytes(), &nonce)
        .map_err(ClientError::Core)?;
    aetherlink_netstack::debug_log("connect: auth ok");
    Ok(ConnectedTunnel { stream, sess })
}

/// Attach the pump: connect the transport, then bridge TUN<->TLS session.
///
/// Single call for tests and `Client::up_full`: `tun` is shared with the
/// caller (usually the platform's held handle). Fails closed before any
/// byte moves when the handshake or spawn fails.
pub fn attach_pump<T>(
    tun: Arc<Mutex<T>>,
    config: &ClientConfig,
    verifier: Option<Arc<dyn ServerCertVerifier>>,
) -> Result<crate::threads::PumpHandle>
where
    T: aetherlink_netstack::tun::TunPackets + Send + 'static,
{
    let tunnel = connect(config, verifier)?;
    let pad = config.pad_multiple;
    crate::threads::spawn_pump_tls(tun, tunnel, pad)
        .map_err(|e| ClientError::PlatformError(format!("pump spawn: {e}")))
}
