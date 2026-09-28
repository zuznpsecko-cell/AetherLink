//! Server accept-loop: TLS accept → AUTH gate → tunnel / static / closed.
//!
//! * TLS handshake fails (plaintext probe) → [`Path::Closed`], nothing served;
//! * AUTH fails → [`Path::Static`]: minimal static HTTP over the same TLS
//!   connection, with no tunnel/proxy/vpn banner (G2);
//! * AUTH ok → [`Path::Tunnel`]: OPEN frames register ids and teach the
//!   loop their dial targets; DATA and datagrams then flow through them.
//!
//! Scope note: each DATA/DATAGRAM frame is one request→one reply exchange
//! (fits DNS and proxied request/response). Bidirectional streaming relay
//! is a follow-up.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aetherlink_core::{session, tls};
use aetherlink_crypto::auth::NonceCache;
use aetherlink_frame::codec::FrameHeader;
use aetherlink_frame::FRAME_HEADER_SIZE;
use aetherlink_mux::manager::MuxManager;
use aetherlink_protocol::{FrameType, VIRTUAL_DNS_IP, VIRTUAL_DNS_PORT};
use bytes::BytesMut;

use crate::{
    debug::debug_log,
    dns,
    pool::{Completion, RelayPool},
    relay,
};

/// How one accepted connection was served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Authenticated: mux inside TLS.
    Tunnel,
    /// Bad/missing auth: static web fallback (G2).
    Static,
    /// Not TLS at all: closed silently.
    Closed,
}

/// Per-listener server context (shared across connections).
pub struct ServerCtx {
    /// TLS1.3-only config with ALPN.
    pub tls: Arc<rustls::ServerConfig>,
    /// Pre-shared key for AUTH.
    pub psk: Vec<u8>,
    /// Nonce replay cache (TTL enforced inside).
    pub cache: NonceCache,
    /// Static response body (must carry no tunnel banner).
    pub static_body: Vec<u8>,
    /// DNS upstreams `"ip:port"` (primary first) for the virtual
    /// resolver intercept; tried in order per datagram.
    pub dns_upstream: Vec<String>,
}

/// Relay read timeout: a silent target burns one worker for this long;
/// the loop itself never stalls (concurrent pool + dead-target cooldown).
const RELAY_TIMEOUT: Duration = Duration::from_secs(5);

/// UDP relay timeout: DNS answers in well under this; multicast/NetBIOS
/// noise must fail fast instead of burning a worker per datagram.
const UDP_RELAY_TIMEOUT: Duration = Duration::from_secs(2);

/// Wire-read timeout: the loop must keep draining pool completions even
/// when the peer sends nothing (a blocking read would wedge replies
/// behind an idle connection).
const READ_TIMEOUT: Duration = Duration::from_millis(200);

/// Pool workers: blocking dials/relays run here so one slow target never
/// serially stalls the loop (seen live: 11s backlog, client gone by reply).
/// At cap the loop sheds (fail fast, app retransmits) instead of queueing.
const POOL_WORKERS: usize = 32;

/// Completed relay work, back on the loop thread. Seal + write stay here:
/// single writer, the mux never leaves this thread, and reply order per
/// stream does not matter (the peer's replay window tolerates reorder).
enum RelayOut {
    /// TCP reply plus the socket to return to the cache.
    Tcp {
        reply: Vec<u8>,
        sock: Option<TcpStream>,
    },
    /// Dial-warm (empty DATA): socket to cache, nothing to seal.
    Warmed(Option<TcpStream>),
    /// UDP reply bytes.
    Udp(Vec<u8>),
}

/// Pool key: carried through for logging, cooldown and cache decisions.
struct FlowKey {
    id: u16,
    target: (String, u16),
    is_udp: bool,
    warm: bool,
}

/// Unanswerable destinations: multicast, broadcast, unspecified.
/// Relaying them only burns a full timeout per datagram (LLMNR/mDNS/SSDP
/// chatter does exactly that, constantly) — skip without a relay attempt.
/// Reuse a cached relay socket only when no job for this stream is in
/// flight (two workers must never share one socket); otherwise the worker
/// dials fresh and its socket is dropped on return.
fn take_idle_socket(
    relays: &mut HashMap<u16, TcpStream>,
    in_flight: &HashMap<u16, usize>,
    id: u16,
) -> Option<TcpStream> {
    if in_flight.get(&id).copied().unwrap_or(0) == 0 {
        relays.remove(&id)
    } else {
        None
    }
}

/// Reused socket or fresh dial (with read timeout); Err drops the attempt.
fn prep_socket(sock: Option<TcpStream>, ip: &str, port: u16) -> Result<TcpStream, ()> {
    match sock {
        Some(s) => Ok(s),
        None => {
            let s = relay::dial_tcp(ip, port).map_err(|_| ())?;
            s.set_read_timeout(Some(RELAY_TIMEOUT)).map_err(|_| ())?;
            Ok(s)
        }
    }
}

/// Release one in-flight slot for a stream.
fn release_slot(in_flight: &mut HashMap<u16, usize>, id: u16) {
    match in_flight.get_mut(&id) {
        Some(n) => {
            *n = n.saturating_sub(1);
            if *n == 0 {
                in_flight.remove(&id);
            }
        }
        None => {}
    }
}

/// Seal + write one completion; false ends the session (write failed).
#[allow(clippy::too_many_arguments)]
fn handle_completion(
    c: Completion<FlowKey, Result<RelayOut, ()>>,
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    relays: &mut HashMap<u16, TcpStream>,
    in_flight: &mut HashMap<u16, usize>,
    dead: &mut HashMap<(String, u16), Instant>,
) -> bool {
    let FlowKey {
        id,
        target,
        is_udp,
        warm,
    } = c.key;
    release_slot(in_flight, id);
    match c.result {
        Ok(RelayOut::Tcp { reply, sock }) => {
            debug_log(&format!("tunnel: data id={id} relay {}B", reply.len()));
            dead.remove(&target);
            if let Some(s) = sock {
                if !in_flight.contains_key(&id) {
                    relays.insert(id, s);
                }
            }
            match send_data(sess, stream, id, &reply) {
                Ok(()) => true,
                Err(e) => {
                    debug_log(&format!(
                        "tunnel: data id={id} reply write failed ({e}), closing"
                    ));
                    false
                }
            }
        }
        Ok(RelayOut::Warmed(sock)) => {
            if let Some(s) = sock {
                if !in_flight.contains_key(&id) {
                    relays.insert(id, s);
                }
            }
            true
        }
        Ok(RelayOut::Udp(reply)) => {
            debug_log(&format!("tunnel: datagram id={id} relay {}B", reply.len()));
            let sealed = match sess.mux.seal_datagram(sess.keys.tx_key(), id, &reply, 128) {
                Ok(sealed) => sealed,
                Err(e) => {
                    debug_log(&format!(
                        "tunnel: datagram id={id} seal failed: {e}, skipping flow"
                    ));
                    return true;
                }
            };
            if write_sealed(stream, &sealed.header, &sealed.ciphertext).is_err() {
                debug_log(&format!(
                    "tunnel: datagram id={id} reply write failed, closing"
                ));
                return false;
            }
            true
        }
        Err(()) => {
            if warm {
                debug_log(&format!(
                    "tunnel: data id={id} warm dial failed, skipping flow"
                ));
            } else if is_udp {
                debug_log(&format!(
                    "tunnel: datagram id={id} relay to {}:{} failed, skipping flow",
                    target.0, target.1
                ));
            } else {
                debug_log(&format!(
                    "tunnel: data id={id} relay failed, cooling down {}:{}",
                    target.0, target.1
                ));
                relay::mark_dead(dead, &target.0, target.1, Instant::now());
            }
            true
        }
    }
}

/// Seal + write every arrived completion; false ends the session.
#[allow(clippy::too_many_arguments)]
fn drain_completions(
    pool: &RelayPool<FlowKey, Result<RelayOut, ()>>,
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    relays: &mut HashMap<u16, TcpStream>,
    in_flight: &mut HashMap<u16, usize>,
    dead: &mut HashMap<(String, u16), Instant>,
) -> bool {
    while let Some(c) = pool.try_recv() {
        if !handle_completion(c, sess, stream, relays, in_flight, dead) {
            return false;
        }
    }
    true
}

fn is_unroutable_target(target: &SocketAddr) -> bool {
    match target.ip() {
        std::net::IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified(),
        std::net::IpAddr::V6(_) => false,
    }
}

/// Serve one static HTTP response over an open TLS stream.
fn serve_static(stream: &mut tls::ServerTlsStream, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    close_quietly(stream);
}

/// TLS close_notify + flush, ignoring errors (peer may be gone).
fn close_quietly(stream: &mut tls::ServerTlsStream) {
    let _ = stream.conn.send_close_notify();
    let _ = stream.flush();
}

/// Serve one accepted TCP connection to a path decision.
///
/// `routes` starts empty on a live listener and is filled from the peer's
/// OPEN frames; tests may pre-register entries instead.
pub fn serve_connection(
    sock: TcpStream,
    ctx: &ServerCtx,
    routes: &mut HashMap<u16, SocketAddr>,
) -> Path {
    let mut stream = match tls::accept_tls(sock, &ctx.tls) {
        Ok(s) => {
            debug_log("accept: tls ok");
            s
        }
        Err(e) => {
            debug_log(&format!("accept: tls failed: {e}"));
            return Path::Closed;
        }
    };
    let sess = match session::handshake_server(&mut stream, &ctx.psk, &ctx.cache) {
        Ok(s) => {
            debug_log("accept: auth ok, tunnel");
            s
        }
        Err(e) => {
            debug_log(&format!("accept: auth failed ({e}), static fallback"));
            serve_static(&mut stream, &ctx.static_body);
            return Path::Static;
        }
    };
    tunnel_loop(&mut stream, sess, &ctx, routes);
    close_quietly(&mut stream);
    Path::Tunnel
}

/// Pump mux frames until EOF, protocol error, or GOAWAY/RST.
///
/// OPEN frames register the id and learn the dial target (server resolves
/// domain targets via its own DNS, like any proxy); DATA and datagrams
/// then flow through the learned routes.
///
/// Per-flow isolation: transport errors (EOF, undecodable header, absurd
/// length, reply write failure) and unauthenticable OPEN frames end the
/// loop; per-flow NETWORK failures (dial refused, relay timeout, replay on
/// one stream) only skip that flow. One dead target — multicast noise, a
/// closed port — must never kill healthy streams (seen live: a single
/// LLMNR flow took down the whole tunnel).
fn tunnel_loop(
    stream: &mut tls::ServerTlsStream,
    mut sess: session::ServerSession,
    ctx: &ServerCtx,
    routes: &mut HashMap<u16, SocketAddr>,
) {
    let mut relays: HashMap<u16, TcpStream> = HashMap::new();
    // Targets whose dial recently failed: fail fast for the cooldown
    // instead of burning a worker behind another dial timeout.
    let mut dead: HashMap<(String, u16), Instant> = HashMap::new();
    // Stream ids with relay jobs in flight (socket reuse only when idle).
    let mut in_flight: HashMap<u16, usize> = HashMap::new();
    let pool: RelayPool<FlowKey, Result<RelayOut, ()>> = RelayPool::new(POOL_WORKERS);
    // Best-effort: without a timeout an idle peer wedges completion
    // draining; failure keeps the old blocking behaviour.
    let _ = stream.get_mut().set_read_timeout(Some(READ_TIMEOUT));
    loop {
        let mut hb = [0u8; FRAME_HEADER_SIZE];
        match stream.read_exact(&mut hb) {
            Ok(()) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                if !drain_completions(
                    &pool,
                    &mut sess,
                    stream,
                    &mut relays,
                    &mut in_flight,
                    &mut dead,
                ) {
                    break;
                }
                continue;
            }
            Err(_) => {
                debug_log("tunnel: header eof, closing");
                break; // EOF or transport error: fail closed.
            }
        }
        let mut hbuf = BytesMut::from(&hb[..]);
        let header = match FrameHeader::decode(&mut hbuf) {
            Ok(h) => h,
            Err(_) => break,
        };
        if header.length as usize > 65535 + 1024 {
            break; // Absurd length: fail closed.
        }
        let mut ct = vec![0u8; header.length as usize];
        if stream.read_exact(&mut ct).is_err() {
            debug_log("tunnel: body eof, closing");
            break;
        }
        debug_log(&format!(
            "tunnel: {:?} id={} seq={} len={}",
            header.frame_type, header.stream_id, header.sequence, header.length
        ));
        match header.frame_type {
            FrameType::Data => {
                let Some(target) = routes.get(&header.stream_id) else {
                    debug_log(&format!(
                        "tunnel: data id={} without route",
                        header.stream_id
                    ));
                    break; // No route for this stream: fail closed.
                };
                if sess
                    .mux
                    .register_inbound(
                        header.stream_id,
                        &target.ip().to_string(),
                        target.port(),
                        false,
                    )
                    .is_err()
                {
                    debug_log(&format!(
                        "tunnel: data id={} register failed, skipping flow",
                        header.stream_id
                    ));
                    continue;
                }
                let pt = match sess.mux.open_data(sess.keys.rx_key(), &header, &ct) {
                    Ok(pt) => {
                        debug_log(&format!(
                            "tunnel: data id={} open {}B",
                            header.stream_id,
                            pt.len()
                        ));
                        pt
                    }
                    Err(e) => {
                        debug_log(&format!(
                            "tunnel: data id={} open failed: {e}, skipping flow",
                            header.stream_id
                        ));
                        continue;
                    }
                };
                // Bare SYN/ACK (empty DATA): warm the cached socket on a
                // worker; the reply that cannot exist yet needs no read.
                if pt.is_empty() {
                    let sock = take_idle_socket(&mut relays, &in_flight, header.stream_id);
                    let warm_ip = target.ip().to_string();
                    let warm_port = target.port();
                    let key = FlowKey {
                        id: header.stream_id,
                        target: (warm_ip.clone(), warm_port),
                        is_udp: false,
                        warm: true,
                    };
                    if pool.dispatch(key, move || match prep_socket(sock, &warm_ip, warm_port) {
                        Ok(s) => Ok(RelayOut::Warmed(Some(s))),
                        Err(()) => Err(()),
                    }) {
                        *in_flight.entry(header.stream_id).or_insert(0) += 1;
                    } else {
                        debug_log(&format!(
                            "tunnel: data id={} server busy, skipping flow",
                            header.stream_id
                        ));
                    }
                    if !drain_completions(
                        &pool,
                        &mut sess,
                        stream,
                        &mut relays,
                        &mut in_flight,
                        &mut dead,
                    ) {
                        break;
                    }
                    continue;
                }
                let target_key = (target.ip().to_string(), target.port());
                if relay::is_fresh_dead(&dead, &target_key.0, target_key.1, Instant::now()) {
                    debug_log(&format!(
                        "tunnel: data id={} target {target} in dead cooldown, skipping flow",
                        header.stream_id
                    ));
                    continue;
                }
                // Payload: relay on a worker; seal + write on completion.
                let sock = take_idle_socket(&mut relays, &in_flight, header.stream_id);
                let job_ip = target.ip().to_string();
                let job_port = target.port();
                let key = FlowKey {
                    id: header.stream_id,
                    target: target_key,
                    is_udp: false,
                    warm: false,
                };
                if pool.dispatch(key, move || {
                    let mut sock = match prep_socket(sock, &job_ip, job_port) {
                        Ok(s) => s,
                        Err(()) => return Err(()),
                    };
                    if sock.write_all(&pt).is_err() {
                        return Err(());
                    }
                    let mut buf = vec![0u8; 65535];
                    match sock.read(&mut buf) {
                        Ok(n) => {
                            buf.truncate(n);
                            Ok(RelayOut::Tcp {
                                reply: buf,
                                sock: Some(sock),
                            })
                        }
                        Err(_) => Err(()),
                    }
                }) {
                    *in_flight.entry(header.stream_id).or_insert(0) += 1;
                } else {
                    debug_log(&format!(
                        "tunnel: data id={} server busy, skipping flow",
                        header.stream_id
                    ));
                }
                if !drain_completions(
                    &pool,
                    &mut sess,
                    stream,
                    &mut relays,
                    &mut in_flight,
                    &mut dead,
                ) {
                    break;
                }
            }
            FrameType::UdpDatagram => {
                let Some(target) = routes.get(&header.stream_id) else {
                    debug_log(&format!(
                        "tunnel: datagram id={} without route",
                        header.stream_id
                    ));
                    break;
                };
                if sess
                    .mux
                    .register_inbound(
                        header.stream_id,
                        &target.ip().to_string(),
                        target.port(),
                        true,
                    )
                    .is_err()
                {
                    debug_log(&format!(
                        "tunnel: datagram id={} register failed, skipping flow",
                        header.stream_id
                    ));
                    continue;
                }
                let pt = match sess.mux.open_datagram(sess.keys.rx_key(), &header, &ct) {
                    Ok(pt) => {
                        debug_log(&format!(
                            "tunnel: datagram id={} open {}B to {target}",
                            header.stream_id,
                            pt.len()
                        ));
                        pt
                    }
                    Err(e) => {
                        debug_log(&format!(
                            "tunnel: datagram id={} open failed: {e}, skipping flow",
                            header.stream_id
                        ));
                        continue;
                    }
                };
                if is_unroutable_target(target) {
                    debug_log(&format!(
                        "tunnel: datagram id={} to {target} unroutable, skipping relay",
                        header.stream_id
                    ));
                    continue;
                }
                // Virtual-DNS flows resolve across the whole upstream
                // list (one silent upstream must not kill DNS); ordinary
                // flows relay to their learned target exactly once.
                let is_virtual = ctx.dns_upstream.iter().any(|u| {
                    u.rsplit_once(':').is_some_and(|(host, port)| {
                        host == target.ip().to_string()
                            && port.parse::<u16>().ok() == Some(target.port())
                    })
                });
                let key = FlowKey {
                    id: header.stream_id,
                    target: (target.ip().to_string(), target.port()),
                    is_udp: true,
                    warm: false,
                };
                let job_ip = target.ip().to_string();
                let job_port = target.port();
                let upstreams = ctx.dns_upstream.clone();
                if pool.dispatch(key, move || {
                    let out = if is_virtual {
                        dns::resolve_any(&pt, &upstreams, UDP_RELAY_TIMEOUT)
                    } else {
                        relay::relay_udp(&job_ip, job_port, &pt, UDP_RELAY_TIMEOUT)
                    };
                    out.map(RelayOut::Udp).map_err(|_| ())
                }) {
                    *in_flight.entry(header.stream_id).or_insert(0) += 1;
                } else {
                    debug_log(&format!(
                        "tunnel: datagram id={} server busy, skipping flow",
                        header.stream_id
                    ));
                }
                if !drain_completions(
                    &pool,
                    &mut sess,
                    stream,
                    &mut relays,
                    &mut in_flight,
                    &mut dead,
                ) {
                    break;
                }
            }
            FrameType::Ping => {
                debug_log("tunnel: ping");
                continue;
            }
            FrameType::GoAway | FrameType::Rst => {
                debug_log("tunnel: goaway/rst, closing");
                break;
            }
            FrameType::OpenTcp => {
                let target = match MuxManager::parse_open_tcp(sess.keys.rx_key(), &header, &ct) {
                    Ok(target) => target,
                    Err(e) => {
                        debug_log(&format!("tunnel: open_tcp parse failed: {e}"));
                        break;
                    }
                };
                debug_log(&format!(
                    "tunnel: open_tcp id={} -> {}:{}",
                    target.id, target.addr, target.port
                ));
                let sock = match dial_addr(&target.addr, target.port) {
                    Some(sock) => sock,
                    None => {
                        debug_log(&format!(
                            "tunnel: open_tcp id={} dial failed, skipping flow",
                            header.stream_id
                        ));
                        continue;
                    }
                };
                if sess
                    .mux
                    .register_inbound(header.stream_id, &target.addr, target.port, false)
                    .is_err()
                {
                    debug_log(&format!(
                        "tunnel: open_tcp id={} register failed, skipping flow",
                        header.stream_id
                    ));
                    continue;
                }
                routes.insert(header.stream_id, sock);
            }
            FrameType::OpenUdp => {
                let flow = match MuxManager::parse_open_udp(sess.keys.rx_key(), &header, &ct) {
                    Ok(flow) => flow,
                    Err(e) => {
                        debug_log(&format!("tunnel: open_udp parse failed: {e}"));
                        break;
                    }
                };
                // Virtual-resolver intercept: the client only knows
                // 10.255.0.1:53; the server terminates it at its upstream
                // (dialing .1 would time out and kill the loop instead).
                let (addr, port) = if flow.addr == VIRTUAL_DNS_IP && flow.port == VIRTUAL_DNS_PORT {
                    let primary = ctx.dns_upstream.first().cloned().unwrap_or_default();
                    debug_log(&format!(
                        "tunnel: open_udp id={} virtual dns -> upstream {}",
                        flow.id, primary
                    ));
                    match primary.rsplit_once(':') {
                        Some((host, port)) => match port.parse::<u16>() {
                            Ok(port) => (host.to_string(), port),
                            Err(_) => break,
                        },
                        None => break,
                    }
                } else {
                    debug_log(&format!(
                        "tunnel: open_udp id={} -> {}:{}",
                        flow.id, flow.addr, flow.port
                    ));
                    (flow.addr.clone(), flow.port)
                };
                let sock = match dial_addr(&addr, port) {
                    Some(sock) => sock,
                    None => {
                        debug_log(&format!(
                            "tunnel: open_udp id={} dial {addr}:{port} failed, skipping flow",
                            header.stream_id
                        ));
                        continue;
                    }
                };
                if sess
                    .mux
                    .register_inbound(header.stream_id, &addr, port, true)
                    .is_err()
                {
                    debug_log(&format!(
                        "tunnel: open_udp id={} register failed, skipping flow",
                        header.stream_id
                    ));
                    continue;
                }
                routes.insert(header.stream_id, sock);
            }
            _ => {
                debug_log("tunnel: unsupported frame type, closing");
                break; // WINDOW/AUTH post-handshake: unsupported yet.
            }
        }
    }
}

/// Resolve a dial target announced by the peer (server-side system DNS).
fn dial_addr(addr: &str, port: u16) -> Option<SocketAddr> {
    format!("{addr}:{port}").to_socket_addrs().ok()?.next()
}

/// Seal + write one DATA reply; Err carries seal or transport failure.
fn send_data(
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    id: u16,
    payload: &[u8],
) -> Result<(), String> {
    let sealed = sess
        .mux
        .seal_data(sess.keys.tx_key(), id, payload, 128)
        .map_err(|e| format!("seal: {e}"))?;
    write_sealed(stream, &sealed.header, &sealed.ciphertext)
        .map_err(|e| format!("transport: {e}"))?;
    Ok(())
}

/// Write one sealed frame; Err on transport failure.
fn write_sealed(
    stream: &mut tls::ServerTlsStream,
    header: &FrameHeader,
    ct: &[u8],
) -> std::io::Result<()> {
    let mut buf = BytesMut::new();
    header.encode(&mut buf);
    stream.write_all(&buf)?;
    stream.write_all(ct)?;
    stream.flush()
}
