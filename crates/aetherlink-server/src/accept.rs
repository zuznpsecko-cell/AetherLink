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
use std::sync::{mpsc, Arc};
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
const UDP_RELAY_TIMEOUT: Duration = Duration::from_secs(2);

/// Wire-read quantum: the loop must keep draining completions even when
/// the peer sends nothing (a blocking read would wedge replies behind an
/// idle connection).
const READ_TIMEOUT: Duration = Duration::from_millis(50);

/// Bound for one frame body across stalls (fail closed eventually).
const BODY_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Pool workers: blocking dials/relays run here so one slow target never
/// serially stalls the loop (seen live: 11s backlog, client gone by reply).
/// At cap the loop sheds (fail fast, app retransmits) instead of queueing.
const POOL_WORKERS: usize = 32;

/// Queue depth past the workers: legit bursts (120+ flows in one go,
/// seen in tests and on noisy machines) must not shed — shed TCP DATA
/// stalls that stream past client dedup, so shed stays flood-only.
const POOL_QUEUE: usize = 256;

/// Idle drain after the first reply chunk: multi-chunk flights (TLS
/// handshakes) arrive with small gaps; shorter stalls interactive
/// traffic, longer delays every exchange by the tail.
/// /// Completed relay work, back on the loop thread. Seal + write stay here:
/// single writer, the mux never leaves this thread, and reply order per
/// stream does not matter (the peer's replay window tolerates reorder).
enum RelayOut {
    /// UDP reply bytes (datagrams fit request/response; TCP streams have
    /// dedicated workers below).
    Udp(Vec<u8>),
}

/// Pool key: carried through for logging and cooldown decisions.
struct FlowKey {
    id: u16,
    target: (String, u16),
}

/// Cap live stream workers: every TCP stream gets a thread+dial; past this
/// the loop sheds new streams (fail fast) instead of exploding under a SYN
/// flood. Legit use never approaches it (noisy machine: low hundreds).
const WORKER_CAP: usize = 512;

/// Payloads a worker inbox holds: backpressure bound (see forward_tcp).
const WORKER_QUEUE: usize = 128;

/// Poll quantum of a stream worker: socket reads stay responsive to newly
/// arrived payloads and to session end. 10ms keeps added latency far under
/// a typical RTO (50ms showed up in ping/RTT budgets, seen live).
const WORKER_POLL: Duration = Duration::from_millis(10);

/// Stack per stream worker: it only dials/reads/writes (no deep frames).
const WORKER_STACK: usize = 256 * 1024;

/// Worker -> loop replies, possibly many per stream, in worker order.
/// Failure kind travels so only definitive refusals cool the target down.
struct StreamReply {
    id: u16,
    target: (String, u16),
    result: Result<Vec<u8>, relay::DialFail>,
}

fn worker_fail(
    out: &mpsc::Sender<StreamReply>,
    id: u16,
    target: (String, u16),
    kind: relay::DialFail,
) {
    let _ = out.send(StreamReply {
        id,
        target,
        result: Err(kind),
    });
}

/// One thread per TCP stream: owns its relay socket cradle-to-grave.
/// Payloads are written as they arrive, replies forwarded as they arrive —
/// full duplex, no request/response pairing, no idle tails. Reports once
/// on socket error/EOF, then exits; silent exit when the loop is gone.
fn stream_worker(
    id: u16,
    ip: String,
    port: u16,
    first: Vec<u8>,
    inbox: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<StreamReply>,
) {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    let target = (ip.clone(), port);
    // TEMP-DIAG(upload): per-stream byte counters, logged at worker exit.
    let t0 = Instant::now();
    let mut written: u64 = 0;
    let mut read_back: u64 = 0;
    let mut sock = match relay::dial_tcp(&ip, port) {
        Ok(s) => {
            debug_log(&format!(
                "TEMP-DIAG id={id} dial {}:{} ok in {:?}",
                target.0,
                target.1,
                t0.elapsed()
            ));
            s
        }
        Err(kind) => {
            debug_log(&format!(
                "TEMP-DIAG id={id} dial {}:{} failed {kind:?} in {:?}",
                target.0,
                target.1,
                t0.elapsed()
            ));
            worker_fail(&out, id, target, kind);
            return;
        }
    };
    if sock.set_read_timeout(Some(WORKER_POLL)).is_err() {
        worker_fail(&out, id, target, relay::DialFail::Transient);
        return;
    }
    if !first.is_empty() {
        written += first.len() as u64;
        if sock.write_all(&first).is_err() {
            debug_log(&format!(
                "TEMP-DIAG id={id} first-write failed written={written}"
            ));
            worker_fail(&out, id, target, relay::DialFail::Transient);
            return;
        }
    }
    let mut buf = vec![0u8; 65535];
    loop {
        // Drain newly arrived payloads (no loss under burst).
        loop {
            match inbox.try_recv() {
                Ok(payload) => {
                    if !payload.is_empty() {
                        written += payload.len() as u64;
                        if sock.write_all(&payload).is_err() {
                            debug_log(&format!(
                                "TEMP-DIAG id={id} write failed written={written}"
                            ));
                            worker_fail(&out, id, target, relay::DialFail::Transient);
                            return;
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return, // session over
            }
        }
        match sock.read(&mut buf) {
            Ok(0) => {
                // Clean EOF: one empty reply (old semantic), then exit;
                // the loop forgets the worker.
                debug_log(&format!(
                    "TEMP-DIAG id={id} worker end eof written={written} read={read_back}"
                ));
                let _ = out.send(StreamReply {
                    id,
                    target,
                    result: Ok(Vec::new()),
                });
                return;
            }
            Ok(n) => {
                read_back += n as u64;
                let reply = StreamReply {
                    id,
                    target: target.clone(),
                    result: Ok(buf[..n].to_vec()),
                };
                if out.send(reply).is_err() {
                    debug_log(&format!(
                        "TEMP-DIAG id={id} worker end loop-gone written={written} read={read_back}"
                    ));
                    return;
                }
            }
            Err(e) if e.kind() == TimedOut || e.kind() == WouldBlock => {}
            Err(_) => {
                debug_log(&format!(
                    "TEMP-DIAG id={id} worker end read-err written={written} read={read_back}"
                ));
                worker_fail(&out, id, target, relay::DialFail::Transient);
                return;
            }
        }
    }
}

/// Forward one TCP payload to its stream worker, spawning (dialing) on
/// first sight. Empty payloads (would-be warms) just ensure the worker.
#[allow(clippy::too_many_arguments)]
fn forward_tcp(
    workers: &mut HashMap<u16, mpsc::SyncSender<Vec<u8>>>,
    dead: &HashMap<(String, u16), Instant>,
    stream_tx: &mpsc::Sender<StreamReply>,
    id: u16,
    target: (String, u16),
    pt: Vec<u8>,
) {
    if !pt.is_empty() && relay::is_fresh_dead(dead, &target.0, target.1, Instant::now()) {
        debug_log(&format!(
            "tunnel: data id={id} target {}:{} in dead cooldown, skipping flow",
            target.0, target.1
        ));
        return;
    }
    let mut carry = Some(pt);
    if let Some(tx) = workers.get(&id).cloned() {
        match tx.try_send(carry.take().unwrap_or_default()) {
            Ok(()) => return,
            Err(mpsc::TrySendError::Full(_)) => {
                // Worker alive but buried (flood-only): drop this payload,
                // keep the stream (a gap beats a split brain).
                debug_log(&format!(
                    "tunnel: data id={id} worker channel full, dropping payload"
                ));
                return;
            }
            Err(mpsc::TrySendError::Disconnected(p)) => {
                workers.remove(&id);
                carry = Some(p);
            }
        }
    }
    let first = carry.unwrap_or_default();
    if workers.len() >= WORKER_CAP {
        debug_log(&format!(
            "tunnel: data id={id} too many streams, skipping flow"
        ));
        return;
    }
    let (tx, rx) = mpsc::sync_channel(WORKER_QUEUE);
    let out = stream_tx.clone();
    let (tip, tport) = target;
    match std::thread::Builder::new()
        .name(format!("relay-{id}"))
        .stack_size(WORKER_STACK)
        .spawn(move || stream_worker(id, tip, tport, first, rx, out))
    {
        Ok(_) => {
            workers.insert(id, tx);
        }
        Err(e) => debug_log(&format!("tunnel: data id={id} worker spawn failed: {e}")),
    }
}

/// Seal + write one UDP completion; false ends the session (write failed).
/// (TCP streams report through the stream channel now; the pool is UDP-only.)
fn handle_completion(
    c: Completion<FlowKey, Result<RelayOut, ()>>,
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    _dead: &mut HashMap<(String, u16), Instant>,
) -> bool {
    let FlowKey { id, target } = c.key;
    match c.result {
        Ok(RelayOut::Udp(reply)) => {
            debug_log(&format!("tunnel: datagram id={id} relay {}B", reply.len()));
            match send_chunked(sess, stream, id, &reply, true) {
                Ok(()) => true,
                Err(e) => {
                    debug_log(&format!(
                        "tunnel: datagram id={id} reply failed ({e}), closing"
                    ));
                    false
                }
            }
        }
        Err(()) => {
            debug_log(&format!(
                "tunnel: datagram id={id} relay to {}:{} failed, skipping flow",
                target.0, target.1
            ));
            true
        }
    }
}

/// Seal + write one stream-worker reply; false ends the session.
/// Empty reply = target closed cleanly: forget the worker, answer once.
/// Error = relay died: forget the worker, cool the target down.
#[allow(clippy::too_many_arguments)]
fn handle_stream_reply(
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    workers: &mut HashMap<u16, mpsc::SyncSender<Vec<u8>>>,
    dead: &mut HashMap<(String, u16), Instant>,
    r: StreamReply,
) -> bool {
    match r.result {
        Ok(bytes) => {
            if bytes.is_empty() {
                workers.remove(&r.id);
            } else {
                dead.remove(&r.target);
            }
            match send_data(sess, stream, r.id, &bytes) {
                Ok(()) => true,
                Err(e) => {
                    debug_log(&format!(
                        "tunnel: data id={} reply write failed ({e}), closing",
                        r.id
                    ));
                    false
                }
            }
        }
        Err(relay::DialFail::Refused) => {
            workers.remove(&r.id);
            debug_log(&format!(
                "tunnel: data id={} relay refused, cooling down {}:{}",
                r.id, r.target.0, r.target.1
            ));
            relay::mark_dead(dead, &r.target.0, r.target.1, Instant::now());
            true
        }
        Err(relay::DialFail::Transient) => {
            workers.remove(&r.id);
            debug_log(&format!(
                "tunnel: data id={} relay failed (transient, no cooldown)",
                r.id
            ));
            true
        }
    }
}

/// Drain pool (UDP) + stream (TCP) completions; false ends the session.
#[allow(clippy::too_many_arguments)]
fn drain_completions(
    pool: &RelayPool<FlowKey, Result<RelayOut, ()>>,
    stream_rx: &mpsc::Receiver<StreamReply>,
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    workers: &mut HashMap<u16, mpsc::SyncSender<Vec<u8>>>,
    dead: &mut HashMap<(String, u16), Instant>,
) -> bool {
    while let Some(c) = pool.try_recv() {
        if !handle_completion(c, sess, stream, dead) {
            return false;
        }
    }
    while let Ok(r) = stream_rx.try_recv() {
        if !handle_stream_reply(sess, stream, workers, dead, r) {
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
    // Nagle would stall our small per-frame writes behind delayed ACKs.
    let _ = sock.set_nodelay(true);
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
    // Live TCP stream workers (one thread+dial per stream, full duplex).
    let mut workers: HashMap<u16, mpsc::SyncSender<Vec<u8>>> = HashMap::new();
    let (stream_tx, stream_rx) = mpsc::channel::<StreamReply>();
    // Targets whose dial recently failed: fail fast for the cooldown
    // instead of spawning another doomed worker.
    let mut dead: HashMap<(String, u16), Instant> = HashMap::new();
    let pool: RelayPool<FlowKey, Result<RelayOut, ()>> =
        RelayPool::new(POOL_WORKERS, POOL_WORKERS + POOL_QUEUE);
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
                    &stream_rx,
                    &mut sess,
                    stream,
                    &mut workers,
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
        // Body: tolerate stalls past the read quantum (a big body is many
        // TCP segments; any gap tripping the 50ms timeout must resume, not
        // abort the session — seen live: "body eof, closing" killed healthy
        // sessions mid-frame). Position-tracked; bounded 30s (fail closed).
        let mut ct = vec![0u8; header.length as usize];
        let body_start = Instant::now();
        let mut filled = 0;
        let body_ok = loop {
            match stream.read(&mut ct[filled..]) {
                Ok(0) => break false,
                Ok(n) => {
                    filled += n;
                    if filled >= ct.len() {
                        break true;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    if body_start.elapsed() > BODY_TOTAL_TIMEOUT {
                        break false;
                    }
                }
                Err(_) => break false,
            }
        };
        if !body_ok {
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
                // TCP payload (possibly empty): forward to the stream
                // worker, spawning (dialing) on first sight. Full duplex:
                // writes and reads interleave with no pairing or tails.
                let id = header.stream_id;
                forward_tcp(
                    &mut workers,
                    &dead,
                    &stream_tx,
                    id,
                    (target.ip().to_string(), target.port()),
                    pt,
                );
                if !drain_completions(
                    &pool,
                    &stream_rx,
                    &mut sess,
                    stream,
                    &mut workers,
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
                } else {
                    debug_log(&format!(
                        "tunnel: datagram id={} server busy, skipping flow",
                        header.stream_id
                    ));
                }
                if !drain_completions(
                    &pool,
                    &stream_rx,
                    &mut sess,
                    stream,
                    &mut workers,
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
                if workers.contains_key(&header.stream_id) {
                    debug_log(&format!(
                        "tunnel: open_tcp id={} duplicate, worker exists",
                        header.stream_id
                    ));
                    continue;
                }
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

/// Max plaintext per TCP reply frame. One frame becomes one TCP segment on
/// the peer, so it must stay IP-carriable (<= 65535 incl. headers): a bigger
/// frame panics the peer packet builder and kills its pump outright (seen
/// live: a 189KB reply -> pump dead, tunnel mute). Sealed 16KiB + tag.
const REPLY_CHUNK: usize = 16384;

/// Max UDP reply payload sent as one datagram. Datagrams have no reassembly:
/// past IP-carriable size (65507 incl. headers) the reply is undeliverable,
/// so it is dropped with a log and the loop lives on.
const UDP_SINGLE_MAX: usize = 65000;

/// Seal + write one reply, chunked to the wire cap; Err carries the first
/// seal or transport failure. Empty payload keeps the old single empty
/// frame (some flows rely on the reply existing, not its size).
fn send_chunked(
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    id: u16,
    payload: &[u8],
    udp: bool,
) -> Result<(), String> {
    let seal_one = |sess: &mut session::ServerSession, chunk: &[u8]| {
        if udp {
            sess.mux.seal_datagram(sess.keys.tx_key(), id, chunk, 128)
        } else {
            sess.mux.seal_data(sess.keys.tx_key(), id, chunk, 128)
        }
    };
    if udp && payload.len() > UDP_SINGLE_MAX {
        debug_log(&format!(
            "tunnel: datagram id={id} reply {}B exceeds one packet, skipping flow",
            payload.len()
        ));
        return Ok(());
    }
    if payload.is_empty() || udp {
        let sealed = seal_one(sess, payload).map_err(|e| format!("seal: {e}"))?;
        return write_sealed(stream, &sealed.header, &sealed.ciphertext)
            .map_err(|e| format!("transport: {e}"));
    }
    for chunk in payload.chunks(REPLY_CHUNK) {
        let sealed = seal_one(sess, chunk).map_err(|e| format!("seal: {e}"))?;
        write_sealed(stream, &sealed.header, &sealed.ciphertext)
            .map_err(|e| format!("transport: {e}"))?;
    }
    Ok(())
}

/// Seal + write one DATA reply; Err carries seal or transport failure.
fn send_data(
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    id: u16,
    payload: &[u8],
) -> Result<(), String> {
    send_chunked(sess, stream, id, payload, false)
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
