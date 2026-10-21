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
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
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
    /// Domain blocklist (ads/trackers): DNS answers and OPEN targets.
    pub blocklist: crate::blocklist::Blocklist,
}

/// Relay read timeout: a silent target burns one worker for this long;
const UDP_RELAY_TIMEOUT: Duration = Duration::from_secs(2);

/// Wire-read quantum: short 5ms poll so server->client download replies
/// drain smoothly without 50ms stalls while client->server is quiet.
const READ_TIMEOUT: Duration = Duration::from_millis(5);

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
/// Sized generously (~1.4 MiB at 1360B MSS) so initial dial latency and
/// transient target jitter never stall the multiplexed tunnel loop.
const WORKER_QUEUE: usize = 1024;

/// How long the loop waits for a buried worker before it gives up on the
/// stream. Bound it so one genuinely wedged target cannot hold up the session,
/// while tolerating slow-start / transient congestion on multi-MB uploads.
const SEND_HOLD: Duration = Duration::from_secs(10);
/// Poll step inside the bounded wait below.
const SEND_HOLD_POLL: Duration = Duration::from_millis(2);

/// Idle wake interval for a non-blocking stream worker checking target reads
/// while waiting on new upload messages from `inbox`.
const WORKER_IDLE_POLL: Duration = Duration::from_millis(1);

/// Maximum bytes buffered inside a worker's non-blocking write buffer before
/// applying channel backpressure to `inbox`.
const WORKER_WRITE_BATCH: usize = 256 * 1024;

/// Bounded downstream TCP reply queue (`64 * 64 KiB = 4 MiB` across active
/// streams) so multi-Gbps datacenter upstream servers apply clean TCP receive
/// backpressure instead of buffering hundreds of megabytes of ahead-of-WAN
/// download data in user-space RAM.
const STREAM_REPLY_QUEUE: usize = 64;

/// Downstream bytes encrypted per `drain_completions` slice before doing a
/// non-blocking poll of `stream.sock` for inbound client frames (`OpenTcp`,
/// `Data`, `Rst`, `OpenUdp`), preventing fast downloads from ever starving
/// concurrent uploads or stream `RST` aborts while keeping 0ms download pause.
const DRAIN_BYTES_QUANTUM: usize = 128 * 1024;

/// Active TCP stream worker handle stored in `workers`. Dropping the handle
/// (on `FrameType::Rst`, stream recycling, stall cleanup, or session exit)
/// immediately signals `aborted = true` so the worker aborts its upstream
/// socket (`SO_LINGER = 0` `TCP RST`) and exits without waiting on queue drain.
struct WorkerHandle {
    tx: mpsc::SyncSender<WorkerMsg>,
    aborted: Arc<AtomicBool>,
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        self.aborted.store(true, Ordering::Relaxed);
    }
}

#[cfg(unix)]
fn abort_tcp_socket(sock: &TcpStream) {
    use std::os::fd::AsRawFd;
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    unsafe {
        let _ = libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            std::mem::size_of_val(&linger) as libc::socklen_t,
        );
    }
}

#[cfg(not(unix))]
fn abort_tcp_socket(sock: &TcpStream) {
    let _ = sock.shutdown(std::net::Shutdown::Both);
}

thread_local! {
    /// First precise reason a tunnel session failed on this thread (helpers
    /// deep inside drain/close only return `bool`). Cleared per session.
    static SESSION_END: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// Remember why the session is about to end (first reason wins).
fn note_end(why: String) {
    SESSION_END.with(|c| {
        let mut c = c.borrow_mut();
        if c.is_none() {
            *c = Some(why);
        }
    });
}

thread_local! {
    /// (client->target upload bytes, target->client download bytes) of the
    /// current session, reported on disconnect so one journal line shows
    /// whether a Speedtest upload ever reached the server.
    static TRAFFIC: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
}

fn count_up(n: usize) {
    TRAFFIC.with(|t| {
        let (u, d) = t.get();
        t.set((u.saturating_add(n as u64), d));
    });
}

fn count_down(n: usize) {
    TRAFFIC.with(|t| {
        let (u, d) = t.get();
        t.set((u, d.saturating_add(n as u64)));
    });
}

fn mib(n: u64) -> String {
    format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
}

fn take_end() -> Option<String> {
    SESSION_END.with(|c| c.borrow_mut().take())
}

/// Return `prefix: <noted reason>` (or just `prefix`) for the journal.
fn end_reason(prefix: &str) -> String {
    match take_end() {
        Some(why) => format!("{prefix}: {why}"),
        None => prefix.to_string(),
    }
}

/// Outcome of pushing one message toward a worker with a bounded wait
/// (std has no send_timeout on SyncSender; this is its manual equivalent).
enum SendHoldFail {
    /// Still full after SEND_HOLD: payload dropped, caller closes stream.
    Stalled,
    /// Worker exited: stream is over, caller closes stream.
    Gone,
    /// Session write failed while draining completions during backpressure.
    SessionDead,
}

#[allow(clippy::too_many_arguments)]
fn send_hold(
    tx: &mpsc::SyncSender<WorkerMsg>,
    msg: WorkerMsg,
    pool: &RelayPool<FlowKey, Result<RelayOut, ()>>,
    stream_rx: &mpsc::Receiver<StreamReply>,
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    routes: &mut HashMap<u16, SocketAddr>,
    workers: &mut HashMap<u16, WorkerHandle>,
    dead: &mut HashMap<(String, u16), Instant>,
) -> Result<(), SendHoldFail> {
    let start = Instant::now();
    let mut msg = msg;
    loop {
        match tx.try_send(msg) {
            Ok(()) => return Ok(()),
            Err(mpsc::TrySendError::Disconnected(_)) => return Err(SendHoldFail::Gone),
            Err(mpsc::TrySendError::Full(m)) => {
                if start.elapsed() >= SEND_HOLD {
                    return Err(SendHoldFail::Stalled);
                }
                if !drain_completions(pool, stream_rx, sess, stream, routes, workers, dead) {
                    return Err(SendHoldFail::SessionDead);
                }
                msg = m;
                std::thread::sleep(SEND_HOLD_POLL);
            }
        }
    }
}

/// Stack per stream worker: 4 MiB so Ubuntu glibc `getaddrinfo` / `libnss_*`
/// plus `.NET` CoreCLR GC signal handler frames never hit the pthread stack
/// guard page (`SIGSEGV` seen live when this was only 256 KiB).
const WORKER_STACK: usize = 4 * 1024 * 1024;

/// Worker -> loop replies, possibly many per stream, in worker order.
/// Failure kind travels so only definitive refusals cool the target down.
struct StreamReply {
    id: u16,
    target: (String, u16),
    result: Result<Vec<u8>, relay::DialFail>,
}

fn send_reply_bounded(
    out: &mpsc::SyncSender<StreamReply>,
    aborted: &AtomicBool,
    mut reply: StreamReply,
) -> bool {
    loop {
        if aborted.load(Ordering::Relaxed) {
            return false;
        }
        match out.try_send(reply) {
            Ok(()) => return true,
            Err(mpsc::TrySendError::Full(r)) => {
                reply = r;
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return false,
        }
    }
}

fn worker_fail(
    out: &mpsc::SyncSender<StreamReply>,
    aborted: &AtomicBool,
    id: u16,
    target: (String, u16),
    kind: relay::DialFail,
) {
    let _ = send_reply_bounded(
        out,
        aborted,
        StreamReply {
            id,
            target,
            result: Err(kind),
        },
    );
}

/// One relay hop for a stream worker: bytes to write, or the peer's
/// half-close (FIN) so the target can answer and end the connection.
enum WorkerMsg {
    Data(Vec<u8>),
    HalfClose,
}

/// One thread per TCP stream: owns its relay socket cradle-to-grave.
/// Payloads are written as they arrive, replies forwarded as they arrive —
/// full duplex, non-blocking I/O so socket backpressure on one direction
/// never stalls the other direction and upload bursts do not pause 10ms
/// per read timeout. Reports once on socket error/EOF, then exits; silent
/// exit when the loop is gone.
fn stream_worker(
    id: u16,
    ip: String,
    port: u16,
    first: Vec<u8>,
    inbox: mpsc::Receiver<WorkerMsg>,
    out: mpsc::SyncSender<StreamReply>,
    aborted: Arc<AtomicBool>,
) {
    use std::io::ErrorKind::{Interrupted, TimedOut, WouldBlock};
    use std::net::Shutdown;
    let target = (ip.clone(), port);
    let mut sock = match relay::dial_tcp(&ip, port) {
        Ok(s) => s,
        Err(kind) => {
            debug_log(&format!(
                "tunnel: id={id} dial {}:{} failed {kind:?}",
                target.0, target.1
            ));
            worker_fail(&out, &aborted, id, target, kind);
            return;
        }
    };
    let _ = sock.set_nodelay(true);
    if sock.set_nonblocking(true).is_err() {
        worker_fail(&out, &aborted, id, target, relay::DialFail::Transient);
        return;
    }
    let mut write_buf = first;
    let mut write_pos: usize = 0;
    let mut half_close_pending = false;
    let mut half_closed = false;
    let mut session_gone = false;
    let mut buf = vec![0u8; 65535];
    loop {
        if aborted.load(Ordering::Relaxed) {
            abort_tcp_socket(&sock);
            return;
        }
        while write_buf.len().saturating_sub(write_pos) < WORKER_WRITE_BATCH {
            match inbox.try_recv() {
                Ok(WorkerMsg::Data(payload)) => {
                    if !payload.is_empty() {
                        write_buf.extend_from_slice(&payload);
                    }
                }
                Ok(WorkerMsg::HalfClose) => {
                    half_close_pending = true;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    session_gone = true;
                    break;
                }
            }
        }
        if session_gone || aborted.load(Ordering::Relaxed) {
            abort_tcp_socket(&sock);
            return;
        }

        let mut progressed = false;
        while write_pos < write_buf.len() {
            match sock.write(&write_buf[write_pos..]) {
                Ok(0) => {
                    debug_log(&format!("tunnel: id={id} write returned 0"));
                    worker_fail(&out, &aborted, id, target, relay::DialFail::Transient);
                    return;
                }
                Ok(n) => {
                    write_pos += n;
                    progressed = true;
                }
                Err(e) if e.kind() == Interrupted => continue,
                Err(e) if e.kind() == WouldBlock || e.kind() == TimedOut => break,
                Err(_) => {
                    debug_log(&format!("tunnel: id={id} write failed"));
                    worker_fail(&out, &aborted, id, target, relay::DialFail::Transient);
                    return;
                }
            }
        }
        if write_pos > 0 {
            if write_pos == write_buf.len() {
                write_buf.clear();
                write_pos = 0;
            } else if write_pos >= 65536 {
                write_buf.drain(..write_pos);
                write_pos = 0;
            }
        }

        if write_buf.is_empty() && half_close_pending && !half_closed {
            // The peer is done sending and all queued upload bytes have
            // entered the socket: signal EOF so the target can respond.
            if sock.shutdown(Shutdown::Write).is_err() {
                debug_log(&format!("tunnel: id={id} shutdown(write) failed"));
                worker_fail(&out, &aborted, id, target, relay::DialFail::Transient);
                return;
            }
            half_closed = true;
            progressed = true;
        }

        for _ in 0..16 {
            if aborted.load(Ordering::Relaxed) {
                abort_tcp_socket(&sock);
                return;
            }
            match sock.read(&mut buf) {
                Ok(0) => {
                    debug_log(&format!("tunnel: id={id} relay eof"));
                    let _ = send_reply_bounded(
                        &out,
                        &aborted,
                        StreamReply {
                            id,
                            target,
                            result: Ok(Vec::new()),
                        },
                    );
                    return;
                }
                Ok(n) => {
                    progressed = true;
                    let reply = StreamReply {
                        id,
                        target: target.clone(),
                        result: Ok(buf[..n].to_vec()),
                    };
                    if !send_reply_bounded(&out, &aborted, reply) {
                        abort_tcp_socket(&sock);
                        return;
                    }
                }
                Err(e) if e.kind() == Interrupted => continue,
                Err(e) if e.kind() == WouldBlock || e.kind() == TimedOut => break,
                Err(_) => {
                    debug_log(&format!("tunnel: id={id} relay read error"));
                    worker_fail(&out, &aborted, id, target, relay::DialFail::Transient);
                    return;
                }
            }
        }

        if !progressed {
            match inbox.recv_timeout(WORKER_IDLE_POLL) {
                Ok(WorkerMsg::Data(payload)) => {
                    if !payload.is_empty() {
                        write_buf.extend_from_slice(&payload);
                    }
                }
                Ok(WorkerMsg::HalfClose) => {
                    half_close_pending = true;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    abort_tcp_socket(&sock);
                    return;
                }
            }
        }
    }
}

/// Outcome of `forward_tcp`.
enum ForwardOutcome {
    Delivered,
    CloseStream,
    SessionDead,
}

/// Forward one TCP payload to its stream worker, spawning (dialing) on
/// first sight. An empty payload on a live worker is the peer's half-close
/// (FIN); with no worker yet it stays the bare-SYN warm-up.
///
/// Never re-dials mid-stream if an existing worker exited: opening a fresh
/// TCP connection to the target with mid-body payload bytes corrupts the
/// application stream. Instead `CloseStream` notifies the peer cleanly.
#[allow(clippy::too_many_arguments)]
fn forward_tcp(
    pool: &RelayPool<FlowKey, Result<RelayOut, ()>>,
    stream_rx: &mpsc::Receiver<StreamReply>,
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    routes: &mut HashMap<u16, SocketAddr>,
    workers: &mut HashMap<u16, WorkerHandle>,
    dead: &mut HashMap<(String, u16), Instant>,
    stream_tx: &mpsc::SyncSender<StreamReply>,
    id: u16,
    target: (String, u16),
    pt: Vec<u8>,
) -> ForwardOutcome {
    if !pt.is_empty() && relay::is_fresh_dead(dead, &target.0, target.1, Instant::now()) {
        debug_log(&format!(
            "tunnel: data id={id} target {}:{} in dead cooldown, closing stream",
            target.0, target.1
        ));
        return ForwardOutcome::CloseStream;
    }
    if let Some(tx) = workers.get(&id).map(|h| h.tx.clone()) {
        let msg = if pt.is_empty() {
            WorkerMsg::HalfClose
        } else {
            WorkerMsg::Data(pt)
        };
        return match send_hold(
            &tx, msg, pool, stream_rx, sess, stream, routes, workers, dead,
        ) {
            Ok(()) => ForwardOutcome::Delivered,
            Err(SendHoldFail::Stalled) => {
                debug_log(&format!(
                    "tunnel: data id={id} relay stalled past {:?}, closing stream",
                    SEND_HOLD
                ));
                workers.remove(&id);
                ForwardOutcome::CloseStream
            }
            Err(SendHoldFail::Gone) => {
                debug_log(&format!(
                    "tunnel: data id={id} worker already exited, draining final replies"
                ));
                workers.remove(&id);
                if !drain_completions(pool, stream_rx, sess, stream, routes, workers, dead) {
                    return ForwardOutcome::SessionDead;
                }
                if routes.contains_key(&id) {
                    ForwardOutcome::CloseStream
                } else {
                    ForwardOutcome::Delivered
                }
            }
            Err(SendHoldFail::SessionDead) => ForwardOutcome::SessionDead,
        };
    }
    if workers.len() >= WORKER_CAP {
        debug_log(&format!(
            "tunnel: data id={id} too many streams, closing stream"
        ));
        return ForwardOutcome::CloseStream;
    }
    let (tx, rx) = mpsc::sync_channel(WORKER_QUEUE);
    let aborted = Arc::new(AtomicBool::new(false));
    let aborted_worker = Arc::clone(&aborted);
    let out = stream_tx.clone();
    let (tip, tport) = target;
    match std::thread::Builder::new()
        .name(format!("relay-{id}"))
        .stack_size(WORKER_STACK)
        .spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                stream_worker(id, tip, tport, pt, rx, out, aborted_worker);
            }));
        })
    {
        Ok(_) => {
            workers.insert(id, WorkerHandle { tx, aborted });
            ForwardOutcome::Delivered
        }
        Err(e) => {
            debug_log(&format!("tunnel: data id={id} worker spawn failed: {e}"));
            ForwardOutcome::CloseStream
        }
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
                    note_end(format!("udp reply write to client failed: {e}"));
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

/// Tell the peer a stream is finished: one empty DATA frame.
///
/// The peer's stack turns it into a FIN (its app sees the connection end)
/// instead of leaving the socket to hang until the app's own timeout.
/// Silent failure is what made a whole upload measure zero: every attempt
/// stalled in the dark while the app waited.
fn close_stream(
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    routes: &mut HashMap<u16, SocketAddr>,
    id: u16,
) -> bool {
    let sealed = match sess.mux.seal_data(sess.keys.tx_key(), id, &[], 128) {
        Ok(sealed) => Some(sealed),
        Err(e) => {
            // Id already gone (never registered / closed): nothing to say.
            debug_log(&format!("tunnel: close id={id} seal failed: {e}"));
            None
        }
    };
    // Free both mux state and route: any queued mid-body frames already in
    // flight for this closed stream must be skipped cleanly instead of
    // dialing a brand-new TCP connection with mid-stream payload bytes.
    routes.remove(&id);
    let _ = sess.mux.close(id);
    match sealed {
        Some(sealed) => match write_sealed(stream, &sealed.header, &sealed.ciphertext) {
            Ok(()) => true,
            Err(e) => {
                debug_log(&format!(
                    "tunnel: close id={id} write failed ({e}), closing"
                ));
                note_end(format!("stream close write to client failed: {e}"));
                false
            }
        },
        None => true,
    }
}

/// Seal + write one stream-worker reply; returns `Some(wire_bytes)` on success
/// or `None` when the outer TLS socket failed (ending the session).
/// Empty reply = target closed cleanly: forget the worker, close the stream.
/// Error = relay died: forget the worker, close the stream, cool the target
/// down when the refusal was definitive.
#[allow(clippy::too_many_arguments)]
fn handle_stream_reply(
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    routes: &mut HashMap<u16, SocketAddr>,
    workers: &mut HashMap<u16, WorkerHandle>,
    dead: &mut HashMap<(String, u16), Instant>,
    r: StreamReply,
) -> Option<usize> {
    match r.result {
        Ok(bytes) => {
            if bytes.is_empty() {
                workers.remove(&r.id);
                close_stream(sess, stream, routes, r.id).then_some(0)
            } else {
                dead.remove(&r.target);
                let counted = if sess.mux.is_open(r.id) {
                    bytes.len()
                } else {
                    0
                };
                match send_data(sess, stream, r.id, &bytes) {
                    Ok(()) => {
                        count_down(counted);
                        Some(counted)
                    }
                    Err(e) => {
                        debug_log(&format!(
                            "tunnel: data id={} reply write failed ({e}), closing",
                            r.id
                        ));
                        note_end(format!("tcp reply write to client failed: {e}"));
                        None
                    }
                }
            }
        }
        Err(kind) => {
            workers.remove(&r.id);
            if kind == relay::DialFail::Refused {
                debug_log(&format!(
                    "tunnel: data id={} relay refused, cooling down {}:{}",
                    r.id, r.target.0, r.target.1
                ));
                relay::mark_dead(dead, &r.target.0, r.target.1, Instant::now());
            } else {
                debug_log(&format!(
                    "tunnel: data id={} relay failed (transient, no cooldown)",
                    r.id
                ));
            }
            close_stream(sess, stream, routes, r.id).then_some(0)
        }
    }
}

/// Non-blockingly poll whether the client sent any TLS bytes while the server
/// is streaming downstream replies:
/// - `Ok(true)`: decrypted plaintext is already buffered in `stream.conn`, OR
///   at least one new TLS byte / EOF arrived on `stream.sock` (left decrypted
///   inside `stream.conn` for `tunnel_loop`'s next `read_tls_step`).
/// - `Ok(false)`: `WouldBlock` — zero client bytes waiting, so downstream
///   streaming can continue immediately without incurring `READ_TIMEOUT`.
fn poll_client_inbound(stream: &mut tls::ServerTlsStream) -> std::io::Result<bool> {
    if stream
        .conn
        .process_new_packets()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        .plaintext_bytes_to_read()
        > 0
    {
        return Ok(true);
    }
    if stream.get_ref().set_nonblocking(true).is_err() {
        return Ok(false);
    }
    let res = loop {
        match stream.conn.read_tls(&mut stream.sock) {
            Ok(0) => break Ok(true),
            Ok(_) => {
                stream
                    .conn
                    .process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                break Ok(true);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break Ok(false);
            }
            Err(e) => break Err(e),
        }
    };
    let _ = stream.get_ref().set_nonblocking(false);
    res
}

/// Drain pool (UDP) + stream (TCP) completions; false ends the session.
///
/// Interleaves non-blocking client socket checks every `DRAIN_BYTES_QUANTUM`
/// so multi-Gbps datacenter downloads NEVER starve client `FrameType::Rst`
/// aborts or concurrent `OpenTcp`/`Data` upload streams while maintaining
/// continuous zero-pause download throughput when the client is silent.
#[allow(clippy::too_many_arguments)]
fn drain_completions(
    pool: &RelayPool<FlowKey, Result<RelayOut, ()>>,
    stream_rx: &mpsc::Receiver<StreamReply>,
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    routes: &mut HashMap<u16, SocketAddr>,
    workers: &mut HashMap<u16, WorkerHandle>,
    dead: &mut HashMap<(String, u16), Instant>,
) -> bool {
    while let Some(c) = pool.try_recv() {
        if !handle_completion(c, sess, stream, dead) {
            return false;
        }
    }
    let mut drained_bytes: usize = 0;
    while let Ok(r) = stream_rx.try_recv() {
        match handle_stream_reply(sess, stream, routes, workers, dead, r) {
            Some(written) => drained_bytes += written,
            None => return false,
        }
        if drained_bytes >= DRAIN_BYTES_QUANTUM {
            drained_bytes = 0;
            match poll_client_inbound(stream) {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => {
                    debug_log(&format!(
                        "tunnel: client socket poll failed during drain ({e}), closing"
                    ));
                    note_end(format!("client socket poll failed: {e}"));
                    return false;
                }
            }
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
    let _ = write_tls_all(stream, head.as_bytes());
    let _ = write_tls_all(stream, body);
    close_quietly(stream);
}

/// TLS close_notify + flush, ignoring errors (peer may be gone).
fn close_quietly(stream: &mut tls::ServerTlsStream) {
    stream.conn.send_close_notify();
    let _ = flush_tls_writes(stream);
}

/// Best-effort one-shot Linux kernel WAN tuning when `aetherlink-server` runs
/// as root (the systemd unit default). Raises auto-tuned TCP buffer ceilings
/// from Ubuntu's default 208 KiB (`rmem_max`/`wmem_max`) to 16 MiB and enables
/// `fq` + `bbr` while silently no-oping in unprivileged tests/containers.
#[cfg(target_os = "linux")]
fn ensure_linux_wan_tuning() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for (path, val) in [
            ("/proc/sys/net/core/rmem_max", "16777216\n"),
            ("/proc/sys/net/core/wmem_max", "16777216\n"),
            ("/proc/sys/net/ipv4/tcp_rmem", "4096 131072 16777216\n"),
            ("/proc/sys/net/ipv4/tcp_wmem", "4096 65536 16777216\n"),
            ("/proc/sys/net/core/default_qdisc", "fq\n"),
            ("/proc/sys/net/ipv4/tcp_congestion_control", "bbr\n"),
        ] {
            let _ = std::fs::write(path, val);
        }
    });
}

/// Enable kernel TCP keepalive (`15s` idle, `5s` interval, `6` probes) on
/// accepted Linux sockets so CGNATs, stateful firewalls, and middleboxes
/// observe bidirectional packets during idle windows instead of injecting RST.
#[cfg(target_os = "linux")]
fn enable_linux_tcp_keepalive(sock: &TcpStream) {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    let on: libc::c_int = 1;
    let idle: libc::c_int = 15;
    let intvl: libc::c_int = 5;
    let cnt: libc::c_int = 6;
    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            (&raw const on).cast(),
            std::mem::size_of_val(&on) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            (&raw const idle).cast(),
            std::mem::size_of_val(&idle) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            (&raw const intvl).cast(),
            std::mem::size_of_val(&intvl) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            (&raw const cnt).cast(),
            std::mem::size_of_val(&cnt) as libc::socklen_t,
        );
    }
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
    #[cfg(target_os = "linux")]
    ensure_linux_wan_tuning();
    #[cfg(target_os = "linux")]
    enable_linux_tcp_keepalive(&sock);

    let peer = sock
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Nagle would stall our small per-frame writes behind delayed ACKs.
    // Leave SO_SNDBUF/SO_RCVBUF unlocked so Linux tcp_rmem/tcp_wmem auto-tunes
    // dynamically up to 16 MiB without triggering SOCK_*BUF_LOCK.
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
    eprintln!("[aetherlink] tunnel connected ({peer})");
    let started = Instant::now();
    let reason = tunnel_loop(&mut stream, sess, ctx, routes);
    let (up, down) = TRAFFIC.with(std::cell::Cell::get);
    eprintln!(
        "[aetherlink] tunnel disconnected ({peer}): {reason} [up {}, down {}, {}s]",
        mib(up),
        mib(down),
        started.elapsed().as_secs()
    );
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
) -> String {
    let _ = take_end();
    TRAFFIC.with(|t| t.set((0, 0)));
    // Live TCP stream workers (one thread+dial per stream, full duplex).
    let mut workers: HashMap<u16, WorkerHandle> = HashMap::new();
    let (stream_tx, stream_rx) = mpsc::sync_channel::<StreamReply>(STREAM_REPLY_QUEUE);
    // Targets whose dial recently failed: fail fast for the cooldown
    // instead of spawning another doomed worker.
    let mut dead: HashMap<(String, u16), Instant> = HashMap::new();
    let pool: RelayPool<FlowKey, Result<RelayOut, ()>> =
        RelayPool::new(POOL_WORKERS, POOL_WORKERS + POOL_QUEUE);
    // Best-effort: without a timeout an idle peer wedges completion
    // draining; failure keeps the old blocking behaviour. Keep writes
    // unbounded (`set_write_timeout(None)`) so large downstream bursts
    // block cleanly in the kernel send queue until window opens.
    let _ = stream.get_mut().set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.get_mut().set_write_timeout(None);
    let mut hb = [0u8; FRAME_HEADER_SIZE];
    let mut hb_filled = 0usize;
    let mut hb_since: Option<Instant> = None;
    loop {
        while hb_filled < FRAME_HEADER_SIZE {
            match read_tls_step(stream, &mut hb[hb_filled..]) {
                Ok(0) => {
                    debug_log("tunnel: header eof, closing");
                    return "header eof".to_string();
                }
                Ok(n) => {
                    hb_filled += n;
                    if hb_filled < FRAME_HEADER_SIZE {
                        hb_since.get_or_insert_with(Instant::now);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    if let Some(since) = hb_since {
                        if since.elapsed() > BODY_TOTAL_TIMEOUT {
                            debug_log("tunnel: header stall, closing");
                            return "header stall past 30s".to_string();
                        }
                    }
                    if !drain_completions(
                        &pool,
                        &stream_rx,
                        &mut sess,
                        stream,
                        routes,
                        &mut workers,
                        &mut dead,
                    ) {
                        return end_reason("reply write failed during idle drain");
                    }
                }
                Err(e) => {
                    debug_log(&format!("tunnel: header read error ({e}), closing"));
                    return format!("header read error: {e}");
                }
            }
        }
        hb_filled = 0;
        hb_since = None;
        let mut hbuf = BytesMut::from(&hb[..]);
        let header = match FrameHeader::decode(&mut hbuf) {
            Ok(h) => h,
            Err(e) => return format!("bad frame header: {e}"),
        };
        if header.length as usize > 65535 + 1024 {
            return format!("absurd frame length: {}", header.length);
        }
        // Body: tolerate stalls past the read quantum and EINTR signals from
        // the host runtime (e.g. .NET CoreCLR GC suspension on Linux, which
        // never auto-restarts `recv` when `SO_RCVTIMEO` is set). Drain worker
        // completions during inter-segment gaps so replies never stall.
        let mut ct = vec![0u8; header.length as usize];
        let body_start = Instant::now();
        let mut filled = 0;
        let mut body_err: Option<String> = None;
        let body_ok = loop {
            if filled >= ct.len() {
                break true;
            }
            match read_tls_step(stream, &mut ct[filled..]) {
                Ok(0) => {
                    body_err = Some("body eof".to_string());
                    break false;
                }
                Ok(n) => {
                    filled += n;
                    if filled >= ct.len() {
                        break true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    if body_start.elapsed() > BODY_TOTAL_TIMEOUT {
                        body_err = Some("body stall past 30s".to_string());
                        break false;
                    }
                    if !drain_completions(
                        &pool,
                        &stream_rx,
                        &mut sess,
                        stream,
                        routes,
                        &mut workers,
                        &mut dead,
                    ) {
                        body_err = Some(end_reason("reply write failed during body wait"));
                        break false;
                    }
                }
                Err(e) => {
                    body_err = Some(format!("body read error: {e}"));
                    break false;
                }
            }
        };
        if !body_ok {
            let why = body_err.unwrap_or_else(|| "body error".to_string());
            debug_log(&format!("tunnel: {why}, closing"));
            return why;
        }
        if crate::debug::debug_enabled() {
            debug_log(&format!(
                "tunnel: {:?} id={} seq={} len={}",
                header.frame_type, header.stream_id, header.sequence, header.length
            ));
        }
        match header.frame_type {
            FrameType::Data => {
                let Some(&target) = routes.get(&header.stream_id) else {
                    // One stray stream (its OPEN was skipped, or the stream
                    // already closed) must not take the whole tunnel down —
                    // skip the flow cleanly.
                    debug_log(&format!(
                        "tunnel: data id={} without route, skipping flow",
                        header.stream_id
                    ));
                    continue;
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
                count_up(pt.len());
                // TCP payload (possibly empty): forward to the stream
                // worker, spawning (dialing) on first sight. Full duplex:
                // writes and reads interleave with no pairing or tails.
                let id = header.stream_id;
                match forward_tcp(
                    &pool,
                    &stream_rx,
                    &mut sess,
                    stream,
                    routes,
                    &mut workers,
                    &mut dead,
                    &stream_tx,
                    id,
                    (target.ip().to_string(), target.port()),
                    pt,
                ) {
                    ForwardOutcome::Delivered => {}
                    ForwardOutcome::CloseStream => {
                        if !close_stream(&mut sess, stream, routes, id) {
                            return end_reason("stream close failed after data frame");
                        }
                    }
                    ForwardOutcome::SessionDead => {
                        return end_reason("reply write failed while forwarding upload");
                    }
                }
                if !drain_completions(
                    &pool,
                    &stream_rx,
                    &mut sess,
                    stream,
                    routes,
                    &mut workers,
                    &mut dead,
                ) {
                    return end_reason("reply write failed after data frame");
                }
            }
            FrameType::UdpDatagram => {
                let Some(&target) = routes.get(&header.stream_id) else {
                    // Parity with FrameType::Data: a UDP datagram whose OPEN
                    // was skipped (blocklist, transient DNS error, QUIC/STUN
                    // race during upload) must skip the flow, never kill the
                    // whole tunnel session.
                    debug_log(&format!(
                        "tunnel: datagram id={} without route, skipping flow",
                        header.stream_id
                    ));
                    continue;
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
                if is_unroutable_target(&target) {
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
                // Blocked QNAME: answer empty locally, never burn a
                // worker or leak the query to upstream resolvers.
                if is_virtual {
                    if let Some(qname) = crate::blocklist::dns_query_name(&pt) {
                        if ctx.blocklist.is_blocked(&qname) {
                            debug_log(&format!(
                                "tunnel: datagram id={} DNS {qname} blocked",
                                header.stream_id
                            ));
                            let reply = dns::empty_response(&pt);
                            match send_chunked(&mut sess, stream, header.stream_id, &reply, true) {
                                Ok(()) => {}
                                Err(e) => {
                                    debug_log(&format!(
                                        "tunnel: datagram id={} blocked-reply write failed ({e}), closing",
                                        header.stream_id
                                    ));
                                    return format!("blocked dns reply write failed: {e}");
                                }
                            }
                            continue;
                        }
                    }
                }
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
                    routes,
                    &mut workers,
                    &mut dead,
                ) {
                    return end_reason("reply write failed after udp datagram");
                }
            }
            FrameType::Ping => {
                debug_log("tunnel: ping");
                continue;
            }
            FrameType::GoAway => {
                debug_log("tunnel: goaway, closing");
                return "client sent goaway".to_string();
            }
            FrameType::Rst => {
                if header.stream_id == 0 {
                    debug_log("tunnel: session rst (id=0), closing");
                    return "client sent session rst (id=0)".to_string();
                }
                debug_log(&format!(
                    "tunnel: stream rst id={}, closing stream",
                    header.stream_id
                ));
                workers.remove(&header.stream_id);
                routes.remove(&header.stream_id);
                let _ = sess.mux.close(header.stream_id);
                continue;
            }
            FrameType::OpenTcp => {
                let target = match MuxManager::parse_open_tcp(sess.keys.rx_key(), &header, &ct) {
                    Ok(target) => target,
                    Err(e) => {
                        debug_log(&format!("tunnel: open_tcp parse failed: {e}"));
                        return format!("open_tcp id={} auth/parse failed: {e}", header.stream_id);
                    }
                };
                if ctx.blocklist.is_blocked(&target.addr) {
                    // Unresolved domain target on the list: fail closed
                    // before resolve+dial (also avoids leaking the lookup
                    // to the system resolver). IP literals never match.
                    debug_log(&format!(
                        "tunnel: open_tcp id={} to blocked {}, skipping flow",
                        header.stream_id, target.addr
                    ));
                    continue;
                }
                if workers.remove(&header.stream_id).is_some() {
                    // The peer recycles ids, so this is a new flow on a
                    // fresh id: dropping the sender ends the stale relay
                    // silently (it reports nothing on disconnect).
                    debug_log(&format!(
                        "tunnel: open_tcp id={} recycled, stale worker dropped",
                        header.stream_id
                    ));
                }
                // Re-register: a recycled id carries the old flow's replay
                // window, which would reject the new flow's first 1024
                // frames as stale. OPEN means "new stream", so reset it.
                let _ = sess.mux.close(header.stream_id);
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
                        return format!("open_udp id={} auth/parse failed: {e}", header.stream_id);
                    }
                };
                if ctx.blocklist.is_blocked(&flow.addr) {
                    // Unresolved domain target on the list (the virtual
                    // resolver address itself never matches).
                    debug_log(&format!(
                        "tunnel: open_udp id={} to blocked {}, skipping flow",
                        flow.id, flow.addr
                    ));
                    continue;
                }
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
                            Err(_) => return format!("bad dns upstream port: {primary}"),
                        },
                        None => return format!("bad dns upstream: {primary}"),
                    }
                } else {
                    debug_log(&format!(
                        "tunnel: open_udp id={} -> {}:{}",
                        flow.id, flow.addr, flow.port
                    ));
                    (flow.addr.clone(), flow.port)
                };
                // Same as OPEN_TCP: ids are recycled, so reset the window.
                let _ = sess.mux.close(header.stream_id);
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
            other => {
                debug_log("tunnel: unsupported frame type, closing");
                // WINDOW/AUTH post-handshake: unsupported yet.
                return format!(
                    "unsupported frame type {other:?} id={} len={}",
                    header.stream_id, header.length
                );
            }
        }
    }
}

/// Resolve a dial target announced by the peer (server-side system DNS).
fn dial_addr(addr: &str, port: u16) -> Option<SocketAddr> {
    format!("{addr}:{port}").to_socket_addrs().ok()?.next()
}

/// Max plaintext per TCP reply frame, sized (`16_000` bytes) so
/// `24B FrameHeader + 4B len + 16_000B payload + 128B pad + 16B tag <= 16_384B`
/// fits cleanly inside a single 16 KiB TLS 1.3 record without emitting tiny
/// trailing micro-records on every chunk.
const REPLY_CHUNK: usize = 16_000;

/// Max UDP reply payload sent as one datagram. Datagrams have no reassembly:
/// past IP-carriable size (65507 incl. headers) the reply is undeliverable,
/// so it is dropped with a log and the loop lives on.
const UDP_SINGLE_MAX: usize = 65000;

/// Seal + write one reply, chunked to single-TLS-record wire frames and
/// flushed in one batch.
///
/// Crucially separates **per-stream mux closure** (`MuxError::StreamClosed` /
/// `FlowClosed` when a worker delivers a late reply after `close_stream` or id
/// recycling) from **outer TLS socket `io::Error`**:
/// - Closed inner stream -> skip that flow cleanly (`Ok(())`), NEVER reset the
///   outer tunnel TCP connection!
/// - Outer TLS socket failure -> return `Err(io::Error)` so `tunnel_loop` exits.
fn send_chunked(
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    id: u16,
    payload: &[u8],
    udp: bool,
) -> std::io::Result<()> {
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
        let sealed = match seal_one(sess, payload) {
            Ok(s) => s,
            Err(e) => {
                debug_log(&format!(
                    "tunnel: skip reply on closed flow id={id}: {e}"
                ));
                return Ok(());
            }
        };
        return write_sealed(stream, &sealed.header, &sealed.ciphertext);
    }
    let chunks = payload.chunks(REPLY_CHUNK);
    let mut batch = BytesMut::with_capacity(payload.len() + chunks.len() * 256);
    for chunk in chunks {
        let sealed = match seal_one(sess, chunk) {
            Ok(s) => s,
            Err(e) => {
                debug_log(&format!(
                    "tunnel: skip reply on closed stream id={id}: {e}"
                ));
                return Ok(());
            }
        };
        sealed.header.encode(&mut batch);
        batch.extend_from_slice(&sealed.ciphertext);
    }
    write_tls_all(stream, &batch)
}

/// Seal + write one DATA reply; Err carries outer TLS transport failure only.
fn send_data(
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    id: u16,
    payload: &[u8],
) -> std::io::Result<()> {
    send_chunked(sess, stream, id, payload, false)
}

/// Write one sealed frame in a single TLS record write; Err on transport failure.
fn write_sealed(
    stream: &mut tls::ServerTlsStream,
    header: &FrameHeader,
    ct: &[u8],
) -> std::io::Result<()> {
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + ct.len());
    header.encode(&mut buf);
    buf.extend_from_slice(ct);
    write_tls_all(stream, &buf)
}

/// Flush all pending encrypted bytes from `stream.conn` into `stream.sock`
/// without calling `read_tls` (`StreamOwned::write_all`/`flush` call
/// `complete_prior_io()`, which reads `stream.sock` and spuriously trips the
/// 5ms `SO_RCVTIMEO` read timeout as `Err(WouldBlock)` during writes!).
/// Retries `ErrorKind::Interrupted` and transient `WouldBlock`/`TimedOut`
/// stalls so active downloads/uploads never drop the session.
fn flush_tls_writes(stream: &mut tls::ServerTlsStream) -> std::io::Result<()> {
    let mut stalled_since: Option<Instant> = None;
    while stream.conn.wants_write() {
        match stream.conn.write_tls(&mut stream.sock) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "tls socket write returned 0",
                ));
            }
            Ok(_) => {
                stalled_since = None;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                let since = *stalled_since.get_or_insert_with(Instant::now);
                if since.elapsed() > BODY_TOTAL_TIMEOUT {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Encrypt all of `plain` in chunks that respect `rustls`'s internal send
/// buffer capacity (`sendable_tls` returns short writes + `Ok(0)` once full
/// until `write_tls` drains ciphertext to the socket!), flushing between
/// slices and at the end without ever touching the receive path.
fn write_tls_all(stream: &mut tls::ServerTlsStream, mut plain: &[u8]) -> std::io::Result<()> {
    while !plain.is_empty() {
        flush_tls_writes(stream)?;
        match stream.conn.writer().write(plain) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "tls writer returned 0 after full flush",
                ));
            }
            Ok(n) => plain = &plain[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    flush_tls_writes(stream)
}

/// Read decrypted plaintext bytes from `stream`, advancing TLS deframing on
/// `stream.sock` when needed while retrying `Interrupted` and preserving the
/// socket's `SO_RCVTIMEO` (`TimedOut`/`WouldBlock`) exclusively for reads.
fn read_tls_step(stream: &mut tls::ServerTlsStream, dst: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match stream.conn.reader().read(dst) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        flush_tls_writes(stream)?;
        match stream.conn.read_tls(&mut stream.sock) {
            Ok(0) => return Ok(0),
            Ok(_) => {
                stream
                    .conn
                    .process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}
