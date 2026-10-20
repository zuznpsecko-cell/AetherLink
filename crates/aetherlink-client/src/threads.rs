//! Pump threads: TUN<->wire bridge on two background threads (Phase W4).
//!
//! `spawn_pump` takes a shared TUN handle plus a connected stream (localhost
//! TCP in tests; the same framing helpers serve a TLS stream in production).
//! TUN->wire seals with `tx`, wire->TUN opens with `rx` (session traffic
//! keys). `stop()` is idempotent and joins; the wire thread's 200ms read
//! timeout keeps it stoppable, EOF/transport errors end it fail-closed.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::BytesMut;

use aetherlink_frame::{codec::FrameHeader, FRAME_HEADER_SIZE};
use aetherlink_mux::manager::SealedFrame;
use aetherlink_netstack::tun::TunPackets;
use aetherlink_protocol::FrameType;

use crate::lifecycle::ConnectedTunnel;
use crate::pump::DataPump;

/// Read timeout so the plain-TCP wire thread polls the stop flag instead of blocking.
const READ_TIMEOUT: Duration = Duration::from_millis(10);
/// Idle poll sleep when neither TUN nor non-blocking TLS socket made progress.
const TLS_IDLE_POLL: Duration = Duration::from_millis(1);
/// Bound for one frame body across stalls (fail closed eventually).
const BODY_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle sleep in the plain-TCP TUN->wire loop.
const TUN_IDLE: Duration = Duration::from_millis(10);
/// Absurd ciphertext length: fail closed instead of allocating.
const MAX_WIRE_BODY: usize = 65535 + 1024;
/// Write stall bound on the plain-TCP pump.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard stall bound on the non-blocking TLS socket when zero encrypted bytes
/// move across the kernel send buffer for an extended period (dead cable/path).
const TLS_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Soft upper bound on frames held in the client TLS outbox at once so `DataPump`
/// backpressure (`in_flight` / advertised TCP window) paces local sockets smoothly.
const TLS_OUTBOX_MAX: usize = 512;
/// Maximum mux bytes coalesced into a single `rustls::Writer` batch so normal
/// MTU frames pack cleanly into one 16 KiB TLS 1.3 record without splitting
/// a 24-byte `FrameHeader` across two TLS records.
const TLS_BATCH_FRAMES: usize = 32;
const TLS_BATCH_BYTES: usize = 16 * 1024;
/// Periodic mux `PING` interval when no upload frames have been sent recently.
const TLS_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Write one sealed frame: 24B header + ciphertext.
///
/// `io::Result` (not the crate error) so callers keep `ErrorKind`
/// (timeouts vs EOF); protocol misuse cannot happen here by construction.
pub fn write_sealed<W: Write>(
    w: &mut W,
    header: &FrameHeader,
    ciphertext: &[u8],
) -> std::io::Result<()> {
    let mut hb = BytesMut::with_capacity(FRAME_HEADER_SIZE + ciphertext.len());
    header.encode(&mut hb);
    hb.extend_from_slice(ciphertext);
    w.write_all(&hb)?;
    w.flush()
}

/// Read one sealed frame (blocking; set a read timeout to stay stoppable).
///
/// Truncated headers, undecodable headers and absurd lengths are
/// `InvalidData`: fail closed, never allocate-and-wait on attacker lengths.
pub fn read_sealed<R: Read>(r: &mut R) -> std::io::Result<(FrameHeader, Vec<u8>)> {
    use std::io::{Error, ErrorKind};
    let mut hb = [0u8; FRAME_HEADER_SIZE];
    let hdr_start = std::time::Instant::now();
    let mut hb_filled = 0usize;
    while hb_filled < FRAME_HEADER_SIZE {
        match r.read(&mut hb[hb_filled..]) {
            Ok(0) => {
                if hb_filled == 0 {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "header eof"));
                }
                return Err(Error::new(ErrorKind::UnexpectedEof, "truncated header"));
            }
            Ok(n) => hb_filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                if hb_filled == 0 {
                    return Err(e);
                }
                if hdr_start.elapsed() > BODY_TOTAL_TIMEOUT {
                    return Err(Error::new(ErrorKind::TimedOut, "header stall"));
                }
            }
            Err(e) => return Err(e),
        }
    }
    let mut hbuf = BytesMut::from(&hb[..]);
    let header = FrameHeader::decode(&mut hbuf)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("bad frame header: {e}")))?;
    if header.length as usize > MAX_WIRE_BODY {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("absurd frame length {}", header.length),
        ));
    }
    // Body: tolerate stalls past the read quantum (a 64KB body is many
    // TCP segments; any gap tripping the timeout must resume, not abort —
    // seen live: "body eof, closing" killed healthy sessions). Position is
    // tracked so resumed reads never lose bytes. Bounded: a peer dribbling
    // forever still fails closed, just later.
    let mut ct = vec![0u8; header.length as usize];
    let start = std::time::Instant::now();
    let mut filled = 0;
    while filled < ct.len() {
        match r.read(&mut ct[filled..]) {
            Ok(0) => {
                return Err(Error::new(ErrorKind::UnexpectedEof, "body eof"));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                if start.elapsed() > BODY_TOTAL_TIMEOUT {
                    return Err(Error::new(ErrorKind::TimedOut, "body stall"));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok((header, ct))
}

/// Running pump: flip the flag + join (idempotent, also on drop).
pub struct PumpHandle {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    /// Second handle to the active wire socket, used only to unblock threads
    /// on `stop()` (updated across transparent TLS auto-reconnects).
    sock: Arc<Mutex<Option<TcpStream>>>,
    /// Non-secret diagnostic recorded when a pump thread exits on its own.
    exit_reason: Arc<Mutex<Option<String>>>,
}

impl PumpHandle {
    /// Signal stop and join all threads; safe to call twice.
    pub fn stop(&mut self) {
        aetherlink_netstack::debug_log("pump: stop requested");
        self.stop.store(true, Ordering::SeqCst);
        // Shut the socket first: a thread parked in a read/write on a dead
        // peer wakes up with an error instead of holding the join hostage.
        if let Ok(mut guard) = self.sock.lock() {
            if let Some(sock) = guard.take() {
                let _ = sock.shutdown(std::net::Shutdown::Both);
            }
        }
        while let Some(h) = self.threads.pop() {
            let _ = h.join();
        }
        aetherlink_netstack::debug_log("pump: stopped");
    }

    /// True while every pump thread is still running. A finished thread
    /// means the wire or TUN side ended: the session is dead even though
    /// routes/DNS are still applied, so callers must tear it down.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        !self.threads.is_empty() && self.threads.iter().all(|h| !h.is_finished())
    }

    /// Non-secret diagnostic explaining why the pump exited, if known.
    #[must_use]
    pub fn exit_reason(&self) -> Option<String> {
        self.exit_reason.lock().ok().and_then(|g| g.clone())
    }
}

impl Drop for PumpHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn TUN->wire and wire->TUN threads over `stream`.
///
/// The stream needs a read timeout (set here); `tun` is shared behind its
/// mutex with the caller. Tampered wire frames are dropped without killing
/// the loop; transport EOF/errors end the wire thread fail-closed.
pub fn spawn_pump<T>(
    tun: Arc<Mutex<T>>,
    stream: TcpStream,
    tx: [u8; 32],
    rx: [u8; 32],
    pad: usize,
) -> std::io::Result<PumpHandle>
where
    T: TunPackets + Send + 'static,
{
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let read_side = stream.try_clone()?;
    let shutdown_side = stream.try_clone()?;
    let mut write_side = stream;
    let stop = Arc::new(AtomicBool::new(false));
    let pump = Arc::new(Mutex::new(DataPump::new_split(tx, rx, pad)));
    aetherlink_netstack::debug_log(&format!("pump: spawned (pad {pad})"));

    // TUN -> wire: drain TUN, seal, write.
    let (stop_tun, pump_tun, tun_tun) = (Arc::clone(&stop), Arc::clone(&pump), Arc::clone(&tun));
    let tun_thread = std::thread::spawn(move || {
        while !stop_tun.load(Ordering::SeqCst) {
            // `None` = lock poisoned (fatal); `Some(Err(..))` = one bad
            // packet, which must never end the session.
            let frames = (|| {
                let mut tun_guard = tun_tun.lock().ok()?;
                let mut pump_guard = pump_tun.lock().ok()?;
                Some(pump_guard.poll_once(&mut *tun_guard))
            })();
            match frames {
                Some(Err(e)) => {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tun drain error: {e}, continuing"
                    ));
                    std::thread::sleep(TUN_IDLE);
                }
                Some(Ok(fs)) => {
                    if !fs.is_empty() {
                        aetherlink_netstack::debug_log(&format!(
                            "pump: tun->wire {} frame(s)",
                            fs.len()
                        ));
                    }
                    let mut ok = true;
                    for f in &fs {
                        if write_sealed(&mut write_side, &f.header, &f.ciphertext).is_err() {
                            aetherlink_netstack::debug_log(
                                "pump: wire write failed, tun thread ends",
                            );
                            ok = false;
                            break;
                        }
                    }
                    if !ok {
                        break;
                    }
                    // These frames are gone: free the upload buffer and
                    // confirm them to the app (never confirm earlier — see
                    // DataPump::flush_acks).
                    {
                        let mut pump_guard = pump_tun.lock().ok();
                        let mut tun_guard = tun_tun.lock().ok();
                        if let (Some(p), Some(t)) =
                            (pump_guard.as_deref_mut(), tun_guard.as_deref_mut())
                        {
                            p.frames_written(fs.len());
                            p.flush_acks(t);
                        }
                    }
                    if fs.is_empty() {
                        std::thread::sleep(TUN_IDLE);
                    }
                }
                None => {
                    aetherlink_netstack::debug_log("pump: lock failed, tun thread ends");
                    break;
                }
            }
        }
        aetherlink_netstack::debug_log("pump: tun thread joined");
    });

    // Wire -> TUN: read, open, inject; timeouts just re-poll the stop flag.
    let (stop_wire, pump_wire, tun_wire) = (Arc::clone(&stop), Arc::clone(&pump), tun);
    let wire_thread = std::thread::spawn(move || {
        let mut reader = read_side;
        loop {
            if stop_wire.load(Ordering::SeqCst) {
                break;
            }
            match read_sealed(&mut reader) {
                Ok((header, ct)) => {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: wire {:?} id={} len={}",
                        header.frame_type, header.stream_id, header.length
                    ));
                    let injected = (|| {
                        let mut tun_guard = tun_wire.lock().ok()?;
                        let mut pump_guard = pump_wire.lock().ok()?;
                        Some(pump_guard.receive_mux(&header, &ct, &mut *tun_guard))
                    })();
                    match injected {
                        Some(Ok(())) => aetherlink_netstack::debug_log("pump: wire->tun injected"),
                        // Tamper/unknown id dropped, loop lives.
                        Some(Err(e)) => aetherlink_netstack::debug_log(&format!(
                            "pump: wire frame dropped: {e}"
                        )),
                        None => {
                            aetherlink_netstack::debug_log("pump: lock failed, wire thread ends");
                            break; // lock poisoned: fail closed
                        }
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(e) => {
                    aetherlink_netstack::debug_log(&format!("pump: wire read failed ({e}), ends"));
                    break;
                }
            }
        }
        aetherlink_netstack::debug_log("pump: wire thread joined");
    });

    Ok(PumpHandle {
        stop,
        threads: vec![tun_thread, wire_thread],
        sock: Arc::new(Mutex::new(Some(shutdown_side))),
        exit_reason: Arc::new(Mutex::new(None)),
    })
}

/// Push queued TLS records from `stream.conn` out to the non-blocking socket.
///
/// `WouldBlock`/`TimedOut` on a temporarily full kernel send buffer is normal
/// during upload bursts and NEVER kills the session unless zero bytes move for
/// longer than `TLS_WRITE_STALL_TIMEOUT`.
fn flush_tls_writes(
    stream: &mut aetherlink_core::tls::ClientTlsStream,
    stalled_since: &mut Option<Instant>,
) -> std::io::Result<usize> {
    use std::io::{Error, ErrorKind};
    let mut written = 0usize;
    while stream.conn.wants_write() {
        match stream.conn.write_tls(&mut stream.sock) {
            Ok(0) => {
                return Err(Error::new(ErrorKind::WriteZero, "tls socket write zero"));
            }
            Ok(n) => {
                written += n;
                *stalled_since = None;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                let since = *stalled_since.get_or_insert_with(Instant::now);
                if since.elapsed() > TLS_WRITE_STALL_TIMEOUT {
                    return Err(Error::new(ErrorKind::TimedOut, "tls write stalled"));
                }
                break;
            }
            Err(e) => return Err(e),
        }
    }
    if !stream.conn.wants_write() {
        *stalled_since = None;
    }
    Ok(written)
}

/// Spawn the non-blocking full-duplex pump inside an established TLS session.
///
/// Runs both directions non-blockingly on a single owner thread:
/// - Upload frames are pulled from TUN without holding `tun.lock()` across
///   socket syscalls, coalesced into full TLS 1.3 records, and only confirmed
///   (`frames_written` + `flush_acks`) as ciphertext actually enters the socket.
/// - Download TLS records are drained continuously even when the upload socket
///   send buffer is full (`WouldBlock`), decoding multiple frames per turn from
///   a persistent `BytesMut` buffer without head-of-line stalls.
pub fn spawn_pump_tls<T>(
    tun: Arc<Mutex<T>>,
    tunnel: ConnectedTunnel,
    pad: usize,
) -> std::io::Result<PumpHandle>
where
    T: TunPackets + Send + 'static,
{
    spawn_pump_tls_resilient::<T, fn() -> crate::Result<ConnectedTunnel>>(tun, tunnel, pad, None)
}

/// Spawn the non-blocking full-duplex TLS pump with optional automatic transport
/// re-dialing (`reconnect`) on unexpected outer TCP/TLS drops (`os error 10054`,
/// CGNAT timeout, middlebox reset, or transient link loss).
pub fn spawn_pump_tls_resilient<T, R>(
    tun: Arc<Mutex<T>>,
    tunnel: ConnectedTunnel,
    pad: usize,
    reconnect: Option<R>,
) -> std::io::Result<PumpHandle>
where
    T: TunPackets + Send + 'static,
    R: Fn() -> crate::Result<ConnectedTunnel> + Send + 'static,
{
    use std::io::ErrorKind;

    let ConnectedTunnel { mut stream, sess } = tunnel;
    let _ = stream.sock.set_nodelay(true);
    let _ = stream.sock.set_read_timeout(None);
    let _ = stream.sock.set_write_timeout(None);
    let shutdown_side = stream.sock.try_clone()?;
    stream.sock.set_nonblocking(true)?;

    let sock_slot = Arc::new(Mutex::new(Some(shutdown_side)));
    let sock_loop = Arc::clone(&sock_slot);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_loop = Arc::clone(&stop);
    let exit_reason: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let exit_loop = Arc::clone(&exit_reason);
    aetherlink_netstack::debug_log("pump: tls nonblocking thread spawned");
    let thread = std::thread::spawn(move || {
        const RECONNECT_BACKOFF_MS: [u64; 8] = [50, 150, 300, 600, 1000, 1500, 2000, 2500];

        let record_exit = |reason: String| {
            aetherlink_netstack::debug_log(&format!("pump: tls exit: {reason}"));
            if let Ok(mut g) = exit_loop.lock() {
                if g.is_none() {
                    *g = Some(reason);
                }
            }
        };

        let mut pump = DataPump::with_mux(sess.mux, *sess.keys.tx_key(), *sess.keys.rx_key(), pad);
        let mut outbox: VecDeque<SealedFrame> = VecDeque::with_capacity(TLS_OUTBOX_MAX);
        let mut tx_buf = BytesMut::with_capacity(TLS_BATCH_BYTES + 2048);
        let mut rx_buf = BytesMut::with_capacity(65536);
        let mut write_stalled_since: Option<Instant> = None;
        let mut rx_partial_since: Option<Instant> = None;
        let mut last_tx = Instant::now();

        // Drain any post-handshake plaintext bytes buffered alongside ServerAuthOk.
        if let Ok(state) = stream.conn.process_new_packets() {
            let avail = state.plaintext_bytes_to_read();
            if avail > 0 {
                let start = rx_buf.len();
                rx_buf.resize(start + avail, 0);
                let _ = stream.conn.reader().read_exact(&mut rx_buf[start..]);
            }
        }

        'session: loop {
            let drop_reason: String = 'pump: loop {
                if stop_loop.load(Ordering::SeqCst) {
                    break 'session;
                }
                let mut progressed = false;

                // 1. Drain any pending encrypted TLS bytes into the OS TCP socket.
                match flush_tls_writes(&mut stream, &mut write_stalled_since) {
                    Ok(n) => {
                        if n > 0 {
                            progressed = true;
                        }
                    }
                    Err(e) => {
                        break 'pump format!("tls socket write failed: {e}");
                    }
                }

            // 2. Always drain inbound TUN packets into `outbox` and flush
            //    immediate `RCV.NXT + RCV.WND` ACKs so local `tcpip.sys` streams
            //    pace smoothly on window updates without false 10ms RTO livelocks
            //    and interactive flows are never head-of-line blocked in Wintun.
            match tun.lock() {
                Ok(mut guard) => match pump.poll_once(&mut *guard) {
                    Ok(frames) => {
                        if !frames.is_empty() {
                            progressed = true;
                            if aetherlink_netstack::debug::debug_enabled() {
                                aetherlink_netstack::debug_log(&format!(
                                    "pump: tls tun->outbox {} frame(s)",
                                    frames.len()
                                ));
                            }
                            outbox.extend(frames);
                        }
                        pump.flush_acks(&mut *guard);
                    }
                    Err(e) => {
                        aetherlink_netstack::debug_log(&format!(
                            "pump: tls tun drain error: {e}, continuing"
                        ));
                        pump.flush_acks(&mut *guard);
                    }
                },
                Err(_) => {
                    record_exit("tun mutex poisoned".to_string());
                    break 'session;
                }
            }

            // 3. Coalesce queued frames into full 16 KiB TLS records while the
            //    socket send buffer accepts data (up to 1 MiB per turn), issuing
            //    window-update ACKs as each batch enters the WAN socket.
            for _ in 0..64 {
                if stream.conn.wants_write() || outbox.is_empty() {
                    break;
                }
                tx_buf.clear();
                let mut batch = 0usize;
                while batch < TLS_BATCH_FRAMES {
                    let Some(front) = outbox.front() else {
                        break;
                    };
                    let wire_len = FRAME_HEADER_SIZE + front.ciphertext.len();
                    if batch > 0 && tx_buf.len() + wire_len > TLS_BATCH_BYTES {
                        break;
                    }
                    let Some(f) = outbox.pop_front() else {
                        break;
                    };
                    f.header.encode(&mut tx_buf);
                    tx_buf.extend_from_slice(&f.ciphertext);
                    batch += 1;
                }
                if batch == 0 {
                    break;
                }
                if let Err(e) = stream.conn.writer().write_all(&tx_buf) {
                    break 'pump format!("tls plaintext writer failed: {e}");
                }
                last_tx = Instant::now();
                progressed = true;

                let write_res = flush_tls_writes(&mut stream, &mut write_stalled_since);
                match tun.lock() {
                    Ok(mut guard) => {
                        pump.frames_written(batch);
                        pump.flush_acks(&mut *guard);
                    }
                    Err(_) => {
                        record_exit("tun mutex poisoned".to_string());
                        break 'session;
                    }
                }
                if let Err(e) = write_res {
                    break 'pump format!("tls socket write failed: {e}");
                }
            }

                // 4. Periodic idle keepalive so NATs and middleboxes keep state warm.
                //    Includes a 16-byte zero body so older servers that read non-empty
                //    frame bodies directly do not misread `read(&mut []) -> Ok(0)` as EOF.
                if !stream.conn.wants_write()
                    && outbox.is_empty()
                    && last_tx.elapsed() >= TLS_KEEPALIVE_INTERVAL
                {
                    tx_buf.clear();
                    FrameHeader {
                        length: 16,
                        frame_type: FrameType::Ping,
                        flags: 0,
                        stream_id: 0,
                        sequence: 0,
                    }
                    .encode(&mut tx_buf);
                    tx_buf.extend_from_slice(&[0u8; 16]);
                    let _ = stream.conn.writer().write_all(&tx_buf);
                    last_tx = Instant::now();
                    if let Err(e) = flush_tls_writes(&mut stream, &mut write_stalled_since) {
                        break 'pump format!("tls keepalive write failed: {e}");
                    }
                }

                // 5. Non-blocking read of available TLS records + exact buffered plaintext.
                //    `process_new_packets()` + `read_exact` MUST run inside every `Ok(_)`
                //    iteration so `rustls`'s ~16.6 KB `DeframerVecBuffer` never fills up
                //    during a multi-record burst (which otherwise causes `read_tls` to pass
                //    `&mut []` to `TcpStream::read` and get a false `Ok(0)` EOF!).
                let mut peer_eof: Option<String> = None;
                for _ in 0..32 {
                    match stream.conn.read_tls(&mut stream.sock) {
                        Ok(0) => {
                            peer_eof = Some("server closed TLS connection (EOF)".to_string());
                            break;
                        }
                        Ok(_) => {
                            progressed = true;
                            rx_partial_since = None;
                            match stream.conn.process_new_packets() {
                                Ok(state) => {
                                    let avail = state.plaintext_bytes_to_read();
                                    if avail > 0 {
                                        let start = rx_buf.len();
                                        rx_buf.resize(start + avail, 0);
                                        if let Err(e) =
                                            stream.conn.reader().read_exact(&mut rx_buf[start..])
                                        {
                                            peer_eof =
                                                Some(format!("tls plaintext read failed: {e}"));
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    peer_eof = Some(format!("tls protocol error: {e}"));
                                    break;
                                }
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                        Err(e)
                            if e.kind() == ErrorKind::WouldBlock
                                || e.kind() == ErrorKind::TimedOut =>
                        {
                            break;
                        }
                        Err(e) => {
                            peer_eof = Some(format!("tls socket read failed: {e}"));
                            break;
                        }
                    }
                }

                // 6. Decode all complete mux frames from `rx_buf` and inject them.
                let mut decoded: Vec<(FrameHeader, BytesMut)> = Vec::new();
                let mut fatal: Option<String> = None;
                while rx_buf.len() >= FRAME_HEADER_SIZE {
                    let mut hdr_slice = BytesMut::from(&rx_buf[..FRAME_HEADER_SIZE]);
                    let header = match FrameHeader::decode(&mut hdr_slice) {
                        Ok(h) => h,
                        Err(e) => {
                            fatal = Some(format!("bad frame header from server: {e}"));
                            break;
                        }
                    };
                    if header.length as usize > MAX_WIRE_BODY {
                        fatal = Some(format!("absurd frame length {}", header.length));
                        break;
                    }
                    let total = FRAME_HEADER_SIZE + header.length as usize;
                    if rx_buf.len() < total {
                        let since = *rx_partial_since.get_or_insert_with(Instant::now);
                        if since.elapsed() > BODY_TOTAL_TIMEOUT {
                            fatal = Some("frame body stalled past 30s".to_string());
                        }
                        break;
                    }
                    rx_partial_since = None;
                    let _ = rx_buf.split_to(FRAME_HEADER_SIZE);
                    let ct = rx_buf.split_to(header.length as usize);
                    decoded.push((header, ct));
                }

                if let Some(reason) = fatal {
                    break 'pump reason;
                }

                if !decoded.is_empty() {
                    match tun.lock() {
                        Ok(mut guard) => {
                            let dbg = aetherlink_netstack::debug::debug_enabled();
                            for (header, ct) in &decoded {
                                if dbg {
                                    aetherlink_netstack::debug_log(&format!(
                                        "pump: tls wire {:?} id={} len={}",
                                        header.frame_type, header.stream_id, header.length
                                    ));
                                }
                                if let Err(e) = pump.receive_mux(header, ct, &mut *guard) {
                                    aetherlink_netstack::debug_log(&format!(
                                        "pump: tls frame dropped: {e}"
                                    ));
                                }
                            }
                            pump.flush_acks(&mut *guard);
                        }
                        Err(_) => {
                            record_exit("tun mutex poisoned".to_string());
                            break 'session;
                        }
                    }
                }

                if let Some(reason) = peer_eof {
                    break 'pump reason;
                }

                if !progressed {
                    std::thread::sleep(TLS_IDLE_POLL);
                }
            };

            if stop_loop.load(Ordering::SeqCst) {
                break 'session;
            }

            let Some(ref dial) = reconnect else {
                record_exit(drop_reason);
                break 'session;
            };

            aetherlink_netstack::debug_log(&format!(
                "pump: transport dropped ({drop_reason}), attempting transparent reconnect"
            ));
            let mut last_err = String::new();
            let mut recovered = false;
            for (attempt, delay_ms) in RECONNECT_BACKOFF_MS.iter().copied().enumerate() {
                let deadline = Instant::now() + Duration::from_millis(delay_ms);
                while Instant::now() < deadline {
                    if stop_loop.load(Ordering::SeqCst) {
                        break 'session;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                if stop_loop.load(Ordering::SeqCst) {
                    break 'session;
                }
                match dial() {
                    Ok(ConnectedTunnel {
                        stream: mut new_stream,
                        sess: new_sess,
                    }) => {
                        let _ = new_stream.sock.set_nodelay(true);
                        let _ = new_stream.sock.set_read_timeout(None);
                        let _ = new_stream.sock.set_write_timeout(None);
                        let Ok(cloned_sock) = new_stream.sock.try_clone() else {
                            last_err = "try_clone failed on reconnected socket".to_string();
                            continue;
                        };
                        if let Err(e) = new_stream.sock.set_nonblocking(true) {
                            last_err = format!("set_nonblocking failed: {e}");
                            continue;
                        }
                        if let Ok(mut slot) = sock_loop.lock() {
                            *slot = Some(cloned_sock);
                        }
                        outbox.clear();
                        tx_buf.clear();
                        rx_buf.clear();
                        write_stalled_since = None;
                        rx_partial_since = None;
                        last_tx = Instant::now();
                        if let Ok(state) = new_stream.conn.process_new_packets() {
                            let avail = state.plaintext_bytes_to_read();
                            if avail > 0 {
                                rx_buf.resize(avail, 0);
                                let _ = new_stream.conn.reader().read_exact(&mut rx_buf[..avail]);
                            }
                        }
                        match tun.lock() {
                            Ok(mut guard) => {
                                pump.reset_transport(
                                    new_sess.mux,
                                    *new_sess.keys.tx_key(),
                                    *new_sess.keys.rx_key(),
                                    &mut *guard,
                                );
                            }
                            Err(_) => {
                                record_exit("tun mutex poisoned".to_string());
                                break 'session;
                            }
                        }
                        stream = new_stream;
                        aetherlink_netstack::debug_log(&format!(
                            "pump: transparent reconnect succeeded on attempt {}",
                            attempt + 1
                        ));
                        recovered = true;
                        break;
                    }
                    Err(e) => {
                        last_err = e.to_string();
                        aetherlink_netstack::debug_log(&format!(
                            "pump: reconnect attempt {} failed: {last_err}",
                            attempt + 1
                        ));
                    }
                }
            }
            if !recovered {
                record_exit(format!("{drop_reason} (reconnect failed: {last_err})"));
                break 'session;
            }
        }
        aetherlink_netstack::debug_log("pump: tls thread joined");
    });
    Ok(PumpHandle {
        stop,
        threads: vec![thread],
        sock: sock_slot,
        exit_reason,
    })
}

#[cfg(test)]
mod read_tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    /// Yields the header whole, then the body one byte per 300ms
    /// (past the 200ms read quantum): the frame must still assemble.
    struct Dribble {
        chunks: std::collections::VecDeque<Vec<u8>>,
    }
    impl Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.chunks.pop_front() {
                None => Err(Error::new(ErrorKind::TimedOut, "drip")),
                Some(c) => {
                    let n = c.len().min(buf.len());
                    buf[..n].copy_from_slice(&c[..n]);
                    if c.len() > n {
                        self.chunks.push_front(c[n..].to_vec());
                    }
                    if n == 0 {
                        // Stall without EOF: must not abort the frame.
                        std::thread::sleep(Duration::from_millis(300));
                        return Err(Error::new(ErrorKind::TimedOut, "drip"));
                    }
                    Ok(n)
                }
            }
        }
    }

    #[test]
    fn dribbled_body_assembles() {
        use aetherlink_protocol::FrameType;
        let header = FrameHeader {
            length: 3,
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 7,
            sequence: 1,
        };
        let mut hb = BytesMut::new();
        header.encode(&mut hb);
        let mut chunks = std::collections::VecDeque::new();
        chunks.push_back(hb.to_vec());
        chunks.push_back(vec![]); // 300ms stall, then byte by byte
        chunks.push_back(b"A".to_vec());
        chunks.push_back(vec![]);
        chunks.push_back(b"B".to_vec());
        chunks.push_back(vec![]);
        chunks.push_back(b"C".to_vec());
        let mut r = Dribble { chunks };
        let (h, ct) = read_sealed(&mut r).expect("frame assembles");
        assert_eq!(h.stream_id, 7);
        assert_eq!(ct, b"ABC");
    }
}
