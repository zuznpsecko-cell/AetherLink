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
/// Maximum mux frames coalesced into a single `rustls::Writer` batch (~2 full
/// 16 KiB TLS 1.3 records per `write_tls` burst).
const TLS_BATCH_FRAMES: usize = 32;
const TLS_BATCH_BYTES: usize = 32 * 1024;
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
    let mut hb = BytesMut::new();
    header.encode(&mut hb);
    w.write_all(&hb)?;
    w.write_all(ciphertext)?;
    w.flush()
}

/// Read one sealed frame (blocking; set a read timeout to stay stoppable).
///
/// Truncated headers, undecodable headers and absurd lengths are
/// `InvalidData`: fail closed, never allocate-and-wait on attacker lengths.
pub fn read_sealed<R: Read>(r: &mut R) -> std::io::Result<(FrameHeader, Vec<u8>)> {
    use std::io::{Error, ErrorKind};
    let mut hb = [0u8; FRAME_HEADER_SIZE];
    r.read_exact(&mut hb)?;
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
    /// Second handle to the wire socket, used only to unblock the threads
    /// on `stop()` (a blocked read/write cannot see the stop flag).
    sock: Option<TcpStream>,
}

impl PumpHandle {
    /// Signal stop and join all threads; safe to call twice.
    pub fn stop(&mut self) {
        aetherlink_netstack::debug_log("pump: stop requested");
        self.stop.store(true, Ordering::SeqCst);
        // Shut the socket first: a thread parked in a read/write on a dead
        // peer wakes up with an error instead of holding the join hostage.
        if let Some(sock) = self.sock.take() {
            let _ = sock.shutdown(std::net::Shutdown::Both);
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
        sock: Some(shutdown_side),
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
    use std::io::ErrorKind;

    let ConnectedTunnel { mut stream, sess } = tunnel;
    let _ = stream.sock.set_nodelay(true);
    let shutdown_side = stream.sock.try_clone()?;
    stream.sock.set_nonblocking(true)?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_loop = Arc::clone(&stop);
    aetherlink_netstack::debug_log("pump: tls nonblocking thread spawned");
    let thread = std::thread::spawn(move || {
        let mut pump = DataPump::with_mux(sess.mux, *sess.keys.tx_key(), *sess.keys.rx_key(), pad);
        let mut outbox: VecDeque<SealedFrame> = VecDeque::with_capacity(TLS_OUTBOX_MAX);
        let mut tx_buf = BytesMut::with_capacity(TLS_BATCH_BYTES + 2048);
        let mut rx_buf = BytesMut::with_capacity(65536);
        let mut plain_buf = [0u8; 32768];
        let mut write_stalled_since: Option<Instant> = None;
        let mut rx_partial_since: Option<Instant> = None;
        let mut last_tx = Instant::now();

        loop {
            if stop_loop.load(Ordering::SeqCst) {
                break;
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
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tls write failed ({e}), thread ends"
                    ));
                    break;
                }
            }

            // 2. Drain inbound TUN packets into `outbox` without doing network I/O
            //    under `tun.lock()`.
            if outbox.len() < TLS_OUTBOX_MAX {
                match tun.lock() {
                    Ok(mut guard) => match pump.poll_once(&mut *guard) {
                        Ok(frames) => {
                            if !frames.is_empty() {
                                progressed = true;
                                aetherlink_netstack::debug_log(&format!(
                                    "pump: tls tun->outbox {} frame(s)",
                                    frames.len()
                                ));
                                outbox.extend(frames);
                            }
                        }
                        Err(e) => {
                            aetherlink_netstack::debug_log(&format!(
                                "pump: tls tun drain error: {e}, continuing"
                            ));
                            pump.flush_acks(&mut *guard);
                        }
                    },
                    Err(_) => {
                        aetherlink_netstack::debug_log("pump: tls lock failed, thread ends");
                        break;
                    }
                }
            }

            // 3. Coalesce queued frames into full TLS records ONLY while rustls
            //    has flushed prior records to the socket — tying TCP ACKs and
            //    window sizing directly to real uplink drain speed.
            for _ in 0..4 {
                if stream.conn.wants_write() || outbox.is_empty() {
                    break;
                }
                tx_buf.clear();
                let mut batch = 0usize;
                while batch < TLS_BATCH_FRAMES && tx_buf.len() < TLS_BATCH_BYTES {
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
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tls writer failed ({e}), thread ends"
                    ));
                    return;
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
                        aetherlink_netstack::debug_log("pump: tls lock failed, thread ends");
                        return;
                    }
                }
                if let Err(e) = write_res {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tls write failed ({e}), thread ends"
                    ));
                    return;
                }
            }

            // 4. Periodic idle keepalive so NATs and middleboxes keep state warm.
            if !stream.conn.wants_write()
                && outbox.is_empty()
                && last_tx.elapsed() >= TLS_KEEPALIVE_INTERVAL
            {
                tx_buf.clear();
                FrameHeader {
                    length: 0,
                    frame_type: FrameType::Ping,
                    flags: 0,
                    stream_id: 0,
                    sequence: 0,
                }
                .encode(&mut tx_buf);
                let _ = stream.conn.writer().write_all(&tx_buf);
                last_tx = Instant::now();
                if let Err(e) = flush_tls_writes(&mut stream, &mut write_stalled_since) {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tls keepalive write failed ({e}), thread ends"
                    ));
                    break;
                }
            }

            // 5. Non-blocking read of all available TLS records + buffered plaintext.
            let mut peer_eof = false;
            for _ in 0..32 {
                match stream.conn.read_tls(&mut stream.sock) {
                    Ok(0) => {
                        peer_eof = true;
                        break;
                    }
                    Ok(_) => {
                        progressed = true;
                        rx_partial_since = None;
                        if let Err(e) = stream.conn.process_new_packets() {
                            aetherlink_netstack::debug_log(&format!(
                                "pump: tls protocol error ({e}), thread ends"
                            ));
                            peer_eof = true;
                            break;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e)
                        if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(e) => {
                        aetherlink_netstack::debug_log(&format!(
                            "pump: tls read failed ({e}), ends"
                        ));
                        peer_eof = true;
                        break;
                    }
                }
            }

            loop {
                match stream.conn.reader().read(&mut plain_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        progressed = true;
                        rx_buf.extend_from_slice(&plain_buf[..n]);
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => {
                        aetherlink_netstack::debug_log(&format!(
                            "pump: tls plaintext read failed ({e}), ends"
                        ));
                        peer_eof = true;
                        break;
                    }
                }
            }

            // 6. Decode all complete mux frames from `rx_buf` and inject them.
            let mut decoded: Vec<(FrameHeader, BytesMut)> = Vec::new();
            let mut fatal = false;
            while rx_buf.len() >= FRAME_HEADER_SIZE {
                let mut hdr_slice = BytesMut::from(&rx_buf[..FRAME_HEADER_SIZE]);
                let header = match FrameHeader::decode(&mut hdr_slice) {
                    Ok(h) => h,
                    Err(e) => {
                        aetherlink_netstack::debug_log(&format!(
                            "pump: tls bad frame header ({e}), ends"
                        ));
                        fatal = true;
                        break;
                    }
                };
                if header.length as usize > MAX_WIRE_BODY {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tls absurd frame length {}, ends",
                        header.length
                    ));
                    fatal = true;
                    break;
                }
                let total = FRAME_HEADER_SIZE + header.length as usize;
                if rx_buf.len() < total {
                    let since = *rx_partial_since.get_or_insert_with(Instant::now);
                    if since.elapsed() > BODY_TOTAL_TIMEOUT {
                        aetherlink_netstack::debug_log("pump: tls body stalled, ends");
                        fatal = true;
                    }
                    break;
                }
                rx_partial_since = None;
                let _ = rx_buf.split_to(FRAME_HEADER_SIZE);
                let ct = rx_buf.split_to(header.length as usize);
                decoded.push((header, ct));
            }

            if fatal {
                break;
            }

            match tun.lock() {
                Ok(mut guard) => {
                    for (header, ct) in &decoded {
                        aetherlink_netstack::debug_log(&format!(
                            "pump: tls wire {:?} id={} len={}",
                            header.frame_type, header.stream_id, header.length
                        ));
                        if let Err(e) = pump.receive_mux(header, ct, &mut *guard) {
                            aetherlink_netstack::debug_log(&format!(
                                "pump: tls frame dropped: {e}"
                            ));
                        }
                    }
                    pump.flush_acks(&mut *guard);
                }
                Err(_) => {
                    aetherlink_netstack::debug_log("pump: tls lock failed, thread ends");
                    break;
                }
            }

            if peer_eof {
                aetherlink_netstack::debug_log("pump: tls peer closed stream");
                break;
            }

            if !progressed {
                std::thread::sleep(TLS_IDLE_POLL);
            }
        }
        aetherlink_netstack::debug_log("pump: tls thread joined");
    });
    Ok(PumpHandle {
        stop,
        threads: vec![thread],
        sock: Some(shutdown_side),
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
