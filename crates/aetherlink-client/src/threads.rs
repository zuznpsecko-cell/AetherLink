//! Pump threads: TUN<->wire bridge on two background threads (Phase W4).
//!
//! `spawn_pump` takes a shared TUN handle plus a connected stream (localhost
//! TCP in tests; the same framing helpers serve a TLS stream in production).
//! TUN->wire seals with `tx`, wire->TUN opens with `rx` (session traffic
//! keys). `stop()` is idempotent and joins; the wire thread's 200ms read
//! timeout keeps it stoppable, EOF/transport errors end it fail-closed.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::Duration;

use bytes::BytesMut;

use aetherlink_frame::{codec::FrameHeader, FRAME_HEADER_SIZE};
use aetherlink_netstack::tun::TunPackets;

use crate::lifecycle::ConnectedTunnel;
use crate::pump::DataPump;

/// Read timeout so the wire thread polls the stop flag instead of blocking.
/// Wire-read quantum: bounds per-turn wait on a silent peer (bulk senders
/// must not pay 200ms per turn) and stop latency. Replies still arrive
/// instantly when present; 10ms only prices true idleness.
const READ_TIMEOUT: Duration = Duration::from_millis(10);
/// Same read while the TUN is actively producing: an app in mid-upload
/// gets its device drained again at once instead of paying the idle
/// quantum per turn (the TUN-side and the wire side share one thread).
const READ_TIMEOUT_BUSY: Duration = Duration::from_millis(1);
/// Bound for one frame body across stalls (fail closed eventually).
const BODY_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle sleep in the TUN->wire loop (no busy spin on an empty TUN).
const TUN_IDLE: Duration = Duration::from_millis(10);
/// Absurd ciphertext length: fail closed instead of allocating.
const MAX_WIRE_BODY: usize = 65535 + 1024;
/// Write stall bound. Without it a write to a silently dead peer blocks
/// until the kernel gives up on retransmits (minutes), and `stop()` — and
/// with it `down` — waits on that join while the FFI lock is held.
/// Progress resets the clock per syscall, so a slow but live link is fine.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Spawn the pump inside an established TLS session (production path).
///
/// Single thread owns the TLS stream (rustls has no split halves): each turn
/// drains TUN->wire, then reads one wire frame with the 200ms timeout.
/// Session mux/keys move in (`with_mux`); tamper is dropped, EOF/errors end
/// fail-closed. `stop()` stays idempotent.
pub fn spawn_pump_tls<T>(
    tun: Arc<Mutex<T>>,
    tunnel: ConnectedTunnel,
    pad: usize,
) -> std::io::Result<PumpHandle>
where
    T: TunPackets + Send + 'static,
{
    let ConnectedTunnel { mut stream, sess } = tunnel;
    stream.get_mut().set_read_timeout(Some(READ_TIMEOUT))?;
    stream.get_mut().set_write_timeout(Some(WRITE_TIMEOUT))?;
    let shutdown_side = stream.get_ref().try_clone()?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_loop = Arc::clone(&stop);
    aetherlink_netstack::debug_log("pump: tls thread spawned");
    let thread = std::thread::spawn(move || {
        let mut pump = DataPump::with_mux(sess.mux, *sess.keys.tx_key(), *sess.keys.rx_key(), pad);
        // Socket read timeout currently installed (switched between the
        // idle and the busy quantum only when it actually changes).
        let mut read_quantum = READ_TIMEOUT;
        loop {
            if stop_loop.load(Ordering::SeqCst) {
                break;
            }
            // TUN -> wire: drain all queued packets.
            let mut busy = false;
            match tun.lock() {
                Ok(mut guard) => match pump.poll_once(&mut *guard) {
                    Ok(frames) => {
                        busy = !frames.is_empty();
                        if busy {
                            aetherlink_netstack::debug_log(&format!(
                                "pump: tls tun->wire {} frame(s)",
                                frames.len()
                            ));
                        }
                        let mut written = 0usize;
                        let mut ok = true;
                        for f in &frames {
                            if write_sealed(&mut stream, &f.header, &f.ciphertext).is_err() {
                                aetherlink_netstack::debug_log(
                                    "pump: tls write failed, thread ends",
                                );
                                ok = false;
                                break;
                            }
                            written += 1;
                        }
                        // Only now are these bytes really gone: free the
                        // upload buffer and confirm them to the app. The app
                        // is throttled by this confirmation, so it paces
                        // itself to what the tunnel can actually carry
                        // instead of overrunning it and losing the surplus.
                        pump.frames_written(written);
                        pump.flush_acks(&mut *guard);
                        if !ok {
                            break;
                        }
                    }
                    Err(e) => {
                        // One bad packet (truncated, unsupported, a full
                        // device on the way back) must never end the
                        // session: back off and keep pumping.
                        aetherlink_netstack::debug_log(&format!(
                            "pump: tls tun drain error: {e}, continuing"
                        ));
                        pump.flush_acks(&mut *guard);
                        std::thread::sleep(TUN_IDLE);
                    }
                },
                Err(_) => {
                    aetherlink_netstack::debug_log("pump: tls lock failed, thread ends");
                    break;
                }
            }
            // An app mid-upload must not wait out the idle quantum: while
            // the device is producing, the wire read only peeks.
            let want = if busy {
                READ_TIMEOUT_BUSY
            } else {
                READ_TIMEOUT
            };
            if want != read_quantum {
                match stream.get_mut().set_read_timeout(Some(want)) {
                    Ok(()) => read_quantum = want,
                    Err(e) => {
                        aetherlink_netstack::debug_log(&format!(
                            "pump: tls read timeout failed ({e}), thread ends"
                        ));
                        break;
                    }
                }
            }
            // Inject one received frame; false ends the thread.
            let mut inject = |header: &FrameHeader, ct: &[u8]| -> bool {
                match tun.lock() {
                    Ok(mut guard) => match pump.receive_mux(header, ct, &mut *guard) {
                        Ok(()) => {
                            aetherlink_netstack::debug_log("pump: tls injected to tun");
                            true
                        }
                        Err(e) => {
                            aetherlink_netstack::debug_log(&format!(
                                "pump: tls frame dropped: {e}"
                            ));
                            true
                        }
                    },
                    Err(_) => false,
                }
            };
            // Wire -> TUN: one frame per turn; timeout re-polls stop.
            match read_sealed(&mut stream) {
                Ok((header, ct)) => {
                    aetherlink_netstack::debug_log(&format!(
                        "pump: tls wire {:?} id={} len={}",
                        header.frame_type, header.stream_id, header.length
                    ));
                    if !inject(&header, &ct) {
                        break;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(e) => {
                    aetherlink_netstack::debug_log(&format!("pump: tls read failed ({e}), ends"));
                    break;
                }
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
