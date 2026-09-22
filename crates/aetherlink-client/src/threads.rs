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
const READ_TIMEOUT: Duration = Duration::from_millis(200);
/// Idle sleep in the TUN->wire loop (no busy spin on an empty TUN).
const TUN_IDLE: Duration = Duration::from_millis(10);
/// Absurd ciphertext length: fail closed instead of allocating.
const MAX_WIRE_BODY: usize = 65535 + 1024;

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
    let mut ct = vec![0u8; header.length as usize];
    r.read_exact(&mut ct)?;
    Ok((header, ct))
}

/// Running pump: flip the flag + join (idempotent, also on drop).
pub struct PumpHandle {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl PumpHandle {
    /// Signal stop and join all threads; safe to call twice.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        while let Some(h) = self.threads.pop() {
            let _ = h.join();
        }
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
    let read_side = stream.try_clone()?;
    let mut write_side = stream;
    let stop = Arc::new(AtomicBool::new(false));
    let pump = Arc::new(Mutex::new(DataPump::new_split(tx, rx, pad)));

    // TUN -> wire: drain TUN, seal, write.
    let (stop_tun, pump_tun, tun_tun) = (Arc::clone(&stop), Arc::clone(&pump), Arc::clone(&tun));
    let tun_thread = std::thread::spawn(move || {
        while !stop_tun.load(Ordering::SeqCst) {
            let frames = (|| {
                let mut tun_guard = tun_tun.lock().ok()?;
                let mut pump_guard = pump_tun.lock().ok()?;
                pump_guard.poll_once(&mut *tun_guard).ok()
            })();
            match frames {
                Some(fs) => {
                    let mut ok = true;
                    for f in &fs {
                        if write_sealed(&mut write_side, &f.header, &f.ciphertext).is_err() {
                            ok = false;
                            break;
                        }
                    }
                    if !ok {
                        break;
                    }
                    if fs.is_empty() {
                        std::thread::sleep(TUN_IDLE);
                    }
                }
                None => break,
            }
        }
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
                    let injected = (|| {
                        let mut tun_guard = tun_wire.lock().ok()?;
                        let mut pump_guard = pump_wire.lock().ok()?;
                        Some(pump_guard.receive_mux(&header, &ct, &mut *tun_guard))
                    })();
                    match injected {
                        Some(Ok(())) | Some(Err(_)) => {} // tamper dropped, loop lives
                        None => break,                    // lock poisoned: fail closed
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
    });

    Ok(PumpHandle {
        stop,
        threads: vec![tun_thread, wire_thread],
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
    let stop = Arc::new(AtomicBool::new(false));
    let stop_loop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        let mut pump = DataPump::with_mux(sess.mux, *sess.keys.tx_key(), *sess.keys.rx_key(), pad);
        loop {
            if stop_loop.load(Ordering::SeqCst) {
                break;
            }
            // TUN -> wire: drain all queued packets.
            match tun.lock() {
                Ok(mut guard) => match pump.poll_once(&mut *guard) {
                    Ok(frames) => {
                        let mut ok = true;
                        for f in &frames {
                            if write_sealed(&mut stream, &f.header, &f.ciphertext).is_err() {
                                ok = false;
                                break;
                            }
                        }
                        if !ok {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                Err(_) => break,
            }
            // Wire -> TUN: one frame per turn; timeout re-polls stop.
            match read_sealed(&mut stream) {
                Ok((header, ct)) => match tun.lock() {
                    Ok(mut guard) => {
                        let _ = pump.receive_mux(&header, &ct, &mut *guard);
                    }
                    Err(_) => break,
                },
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
    });
    Ok(PumpHandle {
        stop,
        threads: vec![thread],
    })
}
