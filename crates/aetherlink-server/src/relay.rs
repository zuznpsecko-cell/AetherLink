//! TCP/UDP relay: dial the target, pipe bytes both ways.
//!
//! The mux layer owns framing/crypto; relay owns the plain sockets.

use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use crate::{Result, ServerError};

/// Bound for outbound TCP dials: a silent target must fail fast instead of
/// inheriting the ~21s OS connect stall and serially blocking the mux.
const TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// How a dial failed: refused is definitive (nothing listens, stable),
// anything else is transient (congestion, slow path — retry-worthy).
/// Only [`DialFail::Refused`] may cool a target down; cooling on transient
/// failures blacks out whole tests after one slow dial (seen live: 0.00 on
/// speedtest upload after a single stall).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialFail {
    Refused,
    Transient,
}

/// Classify a dial error for cooldown decisions (pure, unit-tested).
pub fn classify_dial_err(e: &std::io::Error) -> DialFail {
    if e.kind() == std::io::ErrorKind::ConnectionRefused {
        DialFail::Refused
    } else {
        DialFail::Transient
    }
}

/// Dial `(addr, port)` for a relayed stream.
///
/// Failure kind travels with the error so the loop cools down only
/// definitive refusals (see [`DialFail`]).
pub fn dial_tcp(addr: &str, port: u16) -> std::result::Result<TcpStream, DialFail> {
    let target = format!("{addr}:{port}");
    let mut last = DialFail::Transient;
    let addrs = match target.to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return Err(DialFail::Transient),
    };
    for sock_addr in addrs {
        match TcpStream::connect_timeout(&sock_addr, TCP_DIAL_TIMEOUT) {
            Ok(stream) => {
                // Nagle would stall our small per-frame writes behind
                // delayed ACKs (seen live as a hard ~40pps cap).
                if stream.set_nodelay(true).is_err() {
                    return Err(DialFail::Transient);
                }
                return Ok(stream);
            }
            Err(e) => last = classify_dial_err(&e),
        }
    }
    let _ = target;
    Err(last)
}

/// Relay one UDP datagram: send `payload`, wait for the reply.
///
/// Bounded by `timeout` so a silent target can never stall the mux.
pub fn relay_udp(addr: &str, port: u16, payload: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    let target = format!("{addr}:{port}");
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| ServerError::RelayError(format!("udp bind: {e}")))?;
    sock.connect(&target)
        .map_err(|e| ServerError::RelayError(format!("udp connect {target}: {e}")))?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| ServerError::RelayError(format!("udp timeout: {e}")))?;
    sock.send(payload)
        .map_err(|e| ServerError::RelayError(format!("udp send {target}: {e}")))?;
    let mut buf = vec![0u8; 65535];
    let n = sock
        .recv(&mut buf)
        .map_err(|e| ServerError::RelayError(format!("udp recv {target}: {e}")))?;
    buf.truncate(n);
    Ok(buf)
}

/// One payload in, full reply flight out: write, one blocking first read
/// (socket's own timeout), then drain until `idle` with no new bytes.
///
/// A single read strands multi-chunk flights (TLS handshakes) in the
/// socket buffer and the peer stalls forever (seen live:
/// ERR_SSL_PROTOCOL_ERROR in the browser). Idle-bounded, not
/// close-bounded: keep-alive targets that answer but hold the connection
/// open still release. Capped at 1MB per exchange (bulk streaming beyond
/// that needs full-duplex relay, a follow-up).
pub fn exchange_stream(
    sock: &mut TcpStream,
    payload: &[u8],
    first: Duration,
    idle: Duration,
) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    const CAP: usize = 1 << 20;
    sock.write_all(payload)
        .map_err(|e| ServerError::RelayError(format!("stream write: {e}")))?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65535];
    sock.set_read_timeout(Some(first))
        .map_err(|e| ServerError::RelayError(format!("stream timeout: {e}")))?;
    let n = sock
        .read(&mut buf)
        .map_err(|e| ServerError::RelayError(format!("stream read: {e}")))?;
    out.extend_from_slice(&buf[..n]);
    sock.set_read_timeout(Some(idle))
        .map_err(|e| ServerError::RelayError(format!("stream timeout: {e}")))?;
    while out.len() < CAP {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break
            }
            Err(e) => return Err(ServerError::RelayError(format!("stream drain: {e}"))),
        }
    }
    Ok(out)
}

/// Cooldown for targets whose dial just failed: retry storms (an app
/// re-SYNing a blackholed host every few seconds) must fail fast instead of
/// serially stalling the whole mux loop behind another full dial timeout.
pub const DEAD_COOLDOWN: Duration = Duration::from_secs(30);

/// Whether `addr:port` failed recently enough to skip re-dialing outright.
#[must_use]
pub fn is_fresh_dead(
    dead: &HashMap<(String, u16), Instant>,
    addr: &str,
    port: u16,
    now: Instant,
) -> bool {
    dead.get(&(addr.to_string(), port))
        .is_some_and(|t| now.duration_since(*t) < DEAD_COOLDOWN)
}

/// Record a dial failure for cooldown.
pub fn mark_dead(dead: &mut HashMap<(String, u16), Instant>, addr: &str, port: u16, now: Instant) {
    dead.insert((addr.to_string(), port), now);
}

/// Legacy id-based relay hook (kept for the FFI surface; dials via mux target).
pub fn relay(_id: u16) -> Result<()> {
    Err(ServerError::RelayError("use dial_tcp".to_string()))
}

#[cfg(test)]
mod dead_cache_tests {
    use super::*;

    #[test]
    fn fresh_dead_target_is_skipped_until_cooldown() {
        // Given: a target marked dead just now
        let mut dead = HashMap::new();
        let now = Instant::now();
        mark_dead(&mut dead, "10.9.9.9", 443, now);
        // Then: skipped within cooldown, allowed after it.
        assert!(is_fresh_dead(&dead, "10.9.9.9", 443, now));
        assert!(is_fresh_dead(
            &dead,
            "10.9.9.9",
            443,
            now + DEAD_COOLDOWN - Duration::from_secs(1)
        ));
        assert!(!is_fresh_dead(&dead, "10.9.9.9", 443, now + DEAD_COOLDOWN));
        // And: other ports/hosts unaffected.
        assert!(!is_fresh_dead(&dead, "10.9.9.9", 80, now));
        assert!(!is_fresh_dead(&dead, "10.9.9.8", 443, now));
    }

    #[test]
    fn unknown_target_never_skipped() {
        let dead: HashMap<(String, u16), Instant> = HashMap::new();
        assert!(!is_fresh_dead(&dead, "10.9.9.9", 443, Instant::now()));
    }
}
