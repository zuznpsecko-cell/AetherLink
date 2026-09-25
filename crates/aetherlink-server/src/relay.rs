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

/// Dial `(addr, port)` for a relayed stream.
pub fn dial_tcp(addr: &str, port: u16) -> Result<TcpStream> {
    let target = format!("{addr}:{port}");
    let mut last_err = String::new();
    for sock_addr in target
        .to_socket_addrs()
        .map_err(|e| ServerError::RelayError(e.to_string()))?
    {
        match TcpStream::connect_timeout(&sock_addr, TCP_DIAL_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(ServerError::RelayError(format!(
        "dial {target}: {last_err}"
    )))
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
