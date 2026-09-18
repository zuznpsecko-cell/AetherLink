//! TCP/UDP relay: dial the target, pipe bytes both ways.
//!
//! The mux layer owns framing/crypto; relay owns the plain sockets.

use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::{Result, ServerError};

/// Dial `(addr, port)` for a relayed stream.
pub fn dial_tcp(addr: &str, port: u16) -> Result<TcpStream> {
    let target = format!("{addr}:{port}");
    let mut last_err = String::new();
    for sock_addr in target
        .to_socket_addrs()
        .map_err(|e| ServerError::RelayError(e.to_string()))?
    {
        match TcpStream::connect(sock_addr) {
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

/// Legacy id-based relay hook (kept for the FFI surface; dials via mux target).
pub fn relay(_id: u16) -> Result<()> {
    Err(ServerError::RelayError("use dial_tcp".to_string()))
}
